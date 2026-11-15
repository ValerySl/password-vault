"""Хранилище паролей в одном зашифрованном файле. Два секрета: ключ на бумаге + код.

Запуск:  python vault.py [путь_к_файлу]
         Без пути: последний открытый файл, иначе файл хранилища рядом с программой
         (ищется по метке, имя любое), иначе создаётся новый со случайным именем.

Как устроена защита
-------------------
* СЕКРЕТНЫЙ КЛЮЧ — 160 случайных бит (32 символа). Создаётся программой один раз,
  вы храните его на бумаге. Нужен только при первом входе на новом устройстве.
* КОД — минимум 6 символов, буквы и цифры. Вводится при каждом входе.
* Ключ шифрования = Argon2id(секретный ключ + код). Нужны ОБА одновременно:
  файл без секретного ключа подобрать невозможно, а секретный ключ без кода
  не открывает файл — каждая попытка подбора кода стоит 1 ГБ памяти и ~1 с.
* Данные шифруются AES-256-GCM: любое изменение файла или неверный секрет —
  и расшифровка не выполнится.
* После первого входа устройство «запоминает» секретный ключ: он сохраняется
  в профиле пользователя, зашифрованный средствами Windows (DPAPI, привязка
  к вашей учётной записи Windows). Сам код и пароли на диск не пишутся никогда.

Формат файла:
  MAGIC(4) | память_КиБ(4) | проходы(4) | потоки(4) | соль(16) | id(8) | nonce(12) | шифртекст+тег
"""

import base64
import getpass
import json
import os
import secrets
import shutil
import string
import struct
import subprocess
import sys
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

MAGIC = b"PWV2"
HEADER = struct.Struct(">4sIII16s8s")  # magic, memory_kib, iterations, lanes, salt, vault_id
NONCE_LEN = 12
SECRET_KEY_LEN = 20  # байт = 160 бит = 32 символа base32

# Параметры Argon2id для новых файлов. Тяжёлые намеренно: код короткий,
# и именно они делают его подбор дорогим, даже если секретный ключ украден.
MEMORY_KIB = 1024 * 1024  # 1 ГБ
ITERATIONS = 4
LANES = 4

BACKUP_DIR = "backups"
BACKUP_KEEP = 20  # сколько последних версий хранить

MIN_CODE_LEN = 6
CLIPBOARD_SECONDS = 20


class WrongSecretOrCorrupted(Exception):
    pass


# ------------------------------------------------------------ секретный ключ

def new_secret_key() -> bytes:
    return secrets.token_bytes(SECRET_KEY_LEN)


def format_secret_key(key: bytes) -> str:
    s = base64.b32encode(key).decode("ascii")
    return "-".join(s[i : i + 4] for i in range(0, len(s), 4))


def parse_secret_key(text: str) -> bytes:
    """Принимает ключ в любом виде: с дефисами/пробелами, в любом регистре."""
    s = "".join(ch for ch in text.upper() if ch.isalnum())
    s = s.replace("0", "O").replace("1", "I").replace("8", "B")  # этих цифр в алфавите нет
    try:
        key = base64.b32decode(s)
    except ValueError:
        raise ValueError("ключ введён с ошибкой") from None
    if len(key) != SECRET_KEY_LEN:
        raise ValueError("ключ должен состоять из 32 символов")
    return key


def check_code(code: str) -> str | None:
    """Возвращает текст ошибки или None, если код годится."""
    if len(code) < MIN_CODE_LEN:
        return f"Нужно минимум {MIN_CODE_LEN} символов."
    if not (any(c.isalpha() for c in code) and any(c.isdigit() for c in code)):
        return "В коде должны быть и буквы, и цифры."
    if len(set(code)) < 4:
        return "Слишком много одинаковых символов."
    return None


def derive_key(secret_key: bytes, code: str, salt: bytes, memory_kib: int, iterations: int, lanes: int) -> bytes:
    kdf = Argon2id(salt=salt, length=32, iterations=iterations, lanes=lanes, memory_cost=memory_kib)
    # Секретный ключ фиксированной длины, поэтому склейка однозначна.
    return kdf.derive(secret_key + code.encode("utf-8"))


# ----------------------------------------------------------------- хранилище

class Vault:
    """Расшифрованное хранилище в памяти. entries: {название: запись}, запись одного из видов:
    пароль:  {login, password, note}
    кошелёк: {type: "wallet", network, address, seed, key, note}"""

    def __init__(self, path: str, secret_key: bytes, key: bytes, header: bytes, entries: dict):
        self.path = path
        self.secret_key = secret_key
        self._key = key
        self._header = header
        self.entries = entries

    @property
    def vault_id(self) -> str:
        return HEADER.unpack(self._header)[5].hex()

    @staticmethod
    def read_id(path: str) -> str:
        """id хранилища из заголовка файла (не секрет, нужен чтобы найти запомненный ключ)."""
        with open(path, "rb") as f:
            header = f.read(HEADER.size)
        if len(header) < HEADER.size or header[:4] != MAGIC:
            raise WrongSecretOrCorrupted("это не файл хранилища")
        return HEADER.unpack(header)[5].hex()

    @classmethod
    def create(cls, path: str, secret_key: bytes, code: str) -> "Vault":
        salt = secrets.token_bytes(16)
        header = HEADER.pack(MAGIC, MEMORY_KIB, ITERATIONS, LANES, salt, secrets.token_bytes(8))
        key = derive_key(secret_key, code, salt, MEMORY_KIB, ITERATIONS, LANES)
        vault = cls(path, secret_key, key, header, {})
        vault.save()
        return vault

    @classmethod
    def open(cls, path: str, secret_key: bytes, code: str) -> "Vault":
        with open(path, "rb") as f:
            blob = f.read()
        if len(blob) < HEADER.size + NONCE_LEN + 16:
            raise WrongSecretOrCorrupted("файл слишком короткий")
        header = blob[: HEADER.size]
        magic, memory_kib, iterations, lanes, salt, _ = HEADER.unpack(header)
        if magic != MAGIC:
            raise WrongSecretOrCorrupted("это не файл хранилища")
        # Защита от подсунутого файла с абсурдными параметрами (зависание/съедание памяти).
        if not (8 * lanes <= memory_kib <= 4 * 1024 * 1024 and 1 <= iterations <= 64 and 1 <= lanes <= 64):
            raise WrongSecretOrCorrupted("недопустимые параметры в заголовке")
        nonce = blob[HEADER.size : HEADER.size + NONCE_LEN]
        ciphertext = blob[HEADER.size + NONCE_LEN :]
        key = derive_key(secret_key, code, salt, memory_kib, iterations, lanes)
        try:
            # Заголовок передаётся как AAD: его подмена тоже ломает расшифровку.
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
        except InvalidTag:
            raise WrongSecretOrCorrupted("неверный код или секретный ключ (или файл повреждён)") from None
        return cls(path, secret_key, key, header, json.loads(plaintext.decode("utf-8")))

    # ---- резервные копии: папка backups рядом с файлом хранилища

    @property
    def backup_dir(self) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(self.path)), BACKUP_DIR)

    def list_backups(self) -> list[str]:
        """Копии этого хранилища, сначала самые новые."""
        stem = os.path.splitext(os.path.basename(self.path))[0]
        try:
            names = os.listdir(self.backup_dir)
        except OSError:
            return []
        own = [n for n in names if n.startswith(stem + "-") and n.endswith(".dat")]
        return [os.path.join(self.backup_dir, n) for n in sorted(own, reverse=True)]

    def _make_backup(self) -> None:
        """Копирует текущую версию файла перед перезаписью. Имя — время той версии."""
        if not os.path.exists(self.path):
            return
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            stem = os.path.splitext(os.path.basename(self.path))[0]
            mtime = os.path.getmtime(self.path)
            stamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(mtime)) + f"-{int(mtime * 1000) % 1000:03d}"
            dest = os.path.join(self.backup_dir, f"{stem}-{stamp}.dat")
            n = 1
            while os.path.exists(dest):
                dest = os.path.join(self.backup_dir, f"{stem}-{stamp}{n:02d}.dat")
                n += 1
            shutil.copy2(self.path, dest)
            for old in self.list_backups()[BACKUP_KEEP:]:
                os.remove(old)
        except OSError:
            pass  # копия не получилась — это не повод не сохранить основной файл

    def purge_backups(self) -> None:
        for path in self.list_backups():
            try:
                os.remove(path)
            except OSError:
                pass

    def read_backup(self, path: str) -> dict:
        """Записи из резервной копии. Открывается текущим ключом, повторно код не нужен."""
        with open(path, "rb") as f:
            blob = f.read()
        header = blob[: HEADER.size]
        if header != self._header:
            raise WrongSecretOrCorrupted("копия сделана до смены кода или от другого хранилища")
        nonce = blob[HEADER.size : HEADER.size + NONCE_LEN]
        try:
            plaintext = AESGCM(self._key).decrypt(nonce, blob[HEADER.size + NONCE_LEN :], header)
        except InvalidTag:
            raise WrongSecretOrCorrupted("копия повреждена") from None
        return json.loads(plaintext.decode("utf-8"))

    def save(self, backup: bool = True) -> None:
        if backup:
            self._make_backup()
        nonce = secrets.token_bytes(NONCE_LEN)  # новый nonce при каждом сохранении
        plaintext = json.dumps(self.entries, ensure_ascii=False).encode("utf-8")
        blob = self._header + nonce + AESGCM(self._key).encrypt(nonce, plaintext, self._header)
        # Атомарная запись: сначала во временный файл, потом подмена.
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)

    def change_code(self, new_code: str) -> None:
        vault_id = HEADER.unpack(self._header)[5]
        salt = secrets.token_bytes(16)
        self._header = HEADER.pack(MAGIC, MEMORY_KIB, ITERATIONS, LANES, salt, vault_id)
        self._key = derive_key(self.secret_key, new_code, salt, MEMORY_KIB, ITERATIONS, LANES)
        self.save(backup=False)
        # Старые копии открываются старым кодом. Если код меняют из-за утечки,
        # они не должны остаться лазейкой — удаляем.
        self.purge_backups()


def program_dir() -> str:
    """Папка программы: рядом со скриптом или, в собранном .exe, рядом с ним."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def random_vault_name() -> str:
    """Имя нового файла хранилища — случайное, ничего не говорящее о содержимом."""
    return secrets.token_hex(8) + ".dat"


def find_vault(folder: str) -> str | None:
    """Ищет файл хранилища по метке в начале файла: имя может быть любым."""
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return None
    for name in names:
        path = os.path.join(folder, name)
        if name.endswith(".tmp") or not os.path.isfile(path):
            continue
        try:
            with open(path, "rb") as f:
                if f.read(len(MAGIC)) == MAGIC:
                    return path
        except OSError:
            continue
    return None


def default_vault_path(device: "Device") -> str:
    """Последний открытый файл, иначе найденный рядом с программой, иначе новое случайное имя."""
    remembered = device.last_path()
    if remembered and os.path.exists(remembered):
        return remembered
    folder = program_dir()
    return find_vault(folder) or os.path.join(folder, random_vault_name())


def subtitle(entry: dict) -> str:
    """Вторая строка в списке: логин для пароля, сеть для криптокошелька."""
    if entry.get("type") == "wallet":
        return entry.get("network") or "Криптокошелёк"
    return entry.get("login", "")


def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)):
            return pw


# ------------------------------------------------- память устройства (DPAPI)

def _dpapi(protect: bool, data: bytes) -> bytes:
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    func = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData

    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    if not func(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise OSError(ctypes.get_last_error(), "DPAPI отказал")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(blob_out.pbData, ctypes.c_void_p))


class Device:
    """То, что программа помнит на этом устройстве: путь к файлу и секретные ключи
    (зашифрованные Windows под текущую учётную запись). Ни кода, ни паролей здесь нет."""

    def __init__(self):
        base = os.environ.get("PWVAULT_CONFIG_DIR") or os.path.join(
            os.environ.get("APPDATA") or os.path.expanduser("~"), "PasswordVault")
        self.file = os.path.join(base, "device.json")
        try:
            with open(self.file, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {}
        self.data.setdefault("keys", {})

    @property
    def can_remember(self) -> bool:
        return sys.platform == "win32"

    def _write(self) -> None:
        os.makedirs(os.path.dirname(self.file), exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as f:
            json.dump(self.data, f)

    def get_setting(self, name: str, default):
        return self.data.get("settings", {}).get(name, default)

    def set_setting(self, name: str, value) -> None:
        self.data.setdefault("settings", {})[name] = value
        self._write()

    def last_path(self) -> str | None:
        return self.data.get("last_path")

    def set_last_path(self, path: str) -> None:
        self.data["last_path"] = os.path.abspath(path)
        self._write()

    def get_key(self, vault_id: str) -> bytes | None:
        blob = self.data["keys"].get(vault_id)
        if not blob or not self.can_remember:
            return None
        try:
            return _dpapi(False, base64.b64decode(blob))
        except (OSError, ValueError):
            return None  # другая учётная запись/другой компьютер — ключ придётся ввести заново

    def remember_key(self, vault_id: str, secret_key: bytes) -> bool:
        if not self.can_remember:
            return False
        self.data["keys"][vault_id] = base64.b64encode(_dpapi(True, secret_key)).decode("ascii")
        self._write()
        return True

    def forget_key(self, vault_id: str) -> None:
        if self.data["keys"].pop(vault_id, None) is not None:
            self._write()


# ---------------------------------------------------------------- интерфейс

def set_clipboard(text: str) -> bool:
    try:
        if sys.platform == "win32":
            subprocess.run(["clip"], input=text.encode("utf-16-le"), check=True)
        elif sys.platform == "darwin":
            subprocess.run(["pbcopy"], input=text.encode("utf-8"), check=True)
        else:
            subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode("utf-8"), check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def copy_temporarily(text: str) -> None:
    if not set_clipboard(text):
        print("Не удалось скопировать в буфер обмена.")
        return
    print(f"Пароль скопирован. Буфер обмена очистится через {CLIPBOARD_SECONDS} с.")
    timer = threading.Timer(CLIPBOARD_SECONDS, set_clipboard, args=("",))
    timer.daemon = True
    timer.start()


def ask_new_code() -> str:
    print(f"Код: минимум {MIN_CODE_LEN} символов, буквы и цифры, регистр важен. "
          "Не дата, не имя и не «qwe123».")
    while True:
        code = getpass.getpass("Новый код: ")
        if problem := check_code(code):
            print(problem)
            continue
        if code != getpass.getpass("Повторите: "):
            print("Коды не совпали.")
            continue
        return code


def show_secret_key(secret_key: bytes) -> None:
    print("\n" + "=" * 56)
    print("  СЕКРЕТНЫЙ КЛЮЧ — перепишите на бумагу и уберите:")
    print(f"\n    {format_secret_key(secret_key)}\n")
    print("  Понадобится для входа на другом устройстве и после")
    print("  переустановки Windows. Без него файл не открыть никак.")
    print("=" * 56)


def create_vault(path: str, device: Device) -> Vault:
    print(f"Создаём новое хранилище: {path}")
    code = ask_new_code()
    secret_key = new_secret_key()
    print("Шифруем...")
    vault = Vault.create(path, secret_key, code)
    show_secret_key(secret_key)
    while True:  # убеждаемся, что ключ действительно переписан верно
        try:
            if parse_secret_key(input("Введите ключ с бумаги для проверки: ")) == secret_key:
                break
            print("Не совпадает — проверьте запись.")
        except ValueError as e:
            print(f"Ошибка: {e}.")
    device.remember_key(vault.vault_id, secret_key)
    print("Хранилище создано. На этом устройстве дальше нужен только код.")
    return vault


def open_vault(path: str, device: Device) -> Vault:
    vault_id = Vault.read_id(path)
    secret_key = device.get_key(vault_id)
    is_new_device = secret_key is None
    if is_new_device:
        print("Это устройство ещё не авторизовано для этого файла.")
        while secret_key is None:
            try:
                secret_key = parse_secret_key(input("Секретный ключ (с бумаги): "))
            except ValueError as e:
                print(f"Ошибка: {e}.")
    code = getpass.getpass("Код: ")
    print("Проверяем...")
    vault = Vault.open(path, secret_key, code)
    if is_new_device and device.remember_key(vault_id, secret_key):
        print("Устройство авторизовано: дальше здесь нужен только код.")
    return vault


def pick_entry(vault: Vault) -> str | None:
    names = sorted(vault.entries, key=str.lower)
    if not names:
        print("Хранилище пусто.")
        return None
    for i, name in enumerate(names, 1):
        print(f"  {i}. {name}  ({subtitle(vault.entries[name])})")
    choice = input("Номер записи: ").strip()
    if choice.isdigit() and 1 <= int(choice) <= len(names):
        return names[int(choice) - 1]
    print("Нет такой записи.")
    return None


def add_entry(vault: Vault) -> None:
    name = input("Название (сайт/сервис): ").strip()
    if not name:
        return
    if name in vault.entries and input("Такая запись есть. Перезаписать? (д/н): ").strip().lower() != "д":
        return
    login = input("Логин / e-mail: ").strip()
    password = getpass.getpass("Пароль (Enter — сгенерировать): ")
    if not password:
        password = generate_password()
        print("Сгенерирован случайный пароль из 20 символов.")
    note = input("Заметка (необязательно): ").strip()
    vault.entries[name] = {"login": login, "password": password, "note": note}
    vault.save()
    print("Сохранено.")


def main() -> None:
    device = Device()
    path = sys.argv[1] if len(sys.argv) > 1 else default_vault_path(device)

    try:
        vault = open_vault(path, device) if os.path.exists(path) else create_vault(path, device)
    except WrongSecretOrCorrupted as e:
        sys.exit(f"Не удалось открыть: {e}")
    device.set_last_path(path)

    menu = ("\n1 — список   2 — добавить   3 — скопировать пароль   4 — показать запись\n"
            "5 — удалить  6 — сменить код  7 — показать секретный ключ\n"
            "8 — забыть это устройство     0 — выход")
    try:
        while True:
            print(menu)
            cmd = input("> ").strip()
            if cmd == "1":
                names = sorted(vault.entries, key=str.lower)
                if not names:
                    print("Хранилище пусто.")
                for name in names:
                    print(f"  {name}  ({subtitle(vault.entries[name])})")
            elif cmd == "2":
                add_entry(vault)
            elif cmd == "3":
                if name := pick_entry(vault):
                    e = vault.entries[name]
                    copy_temporarily(e.get("password") or e.get("seed") or e.get("key", ""))
            elif cmd == "4":
                if name := pick_entry(vault):
                    e = vault.entries[name]
                    if e.get("type") == "wallet":
                        e = {"login": f"{e['network']} {e['address']}", "note": e["note"],
                             "password": f"сид-фраза: {e['seed']} | ключ: {e['key']}"}
                    print(f"  Логин:  {e['login']}\n  Пароль:  {e['password']}\n  Заметка: {e['note']}")
            elif cmd == "5":
                if (name := pick_entry(vault)) and input(f"Удалить «{name}»? (д/н): ").strip().lower() == "д":
                    del vault.entries[name]
                    vault.save()
                    print("Удалено.")
            elif cmd == "6":
                vault.change_code(ask_new_code())
                print("Код изменён, файл перешифрован.")
            elif cmd == "7":
                show_secret_key(vault.secret_key)
            elif cmd == "8":
                device.forget_key(vault.vault_id)
                print("Готово: при следующем входе здесь снова понадобится секретный ключ.")
                break
            elif cmd == "0":
                break
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        set_clipboard("")  # не оставляем пароль в буфере после выхода


if __name__ == "__main__":
    main()
