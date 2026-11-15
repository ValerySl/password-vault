"""Оконный интерфейс хранилища паролей. Шифрование — в vault.py, здесь только экран.

Запуск:  python vault_gui.py [путь_к_файлу]     (или двойной щелчок по «Хранилище.bat»)
"""

import os
import queue
import secrets
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

import vault as core

# Палитра
BG = "#0d0f17"
PANEL = "#151824"
CARD = "#1c2030"
LINE = "#2b3045"
TEXT = "#eceae4"
MUTED = "#878ca3"
GOLD = "#c9a65b"
GOLD_HOVER = "#dcbb72"
DANGER = "#d0655e"
GOOD = "#74c193"

AUTO_LOCK_CHOICES = {"30 с": 30, "1 мин": 60, "2 мин": 120, "5 мин": 300, "10 мин": 600}
AUTO_LOCK_DEFAULT = 300
CLIPBOARD_SECONDS = 20
FIELD_W = 372


def font(size=14, bold=False, mono=False):
    return ctk.CTkFont(family="Consolas" if mono else "Segoe UI", size=size,
                       weight="bold" if bold else "normal")


def label(master, text="", size=14, color=TEXT, bold=False, mono=False, **kw):
    return ctk.CTkLabel(master, text=text, font=font(size, bold, mono), text_color=color, **kw)


def primary(master, text, command, **kw):
    kw.setdefault("height", 44)
    return ctk.CTkButton(master, text=text, command=command, fg_color=GOLD, hover_color=GOLD_HOVER,
                         text_color="#1a1508", text_color_disabled="#5d5133", font=font(14, True),
                         corner_radius=10, **kw)


def ghost(master, text, command, color=TEXT, **kw):
    kw.setdefault("height", 36)
    return ctk.CTkButton(master, text=text, command=command, fg_color="transparent", hover_color=LINE,
                         text_color=color, border_width=1, border_color=LINE, font=font(13),
                         corner_radius=9, **kw)


def link(master, text, command):
    return ctk.CTkButton(master, text=text, command=command, fg_color="transparent", hover_color=PANEL,
                         text_color=MUTED, font=font(12), height=24, width=10)


def entry(master, placeholder="", secret=False, mono=False, **kw):
    kw.setdefault("width", FIELD_W)
    kw.setdefault("height", 44)
    return ctk.CTkEntry(master, placeholder_text=placeholder, show="•" if secret else "",
                        fg_color=BG, border_color=LINE, border_width=1, text_color=TEXT,
                        placeholder_text_color="#5b6078", font=font(14, mono=mono),
                        corner_radius=10, **kw)


class App(ctk.CTk):
    def __init__(self, path=None):
        ctk.set_appearance_mode("dark")
        super().__init__(fg_color=BG)
        self.title("Хранилище паролей")
        self.geometry("1000x660")
        self.minsize(880, 580)

        self.device = core.Device()
        default = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.dat")
        remembered = self.device.last_path()
        self.path = path or (remembered if remembered and os.path.exists(remembered) else default)

        saved = self.device.get_setting("auto_lock_seconds", AUTO_LOCK_DEFAULT)
        self.auto_lock_seconds = saved if saved in AUTO_LOCK_CHOICES.values() else AUTO_LOCK_DEFAULT

        self.vault = None
        self.selected = None
        self._clip = None
        self._toast_id = 0
        self._tasks = queue.Queue()
        self._last_activity = time.monotonic()

        self.root_frame = ctk.CTkFrame(self, fg_color=BG, corner_radius=0)
        self.root_frame.pack(fill="both", expand=True)

        for ev in ("<Any-KeyPress>", "<Any-ButtonPress>", "<Motion>"):
            self.bind_all(ev, self._touch, add="+")
        self.protocol("WM_DELETE_WINDOW", self._quit)
        self.after(50, self._pump)
        self.after(1000, self._idle_check)
        self.show_start()
        self.update_idletasks()
        self.capture_protected = self._protect_from_capture()

    def _protect_from_capture(self, enable=True):
        """Исключает окно из скриншотов, записи и показа экрана (штатная функция Windows)."""
        if sys.platform != "win32":
            return False
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.GetParent.argtypes = [wintypes.HWND]
        user32.GetParent.restype = wintypes.HWND
        user32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
        user32.SetWindowDisplayAffinity.restype = wintypes.BOOL
        hwnd = user32.GetParent(self.winfo_id()) or self.winfo_id()
        if not enable:
            return bool(user32.SetWindowDisplayAffinity(hwnd, 0))
        # 0x11 — окна нет на снимке вовсе (Windows 10 2004+); 0x01 — на снимке чёрный прямоугольник.
        return bool(user32.SetWindowDisplayAffinity(hwnd, 0x11) or user32.SetWindowDisplayAffinity(hwnd, 0x01))

    # ------------------------------------------------------------ служебное

    def _touch(self, _event=None):
        self._last_activity = time.monotonic()

    def _pump(self):
        """Результаты фоновых вычислений забираем только в главном потоке."""
        try:
            while True:
                self._tasks.get_nowait()()
        except queue.Empty:
            pass
        self.after(50, self._pump)

    def run_async(self, work, done, fail):
        def target():
            try:
                result = work()
            except Exception as e:  # noqa: BLE001 — показываем любую ошибку пользователю
                self._tasks.put(lambda e=e: fail(e))
            else:
                self._tasks.put(lambda: done(result))
        threading.Thread(target=target, daemon=True).start()

    def _idle_check(self):
        if self.vault is not None and time.monotonic() - self._last_activity > self.auto_lock_seconds:
            self.lock("Заблокировано из-за бездействия")
        self.after(1000, self._idle_check)

    def _quit(self):
        self._clear_clip()
        self.destroy()

    def _screen(self):
        for w in self.root_frame.winfo_children():
            w.destroy()
        return self.root_frame

    def _card(self):
        card = ctk.CTkFrame(self._screen(), fg_color=PANEL, corner_radius=20, border_width=1, border_color=LINE)
        card.place(relx=0.5, rely=0.5, anchor="center")
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(padx=40, pady=34)
        return inner

    def _brand(self, parent, subtitle):
        label(parent, "◆", 30, GOLD).pack()
        label(parent, "Хранилище", 26, bold=True).pack(pady=(2, 0))
        label(parent, subtitle, 13, MUTED, wraplength=FIELD_W, justify="center").pack(pady=(4, 22))

    def _file_links(self, parent):
        row = ctk.CTkFrame(parent, fg_color="transparent")
        row.pack(pady=(14, 0))
        link(row, "Открыть другой файл", self._choose_existing).pack(side="left", padx=4)
        label(row, "·", 12, MUTED).pack(side="left")
        link(row, "Создать новое", self._choose_new).pack(side="left", padx=4)
        label(parent, self.path, 11, "#5b6078", wraplength=FIELD_W, justify="center").pack(pady=(6, 0))

    def _choose_existing(self):
        chosen = filedialog.askopenfilename(title="Файл хранилища",
                                            filetypes=[("Хранилище", "*.dat"), ("Все файлы", "*.*")])
        if chosen:
            self.path = os.path.normpath(chosen)
            self.show_start()

    def _choose_new(self):
        chosen = filedialog.asksaveasfilename(title="Где создать хранилище", defaultextension=".dat",
                                              initialfile="vault.dat", confirmoverwrite=False,
                                              filetypes=[("Хранилище", "*.dat")])
        if chosen:
            self.path = os.path.normpath(chosen)
            if os.path.exists(self.path):
                self.show_unlock()  # существующий файл никогда не перезаписываем
            else:
                self.show_create()

    def toast(self, text, color=GOOD):
        if not getattr(self, "_toast", None) or not self._toast.winfo_exists():
            return
        self._toast_id += 1
        my_id = self._toast_id
        self._toast.configure(text=text, text_color=color)
        self._toast.place(relx=1.0, rely=1.0, x=-28, y=-22, anchor="se")
        self._toast.lift()

        def hide():
            if my_id == self._toast_id and self._toast.winfo_exists():
                self._toast.place_forget()
        self.after(2600, hide)

    # --------------------------------------------------------- буфер обмена

    def copy(self, text, message):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.update_idletasks()
        self._clip = text
        self.toast(f"{message} · буфер очистится через {CLIPBOARD_SECONDS} с")
        self.after(CLIPBOARD_SECONDS * 1000, lambda t=text: self._clear_clip(t))

    def _clear_clip(self, only_if=None):
        if self._clip is None or (only_if is not None and only_if != self._clip):
            return
        try:
            current = self.clipboard_get()
        except tk.TclError:
            current = None
        if current == self._clip:  # чужое содержимое не трогаем
            self.clipboard_clear()
            self.clipboard_append("")
            self.update_idletasks()
        self._clip = None

    # ----------------------------------------------------------------- вход

    def show_start(self):
        if os.path.exists(self.path):
            self.show_unlock()
        else:
            self.show_create()

    def show_unlock(self, message=""):
        self.vault = None
        self.selected = None
        try:
            self._vault_id = core.Vault.read_id(self.path)
        except (OSError, core.WrongSecretOrCorrupted) as e:
            self.show_create(error=f"Не удалось открыть выбранный файл: {e}")
            return
        self._stored_key = self.device.get_key(self._vault_id)
        new_device = self._stored_key is None

        c = self._card()
        self._brand(c, "Новое устройство: нужен секретный ключ с бумаги и код"
                    if new_device else "Введите код, чтобы открыть")
        self.key_entry = None
        if new_device:
            self.key_entry = entry(c, "Секретный ключ  XXXX-XXXX-…", mono=True)
            self.key_entry.pack(pady=(0, 10))
        self.code_entry = entry(c, "Код", secret=True)
        self.code_entry.pack()
        self.status = label(c, message, 12, MUTED, wraplength=FIELD_W, justify="center")
        self.status.pack(pady=(10, 10))
        self.submit_btn = primary(c, "Войти", self._unlock, width=FIELD_W)
        self.submit_btn.pack()
        self._file_links(c)

        for w in (self.key_entry, self.code_entry):
            if w is not None:
                w.bind("<Return>", lambda _e: self._unlock())
        (self.key_entry or self.code_entry).focus_set()

    def _unlock(self):
        if str(self.submit_btn.cget("state")) == "disabled":
            return
        secret_key = self._stored_key
        if secret_key is None:
            try:
                secret_key = core.parse_secret_key(self.key_entry.get())
            except ValueError as e:
                self.status.configure(text=f"Секретный ключ: {e}", text_color=DANGER)
                return
        code = self.code_entry.get()
        if not code:
            self.status.configure(text="Введите код", text_color=DANGER)
            return
        self.submit_btn.configure(state="disabled", text="Проверяем…")
        self.status.configure(text="", text_color=MUTED)
        path, was_new = self.path, self._stored_key is None

        def done(v):
            if was_new:
                self.device.remember_key(v.vault_id, secret_key)
            self.device.set_last_path(path)
            self.vault = v
            self._touch()
            self.show_main()
            if was_new:
                self.toast("Устройство авторизовано — дальше здесь нужен только код")

        def fail(e):
            if not self.submit_btn.winfo_exists():
                return
            text = str(e)
            self.status.configure(text=text[:1].upper() + text[1:], text_color=DANGER)
            self.submit_btn.configure(state="normal", text="Войти")
            self.code_entry.delete(0, "end")
            self.code_entry.focus_set()

        self.run_async(lambda: core.Vault.open(path, secret_key, code), done, fail)

    # ------------------------------------------------------------- создание

    def show_create(self, error=""):
        self.vault = None
        c = self._card()
        self._brand(c, "Создадим новое хранилище. Придумайте код — его вы будете вводить при каждом входе")
        self.code_entry = entry(c, "Код: от 6 символов, буквы и цифры", secret=True)
        self.code_entry.pack(pady=(0, 10))
        self.code2_entry = entry(c, "Повторите код", secret=True)
        self.code2_entry.pack()
        self.status = label(c, error or "Регистр важен. Не дата, не имя и не «qwe123»", 12,
                            DANGER if error else MUTED, wraplength=FIELD_W, justify="center")
        self.status.pack(pady=(10, 10))
        self.submit_btn = primary(c, "Создать хранилище", self._create, width=FIELD_W)
        self.submit_btn.pack()
        self._file_links(c)
        for w in (self.code_entry, self.code2_entry):
            w.bind("<Return>", lambda _e: self._create())
        self.code_entry.focus_set()

    def _create(self):
        if str(self.submit_btn.cget("state")) == "disabled":
            return
        code = self.code_entry.get()
        problem = core.check_code(code)
        if problem is None and code != self.code2_entry.get():
            problem = "Коды не совпали."
        if problem is None and os.path.exists(self.path):
            problem = "Такой файл уже существует — выберите другое место."
        if problem:
            self.status.configure(text=problem, text_color=DANGER)
            return
        self.submit_btn.configure(state="disabled", text="Шифруем…")
        path = self.path

        def work():
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            return core.Vault.create(path, core.new_secret_key(), code)

        def fail(e):
            if self.submit_btn.winfo_exists():
                self.status.configure(text=f"Не получилось: {e}", text_color=DANGER)
                self.submit_btn.configure(state="normal", text="Создать хранилище")

        self.run_async(work, self.show_key_confirm, fail)

    def show_key_confirm(self, new_vault):
        """Ключ показываем один раз и не пускаем дальше, пока его не введут с бумаги."""
        c = self._card()
        label(c, "◆", 30, GOLD).pack()
        label(c, "Секретный ключ", 24, bold=True).pack(pady=(2, 4))
        label(c, "Перепишите на бумагу и уберите в надёжное место. Он понадобится для входа "
                 "на другом устройстве и после переустановки Windows. Без него файл не открыть никак.",
              13, MUTED, wraplength=FIELD_W + 40, justify="center").pack(pady=(0, 16))

        groups = core.format_secret_key(new_vault.secret_key).split("-")
        box = ctk.CTkFrame(c, fg_color=BG, corner_radius=12, border_width=1, border_color=GOLD)
        box.pack(fill="x")
        label(box, "  ".join(groups[:4]) + "\n" + "  ".join(groups[4:]), 21, GOLD, bold=True, mono=True,
              justify="center").pack(padx=18, pady=16)

        label(c, "Теперь введите ключ с бумаги — проверим, что записан без ошибок", 12, MUTED).pack(pady=(16, 4))
        self.key_entry = entry(c, "XXXX-XXXX-…", mono=True, width=FIELD_W + 40)
        self.key_entry.pack()
        self.status = label(c, "", 12, DANGER)
        self.status.pack(pady=(8, 8))

        def confirm():
            try:
                ok = core.parse_secret_key(self.key_entry.get()) == new_vault.secret_key
            except ValueError:
                ok = False
            if not ok:
                self.status.configure(text="Не совпадает — сверьте запись с ключом выше")
                return
            self.device.remember_key(new_vault.vault_id, new_vault.secret_key)
            self.device.set_last_path(new_vault.path)
            self.vault = new_vault
            self._touch()
            self.show_main()

        primary(c, "Я записал ключ", confirm, width=FIELD_W + 40).pack()
        self.key_entry.bind("<Return>", lambda _e: confirm())
        self.key_entry.focus_set()

    # ------------------------------------------------------- основной экран

    def lock(self, message=""):
        self._clear_clip()
        self.show_unlock(message)

    def show_main(self):
        root = self._screen()
        root.grid_columnconfigure(0, weight=0)
        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(0, weight=1)

        side = ctk.CTkFrame(root, fg_color=PANEL, corner_radius=0, width=310)
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)
        side.grid_columnconfigure(0, weight=1)
        side.grid_rowconfigure(2, weight=1)

        head = ctk.CTkFrame(side, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=20, pady=(22, 12))
        label(head, "◆", 18, GOLD).pack(side="left")
        label(head, " Хранилище", 18, bold=True).pack(side="left")
        self.count_label = label(head, "", 12, MUTED)
        self.count_label.pack(side="right")

        self.search = entry(side, "Поиск", height=38)
        self.search.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))
        self.search.bind("<KeyRelease>", lambda _e: self._render_list())

        self.list_frame = ctk.CTkScrollableFrame(side, fg_color="transparent",
                                                 scrollbar_button_color=LINE,
                                                 scrollbar_button_hover_color=MUTED)
        self.list_frame.grid(row=2, column=0, sticky="nsew", padx=6)

        primary(side, "+  Новая запись", lambda: self.show_form(None), height=42).grid(
            row=3, column=0, sticky="ew", padx=16, pady=(10, 8))
        foot = ctk.CTkFrame(side, fg_color="transparent")
        foot.grid(row=4, column=0, sticky="ew", padx=16, pady=(0, 16))
        foot.grid_columnconfigure((0, 1), weight=1)
        ghost(foot, "Настройки", self.show_settings).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ghost(foot, "Заблокировать", self.lock).grid(row=0, column=1, sticky="ew", padx=(4, 0))

        self.detail = ctk.CTkFrame(root, fg_color=BG, corner_radius=0)
        self.detail.grid(row=0, column=1, sticky="nsew")
        self._toast = ctk.CTkLabel(root, text="", font=font(13), fg_color=CARD, corner_radius=10,
                                   text_color=GOOD, height=38, padx=16)

        self._render_list()
        if self.selected in self.vault.entries:
            self.show_entry(self.selected)
        else:
            self.show_empty()

    def _render_list(self):
        for w in self.list_frame.winfo_children():
            w.destroy()
        entries = self.vault.entries
        self.count_label.configure(text=str(len(entries)) if entries else "")
        needle = self.search.get().strip().lower()
        names = [n for n in sorted(entries, key=str.lower)
                 if needle in n.lower() or needle in core.subtitle(entries[n]).lower()
                 or needle in entries[n].get("address", "").lower()]
        if not names:
            label(self.list_frame, "Ничего не найдено" if entries else "Пока пусто", 13, MUTED).pack(pady=30)
        for name in names:
            active = name == self.selected
            login = core.subtitle(entries[name])
            base = CARD if active else PANEL
            row = ctk.CTkFrame(self.list_frame, fg_color=base, corner_radius=10, border_width=1,
                               border_color=GOLD if active else PANEL, cursor="hand2")
            row.pack(fill="x", pady=2, padx=4)
            parts = [row, label(row, name, 14, bold=True, anchor="w", height=20)]
            parts[1].pack(fill="x", padx=14, pady=(9, 0 if login else 9))
            if login:
                parts.append(label(row, login, 12, MUTED, anchor="w", height=18))
                parts[2].pack(fill="x", padx=14, pady=(0, 9))
            for w in parts:
                w.bind("<Button-1>", lambda _e, n=name: self.show_entry(n))
                if not active:
                    w.bind("<Enter>", lambda _e, r=row: r.configure(fg_color=CARD))
                    w.bind("<Leave>", lambda _e, r=row: r.configure(fg_color=PANEL))

    def _pane(self, title, scroll=False):
        for w in self.detail.winfo_children():
            w.destroy()
        if scroll:
            pane = ctk.CTkScrollableFrame(self.detail, fg_color="transparent",
                                          scrollbar_button_color=LINE, scrollbar_button_hover_color=MUTED)
            pane.pack(fill="both", expand=True, padx=(34, 14), pady=(26, 16))
        else:
            pane = ctk.CTkFrame(self.detail, fg_color="transparent")
            pane.pack(fill="both", expand=True, padx=40, pady=(30, 24))
        label(pane, title, 26, bold=True, anchor="w", wraplength=560, justify="left").pack(fill="x", pady=(0, 16))
        return pane

    def show_empty(self):
        for w in self.detail.winfo_children():
            w.destroy()
        box = ctk.CTkFrame(self.detail, fg_color="transparent")
        box.place(relx=0.5, rely=0.46, anchor="center")
        label(box, "◆", 40, LINE).pack()
        label(box, "Выберите запись слева" if self.vault.entries else "Здесь пока ничего нет",
              16, MUTED).pack(pady=(8, 2))
        label(box, "или создайте новую", 13, "#5b6078").pack()

    def _block(self, parent, caption):
        block = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=14)
        block.pack(fill="x", pady=6)
        block.grid_columnconfigure(0, weight=1)
        label(block, caption.upper(), 11, MUTED, anchor="w").grid(row=0, column=0, sticky="w", padx=18, pady=(12, 0))
        return block

    def _value_block(self, pane, caption, value, copied=None, secret=False, shown=None, wrap=400):
        """Карточка одного поля. secret — значение скрыто точками, пока не нажать «Показать»."""
        b = self._block(pane, caption)
        hidden = "•" * 14
        v = label(b, hidden if secret else value, 15, mono=secret, anchor="w", justify="left", wraplength=wrap)
        wide = wrap == 0  # многострочное значение без переноса: отдельная строка под кнопками
        v.grid(row=1, column=0, columnspan=3 if wide else 1, sticky="w", padx=18,
               pady=(8 if wide else 2, 14))
        span = 1 if wide else 2
        col = 1
        if secret:
            def toggle():
                is_shown = v.cget("text") != hidden
                v.configure(text=hidden if is_shown else (shown or value))
                eye.configure(text="Показать" if is_shown else "Скрыть")

            eye = ghost(b, "Показать", toggle, width=96)
            eye.grid(row=0, column=1, rowspan=span, padx=(0, 6), pady=(10 if wide else 0, 0))
            col = 2
        if copied:
            ghost(b, "Копировать", lambda: self.copy(value, copied), color=GOLD if secret else TEXT,
                  width=110).grid(row=0, column=col, rowspan=span, padx=(0, 14), pady=(10 if wide else 0, 0))

    def show_entry(self, name):
        self.selected = name
        self._render_list()
        e = self.vault.entries[name]
        wallet = e.get("type") == "wallet"
        pane = self._pane(name, scroll=wallet)

        if wallet:
            if e["network"]:
                self._value_block(pane, "Сеть / монета", e["network"])
            if e["address"]:
                self._value_block(pane, "Адрес", e["address"], "Адрес скопирован", wrap=380)
            if e["seed"]:
                words = e["seed"].split()
                lines = ["   ".join(f"{i + j + 1:>2}. {w:<10}" for j, w in enumerate(words[i:i + 3])).rstrip()
                         for i in range(0, len(words), 3)]
                self._value_block(pane, f"Сид-фраза · слов: {len(words)}", e["seed"], "Сид-фраза скопирована",
                                  secret=True, shown="\n".join(lines), wrap=0)
            if e["key"]:
                self._value_block(pane, "Приватный ключ", e["key"], "Ключ скопирован", secret=True, wrap=330)
        else:
            if e["login"]:
                self._value_block(pane, "Логин / e-mail", e["login"], "Логин скопирован")
            if e["password"]:
                self._value_block(pane, "Пароль", e["password"], "Пароль скопирован", secret=True, wrap=330)
        if e["note"]:
            self._value_block(pane, "Заметка", e["note"], wrap=520)

        row = ctk.CTkFrame(pane, fg_color="transparent")
        row.pack(fill="x", pady=(14, 0))
        ghost(row, "Изменить", lambda: self.show_form(name), width=120).pack(side="left")
        ghost(row, "Удалить", lambda: self.show_delete_confirm(name), color=DANGER, width=120).pack(side="left", padx=8)

    def show_delete_confirm(self, name):
        """Удаление только после ввода четырёх случайных цифр — чтобы не удалить случайным щелчком."""
        pane = self._pane("Удалить запись?")
        label(pane, f"«{name}» будет удалена навсегда, вернуть её будет нельзя.\n"
                    "Чтобы подтвердить, введите цифры:", 14, MUTED, anchor="w", justify="left",
              wraplength=540).pack(fill="x")

        self._delete_code = f"{secrets.randbelow(10000):04d}"
        box = ctk.CTkFrame(pane, fg_color=CARD, corner_radius=14, border_width=1, border_color=DANGER)
        box.pack(anchor="w", pady=(18, 12))
        label(box, "  ".join(self._delete_code), 34, DANGER, bold=True, mono=True).pack(padx=30, pady=14)

        self.delete_entry = entry(pane, "Цифры", mono=True, width=200)
        self.delete_entry.pack(anchor="w")
        err = label(pane, "", 12, DANGER, anchor="w")
        err.pack(fill="x", pady=(8, 6))

        def confirm():
            if self.delete_entry.get().strip() != self._delete_code:
                err.configure(text="Цифры не совпадают")
                self.delete_entry.delete(0, "end")
                return
            self._delete(name)

        row = ctk.CTkFrame(pane, fg_color="transparent")
        row.pack(fill="x")
        ctk.CTkButton(row, text="Удалить навсегда", command=confirm, fg_color=DANGER, hover_color="#e0766f",
                      text_color="#1a0a09", font=font(14, True), height=44, width=180,
                      corner_radius=10).pack(side="left")
        ghost(row, "Отмена", lambda: self.show_entry(name), width=110, height=44).pack(side="left", padx=8)
        self.delete_entry.bind("<Return>", lambda _e: confirm())
        self.delete_entry.bind("<Escape>", lambda _e: self.show_entry(name))
        self.delete_entry.focus_set()

    def _delete(self, name):
        del self.vault.entries[name]
        self.vault.save()
        self.selected = None
        self._render_list()
        self.show_empty()
        self.toast("Запись удалена")

    def show_form(self, name, kind=None):
        e = self.vault.entries.get(name) if name is not None else None
        kind = (e.get("type", "password") if e else kind) or "password"
        e = e or {}
        wallet = kind == "wallet"
        pane = self._pane("Изменить запись" if name else "Новая запись", scroll=True)

        if name is None:  # тип выбирается только при создании
            def switch(choice):
                self.after(1, lambda: self.show_form(None, "wallet" if choice == "Криптокошелёк" else "password"))

            seg = ctk.CTkSegmentedButton(pane, values=["Пароль", "Криптокошелёк"], command=switch, height=36,
                                         font=font(13), fg_color=PANEL, unselected_color=PANEL,
                                         unselected_hover_color=LINE, selected_color="#8a6d2f",
                                         selected_hover_color="#9c7d39", text_color=TEXT, corner_radius=9)
            seg.set("Криптокошелёк" if wallet else "Пароль")
            seg.pack(anchor="w", pady=(0, 6))

        def caption(text):
            label(pane, text, 12, MUTED, anchor="w").pack(fill="x", pady=(6, 3))

        def field(text, value, **kw):
            caption(text)
            w = entry(pane, width=10, **kw)
            w.pack(fill="x")
            w.insert(0, value)
            return w

        def secret_field(text, value, generate=False):
            caption(text)
            row = ctk.CTkFrame(pane, fg_color="transparent")
            row.pack(fill="x")
            f = entry(row, secret=True, mono=True, width=10)
            f.pack(side="left", fill="x", expand=True)
            f.insert(0, value)

            def toggle():
                hidden = f.cget("show") != ""
                f.configure(show="" if hidden else "•")
                eye.configure(text="Скрыть" if hidden else "Показать")

            def make():
                f.delete(0, "end")
                f.insert(0, core.generate_password())
                if f.cget("show") != "":
                    toggle()

            eye = ghost(row, "Показать", toggle, width=96, height=44)
            eye.pack(side="left", padx=(8, 0))
            if generate:
                ghost(row, "Сгенерировать", make, color=GOLD, width=130, height=44).pack(side="left", padx=(8, 0))
            return f

        f_name = field("Название кошелька" if wallet else "Название — сайт или сервис", name or "")
        if wallet:
            f_net = field("Сеть / монета — например, Bitcoin, Ethereum, TRON", e.get("network", ""))
            f_addr = field("Адрес (публичный)", e.get("address", ""), mono=True)
            f_seed = secret_field("Сид-фраза — слова через пробел", e.get("seed", ""))
            f_key = secret_field("Приватный ключ, если есть", e.get("key", ""))
        else:
            f_login = field("Логин / e-mail", e.get("login", ""))
            f_pass = secret_field("Пароль", e.get("password", ""), generate=True)

        caption("Заметка")
        f_note = ctk.CTkTextbox(pane, height=84, fg_color=BG, border_color=LINE, border_width=1,
                                text_color=TEXT, font=font(14), corner_radius=10)
        f_note.pack(fill="x")
        f_note.insert("1.0", e.get("note", ""))

        err = label(pane, "", 12, DANGER, anchor="w")
        err.pack(fill="x", pady=(8, 4))

        def save():
            new_name = f_name.get().strip()
            if not new_name:
                err.configure(text="Укажите название")
                return
            if new_name != name and new_name in self.vault.entries:
                err.configure(text="Запись с таким названием уже есть")
                return
            note = f_note.get("1.0", "end").strip()
            if wallet:
                data = {"type": "wallet", "network": f_net.get().strip(), "address": f_addr.get().strip(),
                        "seed": " ".join(f_seed.get().split()), "key": f_key.get().strip(), "note": note}
            else:
                data = {"login": f_login.get().strip(), "password": f_pass.get(), "note": note}
            if name is not None and new_name != name:
                del self.vault.entries[name]
            self.vault.entries[new_name] = data
            self.vault.save()
            self.show_entry(new_name)
            self.toast("Сохранено")

        def cancel():
            self.show_entry(name) if name in self.vault.entries else self.show_empty()

        row = ctk.CTkFrame(pane, fg_color="transparent")
        row.pack(fill="x")
        primary(row, "Сохранить", save, width=150).pack(side="left")
        ghost(row, "Отмена", cancel, width=110, height=44).pack(side="left", padx=8)
        f_name.focus_set()

    # ------------------------------------------------------------ настройки

    def show_settings(self):
        self.selected = None
        self._render_list()
        pane = self._pane("Настройки", scroll=True)

        b = self._block(pane, "Сменить код")
        inner = ctk.CTkFrame(b, fg_color="transparent")
        inner.grid(row=1, column=0, sticky="w", padx=18, pady=(8, 16))
        c1 = entry(inner, "Новый код", secret=True, width=220, height=40)
        c1.grid(row=0, column=0, padx=(0, 8))
        c2 = entry(inner, "Повторите", secret=True, width=220, height=40)
        c2.grid(row=0, column=1, padx=(0, 8))
        msg = label(inner, "От 6 символов, буквы и цифры, регистр важен", 12, MUTED, anchor="w")
        msg.grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))

        def change():
            if str(btn.cget("state")) == "disabled":
                return
            code = c1.get()
            problem = core.check_code(code) or ("Коды не совпали." if code != c2.get() else None)
            if problem:
                msg.configure(text=problem, text_color=DANGER)
                return
            btn.configure(state="disabled", text="Шифруем…")
            v = self.vault

            def done(_):
                if btn.winfo_exists():
                    btn.configure(state="normal", text="Сменить")
                    c1.delete(0, "end")
                    c2.delete(0, "end")
                    msg.configure(text="Код изменён, файл перешифрован", text_color=GOOD)

            def fail(e):
                if btn.winfo_exists():
                    btn.configure(state="normal", text="Сменить")
                    msg.configure(text=f"Не получилось: {e}", text_color=DANGER)

            self.run_async(lambda: v.change_code(code), done, fail)

        btn = primary(inner, "Сменить", change, width=110, height=40)
        btn.grid(row=0, column=2)

        b = self._block(pane, "Автоблокировка")
        label(b, "Если в окне программы ничего не нажимать и не двигать мышью, хранилище "
                 "закроется и снова попросит код.", 13, MUTED, anchor="w", justify="left",
              wraplength=520).grid(row=1, column=0, sticky="w", padx=18, pady=(4, 0))

        def set_auto_lock(choice):
            self.auto_lock_seconds = AUTO_LOCK_CHOICES[choice]
            self.device.set_setting("auto_lock_seconds", self.auto_lock_seconds)
            self.toast(f"Автоблокировка: {choice}")

        seg = ctk.CTkSegmentedButton(b, values=list(AUTO_LOCK_CHOICES), command=set_auto_lock, height=36,
                                     font=font(13), fg_color=BG, unselected_color=BG,
                                     unselected_hover_color=LINE, selected_color="#8a6d2f",
                                     selected_hover_color="#9c7d39", text_color=TEXT, corner_radius=9)
        seg.set(next(k for k, v in AUTO_LOCK_CHOICES.items() if v == self.auto_lock_seconds))
        seg.grid(row=2, column=0, sticky="w", padx=18, pady=(12, 16))

        b = self._block(pane, "Секретный ключ")
        label(b, "Нужен для входа на другом устройстве. Храните только на бумаге.", 13, MUTED,
              anchor="w").grid(row=1, column=0, sticky="w", padx=18, pady=(4, 0))
        key_label = label(b, "", 16, GOLD, bold=True, mono=True, anchor="w", justify="left")

        def toggle_key():
            if key_label.cget("text"):
                key_label.configure(text="")
                key_label.grid_forget()
                key_btn.configure(text="Показать ключ")
            else:
                g = core.format_secret_key(self.vault.secret_key).split("-")
                key_label.configure(text="  ".join(g[:4]) + "\n" + "  ".join(g[4:]))
                key_label.grid(row=2, column=0, sticky="w", padx=18, pady=(10, 0))
                key_btn.configure(text="Скрыть ключ")

        key_btn = ghost(b, "Показать ключ", toggle_key, width=150)
        key_btn.grid(row=3, column=0, sticky="w", padx=18, pady=(12, 16))

        b = self._block(pane, "Это устройство")
        label(b, "Сейчас здесь для входа достаточно кода. Если забыть устройство, при следующем "
                 "входе снова понадобится секретный ключ.", 13, MUTED, anchor="w", justify="left",
              wraplength=520).grid(row=1, column=0, sticky="w", padx=18, pady=(4, 0))

        def forget():
            if messagebox.askyesno("Забыть устройство",
                                   "Секретный ключ будет удалён с этого компьютера.\n"
                                   "Убедитесь, что он записан на бумаге. Продолжить?", icon="warning"):
                self.device.forget_key(self.vault.vault_id)
                self.lock()

        ghost(b, "Забыть устройство и выйти", forget, color=DANGER, width=230).grid(
            row=2, column=0, sticky="w", padx=18, pady=(12, 16))

        b = self._block(pane, "Файл хранилища")
        label(b, self.vault.path, 13, anchor="w", justify="left", wraplength=520).grid(
            row=1, column=0, sticky="w", padx=18, pady=(4, 2))
        label(b, "Файл зашифрован — его копию можно держать на флешке или в облаке.", 12, MUTED,
              anchor="w", justify="left", wraplength=520).grid(row=2, column=0, sticky="w", padx=18, pady=(0, 14))


def main():
    App(sys.argv[1] if len(sys.argv) > 1 else None).mainloop()


if __name__ == "__main__":
    main()
