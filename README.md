# Password Vault

A small offline password manager for Windows. Everything lives in one encrypted file, and opening it takes two secrets: a long secret key you keep on paper and a short code you remember.

It also stores crypto wallet records: network, address, seed phrase and private key.

> **Hobby project, not audited.** Read [Limitations and warnings](#limitations-and-warnings) before trusting it with anything you can't afford to lose.

The interface is in Russian.

## Features

- **One encrypted file with a random name.** All entries are stored in one file named like `3f9a1c7e5b20d84e.dat`. Without the secrets nothing in it is readable, not even the number or names of entries.
- **Two secrets, needed together.** A random 160-bit secret key (written on paper) plus a code of 6+ letters and digits. Both feed into the same key derivation, so neither works alone.
- **Code-only unlock on a known device.** The secret key is entered once per device, then remembered under Windows DPAPI, tied to your Windows account.
- **Password entries.** Login, password, note, and a built-in generator (20 random characters).
- **Crypto wallet entries.** Network, address, seed phrase (shown numbered), private key.
- **Search** by name, login, network or address.
- **Auto-lock** after inactivity: 30 s, 1, 2, 5 or 10 min.
- **Clipboard cleared** 20 seconds after copying.
- **Hidden from screenshots**, screen recording and screen sharing.
- **Delete confirmation** by typing four random digits.
- **Automatic backups.** Every save keeps the previous version in a `backups` folder next to the vault (last 20), restorable from the settings in one click.

## How the encryption works

```
secret key (160 bit, on paper) ─┐
                                ├─► Argon2id ─► 256-bit key ─┐
code (6+ chars) ────────────────┘      ▲                     │
                                     salt                    ▼
entries (JSON) ───────────────────────────────────────► AES-256-GCM ─► ciphertext + tag
                                                             ▲
                                                 nonce + file header (AAD)
```

1. **Key derivation.** The secret key and the code go through **Argon2id** (1 GiB memory, 4 passes, 4 lanes) with a random 16-byte salt. One guess costs about a second and a gigabyte of RAM, which makes brute-forcing the short code expensive and hard to speed up on GPUs.
2. **Encryption.** Entries are serialized to JSON and encrypted with **AES-256-GCM**. A fresh 12-byte nonce is used on every save.
3. **Integrity.** The file header is authenticated together with the data. A wrong secret or any changed byte, header included, makes decryption fail. There is no separate "password check" to patch out.
4. **Device memory.** The secret key is stored in `%APPDATA%\PasswordVault\device.json`, encrypted with Windows **DPAPI** for the current user. A copy of the disk does not reveal it without logging into that Windows account.
5. **Safe writes.** Saving writes to a temporary file, flushes it, and atomically replaces the vault.

File format, big-endian:

```
MAGIC "PWV2" (4) | memory KiB (4) | iterations (4) | lanes (4) | salt (16) | vault id (8) | nonce (12) | ciphertext + GCM tag
```

Argon2 parameters are stored in the header, so they can be raised later without breaking older files.

### What an attacker needs

| Attacker has | What is left to guess | Rough estimate |
|---|---|---|
| Only the vault file | The 160-bit secret key | Not feasible |
| Vault file + secret key | The code | A random 6-character code is ~57 billion options at ~1 s and 1 GiB per guess: centuries on one PC, months on a large rig |
| Vault file + secret key + code | Nothing | Opens immediately |

The middle row only holds for a **random** code. A word with digits, a date or a name falls to a dictionary attack in hours.

## Installation

Requires Windows 10/11 and Python 3.10 or newer.

```bash
git clone https://github.com/ValerySl/password-vault.git
cd password-vault
python -m pip install -r requirements.txt
```

## Usage

Start the GUI:

```bash
python vault_gui.py
```

Or double-click `PasswordVault.vbs` to start it without a console window.

A console version is also included: `python vault.py`.

### First run

1. Choose a code: at least 6 characters, letters and digits, case-sensitive.
2. The app shows the **secret key** once: 32 characters in 8 groups, read the first line left to right, then the second.
3. Write it down on paper and type it back to confirm. You can't continue until it matches.

The vault is created next to the program under a random name such as `3f9a1c7e5b20d84e.dat`, so the name says nothing about what is inside.

On start the app opens the last vault it used. If it has none, it looks next to the program for a vault file by the marker at the start of the file, so you can rename the file to anything you like. If nothing is found, it offers to create a new one. Use "Открыть другой файл" (Open another file) on the unlock screen to pick a vault elsewhere.

### Everyday use

Enter the code. That's it.

### New device or reinstalled Windows

You need the program, a copy of the vault file, the secret key from paper and the code. After one successful unlock the device remembers the key.

## Files

| File | Where | What it is |
|---|---|---|
| `<random>.dat` | Next to the program, or wherever you chose | The encrypted vault. **Back this up.** Safe to keep on a USB stick or in the cloud |
| `backups\<name>-<date>-<time>.dat` | `backups` folder next to the vault | Previous versions of the vault, encrypted the same way. The last 20 are kept |
| `device.json` | `%APPDATA%\PasswordVault` | Secret key under DPAPI, last opened path, settings. Useless on another computer |

Never open the vault file in a text editor and save it: the file will be rejected as corrupted.

## Backups

Before every save the current file is copied to `backups`. The backup name holds the time of that version.

- **Undo a change.** Settings → Резервные копии (Backups) → Восстановить (Restore). The current version is backed up first, so a restore can be undone too.
- **Main file corrupted or deleted.** Each backup is a complete vault and opens with the same secret key and code. Replace the broken file with the newest backup (copy it next to the program, any name works).
- **Changing the code deletes old backups.** They open with the old code, and if you change it because it leaked, they must not stay behind as a way in.

Backups sit on the same disk as the vault. They protect against a broken file or a bad edit, not against a dead disk or a lost laptop: keep your own copy elsewhere too.

## Limitations and warnings

This is not Enigma. Which is good news, since Enigma got broken. Still, be realistic about what this project is:

- **Not audited.** Written as a personal project and never reviewed by a security professional. It uses well-established primitives from the `cryptography` library, but the code around them may have mistakes.
- **No recovery.** Lose the secret key and the device that remembers it, or forget the code, and the data is gone. There is no backdoor and no reset.
- **Built-in backups are local.** They live next to the vault on the same disk. A dead drive, theft or ransomware takes them along with the vault, so keep an off-device copy.
- **The random name is camouflage, not protection.** It hides the purpose of the file from a casual look. The file still starts with a fixed 4-byte marker (`PWV2`), so anyone who knows this project can recognize it. Security comes from the encryption, not from the name.
- **Malware wins.** A keylogger sees your code as you type it. Anything running under your Windows account can read the remembered secret key and, while the vault is unlocked, its contents in memory. No password manager protects a compromised computer.
- **Secrets in memory are not wiped.** Python can't reliably zero strings, so decrypted data may stay in RAM until it is overwritten.
- **The clipboard is shared.** Other programs and clipboard history (Win+V) can see what you copy. Prefer reading seed phrases from the screen over copying them.
- **Screenshot protection is limited.** It stops normal screenshots and recordings, not a phone camera, and not malware.
- **The code is the weak link.** If the secret key leaks (paper found, or someone uses your logged-in PC), only the short code stands between them and your data. Keep the paper away from the computer.
- **Windows only** for device memory and screenshot protection.

For large crypto holdings, use a hardware wallet and keep the seed phrase offline on paper or metal. This app is fine as a second copy, not as the only one.

## License

No license has been chosen yet, so all rights are reserved by default.
