# passgo — Specification

Implementation contract for `passgo`. This document defines the vault file
format, the cryptographic construction, the entry schema, and the exact
behaviour of each command. It is the reference the implementation is built
against; where code and this document disagree, this document is wrong and
should be corrected in the same change.

**Format version: 1** (unstable until v1.0)

---

## 1. Threat model

### In scope

The vault file falls into someone else's hands: a stolen or lost laptop, a
backup drive, a cloud-synced directory, a discarded disk. An attacker with the
file and unlimited offline time must not be able to recover secrets without the
master password.

### Out of scope

A compromised machine. Once code is running as the user, it can log keystrokes,
read process memory, or simply wait for the vault to be unlocked. No local
password manager defends against this, and `passgo` will not pretend to.

Also out of scope: shoulder surfing, clipboard snooping by other local
applications, and physical coercion.

### Known limitations

- **Memory hygiene is best-effort.** Go is garbage collected with a moving
  allocator. Key material held in `[]byte` is zeroed as soon as it is no longer
  needed, but Go strings are immutable and copies may persist in memory until
  collected. This is an accepted limitation, not a bug to be filed.
- **Metadata leaks file size.** The vault is a single blob, so its length
  reveals roughly how much is stored. Entry count and individual field sizes are
  not distinguishable. No padding is applied in v1.
- **Wrong password and corruption are indistinguishable.** A failed
  authentication tag means one or the other; the error message says so.

---

## 2. Cryptography

### 2.1 Key derivation

| Parameter | Value |
| --- | --- |
| Function | Argon2id (`golang.org/x/crypto/argon2.IDKey`) |
| Memory | 65536 KiB (64 MiB) |
| Iterations | 3 |
| Parallelism | 4 |
| Salt | 16 bytes from `crypto/rand` |
| Output | 32 bytes |

The salt is generated once at `init` and regenerated on `passwd`. Cost
parameters are stored in the file header so they can be raised later without
breaking existing vaults; a reader MUST use the parameters from the header it is
reading, never its own compiled-in defaults.

Implementations MUST reject header parameters outside sane bounds before
allocating memory for them — a hostile file could otherwise request a terabyte
of RAM. Accept memory in `[8192, 1048576]` KiB, iterations in `[1, 32]`, and
parallelism in `[1, 16]`.

### 2.2 Encryption

| Parameter | Value |
| --- | --- |
| Cipher | AES-256-GCM (`crypto/aes` + `crypto/cipher`) |
| Nonce | 12 bytes from `crypto/rand`, fresh on every write |
| AAD | The complete 46-byte header |
| Tag | 16 bytes, appended by `gcm.Seal` |

The entire plaintext payload is encrypted as one message. Per-entry encryption
is explicitly rejected: it would leak entry count and sizes, require nonce
management per entry, and complicate rewrites, for no benefit at personal scale.

Binding the header as additional authenticated data means an attacker cannot
edit the stored Argon2id parameters — lowering the memory cost to make a
brute-force cheaper — without invalidating the tag.

Random 96-bit nonces under a fixed key have a birthday bound around 2^32
messages. A personal vault saved a few times a day will not approach this in
any realistic lifetime, so a random nonce per write is safe here.

### 2.3 Password generation

Generated passwords use `crypto/rand` with rejection sampling to avoid modulo
bias. Default length is 20 characters. The default alphabet is
`[A-Za-z0-9]` plus `!#$%&()*+,-.:;<=>?@[]^_{|}~` (ASCII printable, excluding
space, quote, backslash, and backtick, which are prone to shell and
copy-paste trouble).

Deterministic site-and-username derivation (LessPass / Spectre style) is
**deferred**. See §7.

---

## 3. Vault file format

### 3.1 Layout

A vault is a single binary file: a plaintext header followed by one AEAD
ciphertext.

```
offset  size   field
------  -----  -----------------------------------------------
0       6      magic, ASCII "PASSGO"
6       1      format version (currently 0x01)
7       1      KDF identifier (0x01 = Argon2id)
8       4      Argon2id memory in KiB   (uint32, big endian)
12      4      Argon2id iterations      (uint32, big endian)
16      1      Argon2id parallelism     (uint8)
17      1      reserved, MUST be 0x00
18      16     salt
34      12     nonce
------  -----  -----------------------------------------------
46      n      ciphertext || 16-byte GCM tag
```

Bytes `[0, 46)` are the header and are passed verbatim as AAD. The reserved
byte exists so a future flag (compression, padding) can be added without moving
any offset.

A reader MUST verify the magic and reject an unknown format version with a clear
message rather than attempting to parse.

### 3.2 Plaintext payload

The decrypted payload is UTF-8 JSON:

```json
{
  "version": 1,
  "entries": [
    {
      "name": "github.com",
      "username": "me@example.com",
      "secret": "correct-horse-battery-staple",
      "notes": "recovery codes in the safe",
      "updated": "2026-09-06T17:20:00Z"
    }
  ]
}
```

| Field | Required | Notes |
| --- | --- | --- |
| `name` | yes | What the entry is for — a site, a token description, a vault name. Unique, matched case-insensitively. Also the entry's identity: renaming an entry means editing this field directly. |
| `username` | no | A name may have several entries with different usernames. |
| `secret` | yes | The password, token, or key. Not called `password` because it is not always one. |
| `notes` | no | Free text. |
| `updated` | yes | RFC 3339, UTC. Set on every write, including creation. |

`entries` is sorted by `name`, then `username`, on every write. This keeps
diffs stable for anyone versioning the file.

Deferred, not in v1: a stable `id` independent of `name`, unknown-field
preservation for forward compatibility (the format is unstable until v1.0, so
there is nothing yet to stay compatible with), and generation metadata on the
entry (see §7).

### 3.3 Location and permissions

Resolved in order:

1. `$PASSGO_VAULT`
2. `$XDG_DATA_HOME/passgo/vault.pgv`
3. `~/.local/share/passgo/vault.pgv`

The vault is created with mode `0600` and its directory with `0700`. On open,
`passgo` warns to stderr if the file is group- or world-readable.

### 3.4 Writing

Every write is atomic and never truncates the existing vault in place:

1. Serialize and encrypt the full payload in memory.
2. Write to a temporary file in the *same directory* (same filesystem, so the
   rename is atomic), mode `0600`.
3. `fsync` the temporary file.
4. Copy the current vault to `vault.pgv.bak` if one exists.
5. `rename` the temporary file over the vault.
6. `fsync` the containing directory.

If any step fails, the temporary file is removed and the original vault is left
untouched.

---

## 4. Master password handling

Read from `/dev/tty` with echo disabled via `golang.org/x/term`. Reading from
the TTY rather than stdin is what allows `passgo get x | pbcopy` to prompt
correctly while stdout is a pipe.

`init` and `passwd` prompt twice and require the entries to match.

The master password MUST NOT be accepted as a command-line flag under any
circumstances — arguments are visible in `ps` output and land in shell history.

`$PASSGO_MASTER` is honoured when set, for scripting and tests only. It is
documented as discouraged: environment variables are readable via `/proc` on
Linux and are inherited by child processes.

If no TTY is available and `$PASSGO_MASTER` is unset, the command fails with
exit code 2 rather than silently reading from stdin.

Each command performs exactly one derive-and-unlock. There is no session,
agent, or cached key in v1 — the master password is entered every time. At the
parameters in §2.1 an unlock costs roughly half a second, which is acceptable
for a personal tool and removes an entire class of cached-credential
vulnerabilities.

---

## 5. Query resolution

Commands taking a `<query>` resolve it against the vault in this order, stopping
at the first stage that produces matches:

1. Exact, case-insensitive match on `name`.
2. Case-insensitive substring match on `name`, `username`, or `notes`.

Outcomes:

- **Exactly one match** — proceed.
- **No match** — error to stderr, exit code 4.
- **Multiple matches** — error to stderr listing the candidates with their
  names and usernames, exit code 3. Never guess, and never fall back to "most
  recently updated." Silently returning the wrong password is the worst failure
  mode this tool has.

`-u/--username` narrows a query before resolution, so
`passgo get github.com -u me@example.com` disambiguates without an extra flag.

---

## 6. Commands

Global flags: `--vault <path>`, `--help`, `--version`.

### `passgo init`
Creates a new vault at the resolved path. Prompts for the master password
twice. Fails with exit code 1 if a vault already exists — overwriting is never
implicit.

### `passgo add <name> [flags]`
`-u --username`, `-p --password` (prompt, never an argument value; stored as
the entry's `secret`), `-g --gen [length]`, `-n --notes`.

Exactly one of `-p` or `-g` is required. `-g` prints the generated password to
stdout on success so it can be piped somewhere on first use. Rejects a
duplicate `(name, username)` pair with exit code 1.

### `passgo get <query> [--clip]`
Prints the password alone to stdout — no label, no field name, no quoting. A
trailing newline is written only when stdout is a TTY, so piping produces the
exact secret and nothing else. All prompts and diagnostics go to stderr.

`--clip` copies to the clipboard instead of printing, shelling out to `pbcopy`,
`wl-copy`, or `xclip` — whichever is found first. No clipboard library
dependency is taken. The clipboard is not auto-cleared in v1.

### `passgo show <query>`
Prints all fields with the password shown as `••••••••`. Never reveals a
secret, so it is safe to run in a shared terminal or a screen share.

### `passgo ls [query]`
Lists matching entries as an aligned table of `name`, `username`, and
`updated`. With no query, lists everything. Never prints secrets. Output is
one entry per line and stable, so it composes with `grep` and `awk`.

### `passgo edit <query> [flags]`
Same field flags as `add`, plus `--name` to rename the entry in place. Only
the flags given are changed; `-p` prompts for a new password and `-g`
generates one. Refreshes `updated`.

### `passgo rm <query>`
Prompts for confirmation unless `-f/--force` is given.

### `passgo gen [length]`
Generates a password and prints it. Does not touch the vault and does not
prompt for the master password, so it is usable as a standalone generator.

### `passgo passwd`
Prompts for the current master password, then the new one twice. Generates a
**fresh salt and nonce**, re-derives the key, and rewrites the vault. Entries
are unchanged.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | General error (I/O, vault exists, duplicate entry) |
| 2 | Usage error (bad flags, no TTY available) |
| 3 | Ambiguous query — multiple entries matched |
| 4 | No matching entry |
| 5 | Authentication failed — wrong master password or corrupted vault |

Exit code 5 is distinct so scripts can tell "you typed it wrong" from "this
entry does not exist."

---

## 7. Deferred

Recorded here so the design leaves room for them, explicitly out of scope for v1.

**Deterministic derivation.** Generating a password as
`KDF(master, name + username + counter)` rather than storing it. Would need a
`gen` object added to the entry schema (mode, rotation counter, character
policy) that v1 does not have. Deferred because a rotation counter, per-name
character policies, and legacy secrets all have to be stored regardless — so
the vault is required either way, and once it exists, storing 20 random bytes
is no harder than storing the parameters to regenerate them. Revisit once the
vault is solid.

**Session agent.** A short-lived cached key so the master password is not
retyped every command. Only if retyping actually proves annoying in daily use.

**Also deferred:** import and export, TOTP, clipboard auto-clear, vault padding
to hide size, and entry history.

Sync, sharing, browser integration, and team features are non-goals rather than
deferred work. They will not be added.
