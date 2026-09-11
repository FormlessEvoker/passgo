# passgo

A small, local-first password manager for the command line.

> Pass go. Collect your password.

`passgo` keeps your logins in a single encrypted file on your own machine. One
master password unlocks it. There is no server, no account, no sync, and no
network access of any kind — the vault is a file, and you own it.

## Status

Stable. As of v1.0.0 the vault format is frozen: a vault written by any
released build stays readable by every later release, and a future format
version ships with its migration in the same change. §3.5 of the
[specification](docs/SPECIFICATION.md) sets out the full obligation.

## Why

This started as a handful of shell functions wrapping `gpg` over a `.pw` file.
That works, but it has three problems worth fixing:

- **Reading one entry means decrypting and printing all of them**, passwords
  included, straight to the terminal.
- **No structure.** A flat text blob has no notion of "the GitHub entry," so
  there is nothing to look up, update, or delete.
- **Secrets on the command line.** Passing a master password as an argument
  leaks it into `ps` output and shell history.

`passgo` keeps the part that was good — one password, one file, no daemon — and
fixes those three things.

## Install

### Download a release binary

Prebuilt binaries for macOS, Linux, and Windows are attached to every
[release](https://github.com/FormlessEvoker/passgo/releases). Download the
archive for your platform, verify it, and put `passgo` on your `PATH`:

```sh
tar -xzf passgo_1.0.0_darwin_arm64.tar.gz
sudo install passgo /usr/local/bin/passgo
```

Each release also carries a `checksums.txt`. Verify before installing:

```sh
sha256sum --check --ignore-missing checksums.txt
```

On macOS, a binary downloaded through a browser is quarantined by Gatekeeper
and will refuse to run. Clear the flag once:

```sh
xattr -d com.apple.quarantine /usr/local/bin/passgo
```

Downloading with `curl` avoids the quarantine flag entirely.

### With the Go toolchain

```sh
go install github.com/FormlessEvoker/passgo@latest
```

This builds from source through the Go module proxy, with the module checksum
database verifying what it fetched.

### From source

```sh
git clone https://github.com/FormlessEvoker/passgo
cd passgo
make build
```

Both source paths require Go 1.26 or newer.

## Quickstart

```sh
passgo init                                  # create the vault, set a master password
passgo add github.com -u me@example.com -g   # -g generates and stores a strong password
passgo get github.com | pbcopy               # copy the password, print nothing
```

Every command in the table below is implemented. Full semantics and exit codes
are in the [specification](docs/SPECIFICATION.md).

## Commands

| Command | Description | Status |
| --- | --- | --- |
| `passgo init` | Create a new vault and set the master password. | ✅ |
| `passgo add <name>` | Add an entry. `-g` generates the password for you. | ✅ |
| `passgo get <query>` | Print the password for a single entry, and nothing else. | ✅ |
| `passgo show <query>` | Show an entry's details with the password redacted. | ✅ |
| `passgo ls [query]` | List entries. Never prints secrets. | ✅ |
| `passgo edit <query>` | Change fields on an existing entry. | ✅ |
| `passgo mv <query> <new-name>` | Rename an entry, leaving its other fields alone. | ✅ |
| `passgo rm <query>` | Delete an entry. | ✅ |
| `passgo gen [length]` | Generate a password without storing it. | ✅ |
| `passgo passwd` | Change the master password and re-encrypt the vault. | ✅ |

Four things put a secret on stdout: `get`, `gen`, and the `-g` flag on `add` and
`edit`. All four print the secret alone — no label, no quoting — and add a
trailing newline only when stdout is a terminal, so piping into `pbcopy`,
`wl-copy`, or anything else yields the exact secret and nothing more. Prompts
and diagnostics always go to stderr, so redirecting stdout never mixes them in.

Nothing else prints a secret: `show` redacts the password, and `ls` never reads
one.

Full command semantics, exit codes, and the vault format are in the
[specification](docs/SPECIFICATION.md).

## Security

The vault is encrypted with **AES-256-GCM**, using a key derived from your
master password with **Argon2id**. The cost parameters and salt are stored in
the file header and authenticated alongside the ciphertext, so they cannot be
tampered with to weaken the next unlock.

The master password is read from your terminal with echo disabled. It is never
accepted as a command-line flag.

For scripting and testing, `--master-password-file <path>` (or
`$PASSGO_MASTER_FILE`) reads it from a file instead of prompting. Prefer this
over `$PASSGO_MASTER` — a file under normal permissions beats a secret sitting
in the environment, where it's visible via `/proc` on Linux and inherited by
every child process.

**What this protects against:** someone who obtains the vault file — a stolen
laptop, a backup drive, a cloud-synced directory, a misplaced USB stick.

**What it does not protect against:** a compromised machine. If something is
already running as you, it can log your keystrokes or read the decrypted vault
out of memory, and no local password manager can prevent that.

See the threat model in the [specification](docs/SPECIFICATION.md) for the full
picture, including known limitations around clearing secrets from memory in Go.

## Dependencies

Deliberately minimal. Beyond the standard library:

- `golang.org/x/crypto` — Argon2id (not available in the standard library)
- `golang.org/x/term` — reading the master password without echoing it

Both are maintained by the Go team. There are no third-party dependencies.

## Non-goals

Sync, sharing, browser extensions, TOTP codes, and team features are out of
scope. This is a personal tool for one person on one machine.

## Documentation

- [Specification](docs/SPECIFICATION.md) — threat model, cryptography, vault
  format, command semantics, exit codes.
- [Releasing](docs/RELEASING.md) — how a version is cut and what ships with it.

## License

See [LICENSE](LICENSE).
