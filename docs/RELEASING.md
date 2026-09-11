# Releasing

Releases are cut from merged pull requests, not from a local machine. You never tag by hand.

## Cutting a release

1. Open a PR into `main` as usual.
2. Before merging, add exactly one label:

   | Label | Bump | Example |
   | --- | --- | --- |
   | `release:patch` | `x.y.Z` | v1.0.0 → v1.0.1 |
   | `release:minor` | `x.Y.0` | v1.0.1 → v1.1.0 |
   | `release:major` | `X.0.0` | v1.1.0 → v2.0.0 |

3. Merge. `.github/workflows/release.yml` does the rest.

A PR with no `release:*` label merges without releasing anything. That is the
default, and most PRs should take it — batch several merges and release once.

If two labels are present, the largest bump wins (major over minor over patch).

## What the workflow does

1. Reads the latest `v*` tag, applies the label's bump, and computes the next
   version. No version number is stored in a file; the tag is the source of
   truth.
2. Creates and pushes an annotated tag.
3. Creates the GitHub release with auto-generated notes from the merged PRs.
4. Runs GoReleaser, which cross-compiles every target and attaches the archives
   and `checksums.txt` to that release.

Steps 2–4 are one job. A tag pushed with `GITHUB_TOKEN` does not trigger other
workflows, so a separate tag-triggered build workflow would need a personal
access token and gain nothing.

## Build targets

| OS | amd64 | arm64 |
| --- | --- | --- |
| macOS | ✅ | ✅ |
| Linux | ✅ | ✅ |
| Windows | ✅ | — |

Windows on arm64 is skipped deliberately: it exists, but not for a terminal
password manager's audience, and every extra artifact is one more thing users
have to tell apart.

Nothing in the dependency tree needs cgo — only `x/crypto`, `x/term`, and
`x/sys` — so `CGO_ENABLED=0` cross-compiles all of it from the Linux runner
with no per-platform toolchain.

## Version reporting

`passgo --version` reads, in order:

1. The tag stamped at link time by the release build
   (`-X .../internal/cli.version={{ .Tag }}`).
2. Otherwise the module version from `debug.ReadBuildInfo` — a real version for
   `go install ...@v1.0.0`, a git-derived pseudo-version for a local build.
3. `"dev"` if there is no build info at all.

The stamp exists because a release binary is cross-compiled from a detached
checkout in CI, where the VCS state Go reads for `Main.Version` is not
guaranteed to be the tag being published. Recording the tag explicitly removes
the guesswork.

## Testing release changes locally

Install [GoReleaser](https://goreleaser.com/install/), then:

```sh
make release-check   # validate .goreleaser.yaml
make snapshot        # build every target into dist/, publish nothing
```

CI runs both on every PR (the `release-dry-run` job), so a broken config or a
target that stopped compiling fails on the PR rather than halfway through a
release that has already pushed a tag.

## Compatibility obligations

As of v1.0.0 the vault format is stable. §3.5 of the
[specification](SPECIFICATION.md) sets out what that means: every format and
payload version written by a release must have a path forward, and a version
bump ships its migration in the same change.

A `release:major` bump has a second consequence. Go's module rules require the
module path to carry the major version from v2 on, so releasing v2.0.0 means
changing `module github.com/FormlessEvoker/passgo` to `.../passgo/v2` in
`go.mod` and updating every internal import — in the same PR as the label.

## Not yet set up

**Homebrew.** GoReleaser can keep a formula in a personal tap
(`FormlessEvoker/homebrew-tap`) up to date automatically, which is roughly ten
lines of config plus a second repository and a cross-repo token stored as an
Actions secret. Ongoing maintenance after that is close to zero. Deferred, not
rejected.

**Signing and provenance.** `checksums.txt` proves an artifact was not altered
in transit, but not who built it. Cosign keyless signing via the GitHub OIDC
token and SLSA provenance attestation are the usual next step for a tool that
handles credentials, and neither needs key management.
