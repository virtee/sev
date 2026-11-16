# Releasing `sev`

## 1. Versioning

`sev` follows [SemVer](https://semver.org) for crate versioning.

Pre-releases should be published whenever we need downstream tools to validate a change before it's final. See [Pre-releases](#pre-releases) for more information about how to cut and consume these downstream.

### What bump is this?

`sev` is a **library**, so judge against its **public API** (exported types, fn signatures, traits, public enum variants/fields).

| Bump      | When                                                              |
| --------- | ---------------------------------------------------------------- |
| **major** | Breaking change: remove/rename public items, change a signature, add a field to a non-`#[non_exhaustive]` struct/enum, tighten a bound. |
| **minor** | Backward-compatible *new* API: add a public fn/type/variant, add a trait impl. |
| **patch** | Backward-compatible bug fix, internal refactor, perf - **no** public-API change. |

Run the following command to automatically check:
```
cargo semver-checks --only-explicit-features --features openssl,sev,snp,serde
```

Note that in the future this tool will be added to `sev`'s CI to ensure PR writers are incrementing the appropriate version values.

### Versioning Tips
- Favor `#[non_exhaustive]` on enums where logical - otherwise, adding a field to an existing public struct/enum is breaking and requires a major bump.
- Dependency updates are typically a minor bump, unless it breaks `sev`'s own public API. The `cargo semver-checks` command can help identify these cases.
- It is unnecessary to increment a major, minor, or patch more than 1 past what is published in crates.io.
- Incrementing the Minimum Supported Rust Version (MSRV - i.e. `rust-version` in `Cargo.toml`) is not a `sev` API change, but can require a consumer code change to pass linting (and will break our CI if not addressed). This typically warrants a minor bump - major only in the rare case where it breaks downstream consumers.

### Pre-releases

A pre-release is **early-access**: it lets `snphost`/`snpguest` or other downstream consumers
pull the crate and test new features. Cargo won't resolve a pre-release unless a consumer pins it exactly, which makes it safe to publish as needed without affecting existing users.

- **Identifiers** follow the [SemVer spec][semver-prerelease]:
  `9.0.0-rc.1` etc. Precedence: `…-alpha < …-beta < …-rc.1 < 9.0.0`.
  - In this crate, `-alpha` and `-beta` are cut ad-hoc when a downstream tool wants to develop against a new feature. `-rc.X` is cut close to a release, to validate the crate before it's published officially.
- **Downstream invariant:** a tool may *develop* against a pre-release
  (temporarily pin `sev = "9.0.0-rc.1"`), but must **not cut its own release**
  while pinned to one - flip to the stable `sev = "9.0.0"` before tagging.
  A pre-release dependency must never leak into a published downstream tool.
  **Enforce this in CI** on the downstream tool's tagging/releasing actions so it can't happen by accident.

## 2. Dependency updates

- Gate releases on `cargo deny check` or `cargo audit` (yanks, advisories,
  licenses).
- Run `cargo tree -i <crate>` first, to confirm a direct bump is actually needed.
- `sev` is a **library**: its `Cargo.lock` governs only its own CI. Downstream
  consumers resolve from the version *requirements* in `Cargo.toml` plus their
  own lock - a lockfile fix here does **not** propagate to them.

### Yanked crates

A yanked crate in the tree is normal and usually transitive, surfacing as a
`cargo deny` / `cargo audit` **warning** (not a compile error) - an
already-locked yanked crate still builds fine. Because `sev`'s lock never
reaches consumers, a yank is **not a release gate** for a library - clear it as
routine `main` hygiene whenever `cargo deny` goes red. Typical responses, least
to most invasive:

1. **Leave it** if the yank is a mistaken/early publish and the crate still builds.
2. **Lockfile bump (preferred):** confirm the path with `cargo tree -i <crate>`,
   then pin past the yank, e.g. `cargo update -p spin --precise 0.9.9`; commit the
   lock once `cargo deny` passes.
3. **Bump the direct dependency** only if a lockfile update can't clear the yank -
   and accept any MSRV increase that pulls in.

> **Security exception:** if the yank stems from a RUSTSEC **advisory** (not a
> mistaken publish), clear it promptly and call it out in release notes, even for
> a library. Note which consumers (Kata, `guest-components`, Trustee) must run
> `cargo update` against their own lock - bumping `sev` won't move an
> already-locked transitive for them.

### Toolchain / MSRV

MSRV updates should be driven by need. A bump touches several places:
- `Cargo.toml` (`rust-version`)
- the `toolchain` matrix in `test.yml`
- all four hardcoded `toolchain:` values in `lint.yml` (one per job).

## 3. Release Process

Once the version bump is settled and dependencies are clean, cut the
release in this order:

1. **Audit the dependency graph.** `cargo deny check` and `cargo audit` must both
   be clean on `main` - resolve or consciously accept any advisory/license finding
   before proceeding.
2. **Confirm the version bump.** Verify the `Cargo.toml` version against the
   SemVer rules in section 1:
   ```
   cargo semver-checks --only-explicit-features --features openssl,sev,snp,serde
   ```
3. **Publish a release candidate.** Bump to a pre-release identifier
   (`X.Y.Z-rc.1`), commit to main, and `cargo publish` it. This is early-access only; Cargo won't
   resolve it unless a consumer pins it exactly (see [Pre-releases](#pre-releases)).
4. **Validate downstream.** Open a PR against `snphost` or `snpguest` pinning the
   release candidate (`sev = "X.Y.Z-rc.1"`) and confirm all CI tests pass. This is
   the real signal that the API change works for consumers. Iterate with
   additional `-rc.N` candidates if fixes are needed.
5. **Publish the real release.** Drop the pre-release suffix, land the final
   `Cargo.toml` version on `main`, and `cargo publish` the stable `X.Y.Z`. Tag the
   release and write release notes, calling out any security fixes and any
   downstream `cargo update` needed.

## Future CI Plans

- [`release-plz`](https://release-plz.dev) automates the mechanical loop via
[Conventional Commits][conventional-commits]:
  - `release-pr` (on push to `main`): opens a PR bumping `Cargo.toml` + changelog.
  - `release` (on merge of release-pr): publishes to crates.io, tags, cuts a GitHub Release.
  - Bump inferred from commit tags (`fix:`→patch, `feat:`→minor, `feat!:`→major),
  optionally checked with [`cargo-semver-checks`][cargo-semver-checks].
- [`cargo-semver-checks`][cargo-semver-checks] as a PR CI check - it checks what's published on crates.io against the PR code & flags if crate version should be incremented (smart enough to not trigger if it's already 1 higher than the published crate).
- `cargo audit` or `cargo deny` as a PR CI check - tending towards `cargo deny`, as it also does security compliance checks that `cargo audit` does.


<!-- links -->
[semver-prerelease]: https://semver.org/#spec-item-9
[conventional-commits]: https://www.conventionalcommits.org/
[cargo-semver-checks]: https://github.com/obi1kenobi/cargo-semver-checks
