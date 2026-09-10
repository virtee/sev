# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

### Added

- Introduced [`FirmwareVersion`](crate::types::shared::FirmwareVersion) in
  `types::shared::version` as the shared major/minor/build triple for
  SEV platform status and SNP attestation reports.
- Moved `PageType` from `launch` into `types::snp` so reference and launch
  code share the SNP firmware page-type enum without coupling roles to launch.
- Added `platform` and `launch` Cargo features. `platform` gates host `/dev/sev`
  management; `launch` gates KVM guest bring-up and depends on `platform`.
  Neither is enabled by default.
- Added RATS role features: `evidence`, `reference`, `verifier`, `endorser`,
  and `attester`. Defaults include all roles except `attester` (guest-side
  `/dev/sev-guest` collection). The `attestation` module is compiled only when
  at least one role feature is enabled.
- Added `crypto-openssl` and `crypto-rust` crypto backend features.
  `verifier`, `endorser`, and `reference` require one of them. `verifier`
  implies `endorser` (certificate types used during verification).
- Introduced the `types` module with `types::snp`, `types::sev`, and
  `types::shared` for firmware ABI value types (replacing `snp::types`).
- Moved first-generation SEV ABI types (`Version`, `Build`, `State`, `Status`)
  into `types::sev`.
- Removed the `platform::types` submodule; platform re-exports ABI types from
  `types::sev` and `types::snp::platform` via `platform::sev` and
  `platform::snp`.
- Split host platform APIs into `platform::sev` (legacy SEV ioctls and types)
  and `platform::snp` (SNP ioctls and types). `platform::Firmware` remains
  the shared `/dev/sev` handle at the module root; legacy `platform_status` and
  `get_identifier` are on that shared handle (require `sev` and/or `snp`).
- Moved SNP platform types (`Config`, `SnpPlatformStatus`, `CertTableEntry`, …)
  from `platform::types::snp` into `types::snp::platform`.
- Introduced the `snp::types` module for portable SNP ABI value types shared
  across attestation and platform code. `TcbVersion` is the first type moved
  there; `platform::TcbVersion` remains available as a re-export.
- Moved `GuestPolicy` and `Version` into `snp::types`.
- Moved `CertType` and `MaskId` into `snp::types`; `platform`
  re-exports them for compatibility.
- Moved `DerivedKey` and `GuestFieldSelect` into `snp::types::derived_key`.
- Introduced the `attestation` module with `attestation::evidence::snp` for
  SNP attestation report types (`Report`, `ReportBody`, `ReportVariant`,
  `KeyInfo`, `PlatformInfo`).
- Introduced `attestation::verifier::snp` for SNP report signature
  verification and the verified `ReportBody` conversion path.
- Introduced `attestation::endorser::snp` for SNP endorsement chains
  (`Certificate`, `Chain`, `ca`, `builtin`).
- Moved the SNP `Verifiable` trait and all verification impls into
  `attestation::verifier`.
- Moved SNP report signature wire types (`SignatureAlgorithm`, `Signature`)
  into `attestation::evidence::snp` and ECDSA verification into
  `attestation::verifier::snp`.
- Introduced `attestation::attester::snp` for the SNP guest attester role
  (`attestation::attester::snp::Firmware`).
- Introduced `attestation::reference::snp::idblock` and
  `attestation::reference::snp::measurement` for SNP ID block and launch
  digest reference calculation. Shared helpers (`sev_hashes`) live directly
  under `attestation::reference`.
- Moved guest launch wire types into `types::shared::reference` (OVMF metadata
  layouts, QEMU vCPU models, OVMF firmware parsing, and SEV-ES VMSA save-area
  pages). Requires the `reference` feature.
- Introduced the `platform` module for host platform management (`/dev/sev`).
  Low-level Linux ioctl definitions remain internal under `firmware`.
- Moved legacy SEV certificate chains into `attestation::endorser::sev` and
  verification into `attestation::verifier::sev`. Moved
  `LegacyAttestationReport` into `attestation::evidence::sev`.

### Changed

- Gated SNP-only [`parser_helper`] helpers (`validate_reserved`,
  `ReadExt::read_bytes_with`) behind the `snp` feature so `sev` + `reference`
  builds compile without dead-code warnings.
- Gated [`openssl_helpers`] behind `crypto-openssl` plus either SNP verification
  (`verifier` + `snp`) or legacy SEV endorsement (`endorser` + `sev`).
- Flattened legacy SEV platform certificate types from
  `attestation::endorser::sev::sev::cert` into
  [`attestation::endorser::sev::cert`](crate::attestation::endorser::sev::cert).
- KVM guest launch (SEV, SEV-ES, and SNP) initializes the encrypting context
  through the `KVM_SEV_INIT2` ioctl exclusively.
- Legacy SEV host platform APIs (`platform` + `sev`) require `endorser` and
  `verifier` for PEK/PDH certificate types. The same requirement applies to
  `launch` + `sev` (`compile_error!` when `platform` or `launch` is enabled
  without both attestation features).
- Moved offline reference-measurement wire types from `types::shared::launch`
  to [`types::shared::reference`](crate::types::shared::reference) (`ovmf`, `vcpu`,
  `vmsa`). These types are consumed by [`attestation::reference`], not the
  runtime [`launch`](crate::launch) ioctl path.
- Removed `types::sev::Build`; use [`FirmwareVersion`](crate::types::shared::FirmwareVersion)
  for the major/minor/build triple. `types::sev::Version` remains the
  major/minor pair for ioctl and certificate layouts. `Status::firmware_version`
  replaces `Status::build`.
- Host platform APIs and guest launch are no longer compiled by default; enable
  `platform` or `launch` explicitly when needed.
- Default features are now `snp`, `evidence`, `verifier`, `endorser`,
  `reference`, and `crypto-openssl`.
- Removed `openssl` and `crypto_nossl` feature aliases; use `crypto-openssl`
  and `crypto-rust` instead.
- Guest firmware ioctls (`firmware::guest`) compile only with `attester`.
- SNP platform APIs take [`Generation`] explicitly instead of auto-detecting via
  CPUID. [`Generation::identify_host_generation`](crate::types::shared::Generation::identify_host_generation)
  remains available on Linux x86_64 as an optional helper.
- Moved `PlatformInfo` and `KeyInfo` to `attestation::evidence::snp::fields`.
  These are grouped report-body parsing views, not standalone SNP ABI types.
- Grouped `Version` and `GuestPolicy` under `snp::types::primitives` and `MaskId`
  under `snp::types::platform_config`. `GuestPolicy` is shared across the
  attestation report, launch, and id-block paths, not report-only. Flat
  re-exports at `snp::types` are unchanged.
- Grouped `DerivedKey` and `GuestFieldSelect` under `snp::types::derived_key`
  for the `SNP_GET_DERIVED_KEY` guest ioctl ABI.
- Moved `Report`, `ReportBody`, and `ReportVariant` from the guest firmware
  path into `attestation::evidence::snp`, split across `report`, `body`, and
  `variant` submodules. Flat re-exports at `attestation` are unchanged.
- Moved SNP report verification (`Verifiable` impls and verified
  `ReportBody` `TryFrom` paths) from `attestation::evidence::snp::report` into
  `attestation::verifier::snp`. Evidence retains framing and parse-only APIs.
- Moved SNP certificate chain types (`Certificate`, `Chain`, `ca`, `builtin`)
  from `certs::snp` into `attestation::endorser::snp`.
- Moved the SNP `Verifiable` trait and verification impls (certificate,
  chain, report signature, and report appraisal) into
  `attestation::verifier`.
- Removed `certs::snp`. SNP attestation now lives entirely under
  `attestation`.
- Removed the `certs` module. Legacy SEV endorsement material lives under
  `attestation::endorser::sev`.
- Moved host platform APIs from `firmware::host` to `platform`. The `firmware`
  module is now crate-internal ioctl plumbing for host and guest devices.
  Host ioctl layouts live at `firmware::host` (formerly `firmware::linux::host`).
- Moved the legacy SEV guest-owner launch session from the crate root into
  `launch::sev::session`.
- Removed the `firmware::guest::types` shim. Guest attestation device access
  moved to `attestation::attester::snp::Firmware`.
- Moved SNP guest firmware ioctl definitions from `firmware::linux::guest`
  into `firmware::guest`.
- Moved SNP launch digest and ID block wire types into `snp::types`
  (`SnpLaunchDigest`, `FamilyId`, `ImageId`, `IdBlock`, `IdAuth`, and related
  ECDSA wire layouts). OpenSSL conversions remain in
  `attestation::reference`.
- Moved QEMU vCPU model types (`CpuType`, `cpu_sig`) into
  `types::shared::reference::vcpu`. Removed `attestation::reference::vcpu_types`.
- Reorganized `attestation::reference::snp` into `reference::snp::idblock`
  and `reference::snp::measurement`. `IdMeasurements` lives in
  `reference::snp::idblock`; wire types remain in `snp::types`. Removed
  `reference::snp::idblock_types`.
- Reorganized `attestation::reference` into `reference::snp` and
  `reference::sev`. Shared helpers (`sev_hashes`, `digest`) live directly
  under `attestation::reference`.
- Removed the unused top-level `vmsa` module (superseded by
  `types::shared::reference::vmsa`).
- Removed legacy `sev` from the crate's default features. Defaults are now
  `snp` only, so SNP attestation and verification can be built on non-x86_64
  targets without pulling in first-generation SEV code. Enable the `sev`
  feature explicitly for the full pre-SNP stack: platform APIs, certificate and
  attestation report verification, launch, and session.

### Removed

- Removed deprecated launch ioctls `_INIT` and `_ES_INIT` and the unused legacy
  init marker types for KVM platform setup (superseded by `KVM_SEV_INIT2`).
- Removed the `TryFrom<&Chain> for Generation` conversion for legacy SEV
  platform certificate chains (`Generation::try_from(&chain)`, where `Chain` was
  `certs::sev::sev::Chain` and is now
  [`attestation::endorser::sev::cert::Chain`](crate::attestation::endorser::sev::cert::Chain)).
  Inferring a [`Generation`](crate::types::shared::Generation) from an exported
  chain is crate-internal, with no public replacement; its only consumer is the
  `dangerous_hw_tests` chain helper `cached_chain::get_chain`.
