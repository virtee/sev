[![Workflow Status](https://github.com/virtee/sev/workflows/test/badge.svg)](https://github.com/virtee/sev/actions?query=workflow%3A%22test%22)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/virtee/sev.svg)](https://isitmaintained.com/project/virtee/sev "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/virtee/sev.svg)](https://isitmaintained.com/project/virtee/sev "Percentage of issues still open")
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# sev

The `sev` crate provides an implementation of the [AMD Secure Encrypted
Virtualization (SEV)][SEV] APIs and the [SEV Secure Nested Paging
Firmware (SNP)][SNP] ABIs.

[SEV]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/programmer-references/55766_SEV-KM_API_Specification.pdf
[SNP]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf

### SEV APIs

The linux kernel exposes two technically distinct AMD SEV APIs:

1. An API for managing the SEV platform itself
2. An API for managing SEV-enabled KVM virtual machines

This crate implements both of those APIs and offers them to client.
code through a flexible and type-safe high-level interface.

### SNP ABIs

Like SEV, the linux kernel exposes another two different AMD SEV-SNP ABIs:

1. An ABI for managing the SEV-SNP platform itself
2. An ABI for managing SEV-SNP enabled KVM virtual machines

These new ABIs work only for **SEV-SNP** enabled hosts and guests.

This crate implements APIs for both SEV and SEV-SNP management.

### SEV and SEV-SNP enablement

By default, both the SEV and SEV-SNP libraries are compiled.
Because many modules provide support to both legacy SEV and SEV-SNP, they have been split into individual sub-modules `sev.rs` and `snp.rs`, isolating generation specific behavior.
If desired, you may opt to exclude either of the sub-modules by disabling its feature in your project's `Cargo.toml`

For example, to include the SEV APIs only:
`sev = { version = "1.2.1", default-features = false, features = ["sev"] }`

To include the SEV-SNP APIs only:
`sev = { version = "1.2.1", default-features = false, features = ["snp"] }`

### Platform Management

Refer to the [`firmware`] module for more information.

### Guest Management

Refer to the [`launch`] module for more information.

### Cryptographic Verification

To enable the cryptographic verification of certificate chains and
attestation reports, either the `openssl` or `crypto_nossl` feature
has to be enabled manually. With `openssl`, OpenSSL is used for the
verification. With `crypto_nossl`, OpenSSL is _not_ used for the
verification and instead pure-Rust libraries (e.g., `p384`, `rsa`,
etc.) are used. `openssl` and `crypto_nossl` are mutually exclusive,
and enabling both at the same time leads to a compiler error.

### Remarks

Note that the linux kernel provides access to these APIs through a set
of `ioctl`s that are meant to be called on device nodes (`/dev/kvm` and
`/dev/sev`, to be specific). As a result, these `ioctl`s form the substrate
of the `sev` crate. Binaries that result from consumers of this crate are
expected to run as a process with the necessary privileges to interact
with the device nodes.

### Using the C API

Projects in C can take advantage of the C API for the SEV [`launch`] ioctls.
To install the C API, users can use `cargo-c` with the features they would
like to produce and install a `pkg-config` file, a static library, a dynamic
library, and a C header:

`cargo cinstall --prefix=/usr --libdir=/usr/lib64`

[`firmware`]: ./src/firmware/
[`launch`]: ./src/launch/

License: Apache-2.0
