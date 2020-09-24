[![Workflow Status](https://github.com/enarx/sev/workflows/test/badge.svg)](https://github.com/enarx/sev/actions?query=workflow%3A%22test%22)
[![Average time to resolve an issue](https://isitmaintained.com/badge/resolution/enarx/sev.svg)](https://isitmaintained.com/project/enarx/sev "Average time to resolve an issue")
[![Percentage of issues still open](https://isitmaintained.com/badge/open/enarx/sev.svg)](https://isitmaintained.com/project/enarx/sev "Percentage of issues still open")
![Maintenance](https://img.shields.io/badge/maintenance-activly--developed-brightgreen.svg)

# sev

The `sev` crate provides an implementation of [AMD Secure Encrypted
Virtualization (SEV)](https://developer.amd.com/sev/) APIs.

The Linux kernel exposes two technically distinct AMD SEV APIs:

1. An API for managing the SEV platform itself
2. An API for managing SEV-enabled KVM virtual machines

This crate implements both of those APIs and offers them to client
code through a flexible and type-safe high level interface.

### Platform Management

Refer to the [`firmware`] module for more information.

### Guest Management

Refer to the [`launch`] module for more information.

### Remarks

Note that the Linux kernel provides access to these APIs through a set
of `ioctl`s that are meant to be called on device nodes (`/dev/kvm` and
`/dev/sev`, to be specific). As a result, these `ioctl`s form the substrate
of the `sev` crate. Binaries that result from consumers of this crate are
expected to run as a process with the necessary privileges to interact
with the device nodes.

[`firmware`]: ./firmware/index.html
[`launch`]: ./launch/index.html

License: Apache-2.0
