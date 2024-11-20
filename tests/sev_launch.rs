// SPDX-License-Identifier: Apache-2.0

#![cfg(all(
    feature = "openssl",
    target_os = "linux",
    feature = "sev",
    feature = "dangerous_hw_tests"
))]

use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuExit};
use serial_test::serial;
use sev::certs::sev::sev::Usage;
use sev::certs::sev::{sev::Certificate, Signer};
use sev::{cached_chain, firmware::host::Firmware, launch::sev::*, session::Session};
use std::slice::from_raw_parts;
use std::{convert::TryFrom, os::unix::io::AsRawFd};

// Has to be a multiple of 16
const CODE: &[u8; 16] = &[
    0xf4; 16 // hlt
];

#[cfg_attr(not(host), ignore)]
#[test]
#[serial]
fn sev_launch_test() {
    // KVM SEV type
    const KVM_X86_SEV_VM: u64 = 2;

    let mut sev = Firmware::open().unwrap();
    let build = sev.platform_status().unwrap().build;

    // Generating OCA cert and private key
    let (mut oca, prv) = Certificate::generate(Usage::OCA).expect("Generating OCA key pair");
    prv.sign(&mut oca).expect("OCA key signing");

    // Provisioning the PEK with the generated OCA key pair
    let mut pek = sev.pek_csr().expect("Cross signing request");
    prv.sign(&mut pek).expect("Sign PEK with OCA private key");
    sev.pek_cert_import(&pek, &oca)
        .expect("Import the newly-signed PEK");

    // Export the full chain to launch SEV guest
    let chain = cached_chain::get_chain();

    let policy = Policy::default();
    let session = Session::try_from(policy).unwrap();
    let start = session.start(chain).unwrap();

    let kvm = Kvm::new().unwrap();

    // Create VMft with SEV type
    let vm = kvm.create_vm_with_type(KVM_X86_SEV_VM).unwrap();

    // Allocate a 1kB page of memory for the address space of the VM.
    const MEM_SIZE: usize = 0x1000;
    let address_space = unsafe { libc::mmap(0 as _, MEM_SIZE, 3, 34, -1, 0) };

    if address_space == libc::MAP_FAILED {
        panic!("mmap() failed");
    }

    let address_space: &[u8] = unsafe { from_raw_parts(address_space as *mut u8, MEM_SIZE) };

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: MEM_SIZE as _,
        userspace_addr: address_space.as_ptr() as _,
        flags: 0,
    };

    unsafe {
        vm.set_user_memory_region(mem_region).unwrap();
    }

    let mut session = session.measure().unwrap();
    session.update_data(address_space.as_ref()).unwrap();

    let (mut launcher, measurement) = {
        let launcher = Launcher::new(vm.as_raw_fd(), sev.as_raw_fd()).unwrap();
        let mut launcher = launcher.start(start).unwrap();
        launcher.update_data(address_space.as_ref()).unwrap();
        let launcher = launcher.measure().unwrap();
        let measurement = launcher.measurement();
        (launcher, measurement)
    };

    let session = session.verify(build, measurement).unwrap();
    let secret = session.secret(HeaderFlags::default(), CODE).unwrap();

    launcher
        .inject(&secret, address_space.as_ptr() as usize)
        .unwrap();

    let _handle = launcher.finish().unwrap();

    let mut vcpu = vm.create_vcpu(0).unwrap();
    let mut sregs = vcpu.get_sregs().unwrap();
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    vcpu.set_sregs(&sregs).unwrap();

    let mut regs = vcpu.get_regs().unwrap();
    regs.rip = std::ptr::null::<u64>() as u64;
    regs.rflags = 2;
    vcpu.set_regs(&regs).unwrap();

    match vcpu.run().unwrap() {
        VcpuExit::Hlt => (),
        exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
    }

    drop(vcpu);
    drop(vm);

    sev.platform_reset().unwrap();
    cached_chain::rm_cached_chain();
}
