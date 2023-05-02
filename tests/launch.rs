// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "openssl")]

#[cfg(feature = "sev")]
use std::{convert::TryFrom, os::unix::io::AsRawFd};

#[cfg(feature = "sev")]
use sev::{cached_chain, firmware::host::Firmware, launch::sev::*, session::Session};

#[cfg(feature = "sev")]
use kvm_bindings::kvm_userspace_memory_region;

#[cfg(feature = "sev")]
use kvm_ioctls::{Kvm, VcpuExit};

#[cfg(feature = "sev")]
use mmarinus::{perms, Map};

#[cfg(feature = "sev")]
use serial_test::serial;

// has to be a multiple of 16
#[cfg(feature = "sev")]
const CODE: &[u8; 16] = &[
    0xf4; 16 // hlt
];

#[cfg(feature = "sev")]
#[cfg_attr(not(has_sev), ignore)]
#[test]
#[serial]
fn sev() {
    let mut sev = Firmware::open().unwrap();
    let build = sev.platform_status().unwrap().build;
    let chain = cached_chain::get().expect(
        r#"could not find certificate chain
        export with: sevctl export --full ~/.cache/amd-sev/chain"#,
    );

    let policy = Policy::default();
    let session = Session::try_from(policy).unwrap();
    let start = session.start(chain).unwrap();

    let kvm = Kvm::new().unwrap();
    let vm = kvm.create_vm().unwrap();

    const MEM_SIZE: usize = 0x1000;
    let address_space = Map::bytes(MEM_SIZE)
        .anywhere()
        .anonymously()
        .with(perms::ReadWrite)
        .unwrap();

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0,
        memory_size: address_space.size() as _,
        userspace_addr: address_space.addr() as _,
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

    launcher.inject(&secret, address_space.addr()).unwrap();

    let _handle = launcher.finish().unwrap();

    let vcpu = vm.create_vcpu(0).unwrap();
    let mut sregs = vcpu.get_sregs().unwrap();
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    vcpu.set_sregs(&sregs).unwrap();

    let mut regs = vcpu.get_regs().unwrap();
    regs.rip = std::ptr::null() as *const u64 as u64;
    regs.rflags = 2;
    vcpu.set_regs(&regs).unwrap();

    loop {
        match vcpu.run().unwrap() {
            VcpuExit::Hlt => break,
            exit_reason => panic!("unexpected exit reason: {:?}", exit_reason),
        }
    }
}
