// SPDX-License-Identifier: Apache-2.0

use sev::firmware::Firmware;
use sev::launch::snp::*;

use kvm_bindings::fam_wrappers::KVM_MAX_CPUID_ENTRIES;
pub use kvm_bindings::kvm_segment as KvmSegment;
use kvm_bindings::kvm_userspace_memory_region;
use kvm_ioctls::{Kvm, VcpuFd};
use mmarinus::{perms, Kind, Map};

const CODE_SIZE: usize = 0x1000;

/*
#![feature(asm, naked_functions)]

#[naked]
pub unsafe extern "sysv64" fn vm_code() -> ! {
    asm!(
        "
.set SEV_GHCB_MSR,                0xc0010130

.code32
2:
    #
    # Use VMGEXIT to request termination. At this point the reason code is
    # located in EAX, so shift it left 16 bits to the proper location.
    #
    # EAX[11:0]  => 0x100 - request termination
    # EAX[15:12] => 0x1   - REASON CODE 1
    # EAX[23:16] => 0xXX  - REASON CODE 2
    mov     eax, 0x21100
    xor     edx, edx
    mov     ecx, SEV_GHCB_MSR
    wrmsr
    rep     vmmcall

    #
    # We shouldn't come back from the VMGEXIT, but if we do, just loop.
    #
3:
    hlt
    jmp     3b
4:
.fill(({CODE_SIZE} - (4b - 2b)))
    ",
    CODE_SIZE = const CODE_SIZE,
    options(noreturn)
    )
}
 */

#[cfg_attr(not(has_sev), ignore)]
#[test]
fn snp() {
    fn set_cpu(kvm_fd: &Kvm, vcpu_fd: &mut VcpuFd) {
        vcpu_fd
            .set_cpuid2(&kvm_fd.get_supported_cpuid(KVM_MAX_CPUID_ENTRIES).unwrap())
            .unwrap();

        let mut regs = vcpu_fd.get_regs().unwrap();
        regs.rip = 0xFFFF_F000;
        vcpu_fd.set_regs(&regs).unwrap();

        let mut sregs = vcpu_fd.get_sregs().unwrap();

        sregs.cs = KvmSegment {
            base: 0x0,
            limit: 0xffffffff,
            selector: 0x8,
            type_: 0xb,
            present: 0x1,
            dpl: 0x0,
            db: 0x1,
            s: 0x1,
            l: 0x0,
            g: 0x1,
            avl: 0x0,
            unusable: 0x0,
            padding: 0x0,
        };

        sregs.ds = KvmSegment {
            base: 0x0,
            limit: 0xffffffff,
            selector: 0x10,
            type_: 0x3,
            present: 0x1,
            dpl: 0x0,
            db: 0x1,
            s: 0x1,
            l: 0x0,
            g: 0x1,
            avl: 0x0,
            unusable: 0x0,
            padding: 0x0,
        };

        sregs.cr0 |= 1; // Cr0Flags::PROTECTED_MODE_ENABLE.bits();

        vcpu_fd.set_sregs(&sregs).unwrap();
    }

    let kvm_fd = Kvm::new().unwrap();
    let mut vm_fd = kvm_fd.create_vm().unwrap();
    vm_fd.create_irq_chip().unwrap();

    let mut address_space = Map::map(CODE_SIZE)
        .anywhere()
        .anonymously()
        .known::<perms::ReadWrite>(Kind::Private)
        .unwrap();

    /*
    let code = unsafe { std::slice::from_raw_parts(vm_code as *const u8, CODE_SIZE) };

    000000000000c5a0 <snp_launch::code>:
        c5a0:   b8 00 11 02 00          mov    eax,0x21100
        c5a5:   31 d2                   xor    edx,edx
        c5a7:   b9 30 01 01 c0          mov    ecx,0xc0010130
        c5ac:   0f 30                   wrmsr
        c5ae:   f3 0f 01 d9             vmgexit
        c5b2:   f4                      hlt
        c5b3:   eb fd                   jmp    c5b2 <snp_launch::code+0x12>
        ...
      */

    let code: [u8; 21] = [
        0xb8, 0x00, 0x11, 0x02, 0x00, 0x31, 0xd2, 0xb9, 0x30, 0x01, 0x01, 0xc0, 0x0f, 0x30, 0xf3,
        0x0f, 0x01, 0xd9, 0xf4, 0xeb, 0xfd,
    ];

    address_space[..code.len()].copy_from_slice(&code);

    let mem_region = kvm_userspace_memory_region {
        slot: 0,
        guest_phys_addr: 0xFFFF_F000,
        memory_size: address_space.size() as _,
        userspace_addr: address_space.addr() as _,
        flags: 0,
    };

    unsafe {
        vm_fd.set_user_memory_region(mem_region).unwrap();
    }

    let mut sev = Firmware::open().unwrap();
    let launcher = Launcher::new(&mut vm_fd, &mut sev).unwrap();

    let start = SnpStart {
        policy: SnpPolicy {
            flags: SnpPolicyFlags::SMT,
            ..Default::default()
        },
        ..Default::default()
    };

    let mut launcher = launcher.start(start).unwrap();

    // If VMPL is not enabled, perms must be zero
    let dp = VmplPerms::empty();

    let update = SnpUpdate::new(
        mem_region.guest_phys_addr >> 12,
        address_space.as_ref(),
        false,
        SnpPageType::Normal,
        (dp, dp, dp),
    );

    launcher.update_data(update).unwrap();

    let finish = SnpFinish::new(None, None, [0u8; 32]);

    let mut vcpu_fd = launcher.as_mut().create_vcpu(0).unwrap();
    set_cpu(&kvm_fd, &mut vcpu_fd);

    launcher.finish(finish).unwrap();

    let ret = vcpu_fd.run();

    match ret {
        Ok(exit_reason) => {
            panic!(
                "Unexpected vCPU run return:\n{:?}\n{:#x?}\n{:#x?}",
                exit_reason,
                vcpu_fd.get_regs().unwrap(),
                vcpu_fd.get_sregs().unwrap(),
            );
        }
        Err(e) if e.errno() == 22 => {
            eprintln!("Got expected EINVAL vCPU return value.\nCheck dmesg for `SEV-ES guest requested termination: 0x1:0x2`")
        }
        Err(e) => {
            panic!("Unexpected vCPU return value: {:?}", e);
        }
    }
}
