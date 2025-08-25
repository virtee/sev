// SPDX-License-Identifier: Apache-2.0

//! Types and abstractions regarding Virtual Machine Save Areas (VMSAs).

#![allow(dead_code)]
use crate::{
    parser::{Decoder, Encoder},
    util::array::Array,
};

use super::{
    util::{TypeLoad, TypeSave},
    *,
};

use std::{fs, io, mem::size_of};

const ATTR_G_SHIFT: usize = 23;
const ATTR_B_SHIFT: usize = 22;
const ATTR_L_SHIFT: usize = 21;
const ATTR_AVL_SHIFT: usize = 20;
const ATTR_P_SHIFT: usize = 15;
const ATTR_DPL_SHIFT: usize = 13;
const ATTR_S_SHIFT: usize = 12;
const ATTR_TYPE_SHIFT: usize = 8;
const ATTR_A_SHIFT: usize = 8;
const ATTR_CS_SHIFT: usize = 11;
const ATTR_C_SHIFT: usize = 10;
const ATTR_R_SHIFT: usize = 9;
const ATTR_E_SHIFT: usize = 10;
const ATTR_W_SHIFT: usize = 9;

const ATTR_G_MASK: usize = 1 << ATTR_G_SHIFT;
const ATTR_B_MASK: usize = 1 << ATTR_B_SHIFT;
const ATTR_L_MASK: usize = 1 << ATTR_L_SHIFT;
const ATTR_AVL_MASK: usize = 1 << ATTR_AVL_SHIFT;
const ATTR_P_MASK: u16 = 1 << ATTR_P_SHIFT;
const ATTR_DPL_MASK: u16 = 1 << ATTR_DPL_SHIFT;
const ATTR_S_MASK: u16 = 1 << ATTR_S_SHIFT;
const ATTR_TYPE_MASK: u16 = 1 << ATTR_TYPE_SHIFT;
const ATTR_A_MASK: u16 = 1 << ATTR_A_SHIFT;
const ATTR_CS_MASK: u16 = 1 << ATTR_CS_SHIFT;
const ATTR_C_MASK: u16 = 1 << ATTR_C_SHIFT;
const ATTR_R_MASK: u16 = 1 << ATTR_R_SHIFT;
const ATTR_E_MASK: u16 = 1 << ATTR_E_SHIFT;
const ATTR_W_MASK: u16 = 1 << ATTR_W_SHIFT;

/// Virtual Machine Control Block
/// The layout of a VMCB struct is documented in Table B-1 of the
/// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
#[repr(C, packed)]
#[derive(Default, Serialize, Deserialize, Clone, Copy)]
pub struct VmcbSegment {
    /// Segment selector: documented in Figure 4-3 of the
    /// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
    selector: u16,

    /// Segment attributes.
    attrib: u16,

    /// Segment limit: used in comparisons with pointer offsets to prevent
    /// segment limit violations.
    limit: u32,

    /// Segment base address.
    base: u64,
}

/// Virtual Machine Save Area
/// The layout of a VMCB struct is documented in Table B-4 of the
/// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
#[repr(C, packed)]
#[derive(Default, Copy, Clone, Serialize, Deserialize)]
pub struct Vmsa {
    /// Extra segment.
    es: VmcbSegment,

    /// Code segment.
    cs: VmcbSegment,

    /// Stack segment.
    ss: VmcbSegment,

    /// Data segment.
    ds: VmcbSegment,

    /// Segment with no specific use defined by the hardware.
    fs: VmcbSegment,

    /// Segment with no specific use defined by the hardware.
    gs: VmcbSegment,

    /// Base address of the Global Descriptor Table.
    gdtr: VmcbSegment,

    /// Base address of the Local Descriptor Table.
    ldtr: VmcbSegment,

    /// Base address of the Interrupt Descriptor Table.
    idtr: VmcbSegment,

    /// Points to a valid TSS segment descriptor which resides in the GDT.
    tr: VmcbSegment,

    /// Reserved.
    reserved_1: Array<u8, 43>,

    /// Current privilege level.
    cpl: u8,

    /// Reserved.
    reserved_2: [u8; 4],

    /// Extended features enable register.
    efer: u64,

    /// Reserved.
    reserved_3: Array<u8, 104>,

    /// Bitmap of supervisor-level state components. System software sets bits
    /// in the XSS register bitmap to enable management of corresponding state
    /// component by the XSAVES/XRSTORS instructions.
    xss: u64,

    /// Control register 4.
    cr4: u64,

    /// Control register 3.
    cr3: u64,

    /// Control register 0.
    cr0: u64,

    /// Debug register 7.
    dr7: u64,

    /// Debug register 6.
    dr6: u64,

    /// RFLAGS register. Documented in Figure 3-7 of the
    /// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
    rflags: u64,

    /// Instruction pointer.
    rip: u64,

    /// Reserved.
    reserved_4: Array<u8, 88>,

    /// Stack pointer.
    rsp: u64,

    /// Reserved.
    reserved_5: [u8; 24],

    /// RAX register.
    rax: u64,

    /// STAR register. Documented in Figure 6-1 of the
    /// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
    star: u64,

    /// Target RIP of the called procedure in long mode when the calling
    /// software is in 64-bit mode.
    lstar: u64,

    /// Target RIP of the called procedure in long mode when the calling
    /// software is in compatibility mode.
    cstar: u64,

    /// Used in long mode to specify how rFLAGS is handled by SYSCALL
    /// instructions.
    sfmask: u64,

    /// This register is used by the SWAPGS instruction. This instruction
    /// exchanges the value located in KernelGSbase with the value located in
    /// "GS.base".
    kernel_gs_base: u64,

    /// CS linkage information for SYSENTER and SYSEXIT instructions.
    sysenter_cs: u64,

    /// ESP linkage information for SYSENTER and SYSEXIT instructions.
    sysenter_esp: u64,

    /// EIP linkage information for SYSENTER and SYSEXIT instructions.
    sysenter_eip: u64,

    /// Control register 2.
    cr2: u64,

    /// Reserved.
    reserved_6: [u8; 32],

    /// Register for holding guest PAT information.
    g_pat: u64,

    /// Holds the guest value of the DebugCTL MSR.
    dbgctl: u64,

    /// Holds the guest value of the LastBranchFromIP MSR.
    br_from: u64,

    /// Holds the guest value of the LastBranchToIP MSR.
    br_to: u64,

    /// Holds the guest value of the LastIntFromIP MSR.
    last_excp_from: u64,

    /// Holds the guest value of the LastIntToIPLastIntToIP MSR.
    last_excp_to: u64,

    /// Reserved.
    reserved_7: Array<u8, 72>,

    /// Speculation Control of MSRs. Documented in Section 3.2.9 of the
    /// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
    spec_ctrl: u32,

    /// Reserved.
    reserved_7b: [u8; 4],

    /// Memory Protection Key information. Documented in Section 5.6.7 of the
    /// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
    pkru: u32,

    /// Reserved.
    reserved_7a: [u8; 20],

    /// Reserved.
    reserved_8: u64,

    /// RCX register.
    rcx: u64,

    /// RDX register.
    rdx: u64,

    /// RBX register.
    rbx: u64,

    /// Reserved.
    reserved_9: u64,

    /// RBP register.
    rbp: u64,

    /// RSI register.
    rsi: u64,

    /// RDI register.
    rdi: u64,

    /// R8 register.
    r8: u64,

    /// R9 register.
    r9: u64,

    /// R10 register.
    r10: u64,

    /// R11 register.
    r11: u64,

    /// R12 register.
    r12: u64,

    /// R13 register.
    r13: u64,

    /// R14 register.
    r14: u64,

    /// R15 register.
    r15: u64,

    /// Reserved.
    reserved_10: [u8; 16],

    /// Exit code.
    sw_exit_code: u64,

    /// Values written to the vAPIC ICRH and ICRL registers.
    sw_exit_info_1: u64,

    /// Information describing the specific reason for the IPI delivery
    /// failure.
    sw_exit_info_2: u64,

    /// Scratch register.
    sw_scratch: u64,

    /// Reserved.
    reserved_11: Array<u8, 56>,

    /// XCR0 register.
    xcr0: u64,

    /// Valid bitmap.
    valid_bitmap: [u8; 16],

    /// gPA of the x87 state.
    x87_state_gpa: u64,
}

impl Decoder<()> for Vmsa {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        reader.load()
    }
}

impl Encoder<()> for Vmsa {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.save(self)
    }
}

impl Vmsa {
    /// Set VMSA values to follow initialization for an amd64 CPU.
    pub fn init_amd64(&mut self) {
        self.cr0 = 1 << 4;
        self.rip = 0xfff0;

        self.cs.selector = 0xf000;
        self.cs.base = 0xffff0000;
        self.cs.limit = 0xffff;

        self.ds.limit = 0xffff;

        self.es.limit = 0xffff;
        self.fs.limit = 0xffff;
        self.gs.limit = 0xffff;
        self.ss.limit = 0xffff;

        self.gdtr.limit = 0xffff;
        self.idtr.limit = 0xffff;

        self.ldtr.limit = 0xffff;
        self.tr.limit = 0xffff;

        self.dr6 = 0xffff0ff0;
        self.dr7 = 0x0400;
        self.rflags = 0x2;
        self.xcr0 = 0x1;
    }

    /// Set VMSA values to follow initialization for a VM running as a KVM guest.
    pub fn init_kvm(&mut self) {
        // svm_set_cr4() sets guest X86_CR4_MCE bit if host
        // has X86_CR4_MCE enabled
        self.cr4 = 0x40;

        // svm_set_efer sets guest EFER_SVME (Secure Virtual Machine enable)
        self.efer = 0x1000;

        // init_vmcb + init_sys_seg() sets
        // SVM_SELECTOR_P_MASK | SEG_TYPE_LDT
        self.ldtr.attrib = 0x0082;

        // init_vmcb + init_sys_seg() sets
        // SVM_SELECTOR_P_MASK | SEG_TYPE_BUSY_TSS16
        self.tr.attrib = 0x0083;

        // kvm_arch_vcpu_create() in arch/x86/kvm/x86.c
        self.g_pat = 0x0007040600070406;
    }

    // Based on logic in setup_regs() (src/arch/src/x86_64/regs.rs)
    /// Set VMSA values to follow initialization for a VM running as a krun guest.
    pub fn init_krun(&mut self, cpu: u64) {
        self.rsi = 0x7000;
        self.rbp = 0x8ff0;
        self.rsp = 0x8ff0;

        // Doesn't match with configure_segments_and_sregs
        self.cs.attrib =
            (ATTR_P_MASK | ATTR_S_MASK | ATTR_CS_MASK | ATTR_R_MASK) >> ATTR_TYPE_SHIFT;
        self.ds.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.es.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.ss.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK) >> ATTR_TYPE_SHIFT;
        self.fs.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.gs.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;

        if cpu > 0 {
            self.rip = 0;
            self.rsp = 0;
            self.rbp = 0;
            self.rsi = 0;

            self.cs.selector = 0x9100;
            self.cs.base = 0x91000;
        }
    }

    // Based on logic in x86_cpu_reset() (target/i386/cpu.c)
    /// Set VMSA values to follow initialization for a VM running as a QEMU guest.
    pub fn init_qemu(&mut self, _cpu: u64) {
        self.ldtr.attrib = (ATTR_P_MASK | (2 << ATTR_TYPE_SHIFT)) >> ATTR_TYPE_SHIFT;
        self.tr.attrib = (ATTR_P_MASK | (11 << ATTR_TYPE_SHIFT)) >> ATTR_TYPE_SHIFT;
        self.cs.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_CS_MASK | ATTR_R_MASK | ATTR_A_MASK)
            >> ATTR_TYPE_SHIFT;
        self.ds.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.es.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.ss.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.fs.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.gs.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;

        self.g_pat = 0x0007040600070406;
    }

    /// Set CPU SKU values for a given VMSA.
    pub fn cpu_sku(&mut self, mut family: u64, mut model: u64, mut stepping: u64) {
        stepping &= 0xf;
        model &= 0xff;
        family &= 0xfff;

        self.rdx = stepping;

        if family > 0xf {
            self.rdx |= 0xf00 | ((family - 0x0f) << 20);
        } else {
            self.rdx |= family << 8;
        }

        self.rdx |= ((model & 0xf) << 4) | ((model >> 4) << 16);
    }

    /// Set VMSA reset address register values.
    pub fn reset_addr(&mut self, ra: u32) {
        let reset_cs = ra & 0xffff0000;
        let reset_ip = ra & 0x0000ffff;

        self.rip = u64::from(reset_ip);
        self.cs.base = u64::from(reset_cs);
    }

    /// Read binary content from a passed filename and deserialize it into a
    /// VMSA struct. Validate that the passed file is 4096 bytes long,
    /// which is expected by SEV measurement validation.
    pub fn from_file(filename: &str) -> Result<Self, io::Error> {
        let data = std::fs::read(filename)?;
        if data.len() != 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Expected VMSA length 4096, was {}", data.len()),
            ));
        }
        let vmsa = Vmsa::decode(&mut &data[..], ())?;
        Ok(vmsa)
    }

    /// Serialize a VMSA struct and write it to a passed filename,
    /// This ensures it is padded to 4096 bytes which is expected
    /// by SEV measurement validation.
    pub fn to_file(&self, filename: &str) -> Result<(), io::Error> {
        let mut vmsa_buf = Vec::new();
        self.encode(&mut vmsa_buf, ())?;

        const SIZE: usize = size_of::<Vmsa>();

        // Pad to 4096 bytes
        let buf: &mut [u8] = &mut [0; 4096];
        buf[..SIZE].copy_from_slice(&vmsa_buf[..]);

        fs::write(filename, buf)?;
        Ok(())
    }
}
