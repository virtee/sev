// SPDX-License-Identifier: Apache-2.0

//! Operations to build and interact with an SEV-ES VMSA
use crate::{
    error::MeasurementError,
    measurement::vcpu_types::CpuType,
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};
use bitfield::bitfield;
use std::{
    fmt,
    io::{Read, Write},
    str::FromStr,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "serde")]
use serde_big_array::BigArray;

/// Different Possible SEV modes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SevMode {
    /// SEV
    Sev,
    /// SEV-ES
    SevEs,
    /// SEV-SNP
    SevSnp,
}

impl FromStr for SevMode {
    type Err = MeasurementError;

    fn from_str(s: &str) -> Result<Self, MeasurementError> {
        match s.to_lowercase().as_str() {
            "sev" => Ok(SevMode::Sev),
            "sev-es" | "seves" => Ok(SevMode::SevEs),
            "sev-snp" | "sevsnp" => Ok(SevMode::SevSnp),
            _ => Err(MeasurementError::InvalidSevModeError(s.to_string())),
        }
    }
}

/// Supported Virtual Machine Monitors
#[derive(Clone, Copy, PartialEq)]
pub enum VMMType {
    /// QEMU
    QEMU = 1,
    /// EC2
    EC2 = 2,
    /// KRUN
    KRUN = 3,
}

impl FromStr for VMMType {
    type Err = MeasurementError;

    fn from_str(value: &str) -> Result<Self, MeasurementError> {
        match value.to_lowercase().as_str() {
            "qemu" => Ok(VMMType::QEMU),
            "ec2" => Ok(VMMType::EC2),
            "krun" => Ok(VMMType::KRUN),
            _ => Err(MeasurementError::InvalidVcpuTypeError(value.to_string())),
        }
    }
}

impl fmt::Debug for VMMType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VMMType::QEMU => write!(f, "qemu"),
            VMMType::EC2 => write!(f, "ec2"),
            VMMType::KRUN => write!(f, "krun"),
        }
    }
}

/// Virtual Machine Control Block
/// The layout of a VMCB struct is documented in Table B-1 of the
/// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default, Debug, Clone, Copy)]
struct VmcbSeg {
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

impl Encoder<()> for VmcbSeg {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.selector, ())?;
        writer.write_bytes(self.attrib, ())?;
        writer.write_bytes(self.limit, ())?;
        writer.write_bytes(self.base, ())?;
        Ok(())
    }
}

impl Decoder<()> for VmcbSeg {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let selector = reader.read_bytes()?;
        let attrib = reader.read_bytes()?;
        let limit = reader.read_bytes()?;
        let base = reader.read_bytes()?;
        Ok(Self {
            selector,
            attrib,
            limit,
            base,
        })
    }
}

impl ByteParser<()> for VmcbSeg {
    type Bytes = [u8; Self::SIZE];
    const EXPECTED_LEN: Option<usize> = Some(Self::SIZE);
}

impl VmcbSeg {
    const SIZE: usize = 16;

    fn new(selector: u16, attrib: u16, limit: u32, base: u64) -> Self {
        Self {
            selector,
            attrib,
            limit,
            base,
        }
    }
}

bitfield! {
    /// Kernel features that when enabled could affect the VMSA.
    ///
    /// | Bit(s) | Name
    /// |--------|------|
    /// | 0 | SNPActive |
    /// | 1 | vTOM |
    /// | 2 | ReflectVC |
    /// | 3 | RestrictedInjection |
    /// | 4 | AlternateInjection |
    /// | 5 | DebugSwap |
    /// | 6 | PreventHostIBS |
    /// | 7 | BTBIsolation |
    /// | 8 | VmplSSS |
    /// | 9 | SecureTSC |
    /// | 10 | VmgexitParameter |
    /// | 12 | IbsVirtualization |
    /// | 14 | VmsaRegProt |
    /// | 15 | SmtProtection |
    /// | 63:16 | Reserved, SBZ |
    #[repr(C)]
    #[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct GuestFeatures(u64);
    impl Debug;
    /// SNPActive
    pub snp_active, _: 0;
    /// vTom
    pub v_tom, _: 1;
    /// ReflectVC
    pub reflect_vc, _: 2;
    /// RestrictedInjection
    pub restricted_injection, _: 3;
    /// AlternateInjection
    pub alternate_injection, _: 4;
    /// DebugSwap
    pub debug_swap, _: 5;
    /// PreventHostIbs
    pub prevent_host_ibs, _: 6;
    /// BTBIsolation
    pub btb_isolation, _: 7;
    /// VmplSSS
    pub vmpl_sss, _: 8;
    /// SecureTSC
    pub secure_tsc, _: 9;
    /// VmgExitParameter
    pub vmg_exit_parameter, _: 10;
    /// IbsVirtualization
    pub ibs_virtualization, _: 12;
    /// VmsaRegProt
    pub vmsa_reg_prot, _: 14;
    ///SmtProtection
    pub smt_protection, _: 15;
}

impl Encoder<()> for GuestFeatures {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.0, ())?;
        Ok(())
    }
}

impl Decoder<()> for GuestFeatures {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let features = reader.read_bytes()?;
        Ok(Self(features))
    }
}

impl ByteParser<()> for GuestFeatures {
    type Bytes = [u8; 8];
    const EXPECTED_LEN: Option<usize> = Some(8);
}

impl Default for GuestFeatures {
    fn default() -> Self {
        Self(0x1)
    }
}

/// SEV-ES VMSA page
/// The names of the fields are taken from struct sev_es_work_area in the linux kernel:
/// https://github.com/AMDESE/linux/blob/sev-snp-v12/arch/x86/include/asm/svm.h#L318
/// (following the definitions in AMD APM Vol 2 Table B-4)
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy)]
struct SevEsSaveArea {
    es: VmcbSeg,
    cs: VmcbSeg,
    ss: VmcbSeg,
    ds: VmcbSeg,
    fs: VmcbSeg,
    gs: VmcbSeg,
    gdtr: VmcbSeg,
    ldtr: VmcbSeg,
    idtr: VmcbSeg,
    tr: VmcbSeg,
    vmpl0_ssp: u64,
    vmpl1_ssp: u64,
    vmpl2_ssp: u64,
    vmpl3_ssp: u64,
    u_cet: u64,

    // reserved_0xc8
    #[cfg(feature = "unsafe_parser")]
    reserved_0xc8: [u8; 2],

    vmpl: u8,
    cpl: u8,

    // reserved_0xcc
    #[cfg(feature = "unsafe_parser")]
    reserved_0xcc: [u8; 4],

    efer: u64,

    // reserved_0xd8
    #[cfg(feature = "unsafe_parser")]
    reserved_0xd8: [u8; 104],

    xss: u64,
    cr4: u64,
    cr3: u64,
    cr0: u64,
    dr7: u64,
    dr6: u64,
    rflags: u64,
    rip: u64,
    dr0: u64,
    dr1: u64,
    dr2: u64,
    dr3: u64,
    dr0_addr_mask: u64,
    dr1_addr_mask: u64,
    dr2_addr_mask: u64,
    dr3_addr_mask: u64,

    // reserved_0x1c0
    #[cfg(feature = "unsafe_parser")]
    reserved_0x1c0: [u8; 24],

    rsp: u64,
    s_cet: u64,
    ssp: u64,
    isst_addr: u64,
    rax: u64,
    star: u64,
    lstar: u64,
    cstar: u64,
    sfmask: u64,
    kernel_gs_base: u64,
    sysenter_cs: u64,
    sysenter_esp: u64,
    sysenter_eip: u64,
    cr2: u64,

    // reserved_0x248
    #[cfg(feature = "unsafe_parser")]
    reserved_0x248: [u8; 32],

    g_pat: u64,
    dbgctrl: u64,
    br_from: u64,
    br_to: u64,
    last_excp_from: u64,
    last_excp_to: u64,

    // reserved_0x298
    #[cfg(feature = "unsafe_parser")]
    reserved_0x298: [u8; 80],

    pkru: u32,
    tsc_aux: u32,

    // reserved_0x2f0
    #[cfg(feature = "unsafe_parser")]
    reserved_0x2f0: [u8; 24],

    rcx: u64,
    rdx: u64,
    rbx: u64,

    // reserved_0x320
    #[cfg(feature = "unsafe_parser")]
    reserved_0x320: [u8; 8],

    rbp: u64,
    rsi: u64,
    rdi: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,

    // reserved_0x380
    #[cfg(feature = "unsafe_parser")]
    reserved_0x380: [u8; 16],

    guest_exit_info_1: u64,
    guest_exit_info_2: u64,
    guest_exit_int_info: u64,
    guest_nrip: u64,
    sev_features: u64,
    vintr_ctrl: u64,
    guest_exit_code: u64,
    virtual_tom: u64,
    tlb_id: u64,
    pcpu_id: u64,
    event_inj: u64,
    xcr0: u64,

    // reserved_0x3f0
    #[cfg(feature = "unsafe_parser")]
    reserved_0x3f0: [u8; 16],

    /* Floating Point Area */
    x87_dp: u64,
    mxcsr: u32,
    x87_ftw: u16,
    x87_fsw: u16,
    x87_fcw: u16,
    x87_fop: u16,
    x87_ds: u16,
    x87_cs: u16,
    x87_rip: u64,
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    fpreg_x87: [u8; 80],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    fpreg_xmm: [u8; 256],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    fpreg_ymm: [u8; 256],
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))]
    manual_padding: [u8; 2448],
}

impl Default for SevEsSaveArea {
    fn default() -> Self {
        #[cfg(not(feature = "unsafe_parser"))]
        {
            Self {
                es: Default::default(),
                cs: Default::default(),
                ss: Default::default(),
                ds: Default::default(),
                fs: Default::default(),
                gs: Default::default(),
                gdtr: Default::default(),
                ldtr: Default::default(),
                idtr: Default::default(),
                tr: Default::default(),
                vmpl0_ssp: Default::default(),
                vmpl1_ssp: Default::default(),
                vmpl2_ssp: Default::default(),
                vmpl3_ssp: Default::default(),
                u_cet: Default::default(),
                vmpl: Default::default(),
                cpl: Default::default(),
                efer: Default::default(),
                xss: Default::default(),
                cr4: Default::default(),
                cr3: Default::default(),
                cr0: Default::default(),
                dr7: Default::default(),
                dr6: Default::default(),
                rflags: Default::default(),
                rip: Default::default(),
                dr0: Default::default(),
                dr1: Default::default(),
                dr2: Default::default(),
                dr3: Default::default(),
                dr0_addr_mask: Default::default(),
                dr1_addr_mask: Default::default(),
                dr2_addr_mask: Default::default(),
                dr3_addr_mask: Default::default(),
                rsp: Default::default(),
                s_cet: Default::default(),
                ssp: Default::default(),
                isst_addr: Default::default(),
                rax: Default::default(),
                star: Default::default(),
                lstar: Default::default(),
                cstar: Default::default(),
                sfmask: Default::default(),
                kernel_gs_base: Default::default(),
                sysenter_cs: Default::default(),
                sysenter_esp: Default::default(),
                sysenter_eip: Default::default(),
                cr2: Default::default(),
                g_pat: Default::default(),
                dbgctrl: Default::default(),
                br_from: Default::default(),
                br_to: Default::default(),
                last_excp_from: Default::default(),
                last_excp_to: Default::default(),
                pkru: Default::default(),
                tsc_aux: Default::default(),
                rcx: Default::default(),
                rdx: Default::default(),
                rbx: Default::default(),
                rbp: Default::default(),
                rsi: Default::default(),
                rdi: Default::default(),
                r8: Default::default(),
                r9: Default::default(),
                r10: Default::default(),
                r11: Default::default(),
                r12: Default::default(),
                r13: Default::default(),
                r14: Default::default(),
                r15: Default::default(),
                guest_exit_info_1: Default::default(),
                guest_exit_info_2: Default::default(),
                guest_exit_int_info: Default::default(),
                guest_nrip: Default::default(),
                sev_features: Default::default(),
                vintr_ctrl: Default::default(),
                guest_exit_code: Default::default(),
                virtual_tom: Default::default(),
                tlb_id: Default::default(),
                pcpu_id: Default::default(),
                event_inj: Default::default(),
                xcr0: Default::default(),
                x87_dp: Default::default(),
                mxcsr: Default::default(),
                x87_ftw: Default::default(),
                x87_fsw: Default::default(),
                x87_fcw: Default::default(),
                x87_fop: Default::default(),
                x87_ds: Default::default(),
                x87_cs: Default::default(),
                x87_rip: Default::default(),
                fpreg_x87: [0u8; 80],
                fpreg_xmm: [0u8; 256],
                fpreg_ymm: [0u8; 256],
                manual_padding: [0u8; 2448],
            }
        }
        #[cfg(feature = "unsafe_parser")]
        {
            Self {
                es: Default::default(),
                cs: Default::default(),
                ss: Default::default(),
                ds: Default::default(),
                fs: Default::default(),
                gs: Default::default(),
                gdtr: Default::default(),
                ldtr: Default::default(),
                idtr: Default::default(),
                tr: Default::default(),
                vmpl0_ssp: Default::default(),
                vmpl1_ssp: Default::default(),
                vmpl2_ssp: Default::default(),
                vmpl3_ssp: Default::default(),
                u_cet: Default::default(),
                reserved_0xc8: [0u8; 2],
                vmpl: Default::default(),
                cpl: Default::default(),
                reserved_0xcc: [0u8; 4],
                efer: Default::default(),
                reserved_0xd8: [0u8; 104],
                xss: Default::default(),
                cr4: Default::default(),
                cr3: Default::default(),
                cr0: Default::default(),
                dr7: Default::default(),
                dr6: Default::default(),
                rflags: Default::default(),
                rip: Default::default(),
                dr0: Default::default(),
                dr1: Default::default(),
                dr2: Default::default(),
                dr3: Default::default(),
                dr0_addr_mask: Default::default(),
                dr1_addr_mask: Default::default(),
                dr2_addr_mask: Default::default(),
                dr3_addr_mask: Default::default(),
                reserved_0x1c0: [0u8; 24],
                rsp: Default::default(),
                s_cet: Default::default(),
                ssp: Default::default(),
                isst_addr: Default::default(),
                rax: Default::default(),
                star: Default::default(),
                lstar: Default::default(),
                cstar: Default::default(),
                sfmask: Default::default(),
                kernel_gs_base: Default::default(),
                sysenter_cs: Default::default(),
                sysenter_esp: Default::default(),
                sysenter_eip: Default::default(),
                cr2: Default::default(),
                reserved_0x248: [0u8; 32],
                g_pat: Default::default(),
                dbgctrl: Default::default(),
                br_from: Default::default(),
                br_to: Default::default(),
                last_excp_from: Default::default(),
                last_excp_to: Default::default(),
                reserved_0x298: [0u8; 80],
                pkru: Default::default(),
                tsc_aux: Default::default(),
                reserved_0x2f0: [0u8; 24],
                rcx: Default::default(),
                rdx: Default::default(),
                rbx: Default::default(),
                reserved_0x320: [0u8; 8],
                rbp: Default::default(),
                rsi: Default::default(),
                rdi: Default::default(),
                r8: Default::default(),
                r9: Default::default(),
                r10: Default::default(),
                r11: Default::default(),
                r12: Default::default(),
                r13: Default::default(),
                r14: Default::default(),
                r15: Default::default(),
                reserved_0x380: [0u8; 16],
                guest_exit_info_1: Default::default(),
                guest_exit_info_2: Default::default(),
                guest_exit_int_info: Default::default(),
                guest_nrip: Default::default(),
                sev_features: Default::default(),
                vintr_ctrl: Default::default(),
                guest_exit_code: Default::default(),
                virtual_tom: Default::default(),
                tlb_id: Default::default(),
                pcpu_id: Default::default(),
                event_inj: Default::default(),
                xcr0: Default::default(),
                reserved_0x3f0: [0u8; 16],
                x87_dp: Default::default(),
                mxcsr: Default::default(),
                x87_ftw: Default::default(),
                x87_fsw: Default::default(),
                x87_fcw: Default::default(),
                x87_fop: Default::default(),
                x87_ds: Default::default(),
                x87_cs: Default::default(),
                x87_rip: Default::default(),
                fpreg_x87: [0u8; 80],
                fpreg_xmm: [0u8; 256],
                fpreg_ymm: [0u8; 256],
                manual_padding: [0u8; 2448],
            }
        }
    }
}

impl Encoder<()> for SevEsSaveArea {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.es, ())?;
        writer.write_bytes(self.cs, ())?;
        writer.write_bytes(self.ss, ())?;
        writer.write_bytes(self.ds, ())?;
        writer.write_bytes(self.fs, ())?;
        writer.write_bytes(self.gs, ())?;
        writer.write_bytes(self.gdtr, ())?;
        writer.write_bytes(self.ldtr, ())?;
        writer.write_bytes(self.idtr, ())?;
        writer.write_bytes(self.tr, ())?;
        writer.write_bytes(self.vmpl0_ssp, ())?;
        writer.write_bytes(self.vmpl1_ssp, ())?;
        writer.write_bytes(self.vmpl2_ssp, ())?;
        writer.write_bytes(self.vmpl3_ssp, ())?;
        writer.write_bytes(self.u_cet, ())?;

        // reserved_0xc8
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<2>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved_0xc8, ())?;

        writer.write_bytes(self.vmpl, ())?;
        writer.write_bytes(self.cpl, ())?;
        // reserved_0xcc
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<4>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved_0xcc, ())?;

        writer.write_bytes(self.efer, ())?;

        // reserved_0xd8
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<104>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved_0xd8, ())?;

        writer.write_bytes(self.xss, ())?;
        writer.write_bytes(self.cr4, ())?;
        writer.write_bytes(self.cr3, ())?;
        writer.write_bytes(self.cr0, ())?;
        writer.write_bytes(self.dr7, ())?;
        writer.write_bytes(self.dr6, ())?;
        writer.write_bytes(self.rflags, ())?;
        writer.write_bytes(self.rip, ())?;
        writer.write_bytes(self.dr0, ())?;
        writer.write_bytes(self.dr1, ())?;
        writer.write_bytes(self.dr2, ())?;
        writer.write_bytes(self.dr3, ())?;
        writer.write_bytes(self.dr0_addr_mask, ())?;
        writer.write_bytes(self.dr1_addr_mask, ())?;
        writer.write_bytes(self.dr2_addr_mask, ())?;
        writer.write_bytes(self.dr3_addr_mask, ())?;

        // reserved_0x1c0
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<24>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved_0x1c0, ())?;

        writer.write_bytes(self.rsp, ())?;
        writer.write_bytes(self.s_cet, ())?;
        writer.write_bytes(self.ssp, ())?;
        writer.write_bytes(self.isst_addr, ())?;
        writer.write_bytes(self.rax, ())?;
        writer.write_bytes(self.star, ())?;
        writer.write_bytes(self.lstar, ())?;
        writer.write_bytes(self.cstar, ())?;
        writer.write_bytes(self.sfmask, ())?;
        writer.write_bytes(self.kernel_gs_base, ())?;
        writer.write_bytes(self.sysenter_cs, ())?;
        writer.write_bytes(self.sysenter_esp, ())?;
        writer.write_bytes(self.sysenter_eip, ())?;
        writer.write_bytes(self.cr2, ())?;

        // reserved_0x248
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<32>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved_0x248, ())?;

        writer.write_bytes(self.g_pat, ())?;
        writer.write_bytes(self.dbgctrl, ())?;
        writer.write_bytes(self.br_from, ())?;
        writer.write_bytes(self.br_to, ())?;
        writer.write_bytes(self.last_excp_from, ())?;
        writer.write_bytes(self.last_excp_to, ())?;

        // reserved_0x298
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<80>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved_0x298, ())?;

        writer.write_bytes(self.pkru, ())?;
        writer.write_bytes(self.tsc_aux, ())?;

        // reserved_0x2f0
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<24>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved_0x2f0, ())?;

        writer.write_bytes(self.rcx, ())?;
        writer.write_bytes(self.rdx, ())?;
        writer.write_bytes(self.rbx, ())?;

        // reserved_0x320
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<8>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved_0x320, ())?;

        writer.write_bytes(self.rbp, ())?;
        writer.write_bytes(self.rsi, ())?;
        writer.write_bytes(self.rdi, ())?;
        writer.write_bytes(self.r8, ())?;
        writer.write_bytes(self.r9, ())?;
        writer.write_bytes(self.r10, ())?;
        writer.write_bytes(self.r11, ())?;
        writer.write_bytes(self.r12, ())?;
        writer.write_bytes(self.r13, ())?;
        writer.write_bytes(self.r14, ())?;
        writer.write_bytes(self.r15, ())?;

        // reserved_0x380
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<16>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved_0x380, ())?;

        writer.write_bytes(self.guest_exit_info_1, ())?;
        writer.write_bytes(self.guest_exit_info_2, ())?;
        writer.write_bytes(self.guest_exit_int_info, ())?;
        writer.write_bytes(self.guest_nrip, ())?;
        writer.write_bytes(self.sev_features, ())?;
        writer.write_bytes(self.vintr_ctrl, ())?;
        writer.write_bytes(self.guest_exit_code, ())?;
        writer.write_bytes(self.virtual_tom, ())?;
        writer.write_bytes(self.tlb_id, ())?;
        writer.write_bytes(self.pcpu_id, ())?;
        writer.write_bytes(self.event_inj, ())?;
        writer.write_bytes(self.xcr0, ())?;

        // reserved_0x3f0
        #[cfg(not(feature = "unsafe_parser"))]
        writer.skip_bytes::<16>()?;
        #[cfg(feature = "unsafe_parser")]
        writer.write_bytes(self.reserved_0x3f0, ())?;

        writer.write_bytes(self.x87_dp, ())?;
        writer.write_bytes(self.mxcsr, ())?;
        writer.write_bytes(self.x87_ftw, ())?;
        writer.write_bytes(self.x87_fsw, ())?;
        writer.write_bytes(self.x87_fcw, ())?;
        writer.write_bytes(self.x87_fop, ())?;
        writer.write_bytes(self.x87_ds, ())?;
        writer.write_bytes(self.x87_cs, ())?;
        writer.write_bytes(self.x87_rip, ())?;
        writer.write_bytes(self.fpreg_x87, ())?;
        writer.write_bytes(self.fpreg_xmm, ())?;
        writer.write_bytes(self.fpreg_ymm, ())?;
        writer.write_bytes(self.manual_padding, ())?;

        Ok(())
    }
}

impl Decoder<()> for SevEsSaveArea {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let es = reader.read_bytes()?;
        let cs = reader.read_bytes()?;
        let ss = reader.read_bytes()?;
        let ds = reader.read_bytes()?;
        let fs = reader.read_bytes()?;
        let gs = reader.read_bytes()?;
        let gdtr = reader.read_bytes()?;
        let ldtr = reader.read_bytes()?;
        let idtr = reader.read_bytes()?;
        let tr = reader.read_bytes()?;
        let vmpl0_ssp = reader.read_bytes()?;
        let vmpl1_ssp = reader.read_bytes()?;
        let vmpl2_ssp = reader.read_bytes()?;
        let vmpl3_ssp = reader.read_bytes()?;
        let u_cet = reader.read_bytes()?;

        // reserved_0xc8
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<2>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved_0xc8 = reader.read_bytes()?;

        let vmpl = reader.read_bytes()?;
        let cpl = reader.read_bytes()?;

        // reserved_0xcc
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<4>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved_0xcc = reader.read_bytes()?;

        let efer = reader.read_bytes()?;

        // reserved 0xd8
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<104>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved_0xd8 = reader.read_bytes()?;

        let xss = reader.read_bytes()?;
        let cr4 = reader.read_bytes()?;
        let cr3 = reader.read_bytes()?;
        let cr0 = reader.read_bytes()?;
        let dr7 = reader.read_bytes()?;
        let dr6 = reader.read_bytes()?;
        let rflags = reader.read_bytes()?;
        let rip = reader.read_bytes()?;
        let dr0 = reader.read_bytes()?;
        let dr1 = reader.read_bytes()?;
        let dr2 = reader.read_bytes()?;
        let dr3 = reader.read_bytes()?;
        let dr0_addr_mask = reader.read_bytes()?;
        let dr1_addr_mask = reader.read_bytes()?;
        let dr2_addr_mask = reader.read_bytes()?;
        let dr3_addr_mask = reader.read_bytes()?;

        // reserved_0x1c0
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<24>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved_0x1c0 = reader.read_bytes()?;

        let rsp = reader.read_bytes()?;
        let s_cet = reader.read_bytes()?;
        let ssp = reader.read_bytes()?;
        let isst_addr = reader.read_bytes()?;
        let rax = reader.read_bytes()?;
        let star = reader.read_bytes()?;
        let lstar = reader.read_bytes()?;
        let cstar = reader.read_bytes()?;
        let sfmask = reader.read_bytes()?;
        let kernel_gs_base = reader.read_bytes()?;
        let sysenter_cs = reader.read_bytes()?;
        let sysenter_esp = reader.read_bytes()?;
        let sysenter_eip = reader.read_bytes()?;
        let cr2 = reader.read_bytes()?;

        // reserved_0x248
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<32>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved_0x248 = reader.read_bytes()?;

        let g_pat = reader.read_bytes()?;
        let dbgctrl = reader.read_bytes()?;
        let br_from = reader.read_bytes()?;
        let br_to = reader.read_bytes()?;
        let last_excp_from = reader.read_bytes()?;
        let last_excp_to = reader.read_bytes()?;

        // reserved_0x298
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<80>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved_0x298 = reader.read_bytes()?;

        let pkru = reader.read_bytes()?;
        let tsc_aux = reader.read_bytes()?;

        // reserved_0x2f0
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<24>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved_0x2f0 = reader.read_bytes()?;

        let rcx = reader.read_bytes()?;
        let rdx = reader.read_bytes()?;
        let rbx = reader.read_bytes()?;

        // reserved_0x320
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<8>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved_0x320 = reader.read_bytes()?;

        let rbp = reader.read_bytes()?;
        let rsi = reader.read_bytes()?;
        let rdi = reader.read_bytes()?;
        let r8 = reader.read_bytes()?;
        let r9 = reader.read_bytes()?;
        let r10 = reader.read_bytes()?;
        let r11 = reader.read_bytes()?;
        let r12 = reader.read_bytes()?;
        let r13 = reader.read_bytes()?;
        let r14 = reader.read_bytes()?;
        let r15 = reader.read_bytes()?;

        // reserved_0x380
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<16>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved_0x380 = reader.read_bytes()?;

        let guest_exit_info_1 = reader.read_bytes()?;
        let guest_exit_info_2 = reader.read_bytes()?;
        let guest_exit_int_info = reader.read_bytes()?;
        let guest_nrip = reader.read_bytes()?;
        let sev_features = reader.read_bytes()?;
        let vintr_ctrl = reader.read_bytes()?;
        let guest_exit_code = reader.read_bytes()?;
        let virtual_tom = reader.read_bytes()?;
        let tlb_id = reader.read_bytes()?;
        let pcpu_id = reader.read_bytes()?;
        let event_inj = reader.read_bytes()?;
        let xcr0 = reader.read_bytes()?;

        // reserved_0x3f0
        #[cfg(not(feature = "unsafe_parser"))]
        reader.skip_bytes::<16>()?;
        #[cfg(feature = "unsafe_parser")]
        let reserved_0x3f0 = reader.read_bytes()?;

        let x87_dp = reader.read_bytes()?;
        let mxcsr = reader.read_bytes()?;
        let x87_ftw = reader.read_bytes()?;
        let x87_fsw = reader.read_bytes()?;
        let x87_fcw = reader.read_bytes()?;
        let x87_fop = reader.read_bytes()?;
        let x87_ds = reader.read_bytes()?;
        let x87_cs = reader.read_bytes()?;
        let x87_rip = reader.read_bytes()?;
        let fpreg_x87 = reader.read_bytes()?;
        let fpreg_xmm = reader.read_bytes()?;
        let fpreg_ymm = reader.read_bytes()?;
        let manual_padding = reader.read_bytes()?;

        #[cfg(not(feature = "unsafe_parser"))]
        {
            Ok(Self {
                es,
                cs,
                ss,
                ds,
                fs,
                gs,
                gdtr,
                ldtr,
                idtr,
                tr,
                vmpl0_ssp,
                vmpl1_ssp,
                vmpl2_ssp,
                vmpl3_ssp,
                u_cet,
                vmpl,
                cpl,
                efer,
                xss,
                cr4,
                cr3,
                cr0,
                dr7,
                dr6,
                rflags,
                rip,
                dr0,
                dr1,
                dr2,
                dr3,
                dr0_addr_mask,
                dr1_addr_mask,
                dr2_addr_mask,
                dr3_addr_mask,
                rsp,
                s_cet,
                ssp,
                isst_addr,
                rax,
                star,
                lstar,
                cstar,
                sfmask,
                kernel_gs_base,
                sysenter_cs,
                sysenter_esp,
                sysenter_eip,
                cr2,
                g_pat,
                dbgctrl,
                br_from,
                br_to,
                last_excp_from,
                last_excp_to,
                pkru,
                tsc_aux,
                rcx,
                rdx,
                rbx,
                rbp,
                rsi,
                rdi,
                r8,
                r9,
                r10,
                r11,
                r12,
                r13,
                r14,
                r15,
                guest_exit_info_1,
                guest_exit_info_2,
                guest_exit_int_info,
                guest_nrip,
                sev_features,
                vintr_ctrl,
                guest_exit_code,
                virtual_tom,
                tlb_id,
                pcpu_id,
                event_inj,
                xcr0,
                x87_dp,
                mxcsr,
                x87_ftw,
                x87_fsw,
                x87_fcw,
                x87_fop,
                x87_ds,
                x87_cs,
                x87_rip,
                fpreg_x87,
                fpreg_xmm,
                fpreg_ymm,
                manual_padding,
            })
        }
        #[cfg(feature = "unsafe_parser")]
        {
            Ok(Self {
                es,
                cs,
                ss,
                ds,
                fs,
                gs,
                gdtr,
                ldtr,
                idtr,
                tr,
                vmpl0_ssp,
                vmpl1_ssp,
                vmpl2_ssp,
                vmpl3_ssp,
                u_cet,
                reserved_0xc8,
                vmpl,
                cpl,
                reserved_0xcc,
                efer,
                reserved_0xd8,
                xss,
                cr4,
                cr3,
                cr0,
                dr7,
                dr6,
                rflags,
                rip,
                dr0,
                dr1,
                dr2,
                dr3,
                dr0_addr_mask,
                dr1_addr_mask,
                dr2_addr_mask,
                dr3_addr_mask,
                reserved_0x1c0,
                rsp,
                s_cet,
                ssp,
                isst_addr,
                rax,
                star,
                lstar,
                cstar,
                sfmask,
                kernel_gs_base,
                sysenter_cs,
                sysenter_esp,
                sysenter_eip,
                cr2,
                reserved_0x248,
                g_pat,
                dbgctrl,
                br_from,
                br_to,
                last_excp_from,
                last_excp_to,
                reserved_0x298,
                pkru,
                tsc_aux,
                reserved_0x2f0,
                rcx,
                rdx,
                rbx,
                reserved_0x320,
                rbp,
                rsi,
                rdi,
                r8,
                r9,
                r10,
                r11,
                r12,
                r13,
                r14,
                r15,
                reserved_0x380,
                guest_exit_info_1,
                guest_exit_info_2,
                guest_exit_int_info,
                guest_nrip,
                sev_features,
                vintr_ctrl,
                guest_exit_code,
                virtual_tom,
                tlb_id,
                pcpu_id,
                event_inj,
                xcr0,
                reserved_0x3f0,
                x87_dp,
                mxcsr,
                x87_ftw,
                x87_fsw,
                x87_fcw,
                x87_fop,
                x87_ds,
                x87_cs,
                x87_rip,
                fpreg_x87,
                fpreg_xmm,
                fpreg_ymm,
                manual_padding,
            })
        }
    }
}

impl ByteParser<()> for SevEsSaveArea {
    type Bytes = [u8; Self::SIZE];
    const EXPECTED_LEN: Option<usize> = Some(Self::SIZE);
}
impl SevEsSaveArea {
    /// Size of the SEV-ES Save Area
    pub const SIZE: usize = 4096;
}

const BSP_EIP: u64 = 0xffff_fff0;

/// VMSA Structure
pub struct VMSA {
    /// Bootstrap Processor
    bsp_save_area: SevEsSaveArea,
    /// Auxiliary Processor
    ap_save_area: Option<SevEsSaveArea>,
}

impl VMSA {
    /// Generate a new SEV-ES VMSA
    /// One Bootstrap and an auxiliary save area if needed
    pub fn new(
        ap_eip: u64,
        vcpu_type: CpuType,
        vmm_type: VMMType,
        cpu_num: Option<u64>,
        guest_features: GuestFeatures,
    ) -> Self {
        let bsp_save_area =
            Self::build_save_area(BSP_EIP, guest_features, vcpu_type, vmm_type, cpu_num);

        let ap_save_area = if ap_eip > 0 {
            Some(Self::build_save_area(
                ap_eip,
                guest_features,
                vcpu_type,
                vmm_type,
                cpu_num,
            ))
        } else {
            None
        };

        VMSA {
            bsp_save_area,
            ap_save_area,
        }
    }

    /// Generate a save area
    fn build_save_area(
        eip: u64,
        guest_features: GuestFeatures,
        vcpu_type: CpuType,
        vmm_type: VMMType,
        cpu_num: Option<u64>,
    ) -> SevEsSaveArea {
        let mut area = SevEsSaveArea::default();

        let (cs_flags, ss_flags, tr_flags, rdx, mxcsr, fcw) = match vmm_type {
            VMMType::QEMU => (0x9b, 0x93, 0x8b, vcpu_type.sig() as u64, 0x1f80, 0x37f),
            VMMType::EC2 => {
                if eip == 0xfffffff0 {
                    (0x9a, 0x92, 0x83, 0, 0, 0)
                } else {
                    (0x9b, 0x92, 0x83, 0, 0, 0)
                }
            }
            VMMType::KRUN => {
                match cpu_num {
                    Some(num) => {
                        if num > 0 {
                            area.rip = 0;
                            area.rsp = 0;
                            area.rbp = 0;
                            area.rsi = 0;

                            area.cs.selector = 0x9100;
                            area.cs.base = 0x91000;
                        } else {
                            area.rsi = 0x7000;
                            area.rbp = 0x8ff0;
                            area.rsp = 0x8ff0;
                        }
                    }
                    _ => {
                        area.rsi = 0x7000;
                        area.rbp = 0x8ff0;
                        area.rsp = 0x8ff0;
                    }
                };
                (0x9a, 0x92, 0x83, 0, 0, 0)
            }
        };

        area.es = VmcbSeg::new(0, 0x93, 0xffff, 0);
        area.cs = VmcbSeg::new(0xf000, cs_flags, 0xffff, eip & 0xffff0000);
        area.ss = VmcbSeg::new(0, ss_flags, 0xffff, 0);
        area.ds = VmcbSeg::new(0, 0x93, 0xffff, 0);
        area.fs = VmcbSeg::new(0, 0x93, 0xffff, 0);
        area.gs = VmcbSeg::new(0, 0x93, 0xffff, 0);
        area.gdtr = VmcbSeg::new(0, 0, 0xffff, 0);
        area.idtr = VmcbSeg::new(0, 0, 0xffff, 0);
        area.ldtr = VmcbSeg::new(0, 0x82, 0xffff, 0);
        area.tr = VmcbSeg::new(0, tr_flags, 0xffff, 0);
        area.efer = 0x1000;
        area.cr4 = 0x40;
        area.cr0 = 0x10;
        area.dr7 = 0x400;
        area.dr6 = 0xffff0ff0;
        area.rflags = 0x2;
        area.rip = eip & 0xffff;
        area.g_pat = 0x7040600070406;
        area.rdx = rdx;
        area.sev_features = guest_features.0;
        area.xcr0 = 0x1;
        area.mxcsr = mxcsr;
        area.x87_fcw = fcw;

        area
    }

    /// Return a vector containing the save area pages
    pub fn pages(&self, vcpus: usize) -> Result<Vec<Vec<u8>>, MeasurementError> {
        let bsp_page = self.bsp_save_area.to_bytes()?.to_vec();
        let ap_save_area_bytes: Option<Vec<u8>> = self
            .ap_save_area
            .map(|v| v.to_bytes().map(|b| b.as_ref().to_vec()))
            .transpose()?;

        let mut pages = Vec::new();

        for i in 0..vcpus {
            if i == 0 {
                pages.push(bsp_page.to_vec())
            } else if let Some(v) = ap_save_area_bytes.as_ref() {
                pages.push(v.clone());
            }
        }
        Ok(pages)
    }
}
