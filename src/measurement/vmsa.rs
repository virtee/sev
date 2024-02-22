// SPDX-License-Identifier: Apache-2.0

//! Operations to build and interact with an SEV-ES VMSA
use crate::{
    error::MeasurementError,
    measurement::{large_array::LargeArray, vcpu_types::CpuType},
};
use bitfield::bitfield;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt, str::FromStr};

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

impl TryFrom<u8> for VMMType {
    type Error = MeasurementError;

    fn try_from(value: u8) -> Result<Self, MeasurementError> {
        match value {
            1 => Ok(VMMType::QEMU),
            2 => Ok(VMMType::EC2),
            3 => Ok(VMMType::KRUN),
            _ => Err(MeasurementError::InvalidVmmError(value.to_string())),
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
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

impl VmcbSeg {
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
    /// | 11 | Reserved, SBZ |
    /// | 12 | IbsVirtualization |
    /// | 13 | Reserved, SBZ |
    /// | 14 | VmsaRegProt |
    /// | 15 | SmtProtection |
    /// | 63:16 | Reserved, SBZ |
    #[repr(C)]
    #[derive(Default, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct GuestFeatures(u64);
    impl Debug;
    /// SNPActive
    pub snp_active, _: 0, 0;
    /// vTom
    pub v_tom, _: 1, 1;
    /// ReflectVC
    pub reflect_vc, _: 2, 2;
    /// RestrictedInjection
    pub restricted_injection, _: 3,3;
    /// AlternateInjection
    pub alternate_injection, _: 4,4;
    /// DebugSwap
    pub debug_swap, _: 5,5;
    /// PreventHostIbs
    pub prevent_host_ibs, _: 6,6;
    /// BTBIsolation
    pub btb_isolation, _: 7,7;
    /// VmplSSS
    pub vmpl_sss, _: 8,8;
    /// SecureTSC
    pub secure_tsc, _: 9,9;
    /// VmgExitParameter
    pub vmg_exit_parameter, _: 10,10;
    /// Reserved, SBZ
    reserved_1, _: 11,11;
    /// IbsVirtualization
    pub ibs_virtualization, _: 12,12;
    /// Reserved, SBZ
    reserved_2, _: 13,13;
    /// VmsaRegProt
    pub vmsa_reg_prot, _: 14,14;
    ///SmtProtection
    pub smt_protection, _: 15,15;
    /// Reserved, SBZ
    reserved_3, sbz: 16, 63;
}

/// SEV-ES VMSA page
/// The names of the fields are taken from struct sev_es_work_area in the linux kernel:
/// https://github.com/AMDESE/linux/blob/sev-snp-v12/arch/x86/include/asm/svm.h#L318
/// (following the definitions in AMD APM Vol 2 Table B-4)
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
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
    reserved_1: [u8; 2],
    vmpl: u8,
    cpl: u8,
    reserved_2: [u8; 4],
    efer: u64,
    reserved_3: LargeArray<u8, 104>,
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
    reserved_4: [u8; 24],
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
    reserved_5: [u8; 32],
    g_pat: u64,
    dbgctrl: u64,
    br_from: u64,
    br_to: u64,
    last_excp_from: u64,
    last_excp_to: u64,
    reserved_7: LargeArray<u8, 80>,
    pkru: u32,
    reserved_8: [u8; 20],
    reserved_9: u64,
    rcx: u64,
    rdx: u64,
    rbx: u64,
    reserved_10: u64,
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
    reserved_11: [u8; 16],
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
    reserved_12: [u8; 16],
    x87_dp: u64,
    mxcsr: u32,
    x87_ftw: u16,
    x87_fsw: u16,
    x87_fcw: u16,
    x87_fop: u16,
    x87_ds: u16,
    x87_cs: u16,
    x87_rip: u64,
    fpreg_x87: LargeArray<u8, 80>,
    fpreg_xmm: LargeArray<u8, 256>,
    fpreg_ymm: LargeArray<u8, 256>,
    unused: LargeArray<u8, 2448>,
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

        let (cs_flags, ss_flags, tr_flags, rdx) = match vmm_type {
            VMMType::QEMU => (0x9b, 0x93, 0x8b, vcpu_type.sig() as u64),
            VMMType::EC2 => {
                if eip == 0xfffffff0 {
                    (0x9a, 0x92, 0x83, 0)
                } else {
                    (0x9b, 0x92, 0x83, 0)
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
                    None => {
                        area.rsi = 0x7000;
                        area.rbp = 0x8ff0;
                        area.rsp = 0x8ff0;
                    }
                };
                (0x9a, 0x92, 0x83, 0)
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

        area
    }

    /// Return a vector containing the save area pages
    pub fn pages(&self, vcpus: usize) -> Result<Vec<Vec<u8>>, MeasurementError> {
        let bsp_page = bincode::serialize(&self.bsp_save_area)
            .map_err(|e| MeasurementError::BincodeError(*e))?;
        let ap_save_area_bytes: Option<Vec<u8>> =
            match self.ap_save_area.map(|v| bincode::serialize(&v)) {
                Some(value) => Some(value.map_err(|e| MeasurementError::BincodeError(*e))?),
                None => None,
            };

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
