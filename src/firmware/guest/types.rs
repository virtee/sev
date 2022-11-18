// SPDX-License-Identifier: Apache-2.0

use bitfield::bitfield;

/// When the PSP attempt to retreive an SEV-SNP extended report,
/// but the buffer is of an incorrect size, this is the exact value
/// which will be returned in the [`SnpGuestRequest::fw_err`] field.
///
/// If this value is found, it is important that
/// [`SnpExtReportReq::extend_buffer()`] be called to adjust for the
/// buffer size provided by the PSP.
pub const INVALID_CERT_BUFFER: u64 = 0x0000000100000000;

pub(crate) use crate::firmware::linux::guest::types::{
    SnpDerivedKeyReq, SnpDerivedKeyRsp, SnpReportRsp,
};

pub use crate::firmware::linux::guest::types::{
    AttestationReport, Signature, SnpExtReportReq, SnpGuestPolicy, SnpPlatformInfo, SnpReportReq,
    SnpTcbVersion,
};

/// Structure of required data for fetching the derived key.
pub struct SnpDerivedKey {
    /// Selects the root key to derive the key from.
    /// 0: Indicates VCEK.
    /// 1: Indicates VMRK.
    root_key_select: u32,

    /// Reserved, must be zero
    _reserved_0: u32,

    /// What data will be mixed into the derived key.
    pub guest_field_select: GuestFieldSelect,

    /// The VMPL to mix into the derived key. Must be greater than or equal
    /// to the current VMPL.
    pub vmpl: u32,

    /// The guest SVN to mix into the key. Must not exceed the guest SVN
    /// provided at launch in the ID block.
    pub guest_svn: u32,

    /// The TCB version to mix into the derived key. Must not
    /// exceed CommittedTcb.
    pub tcb_version: u64,
}

impl SnpDerivedKey {
    /// Create a new instance for requesting an SnpDerivedKey.
    ///
    /// # Arguments:
    ///
    /// * `root_key_select` - bool - true: use VMRK to derive key, false: use VCEK to derive key.
    /// * `guest_field_select` - [`GuestFieldSelect`] - Bitfield expressing which will be mixed into the derived key.
    /// * `vmpl` - u32 - What VMPL level the derived key should be associated with.
    /// * `guest_svn` - u32 - Guest SVN to mix into the key.
    /// * `tcb_version` - u64 - The TCB Version to mix into the derived key. Must __NOT__ Exceed Committed TCB.
    pub fn new(
        root_key_select: bool,
        guest_field_select: GuestFieldSelect,
        vmpl: u32,
        guest_svn: u32,
        tcb_version: u64,
    ) -> Self {
        Self {
            root_key_select: u32::from(root_key_select),
            _reserved_0: Default::default(),
            guest_field_select,
            vmpl,
            guest_svn,
            tcb_version,
        }
    }

    /// Obtain a copy of the root key select value (Private Field)
    pub fn get_root_key_select(&self) -> u32 {
        self.root_key_select
    }
}

/// A raw representation of the PSP Report Response after calling SNP_GET_DERIVED_KEY.
pub struct DerivedKeyRsp {
    /// The status of key derivation operation.
    /// 0h: Success.
    /// 16h: Invalid parameters
    pub status: u32,

    _reserved_0: [u8; 28],

    /// The requested derived key if [`DerivedKeyRsp::status`] is 0h.
    pub key: [u8; 32],
}

bitfield! {
    /// Data which will be mixed into the derived key.
    ///
    /// | Bit(s) | Name | Description |
    /// |--------|------|-------------|
    /// |0|GUEST_POLICY|Indicates that the guest policy will be mixed into the key.|
    /// |1|IMAGE_ID|Indicates that the image ID of the guest will be mixed into the key.|
    /// |2|FAMILY_ID|Indicates the family ID of the guest will be mixed into the key.|
    /// |3|MEASUREMENT|Indicates the measurement of the guest during launch will be mixed into the key.|
    /// |4|GUEST_SVN|Indicates that the guest-provided SVN will be mixed into the key.|
    /// |5|TCB_VERSION|Indicates that the guest-provided TCB_VERSION will be mixed into the key.|
    /// |63:6|\-|Reserved. Must be zero.|
    #[repr(C)]
    #[derive(Default)]
    pub struct GuestFieldSelect(u64);
    impl Debug;
    /// Check/Set guest policy inclusion in derived key.
    pub get_guest_policy, set_guest_policy: 0, 0;
    /// Check/Set image id inclusion in derived key.
    pub get_image_id, set_image_id: 1, 1;
    /// Check/Set family id inclusion in derived key.
    pub get_family_id, set_family_id: 2, 2;
    /// Check/Set measurement inclusion in derived key.
    pub get_measurement, set_measurement: 3, 3;
    /// Check/Set svn inclusion in derived key.
    pub get_svn, set_svn: 4, 4;
    /// Check/Set tcb version inclusion in derived key.
    pub get_tcb_version, set_tcb_version: 5, 5;
}
