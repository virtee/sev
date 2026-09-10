// SPDX-License-Identifier: Apache-2.0

//! Bitmask selecting guest fields mixed into a derived key.
//!
//! Each set bit in [`GuestFieldSelect`] tells the ASP to include the
//! corresponding launch-bound value when deriving a guest key. See SNP firmware
//! specification for field definitions.

use bitfield::bitfield;

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
    /// |6|LAUNCH_MIT_VECTOR|Indicates that the guest-provided LAUNCH_MIT_VECTOR will be mixed into the key.|
    /// |63:7|\-|Reserved. Must be zero.|
    #[repr(C)]
    #[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct GuestFieldSelect(u64);
    impl Debug;
    /// Check/Set guest policy inclusion in derived key.
    pub get_guest_policy, set_guest_policy: 0;
    /// Check/Set image id inclusion in derived key.
    pub get_image_id, set_image_id: 1;
    /// Check/Set family id inclusion in derived key.
    pub get_family_id, set_family_id: 2;
    /// Check/Set measurement inclusion in derived key.
    pub get_measurement, set_measurement: 3;
    /// Check/Set svn inclusion in derived key.
    pub get_svn, set_svn: 4;
    /// Check/Set tcb version inclusion in derived key.
    pub get_tcb_version, set_tcb_version: 5;
    /// Indicates that the guest-provied LAUNCH_MIT_VECTOR will be mixed into the key.
    pub get_launch_mit_vector, set_launch_mit_vector: 6;
}

impl From<u64> for GuestFieldSelect {
    fn from(value: u64) -> Self {
        GuestFieldSelect(value)
    }
}

impl From<GuestFieldSelect> for u64 {
    fn from(value: GuestFieldSelect) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guest_field_select_all_on() {
        let actual: GuestFieldSelect = GuestFieldSelect(0b111111);

        assert!(actual.get_guest_policy());
        assert!(actual.get_image_id());
        assert!(actual.get_family_id());
        assert!(actual.get_measurement());
        assert!(actual.get_svn());
        assert!(actual.get_tcb_version());
    }

    #[test]
    fn test_guest_field_select_all_off() {
        let actual: GuestFieldSelect = GuestFieldSelect(0);

        assert!(!actual.get_guest_policy());
        assert!(!actual.get_image_id());
        assert!(!actual.get_family_id());
        assert!(!actual.get_measurement());
        assert!(!actual.get_svn());
        assert!(!actual.get_tcb_version());
    }

    #[test]
    fn test_guest_field_select_operations() {
        let mut field = GuestFieldSelect::default();

        field.set_guest_policy(true);
        assert!(field.get_guest_policy());

        field.set_image_id(true);
        assert!(field.get_image_id());

        field.set_family_id(true);
        assert!(field.get_family_id());

        field.set_measurement(true);
        assert!(field.get_measurement());
    }
}
