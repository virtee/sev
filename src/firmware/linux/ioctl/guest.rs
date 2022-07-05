use std::marker::PhantomData;

use crate::firmware::types::*;
use crate::impl_const_id;

use iocuddle::*;

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/sev-guest.h
impl_const_id! {
    pub Id => u32;
    GetReport<'_, '_> = 0,
    GetDerivedKey = 1,
    GetExtReport = 2,
}

const SEV: Group = Group::new(b'S');

pub const GET_REPORT: Ioctl<WriteRead, &Command<GetReport>> = unsafe { SEV.write_read(0) };
pub const GET_DERIVED_KEY: Ioctl<WriteRead, &Command<GetDerivedKey>> = unsafe { SEV.write_read(0) };
pub const GET_EXT_REPORT: Ioctl<WriteRead, &Command<GetExtReport>> = unsafe { SEV.write_read(0) };

/// The Rust-flavored, FFI-friendly version of `struct sev_issue_cmd` which is
/// used to pass arguments to the SEV ioctl implementation.
///
/// This struct is defined in the Linux kernel: include/uapi/linux/psp-sev.h
#[repr(C, packed)]
pub struct Command<'a, T: Id> {
    code: u32,
    data: u64,
    error: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    /// Create an SEV command with the expectation that the host platform/kernel will write to
    /// the caller's address space either to the data held in the `Command.subcmd` field or some
    /// other region specified by the `Command.subcmd` field.
    pub fn from_mut(subcmd: &'a mut T) -> Self {
        Command {
            code: T::ID,
            data: subcmd as *mut T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }

    /// Create an SEV command with the expectation that the host platform/kernel *WILL NOT* mutate
    /// the caller's address space in its response. Note: this does not actually prevent the host
    /// platform/kernel from writing to the caller's address space if it wants to. This is primarily
    /// a semantic tool for programming against the SEV ioctl API.
    pub fn from(subcmd: &'a T) -> Self {
        Command {
            code: T::ID,
            data: subcmd as *const T as u64,
            error: 0,
            _phantom: PhantomData,
        }
    }
}
