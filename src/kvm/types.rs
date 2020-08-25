// SPDX-License-Identifier: Apache-2.0

use crate::certs::sev;
use crate::launch::{Measurement, Policy, Session};

use std::marker::PhantomData;
use std::mem::{size_of_val, MaybeUninit};

/// Initialize the SEV platform context.
#[repr(C)]
pub struct Init;

#[repr(transparent)]
pub struct Handle(u32);

impl From<LaunchStart<'_>> for Handle {
    fn from(ls: LaunchStart) -> Self {
        ls.handle
    }
}

/// Initiate SEV launch flow.
#[repr(C)]
pub struct LaunchStart<'a> {
    handle: Handle,
    policy: Policy,
    dh_addr: u64,
    dh_len: u32,
    session_addr: u64,
    session_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchStart<'a> {
    pub fn new(policy: &'a Policy, dh: &'a sev::Certificate, session: &'a Session) -> Self {
        Self {
            handle: Handle(0), /* platform will generate one for us */
            policy: *policy,
            dh_addr: dh as *const _ as _,
            dh_len: size_of_val(dh) as _,
            session_addr: session as *const _ as _,
            session_len: size_of_val(session) as _,
            _phantom: PhantomData,
        }
    }
}

/// Encrypt guest data with its VEK.
#[repr(C)]
pub struct LaunchUpdateData<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchUpdateData<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            addr: data.as_ptr() as _,
            len: data.len() as _,
            _phantom: PhantomData,
        }
    }
}

/// Get the guest's measurement.
#[repr(C)]
pub struct LaunchMeasure<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a Measurement>,
}

impl<'a> LaunchMeasure<'a> {
    pub fn new(measurement: &'a mut MaybeUninit<Measurement>) -> Self {
        Self {
            addr: measurement.as_mut_ptr() as _,
            len: size_of_val(measurement) as _,
            _phantom: PhantomData,
        }
    }
}
