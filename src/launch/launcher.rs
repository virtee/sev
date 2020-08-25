// SPDX-License-Identifier: Apache-2.0

use crate::kvm::types::*;
use crate::launch::linux::ioctl::*;

use std::io::Result;
use std::os::unix::io::AsRawFd;

pub struct New;

pub struct Launcher<'a, T, U: AsRawFd, V: AsRawFd> {
    state: T,
    kvm: &'a mut U,
    sev: &'a mut V,
}

impl<'a, U: AsRawFd, V: AsRawFd> Launcher<'a, New, U, V> {
    pub fn new(kvm: &'a mut U, sev: &'a mut V) -> Result<Self> {
        let launcher = Launcher {
            kvm,
            sev,
            state: New,
        };

        let mut cmd = Command::from(launcher.sev, &Init);
        INIT.ioctl(launcher.kvm, &mut cmd)?;

        Ok(launcher)
    }
}
