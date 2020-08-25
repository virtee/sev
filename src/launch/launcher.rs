// SPDX-License-Identifier: Apache-2.0

use super::Start;

use crate::kvm::types::*;
use crate::launch::linux::ioctl::*;

use std::io::Result;
use std::os::unix::io::AsRawFd;

pub struct New;
pub struct Started(Handle);

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

    pub fn start(self, start: Start) -> Result<Launcher<'a, Started, U, V>> {
        let mut launch_start = LaunchStart::new(&start.policy, &start.cert, &start.session);
        let mut cmd = Command::from_mut(self.sev, &mut launch_start);
        LAUNCH_START.ioctl(self.kvm, &mut cmd)?;

        let next = Launcher {
            state: Started(launch_start.into()),
            kvm: self.kvm,
            sev: self.sev,
        };

        Ok(next)
    }
}
