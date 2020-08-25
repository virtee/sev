// SPDX-License-Identifier: Apache-2.0

use super::{Measurement, Secret, Start};

use crate::kvm::types::*;
use crate::launch::linux::ioctl::*;

use std::io::Result;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;

pub struct New;
pub struct Started(Handle);
pub struct Measured(Handle, Measurement);

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

impl<'a, U: AsRawFd, V: AsRawFd> Launcher<'a, Started, U, V> {
    pub fn update_data(&mut self, data: &[u8]) -> Result<()> {
        let launch_update_data = LaunchUpdateData::new(data);
        let mut cmd = Command::from(self.sev, &launch_update_data);
        LAUNCH_UPDATE_DATA.ioctl(self.kvm, &mut cmd)?;
        Ok(())
    }

    pub fn measure(self) -> Result<Launcher<'a, Measured, U, V>> {
        let mut measurement = MaybeUninit::uninit();
        let mut launch_measure = LaunchMeasure::new(&mut measurement);
        let mut cmd = Command::from_mut(self.sev, &mut launch_measure);
        LAUNCH_MEASUREMENT.ioctl(self.kvm, &mut cmd)?;

        let next = Launcher {
            state: Measured(self.state.0, unsafe { measurement.assume_init() }),
            kvm: self.kvm,
            sev: self.sev,
        };

        Ok(next)
    }
}

impl<'a, U: AsRawFd, V: AsRawFd> Launcher<'a, Measured, U, V> {
    pub fn measurement(&self) -> Measurement {
        self.state.1
    }

    pub fn inject(&mut self, secret: Secret, guest: usize) -> Result<()> {
        let launch_secret = LaunchSecret::new(&secret.header, guest, &secret.ciphertext[..]);
        let mut cmd = Command::from(self.sev, &launch_secret);
        LAUNCH_SECRET.ioctl(self.kvm, &mut cmd)?;
        Ok(())
    }
}
