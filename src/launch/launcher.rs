// SPDX-License-Identifier: Apache-2.0

//! An implementation of the SEV launch process as a type-state machine.
//! This ensures (at compile time) that the right steps are called in the
//! right order.

use super::{Measurement, Secret, Start};

use crate::kvm::types::*;
use crate::launch::linux::ioctl::*;
use crate::launch::*;

use std::io::Result;
use std::mem::MaybeUninit;
use std::os::unix::io::AsRawFd;

/// Launcher type-state that indicates a brand new launch.
pub struct New;

/// Launcher type-state that indicates an in-progress launch.
pub struct Started(Handle);

/// Launcher type-state that indicates the availability of a measurement.
pub struct Measured(Handle, Measurement);

/// Launcher type-state that indicates a SNP in-progress.
pub struct SnpStarted;

/// Facilitates the correct execution of the SEV launch process.
pub struct Launcher<'a, T, U: AsRawFd, V: AsRawFd> {
    state: T,
    vm_fd: &'a mut U,
    sev: &'a mut V,
}

impl<'a, U: AsRawFd, V: AsRawFd> Launcher<'a, New, U, V> {
    /// Begin the SEV launch process.
    pub fn new(kvm: &'a mut U, sev: &'a mut V) -> Result<Self> {
        let launcher = Launcher {
            vm_fd: kvm,
            sev,
            state: New,
        };

        let mut cmd = Command::from(launcher.sev, &Init);
        INIT.ioctl(launcher.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(launcher)
    }

    /// Create an encrypted guest context.
    pub fn start(self, start: Start) -> Result<Launcher<'a, Started, U, V>> {
        let mut launch_start = LaunchStart::new(&start.policy, &start.cert, &start.session);
        let mut cmd = Command::from_mut(self.sev, &mut launch_start);
        LAUNCH_START
            .ioctl(self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        let next = Launcher {
            state: Started(launch_start.into()),
            vm_fd: self.vm_fd,
            sev: self.sev,
        };

        Ok(next)
    }

    /// Begin the SEV-SNP launch process by creating a Launcher and issuing the
    /// KVM_SNP_INIT ioctl.
    pub fn snp_new(kvm: &'a mut U, sev: &'a mut V) -> Result<Self> {
        let launcher = Launcher {
            state: New,
            vm_fd: kvm,
            sev,
        };

        let init = SnpInit::default();

        let mut cmd = Command::from(launcher.sev, &init);
        SNP_INIT
            .ioctl(launcher.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(launcher)
    }

    /// Initialize the flow to launch a guest.
    pub fn snp_start(self, start: SnpStart) -> Result<Launcher<'a, SnpStarted, U, V>> {
        let mut launch_start = SnpLaunchStart::new(&start);
        let mut cmd = Command::from_mut(self.sev, &mut launch_start);

        SNP_LAUNCH_START
            .ioctl(self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        let launcher = Launcher {
            state: SnpStarted,
            vm_fd: self.vm_fd,
            sev: self.sev,
        };

        Ok(launcher)
    }
}

impl<'a, U: AsRawFd, V: AsRawFd> Launcher<'a, Started, U, V> {
    /// Encrypt guest data with its VEK.
    pub fn update_data(&mut self, data: &[u8]) -> Result<()> {
        let launch_update_data = LaunchUpdateData::new(data);
        let mut cmd = Command::from(self.sev, &launch_update_data);

        ENC_REG_REGION.ioctl(self.vm_fd, &KvmEncRegion::new(data))?;

        LAUNCH_UPDATE_DATA
            .ioctl(self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(())
    }

    /// Request a measurement from the SEV firmware.
    pub fn measure(self) -> Result<Launcher<'a, Measured, U, V>> {
        let mut measurement = MaybeUninit::uninit();
        let mut launch_measure = LaunchMeasure::new(&mut measurement);
        let mut cmd = Command::from_mut(self.sev, &mut launch_measure);
        LAUNCH_MEASUREMENT
            .ioctl(self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        let next = Launcher {
            state: Measured(self.state.0, unsafe { measurement.assume_init() }),
            vm_fd: self.vm_fd,
            sev: self.sev,
        };

        Ok(next)
    }
}

impl<'a, U: AsRawFd, V: AsRawFd> Launcher<'a, SnpStarted, U, V> {
    /// Encrypt guest SNP data.
    pub fn snp_update_data(&mut self, update: SnpUpdate) -> Result<()> {
        let launch_update_data = SnpLaunchUpdate::new(&update);
        let mut cmd = Command::from(self.sev, &launch_update_data);

        ENC_REG_REGION.ioctl(self.vm_fd, &KvmEncRegion::new(update.uaddr))?;

        SNP_LAUNCH_UPDATE
            .ioctl(self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(())
    }

    /// Complete the SNP launch process.
    pub fn snp_finish(self, finish: SnpFinish) -> Result<()> {
        let launch_finish = SnpLaunchFinish::new(&finish);
        let mut cmd = Command::from(self.sev, &launch_finish);

        SNP_LAUNCH_FINISH
            .ioctl(self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(())
    }
}

impl<'a, U: AsRawFd, V: AsRawFd> Launcher<'a, Measured, U, V> {
    /// Get the measurement that the SEV platform recorded.
    pub fn measurement(&self) -> Measurement {
        self.state.1
    }

    /// Inject a secret into the guest.
    ///
    /// ## Remarks
    ///
    /// This should only be called after a successful attestation flow.
    pub fn inject(&mut self, secret: &Secret, guest: usize) -> Result<()> {
        let launch_secret = LaunchSecret::new(&secret.header, guest, &secret.ciphertext[..]);
        let mut cmd = Command::from(self.sev, &launch_secret);
        LAUNCH_SECRET
            .ioctl(self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;
        Ok(())
    }

    /// Complete the SEV launch process.
    pub fn finish(self) -> Result<Handle> {
        let mut cmd = Command::from(self.sev, &LaunchFinish);
        LAUNCH_FINISH
            .ioctl(self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;
        Ok(self.state.0)
    }
}
