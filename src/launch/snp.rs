// SPDX-License-Identifier: Apache-2.0

//! An implementation of the SEV-SNP launch process as a type-state machine.
//! This ensures (at compile time) that the right steps are called in the
//! right order.

pub use crate::launch::{
    SnpFinish, SnpPageType, SnpPolicy, SnpPolicyFlags, SnpStart, SnpUpdate, VmplPerms,
};

#[cfg(target_os = "linux")]
use crate::launch::linux::ioctl::*;
#[cfg(target_os = "linux")]
use crate::launch::linux::kvm::*;

use std::io::Result;
use std::marker::PhantomData;
use std::os::unix::io::AsRawFd;

/// Launcher type-state that indicates a brand new launch.
pub struct New;

/// Launcher type-state that indicates a SNP in-progress.
pub struct Started;

/// Facilitates the correct execution of the SEV launch process.
pub struct Launcher<T, U: AsRawFd, V: AsRawFd> {
    vm_fd: U,
    sev: V,
    state: PhantomData<T>,
}

impl<T, U: AsRawFd, V: AsRawFd> AsRef<U> for Launcher<T, U, V> {
    /// Give access to the vm fd to create vCPUs or such.
    fn as_ref(&self) -> &U {
        &self.vm_fd
    }
}

impl<T, U: AsRawFd, V: AsRawFd> AsMut<U> for Launcher<T, U, V> {
    /// Give access to the vm fd to create vCPUs or such.
    fn as_mut(&mut self) -> &mut U {
        &mut self.vm_fd
    }
}

impl<U: AsRawFd, V: AsRawFd> Launcher<New, U, V> {
    /// Begin the SEV-SNP launch process by creating a Launcher and issuing the
    /// KVM_SNP_INIT ioctl.
    pub fn new(vm_fd: U, sev: V) -> Result<Self> {
        let mut launcher = Launcher {
            vm_fd,
            sev,
            state: PhantomData::default(),
        };

        let init = SnpInit::default();

        let mut cmd = Command::from(&mut launcher.sev, &init);
        SNP_INIT
            .ioctl(&mut launcher.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(launcher)
    }

    /// Initialize the flow to launch a guest.
    pub fn start(mut self, start: SnpStart) -> Result<Launcher<Started, U, V>> {
        let mut launch_start = SnpLaunchStart::new(&start);
        let mut cmd = Command::from_mut(&mut self.sev, &mut launch_start);

        SNP_LAUNCH_START
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        let launcher = Launcher {
            vm_fd: self.vm_fd,
            sev: self.sev,
            state: PhantomData::default(),
        };

        Ok(launcher)
    }
}

impl<U: AsRawFd, V: AsRawFd> Launcher<Started, U, V> {
    /// Encrypt guest SNP data.
    pub fn update_data(&mut self, update: SnpUpdate) -> Result<()> {
        let launch_update_data = SnpLaunchUpdate::new(&update);
        let mut cmd = Command::from(&mut self.sev, &launch_update_data);

        KvmEncRegion::new(update.uaddr).register(&mut self.vm_fd)?;

        SNP_LAUNCH_UPDATE
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(())
    }

    /// Complete the SNP launch process.
    pub fn finish(mut self, finish: SnpFinish) -> Result<(U, V)> {
        let launch_finish = SnpLaunchFinish::new(&finish);
        let mut cmd = Command::from(&mut self.sev, &launch_finish);

        SNP_LAUNCH_FINISH
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok((self.vm_fd, self.sev))
    }
}
