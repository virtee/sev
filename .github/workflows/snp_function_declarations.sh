# SPDX-License-Identifier: Apache-2.0

#!/bin/bash

verify_snp_host() {
local AMDSEV_URL="https://github.com/LakshmiSaiHarika/AMDSEV.git"
local AMDSEV_DEFAULT_BRANCH="fedora-build-install-upstream-kernel"

# Checks if SNP is enabled on the SNP host Kernel
if ! sudo dmesg | grep -i "SEV-SNP enabled" 2>&1 >/dev/null; then
  echo -e "SEV-SNP not enabled on the host. Please follow these steps to enable:\n\
  $(echo "${AMDSEV_URL}" | sed 's|\.git$||g')/tree/${AMDSEV_DEFAULT_BRANCH}#prepare-host"
  return 1
fi
}

check_rust_on_host() {
  # Install Rust on the host
  source "${HOME}/.cargo/env" 2>/dev/null || true
  if ! command -v rustc &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -sSf | sh -s -- -y
    source "${HOME}/.cargo/env" 2>/dev/null
  fi
}

ssh_guest_command() {
    local guest_name="$2"
    local GUEST_SSH_KEY_PATH="${HOME}/snp/launch/${guest_name}/${guest_name}-key"
    if [ ! -f "${GUEST_SSH_KEY_PATH}" ]; then
      echo "ERROR: Guest SSH key file path not present!"
      exit 1
    fi
    command="$1"
    guest_port_in_use="$3"

    ssh -p ${guest_port_in_use} -i "${GUEST_SSH_KEY_PATH}" -o "StrictHostKeyChecking no" -o "PasswordAuthentication=no" -o ConnectTimeout=1 amd@localhost "${command}"
  }

# verify_snp_guest_msr CLI use: verify_snp_guest_msr "${guest_name}" "${guest_port_number}"
verify_snp_guest_msr(){
  # Install guest rdmsr package dependencies to insert guest msr module
  ssh_guest_command "sudo dnf install -y msr-tools > /dev/null 2>&1" $1 $2> /dev/null 2>&1
  ssh_guest_command "sudo modprobe msr" $1 $2 > /dev/null 2>&1
  local guest_msr_read=$(ssh_guest_command "sudo rdmsr -p 0 0xc0010131"  $1 $2)
  guest_msr_read=$(echo "${guest_msr_read}" | tr -d '\r' | bc)

  # Map all the sev features in a single associative array for all guest SEV features
  declare -A actual_sev_snp_bit_status=(
    [SEV]=$(( ( guest_msr_read >> 0) & 1))
    [SEV-ES]=$(( (guest_msr_read >> 1) & 1))
    [SNP]=$(( (guest_msr_read >> 2) & 1))
  )

  local sev_snp_error=""
  for sev_snp_key in "${!actual_sev_snp_bit_status[@]}";
  do
      if [[ ${actual_sev_snp_bit_status[$sev_snp_key]} != 1 ]]; then
        # Capture the guest SEV/SNP bit value mismatch
        sev_snp_error+=$(echo "$sev_snp_key feature is not active on the guest.\n");
      fi
  done

  if [[ ! -z "${sev_snp_error}" ]]; then
    >&2 echo -e "ERROR: ${sev_snp_error}"
    return 1
  fi
 }

