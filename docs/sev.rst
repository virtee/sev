===
sev
===
-------------------------
AMD SEV + SEV-SNP library
-------------------------
:Manual section: 3

DESCRIPTION
-----------
NOTE: This documentation only pertains to the C API provided by the AMD SEV Rust
library. For documentation for the Rust portion, please consult the generated
Rust docs here: https://docs.rs/sev/latest/sev/index.html.

libsev is a library for managing and interacting with the AMD SEV device. It
implements APIs to the launch ioctls usable from the /dev/sev device.

Error messages
~~~~~~~~~~~~~~
Functions generally return 0 on success and -1 on failure. Each API requires an
argument ``fw_err``. With a failure, ``fw_err`` will be set to a SEV
firmware-specific error (if applicable).

Initializing the SEV (and SEV-ES) launch flow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Given the VM's file descriptor, the sev library will be able to initiate the SEV
launch flow for the guest::

  int vm_fd = $(VM_FD), fw_err;

  int ret = sev_init(vm_fd, &fw_err);
  if (ret != 0) {
    fprintf(stderr, "Error initializing the SEV launch flow (fw_err = %d)\n",
              fw_err);
    return;
  }

  int ret = sev_es_init(vm_fd, &fw_err);
  if (ret != 0) {
    fprintf(stderr, "Error initializing the SEV-ES launch flow (fw_err = %d)\n",
              fw_err);
    return;
  }


Beginning the SEV launch flow
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Launch start requires the VM's file descriptor, a SEV policy, certificate chain,
and session buffer::

  int vm_fd = $(VM_FD), fw_err;
  unsigned int policy = 0x3;
  unsigned char *cert_bytes = $(CERTIFICATE_BYTES);
  unsigned char *session_bytes = $(SEV_LAUNCH_SESSION_BYTES);

  int ret = sev_launch_start(vm_fd, policy, cert_bytes, session_bytes, &fw_err);
  if (ret != 0) {
    fprintf(stderr, "Error beginning the SEV launch flow (fw_err = %d)\n",
              fw_err);
    return;
  }

Encrypt a portion of guest memory with SEV
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Updating guest data requires the VM's file descriptor, the guest memory address
of the region to encrypt, and the length of the aforementioned guest region::

  int vm_fd = $(VM_FD), fw_err;
  unsigned long uaddr = $(GUEST_MEM_ADDRESS);
  unsigned long size = $(SIZE_OF_GUEST_MEMORY_TO_ENCRYPT);

  int ret = sev_launch_update_data(vm_fd, uaddr, size, &fw_err);
  if (ret != 0) {
    fprintf(stderr, "Error updating guest address %lu with SEV (fw_err = %d)\n",
              uaddr, fw_err);
    return;
  }

Encrypt the guest's VMCB save area with its VEK
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Updating guest VMSA requires the VM's file descriptor::

  int vm_fd = $(VM_FD), fw_err;

  int ret = sev_launch_update_vmsa(vm_fd, &fw_err);
  if (ret != 0) {
    fprintf(stderr, "Error encrypting the guest VMSA (fw_err = %d)\n", fw_err);
    return;
  }

Fetch the meaurement of the launched guest's memory pages and VMCB save area (if
ES is enabled)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Launch measurement requires the VM's file descriptor and a pre-allocated pointer
to store the measurement data::

  int vm_fd = $(VM_FD), fw_err;
  unsigned char *data;  // Must be allocated to fit at least 48 bytes.

  int ret = sev_launch_measure(vm_fd, data, &fw_err);
  if (ret != 0) {
    fprintf(stderr, "Error fetching guest measurement (fw_err = %d)\n", fw_err);
    return;
  }

Inject a secret into the guest
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Launch secret injection requires the VM's file descriptor, pre-allocated buffers
for the header and ciphertext, the size of the ciphertext, and the guest memory
address to inject the secret::

  int vm_fd = $(VM_FD), fw_err;
  void *paddr;  // The guest address to inject the secret.
  unsigned int ciphertext_sz;   // The size of the ciphertext buffer.
  unsigned char *header, *ciphertext; // Must be allocated and filled with data.

  int ret = sev_inject_launch_secret(vm_fd, header, ciphertext, ciphertext_sz,
                                     paddr, &fw_err);
  if (ret != 0) {
    fprintf(stderr, "Error injecting launch secret (fw_err = %d)\n", fw_err);
    return;
  }

Finish the launch flow and transition the guest into a state ready to be run
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Launch finish requries the VM's file descriptor::

  int vm_fd = $(VM_FD), fw_err;

  int ret = sev_launch_finish(vm_fd, &fw_err);
  if (ret != 0) {
    fprintf(stderr, "Error finishing launch flow (fw_err = %d\n)", fw_err);
    return;
  }

Fetch the guest's attestation report
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Launch attestation report fetching requires the VM's file descriptor, a 16-byte
mnonce buffer to include in the report (along with its size), a buffer to store
the attestation report, an argument to store the length of the attestation
report::

  int vm_fd = $(VM_FD), fw_err;
  unsigned char *mnonce;    // Contains 16-byte mnonce to include in report.
  unsigned char *report_bytes;  // Must be pre-allocated to hold >= 208 bytes.
  unsigned int len;             // API fills with size of attestation report.

  int ret = sev_attestation_report(vm_fd, mnonce, strlen(mnonce), report_bytes,
                                   &len, &fw_err);
  if (ret != 0) {
    fprintf(stderr, "Error fetching attestation report (fw_err = %d)\n",
            fw_err);
    return;
  }
