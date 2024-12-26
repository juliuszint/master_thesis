Solution Approaches
+++++++++++++++++++
This chapter explores potential solution approaches. Each approach is introduced
with a concise technical description, followed by an evaluation of its
advantages and disadvantages. At the conclusion of the chapter, the most
suitable solution will be selected, and its implementation will be detailed in
the subsequent chapter.

A small note beforehand: In an OpenBSD installation with Full Disk Encryption
(FDE), the kernel is encrypted, and the second-stage bootloader, boot(8),
represents the last unencrypted component. This bootloader resides in a metadata
area on the disk, preceding the kernel.

Reusing components from Qubes AEM
=================================
The Qubes-AEM solution can be seen as a composition of three distinct
components, each serving a specific function. The following section examines
whether and how these components could be adapted for use with OpenBSD.

.. _Component 1 (bootloader):

1. **bootloader:** Grub2 is used as the bootloader, and it can also be used to
   start OpenBSD. Instead of directly loading the operating system kernel as
   usual, it loads tboot. This software initializes an MLE (Measured Launch
   Environment) and then hands control over to the operating system kernel.
   However, tboot requires the kernel to be Multiboot compatible. This
   specification, for example, allows tboot to know the position of the entry
   point and jump to it. When drafting this specification, consideration was
   given to existing formats. Thus, it would theoretically be possible to make
   boot(8) Multiboot compliant.

2. **initramfs:** In this step, the secret is decrypted and displayed using the
   TPM. If the secret is correct, the password for the FDE can be entered. At
   this point, the Trousers TPM software stack and the Plymouth login service
   are already available. The AEM extension makes extensive use of both, which
   poses a challenge for porting, as neither Trousers nor Plymouth is available
   on OpenBSD. A search was conducted in both precompiled binaries and the
   ``ports(7)`` system.

3. **Post login:** Upon successful login, several files are sealed using the
   TPM, including the secret, the shared secret, and the freshness token. This
   phase also encompasses the initial setup, where the TPM is configured and the
   boot medium is created. While the shell scripts involved in this process are
   technically compatible with OpenBSD, their functionality relies on the
   Trousers TPM software stack. Consequently, porting this stack to OpenBSD
   would be a prerequisite for enabling these operations.

OpenBSD does not include an initramfs step. Instead, ``boot(8)`` manages Full
Disk Encryption (FDE) and prompts for the required password via a terminal
interface. OpenBSD lacks a graphical login screen akin to Plymouth, making the
porting of the second component technically infeasible due to inherent
incompatibilities.

The feasibility of porting the third component heavily depends on the effort
required to adapt Trousers for OpenBSD. Even if this could be accomplished with
minimal effort, additional work would still be necessary to migrate the
systemd-specific code to OpenBSD’s init system.

Reusing `Component 1 (bootloader)`_, it would be feasible to establish a Chain
of Trust with Intel TXT up to ``boot(8)`` with a manageable amount of effort.

Reusing components from TrustedGRUB2
====================================
Theoretically, there are two ways to boot OpenBSD via Grub. The first option
involves using the chainloader command to start ``biosboot(8)``, which
corresponds to the contents of the Partition Boot Record (PBR). Grub already
knows the position and format of the PBR, enabling the system to boot without
any modifications to OpenBSD. However, the Chain of Trust ends at
``biosboot(8)``, and extending it to ``boot(8)`` would require additional
adjustments. This approach deviates from the standard OpenBSD boot process and
effectively offers only one advantage: extending the Chain of Trust to the
Master Boot Record (MBR).

The second option involves bypassing the ``biosboot(8)`` step entirely and
directly loading ``boot(8)`` using the Multiboot Grub command. For this to work,
``boot(8)`` must be made Multiboot-compliant. This approach would extend the
Chain of Trust all the way to the program responsible for requesting the FDE
password, thereby making it complete. However, additional functionality for
sealing and unsealing data via the TPM would need to be implemented within
``boot(8)``.

The TrustedGRUB2 feature, which enables unsealing a keyfile for an FDE-encrypted
LUKS partition, can only be utilized indirectly. Theoretically, it would be
possible to copy ``boot(8)`` into a LUKS-encrypted partition, decrypt it by
providing the SRK and unsealing the keyfile, and subsequently execute
``boot(8)``.

Reimplementation for OpenBSD
============================
An approach that does not rely on components from the two tested systems is also
conceivable. This would involve extending the Chain of Trust from the MBR,
through ``biosboot(8)``, and up to ``boot(8)``.

``boot(8)`` must additionally be capable of communicating with the TPM to
encrypt a secret. Since no driver infrastructure is available at this stage and
``boot(8)`` currently lacks any code for TPM communication, this functionality
would need to be implemented from scratch.

Suitability
===========
The only benefit of TrustedGRUB2 is its ability to extend the Chain of Trust
over the MBR. This minimal contribution, combined with the project's state of
abandonment, **disqualifies** this option. A more interesting use case for
TrustedGRUB2 would be in a dual-boot system, where multiple operating systems
are booted from a single drive. However, since this is not a requirement for
this work, the decision remains unchanged.

The reuse of components from the Qubes-AEM system was deemed unsuitable for the
following reasons: The SINIT ACM is cumbersome to use. For licensing reasons,
each user must independently download it and specify it during the installation
of the boot chain. Another negative aspect, aside from poor user-friendliness,
is a security vulnerability discovered in an older version [50]_. A third and
final argument is platform dependency. Intel TXT, as the name suggests, is an
Intel technology and is therefore only available in Intel CPUs.

A complete re-implementation is supported by several reasons. OpenBSD is a fully
integrated operating system that provides its own, as simple and correct as
possible, solutions for all requirements. For example, the bootloader, unlike
Grub, does not have a graphical interface, theming support, or
internationalization. It offers a simple command-line interface through which
different kernels can be started. Additionally, for full disk encryption (FDE),
OpenBSD does not use LUKS but instead employs its own solution with
``softraid(4)``.

To maintain the most stable system possible, deviations from the standard
configuration of OpenBSD should be kept to a minimum. This thread [64]_ from the
misc OpenBSD mailing list discusses the fact that the optional sets available
during installation are not reinstalled during a system upgrade. An OpenBSD
installation that, for example, omits the ``gameXX.tgz`` set would be considered
a non-"standard" installation.

To stay as close as possible to the OpenBSD default, a solution that extends the
OpenBSD components is desirable and will therefore be implemented in the
following chapter.

.. [50] Rafal Wojtczuk, Joanna Rutkowska Attacking Intel TXT®via SINIT code
   execution hijacking, 11/2011

.. [64] https://marc.info/?t=156851721400002&r=1&w=4

