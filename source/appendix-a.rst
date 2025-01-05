QubesOS with AEM
++++++++++++++++
Test system
===========
The following guide is for a Lenovo Thinkpad X240 (20AMS21B00). This device is
equipped with an Intel® Core i7-4600U processor. This processor supports Intel®
Directed-I/O Virtualization Technology (VT-d), Intel® Virtualization Technology
(VT-x), and Intel® Trusted Execution Technology, thereby meeting all the
requirements for the Qubes-AEM extension.

  Intel® Virtualization Technology (VT-x) allows one hardware platform to
  function as multiple “virtual” platforms. It offers improved manageability by
  limiting downtime and maintaining productivity by isolating computing
  activities into separate partitions. [66]_

  Intel® Virtualization Technology for Directed I/O (VT-d) continues from the
  existing support for IA-32 (VT-x) and Itanium® processor (VT-i) virtualization
  adding new support for I/O-device virtualization. Intel VT-d can help end
  users improve security and reliability of the systems and also improve
  performance of I/O devices in virtualized environments. [66]_

The notebook features a dedicated TPM 1.2 chip from STMicroelectronics. In
addition, it is also possible to activate a TPM 2.0. However, this is emulated
by firmware and runs on the Management Engine integrated into the CPU. This
technology is referred to by Intel® as Intel® PPT (Intel® Platform Trusted
Technology) [1]_. Code :numref:`test-system-tpm-version` shows the detailed
version information for the dedicated TPM 1.2 chip.

.. code-block::
   :caption: TPM version information
   :linenos:
   :name: test-system-tpm-version

    $ tpm_version
      TPM 1.2 Version Info:
      Chip Version:         1.2.13.12
      Spec Level:           2
      Errata Revision:      3
      TPM Vendor ID:        STM
      Vendor Specific data: 50
      TPM Version:          01010000
      Manufacturer Info:    53544d20

The installed firmware is UEFI, and its version information can be viewed in
:numref:`test-system-uefi-version`. The user interface allows switching between
the dedicated TPM 1.2 chip, the emulated TPM 2.0, or neither. Intel® TXT can be
enabled or disabled, and the firmware supports both UEFI and (Legacy) MBR
bootloaders. The boot option in the firmware can be set to one of three possible
values: UEFI Only, Legacy Only, or Both.

.. code-block::
   :caption: UEFI version information
   :linenos:
   :name: test-system-uefi-version

    UEFI BIOS Version           GIET92WW (2.42)
    UEFI BIOS Date              2018-02-28
    Embedded Controller Version GIHT32WW (1.17)
    ME Firmware Version         9.5.62.3002
    Machine Type Model          20AMS21B00


UEFI configuration
==================
As a first step, the UEFI should be reset to factory settings to ensure a
defined starting state. To do this, select the 'Restart' tab and then choose the
'Load Setup Defaults' option. The 'OS Optimized Defaults' option was not
activated during this work. This reset has no effect on the settings in the
``Security`` and ``Date & Time`` tabs

In the ``Startup`` tab, the ``UEFI / Legacy Boot`` option must be set to
``Legacy Only``. Without this setting, the Qubes 4.0.1 installer will not start,
and the AEM module of Qubes explicitly requires Legacy Boot. With this
configuration, the firmware searches for the bootloader not on an EFI partition
but in the MBR, i.e., the first 512 bytes of the hard drive.

In the ``Security`` tab, the ``Security Chip`` entry must be selected next.
Pressing Enter opens the configuration options for this setting. First, the
'Security Chip Selection' option must be set to ``Discrete TPM``, enabling the
dedicated TPM 1.2 chip and disabling the emulated TPM 2.0. The AEM extension of
Qubes requires a TPM chip of version 1.2. The following option, ``Security
Chip``, must then be set to ``Active``.

Resetting the TPM chip is not strictly necessary at this stage, but this step
must be completed before installing the AEM module at the latest. To reset, the
``Clear Security Chip`` option must be selected and confirmed by pressing Enter.
After answering the security prompt with ``Yes``, the TPM chip will be reset and
ready for setup by the AEM module.

Finally, the Intel Trusted Execution Technology must be enabled. To do this, set
the option ``Intel (R) TXT Feature`` to ``Enabled``. This is the last necessary
UEFI setting to enable a measured boot using the AEM extension available in
QubesOS.

Installing QubesOS
==================
First, the operating system must be downloaded from the QubesOS homepage [67]_.
All versions, including QubesOS 1 (the first release), are available for
download, and at the time of writing this work, 4.0.1 was the latest version. In
addition to the ISO, which is the image of the installation CD, the
corresponding signature should also be downloaded. As an alternative to
downloading via the browser, lines 1 and 2 of :numref:`setup-prep-qubes-os` can
be executed.

.. code-block:: bash
   :caption: Setup preparation QubesOS
   :linenos:
   :name: setup-prep-qubes-os

   curl -O https://mirrors.edge.kernel.org/qubes/iso/Qubes-R4.0.1-x86_64.iso
   curl -O https://mirrors.edge.kernel.org/qubes/iso/Qubes-R4.0.1-x86_64.iso.asc

   gpg --fetch-keys https://keys.qubes-os.org/keys/qubes-master-signing-key.asc
   gpg --fetch-keys https://keys.qubes-os.org/keys/qubes-release-4-signing-key.asc
   gpg --fingerprint
   gpg --verify Qubes-R4.0.1-x86_64.iso.asc

   dd if=Qubes-R4.0.1-x86_64.iso of=/dev/rdiskX bs=1M report=status

To ensure the integrity and authenticity of the download, it is recommended to
verify it using GNU Privacy Guard (GPG). Qubes uses a unique signature key for
each release, which is itself signed with the Qubes Master Signing Key. The
import of this master key into GPG is done using the command in line 4 of Code
:numref:`setup-prep-qubes-os`.

After the import, it must be ensured via the fingerprint that the key downloaded
from the internet is indeed the actual Qubes Master Signing Key. Using the
command in line 6 of :numref:`setup-prep-qubes-os`, you can display the
fingerprints of all keys.

.. code-block::
   :caption: Qubes Master Signing Key
   :linenos:
   :name: qubes-gpg

    pub   rsa4096 2010-04-01 [SC]
          427F 11FD 0FAA 4B08 0123  F01C DDFA 1A3E 3687 9494
    uid           [ultimate] Qubes Master Signing Key

Here, you look for the fingerprint of the Qubes Master Signing Key and compare
it with several sources. These sources can include not only various internet
sources but also documents, printed T-shirts, or a colleague. The fingerprint of
the Qubes Master Signing Key is also provided in this document in
:numref:`qubes-gpg`.

Next, we instruct GPG to trust the imported key by executing the command from
line 7 in Code :numref:`setup-prep-qubes-os`. The output of this command should
indicate: ``Good signature from "Qubes OS Release 4 Signing Key"``. If this
message appears, the authenticity and integrity of the downloaded file are
successfully verified.

The ISO image can then be transferred to a USB stick using the command from line
9 in Code :numref:`setup-prep-qubes-os`. To initiate the boot process from this
device, press ``F12`` to access the One-Time Boot Menu and select the USB stick
as the boot device.

No modifications were made during the setup process for this work. The keyboard
layout was set to German (DE), and the time zone was configured as
Europe/Berlin. The installation was carried out on the internal hard drive.
Partitioning was left to the setup's default configuration, and full disk
encryption was enabled as per the default settings.

After completing the installation, a system reboot is required, after which the
second part of the setup process begins. During this phase, the newly installed
system is configured. The default settings were kept throughout. However, if one
does not wish to use an external storage device as a boot medium, as outlined in
the following instructions, the following should be considered:
The Thinkpad does not support booting from an SD card. Therefore, only a USB
storage device can be used as an external boot medium. If a separate Qube for
USB devices is created, these devices will not be visible from Dom0 without
additional configuration. This step is essential for creating the external boot
medium, so it may be worth reconsidering the decision to enable the USB-Qube.

Once the configuration step is completed, QubesOS is fully installed, and the
setup of the AEM solution can begin.

Installation and configuration of the AEM module
================================================
After successfully booting into the newly installed system, the next step
involves installing the Anti-Evil-Maid (AEM) package. This is accomplished by
opening a terminal in Dom0 and executing the command provided in line 1 of Code
:numref:`qubes-aem-setup`.

If the TPM was not reset during the UEFI configuration process, this step must
now be completed, as detailed in :ref:`UEFI configuration`. This guide does not
utilize an external boot medium; instead, the boot partition on the internal
hard drive is used. To ensure the security of this approach, an SRK password
must be set. Failure to perform this step would allow unauthorized individuals
to start the system and access the secret, potentially enabling the setup of a
system that appears legitimate but operates with manipulated software. To
initialize the TPM, execute the command specified in line 3 of Code
:numref:`qubes-aem-setup`. Once completed, the TPM is initialized and ready for
use.

The Intel Trusted Execution Technology (Intel TXT) operates not as a 'Static
Root of Trust for Measurement,' where a small, immutable portion of the firmware
serves as the Root of Trust for Measurement, but as a 'Dynamic Root of Trust for
Measurement.' In this approach, firmware may execute prior to initiating a
Measured Launch without compromising the integrity of the measurements. The
software that is executed first during a Measured Launch, albeit unmeasured, is
mutable and not embedded in a processor ROM. While this allows for easy updates,
it also makes the software susceptible to manipulation by attackers. To mitigate
this risk, the processor ensures that the software it executes is signed by
Intel.

The required software binary must be downloaded from Intel's website [68]_. The
selection interface on the website may appear confusing, as multiple entries for
the same file may be listed. However, with few exceptions, each processor
generation has a single applicable version. For the 4th generation, specifically
the Intel® Core i7-4600U, the file ``4th-gen-i5-i7-sinit-75.zip`` is required.
The ``.BIN`` file contained within this archive must be copied to the ``/boot``
directory. This can be achieved using the commands provided in lines 5, 6, and 7
of Code :numref:`qubes-aem-setup`.

.. code-block:: bash
   :caption: Qubes AEM setup
   :linenos:
   :name: qubes-aem-setup

    $ qubes-dom0-update anti-evil-maid

    $ anti-evil-maid-tpm-setup

    $ unzip 4th-gen-i5-i7-sinit-75.zip
    $ cd 4th_gen_i5_i7-SINIT_75
    $ cp 4th_gen_i5_i7_SINIT_75.BIN /boot/

    $ anti-evil-maid-install /dev/sda1

The final step, executed via line 9 of Code :numref:`qubes-aem-setup`, completes
the installation process. For this work, the use of an external boot medium was
deliberately omitted, opting instead to house all components required for the
Measured Launch on the system's boot partition. Upon successful completion of
this step, two undocumented modifications must be applied. These adjustments are
necessary due to errors in the AEM package version ``4.0.1-1.fc25`` — the most
current version available at the time of writing — when installed on an internal
storage device. As stated in the tboot README:

  For Grub2, the new tboot module must be added as the ``multiboot`` in the
  grub.conf file. The existing ``kernel`` entry should follow as a ’module’. The
  SINIT AC module must be added to the grub.conf boot config as the last module
  [69]_


The final issue, unaddressed by the installer, requires manual correction. To
resolve this, the ``/boot/grub2/grub.cfg`` file must be edited. After
installation, this file contains a menuentry labeled ``AEM Qubes, with Xen
hypervisor``. The associated block, enclosed by curly braces, must be modified
to include the ``SINIT`` file as a module before the closing brace. The complete
modified entry is provided in :numref:`qubes-grub-entry`, with the newly added
line appearing as line 23.

.. code-block::
   :caption: Qubes Master Signing Key
   :linenos:
   :name: qubes-grub-entry

    menuentry 'AEM Qubes, with Xen hypervisor' --class qubes --class gnu-linux --class gnu --class os --class xen $menuentry_id_option 'xen-gnulinux-simple-/dev/mapper/qubes_dom0-root' {
        insmod part_msdos
        insmod ext2
        set root='hd0,msdos1'
        if [ x$feature_platform_search_hint = xy ]; then
            search --no-floppy --fs-uuid --set=root --hint-bios=hd0,msdos1 --hint-efi=hd0,msdos1 --hint-baremetal=ahci0,msdos1 --hint='hd0,msdos1'  dde37052-fef8-4e28-8269-309e89771560
        else
            search --no-floppy --fs-uuid --set=root dde37052-fef8-4e28-8269-309e89771560
        fi
        echo      'Loading tboot ...'
        multiboot /tboot.gz placeholder logging=memory,serial,vga vga_delay=10
        echo      'Loading Xen 4.8.4 ...'
        if [ "$grub_platform" = "pc" -o "$grub_platform" = "" ]; then
            xen_rm_opts=
        else
            xen_rm_opts="no-real-mode edd=off"
        fi
        module    /xen-4.8.4.gz placeholder  console=vga dom0_mem=min:1024M dom0_mem=max:4096M iommu=required ucode=scan smt=off ${xen_rm_opts}
        echo      'Loading Linux 4.14.74-1.pvops.qubes.x86_64 ...'
        module    /vmlinuz-4.14.74-1.pvops.qubes.x86_64 placeholder root=/dev/mapper/qubes_dom0-root ro rd.luks.uuid=luks-309f38e0-e318-4b41-9c15-79e21888bd01 rd.lvm.lv=qubes_dom0/root rd.lvm.lv=qubes_dom0/swap i915.alpha_support=1 rhgb quiet  aem.uuid=dde37052-fef8-4e28-8269-309e89771560 rd.luks.key=/tmp/aem-keyfile rd.luks.crypttab=no
        echo      'Loading initial ramdisk ...'
        module    /initramfs-4.14.74-1.pvops.qubes.x86_64.img
        module    /4th_gen_i5_i7_SINIT_75.BIN
    }

An additional adjustment is necessary to prevent the notebook from freezing at
startup, displaying only a black screen. This modification involves assigning
the required value to the iommu parameter, as shown in line 18 of
:numref:`qubes-grub-entry`.

After modifying the grub.conf file, a secret is stored in the secret.txt file
located in the ``/var/lib/anti-evil-maid/aem/`` directory. This secret can be
chosen arbitrarily, but the file size must not exceed 255 bytes. Upon the
system's first boot, this secret is sealed with the TPM. During all subsequent
boots, the secret is displayed prior to the password prompt appearing.

tboot logging
=============
The logging functionality provided by tboot proved to be highly beneficial. To
identify issues during startup or to gain deeper insights into the system's
behavior, the logging parameter (as shown in :numref:`qubes-grub-entry` line 11)
can be set to include the value vga. This configuration enables log messages to
be displayed directly on the screen during boot. Additionally, by setting the
vga_delay parameter, as shown in the listing, to a value of 10, the system
pauses for 10 seconds after each full screen of log messages, allowing
sufficient time for review.

Logging can be enabled not only for ``tboot`` but also for the Xen hypervisor
and the Linux kernel. This comprehensive logging capability facilitates detailed
diagnostics and provides valuable insights into the behavior of the system
components during the boot process


.. [1] Matthew Garrett, Trusted Platform Module nutzen, Linux Magazin, 11/2017

.. [66] https://www.intel.com/content/www/us/en/products/sku/76616/intel-core-i74600u-processor-4m-cache-up-to-3-30-ghz/specifications.html

.. [67] QubesOS homepage: https://www.qubes-os.org/downloads/

.. [68] Intel SINIT https://software.intel.com/protected-download/267276/183305

.. [69] TBoot Readme: https://sourceforge.net/projects/tboot/
