Linux with TrustedGRUB2
+++++++++++++++++++++++
This appendix details the setup used for the analysis of TrustedGRUB2. The
hardware configuration is identical to that described in :ref:`Test system`.
TrustedGRUB2 is not utilized as the default bootloader in any Linux
distribution. Furthermore, it is absent from the standard package repositories
typically associated with Linux systems. Consequently, the choice of
distribution was unrestricted and Arch Linux was selected for this study.

Unlike widely-used Linux distributions such as Ubuntu, Arch Linux does not
provide a standard installation assistant. The installation is entirely manual,
carried out by executing commands within a shell provided by the Arch live
environment. This environment contains all the necessary tools to perform a
complete Arch installation. While this process requires advanced technical
knowledge, for instance, on system partitioning, it offers significant
advantages, such as the ease of repeating the installation and creating a system
that contains only the desired programs.

Arch Linux setup script
=======================
:numref:`arch-setup-script` shows the complete installation script that was
created as part of this work for the analysis of TrustedGRUB2. The exact version
details of Arch Linux, under which the script was developed and tested, can be
found in :numref:`arch-versions`. This also includes further versions of
installed programs, such as gcc or make. Arch uses a rolling release model,
which makes it more challenging to set up a system with matching versions at a
later time. As will be evident throughout this chapter, this is desirable in
order to avoid newly introduced compiler warnings when compiling TrustedGRUB2.
For active open-source projects, this is not a problem, as patches for such
issues are quickly made available.

.. code-block:: bash
   :caption: Arch Linux Versions
   :linenos:
   :name: arch-versions

    $ uname -a
    Linux arch-master 5.3.5-arch1-1-ARCH #1 SMP PREEMPT Mon Oct 7 19:03:00 UTC 2019 x86_64 GNU/Linux

    $ gcc --version
    gcc (GCC) 9.2.0

    $ make --version
    GNU Make 4.2.1

    $ python --version
    Python 3.7.4

The remainder of this chapter focuses on explaining the script from
:numref:`arch-setup-script` and the setup of TrustedGRUB2. Any lines that are
not specifically discussed here are directly taken from the Arch installation
[70]_ guide and can be referenced there if needed.

.. code-block:: bash
   :caption: Arch Linux Setup Script
   :linenos:
   :name: arch-setup-script

    #!/bin/sh

    if [[ $# -eq 0 ]]; then
       timedatectl set-ntp true

       # disk setup
       parted -s -a optimal -- /dev/sda \
           mklabel msdos \
           unit MiB \
           mkpart primary ext4 1 101 \
           mkpart primary ext4 101 100% \
           toggle 1 boot

       # full disk encryption
       cryptsetup -y -v luksFormat /dev/sda2
       cryptsetup open /dev/sda2 cryptroot

       mkfs.ext4 /dev/sda1
       mkfs.ext4 /dev/mapper/cryptroot

       mount /dev/mapper/cryptroot /mnt
       mkdir /mnt/boot
       mount /dev/sda1 /mnt/boot

       # installation
       TGRUB_PACKAGES='git autogen autoconf automake bison flex python gcc make'
       pacstrap /mnt linux base grub iputils openssh vim dhclient cryptsetup $TGRUB_PACKAGES
       genfstab -U /mnt >> /mnt/etc/fstab

       SCRIPTNAME=$(basename $0)
       cp $0 /mnt/
       arch-chroot /mnt /$SCRIPTNAME 1
       rm /mnt/$SCRIPTNAME
    else
        # timezone
        ln -sf /usr/share/zoneinfo/Europe/Berlin /etc/localtime
        hwclock --systohc

        # localization
        sed -i 's/#en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen
        locale-gen
        echo 'LANG=en_US.UTF-8' > /etc/locale.conf
        echo 'KEYMAP=de' > /etc/vconsole.conf

        # network configuration
        HOSTNAMEFILE=/etc/hostname
        HOSTSFILE=/etc/hosts
        HOSTNAME='arch-master'
        echo "$HOSTNAME" > $HOSTNAMEFILE
        echo "127.0.0.1        localhost" >> $HOSTSFILE
        echo "::1              localhost" >> $HOSTSFILE
        echo "127.0.0.1        $HOSTNAME.localdomain $HOSTNAME" >> $HOSTSFILE

        # prepare boot for full disk encryption
        sed -i -E 's/^HOOKS=\([a-z ]+\)$/HOOKS=(base udev autodetect keyboard keymap consolefont modconf block encrypt filesystems fsck)/' /etc/mkinitcpio.conf
        mkinitcpio -P
        CDEVUUID=$(blkid -o value /dev/sda2 | head -n 1)
        sed -i -E "s/^GRUB_CMDLINE_LINUX=\"\"/GRUB_CMDLINE_LINUX=\"cryptdevice=UUID=$CDEVUUID:cryptroot\"/" /etc/default/grub

        # grub setup
        grub-install --target=i386-pc /dev/sda
        grub-mkconfig -o /boot/grub/grub.cfg

        # password
        passwd
    fi

Partitionierung und FDE
-----------------------
Lines 7 to 12 format and partition the disk. The disk is divided into Partition
1 with 100 MiB and Partition 2, which follows Partition 1 and occupies the
remaining disk space. Additionally, the boot flag is enabled for Partition 1. A
separate home or swap partition is deliberately omitted to avoid added
complexity. This is the simplest possible partitioning scheme for a system with
full disk encryption (FDE), where Partition 1 remains unencrypted and encryption
is activated for Partition 2.

The encryption takes place in lines 15 and 16. There, cryptsetup, the Linux
userspace tool for managing full disk encryption (FDE), is used to create a
virtual block device, which transparently handles encryption and decryption. In
the background, ``dm-crypt`` is employed, utilizing the device-mapper framework
of the Linux kernel. The encryption keys are persisted on the disk through LUKS
[21]_. After entering the passphrase twice — once to create and once to open the
encrypted volume — a virtual block device is created at
``/dev/mapper/cryptroot``, which handles the encryption and decryption process
and is used for further work.

Just like Partition 1, the encrypted partition is initialized with a file
system. In both cases, ``ext4`` is used, and the initialization is carried out
in lines 18 and the following. After this step, Partition 2 is mounted at
``/mnt`` and Partition 1 at ``/mnt/boot``. With the execution of line 23, the
preparation of the disk is complete, and the installation of the operating
system can now begin.

OS packages
-----------
In line 27, the pacstrap command is used to install the operating system and all
necessary software components. The package ``linux`` installs the Linux kernel
and the required modules. Along with the package ``base``, which installs the
init system systemd and other programs such as bash, this forms the minimal
possible Arch Linux setup.

The ``grub`` package is used to install the bootloader of the same name.
However, this does not yet include TrustedGRUB2. TrustedGRUB2 is only created
and installed later, after the system installation is complete. The package
includes ``grub-install``, a program that will be used to complete the
bootloader installation at a later stage.

The network configuration is handled by the ``iputils`` and ``dhclient``
packages. The openssh package allows for file transfers via scp, enabling the
later availability of the patch file for TrustedGRUB2 on the system. ``vim`` is
a text editor and is only necessary if further changes to text files are
required. These tools do not directly relate to TrustedGRUB and are only
intended to provide a minimal operating system for compiling the bootloader.

The packages summarized in the shell variable ``TGRUB_PACKAGES`` are necessary
for compiling TrustedGRUB2. ``autogen``, ``autoconf``, ``automake``, ``gcc``,
``bison``, and ``flex`` are explicitly mentioned in the README as prerequisites
for building TrustedGRUB2. Additionally, it was found that ``python`` and
``make`` are also required. ``git``, of course, is not needed for the
compilation process itself but is used to clone the repository.

In the ``/mnt`` directory, all necessary files for a functional Linux system are
placed. The arch-chroot command is used to set ``/mnt`` as the new root
filesystem and execute the setup script with the parameter ``1``, triggering the
``else`` branch. This simplifies the setup by using a single script. The script
is copied to the new root directory in line 31.

The execution starts in line 34, configuring the newly installed system rather
than the live environment. Unlike the Arch installation guide, only the commands
needed to enable the system to boot with an encrypted root partition are
included.

Grub und initramfs
------------------
Lines 55 and 56 extend the initramfs to include the modules required by the
kernel for booting with an encrypted root partition. The ``keyboard`` and
``keymap`` modules allow password entry using a German keyboard layout, while
the 'encrypt' module is necessary for the kernel to handle encrypted partitions.
After modifying the configuration file, the command mkinitcpio is used to
generate a new initramfs image. This image is subsequently loaded into memory by
the bootloader, in this case, GRUB, and passed to the kernel.

After the necessary tools for installing GRUB have been added to the system
during package installation, the bootloader must be installed on the disk by
executing grub-install, as performed in line 61. Line 62 generates the
configuration file required by GRUB. Subsequently, the password for the root
account is set. Once these commands in the else branch have been completed, the
process concludes, triggering the execution of the final commands in the if
branch. These include the removal of the setup script, signaling the completion
of the installation. After a reboot, the system is ready for login with the root
account, and the process of compiling TrustedGRUB2 can begin.

Setting up TrustedGRUB2
=======================
In order to successfully compile TrustedGRUB2 on the freshly installed system,
several patches must be applied after cloning the repository [71]_. This is
necessary because new warning messages were introduced in GCC versions 8 and 9.
The latest commit in the TrustedGRUB2 repository (e656aaa) was made on June 8,
2017, suggesting that the project was last compiled with GCC 7, as GCC 8.1 was
released in May 2018.

:numref:`tgrub2-patches` presents all the applied patches. The first patch
originates from a pull request on GitHub that was not merged into the master
branch. Since this work only requires a functional system with TrustedGRUB2 for
analysis, the patch was not further investigated, although it suggests an unused
variable in the code. All subsequent patches are from the GRUB2 GitHub [72]_
repository and address issues introduced by the newer versions of GCC. The file
``fix_build_with_gcc9.patch`` is provided with this work, consolidating all
changes into a single patch. These changes can be applied to the checked-out
version using the ``git apply`` command.

.. code-block::
   :caption: Patches for TrustedGRUB2
   :linenos:
   :name: tgrub2-patches

    # Juni 2017
    de21808 disable unused-value warning

    # März  2018
    563b1da Fix packed-not-aligned error on GCC 8

    # April 2019
    4dd4cee efi: Fix gcc9 error -Waddress-of-packed-member
    4868e17 chainloader: Fix gcc9 error -Waddress-of-packed-member
    85e08e1 usbtest: Fix gcc9 error -Waddress-of-packed-member
    0b1bf39 acpi: Fix gcc9 error -Waddress-of-packed-member
    6210240 hfsplus: Fix gcc9 error -Waddress-of-packed-member
    0e49748 hfs: Fix gcc9 error -Waddress-of-packed-member
    4f4128d jfs: Fix gcc9 error -Waddress-of-packed-member
    7ea474c cpio: Fix gcc9 error -Waddress-of-packed-member

The compilation process follows the four commands outlined in the README.
Afterward, the TrustedGRUB2 binaries are located in the directory specified by
the prefix during configuration. Running grub-install from the sbin subdirectory
installs TrustedGRUB2 on the hard drive. The exact commands are provided in the
README. Following installation, a reboot should reflect the changes in the PCR
(Platform Configuration Registers)

:numref:`pcr-values-grub-tgrub` displays the contents of the PCR registers at
the top, showing the values after a boot without TrustedGRUB2, and at the
bottom, the values after booting with TrustedGRUB2. PCR registers 08 to 11 show
their initial values at the top, but not at the bottom. This indicates that no
extend operation was called for these PCR registers during the boot without
TrustedGRUB2, but it was triggered during the boot with TrustedGRUB2. This
outcome was expected and confirms that TrustedGRUB2 is functioning as intended.

.. code-block::
   :caption: PCR values Grub vs TrustedGrub
   :linenos:
   :name: pcr-values-grub-tgrub

    # regular Grub
    PCR-06: EE 1B 0F 99 7D 75 17 B2 86 BC 9D 73 A4 CF 74 2C 65 A7 69 BE
    PCR-07: B2 A8 3B 0E BF 2F 83 74 29 9A 5B 2B DF C3 1E A9 55 AD 72 36
    PCR-08: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    PCR-09: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    PCR-10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    PCR-11: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

    # trusted Grub
    PCR-06: EE 1B 0F 99 7D 75 17 B2 86 BC 9D 73 A4 CF 74 2C 65 A7 69 BE
    PCR-07: B2 A8 3B 0E BF 2F 83 74 29 9A 5B 2B DF C3 1E A9 55 AD 72 36
    PCR-08: D3 F6 C9 85 14 27 D4 09 F4 77 F9 F4 98 DD C3 5B 3C 7A 84 E4
    PCR-09: F6 46 86 9A 9E B6 19 CF E1 63 40 1B B5 DA 55 6B 6A 0C 0A F5
    PCR-10: C1 28 20 C2 A8 58 03 09 0E 4A C9 BB 23 D1 7F 53 B8 E4 D3 03
    PCR-11: 94 B6 B9 E4 0E 8A 22 1E D0 23 CB CB B3 1F CF 2A 85 38 BF 30


.. [21] Michael Nerb Workshop: Notebook-Platten mit DM-Crypt und LUKS komplett
   verschlüsseln, LinuxMagazin, 10/2006

.. [70] Arch Installation Guide: https://wiki.archlinux.org/index.php/Installation_guide

.. [71] TrustedGRUB2: https://github.com/Rohde-Schwarz/TrustedGRUB2

.. [72] GRUB2 Github: https://github.com/rhboot/grub2
