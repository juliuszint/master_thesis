#!/bin/sh

if [[ $# -eq 0 ]]; then
   timedatectl set-ntp true

   # disk setup
   parted -s -a optimal -- /dev/sda \
       mklabel msdos\
       unit MiB\
       mkpart primary ext4 1 101\
       mkpart primary ext4 101 100%\
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