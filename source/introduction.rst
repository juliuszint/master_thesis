Introduction
++++++++++++
Full Disk Encryption (FDE) is now widely implemented on many mobile computing
devices, often enabled by default or easily activated post-installation. Since
macOS 10.14, FileVault has provided the ability to encrypt the disk contents
using AES-XTS-128 with minimal configuration [5]_.

Starting with Windows 10 version 1511 Pro or Enterprise, BitLocker has supported
both AES-CBC and AES-XTS with 128-bit or 256-bit block sizes for FDE [6]_.
OpenBSD, on the other hand, employs AES-XTS-256 for disk encryption [7]_
(softraid_crypto.c) Similarly, Fedora, QubesOS, Linux Mint, and Manjaro all
offer built-in options for disk encryption during installation.

Consequently, most major operating systems relevant to the consumer market
provide solutions for protecting user data from unauthorized access when the
device is powered off

When considering the security of Full Disk Encryption (FDE), the algorithm used
for encryption is just as important as the key management. While all operating
systems have the capability to encrypt with the Advanced Encryption Standard
(AES), there are differences in key management. Let's first look at the security
of AES.

The block cipher Rijndael was selected by the National Institute of Standards
and Technology (NIST) in November 2001 as the Advanced Encryption Standard (AES)
for protecting electronic data [8]_. Rijndael emerged as the most suitable
candidate from a selection process among five finalists—Rijndael, MARS, RC6,
Serpent, and Twofish—based on criteria such as security, cost, and algorithmic
and implementation characteristics [9]_ (p. 436). Up until that point, no
security vulnerabilities had been identified in Rijndael [10]_ (p. 558).

Since then, several attacks on AES have been developed, such as Biclique
Cryptanalysis of the Full AES [13]_. However, none of these methods have
successfully reduced the keyspace to a size that could feasibly be tested within
a reasonable time frame. Consequently, AES is still regarded as a secure
encryption method. In the event of a brute-force attack, AES with a 128-bit key
would require testing up to 2^128 possible keys in the worst-case scenario. Even
with modern hardware or cloud computing resources in 2020, this process would
take several years to complete. Thus, AES provides a high level of data
security, as long as the key is both **random** and kept **secret**.

Predictable and thus non-random keys are a common security vulnerability. It is
essential for Full Disk Encryption (FDE) keys to be cryptographically secure.
Software should therefore employ a Cryptographically Secure Random Number
Generator (CSRNG) to generate key material. If the key is user-generated, users
are encouraged to choose one that is as random as possible. Password management
software, such as KeePass, can assist with this process. When keys are randomly
generated, an attacker is forced to attempt every possible key, which, for AES,
is a time-intensive process.

.. TODO: ref für chapter 2.1

Secure storage of key material is just as important as its random generation.
Full Disk Encryption (FDE) protects data confidentiality against individuals
with **physical access** to the device. However, if an attacker gains access to
the hardware, several attack vectors may be exploited to compromise the key.
Such attacks are often described by the term "Evil Maid Attack" (EMA), referring
to attacks by malicious personnel. Chapter 2.1 provides a detailed description
of these attacks. For the purposes of this introduction, it is important to
understand that, despite FDE, the portion of the software that prompts for the
password remains unencrypted on the storage device. An attacker can replace
these unencrypted programs with a modified version that captures and transmits
the password to them. An example of how to mitigate this type of attack can be
seen in Bitlocker’s key management.

BitLocker offers a total of five authentication methods to release the Volume
Master Key (VMK), which is then used to decrypt the Full-Volume Encryption Key
(FVEK). The FVEK, in turn, is used to encrypt and decrypt the data. [11]_, [14]_
(p. 33 ff)

1. **BitLocker with Trusted Platform Module (TPM):** In this configuration, the
   Volume Master Key (VMK) is stored within the TPM. To retrieve it, the
   Platform Control Registers (PCRs) of the TPM must have the same values as
   when the VMK was initially stored. This method is completely transparent to
   users but provides a lower level of data protection compared to other
   methods.

2. **BitLocker with USB Device:** This option is suitable for computers without
   a built-in TPM. In this configuration, a key is stored on a USB drive, which
   is used to decrypt the Volume Master Key (VMK). Accessing confidential data
   requires both the computer and the USB drive.

3. **BitLocker with TPM and PIN:** As in the first configuration, the TPM is
   used to store the Volume Master Key (VMK). In addition to matching the
   correct Platform Control Register (PCR) values, users must also enter a
   Personal Identification Number (PIN). The TPM provides protection against
   brute-force attacks by introducing time delays.

4. **BitLocker with TPM and USB Device:** In this configuration, a USB drive is
   used as the second factor instead of a PIN, as in the third option. Both the
   third and fourth configurations have their respective strengths and
   weaknesses. The PIN-based solution is vulnerable to “shoulder surfing,”
   whereas a USB drive is more susceptible to theft.

5. **BitLocker with TPM and Network:** In this setup, a trusted network is used
   as a second factor. A Windows Deployment Services (WDS) server within the
   network responds to a request from the client to decrypt the second factor.
   This request is encrypted with a private key that is stored exclusively on
   the WDS server [14]_ (p. 59). The advantage of this solution is its complete
   transparency to users, as long as they are connected to the corporate
   network.

The carefully selected standards and the comprehensive configuration options
position BitLocker as an exemplary implementation of Full Disk Encryption (FDE).


Tasks
=====
Although OpenBSD offers FDE during installation, it lacks the ability to utilize
TPM for managing key material. When setting up an encrypted OpenBSD
installation, users can opt to use either a regular password or a key disk,
which is a USB drive containing the key. The second-stage bootloader,
``boot(8)``, either searches for the key disk or prompts the user to enter the
password. The bootloader ``boot(8)`` is stored unencrypted on the hard drive,
making it susceptible to manipulation. Users have no means of detecting such an
attack.

OpenBSD aims to be a global leader in the field of IT security and boldly claims
that it may already have achieved this status. However, this is not yet the case
in the area of key management for Full Disk Encryption (FDE), as evidenced by a
comparison with Windows.

The following quote is from the OpenBSD website.

    **Secure by Default**

    To ensure that novice users of OpenBSD do not need to become security
    experts overnight (a viewpoint which other vendors seem to have), we ship the
    operating system in a Secure by Default mode. All non-essential services are
    disabled. As the user/administrator becomes more familiar with the system,
    he will discover that he has to enable daemons and other parts of the system.
    During the process of learning how to enable a new service, the novice is
    more likely to learn of security considerations. ... [15]_

This is not the case for Full Disk Encryption (FDE). Without intervention,
an OpenBSD installation is performed unencrypted. Automatically enabling FDE
during a new installation would likely cause inconvenience for many users,
as an additional password would need to be entered at startup. This input is
not possible at all for servers that are administered solely via SSH. If
OpenBSD had the ability to use TPM, it would be much more realistic to
enable FDE automatically.

Setting up a system with FDE under OpenBSD is significantly more complicated.
During installation, users must resort to the command line, where they manually
configure the pseudo-device responsible for encryption and decryption using the
``softraid(4)`` driver and ``bioctl(8)``. This process is likely to deter new
users from attempting to set up a system with FDE.

The argument that once hardware is in the hands of an attacker, it can no longer
be trusted, is often used as a catch-all dismissal when discussing Trusted
Computing [16]_. IT systems are never 100% secure; they can only be made
progressively more secure. For example, by adding a new layer of protection in
the form of key management via TPM.

If an attacker is determined to access the contents of a victim's hard drive,
the step from copying unencrypted data to performing an Evil Maid Attack (EMA)
is relatively small. When FDE is enabled, it implicitly assumes that
unauthorized individuals may gain physical access to the device. If these
individuals are willing to obtain offline access to the data, they are very
likely also prepared to replace the bootloader.

Another advantage of key management using a TPM is the potential for complete
transparency to users. Microsoft makes the following statement in the BitLocker
documentation:

    The best type of security measures are transparent to the user during imple-
    mentation and use. Every time there is a possible delay or difficulty because
    of a security feature, there is strong likelihood that users will try to bypass
    security. [14]_ (p. 8)


.. TODO: could be a reference

Configuration 1 of BitLocker demonstrates how Full Disk Encryption (FDE) can be
implemented in a completely transparent manner for users. They are not required
to enter a password, nor are there noticeable performance degradation. If
OpenBSD also supported TPM, a fully transparent solution would be possible as
well.

With TPM, data decryption can not only be tied to a device but also to the
software being executed. User-friendliness and enhanced security are thus
important arguments for integrating TPM into the boot process with FDE. This is
the purpose of this work, which incorporates TPM into the boot process of
OpenBSD.

Goals
=====
The goal is to develop a solution that enables the detection of modifications to
software components that remain unencrypted in an OpenBSD installation with FDE.
Any manipulation must be detectable before users enter the password for
decrypting the drive.

The software components will be measured at startup using a TPM for this
purpose. Whether a Static Root of Trust for Measurement (SRTM) or a Dynamic Root
of Trust for Measurement (DRTM) will be used is not yet determined and will be
evaluated as part of this work.

The ``seal`` and ``unseal`` functions of the TPM, in combination with the
measurements, are used to encrypt a secret. This secret is displayed on the
screen at startup, before the password for decrypting the disk is entered.

Users are able to make a determination about the state of the system based on
the displayed secret and, depending on the result, decide whether or not to
enter the password for the FDE.

Structure
=========
The first step of this work is to refine the attack scenarios. Evil Maid
encompasses several attack scenarios under a single term, and not all of them
can be detected through a measured operating system boot.

An in-depth analysis of Trusted-Grub and QubesOS-AEM examines two existing
open-source solutions. This leads to a better overall understanding of a
measured OS boot and how it can be implemented. A solution through the
composition of existing software components is also conceivable.

Based on the information gathered, a solution approach is then selected, which
excels for the criteria of implementation effort, user-friendliness, and
security.

If a solution approach is identified and deemed feasible, it will be implemented
as part of the master’s thesis. Should the solution require modifications to
OpenBSD, efforts will be made to integrate these changes directly into the
mainline of OpenBSD.

Contributions
=============
During the course of this work, QubesOS was installed and tested to analyze the
AEM package. This was successful on the Thinkpad X240. However, it was not
successful on a Dell XPS 15 and a Thinkpad T410. The Hardware Compatibility List
(HCL_) was updated during this step with an entry for the Thinkpad X240. The
HCL_ serves as the first point of contact to check whether a specific hardware
is compatible with QubesOS.

During the analysis of the test system with QubesOS and the AEM extension,
problems occurred when importing the barcode into a two-factor authentication
app. Troubleshooting revealed that there was a line break at the end of the
Uniform Resource Locator (URL) encoded in the barcode. The pull request `#31`_
with the fix was accepted within one day and merged into the master branch

.. _HCL: https://www.qubes-os.org/hcl/
.. _#31: https://github.com/QubesOS/qubes-antievilmaid/pull/31

Communication with the TPM from boot(8) is handled through BIOS calls. The
interface designed for this contained a bug that prevented the content of the
processor register ``EAX`` from being properly saved in the ``BIOS_regs``
structure after a BIOS call. After a brief `discussion on the OpenBSD misc
mailing list`_, the fix was integrated into OpenBSD.

.. _discussion on the OpenBSD misc mailing list: https://marc.info/?t=157314801500003&r=1&w=2

The OpenBSD source code for the Master Boot Record ``MBR`` and Partition Boot
Record ``PBR`` was modified so that the chain of trust is extended all the way
to the second-stage bootloader, ``boot(8)``. The ``PBR`` is measured in
``PCR-08``, and ``boot(8)`` is measured in ``PCR-09``.

``boot(8)`` has been enhanced, and it is now capable of sealing and unsealing
arbitrary data using the TPM. The contents of the PCRs and random numbers
generated by the TPM can be displayed using the command line.

.. [5] Apple macOS Security 03/2018

.. [6] https://blogs.technet.microsoft.com/dubaisec/2016/03/04/bitlocker-aes-xts-new-encryption-type/

.. [7] OpenBSD 6.5 Source Code 01/2019

.. [8] Advanced Encryption Standard (AES) 26/11/2010

.. [9] James Nechvatal, Elaine Barker, Donna Dodson, Morris Dworkin, James Foti, and
  Edward Roback Status Report on the First Round of the Development of the Advanced
  Encryption Standard 11/1999

.. [10] James Nechvatal, Elaine Barker, Lawrence Bassham, William Burr, Morris Dwor-
  kin, James Foti, and Edward Roback Report on the Development of the Advanced
  Encryption Standard (AES) 07/2001

.. [13] Andrey Bogdanov, Dmitry Khovratovich, and Christian Rechberger Biclique Crypt-
  analysis of the Full AES 08/2011

.. [11] Microsoft Data Encryption Toolkit for Mobile PCs: Security Analysis
  https://web.archive.org/web/20071023233150/http://www.microsoft.com/technet/security/guidance/clientsecurity/dataencryption/analysis/4e6ce820-fcac-495a-9f23-73d65d846638.mspx
  , Zugriff am:  04/2007

.. [14] Microsoft Information protection https://docs.microsoft.com/en-us/windows/security/information-protection/
   , Zugriff am: 09/2019

.. [15] OpenBSD OpenBSD Security https://www.openbsd.org/security.html
  , Zugriff am: 09/2019

.. [16] Joanna Rutkowska Evil Maid goes after TrueCrypt! http://theinvisiblethings.blogspot.com/2009/10/evil-maid-goes-after-truecrypt.html
  , Zugriff am: 09/2019
