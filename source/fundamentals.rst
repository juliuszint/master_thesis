Fundamentals
++++++++++++
The foundations of this work begin with a theoretical section. This section
first describes an Evil Maid Attack and then presents concepts for mitigating
such an attack. The TPM, Intel Trusted Execution Technology (Intel TXT), and AMD
Secure Virtual Machine (SVM) are essential hardware components for implementing
countermeasures. The software leverages these hardware features to establish a
secure boot environment. This work explains each relevant component, from the
lower levels where the firmware resides to the higher levels where the operating
system runs.

A basic understanding of asymmetric cryptography is assumed. Knowledge in
low-level programming with assembler and familiarity with the x86-64 processor
platform are also helpful.

Evil Maid Attack
================
Attacks can be classified as either **opportunistic** or **targeted**. In
opportunistic attacks, the attacker is not familiar with the victim. They simply
exploit opportunities that arise by chance. The following example illustrates an
opportunistic attack: after paying, a customer forgets their laptop in a café.
An attacker who is also in the café notices this and extracts confidential data
from the system. In contrast, a targeted attack involves minimizing the number
of factors dependent on chance. The attacker gathers as much information about
the victim as possible and selects the most promising attack vector based on
this knowledge. The following example illustrates a targeted attack: Malory
seeks information from Bob’s laptop. She knows that Bob takes his laptop to a
café every Friday, goes to the restroom at least once, and does not lock his
laptop during this time. Malory plans to copy a confidential file from Bob’s
laptop within this window.

A successful Evil Maid Attack (EMA) requires detailed information about the
target system. Additionally, either repeated physical access or extended access
over time is necessary. Consequently, EMAs are considered targeted attacks.

Full Disk Encryption (FDE) protects the confidentiality of data in a system’s
powered-off state against attackers with physical access. However, FDE provides
no protection against malware that is executed after authentication to the
system has occurred. This also applies to unlocked systems that an attacker can
physically access [18]_. If most of the attack vectors are impossible, an
attacker might consider using an EMA to gain access to encrypted and
confidential data.

An Evil Maid Attack (EMA) may require either **one-time** or **repeated**
physical access to the hardware. With single access, an image of the hard drive
is created, and the bootloader is replaced with a manipulated version that
transmits the password, for example, over a connected network. If repeated
physical access is possible, it may be sufficient to store the password on the
hard drive. Generally, an attack with multiple access opportunities is easier to
execute. For a one-time access attack to be feasible, the key material must be
stored on the hard drive rather than on a USB stick or in a TPM. Additionally, a
significant amount of time is required to create a complete copy of the hard
drive without the victim noticing the attack.

Tampering can involve either **software** or **hardware** components. Examples
of hardware manipulation include attaching a USB keylogger [19]_, exfiltrating
data via a USB-based Man-in-the-Middle attack, or even creating a complete
duplicate of the target system. Software manipulation, on the other hand,
includes not only programs stored on the system’s hard drive but also firmware
held in the flash memory of integrated circuits (ICs). Additionally,
modifications to data processed by these programs may also count as software
tampering, especially if vulnerabilities like buffer overflows are used to
inject code into them.

Thus, the definition of an EMA for this work can be formulated as follows: In an
EMA, an attacker with single or repeated physical access manipulates the
hardware or software components of a target system protected by FDE to obtain
the authentication token of a specifically chosen victim. The victim must
successfully authenticate on the compromised system at least once.

An attack is **not** necessarily a security vulnerability. Whether an EMA is
considered a security vulnerability is determined by the security policy. For
laptops used exclusively within a corporate environment, it may be deemed
acceptable not to categorize this attack vector as a vulnerability. If an EMA is
considered a security vulnerability, then the security policy must define the
security objectives that an EMA would compromise. Confidentiality, Integrity,
and Availability (CIA) are the established security goals in Information
Technology (IT). When software or hardware is altered, integrity is compromised,
and in the case of a successful attack, confidentiality may also be affected. If
an EMA is classified as a security vulnerability, security measures should be
implemented to protect against this type of attack. This master’s thesis aims to
develop precisely such a security measure for OpenBSD, enabling detection of
software manipulations that remain unencrypted even with active FDE, before a
password entry is required. Detecting hardware or firmware manipulations is
initially out of scope and could be addressed in future research.

Countermeasures
---------------
Now that an EMA has been precisely defined, this chapter addresses theoretical
countermeasures. Established solutions are based on two distinct theoretical
approaches. Secure Boot detects software manipulation through cryptographic
signatures, while Qubes-AEM measures and logs the software being executed.
Starting with signatures, both approaches are examined and evaluated in detail
below.

Signatures
~~~~~~~~~~
Cryptographic signatures typically function through a combination of
cryptographically secure hash algorithms and asymmetric encryption methods, such
as Rivest–Shamir–Adleman (RSA). An executable file is reduced, for example, to a
20-byte value using SHA-1. This value is then encrypted with the private portion
of the key material and appended to the file as a signature. Third parties can
generate the hash value independently and compare it to the decrypted signature.
If both match, it can be concluded that no tampering has occurred. [23]_

Secure Boot is a process defined in the UEFI specification that validates the
signatures of software executed by the firmware. When Secure Boot is enabled,
any software in the boot chain without a valid signature will cause the boot
process to fail. The process begins with a Root of Trust and establishes a chain
of trust, where each program verifies the signature of the next. Computers with
the "Compatible with Windows" logo are required to include Microsoft's digital
keys and ship with Secure Boot enabled by default. Alternative operating
systems, such as Fedora and Ubuntu, are also compatible with Secure Boot. If an
operating system or boot software lacks a valid signature, users can self-sign
it and register the corresponding key in the (UEFI). [28]_

Secure Boot represents a significant improvement over systems that lack any
security mechanisms. However, it is not sufficient for ensuring a fully secure
boot process, as it does not account for the data used by the programs. Buffer
overflow vulnerabilities, for instance, can allow attackers to alter the control
flow and execute malicious code. Signature-based approaches are unable to detect
such exploits, leaving this as a critical security gap.

The measurement of components, which will be explained in more detail in the
next section, enables the detection of modifications to programs and the data
they use.

.. [18] Johannes Götzfried Trusted Systems in Untrusted Environments: Protecting
   against Strong Attackers 12/2017

.. [19] David Kierznowski MSc, Keith Mayes ISG BadUSB 2.0: Exploring USB Man-In-
   The-Middle Attacks 05/2016

.. [23] B. Kaliski PKCS #1: RSA Encryption Version 1.5, RFC 2313 03/1998

.. [28] Hendrik Schwartke , Ralf Spenneberg UEFI-Secure-Boot und alternative
   Betriebs- systeme, ADMIN 03/2014

Measurements
~~~~~~~~~~~~
Measurement refers to the process of recording both executed software and the
data it processes. Instead of storing full copies of the software, the protocol
relies cryptographically secure hash function to conserve storage. The integrity
and reliability of these hash values are directly tied to the cryptographic
strength of the hash function used. Assuming the use of a secure hash function,
it becomes computationally infeasible to generate a malicious copy that produces
an identical hash. The measurement log can be queried by software to assess
whether the system state has deviated from a previously known and verified
configuration.

To address the trust evaluation question in practice, it is essential to
carefully determine which software measurements should be considered for this
purpose. If too many measurements are included, the system could not be trusted
after each boot, as certain data—such as the OptionROMs stored in the Basic
Input Output System (BIOS)—can vary from one boot to the next [60]_. Striking
an appropriate balance between security and practical usability is therefore
crucial. This involves selecting measurements that are critical to the integrity
of the system while minimizing variability that could undermine trust without
reason.

As with cryptographic signatures, measurement-based approaches also require a
Root of Trust, which must itself be inherently trustworthy. In the TPM
specification, this is referred to as the **Root of Trust for Measurement**
(RTM). The RTM's sole responsibility is to measure the next program in the
execution chain. Beyond this task, it does not perform any additional functions,
ensuring a clear and focused role in establishing the trustworthiness of
subsequent components.

In addition to the Root of Trust, the method by which the measurement log is
maintained is a critical consideration. Foremost, it must be ensured that the
log cannot be modified retroactively. This requirement excludes most types of
storage available in modern systems. On the amd64 platform, for instance, only
certain processor registers that can be written to once per boot cycle or
Read-Only Memory meet this criterion. However, these options are insufficient
for broader use, necessitating dedicated hardware that provides tamper-resistant
storage.

Equally important is ensuring the integrity of the log and that the results of
any log queries cannot be falsified. Addressing these challenges is the focus of
the Trusted Computing Group (TCG), which developed the Trusted Platform Module
(TPM) as a solution. The TPM, along with its features and functionality, is
introduced in the following chapter on foundational concepts.

.. [60] https://software.intel.com/en-us/forums/intel-trusted-execution-technology-intel-txt/
   topic/518519

Hardware
================
This chapter delves into the hardware components essential for understanding
this work, covering the fundamentals of the Trusted Platform Module (TPM),
various approaches to the Root of Trust for Measurement (RTM), and relevant
processor extensions. The TPM is an independent System on a Chip (SoC), designed
to provide secure cryptographic operations and measurement capabilities. In
contrast, Intel Trusted Execution Technology (Intel TXT) and AMD Secure Virtual
Machine (SVM) represent extensions of the i386 and amd64 Instruction Set
Architectures (ISA), respectively, and are utilized to implement a Dynamic Root
of Trust for Measurement (DRTM).

Trusted Platform Module
-----------------------
A secure implementation of measured software is not possible without hardware, a
fact recognized by the Trusted Computing Group (TCG), which led to the
development of the TPM specification. This thesis utilizes the Trusted Platform
Module (TPM) described within the specification for both measuring software
components and encrypting/decrypting secrets.

The Trusted Platform Module (TPM) refers not only to the specification but also
to the corresponding System on a Chip (SoC). This passive cryptographic
co-processor provides several functions designed to enhance the security of
systems. The first widely adopted version, TPM 1.1b, was released in 2003. This
was followed by version 1.2 in 2005, which introduced better protection against
dictionary attacks, a standardized API/SoC pin layout, and Direct Anonymous
Attestation (DAA). In 2014, the latest version, TPM 2.0, was released, offering
additional enhancements, including greater flexibility in the selection of
supported algorithms [29]_ (chap. 1) . For the purposes of this thesis, only
version 1.2 will be used to minimize the number of variables involved.

.. [29] Will Arthur, David Challener, Kenneth Goldman A Practical Guide to TPM
   2.0, 01/2015

TPM-Owner und Storage Root Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
When the TPM is in its factory state, a TPM Owner must be set in order to
utilize its full functionality. To do this, a secret is transferred into the
TPM, which will later serve to authenticate the owner. For the TPM, the secret
is a 20-byte array. Users are free to choose how the content of this secret is
generated [30]_ (chap. 7).

To keep the manufacturing costs of a TPM as low as possible, the specification
requires only a minimal amount of internal non-volatile memory. To still enable
the creation of a variety of different keys, whose private parts are never
accessible outside the TPM, a hierarchy is established, with the Storage Root
Key (SRK) at the root. During the initialization of the TPM, this key is set to
a random value. Similar to the TPM Owner, a secret must also be established for
the SRK. This secret is referred to as the SRK password.

The tpm-tools allow the execution of many TPM commands from the command line. On
Fedora, they can be installed using the command ``sudo dnf install tpm-tools``.
After installation, it is possible to set oneself as the owner of a TPM using
the command ``tpm_takeownership``. For further details, the third section of the
TPM specification in Chapter 6.1 can be consulted, which provides a detailed
description of the parameters of the ``tpm_takeownership`` command.

Platform Control Registers
~~~~~~~~~~~~~~~~~~~~~~~~~~
A Platform Control Register (PCR) is a 160-bit protected storage area within the
TPM. In TPM 1.2, there are at least 16 PCRs, which can store an arbitrary number
of integrity measurement values by chaining them through the extend
operation [30]_ (chap. 4.4).

After a platform reset, the contents of the Platform Control Registers (PCRs)
are reset to zero and can subsequently only be modified through the ``extend``
operation. Let *H* represent the cryptographic hash function ``SHA-1``,
*PCRi* denote the content of the PCR register with index *i*, and *E* be
the SHA-1 value of the measured data. The extend operation is defined as
follows [30] (chap. 4.4):

.. math::

   PCRi = H(PCRi || E)

In addition to these fundamental properties, the TPM PC Client Specification
[34]_ also recommends which integrity measurement values should be stored in
which PCRs. :numref:`pcr-usage` shows the details.

.. table:: PCR Usage
   :name: pcr-usage

   =========== ==========================================================
   PCR Index   PCR Usage
   =========== ==========================================================
    0          S-CRTM, BIOS, Host Platform Extensions, and Option ROMs
    1          Host Platform Configuration
    2          Option ROM Code
    3          Option ROM Configuration and Data
    4          IPL Code (usually the MBR) and Boot Attempts
    5          IPL Code Configuration and Data (for use by the IPL Code)
    6          State Transitions and Wake Events
    7          Host Platform Manufacturer Specific
    8-1        Defined for use by the Static OS
    16         Debug
    23         Application Support
   =========== ==========================================================

``PCR-08`` to ``PCR-15`` are reserved for use by the operating system.
Therefore, if OpenBSD wishes to measure its own software components, these PCRs
are available for this purpose.

The values in the PCRs can not only be queried but also set as conditions for
decrypting data. This type of encryption, referred to by the TCG as Sealing and
Unsealing, is explained in the following section.

Sealing and Unsealing
~~~~~~~~~~~~~~~~~~~~~
Sealing refers to the process of encrypting data using a TPM. The resulting
ciphertext can only be decrypted by the same TPM because the specified key must
be non-migratable. In other words, the private part of the key, by definition,
never leaves the TPM [32]_ (chap. 10.1). In addition to the key handle, PCR
indexes can also be specified. This means that the TPM will only decrypt the
data if the contents of the PCRs match the values they had when the data was
originally sealed. The following information is required when invoking the
``tpm_seal`` command:

1. Key: The Key Handle pointing to a non-migratable key. According to the
   specification, Key Handles are 32-bit integers, and integral keys such as the
   Storage Root Key (SRK) have a fixed value. For the SRK, this value is
   ``0x40000000``.

2. KeyAuth: When using a key, the TPM requires proof that the invoking party is
   authorized to do so. Authorized individuals are those in possession of the
   shared secret associated with the key. This shared secret is a 20-byte array,
   which is not transmitted directly but instead used as a key in an HMAC
   (Hash-based Message Authentication Code) algorithm.

3. Data: The data to be encrypted, which can be up to 256 bytes in size. If the
   data exceeds this size, a symmetric key must be used as an intermediate step.

4. DataAuth: Authorization data that must be provided to prove knowledge when
   calling the tpm_unseal command. This data is encrypted and transmitted
   securely over the Low Pin Count (LPC) bus to ensure confidentiality.

5. PCR Indexes: The PCR indexes whose contents are tied to the decryption
   process, such as ``PCR-01``, ``PCR-02``, ``PCR-03``.

The result of the Seal operation is a data stream that contains all the
necessary information for the TPM to later decrypt the data. This includes the
contents of the PCR at the time of encryption. These and additional data must be
provided when executing ``tpm_unseal``.

1. Key: The same as for ``tpm_seal``.

2. KeyAuth: The same as for ``tpm_seal``.

3. Data: The response form ``tpm_seal``.

4. DataAuth: The same as for ``tmp_seal``.

Root of Trust for Measurement
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The TPM is a passive component that does not directly influence which software
runs on a system. To ensure that the executed software and the contents of the
PCR are consistent, a Chain of Trust is employed, in so overcoming the
limitation of not being in control.

Starting from a Root of Trust, or in the context of measurements, a Root of
Trust for Measurement (RTM), each executed software component is measured by its
predecessor. The RTM is unique because it has no predecessor and is therefore
implicitly trusted. Consequently, any manipulation of the RTM must be rendered
impossible. In the TPM specification, the RTM is also referred to as the Core
Root of Trust for Measurement (CRTM).

In a system employing a **Static Root of Trust for Measurement** (S-RTM), the
CRTM must not only remain immutable but also execute as early as possible during
platform initialization. The following excerpt from the specification defines
the key properties of the S-CRTM:

    The Static Core Root of Trust for Measurement (S-CRTM) MUST be an
    immutable portion of the Host Platform’s initialization code. See Section
    1.2.2 (Immutable). [30] (chap. 3.3.1.2)

The entries in the PCR content table (Table 2.1) illustrate the Chain of Trust
within a system utilizing a Static Root of Trust for Measurement (SRTM). Since
the CRTM is implicitly trusted, it measures itself, the BIOS, the Host Platform
Extensions, and the Embedded Option ROMs. The resulting measurement values are
stored in PCR-00, PCR-01, PCR-02, and PCR-03, respectively.

The CRTM subsequently hands over control to the BIOS, which then measures the
Initial Program Loader (IPL) code. In IBM XT2-compatible systems, this
corresponds to the Master Boot Record (MBR). The MBR can return control to the
BIOS if issues arise. If an additional IPL is available, PCR-04 is extended
again, thereby capturing all boot attempts within its cumulative measurement.

The more programs that gain control of the system during startup, the higher the
likelihood that the system's trustworthiness will be compromised. This is
because updates to individual components, even when made with no malicious
intent, can alter the contents of the PCRs [38]_ (chap. 1.2).

Dynamic Root of Trust for Measurement (DRTM) provides a solution to this
challenge. This approach allows for the initiation of a measured environment at
any arbitrary point in time. To facilitate this, PCRs that can be reset were
introduced. The reset operation is restricted to specific entities through
different privilege levels, referred to in the TPM specification as Localities.
:numref:`pcr-attributes` provides a detailed overview of which PCRs can be reset
and the required Locality level for performing this operation.

.. table:: PCR Attributes
   :name: pcr-attributes

   ========== ====================== ======== ============================= ==============================
   PCR Index  Alias                  pcrReset pcrResetLocal (4, 3, 2, 1, 0) pcrExtendLocal (4, 3 ,2, 1, 0)
   ========== ====================== ======== ============================= ==============================
   0 – 15     Static RTM             0        0,0,0,0,0                     1,1,1,1,1
   16         Debug                  1        1,1,1,1,1                     1,1,1,1,1
   17         Locality 4             1        1,0,0,0,0                     1,1,1,0,0
   18         Locality 3             1        1,0,0,0,0                     1,1,1,0,0
   19         Locality 2             1        1,0,0,0,0                     0,1,1,0,0
   20         Locality 1             1        1,0,1,0,0                     0,1,1,1,0
   21         Dynamic OS Controlled  1        0,0,1,0,0                     0,0,1,0,0
   22         Dynamic OS Controlled  1        0,0,1,0,0                     0,0,1,0,0
   23         Application Specific   1        1,1,1,1,1                     1,1,1,1,1
   ========== ====================== ======== ============================= ==============================

It is the platform's responsibility to ensure that Localities cannot be spoofed.
Specifically, Locality 4 can only originate from the CPU itself, necessitating
additional processor features. Both Advanced Micro Devices (AMD) and Intel
provide extensions that enable DRTM in conjunction with a TPM. These extensions
are briefly described in the following sections.

.. [30] TPM Main Part 1 Design Principles, 03/2011 Version 1.2

.. [32] TPM Main Part 3 Commands, 03/2011 Version 1.2

.. [34] TCG PC Client Specific Implementation Specification for Conventional
   BIOS, 02/2012 Specification Version 1.21 Errata

Intel Trusted Execution Technology
----------------------------------
Intel Trusted Execution Technology (TXT) is Intel's branding for a suite of
technologies designed to enhance the security of existing computer systems. It
outlines platform enhancements and building blocks essential for implementing
Trusted Computing principles [38]_ (chap. 1).

As previously outlined, Intel TXT enables the initiation of a Chain of Trust
with a dynamic origin. This approach offers the advantage of maintaining a
shorter chain, reducing the number of components involved and thus minimizing
the number of components required to be trustworthy.

The newly introduced processor instruction SENTER enables the launch of a
Measured Launch Environment (MLE). This instruction first synchronizes all
processor cores and then executes the **Authenticated Code Module** (ACM) on the
**Initiating Logical Processor** (ILP), provided the ACM carries a valid
signature from Intel. Prior to invoking the instruction, both the ACM and the
MLE must be loaded into memory to ensure proper execution [38]_ (chap. 1.2.1).

The Authenticated Code Module (ACM) verifies the state of the Central Processing
Unit (CPU). If the configuration is deemed satisfactory, it resets PCRs 17–23.
Subsequently, the ACM measures itself and the Measured Launch Environment (MLE)
into PCR-17, after which control of the system is handed over to the MLE [38]_
(chap. 1.1–1.9).

:numref:`txt-localities` illustrates how Intel utilizes the four
localities defined in the TPM specification. When analyzed alongside Table 2.2,
it becomes evident which combinations of software components and PCRs are
authorized to perform either the Reset or Extend operations.

.. figure:: ./_static/txt_localities.png
   :name: txt-localities
   :alt: TXT Localities
   :align: center

   TXT Localities

With Intel TXT and resettable PCRs, it is possible to launch an MLE at any
desired point in time. For further details, refer to Intel's Software
Development Guide [38]_, the book A Practical Guide to TPM 2.0 [29]_ (chap. 22),
or the book *Intel Trusted Execution Technology for Server Platforms*.

AMD Secure Virtual Machine
--------------------------
In addition to Intel, AMD also provides the capability to initiate a trusted
environment at runtime through its Secure Virtual Machine technology. If
supported by the CPU, this can be achieved by executing the SKINIT instruction.

The SKINIT instruction requires a single parameter in the eax register, which is
the address of a Secure Loader Block (SLB). This SLB is AMD's term for the
memory region containing the Secure Loader Image (SLI). The SLI includes both
the code and initialized data for the Secure Loader (SL) program. The SL is
responsible for initializing the Secure Virtual Machine (SVM) hardware
mechanisms and transferring control to the next software component, referred to
by AMD as the Security Kernel. In practical applications, this Security Kernel
is often a Virtual Machine Monitor (VMM) [52]_ (chap. 2.4) [36]_ (chap. 15.27).

Before the first instruction of the Secure Loader (SL) program is executed, the
SKINIT instruction initializes the processor to a well-defined state. In this
state, modifications to the Secure Loader Image (SLI) are prevented.
Additionally, interrupts are disabled, ensuring that no previously executed code
can regain control of the system. This guarantees a secure and isolated
execution environment for the SL program [36]_ (chap. 15.27).

Once all hardware protection mechanisms are activated, the CPU sends a signal to
reset the dynamic PCRs to the TPM. Following this, the processor transmits the
Secure Loader Image (SLI) to the TPM, which computes a cryptographic hash of the
received data and extends ``PCR-17`` with the resulting value. This coordinated
interaction between hardware and software establishes a Root of Trust that
serves as the foundation for further extensions within the trust chain.

The book *Trust Extension as a Mechanism for Secure Code Execution on Commodity
Computers* [52]_ provides a highly accessible explanation of AMD SVM and Intel
TXT in Chapter 2.4. For more detailed information on AMD's technology, the
second volume of the AMD64 Architecture Manual [36]_, specifically Section 15.2,
offers an in-depth exploration.

With this, the foundational knowledge regarding hardware is complete. The
sections on Intel TXT and AMD SVM have been kept intentionally brief, as neither
technology is utilized in the implementation. The following chapter will focus
on the software components, spanning from firmware to the operating system, that
are executed during the startup of OpenBSD on an IBM XT-compatible system.

.. [38] Intel® Trusted Execution Technology (Intel® TXT), 11/2017 Measured
   Launched Environment Developer’s Guide

.. [52] Bryan Jeffrey Parno Trust Extension as a Mechanism for Secure Code
   Execution on Commodity Computers, 08/2016

.. [36] AMD64 Architecture Programmer’s Manual, 10/2019 Volume 2: System Pro-
   gramming

Firmware
========
After a platform reset of an i386 or amd64 CPU, the processor enters real mode
with only a single core active. The Extended Instruction Pointer (EIP) register
is set to the address ``FFFF:FFF0``, known as the reset vector [35]_ (chap.
8.4.3). At this address resides the system firmware, which, in the case of the
test system used in this work, implements UEFI.

.. [35] Intel® 64 and IA-32 Architectures Software Developer’s Manual, 09/2016 Volume
    3 (3A, 3B, 3C and 3D): System Programming Guide
