Implementation
++++++++++++++
With the accumulated knowledge about other systems and the resulting decision to
utilize OpenBSD's boot chain, a prototype was developed to meet the following
requirements:

1. The prototype must extend the Chain of Trust across all software components
   involved in the boot process. Specifically, this includes the MBR,
   ``biosboot(8)``, and ``boot(8)``. This fulfills the first part of the title
   of this work: *a measured boot environment.*

2. The prototype leverages this Chain of Trust to enable users to detect
   manipulations of the measured software components. This feature fulfills the
   second part of the title, *including AEM.*

3. The required code should be designed to integrate into OpenBSD. This implies
   it must be released under the BSD license and must not, under any
   circumstances, remove existing functionality.

The order of the requirements corresponds to the structure of the implementation
chapter. It begins with the extension of the startup program in the MBR to
ensure it propagates the Chain of Trust and concludes with the necessary
modifications to ``boot(8)`` for detecting EMAs.

MBR enhancements
================
The source code for the startup program in the MBR is located in the directory
``sys/arch/amd64/stand/mbr/``. It consists of the Makefile, required for
building, and the assembler file ``mbr.S``. Compiling is straightforward:
navigate to the directory and execute the ``make`` command. Once completed, the
file mbr, containing the machine code of the MBR, is generated in the same
directory.

In addition to the actual startup program, which occupies 440 bytes, the MBR
also contains the partition table and the signature ``0x55 0xAA`` at its very
end. The source code includes not only the startup program but also placeholders
for the partition table and signature. Consequently, the assembler generates a
complete MBR with an empty partition table, which can later be modified using
tools such as ``fdisk``. The output file ``mbr`` is exactly 512 bytes in size.
To ensure the partition table remains intact during updates, only the first 440
bytes should be overwritten.

The limited space in the MBR leaves little room for extensive communication with
the TPM. Recognizing this constraint, the Trusted Computing Group (TCG) has
defined an API specifically for such scenarios. This API consists of several
functions, of which only two are sufficient for our use case.

TCG BIOS API
------------
The ``TCG_StatusCheck`` function is used first to verify whether the firmware
provides a TCG-BIOS interface. This function is invoked using the assembly
instruction ``int 0x1A``. Before the call, the CPU must be prepared in the state
shown in :numref:`tcg-status-check-api`.

.. code-block::
   :caption: TCG Status check API [34]_
   :linenos:
   :name: tcg-status-check-api

    # On entry:
        %ah = 0xbb
        %al = 0x00

    # On return:
        %eax = Return code. Set to 00000000h if the system supports the TCG BIOS calls.
        %ebx = 0x41504354
        %ecx = Version and errata of the specification this BIOS supports.
               Bits 7-0 (CL): 0x02 (TCG BIOS Minor Version (02h for version 1.21))
               Bits 15-8 (CH): 0x01 (TCG BIOS Major Version (01h for version 1.21))
        %edx = BIOS TCG Feature Flags (None currently defined. MUST be set to 0)
        %esi = Absolute pointer to the beginning of the event log.
        %edi = is set to the absolute pointer to the first byte of the last event in the log

Thus, only the ah register needs to be set to the value ``0xBB``, and the al
register to ``0x00``, which can be accomplished with a single movw instruction.

The state after returning from the interrupt is also illustrated in
:numref:`tcg-status-check-api`. For the code in the MBR, the primary concern is
determining whether the firmware provides a TCG-BIOS interface. This can be
verified by checking if the content of the eax register is set to ``0x00``. To
ensure accuracy, the ``ebx`` register should also be checked for the value
``0x41504354``, which corresponds to the ASCII characters ``TCPA``. This
abbreviation stands for Trusted Computing Platform Alliance (TCPA).

If both registers hold the correct values, the BIOS provides the TCG interface,
and we can utilize it in the subsequent program flow. The objective is to
measure the Partition Boot Record (PBR) loaded by the MBR by determining its
SHA-1 hash value and extending a Platform Configuration Register (PCR) with it.
However, a standalone SHA-1 implementation already exceeds the 440-byte limit.
Therefore, the hash computation must be delegated to the firmware.

The function provided by the TCG for this task is named
``TCG_CompactHashLogExtendEvent``. Its lengthy name encapsulates all the tasks
it performs: calculating the ``SHA-1`` hash value of a given memory region,
extending the log, and updating a PCR with the computed hash value. This
function is particularly well-suited for space-constrained applications like the
MBR, where only the code for parameter placement and the interrupt invocation is
required.

.. code-block::
   :caption: TCG Compact Hash Log Extend API [34]_
   :linenos:
   :name: tcg-hash-log-extend

    On entry:
        %ah = 0xbb
        %al = 0x07
        %es = Segment portion of the pointer to the start of the data buffer to be hashed
        %di = Offset portion of the pointer to the start of the data buffer to be hashed
        %esi = The informative value to be placed into the event field
        %ebx = 0x41504354
        %ecx = The length, in bytes, of the buffer referenced by ES:DI
        %edx = The PCR number (PCRIndex) to which the hashed result is to be extended

    On return:
        %eax = Return Code as defined in Return Codes 10.2
        %edx = Event number of the event that was logged

:numref:`tcg-hash-log-extend` shows the prerequisites for invoking the
``TCG_CompactHashLogExtendEvent`` function, which is selected by setting the
value ``0xbb07`` in the ``eax`` register. The segment-offset address of the
memory region to be used is expected in the ``es`` and ``si`` registers, while
its size is specified in the ecx register. The ``ebx`` register contains the
ASCII string ``TCPA`` to protect against unintended invocations, edx holds the
index of the PCR register to be used, and esi contains an informational value
for the log. In this implementation, the esi value is consistently set to ``0``
for both calls and is not further utilized.

With these two functions provided by the TCG BIOS API, it is possible to extend
the Chain of Trust. Before invoking the ``TCG_CompactHashLogExtendEvent``
function, it is crucial to understand the exact memory location where the PBR
(Partition Boot Record) is loaded and where the control transfer to it occurs.

OpenBSD MBR
-----------





.. [34] TCG PC Client Specific Implementation Specification for Conventional
   BIOS, 02/2012 Specification Version 1.21 Errata

