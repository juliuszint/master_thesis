Conclusion and Outlook
++++++++++++++++++++++
Now that OpenBSD-AEM provides software that meets all the requirements of the
task, we begin the reflective portion of this work—the conclusion.

Reflection
==========
At the very start of my thesis, I fell slightly behind schedule due to the
unexpected difficulty of finding a compatible device for QubesOS. Occasionally,
there were missing drivers during Linux installations, but severe issues like
the graphical artifacts encountered during the QubesOS installation were
entirely new to me. After my Dell XPS became non-functional following multiple
installation attempts (which could, of course, be a coincidence) and the
ThinkPad T410 loaned by Torben turned out to be incompatible, the installation
eventually succeeded on a ThinkPad borrowed from the university.

The subsequent issues during the installation of Qubes-AEM further delayed the
timeline. I had initially planned about two days for installing an operating
system with an additional module, but it ended up taking almost a month.
However, after this challenging start, I gained not only a functioning QubesOS
with AEM but also a solid understanding of its operation. This knowledge proved
invaluable during the later analysis, allowing me to complete it more quickly.

Despite its abandoned state, TrustedGRUB2 turned out to be very easy to install.
The script for a minimal Arch Linux setup with TrustedGRUB2 was completed and
functional within a day. What surprised me the most was that, aside from
TrustedGRUB, no other open-source bootloader offers support for TPM.

In addition to analyzing existing systems, I also spent time working with
OpenBSD. To do so, I read the book "Absolute OpenBSD", installed the operating
system multiple times, and followed the misc mailing list. I am fond of the
simple structure of the operating system, and the documentation has been
extremely helpful. As the analysis progressed, I delved deeper into OpenBSD's
boot chain. I was particularly impressed by the fact that processors are fully
compatible with their predecessors from about 30 years ago.

It was almost a bit disappointing to examine the assembly code of the MBR and
PBR. The reason for this disappointment was my previous assumption that the code
would contain instructions that could not be understood without knowledge of
long-past times. In reality, however, much of it consists of commands that
instruct the firmware to load a disk block into memory.

Since the software project meets all the requirements of the task,
self-criticism is mainly relevant when it comes to documenting the work. A more
structured approach and additional feedback could have led to a better result.
Apart from that, there were no further difficulties in writing this thesis. The
functional software confirms the approach taken. In order to turn the prototype
into a software solution suitable for practical use, several additional steps
are required, which are outlined in the following outlook.

Outlook
=======
So far, the software is only secure if the secret is stored on an external
storage device. To allow an internal storage device to be used as a target for
the secret, it will be necessary to accept an SRK password in addition to the
Well-Known-SRK secret. In the worst case, this will require making a
Password-Based Key Derivation Function (PBKDF) available in boot(8).

The initialization of the TPM should also be possible within OpenBSD. Currently,
users are expected to designate themselves as the TPM owner using an alternative
Linux distribution, such as Fedora. A natural approach would be to add another
command in boot(8), given that OpenBSD only provides a minimal TPM driver.

After implementing the SRK password and TPM initialization, the storage location
of the secret should be reevaluated. The current solution—storing the secret in
the block immediately after the MBR—is simple to implement, but it may cause
problems if other software also writes data to that location. Specifying the
target storage device through its BIOS number is cumbersome and could be made
more user-friendly in this step.

Parallel to these optimizations, the software should be presented to the OpenBSD
community via a mailing list. It's possible that the community may show little
interest in the source code or reject it due to the requirement to remove the
CHS code path. However, if there is interest, the feedback received should be
incorporated in a timely manner.

Finally, possibly in version 2.0, features such as T-OTP could be implemented.
In principle, it makes sense to offer all features from QubesOS-AEM that are
considered useful. Storing key material for the FDE in the TPM is also sensible
and could be implemented as a feature.

There is still much to be done, but no more as part of this work. At this point,
I would like to thank Mr. M. Sc. Jussi Salzwedel for the topic and supervision
of the master’s thesis. Special thanks also go to AWIN-Software for the
opportunity to pursue my programming passion and finance my studies with it.
Torben Voltmer is thanked for his open technical ear, and a final thank you goes
to my family and my girlfriend Katharina Pfannerstill for their support.
