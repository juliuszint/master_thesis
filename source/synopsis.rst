Synopsis
++++++++
The Trusted Platform Module (TPM) is a small security chip available in most
consumer PC devices. Asymmetric cryptography allows for securely storing
information that can only be decrypted by this TPM. Based on certain criteria,
the TPM is free to decide whether or not it will decrypt a secret. One such
criterion can be the software that has been executed by the processor up until
now.

The OpenBSD operating system prides itself on the security it offers to the end
user. While this is certainly true for most aspects, it is missing some features
during early boot that other operating systems support. A measured boot with the
TPM is one such feature, and it is the focus of this thesis to add that support.

Not only should all components during boot be recorded and measured, but end
users should also be able to detect if any component of the entire boot chain
was tampered with. It is especially important that this verification can happen
before the full disk encryption (FDE) password is typed in, because the
extortion of it is the goal of evil maid attacks.
