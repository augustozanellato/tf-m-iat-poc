# TrustedFirmware-M patches

I had to apply a couple patches to TF-M, I'll detail them below:

1. `0001-fix-bl2-wrapper.patch`: bl2 image wrapper script had an issue where NSPE images were incorrectly marked as SPE images, luckily it was a trivial fix.
2. `0002-add-rp2350-attest-hal.patch`: RP2350 platform is very new for TF-M and some features weren't properly implemented, this patch adds a dedicated attestation HAL (Hardware Abstraction Layer) that adds support for using the hardware provided boot seed insted of the default one stored in OTP.
3. `0003-start-crypto-before-its.patch`: this patch inverts startup priorities for the Cryptography and the Internal Trusted Storage partitions, I'm not really sure why this is needed but without this patch the board fails to boot with a partition initialization error in ITS because the Cryptography partition is not initialized yet.
