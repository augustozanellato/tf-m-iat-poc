#import "@preview/ilm:1.4.0": *

#set text(lang: "en")

#show: ilm.with(
  title: [Initial Attestation\ on TrustedFirmware-M],
  author: "Augusto Cesare Zanellato",
  date: datetime(year: 2025, month: 02, day: 16),
  abstract: [
    Proof of Concept of a system using Initial Attestation based on TrustedFirmware-M running on a cheap and readily available microcontroller equipped with TrustZone-M.
  ],
  chapter-pagebreak: false,
  external-link-circle: false,
)
#show link: box.with(stroke: 1pt + aqua, outset: (y: 0.2em), inset: (x: 0.1em))

= Objectives
The main goal of this project is to implement a system that should be able to attest the firmware running on a microcontroller and provide a proof of the firmware's integrity to a remote verifier.

= System Setup
- Raspberry Pi Pico2 compatible board: the microcontroller board that will be used for testing.
- Generic DAPLink debugger: used to debug issues with the microcontroller, also provides a serial interface useful for interacting with our target application.
- OpenOCD: debug server used to communicate with the DAPLink debugger.
- TrustedFirmware-M: project implementing primitives on top of TrustZone-M.

= Background
== TrustZone-M
TrustZone-M is a security extension for ARM Cortex-M processors that provides isolation between the so called secure and non-secure worlds. This isolation is enforced by an hardware barrier that checks each memory access to ensure that the requested access is allowed by the security attributes of the target memory area. The security attributes are defined as follows:
- Secure (S): the secure world can access this memory area.
- Non-secure (NS): the non-secure world can access this memory area.
- Non-secure callable (NSC): the non-secure world can call functions residing in this memory area, this allows controlled interactions between the secure and non-secure worlds.
It should be noted that in Cortex-M processors all the peripherals are memory mapped, so the security attributes can be used to control access to peripherals as well.

== TrustedFirmware-M
#link("https://trustedfirmware-m.readthedocs.io/en/latest/")[TrustedFirmware-M] (TF-M) is a project that provides a reference implementation of the Trusted Execution Environment (TEE) for ARM Cortex-M processors. It provides a set of primitives that can be used to implement secure applications on top of TrustZone-M. It is developed by ARM and is open-source.

The implemented TEE is running in the secure world (known as Secure World image), while the non-secure world part (known as the Non-Secure World image) can be provided by the user.
As part of the TEE implementation, TrustedFirmware-M provides a set of services that can be used by the Non-secure world to interact with the Secure world. These services include:
- Internal Trusted Storage (ITS): provides a way to store data with the following guarantees:
  - Confidentiality: ITS provides resistance to unauthorized access through hardware and software attacks;
  - Access Authentication: ITS can establish the requester's identity and ensure that the requester is authorized to access the data;
  - Integrity: data is protected from tampering from the NS world;
  - Reliability: data is resistant to power failure and interrupted writes.
- Protected Storage (PS): similar to ITS, but the data is stored encrypted with AES-GCM in order to provide authenticated encryption;
- Cryptography (Crypto): provides access to cryptographic primitives such as hashing, encryption, and decryption, allows the NS world to perform cryptographic operations using keys stored in the Secure world;
- Initial Attestation (IAT): provides a way to attest the firmware running on the microcontroller and provide a proof of the firmware's integrity to a remote verifier. Attestation tokens follow the format specified in the #link("https://datatracker.ietf.org/doc/html/draft-tschofenig-rats-psa-token-07")[IETF draft tschofenig-rats-psa-token].
Each service is running in a so-called _partition_ that is isolated from the other partitions, so that the compromise of one partition does not affect the security of the other partitions.

TF-M also allows for the user to define custom partitions that can be run in the Secure world, these services can be used to implement custom security policies or to provide access to custom hardware peripherals.

=== Boot Process
The Root of Trust (RoT) is enforced by Secure Boot on the microcontroller that only allows signed images to be loaded and executed.
1. At startup the microcontroller checks the integrity of the second stage bootloader (BL2) by validating its signature against the ROTPK (Root of Trust Public Key), if the signature is valid then the BL2 is loaded and executed.
The BL2 then checks the integrity of both the Secure and Non-secure world images by validating each images signature against the expected public key (there are two different public keys, one for the Secure image and one for the Non-secure image), if both signatures are valid then the Secure image is started.
2. The Secure (SPE: Secure Processing Environment) image then sets up TrustZone-M and all the related hardware, configures the Secure world, and initializes all the Secure Partitions and then starts the Non-secure image.
3. The Non-secure (NSPE: Non-Secure Processing Environment) image then initializes the Non-secure world and starts the user application that it contains.

During this process each booted image is measured by BL2 in memory that gets write-locked after measurements are made so that the integrity of the Secure Boot process can be verified by the Initial Attestation service.

=== Initial Attestation
Initial Attestation is a process that allows a remote verifier to verify that a device has correctly followed the Secure Boot process and what firmware is running on the device. The process is as follows:
0. During manufacturing the device is provisioned with an unique asymmetric key pair, the private key is stored in OTP memory on the device and the public key is provided to the verifier, to prevent supply chain attacks the key can be generated by the device itself;
1. The verifier generates a challenge and sends it to the device, the challenge is a random value that is used to ensure that the attestation token is fresh and not replayed;
2. The NSPE receives the challenge and forwards it to the Initial Attestation service via the `psa_initial_attest_get_token` function.
3. The Initial Attestation service (running in the SPE) then generates an attestation report that contains the following information:
  - `BOOT_SEED`: a value that is generated randomly at boot time, can be used to check if there was a reboot between two attestation tokens;
  - `CHALLENGE`: the challenge that was received from the verifier;
  - `CLIENT_ID`: the identifier of the partition that requested the attestation token;
  - `IMPLEMENTATION_ID`: an identifier for microcontroller family used in the device;
  - `INSTANCE_ID`: an hash of the public key that the verifier should use to verify the attestation token;
  - `PROFILE_ID`: identifies the type of attestation token that is being generated;
  - `SECURITY_LIFECYCLE`: the security lifecycle state of the device, can be used to safely decommission devices that are no longer secure, is stored in OTP memory;
  - `SW_COMPONENTS`: a list of the software components that are running on the device, each component has the following fields:
    - `MEASUREMENT_VALUE`: a hash of the component's image;
    - `MEASUREMENT_DESCRIPTION`: the type of hash used in `MEASUREMENT`;
    - `SIGNER_ID`: the identifier of the key that was used to sign the component;
    - `SW_COMPONENT_TYPE`: the type of the component, can be either `SPE` or `NSPE`;
    - `SW_COMPONENT_VERSION`: the version of the component;
4. The report is then encoded using the #link("https://datatracker.ietf.org/doc/html/rfc8949")[CBOR (RFC 8949)] format and signed using the device's private key following the #link("https://datatracker.ietf.org/doc/html/rfc8152")[COSE standard]. The signed report is then referred to as the attestation token.
5. The token is then returned to the NSPE which forwards it to the verifier.
6. The verifier then verifies the token by checking the signature against the public key that was provided during manufacturing and then checks the contents of the token to ensure that the device is in a secure state and that the firmware is the expected one.

Note that, in contrast to Remote Attestation, Initial Attestation does not measure the current runtime state of the device, it only provides information about the firmware that was running at boot time, so an exploit residing in RAM could modify the device behavior without being detected by the verifier.

== Raspberry Pi Pico2

The Raspberry Pi Pico2 is a development board based on the #link("https://www.raspberrypi.com/products/rp2350/")[RP2350] microcontroller, which is a dual-core ARM Cortex-M33 #footnote[It can also be configured as hybrid M33/RISC-V or full RISC-V but that's outside the scope of this project] microcontroller with TrustZone-M support. It was chosen primarily because of its low cost and availability, even if it is not as supported by TF-M as some other microcontrollers from STMicroelectronics or Nordic Semiconductors.
Specifically the TF-M port hasn't yet been certified by PSA and there are some missing features, but fortunately everything needed for this project is already implemented.

= Experiments
All the code produced for this project is available at #link("https://github.com/augustozanellato/tf-m-iat-poc").
The repository is structured as follows:
 - `app/`: contains the Non-secure world application that will be used to interact with the TF-M services;
 - `tf-m-patches/`: contains some patches that are needed to make TF-M work properly on the Raspberry Pi Pico2:
  - `0001-start-crypto-before-its.patch`: this patch inverts startup priorities for the Crypto and ITS partitions, I'm not really sure why this is needed but without this patch the board fails to boot with a partition initialization error in ITS because the Crypto partition is not initialized yet.
  - `0002-fix-bl2-wrapper.patch`: bl2 image wrapper script had an issue where NSPE images were incorrectly marked as SPE images, luckily it was a trivial fix.
  - `0003-add-rp2350-attest-hal.patch`: this patch adds a dedicated attestation HAL (Hardware Abstraction Layer) that adds support for using the hardware provided boot seed instead of the static one stored in OTP.
 - `verifier`: contains a verifier that can be used to verify the attestation token generated by the device is valid and matches the expected software components.
 - `.env.example`: contains configuration for the verifier, must be copied to `.env` and filled with the correct values.
 - `dbgkey_gen.py`: generates an OpenOCD script that can be used to debug the device if secure debug is enabled, shouldn't be needed for this project.
 - `justfile`: contains some helper commands to build the project, run the verifier, and debug the device. #link("https://github.com/casey/just")[Just] is needed to run these commands. The most important commands are:
  - `just apply-patches`: applies the patches in `tf-m-patches/` to the TF-M repository;
  - `just configure-tfm`: configures the TF-M build environment.
  - `just build-tfm`: builds TF-M;
  - `just configure-app`: configures the Non-secure world application build environment;
  - `just build-app`: builds the Non-secure world application;
  - `just flash-full-uf2`: flashes BL2, SPE and NSPE to a device connected in `bootsel` mode;
  - `just flash-provisioning-uf2`: flashes the provisioning bundle to a device connected in `bootsel` mode;
  - `just serial-term`: opens a serial terminal to the device, allowing to interact with the Non-secure world application;
  - `just verify`: runs the verifier;
  - Other commands are available, run `just --list` to see them all.
 - `pyproject.toml`: contains the dependencies for the verifier, must be installed with `uv install`.
The repository is using Git submodules to include dependencies, so it must be cloned with `git clone --recurse-submodules`.


== Initial testing of TF-M on the Raspberry Pi Pico2

The first thing done was testing if my local environment was correctly set up to build TF-M for the RP2350, this was done by trying to flash the TF-M regression tests to the board and checking if they passed.
The regression tests are a set of tests that are run on the device to ensure that the TF-M services are working correctly, to my surprise the tests passed on the first try, which was a good sign that the environment was correctly set up.

Another (less fun) surprise was that the hello world NSPE application provided by TF-M sometimes crashed at startup, after investigating the issue with a debugger I found out that it was caused by a bug that was causing the ITS service to start before it's dependencies were initialized, this was fixed by applying the `0001-start-crypto-before-its.patch` patch.

After fixing the issue the hello world application booted correctly and I was able to start working on actually doing Initial Attestation. After getting my first attestation report back from the device I started working on the verifier, which is a simple Python script that verifies the attestation token generated by the device. While working on it I noticed that the measured software components were not being correctly reported by the device, specifically it seemed like the device was running two SPE images instead of the expected one SPE and one NSPE image. After some debugging I found out that the issue was caused by the BL2 image wrapper script incorrectly marking the NSPE image as an SPE image, this was fixed by applying the `0002-fix-bl2-wrapper.patch` patch.

Last found issue was that the RP2350 implementation of TF-M was missing support for using the hardware provided boot seed in the attestation token and was instead using a static boot seed programmed in OTP memory, this was fixed by adding the `0003-add-rp2350-attest-hal.patch` patch.

All the developed patches will be submitted upstream to TF-M maintainers so that they can be reviewed and hopefully merged into the mainline repository.

== Final Non-Secure application

The implemented NSPE is an application that exposes a simple shell-like environment on the serial port available on `UART0` (TX on `GP0` and RX on `GP1`, baud rate 115200), the following commands are available:
- `help`: prints a list of available commands;
- `version`: prints information about versions of the software components;
- `info`: prints information about the device;
- `attest`: requests an attestation token from the Initial Attestation service;

#figure(caption: "NSPE booting up", image("images/nspe-cli.svg"))
#figure(caption: "Example of an attestation flow", image("images/nspe-cli-commands.svg"))

The warning seen in the first image is caused by the fact that the device is using the default keys provided by TF-M, which are not secure and should not be used in a production environment, but were deemed to be good enough for this proof of concept, especially since the keys are programmed in OTP memory and losing them during testing would have caused the device to be bricked.

== Verifier
The verifier is implemented in Python and is based on #link("https://github.com/TrustedFirmware-M/tf-m-tools/tree/3450f2a26fd5c1aec0f93b820e89add0ea6a5f3b/iat-verifier")[TF-M's own `iat-verifier`], it is a simple script that connects via serial to the device, generates a challenge, sends it to the device, receives the attestation token, verifies it using the expected public key and then checks the contents of the token to ensure that the device is in a secure state and that the firmware is the expected one.

#figure(caption: "Verifier output", image("images/verifier-output.svg"))
#figure(caption: "Verifier verbose output", image("images/verifier-output-verbose.svg"))

== Replication instructions

To replicate the project you will need the following hardware:
- Raspberry Pi Pico2 compatible board;
- USB to UART adapter.
The following connections are required:
- UART adapter TX to GP1;
- UART adapter RX to GP0;
- UART adapter GND to any GND;

Use the following command to build and flash everything needed to the device `just configure-tfm Release build-tfm configure-app Release build-app flash-full-uf2`, the board must be connected via USB in `bootsel` mode.

If it is the first time flashing a given board you will also need to flash the provisioning bundle with `just flash-provisioning-uf2` after putting the board in `bootsel` mode again.

Beware that doing this will result in burning some OTP bits.

= Results and Discussion
The project was successful in implementing Initial Attestation on the Raspberry Pi Pico2 using TrustedFirmware-M, the attestation token generated by the device was successfully verified by the verifier and the contents of the token were as expected.
I personally found this project very interesting and I gained some knowledge about how TrustZone-M works and how to use it to implement secure applications on microcontrollers.
A big pain point was that documentation for TF-M is not as good as it could be, so I had to go through the source code in order to understand how some things worked, but in retrospect this helped me understand the inner workings of everything way better.

== Possible attacks
Due to the design of the used microcontroller flash memory is on a separate chip from the microcontroller itself, this means that an attacker with physical access could get a full reading of the flash memory. Note that this does not necessarily give access to the private keys stored in OTP memory, but it could allow an attacker to extract the firmware and analyze it for vulnerabilities.

A sophisticated attacker might also be able to bypass Secure Boot with a TOCTOU attack similar to #link("https://www.onekey.com/resource/making-toctou-great-again-xrip")[OneKey's X(R)IP], where the attacker uses two flash chips, one with the original firmware and one with a modified firmware, and switches between them at runtime to bypass the Secure Boot checks.