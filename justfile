set dotenv-load

# Run CMake configure on TrustedFirmware-M
[group("configure")]
configure-tfm build_type="Release":
  cmake -S trusted-firmware-m -B tfm-build \
    -DTFM_PLATFORM=rpi/rp2350 \
    -DCMAKE_INSTALL_PREFIX=$PWD/app/tfm-artifacts \
    -DTFM_PROFILE=profile_medium \
    -DPICO_SDK_PATH=$PWD/pico-sdk \
    -DPLATFORM_DEFAULT_PROVISIONING=OFF \
    -DTFM_DUMMY_PROVISIONING=ON \
    -DCMAKE_BUILD_TYPE={{build_type}} \
    -DMCUBOOT_LOG_LEVEL=INFO \
    -DTFM_SPM_LOG_LEVEL=TFM_SPM_LOG_LEVEL_INFO \
    -DTFM_PARTITION_LOG_LEVEL=TFM_PARTITION_LOG_LEVEL_INFO \
    -DTFM_LOG_FATAL_ERRORS=ON \
    -DTFM_LOG_NONFATAL_ERRORS=ON \
    -DMCUBOOT_IMAGE_VERSION_NS=1.0.0
# Build TrustedFirmware-M and prepare artifacts
[group("build")]
build-tfm:
  cmake --build tfm-build -- -j install
# Cleanup TrustedFirmware-M build files
[group("clean")]
clean-tfm:
  rm -rf tfm-build app/tfm-artifacts
# Run CMake configure for NSPE application
[group("configure")]
configure-app build_type="Release":
  cmake -S app -B app/build \
    -DCONFIG_SPE_PATH=$PWD/app/tfm-artifacts \
    -DPICO_SDK_PATH=$PWD/pico-sdk \
    -DCMAKE_BUILD_TYPE={{build_type}}
# Build NSPE application
[group("build")]
build-app:
  cmake --build app/build -- -j
# Cleanup NSPE application build files
[group("clean")]
clean-app:
  rm -rf app/build
# Cleanup everything
[group("clean")]
clean: clean-tfm clean-app

# Start an OpenOCD server
[group("Debug")]
openocd *args:
  openocd -f interface/cmsis-dap.cfg -c "transport select swd" -c "adapter speed 32000" -f target/rp2350.cfg {{args}}
[private]
gdb file:
  arm-none-eabi-gdb -ex "target extended-remote localhost:3333" -ex "python import arm_gdb" -ex "arm loadfile rp2350 ./pico-sdk/src/rp2350/hardware_regs/RP2350.svd" "{{file}}"
[group("Debug")]
debug-bl2: (gdb "tfm-build/bin/bl2.elf")
[group("Debug")]
debug-s: (gdb "tfm-build/bin/tfm_s.elf")
[group("Debug")]
debug-ns: (gdb "app/build/bin/tfm_ns.elf")

[private]
openocd-cmd cmd:
  echo -e '{{cmd}}\nexit' | nc localhost 4444

[private]
make-uf2 file addr:
  python uf2/utils/uf2conv.py "{{file}}.bin" --base "{{addr}}" --convert --output "{{file}}.uf2" --family 0xe48bff59
[private]
flash-uf2 file:
  picotool load -u "{{file}}.uf2"
[private]
reset-uf2:
  picotool reboot
[private]
flash-openocd file addr: (openocd-cmd "program " + file + ".bin verify " + addr)
[private]
reset-openocd: (openocd-cmd "reset")

bl2_offset  := "0x10000000"
s_offset    := "0x10011000"
ns_offset   := "0x10071000"
prov_offset := "0x1019f000"

# Build UF2 package for 2nd stage bootloader
[group("Make UF2")]
make-uf2-bl2: (make-uf2 "app/tfm-artifacts/bin/bl2" bl2_offset)
_flash-bl2-uf2: make-uf2-bl2 (flash-uf2 "app/tfm-artifacts/bin/bl2")
# Flash 2nd stage bootloader using picotool, device must be in BOOTSEL mode
[group("Flash UF2")]
flash-bl2-uf2: _flash-bl2-uf2 reset-uf2
_flash-bl2-openocd: (flash-openocd "app/tfm-artifacts/bin/bl2" bl2_offset)
# Flash 2nd stage bootloader via SWD, a running OpenOCD server is required.
[group("Flash SWD")]
flash-bl2-openocd: _flash-bl2-openocd reset-openocd

# Build UF2 package for SPE application
[group("Make UF2")]
make-uf2-s: (make-uf2 "app/tfm-artifacts/bin/tfm_s_signed" s_offset)
_flash-s-uf2: make-uf2-s (flash-uf2 "app/tfm-artifacts/bin/tfm_s_signed")
# Flash SPE application using picotool, device must be in BOOTSEL mode
[group("Flash UF2")]
flash-s-uf2: _flash-s-uf2 reset-uf2
_flash-s-openocd: (flash-openocd "app/tfm-artifacts/bin/tfm_s_signed" s_offset)
# Flash SPE application via SWD, a running OpenOCD server is required.
[group("Flash SWD")]
flash-s-openocd: _flash-s-openocd reset-openocd

# Build UF2 package for NSPE application
[group("Make UF2")]
make-uf2-ns: (make-uf2 "app/build/bin/tfm_ns_signed" ns_offset)
_flash-ns-uf2: make-uf2-ns (flash-uf2 "app/build/bin/tfm_ns_signed")
# Flash NSPE application using picotool, device must be in BOOTSEL mode
[group("Flash UF2")]
flash-ns-uf2: _flash-ns-uf2 reset-uf2
_flash-ns-openocd: (flash-openocd "app/build/bin/tfm_ns_signed" ns_offset)
# Flash NSPE application via SWD, a running OpenOCD server is required.
[group("Flash SWD")]
flash-ns-openocd: _flash-ns-openocd reset-openocd

# Flash BL2, SPE and NSPE using picotool, device must be in BOOTSEL mode. Beware that the provisioning package isn't flashed.
[group("Flash UF2")]
flash-full-uf2: _flash-bl2-uf2 _flash-s-uf2 _flash-ns-uf2 reset-uf2
# Flash BL2, SPE and NSPE using SWD, a running OpenOCD server is required. Beware that the provisioning package isn't flashed.
[group("Flash SWD")]
flash-full-openocd: _flash-bl2-openocd _flash-s-openocd _flash-ns-openocd reset-openocd

# Build provisioning bundle UF2 package
[group("Make UF2")]
make-uf2-provisioning: (make-uf2 "app/tfm-artifacts/bin/provisioning_bundle" prov_offset)
# Flash provisioning bundle using picotool, device must be in BOOTSEL mode. Should only be done once on new boards.
[group("Flash UF2")]
flash-provisioning-uf2: make-uf2-provisioning (flash-uf2 "app/tfm-artifacts/bin/provisioning_bundle") reset-uf2
# Flash provisioning package using SWD, a running OpenOCD server is required. Should only be done once on new boards.
[group("Flash SWD")]
flash-provisioning-openocd: (flash-openocd "app/tfm-artifacts/bin/provisioning_bundle" prov_offset) reset-openocd

[group("Report")]
build-report:
  typst compile report/main.typ
[group("Report")]
watch-report:
  typst watch report/main.typ

[private]
[working-directory: 'trusted-firmware-m']
generate-patches:
  git add .
  git diff --staged -- bl2 > ../tf-m-patches/0001-fix-bl2-wrapper.patch
  git diff --staged -- platform > ../tf-m-patches/0002-add-rp2350-attest-hal.patch
  git diff --staged -- secure_fw > ../tf-m-patches/0003-start-crypto-before-its.patch

[private]
[working-directory: 'trusted-firmware-m']
apply-patches:
  git apply -- ../tf-m-patches/*.patch

verify *args:
  uv run python verifier/verify.py $SERIAL_PORT {{args}} 