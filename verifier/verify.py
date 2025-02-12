import re
import secrets
import argparse
import logging
import hashlib
import pycose.algorithms
import time
import math
import pprint

from pwnlib.tubes.serialtube import serialtube
from pwnlib.tubes.tube import tube
from pwnlib.log import getLogger, Handler, Formatter
from Crypto.PublicKey import ECC
from pycose.keys.cosekey import CoseKey
from iatverifier.attest_token_verifier import (
    VerifierConfiguration,
    AttestationTokenVerifier,
    TokenItem,
)
from iatverifier.psa_iot_profile1_token_claims import SecurityLifecycleClaim
from iatverifier.psa_iot_profile1_token_verifier import PSAIoTProfile1TokenVerifier

import mcuboot_tlv

log = getLogger(__name__)


def init_logging(debug: bool):
    console = Handler()
    formatter = Formatter()
    console.setFormatter(formatter)
    log.addHandler(console)
    if debug:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

def recv_hexbuf(r: tube):
    buf = bytes()
    count  = int(r.recvregex(rb"[\w ]+\((\d+)\):", capture=True).group(1)) # type: ignore
    r.recvline()
    lines = math.ceil(count/32)
    log.debug(f"reading {count} bytes in {lines} lines")
    for _ in range(lines):
        buf += bytes.fromhex(r.recvline().decode().strip())
    return buf

parser = argparse.ArgumentParser()
parser.add_argument(
    "--provisioning-config",
    default="trusted-firmware-m/platform/ext/common/provisioning_bundle/provisioning_config.cmake",
    type=argparse.FileType("r"),
)
parser.add_argument("--baud-rate", default=115200, type=int)
parser.add_argument("--challenge-size", default=32, type=int, choices=[32, 48, 64])
parser.add_argument(
    "--expected-spe",
    default="app/tfm-artifacts/bin/tfm_s_signed.bin",
    type=argparse.FileType("rb"),
)
parser.add_argument(
    "--expected-nspe",
    default="app/build/bin/tfm_ns_signed.bin",
    type=argparse.FileType("rb"),
)
parser.add_argument("-v", "--verbose", action="store_true")
parser.add_argument("serial_port")

args = parser.parse_args()

init_logging(args.verbose)

configured_iak = re.search(
    r"set\(IAK \"([0-9A-Fx, \\\n]*)\"",
    args.provisioning_config.read(),
    re.RegexFlag.MULTILINE,
)
if configured_iak is None:
    log.failure("malformed provisioning config")
    exit(1)

# P-256 key that should be used by the device to sign attestation tokens
iak_pub_expected = ECC.construct(
    curve="p256",
    d=int.from_bytes(
        bytes.fromhex(
            configured_iak.group(1)
            .translate(str.maketrans("", "", ", \\\n"))
            .replace("0x", "")
        ),
        byteorder="big",
    ),
).public_key()
log.debug(f"expected iak key {iak_pub_expected}")

r = serialtube(args.serial_port, args.baud_rate)
r.clean(timeout=0.1)
r.sendline()  # trigger initial prompt
r.sendlineafter(b"\x1b[32mTF-M NS> \x1b", b"info")
# P-256 public key that the device is actually using in the format p_x || p_y, both padded to 32 bytes
iak_pub_bytes = recv_hexbuf(r)

iak_pub = ECC.construct(
    curve="p256",
    point_x=int.from_bytes(iak_pub_bytes[:32]),
    point_y=int.from_bytes(iak_pub_bytes[32:]),
)
log.debug(f"device iak public key {iak_pub}")

# check that the device is claiming to use the correct key
if iak_pub_expected != iak_pub:
    log.failure("device isn't using the expected initial attestation key")
    exit(1)
else:
    log.success("device is claiming to be attesting with the correct key")

attest_challenge = secrets.token_bytes(args.challenge_size)
log.info(f"attesting with challenge {attest_challenge.hex()}")
start = time.time()
r.sendlineafter(b"\x1b[32mTF-M NS> \x1b", f"attest {attest_challenge.hex()}".encode())
attest_token = recv_hexbuf(r)
end = time.time()
# note that this doesn't actually represent how much time the device took to compute and sign the token
# it's just provided as a very coarse upper bound
log.info(f"attestation took {(end-start) * 1000:.3f}ms")

verifier_config = VerifierConfiguration(keep_going=False, strict=True)
cose_key = CoseKey.from_pem_public_key(iak_pub.export_key(format="PEM"))
verifier = PSAIoTProfile1TokenVerifier(
    method=AttestationTokenVerifier.SIGN_METHOD_SIGN1,
    cose_alg=pycose.algorithms.Es256,
    signing_key=cose_key,
    configuration=verifier_config,
)

attest_token_obj = verifier.parse_token(token=attest_token, lower_case_key=False)
attest_claims: dict[str, TokenItem] = attest_token_obj.value.value  # type: ignore

log.debug("device claims:\n" + pprint.pformat({k: v.value for k,v in attest_claims.items()}))

# instance_id is 0x01 || SHA256(CoseKeyEncode(IAK_PUB))
expected_instance = b"\x01" + hashlib.sha256(cose_key.encode()).digest()
log.debug(f"expecting instance id {expected_instance.hex()}")
log.debug(f"actual instance id    {attest_claims['INSTANCE_ID'].value.hex()}")
if expected_instance != attest_claims["INSTANCE_ID"].value:
    log.failure("device presented a wrong instance id")
    exit(1)
else:
    log.success("device attested the correct instance id")

# actually verify the token signature
attest_token_obj.verify()
log.success("token signature verified successfully")

attest_token_challenge = attest_claims["CHALLENGE"].value
log.debug(f"device attested to challenge {attest_token_challenge.hex()}")
# challenge must match the provided one to prevent replay attacks
if attest_challenge != attest_token_challenge:
    log.failure(
        "device attested a wrong challenge, this probably means an attacker is replaying an old token"
    )
    exit(1)

log.success("device attested the correct challenge")

lc = SecurityLifecycleClaim.get_formatted_value(
    attest_claims["SECURITY_LIFECYCLE"].value
)
# a non secured device might have been tampered with by an attacker (eg via a debugger)
if not lc.startswith("sl_secured_"):
    log.warn(
        f"device attested an insecure lifecycle state: `{lc}`, token might not be trustworthy"
    )
else:
    log.success(f"device attested a secure lifecycle state ({lc})")

log.info(f"device id: {attest_claims['IMPLEMENTATION_ID'].value.hex()}")
log.info(f"device boot seed: {attest_claims['BOOT_SEED'].value.hex()}")

client_id: int = attest_claims["CLIENT_ID"].value
log.info(
    f"attestation requested by {'Non-' if client_id < 0 else ''}Secure Partition with ID {client_id} [0x{abs(client_id).to_bytes(4).hex()}]"
)

validated_spe = False
validated_nspe = False
expected_images = {
    "SPE": mcuboot_tlv.parse_tlvs(args.expected_spe.read()),
    "NSPE": mcuboot_tlv.parse_tlvs(args.expected_nspe.read()),
}

for component in attest_claims["SW_COMPONENTS"].value:
    comp_type = component["SW_COMPONENT_TYPE"].value
    log.info(
        f"found software component {component['SW_COMPONENT_TYPE'].value} version {component['SW_COMPONENT_VERSION'].value}:"
    )

    log.debug(f"signed by {component['SIGNER_ID'].value.hex()}")
    log.debug(
        f"measurement {component['MEASUREMENT_VALUE'].value.hex()} ({component['MEASUREMENT_DESCRIPTION'].value})"
    )
    match comp_type:
        case "SPE":
            validated_spe = True
        case "NSPE":
            validated_nspe = True
        case _:
            continue
    expected_image = expected_images[comp_type]

    log.debug(f"expected signer {expected_image[1].hex()}")
    # identifies the key that signed the image, should always match the expected key
    if component["SIGNER_ID"].value != expected_image[1]:
        log.failure(
            f"    {comp_type} image signed by different signer, expected `{expected_image[1].hex()}`, found `{component['SIGNER_ID'].value.hex()}`"
        )
        exit(1)

    tlv_key = mcuboot_tlv.HASH_TYPES[component["MEASUREMENT_DESCRIPTION"].value]
    # should actually never happen
    if tlv_key not in expected_image:
        log.failure(f"    expected image is missing measurement tlv {tlv_key}")
        exit(1)
    expected_measurement = expected_image[tlv_key]
    log.debug(f"expected measurement {expected_measurement.hex()}")
    if expected_measurement != component["MEASUREMENT_VALUE"].value:
        # signer matches but hash doesn't, wrong image?
        log.warn(
            f"    has correct signature but doesn't match expected image, expected `{expected_measurement.hex()}`, found `{component['MEASUREMENT_VALUE'].value.hex()}`"
        )
    else:
        log.success(f"    matches expected image!")

if not validated_spe:
    log.warn("SPE image was not attested")
if not validated_nspe:
    log.warn("NSPE image was not attested")
if validated_spe and validated_nspe:
    log.success("all the expected components were attested successfully")
