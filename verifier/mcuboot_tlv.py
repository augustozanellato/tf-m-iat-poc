import struct
from imgtool import image


HEADER_ITEMS = ("magic", "load_addr", "hdr_size", "protected_tlv_size",
                "img_size", "flags", "version")

HASH_TYPES = {
        'SHA256': 0x10,
        'SHA384': 0x11,
}

def parse_tlvs(b: bytes):
    '''Parse a signed image binary and print/save the available information.'''

    # Parsing the image header
    _header = struct.unpack('IIHHIIBBHI', b[:28])
    # Image version consists of the last 4 item ('BBHI')
    _version = _header[-4:]
    header = {}
    for i, key in enumerate(HEADER_ITEMS):
        if key == "version":
            header[key] = "{}.{}.{}+{}".format(*_version)
        else:
            header[key] = _header[i]

    # Parsing the TLV area
    tlv_area = {"tlv_hdr_prot": {},
                "tlvs_prot":    [],
                "tlv_hdr":      {}}
    tlv_off = header["hdr_size"] + header["img_size"]
    protected_tlv_size = header["protected_tlv_size"]

    if protected_tlv_size != 0:
        _tlv_prot_head = struct.unpack(
                            'HH',
                            b[tlv_off:(tlv_off + image.TLV_INFO_SIZE)])
        tlv_area["tlv_hdr_prot"]["magic"] = _tlv_prot_head[0]
        tlv_area["tlv_hdr_prot"]["tlv_tot"] = _tlv_prot_head[1]
        tlv_end = tlv_off + tlv_area["tlv_hdr_prot"]["tlv_tot"]
        tlv_off += image.TLV_INFO_SIZE

        # Iterating through the protected TLV area
        while tlv_off < tlv_end:
            tlv_type, tlv_len = struct.unpack(
                                    'HH',
                                    b[tlv_off:(tlv_off + image.TLV_INFO_SIZE)])
            tlv_off += image.TLV_INFO_SIZE
            tlv_data = b[tlv_off:(tlv_off + tlv_len)]
            tlv_area["tlvs_prot"].append(
                {"type": tlv_type, "len": tlv_len, "data": tlv_data})
            tlv_off += tlv_len

    _tlv_head = struct.unpack('HH', b[tlv_off:(tlv_off + image.TLV_INFO_SIZE)])
    tlv_area["tlv_hdr"]["magic"] = _tlv_head[0]
    tlv_area["tlv_hdr"]["tlv_tot"] = _tlv_head[1]

    tlv_end = tlv_off + tlv_area["tlv_hdr"]["tlv_tot"]
    tlv_off += image.TLV_INFO_SIZE

    tlvs_out: dict[int, bytes] = {}

    # Iterating through the TLV area
    while tlv_off < tlv_end:
        tlv_type, tlv_len = struct.unpack(
                                'HH',
                                b[tlv_off:(tlv_off + image.TLV_INFO_SIZE)])
        tlv_off += image.TLV_INFO_SIZE
        tlv_data = b[tlv_off:(tlv_off + tlv_len)]
        if tlv_type in tlvs_out:
            raise Exception(f"malformed image, duplicate tlv type {tlv_type}")
        tlvs_out[tlv_type] = tlv_data
        tlv_off += tlv_len
    return tlvs_out