"""IKEv2 SA proposal parser."""

import struct

from ..constants import IKE_DH, IKE_ENCR, IKE_INTEG, IKE_PRF


def parse_payloads(data, start_offset, first_payload_type, total_len):
    """Walk IKEv2 payload chain. Returns dict keyed by payload type."""
    payloads = {}
    offset = start_offset
    current_type = first_payload_type
    end = min(total_len, len(data))
    while current_type != 0 and offset + 4 <= end:
        next_type = data[offset]
        payload_len = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        if payload_len < 4 or offset + payload_len > len(data):
            break
        payload_body = data[offset + 4:offset + payload_len]
        payloads[current_type] = payload_body
        current_type = next_type
        offset += payload_len
    return payloads


def parse_sa(sa_data):
    """Parse IKEv2 SA payload. Returns list of proposal dicts."""
    proposals = []
    offset = 0
    while offset + 8 <= len(sa_data):
        last_sub = sa_data[offset]
        prop_len = struct.unpack(">H", sa_data[offset + 2:offset + 4])[0]
        if prop_len < 8 or offset + prop_len > len(sa_data):
            break
        prop_num = sa_data[offset + 4]
        proto_id = sa_data[offset + 5]
        spi_size = sa_data[offset + 6]
        num_transforms = sa_data[offset + 7]
        proto_names = {1: "IKE", 2: "AH", 3: "ESP"}
        proposal = {
            "proposal_num": prop_num,
            "protocol": proto_names.get(proto_id, f"proto_{proto_id}"),
            "transforms": [],
        }
        t_offset = offset + 8 + spi_size
        for _ in range(num_transforms):
            if t_offset + 8 > offset + prop_len:
                break
            last_t = sa_data[t_offset]
            t_len = struct.unpack(">H", sa_data[t_offset + 2:t_offset + 4])[0]
            if t_len < 8:
                break
            t_type = sa_data[t_offset + 4]
            t_id = struct.unpack(">H", sa_data[t_offset + 6:t_offset + 8])[0]
            type_names = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "D-H", 5: "ESN"}
            id_maps = {1: IKE_ENCR, 2: IKE_PRF, 3: IKE_INTEG, 4: IKE_DH}
            t_name = id_maps.get(t_type, {}).get(t_id, f"{type_names.get(t_type,'?')}_{t_id}")
            proposal["transforms"].append({
                "type": type_names.get(t_type, f"type_{t_type}"),
                "id": t_id,
                "name": t_name,
            })
            if last_t == 0:
                break
            t_offset += t_len
        proposals.append(proposal)
        if last_sub == 0:
            break
        offset += prop_len
    return proposals
