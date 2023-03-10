"""
Connect to remote repository.
"""

from typing import List, Tuple

import http.client


def query_refs(host: str, repo: str) -> bytes:
    """
    Request refs from repo at host.
    """
    conn = http.client.HTTPSConnection(host)
    conn.request("GET", f"{repo}/info/refs?service=git-upload-pack")
    response = conn.getresponse()

    if response.headers["Content-Type"] != f"application/x-git-upload-pack-advertisement":
        raise RuntimeError(f"Response from {host} for repo {repo} not valid.")

    return response.read()


def build_packet_line(packet: bytes) -> bytes:
    """
    Build packet line for this content
    """
    if len(packet) == 0:
        return b"0000"
    packet_length = len(packet) + 4
    length = f"{packet_length:04x}".encode()
    return length + packet


def build_want_line(ref: str) -> bytes:
    """
    Build want line for ref.
    """
    packet = ("want " + ref + "\n").encode()
    return build_packet_line(packet)


def build_want_line_with_caps(ref: str, caps: List[str]) -> bytes:
    """
    Build want line for ref with capabilities.
    """
    packet = ("want " + ref + " " + " ".join(caps) + "\n").encode()
    return build_packet_line(packet)


def build_ref_request_body(refs: List[str]) -> bytes:
    """
    Build body for requesting list of refs.
    """
    lines = []
    lines.append(build_want_line_with_caps(refs[0], ["multi_ack"]))
    for ref in refs[1:]:
        lines.append(build_want_line(ref))
    lines.append(build_packet_line(b""))
    lines.append(build_packet_line(b"done"))
    return b"".join(lines)


def query_pack(host: str, repo: str, refs: List[str]) -> bytes:
    """
    Request pack for refs.
    """
    connection = http.client.HTTPSConnection(host)
    headers = {"Content-Type": "application/x-git-upload-pack-request"}

    body = build_ref_request_body(refs)
    print(body)

    connection.request("POST", f"{repo}/git-upload-pack", headers=headers, body=body)
    response = connection.getresponse()

    print(response.status)
    print(response.headers)
    if response.headers["Content-Type"] != f"application/x-git-upload-pack-result":
        raise RuntimeError(f"Response from {host} for repo {repo} not valid.")

    return response.read()


def parse_line_length(data: bytes, i: int) -> int:
    """
    Parse line length.
    XXXX: 4 bytes with hex chars
    """
    length = int.from_bytes(bytes.fromhex(data[i : i + 4].decode()), "big")
    return length


def parse_packet_line(data: bytes, i: int) -> Tuple[int, bytes]:
    """
    Parse a packet line.
    XXXX<content>
    """
    length = parse_line_length(data, i)
    i += 4
    if length == 0:
        return 4, b""
    packet = data[i : i + length - 4]
    return length, packet


def parse_packet_lines(data: bytes) -> List:
    """
    Parse packet lines in data.
    """
    packets = []
    i = 0
    while i < len(data):
        bytes_parsed, packet = parse_packet_line(data, i)
        i += bytes_parsed
        if packet:
            packets.append(packet)
    return packets


def parse_ref(ref_b: bytes) -> Tuple[str, str]:
    """"
    Parse a ref.
    """
    ref = ref_b.decode().strip("\n")
    if " " in ref:
        sha, path = ref.split(" ", maxsplit=1)
        return (sha, path)
    raise ValueError(f"Malformed ref.")


def parse_first_ref_line(packet: bytes) -> Tuple[str, str]:
    """
    Parse first line of refs: ref\\0opts
    """
    ref_b, opts_b = packet.split(b"\x00")
    opts_str = opts_b.decode()
    opts = opts_str.split(" ")
    return parse_ref(ref_b), opts


def parse_pack_resp(pack_resp: bytes) -> Tuple[bool, bytes]:
    """
    Parse response of pack-upload.
    """
    i = 0
    parsed_bytes, packet = parse_packet_line(pack_resp, i)
    i += parsed_bytes
    if packet.decode().strip("\n") == "NAK":
        return True, pack_resp[parsed_bytes:]
    return False, b""


def load_refs():
    """
    Save refs of from file.
    """
    with open("refs.data", "rb") as refs:
        data = refs.read()
    return data


def save_refs(refs):
    """
    Save refs of the repo.
    """
    with open("refs.data", "wb") as ref_file:
        ref_file.write(refs)


def save_pack(pack):
    """
    Save pack.
    """
    with open("pack", "wb") as pack_file:
        pack_file.write(pack)


def load_pack():
    """
    Load pack.
    """
    with open("pack", "rb") as pack_file:
        pack = pack_file.read()
    return pack


def download_pack(host: str, repo: str) -> Tuple[List, List]:
    """
    Download pack from host.
    """
    refs_data = query_refs(host, repo)
    packets = parse_packet_lines(refs_data)
    first, _ = parse_first_ref_line(packets[1])
    refs = [first]
    for packet in packets[2:]:
        refs.append(parse_ref(packet))

    want = set()
    for sha, _ in refs:
        want.add(sha)
    pack_resp = query_pack(host, repo, list(want))
    pack_ok, pack = parse_pack_resp(pack_resp)

    if not pack_ok:
        raise RuntimeError("Cannot parse pack.")
    return refs, pack


def parse_refs(refs_data) -> List[Tuple[str, str]]:
    """
    Parse refs data from host to list of refs.
    """
    packets = parse_packet_lines(refs_data)
    first, _options = parse_first_ref_line(packets[1])

    refs = [first]
    for packet in packets[2:]:
        refs.append(parse_ref(packet))
    return refs