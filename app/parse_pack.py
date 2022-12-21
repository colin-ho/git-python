"""
Parse PACK file.

OBJ_OFS_DELTA type not implemented.
"""

from typing import List, Tuple, Any
import zlib
import hashlib


def load_pack(pack_path: str) -> bytes:
    """
    Load pack.
    """
    with open(pack_path, "rb") as pack_file:
        pack = pack_file.read()
    return pack


def parse_obj_type_and_size(pack: bytes, i: int) -> Tuple[int, int, int]:
    """
    Parse object type and size.
    """
    cur = i
    obj_type = (pack[cur] & 112) >> 4
    obj_size = pack[cur] & 15
    offset = 4
    while pack[cur] >= 128:
        cur += 1
        obj_size += (pack[cur] & 127) << offset
        offset += 7
    return cur - i + 1, obj_type, obj_size


def parse_pack_object(pack: bytes, i: int) -> Tuple[int, Tuple]:
    """
    Parse an object in the pack.
    """
    obj_types = [
        b"INVALID",
        b"commit",
        b"tree",
        b"blob",
        b"tag",
        b"RESERVED",
        b"obj_ofs_delta",
        b"obj_ref_delta",
    ]
    parsed_bytes, obj_type, obj_size = parse_obj_type_and_size(pack, i)
    # print(f"Object of type {obj_types[obj_type]} ({obj_type}) and size {obj_size}.")
    i += parsed_bytes
    # print(f"Object starting at {i} {pack[i]}.")
    if obj_type in [1, 2, 3, 4]:
        decompressor = zlib.decompressobj()
        obj = decompressor.decompress(pack[i:], max_length=obj_size)
        parsed_bytes += len(pack) - i - len(decompressor.unused_data)
        # print(f"Object of size {len(obj)} using {parsed_bytes} bytes.")
        return parsed_bytes, (obj_types[obj_type], obj)
    if obj_type == 7:
        ref = pack[i : i + 20]
        parsed_bytes += 20
        i += 20
        # print(hex(int.from_bytes(ref, "big")))
        # print(pack[i])
        decompressor = zlib.decompressobj()
        delta = decompressor.decompress(pack[i:])
        parsed_bytes += len(pack) - i - len(decompressor.unused_data)
        return parsed_bytes, (obj_types[obj_type], ref, delta)

    raise NotImplementedError(
        f"Pack object type {obj_types[obj_type]!r} not implemented."
    )


def parse_pack(pack: bytes):
    """
    Parse PACK-file.
    """
    signature = pack[0:4]
    if signature != b"PACK":
        raise ValueError("Not a PACK file.")

    version = int.from_bytes(pack[4:8], "big")
    # print(f"PACK version {version}.")
    if version != 2:
        raise NotImplementedError(f"Unknown version of PACK file {version}.")

    num_objects = int.from_bytes(pack[8:12], "big")
    # print(f"Pack contains {num_objects} objects.")

    i = 12
    objects: List[Tuple[Any, ...]] = []
    for obj_num in range(num_objects):
        try:
            parsed_bytes, obj = parse_pack_object(pack, i)
        except NotImplementedError as exc:
            print(exc)
            print(f"At object {obj_num} of {num_objects}.")
            return objects
        except zlib.error as exc:
            print(exc)
            print(f"At object {obj_num} of {num_objects} at pos {i}.")
            return objects
        # print(f"Parsed {parsed_bytes} bytes.")
        i += parsed_bytes
        objects.append(obj)
    chksum = pack[i : i + 20]
    i += 20

    if hashlib.sha1(pack[:-20]).digest() != chksum:
        print("Checksum is NOT OK.")
        raise RuntimeError("Pack checksum does NOT CHECK.")
    # print("Checksum is OK.")

    if len(pack) != i:
        print(f"Parsed {i} bytes out of {len(pack)}.")
        raise RuntimeError("Pack not fully read.")
    # print(f"Pack fully parsed ({i} bytes).")
    return objects


def test():
    """
    Do some tests.
    """
    pack = load_pack("pack")
    print(pack[:100])
    objects = parse_pack(pack)
    print(objects[:10])
    print("Found", len(objects), "objects.")


if __name__ == "__main__":
    test()