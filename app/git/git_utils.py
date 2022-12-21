import os
import zlib
import hashlib

from typing import Tuple, Dict

def hash_bytes_to_str(hash_bytes: bytes) -> str:
    """
    Given the hash in bytes, return a string with the hash in hex.
    """
    return hash_bytes.hex()


def hash_str_to_bytes(hash_str: str) -> bytes:
    """
    Given the hash as hex string, return the hash in bytes.
    """
    return bytes.fromhex(hash_str)

def object_hash_to_dir_and_filename(object_hash: str) -> Tuple[str, str]:
    """
    Given the git object hash, return the dir and filename
    """
    return (object_hash[:2], object_hash[2:])

def object_bytes_to_header_and_content(object_bytes: bytes) -> Tuple[bytes, bytes]:
    """
    Given the git object bytes, return the header and content
    """
    header, content = object_bytes.split(b"\x00", 1)
    return (header, content)

def object_header_to_type_and_length(object_header: str) -> Tuple[str, str]:
    """
    Given the git object header, return the type and length of the content
    """
    content_type, content_length = object_header.split(b" ")
    return (content_type, content_length)

def read_object(object_sha: str, repo_path: str = "") -> Tuple[bytes, bytes, bytes]:
    """
    Read raw object in git repo.
    """
    dir, filename = object_hash_to_dir_and_filename(object_hash=object_sha)
    object_path = os.path.join(repo_path, ".git", "objects", dir, filename)
    with open(object_path, "rb") as git_object:
        compressed_object = git_object.read()

    object_bytes = zlib.decompress(compressed_object)

    header, content = object_bytes_to_header_and_content(object_bytes)
    object_type, content_length = object_header_to_type_and_length(header)
    return object_type, content_length, content

def create_object(object_type: bytes, content: bytes) -> Tuple[str, bytes]:
    """
    Create an object.
    """
    obj = object_type + b" " + str(len(content)).encode() + b"\x00" + content
    object_sha = hashlib.sha1(obj).hexdigest()
    return object_sha, obj


def write_object(object_sha: str, obj: bytes, repo_path: str):
    """
    Write object in git repo, compressing it.
    """
    compressed_object = zlib.compress(obj)
    dir, filename = object_hash_to_dir_and_filename(object_hash=object_sha)
    object_dir = os.path.join(repo_path, ".git", "objects", dir)

    os.makedirs(object_dir, exist_ok=True)
    with open(os.path.join(object_dir, filename), "wb") as object_file:
        object_file.write(compressed_object)

def parse_object_content(object_content: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Given object bytes, parse permissions, filename, and SHA256 checksum bytes
    """

    permissions, content = object_content.split(b" ", 1)
    filename, content = content.split(b"\x00", 1)
    return (permissions, filename, content[:20])


def ignore_path(path: str) -> bool:
    """
    Says if path is to be ignored.
    """
    ignore_list = ["__pycache__", ".git"]
    if path in ignore_list:
        return True
    if path.startswith("."):
        return True
    return False


def build_tree_object(objects: Dict[str, Tuple[str, str, bytes]]) -> Tuple[str, bytes]:
    """
    Build tree object of objects.
    """
    content = [
        objects[key]["permissions"].encode()
        + b" "  
        + objects[key]["filename"].encode()  
        + b"\x00"  
        + objects[key]["hash_bytes"]  
        for key in sorted(objects.keys())
    ]
    content = b"".join(content)
    tree_sha, tree_object = create_object(b"tree", content)
    return tree_sha, tree_object

def write_ref(path: str, sha: str, repo_path: str):
    """
    Write reference in repo.
    """
    file_path = os.path.join(repo_path, ".git", path)
    dirname = os.path.dirname(file_path)
    if not os.path.exists(dirname):
        os.makedirs(dirname)
    with open(file_path, "w") as ref_file:
        ref_file.write(sha)


def write_refs(refs: Tuple[str, str], repo_path: str):
    """
    Write references in repo.
    """
    for sha, path in refs:
        write_ref(path, sha, repo_path)