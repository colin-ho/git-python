"""
Implementation of my git clone.
"""

import os
import zlib
import hashlib
from typing import Tuple, List, Dict

from .remote_repo import download_pack  # pylint: disable=relative-beyond-top-level
from .parse_pack import parse_pack  # pylint: disable=relative-beyond-top-level


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


def init(repo_path: str = ""):
    """
    git init: create initial .git tree.
    """
    os.mkdir(os.path.join(repo_path, ".git"))
    os.mkdir(os.path.join(repo_path, ".git/objects"))
    os.mkdir(os.path.join(repo_path, ".git/refs"))
    with open(os.path.join(repo_path, ".git/HEAD"), "w") as head_file:
        head_file.write("ref: refs/heads/master\n")
    print("Initialized git directory")


def read_object(object_sha: str, repo_path: str = "") -> Tuple[bytes, bytes, bytes]:
    """
    Read raw object in git repo.
    """
    path = os.path.join(repo_path, ".git", "objects", object_sha[:2], object_sha[2:])
    with open(path, "rb") as git_object:
        zobj = git_object.read()
    obj = zlib.decompress(zobj)
    header, content = obj.split(b"\x00", 1)
    object_type, content_length = header.split(b" ")
    return object_type, content_length, content


def create_object(object_type: bytes, content: bytes) -> Tuple[str, bytes]:
    """
    Create an object.
    """
    obj = object_type + b" " + str(len(content)).encode() + b"\x00" + content
    object_sha = hashlib.sha1(obj).hexdigest()
    return object_sha, obj


def write_object(object_sha: str, obj: bytes, repo_path: str) -> str:
    """
    Write object in git repo, compressing it.
    """
    zobj = zlib.compress(obj)
    object_dir = os.path.join(repo_path, ".git", "objects", object_sha[:2])
    os.makedirs(object_dir, exist_ok=True)
    with open(os.path.join(object_dir, object_sha[2:]), "wb") as object_file:
        object_file.write(zobj)
    return object_sha


def cat_file(blob_sha: str, repo_path: str = "") -> bytes:
    """
    git cat-file: return blob content.
    """
    object_type, _content_length, content = read_object(blob_sha, repo_path)
    if object_type == b"blob":
        return content
    raise ValueError(f"Expecting blob object, found {object_type.decode()}.")


def hash_object(object_path: str, repo_path: str = "") -> str:
    """
    git hash-object: write file in object.
    """
    with open(object_path, "rb") as content_file:
        content = content_file.read()
    blob_sha, blob = create_object(b"blob", content)
    write_object(blob_sha, blob, repo_path)
    return blob_sha


def ls_tree(tree_sha: str, repo_path: str = "") -> List[Tuple[bytes, bytes, str]]:
    """
    git ls-tree: return tree.
    """
    object_type, _content_length, content = read_object(tree_sha, repo_path)

    if object_type != b"tree":
        raise ValueError(f"Expecting tree object, found {object_type.decode()}.")

    objects = []
    while len(content) > 0:
        permissions, content = content.split(b" ", 1)
        file_path, content = content.split(b"\x00", 1)
        hash_bytes = content[:20]
        hash_str = hash_bytes_to_str(hash_bytes)
        content = content[20:]
        objects.append((permissions, file_path, hash_str))
    return objects


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


def find_objects(path: str, repo_path: str) -> Dict[str, Tuple[str, str, bytes]]:
    """
    Build list of file/dir objects in path. Recurse on dirs.
    """
    objects = {}
    with os.scandir(path) as dir_entries:
        for dir_entry in dir_entries:
            if ignore_path(dir_entry.name):
                continue
            if dir_entry.is_file():
                blob_sha = hash_object(dir_entry.path, repo_path)
                objects[dir_entry.name] = (
                    f"{dir_entry.stat().st_mode:o}",
                    dir_entry.name,
                    hash_str_to_bytes(blob_sha),
                )
            elif dir_entry.is_dir():
                tree_sha = write_tree(dir_entry.path, os.path.join("..", repo_path))
                objects[dir_entry.name] = (
                    f"{dir_entry.stat().st_mode:o}",
                    dir_entry.name,
                    hash_str_to_bytes(tree_sha),
                )
            else:
                raise ValueError(
                    f"Path {dir_entry.path} is neither file nor directory."
                )
    return objects


def build_tree_object(objects: Dict[str, Tuple[str, str, bytes]]) -> Tuple[str, bytes]:
    """
    Build tree object of objects.
    """
    ordered_content = [
        objects[key][0].encode()
        + b" "  # noqa: ignore=W503
        + objects[key][1].encode()  # noqa: ignore=W503
        + b"\x00"  # noqa: ignore=W503
        + objects[key][2]  # noqa: ignore=W503
        for key in sorted(objects.keys())
    ]
    # print("\n".join([str(obj) for obj in ordered_content]))
    content = b"".join(ordered_content)
    tree_sha, tree_object = create_object(b"tree", content)
    return tree_sha, tree_object


def write_tree(path: str = "", repo_path: str = "") -> str:
    """
    git write-tree: write complete working directory to repo.
        header format: tree content_lenght\\0[entry]*
        entry format: permissions path\\0obj_hash
    """

    objects = find_objects(path, repo_path)
    tree_sha, tree_object = build_tree_object(objects)
    write_object(tree_sha, tree_object, repo_path)
    return tree_sha

def commit_tree(tree_sha: str, opts: Dict[str, str], repo_path: str = "") -> str:
    """
    git commit-tree: write commit object to repo.
    """
    content = [
        f"tree {tree_sha}",
        f"parent {opts['parent']}",
        f"author {opts['author']} {opts['timestamp']}",
        f"committer {opts['committer']} {opts['timestamp']}",
        f"",
        opts["message"],
        f"",
    ]

    content_b = "\n".join(content).encode()
    commit_sha, commit = create_object(b"commit", content_b)
    write_object(commit_sha, commit, repo_path)
    return commit_sha


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


def parse_size(stream: bytes, i: int) -> Tuple[int, int]:
    """
    Parse encoded size.
    """
    size = stream[i] & 127
    parsed_bytes = 1
    offset = 7
    while stream[i] > 127:
        i += 1
        size += (stream[i] & 127) << offset
        parsed_bytes += 1
        offset += 7
    return parsed_bytes, size


def parse_insert(stream: bytes, i: int) -> Tuple[int, bytes]:
    """
    Parse insert instruction.
    """
    size = stream[i]
    parsed_bytes = 1
    i += parsed_bytes
    copy = stream[i : i + size]
    parsed_bytes += size
    # print("Insert:", size, "(", copy[:30], ")")
    return parsed_bytes, copy


def parse_copy_offset(determinant: int, stream: bytes, i: int) -> Tuple[int, int]:
    """
    Parse offset in copy delta instructions.
    """
    parsed_bytes = 0
    offset_parts = []
    for offs in range(4):
        if determinant & (1 << offs):
            offset_parts.append(stream[i])
            i += 1
            parsed_bytes += 1
        else:
            offset_parts.append(0)
    offset = 0
    for offs, offset_part in enumerate(offset_parts):
        offset += offset_part << (offs * 8)
    return parsed_bytes, offset


def parse_copy_size(determinant: int, stream: bytes, i: int) -> Tuple[int, int]:
    """
    Parse size in copy delta instructions.
    """
    parsed_bytes = 0
    size_parts = []
    if determinant == 0x10000:
        return 0, 0
    for offs in range(4, 7):
        if determinant & (1 << (offs)):
            size_parts.append(stream[i])
            i += 1
            parsed_bytes += 1
        else:
            size_parts.append(0)
    size = 0
    for offs, size_part in enumerate(size_parts):
        size += size_part << (offs * 8)
    return parsed_bytes, size


def parse_copy(stream: bytes, i: int) -> Tuple[int, bytes]:
    """
    Parse copy instruction.
    """
    cur = i
    determinant = stream[cur]
    parsed_bytes = 1
    cur += parsed_bytes
    parsed_bytes, offset = parse_copy_offset(determinant, stream, cur)
    cur += parsed_bytes

    parsed_bytes, size = parse_copy_size(determinant, stream, cur)
    cur += parsed_bytes
    # print("Copy: Offs:", offset, "Size:", size)

    return cur - i, offset, size


def decode_delta(instructions: bytes, ref_content: bytes) -> bytes:
    """
    Decode obj delta instructions.
    """
    content = b""
    i = 0

    parsed_bytes, ref_obj_size = parse_size(instructions, i)
    i += parsed_bytes
    if ref_obj_size != len(ref_content):
        raise ValueError("Referenced object size does not correspond.")

    parsed_bytes, obj_size = parse_size(instructions, i)
    i += parsed_bytes

    # print("Ref size:",ref_obj_size, "Obj size:", obj_size, "Instr:", instructions[:i])

    while i < len(instructions):
        if 1 <= instructions[i] <= 127:
            parsed_bytes, to_insert = parse_insert(instructions, i)
            content += to_insert
        elif 128 <= instructions[i] <= 255:
            parsed_bytes, offset, size = parse_copy(instructions, i)
            content += ref_content[offset : offset + size]
        else:
            raise ValueError("Reserved instruction.")
        i += parsed_bytes

    # print(len(content))
    if obj_size != len(content):
        print(content[:200])
        print(content[-200:])
        print(len(content), obj_size)
        print(f"Object sizes do not correspond.")
        print(
            hashlib.sha1(
                b"blob " + str(len(content)).encode() + b"\x00" + content
            ).hexdigest()
        )
        # raise ValueError("Object size does not correspond.")
    return content


def write_obj_ref_delta(ref_obj_sha: bytes, instructions: bytes, repo_path: str) -> str:
    """
    Write decoded obj referring ro ref_obj.
    """
    object_type, _content_length, ref_content = read_object(ref_obj_sha, repo_path)
    content = decode_delta(instructions, ref_content)
    sha, obj_content = create_object(object_type, content)
    write_object(sha, obj_content, repo_path)
    return sha


def clone(host: str, repo: str, repo_path: str) -> str:
    """
    Clone remote repository.
    """

    os.makedirs(repo_path)
    init(repo_path=repo_path)

    refs, pack = download_pack(host, repo)

    write_refs(refs, repo_path)

    objects = parse_pack(pack)

    written_objects = set()
    for obj in objects:
        if obj[0] in [b"commit", b"tree", b"blob", b"tag"]:
            sha, content = create_object(obj[0], obj[1])
            write_object(sha, content, repo_path)
            written_objects.add(sha)
        elif obj[0] == b"obj_ref_delta":
            ref_sha = hash_bytes_to_str(obj[1])
            if ref_sha not in written_objects:
                raise ValueError(f"Obj delta references unknown obect {obj[1]}.")
            sha = write_obj_ref_delta(ref_sha, obj[2], repo_path)
            written_objects.add(sha)

        else:
            raise NotImplementedError("Pack obj type not implemented.")

    return f"Remote repository {repo} cloned in {repo_path}."


def checkout(commit: str, directory: str, repo_path: str = ""):
    """
    Checkout commit from repository.
    """
    if commit == "HEAD":
        with open(os.path.join(repo_path, ".git", "HEAD"), "r") as head_file:
            head = head_file.read()
        if head.startswith("ref: "):
            with open(os.path.join(repo_path, ".git", head[5:]), "r") as commit_file:
                commit = commit_file.read()
        else:
            commit = head

    commit_obj = read_object(commit, repo_path)

    content = commit_obj[2]
    tree_type_sha, _ = content.split(b"\n", 1)
    tree_type, tree_sha = tree_type_sha.split(b" ", 1)
    print(tree_sha)
    if tree_type != b"tree":
        raise ValueError("Expecting tree object in commit.")

    checkout_tree(directory, tree_sha.decode(), repo_path)


def checkout_object(path, obj_name, obj_sha, repo_path):
    """
    Checkout object.
    """
    try:
        object_type, _content_length, _content = read_object(obj_sha, repo_path)
    except FileNotFoundError as file_not_found:
        print(f"File {obj_name} has no corresponding object {obj_sha}")
        print(file_not_found)
        return
    if object_type == b"tree":
        checkout_tree(os.path.join(path, obj_name.decode()), obj_sha, repo_path)
    elif object_type == b"blob":
        checkout_blob(path, obj_name.decode(), obj_sha, repo_path)
    else:
        raise NotImplementedError(f"Checkout of {object_type} not implemented.")


def checkout_tree(path, tree_sha, repo_path):
    """
    Checkout tree in path.
    """
    objects = ls_tree(tree_sha, repo_path)
    if not os.path.exists(path):
        os.mkdir(path)
    for _obj_permissions, obj_name, obj_sha in objects:
        # print(obj_permissions, obj_name, obj_sha)
        checkout_object(path, obj_name, obj_sha, repo_path)


def checkout_blob(path, blob_name, blob_sha, repo_path):
    """
    Checkout a blob.
    """
    with open(os.path.join(path, blob_name), "wb") as blob:
        blob.write(cat_file(blob_sha, repo_path))