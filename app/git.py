import os
import zlib
import hashlib
from typing import Tuple, List, Dict


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


def init():
    """
    git init: create initial .git tree.
    """
    os.mkdir(".git")
    os.mkdir(".git/objects")
    os.mkdir(".git/refs")
    with open(".git/HEAD", "w") as head_file:
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


def ls_tree(tree_sha: str, repo_path: str = "") -> List[Tuple[bytes, bytes, bytes]]:
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
        + b" "
        + objects[key][1].encode()
        + b"\x00"
        + objects[key][2]
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