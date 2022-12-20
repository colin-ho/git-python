import sys
import os
import zlib
import hashlib
import time

def catFile():
    file_hash = sys.argv[-1]
    file_path = f'.git/objects/{file_hash[:2]}/{file_hash[2:]}'
    if os.path.isfile(file_path):
        with open(file_path, 'rb') as f:
            data = f.read()
        raw_bytes = zlib.decompress(data)
        # account for header, example: blob 16\u0000
        raw_bytes_without_header = raw_bytes[raw_bytes.index(b'\x00') + 1:]
        decoded_data = raw_bytes_without_header.decode()
        print(decoded_data, end='')

def hashObject():
    file = sys.argv[-1]
    if os.path.isfile(file):
        with open(file, "rb") as f:
            data = f.read()
        file_size = os.path.getsize(file)
        store = f"blob {file_size}\0".encode() + data
        file_hash = hashlib.sha1(store).hexdigest()
        os.mkdir(f".git/objects/{file_hash[:2]}")
        with open(f".git/objects/{file_hash[:2]}/{file_hash[2:]}", "wb") as f:
            f.write(zlib.compress(store))
        print(file_hash, end="")

def lsTree():
    file_hash = sys.argv[-1]
    file_path = f".git/objects/{file_hash[:2]}/{file_hash[2:]}"
    with open(file_path, "rb") as f:
        data = f.read()
    raw_bytes = zlib.decompress(data)
    raw_bytes_as_arr = raw_bytes.split(b"\x00")
    files = []
    for i in range(1, len(raw_bytes_as_arr) - 1):
        filename = raw_bytes_as_arr[i].split(b" ")[-1]
        files.append(filename)
    for file in files:
        print(file.decode())

def writeTree():
    root_tree_hash = ""
    rootdir = '.'
    visited = {}
    for subdir, dirs, files in os.walk(rootdir, topdown=False):
        # print(visited)
        if '.git' in subdir:
            continue
        # print(subdir, dirs)
        if not dirs:
            size = 0
            data = b''
            for file in sorted(files):
                file_path = os.path.join(subdir, file)
                file_size = os.path.getsize(file_path)
                size += file_size

                with open(file_path, 'rb') as f:
                    file_data = f.read()
                store = f"blob {file_size}\0".encode() + file_data
                file_hash = hashlib.sha1(store).digest()
                data += f'100644 {file}\0'.encode()
                data += file_hash
            tree_obj = f'tree {size}\0'.encode()
            tree_obj += data
            tree_hash_digest_obj = hashlib.sha1(tree_obj)
            tree_hash_as_hex_str = tree_hash_digest_obj.hexdigest()
            root_dir = f'.git/objects/{tree_hash_as_hex_str[:2]}'
            if not os.path.exists(root_dir):
                os.mkdir(root_dir)
            with open(f'{root_dir}/{tree_hash_as_hex_str[2:]}', 'wb') as f:
                f.write(zlib.compress(tree_obj))
            subdir_name = subdir[2:]  # subdir = './vanilla'
            tree_hash_as_bytes = tree_hash_digest_obj.digest()
            visited[subdir_name] = (tree_hash_as_bytes, len(tree_obj))
        else:
            tree_contents = files + dirs
            tree_contents.sort()
            tree_contents = tree_contents[1:]  # remove .git dir

            size = 0
            data = b''
            for file_or_dir in tree_contents:
                if os.path.isfile(file_or_dir):
                    file_size = os.path.getsize(file_or_dir)
                    size += file_size

                    with open(file_or_dir, 'rb') as f:
                        file_data = f.read()
                    store = f"blob {file_size}\0".encode() + file_data
                    file_hash = hashlib.sha1(store).digest()
                    data += f'100644 {file_or_dir}\0'.encode()
                    data += file_hash
                else:
                    data += f'40000 {file_or_dir}\0'.encode()
                    tree_vals = visited[file_or_dir]
                    data += tree_vals[0]
                    size += tree_vals[1]
            tree_obj = f'tree {size}\0'.encode()
            tree_obj += data
            # print(tree_obj.decode())
            tree_hash = hashlib.sha1(tree_obj).hexdigest()
            f_name = f'.git/objects/{tree_hash[:2]}'
            if not os.path.exists(f_name):
                os.mkdir(f_name)
            # print(tree_obj.decode().split('\0'))
            with open(f'.git/objects/{tree_hash[:2]}/{tree_hash[2:]}', 'wb') as f:
                f.write(zlib.compress(tree_obj))
            root_tree_hash = tree_hash
    print(root_tree_hash)

def commitTree():
    tree_sha = sys.argv[2]
    parent_commit_sha = sys.argv[4]
    message = sys.argv[6] + "\n"
    content = f"tree {tree_sha}\n"
    content += f"parent {parent_commit_sha}\n"
    epoch_seconds = int(time.time())
    time_zone = "+0300"
    content += (
        f"author Colin Ho <colinho@gmail.com> {epoch_seconds} {time_zone}\n"
    )
    content += (
        f"committer Colin Ho <colinho@gmail.com {epoch_seconds} {time_zone}\n\n"
    )
    content += message
    content = content.encode()
    commit = f"commit {len(content)}\0".encode() + content
    commit_hash = hashlib.sha1(commit).hexdigest()
    os.mkdir(f".git/objects/{commit_hash[:2]}")
    with open(f".git/objects/{commit_hash[:2]}/{commit_hash[2:]}", "wb") as f:
        f.write(zlib.compress(commit))
    print(commit_hash)

def main():
    command = sys.argv[1]
    if command == "init":
        os.mkdir(".git")
        os.mkdir(".git/objects")
        os.mkdir(".git/refs")
        with open(".git/HEAD", "w") as f:
            f.write("ref: refs/heads/master\n")
        print("Initialized git directory")
    elif command == "cat-file":
        catFile()
    elif command == "hash-object":
        hashObject()
    elif command == "ls-tree":
        lsTree()
    elif command == "write-tree":
        writeTree()
    elif command == "commit-tree":
        commitTree()
    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()
