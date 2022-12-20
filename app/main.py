import sys
import os
import zlib
import hashlib

def catFile(file_hash):
    file_path = f'.git/objects/{file_hash[:2]}/{file_hash[2:]}'
    if os.path.isfile(file_path):
        with open(file_path, 'rb') as f:
            data = f.read()
        raw_bytes = zlib.decompress(data)
        # account for header, example: blob 16\u0000
        raw_bytes_without_header = raw_bytes[raw_bytes.index(b'\x00') + 1:]
        decoded_data = raw_bytes_without_header.decode()
        print(decoded_data, end='')

def hashObject(file):
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

def lsTree(file_hash):
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
        catFile(sys.argv[-1])
    elif command == "hash-object":
        hashObject(sys.argv[-1])
    elif command == "ls-tree":
        lsTree(sys.argv[-1])
    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()
