import sys
import os
import zlib

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
    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()
