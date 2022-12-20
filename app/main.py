import sys
import time
import os
import hashlib
import zlib

from urllib import request


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
    elif command == "hash-object":
        file = sys.argv[-1]
        if os.path.isfile(file):
            with open(file, 'rb') as f:
                data = f.read()
            file_size = os.path.getsize(file)
            store = f"blob {file_size}\0".encode() + data
            file_hash = hashlib.sha1(store).hexdigest()
            os.mkdir(f'.git/objects/{file_hash[:2]}')
            with open(f'.git/objects/{file_hash[:2]}/{file_hash[2:]}', 'wb') as f:
                f.write(zlib.compress(store))
            print(file_hash, end='')
    elif command == "ls-tree":
        try:
            file_hash = sys.argv[-1]
            file_path = f'.git/objects/{file_hash[:2]}/{file_hash[2:]}'
            with open(file_path, 'rb') as f:
                data = f.read()
            raw_bytes = zlib.decompress(data)
            raw_bytes_as_arr = raw_bytes.split(b'\x00')
            files = []
            for i in range(1, len(raw_bytes_as_arr) - 1):
                if b' ' not in raw_bytes_as_arr[i]:  # skip last parsed val
                    continue
                filename = raw_bytes_as_arr[i].split(b' ')[-1]
                files.append(filename)
            for file in files:
                print(file.decode())
        except Exception as e:
            print(e)
    elif command == "write-tree":
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

        # for subdir, dirs, files in os.walk(rootdir):
        #     print(subdir, dirs, files)
    elif command == "commit-tree":
        tree_sha = sys.argv[2]
        parent_commit_sha = sys.argv[4]
        message = sys.argv[6] + '\n'
        content = f'tree {tree_sha}\n'
        content += f'parent {parent_commit_sha}\n'
        epoch_seconds = int(time.time())
        time_zone = '+0300'
        content += f'author Eyal Foni <eyalfoni@gmail.com> {epoch_seconds} {time_zone}\n'
        content += f'committer Eyal Foni <eyalfoni@gmail.com {epoch_seconds} {time_zone}\n\n'
        content += message
        content = content.encode()
        commit = f'commit {len(content)}\0'.encode() + content
        commit_hash = hashlib.sha1(commit).hexdigest()
        root_dir = f'.git/objects/{commit_hash[:2]}'
        if not os.path.exists(root_dir):
            os.mkdir(root_dir)
        with open(f'.git/objects/{commit_hash[:2]}/{commit_hash[2:]}', 'wb') as f:
            f.write(zlib.compress(commit))
        print(commit_hash)
    elif command == "clone":
        url = sys.argv[2]
        target_dir = sys.argv[3]
        os.mkdir(target_dir)
        os.mkdir(target_dir + '/.git')
        os.mkdir(target_dir + '/.git/objects/')
        os.mkdir(target_dir + "/.git/refs")
        with open(target_dir + "/.git/HEAD", "w") as f:
            f.write("ref: refs/heads/master\n")
        # print(url, target_dir)
        resp = request.urlopen(url + "/info/refs?service=git-upload-pack")
        content = resp.read()
        resp.close()
        # print(content)
        resp_as_arr = content.split(b'\n')
        # print(resp_as_arr)
        for c in resp_as_arr:
            if b'refs/heads/master' in c and b'003f' in c:
                tup = c.split(b' ')
                pack_hash = tup[0][4:].decode()  # convert later
                # print(pack_hash)
        post_url = url + '/git-upload-pack'
        req = request.Request(post_url)
        req.add_header('Content-Type', 'application/x-git-upload-pack-request')
        data = f"0032want {pack_hash}\n00000009done\n".encode()
        # print(data)

        ######################
        # import requests
        #
        # resp = requests.post(post_url, data=data, headers={'Content-Type': 'application/x-git-upload-pack-request'})
        ######################

        pack_resp = request.urlopen(req, data=data)
        print(pack_resp.status)
        pack_resp = pack_resp.read()
        # return
        entries_bytes = pack_resp[16:20]
        num_entries = int.from_bytes(entries_bytes, byteorder="big")
        print('entries count', num_entries)
        data = pack_resp[20:-20]

        objs = {}
        seek = 0
        objs_count = 0
        while objs_count != num_entries:
            objs_count += 1
            first = data[seek]

            obj_type = (first & 112) >> 4
            # print('obj_type: ', obj_type)
            # num_entries -= 1
            while data[seek] > 128:
                seek += 1
            seek += 1
            if obj_type < 7:
                content = zlib.decompress(data[seek:])
                obj_type_to_str = {
                    1: 'commit',
                    2: 'tree',
                    3: 'blob'
                }
                obj_write_data = f'{obj_type_to_str[obj_type]} {len(content)}\0'.encode()
                obj_write_data += content
                commit_hash = hashlib.sha1(obj_write_data).hexdigest()

                f_path = target_dir + f'/.git/objects/{commit_hash[:2]}'
                if not os.path.exists(f_path):
                    os.mkdir(f_path)
                with open(target_dir + f'/.git/objects/{commit_hash[:2]}/{commit_hash[2:]}', 'wb') as f:
                    f.write(zlib.compress(obj_write_data))

                objs[commit_hash] = (content, obj_type)
                compressed_len = zlib.compress(content)
                seek += len(compressed_len)
            else:
                # num_entries -= 1

                # 20 byte header for sha1 base reference
                k = data[seek:seek + 20]
                print(k.hex())
                obs_elem = objs[k.hex()]
                base = obs_elem[0]
                seek += 20

                delta = zlib.decompress(data[seek:])
                compressed_data = zlib.compress(delta)

                content = undeltify(delta, base)
                # print(content)
                obj_type = obs_elem[1]
                obj_type_to_str = {
                    1: 'commit',
                    2: 'tree',
                    3: 'blob'
                }
                obj_write_data = f'{obj_type_to_str[obj_type]} {len(content)}\0'.encode()
                obj_write_data += content
                commit_hash = hashlib.sha1(obj_write_data).hexdigest()

                f_path = target_dir + f'/.git/objects/{commit_hash[:2]}'
                if not os.path.exists(f_path):
                    os.mkdir(f_path)
                with open(target_dir + f'/.git/objects/{commit_hash[:2]}/{commit_hash[2:]}', 'wb') as f:
                    f.write(zlib.compress(obj_write_data))

                objs[commit_hash] = (content, obj_type)

                seek += len(compressed_data)

        with open(target_dir + f'/.git/objects/{pack_hash[:2]}/{pack_hash[2:]}', 'rb') as f:
            commit = f.read()
        raw_bytes = zlib.decompress(commit)
        commit_as_arr = raw_bytes.decode().split('\n')
        tree_sha = commit_as_arr[0].split(' ')[-1]
        print('tree_sha', tree_sha)

        sha_len = 20

        def checkout_tree(sha, file_path):
            if not os.path.exists(file_path):
                # print(file_path)
                os.mkdir(file_path)

            with open(target_dir + f'/.git/objects/{sha[:2]}/{sha[2:]}', 'rb') as ff:
                tree = zlib.decompress(ff.read())

            entries = []
            tree = tree[tree.index(b'\x00') + len(b'\x00'):]
            while tree:
                pos = tree.index(b'\x00')
                mode_name = tree[:pos]
                mode, name = mode_name.split(b' ')
                tree = tree[pos + len(b'\x00'):]
                sha = tree[:sha_len]
                tree = tree[sha_len:]
                entries.append((mode, name.decode(), sha.hex()))

            for entry in entries:
                if entry[0] == b'40000':
                    checkout_tree(entry[2], file_path + f'/{entry[1]}')
                else:
                    blob_sha = entry[2]
                    with open(target_dir + f'/.git/objects/{blob_sha[:2]}/{blob_sha[2:]}', 'rb') as blob_file:
                        blob_data = zlib.decompress(blob_file.read())
                    content = blob_data[blob_data.index(b'\x00') + len(b'\x00'):]
                    # print(content)
                    with open(file_path + f'/{entry[1]}', 'w') as w_file:
                        w_file.write(content.decode())

                        # print(entry[0], file_path, entry[1])

        checkout_tree(tree_sha, target_dir)
    else:
        raise RuntimeError(f"Unknown command #{command}")


def undeltify(delta, base):
    # ignore parse source & target length
    seek = 0
    while delta[seek] > 128:
        seek += 1
    seek += 1
    while delta[seek] > 128:
        seek += 1
    seek += 1
    content = b''
    delta_len = len(delta)
    print('delta_len', delta_len)
    while seek < delta_len:
        instr_byte = delta[seek]
        seek += 1
        print(instr_byte)
        is_copy = instr_byte >= 128
        if is_copy:
            # print('copy instruction', instr_byte)
            offset_key = instr_byte & 0b00001111
            offset_key_bin_str = bin(offset_key)[2:]
            offset_bytes = []
            for b in reversed(offset_key_bin_str):
                if b == '1':
                    offset_bytes.append(delta[seek])
                    seek += 1
                else:
                    offset_bytes.append(0)
            offset = int.from_bytes(offset_bytes, byteorder="little")

            len_key = (instr_byte & 0b01110000) >> 4
            len_key_bin_str = bin(len_key)[2:]
            len_bytes = []
            for b in reversed(len_key_bin_str):
                if b == '1':
                    len_bytes.append(delta[seek])
                    seek += 1
                else:
                    len_bytes.append(0)
            len_int = int.from_bytes(len_bytes, byteorder="little")
            content += base[offset: offset + len_int]
        else:
            print('insert instruction', instr_byte)
            num_bytes = instr_byte & 0b01111111
            content += delta[seek:seek+num_bytes]
            seek += num_bytes
    return content


if __name__ == "__main__":
    main()