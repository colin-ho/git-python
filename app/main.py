"""
Entry point for my git clone.
"""

import sys
import datetime

from .git import (  # pylint: disable=relative-beyond-top-level
    init,
    cat_file,
    ls_tree,
    hash_object,
    write_tree,
    commit_tree,
    clone,
    checkout,
)


def hardcoded_commit_params():
    """
    Returns tuple of commit parameters
    """
    author = "Papik Meli <papik@qlac.ch>"
    committer = "Papik Meli <papik@qlac.ch>"
    now = datetime.datetime.now()
    timestamp_local = round(now.timestamp())
    offset_seconds = now.astimezone().utcoffset().seconds
    offset_hours = offset_seconds // 3600
    offset_minutes = offset_seconds % 3600
    timestamp_offset = f"{offset_hours:+03}{offset_minutes:02}"
    timestamp = str(timestamp_local) + " " + timestamp_offset
    return {"author": author, "committer": committer, "timestamp": timestamp}


def parse_commit_params(args):
    """
    Parse commit-tree parameters from CLI and other.
    """
    params = ["-p", "-m"]
    tree_sha = args[2]
    i = 3
    while i < len(args):
        param = args[i]
        if param not in params:
            raise RuntimeError(f"Unknown parameter {param} for `commit-tree`.")
        para_val = args[i + 1]
        if param == "-p":
            parent = para_val
        if param == "-m":
            message = para_val
        i += 2
    return tree_sha, parent, message


def main():
    """
    Entry point.
    """

    command = sys.argv[1]
    if command == "init":
        init()

    elif command == "cat-file":
        opt = sys.argv[2]
        if opt != "-p":
            raise RuntimeError(f"Unknown parameter {opt} for `cat-file`.")
        blob_sha = sys.argv[3]
        content = cat_file(blob_sha)
        print(content.decode(), end="")

    elif command == "hash-object":
        opt = sys.argv[2]
        if opt != "-w":
            raise RuntimeError(f"Unknown parameter {opt} for `hash-object`.")
        file_path = sys.argv[3]
        blob_sha = hash_object(file_path)
        print(blob_sha, end="")

    elif command == "ls-tree":
        opt = sys.argv[2]
        tree_sha = sys.argv[3]
        content = ls_tree(tree_sha)
        if opt == "--name-only":
            print("\n".join([obj[1].decode() for obj in content]))
            return
        raise RuntimeError(f"Unknown parameter {opt} for `ls-tree`.")

    elif command == "write-tree":
        tree_sha = write_tree(".")
        print(tree_sha)

    elif command == "commit-tree":
        tree_sha, parent, message = parse_commit_params(sys.argv)
        opts = hardcoded_commit_params()
        opts["parent"] = parent
        opts["message"] = message
        commit_sha = commit_tree(tree_sha, opts)
        print(commit_sha)

    elif command == "clone":
        url = sys.argv[2]
        directory = sys.argv[3]
        host_repo = url[8:]
        host, repo = host_repo.split("/", 1)
        repo = "/" + repo
        clone(host, repo, directory)
        checkout("HEAD", directory, directory)
        print(f"Cloned {repo} from {host} in {directory}.")

    else:
        raise RuntimeError(f"Unknown command #{command}")


if __name__ == "__main__":
    main()