"""
Entry point for my git clone.
"""

import sys
import datetime
from typing import Tuple, List, Dict

from .git.git_plumbing import (  # pylint: disable=relative-beyond-top-level
    init,
    cat_file,
    ls_tree,
    hash_object,
    write_tree,
    commit_tree,
    clone,
    checkout,
)

def parse_commit_params(args: List[str]) -> List[str]:
    """
    Parse commit-tree parameters from CLI and other.
    """
    available_params = ["-p", "-m"]
    tree_sha = args[2]
    i = 3
    while i < len(args):
        param = args[i]
        if param not in available_params:
            raise RuntimeError(f"Unknown parameter {param} for `commit-tree`.")
        param_val = args[i + 1]
        if param == "-p":
            parent = param_val
        if param == "-m":
            message = param_val
        i += 2
    
    author = "Colin Ho <colin.ho99@gmail.com>"
    committer = "Colin Ho <colin.ho99@gmail.com>"
    dt = datetime.datetime.now(datetime.timezone.utc)
    utc_time = dt.replace(tzinfo=datetime.timezone.utc)
    utc_timestamp = utc_time.timestamp()

    content = [
        f"tree {tree_sha}",
        f"parent {parent}",
        f"author {author} {utc_timestamp}",
        f"committer {committer} {utc_timestamp}",
        f"",
        message,
        f"",
    ]
    return content


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
            for _, filename, _ in content:
                print(filename.decode())
        else:
            raise RuntimeError(f"Unknown parameter {opt} for `ls-tree`.")

    elif command == "write-tree":
        tree_sha = write_tree(".")
        print(tree_sha)

    elif command == "commit-tree":
        opts = parse_commit_params(sys.argv)
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