import sys
from .git import init, cat_file, ls_tree, hash_object, write_tree

 
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
            return None
            return
        raise RuntimeError(f"Unknown parameter {opt} for `ls-tree`.")

    elif command == "write-tree":
        tree_sha = write_tree(".")
        print(tree_sha)

    else:
        raise RuntimeError(f"Unknown command #{command}")
 
 
if __name__ == "__main__":
     main()