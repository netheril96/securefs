import os
import subprocess
import argparse
import contextlib
import sys
from typing import List


def main():
    parser = argparse.ArgumentParser()
    script_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "simple_test.py"
    )
    parser.add_argument(
        "--binary", help="Path to the binary of securefs", required=True
    )
    parser.add_argument(
        "--shards", help="Total number of shards", type=int, default=128
    )
    args = parser.parse_args()
    if args.shards < 1:
        raise ValueError("--shards must be >= 1")
    processes: List[subprocess.Popen] = []
    exit_code = 0
    with contextlib.ExitStack() as stack:
        env = os.environ.copy()
        env["SECUREFS_BINARY"] = args.binary
        env["SECUREFS_TEST_NUM_SHARDS"] = str(args.shards)
        for i in range(args.shards):
            env["SECUREFS_TEST_SHARD_INDEX"] = str(i)
            processes.append(
                stack.enter_context(
                    subprocess.Popen([sys.executable, script_path], env=env)
                )
            )
        for p in processes:
            exit_code |= p.wait()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
