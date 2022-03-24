#!/usr/bin/env python3

"""
A binary file to create all variations of .securefs.json by calling `chpass`.
"""

import enum
import os
import subprocess
import shutil
import sys
import glob


class SecretInputMode(enum.IntEnum):
    PASSWORD = 0b1
    KEYFILE = 0b10
    PASSWORD_WITH_KEYFILE = PASSWORD | KEYFILE


def create(securefs_binary: str, version: int, pbkdf: str, mode: SecretInputMode):
    new_config_filename = f"{version}/.securefs.{pbkdf}.{mode.name}.json"
    if os.path.exists(new_config_filename):
        print(new_config_filename, "already exists", file=sys.stderr)
        return
    original_config_filename = next(glob.iglob(f"{version}/.securefs.*.json"))
    shutil.copy(original_config_filename, new_config_filename)
    args = [
        securefs_binary,
        "chpass",
        "--oldpass",
        "abc",
        "--pbkdf",
        pbkdf,
        "--config",
        new_config_filename,
        "-r",
        "2",
    ]
    if mode & SecretInputMode.KEYFILE:
        args.extend(["--newkeyfile", "keyfile"])
    if mode & SecretInputMode.PASSWORD:
        args.extend(["--newpass", "abc"])
    args.append(f"{version}")
    subprocess.check_call(args)


def main():
    os.environ["SECUREFS_ARGON2_M_COST"] = "16"
    os.environ["SECUREFS_ARGON2_P"] = "2"
    os.chdir(os.path.dirname(__file__))
    for version in range(1, 5):
        for pbkdf in ("scrypt", "pkcs5-pbkdf2-hmac-sha256", "argon2id"):
            for mode in SecretInputMode:
                create(sys.argv[1], version=version, pbkdf=pbkdf, mode=mode)


if __name__ == "__main__":
    main()
