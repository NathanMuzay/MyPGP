#!/usr/bin/env python3
"""Interface des chiffrements XOR, AES, RSA, PGP-XOR et PGP-AES."""

import re
import sys

import aes
import pgp_aes
import pgp_xor
import rsa
import xor


SYSTEMS = {
    "xor": xor,
    "aes": aes,
    "rsa": rsa,
    "pgp-xor": pgp_xor,
    "pgp-aes": pgp_aes,
}


HELP = """USAGE
    ./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]

DESCRIPTION
    Cipher or decipher MESSAGE read from standard input.

    CRYPTO_SYSTEM
        xor         XOR algorithm (implemented)
        aes         AES-128/192/256 algorithms (implemented)
        rsa         RSA algorithm (implemented)
        pgp-xor     RSA and XOR (implemented)
        pgp-aes     RSA and AES-128 (implemented)

    MODE
        -c          Cipher a clear message
        -d          Decipher a hexadecimal message
        -g P Q      Generate RSA keys from little-endian primes

    OPTIONS
        -b          Process one block (AES: 16 bytes; XOR: key size)

    key             Hexadecimal symmetric key or RSA exponent-modulus (little-endian)
                    PGP-XOR/PGP-AES: symmetric-key:RSA-key (-d: encrypted symmetric key)
"""


def parse_hex(value):
    """Un octet est représenté par exactement deux chiffres hexadécimaux."""
    if not value or len(value) % 2 or re.fullmatch(r"[0-9a-fA-F]+", value) is None:
        raise ValueError("expected a non-empty hexadecimal value with complete bytes")
    return bytes.fromhex(value)


def parse_arguments(arguments):
    if len(arguments) < 3:
        raise ValueError("expected CRYPTO_SYSTEM MODE [-b] key; use -h for help")
    system, mode, *remaining = arguments
    if system not in SYSTEMS:
        raise ValueError("unknown cryptosystem: " + system)
    if system == "rsa" and mode == "-g":
        if len(remaining) != 2:
            raise ValueError("RSA generation expects exactly two primes P Q")
        return rsa, mode, False, tuple(remaining)
    if mode not in ("-c", "-d"):
        raise ValueError(system.upper() + " mode must be -c or -d")
    block_mode = remaining[0] == "-b"
    if block_mode:
        remaining = remaining[1:]
    if len(remaining) != 1:
        raise ValueError("expected exactly one key after the optional -b flag")
    if system in ("pgp-xor", "pgp-aes"):
        SYSTEMS[system].parse_key(remaining[0])
        return SYSTEMS[system], mode, block_mode, remaining[0]
    if system == "rsa":
        rsa.parse_key(remaining[0])
        return rsa, mode, block_mode, remaining[0]
    return SYSTEMS[system], mode, block_mode, parse_hex(remaining[0])



def main():
    if sys.argv[1:] == ["-h"]:
        print(HELP, end="")
        return 0
    try:
        system, mode, block_mode, key = parse_arguments(sys.argv[1:])
        if mode == "-g":
            public, private = rsa.generate_keys(*key)
            print("public key: " + public)
            print("private key: " + private)
            return 0
        single_line = block_mode or system is rsa
        data = sys.stdin.buffer.read()
        # Le LF terminal est ignoré en bloc et dans la représentation hex.
        if (single_line or mode == "-d") and data.endswith(b"\n"):
            data = data[:-1]
        if single_line and b"\n" in data:
            raise ValueError("this mode expects a single line")
        if mode == "-d":
            data = parse_hex(data.decode("ascii")) if data else b""
        operation = system.encrypt if mode == "-c" else system.decrypt
        result = operation(data, key, block_mode)
        if mode == "-c":
            if system in (pgp_xor, pgp_aes):
                encrypted_key, result = result
                sys.stdout.buffer.write(encrypted_key.hex().encode("ascii") + b"\n")
            sys.stdout.buffer.write(result.hex().encode("ascii") + b"\n")
        else:
            sys.stdout.buffer.write(result + (b"\n" if single_line else b""))
        return 0
    except (ValueError, OSError) as error:
        print("my_pgp: " + str(error), file=sys.stderr)
        return 84


if __name__ == "__main__":
    sys.exit(main())
