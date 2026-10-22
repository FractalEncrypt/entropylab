#!/usr/bin/env python3
# Counts the Bitcoin block-header attestations in an OpenTimestamps proof by
# walking its structure, so attestation tags count only where the format puts
# an attestation, never inside an op argument or a calendar URI that happens
# to contain the same eight bytes. Standard library only: ots-upgrade.yml runs
# it next to the push token on a proof the untrusted client produced. Prints
# the count; exits 1 on anything that is not a well-formed v1 proof with a
# SHA-256 file hash (wrong header, unknown op, truncation, trailing bytes,
# oversized fields, excessive nesting).
#   python3 scripts/ots-attestations.py entropylab.html.ots
import sys

MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108")
BITCOIN = bytes.fromhex("0588960d73d71901")
UNARY_OPS = {0x02, 0x03, 0x08, 0x67, 0xF2, 0xF3}  # sha1 ripemd160 sha256 keccak256 reverse hexlify
BINARY_OPS = {0xF0, 0xF1}  # append prepend, each with one argument


class Malformed(Exception):
    pass


def count(data):
    if len(data) < len(MAGIC) + 32 or not data.startswith(MAGIC):
        raise Malformed("not an OpenTimestamps v1 proof with a SHA-256 file hash")
    pos = len(MAGIC) + 32

    def byte():
        nonlocal pos
        if pos >= len(data):
            raise Malformed("truncated")
        pos += 1
        return data[pos - 1]

    def varuint():
        value, shift = 0, 0
        while True:
            b = byte()
            value |= (b & 0x7F) << shift
            if not b & 0x80:
                return value
            shift += 7
            if shift > 63:
                raise Malformed("varuint too long")

    def varbytes(limit):
        nonlocal pos
        length = varuint()
        if length > limit or pos + length > len(data):
            raise Malformed("field out of range")
        pos += length

    def item(tag, depth):
        if tag == 0x00:
            attestation = bytes(byte() for _ in range(8))
            varbytes(8192)
            return 1 if attestation == BITCOIN else 0
        if tag in BINARY_OPS:
            varbytes(4096)
        elif tag not in UNARY_OPS:
            raise Malformed("unknown op 0x%02x" % tag)
        return timestamp(depth + 1)

    def timestamp(depth):
        if depth > 256:
            raise Malformed("nested too deeply")
        found = 0
        tag = byte()
        while tag == 0xFF:
            found += item(byte(), depth)
            tag = byte()
        return found + item(tag, depth)

    found = timestamp(0)
    if pos != len(data):
        raise Malformed("trailing bytes")
    return found


if __name__ == "__main__":
    try:
        with open(sys.argv[1], "rb") as proof:
            print(count(proof.read()))
    except (Malformed, OSError, IndexError) as error:
        print("ots-attestations: %s" % error, file=sys.stderr)
        sys.exit(1)
