# -*- coding: utf-8 -*-
"""Offline verify the captured gateway->agent frames with the derived key."""
import struct
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# pip 'cryptography' may be absent: fall back to a pure-python chacha below
# if needed.

DERIVED = bytes.fromhex(
    "b701bff55cbde9a10dbbc6a9c58269be2bc8519a4d0101b661f00762be9ee43b")


def parse_frames(data, label):
    frames = []
    off = 0
    while off + 36 <= len(data):
        magic, ver, ftype, seq, length, padlen = struct.unpack_from(
            "<IHHIIH", data, off)
        if magic != 0x46454900:
            print(label, "bad magic at", off, hex(magic))
            break
        total = 36 + length + 16 + padlen
        frames.append((off, ftype, seq, length, padlen,
                       data[off:off + total]))
        off += total
    print(label, "frames:", [(hex(t), s, l, p) for _, t, s, l, p, _ in frames])
    return frames


def main():
    s2c = open(r"C:\fei_probe\cap_s2c.bin", "rb").read()
    c2s = open(r"C:\fei_probe\cap_c2s.bin", "rb").read()

    frames = parse_frames(s2c, "S2C")
    aead = ChaCha20Poly1305(DERIVED)
    for off, ftype, seq, length, padlen, blob in frames:
        hdr = blob[:36]
        agent_id = hdr[18:26]
        nonce = struct.pack("<I", seq) + agent_id
        ct = blob[36:36 + length + 16]
        try:
            pt = aead.decrypt(nonce, ct, hdr)
            print("frame seq=%d type=0x%x VERIFIED pt=%r" % (seq, ftype, pt[:40]))
        except Exception as e:
            print("frame seq=%d type=0x%x FAILED: %s" % (seq, ftype, e))
            print("  hdr:", hdr.hex())
            print("  ct :", ct.hex())


if __name__ == "__main__":
    main()
