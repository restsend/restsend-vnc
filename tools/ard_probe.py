#!/usr/bin/env python3
"""ARD (Apple Remote Desktop / RFB 003.889) client probe.

Connects to a real macOS Screen Sharing server, performs the Apple DH
authentication, reads the extended ServerInit, then decrypts the
server->client encrypted stream and dumps every record.

Usage:
    python3 ard_probe.py HOST [PORT] [USER] [PASSWORD] [OUTFILE]

Password may also come from $ARD_PASSWORD.  The tool is read-only: it never
sends input events, it just captures what the real server sends (this is how
we learn the exact encryption-setup / control-message layout).

Requires the `openssl` CLI for AES (ECB for the DH-wrapped key/IV, CBC for the
stream); SHA1/MD5 and the DH math are pure Python.
"""
import hashlib
import os
import socket
import struct
import subprocess
import sys
import time

PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
GEN = 2
KEYLEN = 256


def aes(mode, data, key, iv=None):
    """mode: 'ecb' or 'cbc', decrypt; returns bytes"""
    args = ["openssl", "enc", f"-aes-128-{mode}", "-d", "-K", key.hex(), "-nopad"]
    if iv is not None:
        args += ["-iv", iv.hex()]
    p = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        raise RuntimeError("openssl: " + p.stderr.decode(errors="replace"))
    return p.stdout


def recv_exact(sock, n, timeout=10.0):
    sock.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"eof after {len(buf)}/{n} bytes")
        buf += chunk
    return buf


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 5900
    user = sys.argv[3] if len(sys.argv) > 3 else os.environ.get("ARD_USER", "pi")
    password = sys.argv[4] if len(sys.argv) > 4 else os.environ.get("ARD_PASSWORD", "")
    outfile = sys.argv[5] if len(sys.argv) > 5 else "/tmp/ard_probe.out"

    log = open(outfile, "wb")
    def dump(tag, data):
        log.write(tag.encode() + b" " + data.hex().encode() + b"\n")
        log.flush()

    s = socket.create_connection((host, port), timeout=10)
    s.sendall(b"RFB 003.889\n")
    ver = recv_exact(s, 12)
    print("server version:", ver)
    if b"889" not in ver:
        print("warning: server is not 003.889; this probe targets the ARD dialect")

    n = recv_exact(s, 1)[0]
    types = recv_exact(s, n) if n else b""
    print("security types:", list(types))
    if 30 not in types:
        raise SystemExit("server does not offer Apple DH (30)")
    s.sendall(bytes([30]))

    gen = struct.unpack(">H", recv_exact(s, 2))[0]
    klen = struct.unpack(">H", recv_exact(s, 2))[0]
    prime = int.from_bytes(recv_exact(s, klen), "big")
    server_pub = int.from_bytes(recv_exact(s, klen), "big")
    print(f"DH gen={gen} keylen={klen}")

    secret = int.from_bytes(os.urandom(klen), "big")
    client_pub = pow(GEN, secret, prime)
    shared = pow(server_pub, secret, prime)
    # Apple always treats the DH shared secret as a fixed 256-byte big-endian
    # value for the MD5 key derivation, even when the negotiated DH group is
    # 1024-bit (keylen=128).
    key = hashlib.md5(shared.to_bytes(max(klen, 256), "big")).digest()
    print("session key:", key.hex())
    dump("KEY", key)

    creds = bytearray(128)
    creds[:64] = user.encode()[:64].ljust(64, b"\0")
    creds[64:128] = password.encode()[:64].ljust(64, b"\0")
    enc = subprocess.run(["openssl", "enc", "-aes-128-ecb", "-e", "-K", key.hex(),
                          "-nopad"], input=bytes(creds), stdout=subprocess.PIPE).stdout
    s.sendall(enc + client_pub.to_bytes(klen, "big"))

    result = struct.unpack(">I", recv_exact(s, 4))[0]
    print("security result:", result)
    if result != 0:
        raise SystemExit("authentication failed")

    s.sendall(b"\xc1")  # ClientInit with the Apple "extended init" bit
    w, h = struct.unpack(">HH", recv_exact(s, 4))
    pf = recv_exact(s, 16)
    (extralen,) = struct.unpack(">I", recv_exact(s, 4))
    extra = recv_exact(s, extralen)
    print(f"ServerInit {w}x{h} pf={pf.hex()} extralen={extralen}")
    print("extra:", extra.hex())
    dump("SERVERINIT", pf + extra)
    if extralen >= 22:
        info = extra[:22]
        name = extra[22:]
        print("RFBServerInfo2:", info.hex())
        print("machine name:", name)

    # ---- act like a viewer so the server starts its frame/setup path ----
    s.sendall(b"\x0a\x00\x00\x01")  # Apple session-start
    pf_msg = bytes([0, 0, 0, 0, 32, 32, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0])
    s.sendall(pf_msg)
    encs = [1011, 1002, 6, 16, (-239) & 0xFFFFFFFF, 1104, 1100, (-223) & 0xFFFFFFFF,
            1101, 1105, 1107, 1109, 1110]
    msg = struct.pack(">BBH", 2, 0, len(encs)) + b"".join(struct.pack(">I", e) for e in encs)
    s.sendall(msg)
    s.sendall(struct.pack(">BBHHHH", 3, 0, 0, 0, w, h))  # FBUR

    # ---- plaintext phase: the encryption-setup pseudo-rect ----
    # Read until we see a FramebufferUpdate carrying encoding 1103.
    buf = b""
    cbc_key = cbc_iv = None
    while cbc_key is None:
        buf += recv_exact(s, 1)
        # A complete FBU with 1 rect: 4 + 12 + 36 = 52 bytes
        if len(buf) >= 52 and buf[0] == 0x00:
            rec = buf[:52]
            enc_id = struct.unpack(">I", rec[12:16])[0]
            print(f"plaintext message type=0 rects={struct.unpack('>H', rec[2:4])[0]} encoding={enc_id}")
            if enc_id == 0x44F:
                seq = struct.unpack(">I", rec[16:20])[0]
                k = aes("ecb", rec[20:36], key)
                iv = aes("ecb", rec[36:52], key)
                cbc_key, cbc_iv = k, iv
                print(f"encryption setup: seq={seq} key={k.hex()} iv={iv.hex()}")
                dump("SETUP", rec)
            buf = buf[52:]
            break
    if not buf:
        # read whatever remains as the encrypted stream
        pass

    if cbc_key is None:
        print("no encryption setup found; stopping")
        return

    # ---- encrypted phase: read the whole ciphertext stream, then CBC-decrypt ----
    print("capturing encrypted server->client stream for 6s ...")
    s.settimeout(1.0)
    deadline = time.time() + 6
    while time.time() < deadline:
        try:
            chunk = s.recv(1 << 20)
        except socket.timeout:
            continue
        if not chunk:
            break
        buf += chunk
    print("ciphertext bytes:", len(buf))
    dump("CIPHERTEXT", buf)

    # CBC state chains across the whole stream; decrypt it as one blob.
    pad = len(buf) % 16
    if pad:
        buf = buf[:-pad]
    plain = aes("cbc", buf, cbc_key, cbc_iv)
    dump("PLAIN", plain)

    # Parse records: BE16 len || payload || padding || SHA1(seq||...)
    off = 0
    i = 0
    while off + 2 <= len(plain):
        ln = struct.unpack(">H", plain[off:off + 2])[0]
        total = (ln + 0x25) & ~0xF
        if total > len(plain) - off or ln > 0x8000:
            print(f"record {i}: implausible len={ln} at {off}; stopping")
            break
        payload = plain[off + 2: off + 2 + ln]
        print(f"record {i}: len={ln} head={payload[:24].hex()}")
        dump(f"REC{i}", payload)
        off += total
        i += 1
    print(f"parsed {i} encrypted records")
    log.close()
    print("wrote", outfile)


if __name__ == "__main__":
    main()
