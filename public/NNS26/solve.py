#!/usr/bin/env python3

# Only stdlib + py_ecc are required:  pip install py_ecc (I use a pyvenv)
import hashlib
import random
import socket
import ssl
import struct
import sys

from py_ecc.bls12_381 import (
    G1,G2,FQ,FQ2,multiply,pairing,final_exponentiate,curve_order,field_modulus,
)

HOST = "127.0.0.1"  # "impossible-60e153b10e58.chall.nnsc.tf"
PORT = 1337  # 31337
CEREMONY_ID = "3c311d9dfb7735e42643f394dc2c10af"
TAU = 3894627051107121998319229043008213446770981528672674568925122813412699817
CLAIM = 1_000_000_000

r = curve_order  # BLS12-381 scalar field order (matches bellman's Fr)
q = field_modulus  # BLS12-381 base field order (matches bellman's Fq)


# Re-implementation of lib.rs::derive() and lib.rs::mint_ic_scalars()
def _int_to_le32(x: int) -> bytes:
    return x.to_bytes(32, "little")


def _derive_one(tau: int, label: bytes) -> int:
    secret = bytearray(_int_to_le32(tau))
    counter = 0
    while True:
        buf = bytearray(secret[:32])
        buf += counter.to_bytes(4, "little")
        digest = hashlib.blake2b(bytes(buf), digest_size=32, key=label).digest()
        limbs = [
            int.from_bytes(digest[i * 8 : (i + 1) * 8], "little") for i in range(4)
        ]
        value = limbs[0] | (limbs[1] << 64) | (limbs[2] << 128) | (limbs[3] << 192)
        if value != 0 and value < r:  # Fr::from_repr rejects value >= MODLUS
            return value
        counter += 1


def derive(tau: int):
    return [
        _derive_one(tau, b"alpha"),
        _derive_one(tau, b"beta"),
        _derive_one(tau, b"gamma"),
        _derive_one(tau, b"delta"),
        _derive_one(tau, b"g1-scale"),
        _derive_one(tau, b"g2-scale"),
    ]


def mint_ic_scalars(tau: int, alpha: int, beta: int, gamma: int):
    g = 7
    t = 12208678567578594777604504606729831043093128246378069236549469339647  # (r-1)/2^32
    root32 = pow(g, t, r)  # Fr::root_of_unity()
    omega = pow(root32, 1 << 30, r)  # 4th root of unity
    roots = [1, omega, (omega * omega) % r, (omega * omega % r) * omega % r]

    lagrange = [0, 0, 0, 0]
    for i in range(4):
        numerator, denominator = 1, 1
        for j in range(4):
            if i != j:
                numerator = (numerator * ((tau - roots[j]) % r)) % r
                denominator = (denominator * ((roots[i] - roots[j]) % r)) % r
        lagrange[i] = (numerator * pow(denominator, -1, r)) % r

    ic0 = (lagrange[2] * beta) % r
    b0 = ((lagrange[0] + lagrange[1]) * alpha) % r
    ic0 = (ic0 + b0) % r
    c0 = (lagrange[1] * 100) % r
    ic0 = (ic0 + c0) % r
    ic0 = (ic0 * pow(gamma, -1, r)) % r

    ic1 = (lagrange[3] * beta) % r
    ic1 = (ic1 + lagrange[0]) % r
    ic1 = (ic1 * pow(gamma, -1, r)) % r

    return ic0, ic1


# BLS12-381 point helpers matching bellman's `pairing` crate serialization
def g1_mul(scalar: int):
    return multiply(G1, scalar % r)


def g2_mul(scalar: int):
    return multiply(G2, scalar % r)


def _enc_fq(x) -> bytes:
    return int(x).to_bytes(48, "big")


def enc_g1_compressed(p) -> bytes:
    if p is None:
        out = bytearray(48)
        out[0] |= 1 << 7
        out[0] |= 1 << 6
        return bytes(out)
    x, y = p
    out = bytearray(_enc_fq(x))
    out[0] |= 1 << 7
    neg_y = (q - int(y)) % q
    if int(y) > neg_y:
        out[0] |= 1 << 5
    return bytes(out)


def enc_g2_compressed(p) -> bytes:
    if p is None:
        out = bytearray(96)
        out[0] |= 1 << 7
        out[0] |= 1 << 6
        return bytes(out)
    x, y = p
    xc0, xc1 = x.coeffs
    yc0, yc1 = y.coeffs
    out = bytearray(_enc_fq(xc1) + _enc_fq(xc0))
    out[0] |= 1 << 7
    neg_yc0 = (q - int(yc0)) % q
    neg_yc1 = (q - int(yc1)) % q
    if (int(yc1), int(yc0)) > (neg_yc1, neg_yc0):
        out[0] |= 1 << 5
    return bytes(out)


def hexstr(b: bytes) -> str:
    return b.hex()


def dec_g1_uncompressed(data: bytes):
    assert len(data) == 96
    b0 = data[0]
    if b0 & (1 << 7):
        raise ValueError("compression bit set on uncompressed point")
    if b0 & (1 << 6):
        return None
    copy = bytearray(data)
    copy[0] &= 0x1F
    x = FQ(int.from_bytes(bytes(copy[0:48]), "big"))
    y = FQ(int.from_bytes(bytes(copy[48:96]), "big"))
    return (x, y)


def dec_g2_uncompressed(data: bytes):
    assert len(data) == 192
    b0 = data[0]
    if b0 & (1 << 7):
        raise ValueError("compression bit set on uncompressed point")
    if b0 & (1 << 6):
        return None
    copy = bytearray(data)
    copy[0] &= 0x1F
    xc1 = FQ(int.from_bytes(bytes(copy[0:48]), "big"))
    xc0 = FQ(int.from_bytes(bytes(copy[48:96]), "big"))
    yc1 = FQ(int.from_bytes(bytes(copy[96:144]), "big"))
    yc0 = FQ(int.from_bytes(bytes(copy[144:192]), "big"))
    return (FQ2([xc0, xc1]), FQ2([yc0, yc1]))


def sanity_check_against_vkbin(vk_path, alpha, beta, gamma, delta, g1s, g2s, ic0, ic1):
    try:
        data = open(vk_path, "rb").read()
    except OSError:
        print(f"[!] {vk_path} not found, skipping vk.bin sanity check")
        return
    off = 0

    def take(n):
        nonlocal off
        b = data[off : off + n]
        off += n
        return b

    alpha_g1 = dec_g1_uncompressed(take(96))
    beta_g1 = dec_g1_uncompressed(take(96))
    beta_g2 = dec_g2_uncompressed(take(192))
    gamma_g2 = dec_g2_uncompressed(take(192))
    delta_g1 = dec_g1_uncompressed(take(96))
    delta_g2 = dec_g2_uncompressed(take(192))
    ic_len = struct.unpack(">I", take(4))[0]
    ic_pts = [dec_g1_uncompressed(take(96)) for _ in range(ic_len)]

    ok = True
    ok &= g1_mul((alpha * g1s) % r) == alpha_g1
    ok &= g1_mul((beta * g1s) % r) == beta_g1
    ok &= g2_mul((beta * g2s) % r) == beta_g2
    ok &= g2_mul((gamma * g2s) % r) == gamma_g2
    ok &= g1_mul((delta * g1s) % r) == delta_g1
    ok &= g2_mul((delta * g2s) % r) == delta_g2
    ok &= len(ic_pts) == 2
    ok &= g1_mul((ic0 * g1s) % r) == ic_pts[0]
    ok &= g1_mul((ic1 * g1s) % r) == ic_pts[1]

    print(f"[+] vk.bin sanity check: {'PASS' if ok else 'FAIL'}")
    if not ok:
        print(
            "WARNING: derived toxic waste does not match vk.bin -- "
            "check TAU / CEREMONY_ID are correct for this instance!"
        )


def forge_proof(tau: int, claim: int, vk_path: str = None):
    alpha, beta, gamma, delta, g1s, g2s = derive(tau)
    ic0, ic1 = mint_ic_scalars(tau, alpha, beta, gamma)

    if vk_path:
        sanity_check_against_vkbin(
            vk_path, alpha, beta, gamma, delta, g1s, g2s, ic0, ic1
        )

    # Real CRS scalars (discrete logs w.r.t. G1 / G2 generators)
    ALPHA = (alpha * g1s) % r
    BETA_G2 = (beta * g2s) % r
    GAMMA_G2 = (gamma * g2s) % r
    DELTA_G1 = (delta * g1s) % r
    DELTA_G2 = (delta * g2s) % r
    IC0 = (ic0 * g1s) % r
    IC1 = (ic1 * g1s) % r

    acc_scalar = (IC0 + claim * IC1) % r

    # e(A,B) = e(alpha,beta) * e(acc,gamma) * e(C,delta)
    # Pick random a,b, solve for c:
    #   a*b = ALPHA*BETA_G2 + acc*GAMMA_G2 + c*DELTA_G2  (mod r)
    a = random.randrange(1, r)
    b = random.randrange(1, r)
    rhs_known = (ALPHA * BETA_G2 + acc_scalar * GAMMA_G2) % r
    c = ((a * b - rhs_known) * pow(DELTA_G2, -1, r)) % r

    A, B, C = g1_mul(a), g2_mul(b), g1_mul(c)

    # Local verification against the pairing equation before submitting.
    alpha_g1_pt = g1_mul(ALPHA)
    beta_g2_pt = g2_mul(BETA_G2)
    gamma_g2_pt = g2_mul(GAMMA_G2)
    delta_g2_pt = g2_mul(DELTA_G2)
    acc_pt = g1_mul(acc_scalar)

    lhs = final_exponentiate(pairing(B, A))
    rhs = final_exponentiate(
        pairing(beta_g2_pt, alpha_g1_pt)
        * pairing(gamma_g2_pt, acc_pt)
        * pairing(delta_g2_pt, C)
    )
    assert lhs == rhs, "forged proof failed local pairing check!"
    print("[+] Forged proof passes local pairing check.")

    proof_bytes = enc_g1_compressed(A) + enc_g2_compressed(B) + enc_g1_compressed(C)
    return proof_bytes


# Network submission
def submit(
    host: str, port: int, ceremony_id: str, proof_bytes: bytes, use_tls: bool = True
) -> bytes:
    # I was having a lot of issues connecting to their server but found the following worked
    # 1. connect
    # 2. TLS handshake (server_hostname=host, w/no verification)
    # 3. recv() once for the banner (just to display it and get it out of the way)
    # 4. sendall() the proof line
    # 5. recv() in a loop until the socket closes, return raw bytes
    # It then returns raw bytes (not decoded) so garbled output can be inspected directly.

    payload = f"{ceremony_id}:{hexstr(proof_bytes)}\n".encode()

    raw_sock = socket.create_connection((host, port), timeout=10)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(raw_sock, server_hostname=host)
    else:
        sock = raw_sock

    sock.settimeout(5)
    try:
        banner = sock.recv(4096)
        print(f"[+] Server banner ({len(banner)} bytes):")
        print(banner.decode(errors="replace"))
    except socket.timeout:
        print("[!] No banner within 5s")
        banner = b""

    sock.settimeout(10)
    sock.sendall(payload)

    chunks = []
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)

    sock.close()
    return b"".join(chunks)


def main():
    host, port = HOST, PORT
    if len(sys.argv) >= 2:
        host = sys.argv[1]
    if len(sys.argv) >= 3:
        port = int(sys.argv[2])

    vk_path = "vk.bin" if __name__ == "__main__" else None
    import os

    if not os.path.exists(vk_path):
        vk_path = None

    print(f"[+] Deriving toxic waste from TAU for ceremony {CEREMONY_ID} ...")
    proof_bytes = forge_proof(TAU, CLAIM, vk_path=vk_path)
    print(f"[+] Proof: {CEREMONY_ID}:{hexstr(proof_bytes)}")

    print(f"[+] Submitting to {host}:{port} (TLS) ...")
    try:
        resp = submit(host, port, CEREMONY_ID, proof_bytes, use_tls=True)
        print(f"[+] Server response ({len(resp)} bytes):")
        print("    hex:", resp.hex())
        print("    text:", resp.decode(errors="replace"))
    except (ConnectionRefusedError, OSError, ssl.SSLError) as e:
        print(f"[!] TLS attempt failed: {e}")
        print("[+] Retrying with plain TCP ...")
        try:
            resp = submit(host, port, CEREMONY_ID, proof_bytes, use_tls=False)
            print(f"[+] Server response ({len(resp)} bytes):")
            print("    hex:", resp.hex())
            print("    text:", resp.decode(errors="replace"))
        except (ConnectionRefusedError, OSError) as e2:
            print(f"[!] Could not connect to {host}:{port}: {e2}")
            print("    Edit HOST/PORT at the top of this script, or pass them as args:")
            print(f"    python3 {sys.argv[0]} <host> <port>")


if __name__ == "__main__":
    main()

