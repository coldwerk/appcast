"""Ed25519 signing and verification in pure Python, for NoteScope's signed price file (CWVidSync R440, R443).

Adapted from the reference implementation in RFC 8032, "Edwards-Curve Digital Signature Algorithm (EdDSA)", section 6
(https://www.rfc-editor.org/rfc/rfc8032#section-6). Code components of RFCs are licensed under the Simplified BSD
License (IETF Trust Legal Provisions, section 4.e). This is not constant-time code: it is used here only to sign a
public price file on the owner's machine and to verify that file in the app, never to protect a secret over a network.

Command line (used by the price-repository kit):
  python ed25519.py public  < seed-hex          -> prints the public key (hex)
  python ed25519.py sign FILE < seed-hex        -> prints the signature of FILE's bytes (hex)
  python ed25519.py verify FILE PUBHEX SIGHEX   -> prints OK or BAD, exit 0 or 1
The 32-byte seed is read from standard input as 64 hex characters, never from the command line.
"""
import hashlib
import sys

p = 2 ** 255 - 19
q = 2 ** 252 + 27742317777372353535851937790883648493


def _sha512(s: bytes) -> bytes:
    return hashlib.sha512(s).digest()


def _sha512_modq(s: bytes) -> int:
    return int.from_bytes(_sha512(s), "little") % q


def _inv(x: int) -> int:
    return pow(x, p - 2, p)


d = -121665 * _inv(121666) % p
_SQRT_M1 = pow(2, (p - 1) // 4, p)


def _add(P, Q):
    A, B = (P[1] - P[0]) * (Q[1] - Q[0]) % p, (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F, G * H, F * G, E * H)


def _mul(s: int, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _equal(P, Q) -> bool:
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def _recover_x(y: int, sign: int):
    if y >= p:
        return None
    x2 = (y * y - 1) * _inv(d * y * y + 1)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * _SQRT_M1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_GY = 4 * _inv(5) % p
_GX = _recover_x(_GY, 0)
_G = (_GX, _GY, 1, _GX * _GY % p)


def _compress(P) -> bytes:
    zinv = _inv(P[2])
    x, y = P[0] * zinv % p, P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % p)


def _expand(seed: bytes):
    if len(seed) != 32:
        raise ValueError("the seed must be 32 bytes")
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _compress(_mul(a, _G))


def sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _expand(seed)
    A = _compress(_mul(a, _G))
    r = _sha512_modq(prefix + msg)
    Rs = _compress(_mul(r, _G))
    h = _sha512_modq(Rs + A + msg)
    s = (r + h * a) % q
    return Rs + int.to_bytes(s, 32, "little")


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _decompress(public)
    if not A:
        return False
    Rs = signature[:32]
    R = _decompress(Rs)
    if not R:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= q:
        return False
    h = _sha512_modq(Rs + public + msg)
    return _equal(_mul(s, _G), _add(R, _mul(h, A)))


def _seed_from_stdin() -> bytes:
    raw = sys.stdin.read().strip()
    seed = bytes.fromhex(raw)
    if len(seed) != 32:
        raise SystemExit("ERROR: the seed on standard input must be 64 hex characters")
    return seed


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["public"] and len(a) == 1:
        print(public_key(_seed_from_stdin()).hex())
    elif a[:1] == ["sign"] and len(a) == 2:
        print(sign(_seed_from_stdin(), open(a[1], "rb").read()).hex())
    elif a[:1] == ["verify"] and len(a) == 4:
        ok = verify(bytes.fromhex(a[2]), open(a[1], "rb").read(), bytes.fromhex(a[3]))
        print("OK" if ok else "BAD")
        sys.exit(0 if ok else 1)
    else:
        raise SystemExit(__doc__)
