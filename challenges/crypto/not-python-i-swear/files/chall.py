#!/usr/bin/env python3

from ctypes import (
    CDLL, c_void_p, c_char_p, c_int, c_size_t, c_ubyte, c_ushort, c_ulonglong,
    POINTER, cast
)
from ctypes.util import find_library
import os, hashlib

FLAG = "CYB0X1{fake_flag_for_testing}"

# ----------------------------- typedefs/consts ------------------------------
u8   = c_ubyte
u16  = c_ushort
u64  = c_ulonglong
RTLD_NOW = 2

O_WRONLY = 1
O_CREAT  = 0o100
O_TRUNC  = 0o1000
MODE_0644 = 0o644

MASK64 = (1<<64)-1
sha256 = lambda b: hashlib.sha256(b).digest()
SALT   = b"notpythoniswear"  

# --------------------------------- libc/dl -----------------------------------
L = find_library("c")  or "libc.so.6"
D = find_library("dl") or "libdl.so.2"
libc  = CDLL(L)
libdl = CDLL(D)

libdl.dlopen.argtypes  = (c_char_p, c_int)
libdl.dlopen.restype   = c_void_p
_dl = libdl.dlopen(L.encode(), RTLD_NOW)

libc.malloc.argtypes   = (c_size_t,)
libc.malloc.restype    = c_void_p
libc.free.argtypes     = (c_void_p,)
libc.free.restype      = None
libc.memset.argtypes   = (c_void_p, c_int, c_size_t)
libc.memset.restype    = c_void_p
libc.memmove.argtypes  = (c_void_p, c_void_p, c_size_t)
libc.memmove.restype   = c_void_p

libc.open.argtypes     = (c_char_p, c_int, c_int)
libc.open.restype      = c_int
libc.write.argtypes    = (c_int, c_void_p, c_size_t)
libc.write.restype     = c_int
libc.close.argtypes    = (c_int,)
libc.close.restype     = c_int

# -------------------------------- helpers ------------------------------------
def xs64_star(seed: int):
    x = seed & MASK64
    mul = 0x2545F4914F6CDD1D
    while True:
        x ^= (x >> 12) & MASK64
        x ^= (x << 25) & MASK64
        x ^= (x >> 27) & MASK64
        yield (x * mul) & MASK64

def fisher_yates_perm(n: int, rnd):
    a = list(range(n))
    for i in range(n-1, 0, -1):
        j = next(rnd) % (i+1)
        a[i], a[j] = a[j], a[i]
    return a

def gcd(a,b):
    while b: a,b = b, a%b
    return a

def ensure_coprime_stride(n: int):
    raw = int.from_bytes(sha256(f"{n}|stride".encode()+SALT)[:2], "little")
    p = (raw % (n-1)) + 1
    while gcd(p, n) != 1:
        p = (p + 1) % n or 1
    return p

def derive_params(A: int, B: int, P: int, m: int):
    h  = sha256(f"{A}|{B}|{P}|{m}".encode()+SALT)
    r1 = xs64_star(int.from_bytes(h[0:8],  "little"))
    r2 = xs64_star(int.from_bytes(h[8:16], "little"))

    s_hi = fisher_yates_perm(16, r1)  
    s_lo = fisher_yates_perm(16, r2)  

    s_hi_arr    = (u8*16)(*s_hi)
    s_lo_arr    = (u8*16)(*s_lo)
    s_hi_inv    = (u8*16)(*([0]*16))
    s_lo_inv    = (u8*16)(*([0]*16))
    for i in range(16): s_hi_inv[s_hi[i]] = i
    for i in range(16): s_lo_inv[s_lo[i]] = i

    S0 = int.from_bytes(h[16:18], "little")  
    S  = max(1, (int.from_bytes(h[18:20], "little") % m))  

    kseed = int.from_bytes(h[24:32], "little") ^ ((A & 0xffffffff)<<32) ^ (B & 0xffffffff) ^ (P<<1)
    return s_hi_arr, s_lo_arr, s_hi_inv, s_lo_inv, S0, S, kseed

def lcg_fill_keystream(buf: c_void_p, m: int, a: int, c: int, s0: int):
    p = cast(buf, POINTER(u8))
    s = s0 & 0xFFFF
    a &= 0xFFFF; c &= 0xFFFF
    for i in range(m):
        s = (a*s + c) & 0xFFFF
        p[i] = ((s >> 8) ^ (s & 0xFF)) & 0xFF

def permute_stride_into(dst: c_void_p, src: c_void_p, m: int, pstride: int):
    d = cast(dst, POINTER(u8)); s = cast(src, POINTER(u8))
    for i in range(m):
        j = (i * pstride) % m
        d[j] = s[i]

def sub_nibbles_into(dst: c_void_p, src: c_void_p, m: int, s_hi, s_lo):
    d = cast(dst, POINTER(u8)); s = cast(src, POINTER(u8))
    for i in range(m):
        b = s[i]
        d[i] = (s_hi[b >> 4] << 4) | (s_lo[b & 0xF])

def xor_into(dst: c_void_p, a: c_void_p, b: c_void_p, m: int):
    d = cast(dst, POINTER(u8))
    x = cast(a,   POINTER(u8))
    y = cast(b,   POINTER(u8))
    for i in range(m):
        d[i] = x[i] ^ y[i]

def cptr_add(p, off: int) -> c_void_p:
    base = int(p) if not isinstance(p, int) else p
    return c_void_p(base + int(off))

def overlapped_slide_right(buf: c_void_p, m: int, s: int):
    s %= m
    if s == 0: return
    tmp = libc.malloc(s or 1)
    libc.memmove(tmp, cptr_add(buf, m - s), s)   
    libc.memmove(cptr_add(buf, s), buf, m - s)   
    libc.memmove(buf, tmp, s)                    
    libc.free(tmp)

def rk_schedule(kseed: int, rounds: int):
    arr = (u64 * rounds)()
    x = kseed & MASK64
    for r in range(rounds):
        x ^= (x << 13) & MASK64
        x ^= (x >> 7)  & MASK64
        x ^= (x << 17) & MASK64
        arr[r] = (x * 0x9E3779B97F4A7C15) & MASK64
    return arr

def F_func(x: int, k: int) -> int:
    x ^= k
    x ^= ((x << 13) & MASK64); x ^= (x >> 7); x ^= ((x << 17) & MASK64)
    return (x * 0xD1342543DE82EF95) & MASK64

def feistel128_inplace(buf: c_void_p, m: int, rks, rounds: int):
    assert m % 16 == 0
    p64 = cast(buf, POINTER(u64))
    words = m // 8
    for i in range(0, words, 2):
        L = int(p64[i]); R = int(p64[i+1])
        for r in range(rounds):
            f = F_func(R, int(rks[r]))
            L, R = R, (L ^ f) & MASK64
        p64[i]   = u64(L)
        p64[i+1] = u64(R)

# ----------------------------------- main ------------------------------------
def main():
    FLAGB = FLAG.encode()
    n    = len(FLAGB)
    pad  = (16 - (n % 16)) % 16
    m    = n + pad

    A = 0x5B*2 + 1   
    B = 0x2F     
    P = ensure_coprime_stride(m) 

    s_hi, s_lo, s_hi_inv, s_lo_inv, S0, S, KSEED = derive_params(A,B,P,m)
    ROUNDS = 6
    RKS    = rk_schedule(KSEED, ROUNDS)

    buf_plain = libc.malloc(m or 1)
    buf_perm  = libc.malloc(m or 1)
    buf_sub   = libc.malloc(m or 1)
    buf_ks    = libc.malloc(m or 1)
    buf_xor   = libc.malloc(m or 1)
    buf_ct    = libc.malloc(m or 1)

    try:
        src_py = (u8 * m)()
        for i in range(n): src_py[i] = FLAGB[i]
        libc.memmove(buf_plain, cast(src_py, c_void_p), m)

        permute_stride_into(buf_perm, buf_plain, m, P)

        sub_nibbles_into(buf_sub, buf_perm, m, s_hi, s_lo)

        lcg_fill_keystream(buf_ks, m, A, B, S0)
        xor_into(buf_xor, buf_sub, buf_ks, m)

        libc.memmove(buf_ct, buf_xor, m)
        overlapped_slide_right(buf_ct, m, S)
        
        feistel128_inplace(buf_ct, m, RKS, ROUNDS)

        ct = bytes(cast(buf_ct, POINTER(u8))[i] for i in range(m))
        tag = sha256(ct + b"|souvenir|")[:8]

        out = (
            f"len={n}\n"
            f"mlen={m}\n"
            f"pad={pad}\n"
            f"stationery={A},{B},{P}\n"
            f"slide={S}\n"
            f"rounds={ROUNDS}\n"
            f"c={ct.hex()}\n"
            f"tag={tag.hex()}\n"
        ).encode()

        path = b"./output.txt"
        fd = libc.open(path, O_WRONLY | O_CREAT | O_TRUNC, MODE_0644)
        if fd < 0:
            raise OSError("open() failed")
        try:
            buf = (u8 * len(out)).from_buffer_copy(out)
            if libc.write(fd, cast(buf, c_void_p), len(out)) < 0:
                raise OSError("write() failed")
        finally:
            libc.close(fd)

        print(f"Wrote output.txt with {len(out)} bytes of output.")

    finally:
        for p in [buf_plain, buf_perm, buf_sub, buf_ks, buf_xor, buf_ct]:
            libc.free(p)

if __name__ == "__main__":
    main()
