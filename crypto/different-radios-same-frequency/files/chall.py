#!/usr/bin/env python3

import os, struct, random
from Crypto.Cipher import AES

FLAG = "CYB0X1{fake_flag_for_testing}"
FLAGB = FLAG.encode()

def ecb(k,b): return AES.new(k,AES.MODE_ECB).encrypt(b)

def ctr_bytes(k,n,data,ctr0=0):
    out,ctr=bytearray(),ctr0
    for off in range(0,len(data),16):
        ks=ecb(k,n+struct.pack(">Q",ctr))
        frag=data[off:off+16]
        out+=bytes(f^ks[i] for i,f in enumerate(frag))
        ctr+=1
    return bytes(out)

def shuffle_blocks(data,seed):
    random.seed(seed)
    blocks=[data[i:i+16] for i in range(0,len(data),16)]
    idx=list(range(len(blocks)))
    random.shuffle(idx)
    shuffled=b"".join(blocks[i] for i in idx)
    return shuffled,idx

def main():
    key=os.urandom(32); nonce=os.urandom(8)
    known=b"[JINGLE] Welcome back listeners, stay tuned!\n"*128

    flagA=FLAGB[:len(FLAGB)//2]
    flagB=FLAGB[len(FLAGB)//2:]
    secret1=b"DROP1:"+flagA+b":\n"
    secret2=b"DROP2:"+flagB+b":\n"

    c1=ctr_bytes(key,nonce,known,ctr0=5)
    c2=ctr_bytes(key,nonce,secret1+os.urandom(64),ctr0=5)
    c3=ctr_bytes(key,nonce,secret2+os.urandom(64),ctr0=5)

    s2,idx2=shuffle_blocks(c2,1337)
    s3,idx3=shuffle_blocks(c3,4242)

    with open("dump.txt","w") as f:
        for i in range(0,len(c1),16):
            f.write(f"{i:08x}: {c1[i:i+16].hex()}\n")
        s2_hex = s2.hex()
        for i in range(0, len(s2_hex), 43):
            f.write(s2_hex[i:i+43] + "\n")
        s3_hex = s3.hex()
        for i in range(0, len(s3_hex), 43):
            f.write(s3_hex[i:i+43] + "\n")
        f.write(nonce.hex())

if __name__=="__main__":
    main()
