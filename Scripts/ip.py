
import socket
import struct
import sys

def print_block(ip):
	n_ip = socket.inet_aton(ip)
	n_n = struct.unpack('!I', n_ip)[0]
	print str(n_n) # + "/" + str(prefix)


#print_block("74.125.0.0", 1)
print_block(sys.argv[1])
