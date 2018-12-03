#!/usr/bin/env python2
#
# Python Broadcast Forwarder
#
# Copyright 2018 Reto Haeberli
#
# Based on the script pbh created by Dale Sedivec, Copyright 2006,
# retrieved from:
# * http://darkness.codefu.org/wordpress/2006/02/udp-directed-broadcast-helper/
# * http://www.codefu.org/people/darkness/pbh-0.2.tar.gz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA
#
#########################################################################################################
#
# Generates a listener and forwards the packet. The following input options are available:
# -p Listening Port
# -b Broadcast IP
# --debug Enable Debugging Mode (optional)
#########################################################################################################

import sys
import argparse as InputOptions
import itertools
import os

import struct
import socket
import select

# Only to have a time stamp in the diagnose output
from datetime import datetime

def main():	
	args = Options(InputOptions)
	
	if not args.debug:
		daemonize(args.pidfile)

	# Create Listening socket
	server_address=(args.broadcastip,args.port)
	listener_socket = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.IPPROTO_UDP)
	listener_socket.bind(server_address)

	if args.debug:
		print('Starting Listener at ', datetime.now())

	# Create Sender socket
	sender_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
	sender_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)  # Enables Broadcast
	sender_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)  # Sets TTL = 1
	
	while True:
		(data2send,ttl)=listener(args.broadcastip,args.port,args.debug,listener_socket)
		
		sender(args.broadcastip,args.port,data2send,args.debug,sender_socket,ttl)


def listener(broadcastip,port,debug,server):
# Define Listening socket and extract the data from it

	server_address=(broadcastip,port)

	# Listener waits for incoming packet and saves the content as "data".
	data = server.recvfrom(65535)[0]

	header = struct.unpack('!BBHHHBBH4s4s', data[:20])
	ttl = header[5]
	
	if debug:
		print("Header data: ", header)
		print ("Protocol: ", header[6])
		print ("TTL: ", header[5])
	
	return (data,ttl)

def sender(broadcastip,port,data,debug,sender_socket,ttl):
# Define Sender socket and send data to it

	if ttl > 1:

		# Send data to the socket
		client_address=(broadcastip,port)
		sender_socket.sendto(data,client_address)
	
		if debug:
			print ("Packet successfully sent! \n")

	else:
		print("Replay Packet drop")


def Options(InputOptions):
# Options Parser

	parser = InputOptions.ArgumentParser(description='Take Inputs')
	parser.add_argument("-b", "--broadcastip", type=str, required=True,
						help="broadcast IP address to listen for")
	parser.add_argument("-p", "--port", type=int, required=True,
						help="UDP port to listen for (numeric)")
	parser.add_argument("--debug",
						help=("enable debugging mode"),
						action="store_const", const=True)
	parser.add_argument("--pidfile", type=str,
                        help=("write PID to FILE"), metavar="FILE")
	
	parser.set_defaults(pidfile=None)
	options = parser.parse_args()
	
	if options.port < 1 or options.port > 65535:
		print("No valid Port. Please set port in the valid port range.")
		exit()

	if options.debug:
		print(options)
	
	return options

def daemonize(pidFileName):
    if pidFileName:
        pidFile = open(pidFileName, "w")
    pid = os.fork()
    if pid == 0:
        os.setsid()
        os.chdir("/")
        for fd in (0, 1, 2):
            os.close(fd)
        if pidFileName:
            pidFile.close()
    else:
        if pidFileName:
            pidFile.write("%d\n" % (pid,))
            pidFile.close()
        # Parent process exits immediately.
        sys.exit(0)
		
if __name__ == "__main__":
    main()
