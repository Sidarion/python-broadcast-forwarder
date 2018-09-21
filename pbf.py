#!/usr/bin/env python2
#
# Python Broadcast Forwarder for Linux
#
# Copyright 2018 Reto Haeberli, based on the script pbh created by Dale Sedivec, Copyright 2006
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
# -d Listening IP
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
	
	while True:
		data2send=listener(args.destination,args.port,args.debug)
		
		sender(args.destination,args.port,data2send,args.debug)


def listener(destination,port,debug):
# Define Listening socket and extract the data from it

	server_address=(destination,port)

	if debug:
		print('Starting Listener at ', datetime.now())
	
	# Create Listening socket
	server = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	server.bind(server_address)

	# Listener waits for incoming packet. The "client" denotes the sender of the incoming packet and is not used anywhere (yet).
	#data, client = server.recvfrom(65535)
	data = server.recvfrom(65535)[0]
	
	return data

def sender(destination,port,data,debug):
# Define Sender socket and send data to it

	if debug:
		print("Received Data: ", data)
	
	# Create Sender socket
	sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)

	# Send data to the socket
	client_address=(destination,port)
	sender.sendto(data,client_address)
	
	if debug:
		print ("Packet successfully sent! \n")

def Options(InputOptions):
# Options Parser

	parser = InputOptions.ArgumentParser(description='Take Inputs')
	parser.add_argument("-d", "--destination", type=str, required=True,
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
