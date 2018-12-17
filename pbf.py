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
# -s Source_IP
# -p Listening_Port
# -b Broadcast_IP [Broadcast_IP] [Broadcast_IP] [...]
# --loglevel number
LOG_NONE          = 0 # default -  no debug, pbf.py will start daemonized
LOG_LIFECYCLE     = 1 #         -  log start stop
LOG_SUCCESS       = 2 #         -  also log              successful forwards
LOG_FAIL          = 3 #         -  also log              ignored    forwards
LOG_TRACE         = 4 #         -  also log pkg trace of all        forwards
#
# --pidfile (file name): Wirites process ID to a file called "pidfile"
#########################################################################################################


import sys
import argparse as InputOptions
import itertools
import os
import struct
import socket
import thread
from threading import Thread
import resource

# Only to have a time stamp in the diagnose output
from datetime import datetime


def main():
	threads = []

	# if we don't increase this limit, then python will fail with
	# "Fatal Python error: Couldn't create autoTLSkey mapping"
	#
	# TODO: this should be handled differently. I think the issue here is that
	#       python wants to use 1G of stack *address space* per thread.
	#       So we should probably do RLIMIT_AS = n_threads * 1G
	#
	# see https://stackoverflow.com/questions/13398594/fatal-python-error-couldnt-create-autotlskey-mapping-with-cherrypy
	megs = 2000
	resource.setrlimit(resource.RLIMIT_AS, (megs * 1048576L, -1L))

	args = Options(InputOptions)
	
	log_level = args.loglevel

	if not log_level:
		daemonize(args.pidfile)

	for broadcastip in args.broadcastip:
		try:
			t = Thread(target=forwarder, args=(log_level, args, broadcastip))
			t.start()
			threads.append(t)
		except:
			dbg("STARTUP", "ERROR: could not start thread", log_level, LOG_NONE)

	for t in threads:
		t.join

def forwarder(log_level, args, broadcastip):
	if args.allowedsourceip is None:
			allowed_sourceip = None
	else:
			allowed_sourceip = struct.unpack("!4s", socket.inet_aton(args.allowedsourceip))[0]

	# Create sockets
	listener_socket = listening_socket(broadcastip, log_level)
	sender_socket = sending_socket(broadcastip, log_level)
	
	while True:
	# Extract Data from listening socket and send it to the sender socket
		data2send = pbf_recv(broadcastip, allowed_sourceip, listener_socket, args.port, log_level)
		
		if data2send is not None:
			pbf_send(broadcastip, args.port, data2send, sender_socket, log_level)


# output message only message of requested log level <= log level of message
#
def dbg(broadcastip, msg, log_level, msg_level):
	if log_level >= msg_level:
		print(("BCAST: %s: %s" % (broadcastip, msg)))


# the following functions create the sockets
def listening_socket(destination, log_level):

	listener_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
	listener_socket.bind((destination, 0))

	dbg(destination, 'Starting Listener at ' + str(datetime.now()), log_level, LOG_LIFECYCLE)

	return listener_socket

def sending_socket(broadcastip, log_level):
	sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
	sender_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)  # Enable Broadcast
	sender_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 1)  # Set TTL = 1

	dbg(broadcastip, ('Starting Sender at ' + str(datetime.now())) + '\n', log_level, LOG_LIFECYCLE)

	return sender_socket


# the following functions send data to the socket
def pbf_recv(broadcastip, allowed_sourceip, server, port, log_level):
	"""Extract data from the listening socket.
	   When allowed_sourceip is set, then
	   * 'data' will get returned if 'src_ip == allowed_sourceip' and 'port == dst_port'.
	   * 'None' will get returned if it doesn't match
	"""

	# incoming data
	data = server.recvfrom(65535)[0]

	# From the data packet, interpret the fist 28 Bytes as follows:
	# Version/IHL, ToS, Length, ID, Flags/Fragment, TTL, Proto, Checksum, Src IP, Dst IP, Src Port, Dst Port, Length, Checksum
	hdr = struct.unpack('!BBHHHBBH4s4sHHHH', data[:28])
	ttl = hdr[5]
	dst_port = hdr[11]

	
	if log_level >= LOG_TRACE:
	# Extract complete header information for log output		
		pkt_trace = extract_header(hdr)
		dbg(broadcastip, "Received Header Data: " + str(pkt_trace), log_level, LOG_TRACE)

	
	if (allowed_sourceip is not None) and (allowed_sourceip != hdr[8]):
		dbg(broadcastip, "-x-> Ignoring packet, source IP doesn't match given '-s' parameter\n", log_level, LOG_FAIL)
		return None
	elif dst_port != port:
		dbg(broadcastip, "-x-> Ignoring packet, Destination Port doesn't match given '-p' parameter\n", log_level, LOG_FAIL)
		return None
	elif ttl <= 1:
		dbg(broadcastip, "-x-> Ignoring packet, TTL <= 1\n", log_level, LOG_FAIL)
		return None
	else:
		return data

def pbf_send(broadcastip, port, data, sender_socket, log_level):
# Send data to the sender socket

	sender_socket.sendto(data, (broadcastip, port))

	dbg(broadcastip, "---> Packet successfully sent \n", log_level, LOG_SUCCESS)


# other functions
def Options(InputOptions):
# Options Parser

	parser = InputOptions.ArgumentParser(description='Take Inputs')
	parser.add_argument("-s", "--allowedsourceip", type=str, required=False,
						help="source IP address to listen for")
	parser.add_argument("-b", "--broadcastip", type=str, required=True, nargs="+",
						help="broadcast IP address to listen for")
	parser.add_argument("-p", "--port", type=int, required=True,
						help="UDP port to listen for (numeric)")
	parser.add_argument("-l", "--loglevel", type=int, required=False, default=0,
						help="set log level. 0 let's pbf start as daemon. Look into the header of pbf.py for log level descriptions")
	parser.add_argument("--pidfile", type=str, required=False,
						help=("write PID to FILE"), metavar="FILE")

	parser.set_defaults(pidfile=None)
	options = parser.parse_args()
	
	if options.port < 1 or options.port > 65535:
		print("No valid Port. Please set port in the valid port range.")
		exit()

	if options.loglevel:
		print("\n" + str(options))
	
	return options


def daemonize(pidFileName):
# Creates a child process and terminates the parent process

	if pidFileName:
	# If option set, create file to write process ID in it later
		pidFile = open(pidFileName, "w")

	pid = os.fork()

	if pid == 0: # If child process: Remove rights
		os.setsid()
		os.chdir("/")
		for fd in (0, 1, 2):
			os.close(fd)
		if pidFileName:
			pidFile.close()

	else: # If parent process: Terminate process
		if pidFileName:
			pidFile.write("%d\n" % pid)
			pidFile.close()
		# Parent process exits immediately.
		sys.exit(0)


def extract_header(hdr):
# splits the header into more parts for debugging
	src_ip = socket.inet_ntoa(hdr[8])
	dst_ip = socket.inet_ntoa(hdr[9])

	# Header data: 0 - vers/IHL
	#              1 - ToS
	#              2 - len
	#              3 - ID
	#              4 - flags/fragment
	#              5 - TTL
	#              6 - proto
	#              7 - checksum
	#              8 - src IP
	#              9 - dst IP
	#             10 - src port
	#             11 - dst port

	header_fields = ("ToS: %d, ID: %d, flags/frag: %d, TTL: %d, src: %s, dst: %s, dport: %d\n" %
	                 (hdr[1] , hdr[3], hdr[4]        , hdr[5] , src_ip , dst_ip , hdr[11]))

	return(header_fields)

		
if __name__ == "__main__":
	main()
