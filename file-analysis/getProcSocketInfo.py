#! /usr/bin/env python
import os
import sys


class FileSocket:
    """
    Parse TCP, UDP or RAW socket information about the provided PID file.
    """

    def __init__(self, pid):
        self.pid = pid
        self._ino = None
        self.check_fds()

    def _get_proc_name(self):
        """
          Get the process name of the provided PID.
          @return: The process name.
        """
        path = "/proc/{}/comm".format(self.pid)
        with open(path) as file:
            return file.readline().strip("\n")

    @staticmethod
    def _reverse(value, step=2):
        """
          Creates a list then reverses it.
          @param value: Value to be reversed
          @param step: loop steps. 2 Steps for ipv4, 4 steps for ipv6.
          :return: A reversed list.
        """
        data = [value[inx:inx + step] for inx in range(0, len(value), step)][::-1]
        return "".join(data)

    def _get_ip(self, raw_ip):
        """
          Use self._reverse() to return a readable IP address.
          @param raw_ip: The ip address to be reversed.
          :return: a readable IP.
        """
        ret_ip = None

        if len(raw_ip) == 8:
            ip = self._reverse(raw_ip)
            i = [int(ip[inx:inx + 2], base=16) for inx in range(0, 8, 2)]
            ret_ip = "{0[0]}.{0[1]}.{0[2]}.{0[3]}".format(i)

        elif len(raw_ip) == 32:
            ip = self._reverse(raw_ip, 4)
            i = [ip[inx:inx + 4] for inx in range(0, 32, 4)]
            ret_ip = "{0[0]}:{0[1]}:{0[2]}:{0[3]}:{0[4]}:{0[5]}:{0[6]}:{0[7]}".format(i)

        return ret_ip

    def _get_socket_info(self, path):
        """
          Parses the provided file, e.g '/proc/net/tcp',
          and returns information of the matched 'inode number'.
          @param path: The /proc/net/ file to parse.
          :return: Destination address, source address, socket status and uid.
        """
        sock_state = {0x01: "(Established)", 0x0A: "(Listen)"}
        with open(path) as file:

            for line in file.readlines():
                line_data = line.split()

                if self._ino == line_data[9]:
                    # Destination IP address and destination port number.
                    dst = self.get_ip_and_port(line_data[1])

                    # Source IP address and source port number.
                    src = self.get_ip_and_port(line_data[2])

                    # Socket is listening or has a established connection.
                    status = int(line_data[3], base=16)
                    status = sock_state[status] if status in sock_state.keys() else ""
                    uid = line_data[7]

                    return dst, src, status, uid
        return False

    def _set_inode_number(self, link_name):
        """
          'Get' and 'set' the inode number of the provided socket in the /proc/PID/fd directory.
          :return: socket inode number.
        """
        self._ino = link_name[8:len(link_name) - 1]

    def _parse(self, data, proto="TCP"):
        """
          Parses the provided UDP or TCP data.
          @param data: protocol data, i.e (destination IP:port, source IP:port, socket state and uid)
          @param proto: protocol type, e.g TCP or UDP.
          :return:
        """
        dest, src, state, uid = data
        print("\n[*] Process name: {0}\tPID: {1} \tUID: {2}\tInode: {3}".format(self._get_proc_name(),
                                                                                self.pid,
                                                                                uid,
                                                                                self._ino))
        print("\t[{0}] {1} {2:->10s}> {3} {4}".format(proto, src, "", dest, state))

    def get_ip_and_port(self, address):
        """
          Parses the /proc/net/[insert protocol] address and returns the ip address and port number.
          @param address: reversed address in the form REV_HEX:port
          :return: A readable address in the form HEX:port
        """
        # Split IP address and port number.
        raw_ip, raw_port = address.split(":")
        return "{}:{}".format(self._get_ip(raw_ip), int(raw_port, base=16))

    def get_tcp_type(self):
        """
        Get information of a TCP, TCP6 /proc/net/[proto] file.
        :return: TCP or TCP6 file data. None if it's not TCP.
        """
        retData = None
        socket_info = self._get_socket_info("/proc/net/tcp")

        if socket_info:
            retData = 4, socket_info
        else:
            socket_info = self._get_socket_info("/proc/net/tcp6")

            if socket_info:
                retData = 6, socket_info

        return retData

    def parse_tcp(self):
        """
          Parses /proc/net/[tcp or tcp6] file.
          :return: False if socket it's not TCP.
        """
        data = self.get_tcp_type()

        if data is None:
            return False
        elif data[0] == 4:
            self._parse(data[1])
        else:
            self._parse(data[1], "TCP6")

    def get_udp_type(self):
        """
          Get information of a UDP, UDP6, UDP-Lite or UDP6-Lite /proc/net/[proto] file.
          :return: UDP file data. None if it's not UDP.
        """
        retData = None
        socket_info = self._get_socket_info("/proc/net/udp")

        if socket_info:
            retData = 4, socket_info
        else:
            socket_info = self._get_socket_info("/proc/net/udp6")

            if socket_info:
                retData = 6, socket_info
            else:
                socket_info = self._get_socket_info("/proc/net/udplite")

                if socket_info:
                    retData = "4lite", socket_info
                else:
                    socket_info = self._get_socket_info("/proc/net/udplite6")

                    if socket_info:
                        retData = "6lite", socket_info

        return retData

    def parse_udp(self):
        """
          Parses /proc/net/[udp related] file.
          :return: False if socket it's not UDP.
        """
        data = self.get_udp_type()

        if data is None:
            return False
        elif data[0] == 4:
            self._parse(data[1], "UDP")
        elif data[0] == 6:
            self._parse(data[1], "UDP6")
        elif data[0] == "4lite":
            self._parse(data[1], "UDP-Lite")
        else:
            self._parse(data[1], "UDP6-Lite")

    def parser(self):
        """
          Prints socket information.
        """
        self.parse_tcp()
        self.parse_udp()

    def check_fds(self):
        """
          Get information about the process file descriptors and check
          if it's a socket
          :return: Nothing
        """
        path = "/proc/{}".format(self.pid)

        if not os.path.exists(path):
            print("Directory {} doesn't exists.".format(self.pid))
            sys.exit()

        path = "{}/fd/".format(path)

        for file in os.listdir(path):
            # FDs are kinda volatile.
            try:
                link_name = os.readlink("{0}{1}".format(path, file))
                if "socket" in link_name:
                    self._set_inode_number(link_name)
                    self.parser()

            except FileNotFoundError:
                continue

            except Exception as err:
                print(err.args, file=sys.stderr)
                sys.exit()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: {} [pid]".format(sys.argv[0]), file=sys.stderr)
        sys.exit(0)

    FileSocket(sys.argv[1])
