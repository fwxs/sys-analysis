# socket-origin
Get, socket level, information of the provided process id number.

This python script returns socket information of the TCP/IP origin of some process.
It makes use of a process ID number to find file descriptors that are sockets, 
then using the socket inode number it searches through the /proc/net/tcp, tcp6, or udp-related files 
to find the endpoint of the socket.

# dnsUtils.py
Makes A, MX, SRV, TXT, etc. queries to some domain.

# arp_spoofer.py
Executes an ARP spoofing attack on the specifed host and target to spoof. usually the target to spoof 
is the gateway and the target host it's, let's say, some other PC on your LAN.
