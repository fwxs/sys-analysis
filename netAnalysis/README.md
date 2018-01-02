# socket-origin
Get, socket level, information of the provided process id number.

This python script returns socket information of the TCP/IP origin of some process.
It makes use of a process ID number to find file descriptors that are sockets, 
then using the socket inode number it searches through the /proc/net/tcp, tcp6, or udp-related files 
to find the endpoint of the socket.

# Version 1.0
Returns TCP or UDP information about the provided socket.


# dnsUtils.py
Retrieves information about a provided domain.

# Version 1.0
Currently, only retrieves domain information.
