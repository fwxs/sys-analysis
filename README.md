# sys-analysis
A set of tools to parse some Linux system files.

The sys-analysis package is a set of python scripts designed to gather information of a live Linux OS, 
like the origin of an internet socket related to a proces, as well as information of the file descriptors opened by a process or
information of the process memory maps file.

Other modules that this package contains, are related to parse the passwd or shadow files, 
a dns query tool and, recently, a basic implementation of an arp_spoofer in pure python.

# file-analysis
This folder contains a set of tools to retrieve information from some **\*nix** files, like the _passwd_ file, the _shadow_ file, the file descriptors associated with some _PID_ and the memory map of a process.
