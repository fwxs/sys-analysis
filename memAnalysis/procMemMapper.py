#! /usr/bin/env python
import os
import re
import sys


def get_device(maj_min):
    """
    Get the device name, using the 'major' and 'minor' device number.
    :param maj_min: Major and minor device number.
    :return: Return the device name.
    """
    major, minor = maj_min.split(":")
    with open("/proc/diskstats") as diskFile:
        for row in diskFile.readlines():
            diskStats = row.split()
            # The maps file has the major and minor fields with a zero as preffix.
            if (diskStats[0] == major[1]) and (diskStats[1] == minor[1]):
                return diskStats[2]


def get_permissions(perm):
    """
    Gets an encoded version of the process permissions and returns a human readable version of them.
    :param perm: Process permissions.
    :return: A readable output of the process permissions.
    """
    l = list()
    permissions = {"r": "read ",
                   "w": "write ",
                   "x": "execute ",
                   "p": "private (Copy on write) "
                   }
    for char in perm:
        if char in permissions.keys():
            l.append(permissions[char])
        else:
            continue

    return "".join(l)


def get_address_space(address):
    """
    Gets the process address range.
    :param address: /proc/PID/maps address space.
    :return: The process address range.
    """
    a = address.split("-")
    return "\033[1;32m0x{0}\033[0;0m {1:->8}> \033[1;32m0x{2}\033[0;0m".format(a[0], "", a[1])


def get_inode(inode):
    """
    Returns the inode number of the file opened by the process.
    If it's 0, it's an uninitialized data.
    :param inode: inode number
    :return: File inode number or BSS.
    """
    return "BSS (uninitialized data)" if inode == "0" else "\033[0;34m{}\033[0;0m".format(inode)


def process_entries(data):
    """
    Parses the /proc/PID/maps file and returns information of the process memory map.
    :param data: Information to parse.
    """
    pseudo_path_regx = re.compile("\[([a-z]*)|:([0-9]*|[a-z]*)\]")
    device = "Memory"

    try:
        if len(data) == 6:
            if re.match(pseudo_path_regx, data[5]):
                print("[+] Pseudo-file: \033[1;36m{}\033[0;0m".format(data[5]))
            else:
                print("[+] File: \033[1;36m{}\033[0;0m".format(data[5]))
                device = get_device(data[3])
        elif len(data) == 5:
            print("[+] Anonymous mapping.")

        permissions = get_permissions(data[1])
        address = get_address_space(data[0])

        print("\t[-] Address space: {}".format(address))
        print("\t[-] Permissions: {}".format(permissions))

        if int(data[2], base=16) != 0:
            print("\t[-] File offset: \033[1;33m0x{}\033[0;0m".format(data[2]))

        print("\t[-] Device: {}".format(device))
        print("\t[-] Inode: {}\n".format(get_inode(data[4])))

    except BrokenPipeError:
        sys.exit()

    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit()

    except Exception as err:
        print("\033[1;31m{}\033[0;0m".format(err.args), file=sys.stderr)
        sys.exit()


def read_map_file(proc_map_file):
    """
    Prints information about the process maps file.
    :param proc_map_file: Path to the process maps file.
    :return:
    """
    with open(proc_map_file) as map_file:
        for row in map_file.readlines():
            data = row.split()
            process_entries(data)


if __name__ == '__main__':
    if (len(sys.argv) > 2) or (len(sys.argv) < 2):
        print("Usage: {} [pid]".format(sys.argv[0]))
        sys.exit(22)

    file = "/proc/{}/maps".format(sys.argv[1])

    if not os.path.exists(file):
        print("\033[1;31mError: {} it's not real!!\033[0;0m".format(file), file=sys.stderr)
        sys.exit(2)

    print("[*] Processing {} PID memory map...".format(sys.argv[1]))
    read_map_file(file)
