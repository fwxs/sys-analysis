#! /usr/bin/env python
import os
import sys
import time


def get_fd_info(fd):
    """
    Prints information about the specified process file descriptor.
    :param fd: file descriptor path.
    """
    fd_stat = os.stat(fd)

    # Time info
    last_access = time.ctime(fd_stat.st_atime)
    mod_time = time.ctime(fd_stat.st_mtime)
    creation_time = time.ctime(fd_stat.st_ctime)

    # User and group info
    uid = fd_stat.st_uid
    gid = fd_stat.st_gid

    # Link name
    name = os.readlink(fd)

    try:
        print("[*] Link name: {}".format(name))
        print("\t[+] Inode number: {}".format(fd_stat.st_ino))

        if not ((last_access == 0) or (mod_time == 0) or (creation_time == 0)):
            print("\t[-] Link created on {:>33}".format(creation_time))
            print("\t[-] Last time accessed {:>30}".format(last_access))
            print("\t[-] Last time modified {:>30}".format(mod_time))

        print("\t[-] UID: {0}\t\tGID: {1}".format(uid, gid), end="\n\n")
    except BrokenPipeError:
        sys.exit()

    except Exception as err:
        print(err.args, file=sys.stderr)
        sys.exit()


def fd_crawler(pathname):
    """
    Lists the /proc/PID/fd directory.
    :param pathname: Directory pathname.
    """
    for link_file in os.listdir(pathname):
        full_path = "{0}/{1}".format(pathname, link_file)
        get_fd_info(full_path)


if __name__ == '__main__':
    if (len(sys.argv) > 2) or (len(sys.argv) < 2):
        print("Usage: {} [pid]".format(sys.argv[0]))
        sys.exit(22)

    path = "/proc/{}/fd".format(sys.argv[1])

    if not os.path.exists(path):
        print("You know {} it's not real...".format(path))
        sys.exit(2)

    fd_crawler(path)
