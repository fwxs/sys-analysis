#!/usr/bin/env python
import os
import sys
import time


__author__ = "pacmanator"
__email__ = "mrpacmanator@gmail.com"
__version__ = "v1.1"

"""
    Get information from a *nix user.

    Copyright (C) 2018 pacmanator

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""


class Password:
    def __init__(self, shadow_data):
        self.shadow_data = shadow_data
        self.CRYPT_TYPES = {"1": "MD5",
                            "2a": "Blowfish",
                            "5": "SHA-256",
                            "6": "SHA-512"}

        self.password_data()

    def password_data(self):
        """
            Prints more information about the 'shadow file' password field.
        """
        if (self.shadow_data == "!!") or (self.shadow_data == "x"):
            print("[!] No password set.")
        else:
            pass_data = self.shadow_data.split("$")
            print("\t[-] Encryption type: {0}".format(self.CRYPT_TYPES[pass_data[1]]))
            print("\t[-] Encrypted salt: {0}".format(pass_data[2]))
            print("\t[-] Encrypted password: {0}".format(pass_data[3]))


def usage():
    print("Usage: {0} [user]".format(sys.argv[0]), file=sys.stderr)
    sys.exit()


def get_shadow_date(date_change):
    """
        Turns the 'shadow' file date seconds to a ctime date.
        @param date_change: The date in seconds.
    """
    date = None
    if date_change != '':
        date = time.ctime((int(date_change) * 24) * 3600)
    
    return date


def get_user_shadow_info(username):
    """
        Prints information about the user shadow file.
        @param username: The name of the user.
    """

    with open("/etc/shadow") as shadow_file:
        # Iterate through all the registered users.
        for line in shadow_file.readlines():
            user_data = line.split(":")

            if user_data[0] == username:
                print("[+] Login name: {0}".format(username))
                
                if user_data[1] != '':
                    Password(user_data[1])
                else:
                    print("\t[!] User {0} doesn't have a password.".format(username))

                print("\t[-] Last password change: {0}".format(get_shadow_date(user_data[2])))
                print("\t[-] Minimum password age: {0}".format(get_shadow_date(user_data[3])))
                print("\t[-] Maximum password age: {0}".format(get_shadow_date(user_data[4])))
                print("\t[-] Password warning: {0} days".format(user_data[5]))

                if user_data[6] != "":
                    print("[-] Password inactivity: {0} days".format(user_data[6]))

                if user_data[7] != "":
                    print("[-] Account expiration date: {0}".format(user_data[7]))


def get_user_passwd_info(username):
    """
        Prints user information of the passwd file.
        @param username: The name of the user to retrieve information from.
    """
    with open("/etc/passwd") as passwd_file:
        # Iterate through all the registered users.
        for line in passwd_file.readlines():
            passwd_data = line.split(":")

            if passwd_data[0] == username:
                print("\n[+] Login name: {0} \t Home directory: {1}".format(username, passwd_data[5]))
                
                # If the second field of the user 'passwd' file has some value, then we have a problem.
                if passwd_data[1] != "x":
                    print("\033[1;31m\t[!] Warning: Vulnerable Linux system.\033[0;0m")
                    print("\t\tEncrypted password: {}".format(passwd_data[1]))

                print("\t[-] User ID: {0} {1:->5s}> Group ID: {2}".format(passwd_data[2], "", passwd_data[3]))

                if passwd_data[4] != "":
                    print("\t[-] Username or comment: {}".format(passwd_data[4]))

                print("\t[-] Shell: {}".format(passwd_data[6]))


def is_super_user():
    """
        Checks if the user is running with superuser privileges.
        return: False if is a non-system user, True if it's superuser.
    """
    if os.getuid() != 0:
        print("This script needs to be run as superuser.")
        print("Printing 'passwd' file information instead.")
        return False

    return True


if __name__ == '__main__':
    if len(sys.argv) != 2:
        usage()
        sys.exit()

    if is_super_user():
        get_user_shadow_info(sys.argv[1])

    get_user_passwd_info(sys.argv[1])
