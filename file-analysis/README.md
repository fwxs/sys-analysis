# file-analysis

This folder contains a set of tools to retrieve information from some **\*nix** files, like the _passwd_ file, 
the _shadow_ file and the file descriptors associated with some _PID_.

# fdInfo.py

Retrieve information from the file descriptors associated with a process identification (**PID**).

## Usage

Print the dates if their values are greater than zero.

```
$ fdInfo.py <pid>

[*] Link name: xxxxxxxxx
  [+] Inode number: dddddd
  
  [-] Link created on             Date
  [-] Last time accessed          Date
  [-] Last time modified          Date
  
  [-] UID: XXXX    GID: XXXX
```

**OR**

```
$ fdInfo.py <pid>

[*] Link name: xxxxxxxxxxx
  [+] Inode number: xxxxxxxx
  
  [-] UID: XXXX    GID: XXXX
```

# getUserInfo.py

Retrieve information from a **\*nix** user, reading the _passwd_ or the _shadow_ file, based on their privileges.

## Usage

Running with **root** privileges.

```
# getUserInfo.py [user]
[+] Login name: xxxx
  [-] Encryption type: any of {"MD5", "Blowfish", "SHA-256", "SHA-512"}
  [-] Encrypted salt: xxxxxxxxxxx
  [-] Encrypted password: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  [-] Last password change: MM/DD/YYYY
  [-] Minimum password age: MM/DD/YYYY
  [-] Maximum password age: MM/DD/YYYY

  [+] Login name: xxxx    Home directory: xxxxxxx
    [-] User ID: dddd -----> Group ID: dddd
    [-] Shell: xxxxxxxxxx
```

Running **without** privileges.

```
$ getUserInfo.py [user]
  [+] Login name: xxxx    Home directory: xxxxxxx
    [-] User ID: dddd -----> Group ID: dddd
    [-] Shell: xxxxxxxxxx
```
