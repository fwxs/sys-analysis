# file-analysis

This folder contains a set of tools to retrieve information from some **\*nix** files, like the _passwd_ file, 
the _shadow_ file, the file descriptors associated with some _PID_ and the memory map of a process.

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

# procMemMapper.py

Retrieve information of all the memory regions that a process has mapped.

## Usage

```
$ procMemMapper.py [pid]
[+] File: [Type of file]
  [-] Address space: 0xaabbccddeeff -------------> 0x001122334455
  [-] Permissions: [read, write, private (Copy on Write)]
  [-] File offset: 0x00112233
  [-] Device: sdxx OR Memory
  [-] Inode: dddddd OR BSS (uninitialized data)
```


# getProcSocketInfo.py

Return network information of a process.

## Usage

```
$ getProcSocketInfo.py [pid]

[*] Process name: xxxxxxx PID: dddd    UID: dddd   Inode: dddd
  [{(TCP6, TCP), (UDP6, UDP), (UDPLITE6, UDPLITE)}] <Source>:<Port> ----------> <Destination>:<Port> ({Established, Listenning})

```
