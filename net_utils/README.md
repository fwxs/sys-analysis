# arp_spoofer.py
A pure python implementation of an ARP spoof attack.

## Usage
```
usage: arp_spoofer.py -i [interface] -t [targetIP] -s [spoofIP] [sourceIP]

ARP spoofer

positional arguments:
  source               Source IP address

optional arguments:
  -h, --help           show this help message and exit
  -i IFACE             Interface
  -t IP                Target IP
  -s IP                IP address to spoof (e.g Other host)
  --interval INTERVAL  Intervals of seconds at which to poison the target ARP
                       cache (Defaults 20).
```

## Output
```                       
[INFO] Changing IP forwarding status to 1
[*] Asking who-has  [ip 1]
[*] [ip 1] is-at aa:bb:cc:dd:ee:ff
[*] Asking who-has  [ip 2]
[*] [ip 2] is-at ff:ee:dd:cc:bb:aa
[!] Spoofing [ip 1] with 00:11:22:33:44:55->[ip 2]
[!] Spoofing [ip 2] with 00:11:22:55:44:55->[ip 1]
...snip...
[!] User requested exit.

[*] Restoring ARP.
[INFO] Changing IP forwarding status to 0
```

