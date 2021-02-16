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
