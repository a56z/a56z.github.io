---
layout: post
title: "Null Sessions"
permalink: /ctf1/
tags: windows null sessions
date: 2021-02-17 12:11:00 +0100
categories: tool
---

## Null Sessions

##### What are Null Sessions?

A null session attack exploits an authentication vulnerability for Windows Administrative Shares; this lets an attacker connect to a local or remote share without authentication.
Null sessions are remotely exploitable; this means that attackers can use their computers to attack a vulnerable Windows machine. Moreover, this attack can be used to call remote APIs and remote procedure calls. Because of these factors, null session attacks had a huge impact on Windows ecosystems.Nowadays Windows is configured to be immune from this kind of attack. However, legacy hosts can still be vulnerable!
<br/>
##### What is it used for?

Null session attacks can be used to enumerate a lot of information. Attackers can steal information about:
  
• Passwords
• System users
• System groups
• Running system processes
<br/>

Enumerating shares is the first step needed to exploit a Windows machine vulnerable to null sessions
In Windows, the most common command to use when enumerating Windows shares is nbtstat. 
Nbtstat is a Windows command line tool that can display information about a target.

<details> 
  <summary> <b>Nbtstat</b> </summary>

You can check how to use it by passing it the /? parameter:
<br/>
<img src="/assets/images/pts_labs/null_sessions/1.png" height="100%" width="100%">

The most common use of nbtstat is ```bash nbtstat –A <IP> ``` that displays information about a target.
<br/>
<img src="/assets/images/pts_labs/null_sessions/2.png" height="40%" width="40%">
<br/>

Let's analyze the command output.

The first line of the table tells us that the name of the machine running at 10.130.40.80 is   "ELS-WINXP".
The record type <00> tells us that ELS-WINXP is a workstation.
The type "UNIQUE" tells us that this computer must have only one IP address assigned.

This line contains the workgroup or the domain the computer is joined to:
<br/>
<img src="/assets/images/pts_labs/null_sessions/3.png" height="60%" width="60%">
<br/>
And this is the most interesting line of the table! The type <20> records tell us that the file sharing service is up and running on the machine; this means we can try to get some more information about it.
<br/>
<img src="/assets/images/pts_labs/null_sessions/4.png" height="60%" width="60%">
</details>
<br/>

Once an attacker knows that a machine has the File Server service running, they can enumerate the shares by using the NET VIEW command.  

<details> 
  <summary> <b>NET VIEW</b> </summary>


You can use the command by typing:

```bash
> NET VIEW <target IP>
```

We can use it on the previous target: (the type <20> tells us that file sharing is up and running: see nbtstat -A <IP> )
<br/>
<img src="/assets/images/pts_labs/null_sessions/5.png" height="70%" width="70%">
<br/>
This machine is sharing a directory; the share name is eLS.
Another directory on the share is WIA_RIS_SHARE.
<br/>
<img src="/assets/images/pts_labs/null_sessions/6netview.png" height="50%" width="50%">
</details>
<br/>

You can also perform shares enumeration from a Linux machine. You need to use the tools provided by the Samba suite. Samba tools are already installed in Kali Linux, but you can install them in nearly every Linux distribution.
<details> 
  <summary> <b>Nmblookup</b> </summary>
  

To perform the same operations of nbtstat, you can use nmblookup with the same command line switch:

```bash
# nmblookup –A <target ip address>
```
<br/>

As usual, you can check how nmblookup works by using the manual or the brief help:

```bash
# nmblookup --help
```

Here are the results we get from running nmblookupon the same target machine. We get the same results:
<br/>
<img src="/assets/images/pts_labs/null_sessions/7nmblookup.png" height="70%" width="70%">
</details>
<br/>

The Samba suite also provides smbclient, an FTP-like client to access Windows shares; this tool can, among other things, enumerate the shares provided by a host:
<details> 
  <summary> <b>Smbclient</b> </summary>
<br/>
<img src="/assets/images/pts_labs/null_sessions/8smbclient.png" height="70%" width="70%">
<br/>
The previous command line uses the following options:
• -L allows you to look at what services are available on a target
• With //<IP Address> you have to prepend two slashes to the target IP address
• -N forces the tool to not ask for a password.

Smbclient can not only detect the very same shares detected by NET VIEW...
<br/>
<img src="/assets/images/pts_labs/null_sessions/9smbclient.png" height="70%" width="70%">
<br/>

...but it also displays administrative shares that are hidden when using Windows standard tools.
<br/>
<img src="/assets/images/pts_labs/null_sessions/10smbclient.png" height="70%" width="70%">
</details>
<br/>

Once we have detected that the File and Printer Sharing service is active and we have enumerated the available shares on a target, it is time to check if a null session attack is possible. To verify that, we will exploit the IPC$ administrative share by trying to connect to it without valid credentials.
<details> 
  <summary> <b>Checking for Null Sessions</b> </summary>

To verify that, we will exploit the IPC$ administrative share by trying to connect to it without valid credentials.

To connect, you have to type the following command in a Windows shell:

```bash
> NET USE \\<target IP address>\IPC$ '' /u:''
```

This tells Windows to connect to the IPC$ share by using an empty password and an empty username!

Let's try the command on our target:

<br/>
<img src="/assets/images/pts_labs/null_sessions/checking11.png" height="50%" width="50%">
<br/>


The previous command establishes a connection to the IPC$ administrative share without specifying a user; this is possible because our target host is vulnerable to null session attacks. This test only works with the IPC$. For example, it does not work with C$:
  
Example:
<br/>
<img src="/assets/images/pts_labs/null_sessions/checking12.png" height="60%" width="60%">
<br/>
You can also perform the very same checks by using smbclient:
<br/>
<img src="/assets/images/pts_labs/null_sessions/checking13.png" height="70%" width="70%">
</details>
<br/>



Exploiting null sessions can be done by using the Windows NET command, but there are some tools which can automate this task.

Null sessions are a piece of the history of Windows hacking. Even if by default they are not enabled on modern Microsoft operating systems, you can sometimes find them on enterprise networks; this is because of retro compatibility with legacy systems and applications.


<details> 
  <summary> <b>Exploiting Null Sessions with Enum (Windows)</b> </summary>

**_Enum_** is a command line utility that can retrieve information from a system vulnerable to null session attacks. You can install it just by extracting it and running it from the Windows command prompt.

The -S parameter lets you enumerate the shares of a machine:

<br/>
<img src="/assets/images/pts_labs/null_sessions/14enum.png" height="70%" width="70%">
<br/>

Note that it enumerates administrative shares too.

-U enumerates the users:
<br/>
<img src="/assets/images/pts_labs/null_sessions/15enum.png" height="70%" width="70%">
<br/>
This machine has five user accounts.

If you need to mount a network authentication attack, you can check the password policy by using the  -P parameter:
<br/>
<img src="/assets/images/pts_labs/null_sessions/16enum.png" height="70%" width="70%">
<br/>


Checking password policies before running an authentication attack lets you fine-tune an attack tool to:

• Prevent accounts locking
• Prevent false positives
• Choose your dictionary or your bruteforcer configuration

Example:
Knowing the minimum and maximum length of a password helps you save time while bruteforcing a password.
</details>
<br/>

<details> 
  <summary> <b>Nmap</b> </summary>

<details> 
  <summary> <b>Winfo (Windows)</b> </summary>
Winfo is another command line utility you can use to automate null session exploitation. To use it, you just need to specify the target IP address and use the -n command line switch to tell the tool to use null sessions.

```bash
> winfo 10.130.40.80 -n
```
</details>
<br/>

<details> 
  <summary> <b>Enum4linux</b> </summary>
A penetration tester can also exploit null sessions by using enum4linux, a PERL script that can perform the same operations of enum and Winfo. 

It has the same command line options of the original enum tool; moreover, it supplies some other features.

By default, it performs:

• User enumeration
• Share enumeration
• Group and member enumeration
• Password policy extraction
• OS information detection
• A nmblookup run
• Printer information extraction

You can check its options by just calling > enum4linux on the command line.

Example:
```bash
> nmap -sS -p 135,139,445 192.168.102.0-255
```
-->192.168.102.151 has all 3 ports open

```bash
> enum4linux -n 192.168.102.151
```  
→ the <20> flag means the user has open shares

To test this agains null session checking for password policy:

```bash
> enum4linux -P 192.168.102.151
```
-S to enumerate remote machines:

```bash
> enum4linux -S 192.168.102.151
```

to brute force directories:

```bash
> enum4linux -s /usr/share/enum4linux/share-list.txt 192.168.102.151
```

run all commands in a single promt:

```bash
> enum4linux -a 192.168.102.151
```

</details>
<br/>


<details> 
  <summary> <b>Workflow Example</b> </summary>

<H4> 1. Find a Target in the Network</H4>

Verify the remote network:

```bash
$ ifconfig
```

Discover alive hosts on target network:

```bash
$ nmap -sn 192.168.99.0/24
```


<H4> 2. Check for Null Session</H4>

```bash
$ enum4linux -n 192.168.99.162
```

→ watch out for an active File Server Service and that the string <20> appears in the list.


<H4> 3. Exploit Null Session</H4>

Gather information

```bash
$ enum4linux -a 192.168.99.162
```

Use Smbclient to navigate the target machine.

```bash
$ smbclient -L DOMAIN -I 192.168.99.162 -N -U “”

[...]

 smb: \> ls 
 smb: \> exit
```
</details>
<br/>
