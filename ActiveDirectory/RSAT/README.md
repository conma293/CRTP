backup for the Microsoft's ActiveDirectory PowerShell module from Server 2016 with RSAT and module installed. The DLL is usually found at this path: ```C:\Windows\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management.dll```

and the rest of the module files at this path: ```C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ActiveDirectory\```

* * * 

To be able to list all the cmdlets in the module, import the module as well. Remember to import the DLL first.


```
Import-Module C:\ActiveDirectory\RSAT\Microsoft.ActiveDirectory.Management.dll -Verbose
```

```
Import-Module C:\ActiveDirectory\RSAT\ActiveDirectory.psd1
```

```
Get-Command -Module ActiveDirectory
```


https://github.com/samratashok/ADModule
