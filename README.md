# AMSI

Con el lanzamiento de Windows 10, Microsoft introdujo AMSI, una interfaz de programación de aplicaciones (API) que permite la detección de malware en una amplia variedad de lenguajes de programación, incluyendo PowerShell. AMSI actúa como un puente que conecta las aplicaciones con el software antivirus.

Si desean profundizar más en la teoría visitien https://learn.microsoft.com/es-es/windows/win32/amsi/how-amsi-helps.


![image](https://github.com/ivancabrera02/AMSI/assets/103500562/a84a620b-b4bf-40c3-adf0-87922d478b87)

### Que detecta AMSI?

* Control de cuentas de usuario o UAC (elevación de privilegios de archivos EXE, COM y MSI, o instalación de ActiveX)
* PowerShell (evaluación de los scripts, el uso interactivo y el código dinámico)
* Windows Script Host (wscript.exe y cscript.exe)
* JavaScript y VBScript
* Macros de VBA de Office

### Técnicas de evasión para Red Team

Por hacer una breve introducción pondré el típico ejemplo que no puede faltar como es el separar strings.

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/afc8d173-246c-4fab-9741-5288420747d7)

Podemos realizar lo mismo en base64. Ignorar el error de sintaxis :)

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/3758ebe8-95dd-48fe-bf8f-b3c4ae1a9991)

O utilizando XOR.

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/8a20cfca-0305-48cb-a8fe-c6e182c0909d)

Esto no está mal pero la idea es poder ejecutar scripts 'maliciosos' completos.

Una idea sería bajar la versión de powershell utilizando: powershell -version 2

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/68e79214-c511-4be0-ac7d-5cd657c546cc)

![image](https://github.com/ivancabrera02/AMSI/assets/103500562/020611a3-a014-4c93-b839-3d2c3cbb0726)

En la primera imagen se usa la versión 3 de powershell y como se puede apreciar se bloquea el script, en cambio en la segunda imagen usando una versión inferior se ejecuta sin problemas.



### Recursos

* https://amsi.fail/
* https://github.com/tokyoneon/Chimera
* https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
