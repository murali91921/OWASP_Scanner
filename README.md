# Static Code Analysis
Usage:
SAST scanner will be used as follows
<br/>Create a SASTApp object and load files by calling LoadFiles method. If LoadFiles method return true, it creates required objects.
<br/>After LoadFiles method calling, by calling ScanAll method, it retrieves all vulnerbilies objects.
<br/>This Static code analysis support following vulnerabilities
<ol>
  <li>
    Hardcode Password
  </li>
  <li>
    Insecure Cookie Flag 
  </li>
  <li>
Open Redirect 
  </li>
  <li>
Empty TryBlock
  </li>
  <li>
Empty CatchBlock
  </li>
  <li>
Weak Password Configuration
  </li>
  <li>
Weak Hashing Configuration
  </li>
  <li>
Csrf 
  </li>
  <li>
Ldap Injection
  </li>
  <li>
Insecure Random Generation
  </li>
  <li>
Sql Injection
  </li>
  <li>
XPath Injections
  </li>
  <li>
XSS Injection
  </li>
  <li>
XXE Injection
  </li>
  <li>
    Forms Authentication: Weak Cookie Protection
  </li>
  <li>
  Cleartext Machine Key
  </li>
</ol>


How to Use:</br>
You can test applciation by following command</br>
`dotnet run -Path`</br>
Parameter `Path` should be valid path of folder or file.</br>
If you  want to filter for few types of vulnerabilities
goto `LoadFiles` method in `SAST.Engine.CSharp.Tests/Program.cs`, filter the `ScannerType` as you required</br>
```
vulnerabilities = vulnerabilities.Where(obj => obj.Type == Enums.ScannerType.WeakCipherMode);
```