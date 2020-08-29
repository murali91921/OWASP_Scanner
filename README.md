### Static Applcaition Security Testing  
#### Usage:
SAST scanner will be used as follows
<br/>Create a SASTApp object and load files by calling LoadFiles method. If LoadFiles method return true, it creates required objects.
<br/>After LoadFiles method calling, by calling ScanAll method, it retrieves all vulnerbilies objects.
<br/>This Static code analysis support following vulnerabilities
<ol>
  <li>Hardcode Password</li>
  <li>Insecure Cookie Flag</li>
  <li>Open Redirect</li>
  <li>Empty TryBlock</li>
  <li>Empty CatchBlock</li>
  <li>Weak Password Configuration</li>
  <li>Weak Hashing Configuration</li>
  <li>Csrf</li>
  <li>Ldap Injection</li>
  <li>Insecure Random Generation</li>
  <li>Sql Injection</li>
  <li>XPath Injection</li>
  <li>XSS Injection</li>
  <li>XXE Injection</li>
  <li>Forms Authentication: Weak Cookie Protection</li>
  <li>Cleartext Machine Key</li>
  <li>Weak Symmetric Algorithm</li>
  <li>Weak Cipher Mode</li>
</ol>

#### How to Use:</br>
You can test applciation by following command</br>
`dotnet run -Path`</br>
Parameter `Path` should be valid path of folder or file.</br>
You can run the scanners individually by calling `Scan` method with paramater of `Enums.ScannerType` or  
all sccanners by calling `ScanAll` method in `SASTApp` class.

#### Note:
Before running the project, You have to resolve the package references
##### Step 1:
`dotnet restore` on Library project
##### Step 2:
`dotnet run -"FilePath"` on Console project
