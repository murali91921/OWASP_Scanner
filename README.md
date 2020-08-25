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
</ol>


How to Use:</br>
You can test the scanner by following command</br>
`dotnet run -Path`</br>
Parameter `Path` should be valid path of folder or file.</br>
If you  want to test for few types of vulnerabilities
goto `SAST.Engine.CSharp/Core/SASTApp.cs`, comment the code as you required</br>
```
private IScanner Scan(ScannerType scannerType)
        {
            return scannerType switch
            {
                //ScannerType.Csrf => new CsrfScanner(),
                //ScannerType.EmptyCatch => new EmptyCatchScanner(),
                //ScannerType.EmptyTry => new EmptyTryScanner(),
                //ScannerType.HardcodePassword => new CredsFinder(),
                //ScannerType.InsecureCookie => new CookieFlagScanner(),
                //ScannerType.InsecureRandom => new InsecureRandomScanner(),
                //ScannerType.Ldap => new LDAPScanner(),
                //ScannerType.OpenRedirect => new OpenRedirectScanner(),
                //ScannerType.SqlInjection => new SqlInjectionScanner(),
                //ScannerType.WeakHashingConfig => new WeakHashingValidator(),
                //ScannerType.WeakPasswordConfig => new WeakPasswordValidator(),
                //ScannerType.XPath => new XPathScanner(),
                //ScannerType.XSS => new XssScanner(),
                ScannerType.XXE => new XxeScanner(),
                _ => null,
            };
        }```
