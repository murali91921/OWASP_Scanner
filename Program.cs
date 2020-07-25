using System;
using System.IO;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using System.Collections.Generic;
using System.Reflection;
using System.Linq;
using Microsoft.CodeAnalysis.Text;
using ASTTask;
using System.Threading;

namespace ASTTask
{
    // Extension method to print Line number and character
    public static class LinePositionExtension
    {
        public static string ToLineString(this LinePosition lineposition) => (lineposition.Line + 1) + ","
       + (lineposition.Character + 1);
    }
    class Program
    {
        static IEnumerable<string> GetExamples()
        {
            string exampleDirectory = Path.Combine(Directory.GetCurrentDirectory(),"Examples");
            //string exampleDirectory = Path.Combine(Directory.GetParent(".").Parent.Parent.ToString(), "Examples");
            IEnumerable<string> fileNames = Directory.EnumerateFiles(exampleDirectory, "*", SearchOption.TopDirectoryOnly)
                .Where(obj=>obj.EndsWith(".txt",StringComparison.OrdinalIgnoreCase)
                || obj.EndsWith(".config", StringComparison.OrdinalIgnoreCase)
                || obj.EndsWith(".cs", StringComparison.OrdinalIgnoreCase));
            fileNames = fileNames.Where(obj => obj.Contains("Ldap")).ToArray();
            return fileNames;
        }
        static void Scanner(ScannerType scannerType)
        {
            Thread thread = new Thread(() =>
            {
                //Accessing Files under "Examples" directory
                try
                {
                    IEnumerable<string> fileNames = GetExamples();

                    foreach (string filePath in fileNames)
                    {
                        //Console.WriteLine("Analysing "+ filePath);
                        if (filePath.EndsWith(".config", StringComparison.OrdinalIgnoreCase))
                        {
                            if (scannerType == ScannerType.InsecureCookie)
                            {
                                string print = CookieFlagScanner.GetXMLMissingCookieStatements(filePath);
                                if (!string.IsNullOrEmpty(print))
                                    Console.WriteLine(print);
                            }
                        }
                        else
                        {
                            string programLines = File.ReadAllText(filePath);
                            SyntaxNode rootNode = CSharpSyntaxTree.ParseText(programLines).GetRoot();
                            List<SyntaxNode> vulnerabilities = null;

                            //Finding empty catch blocks & printing FileName, Line no, Vulnerable code

                            if (scannerType == ScannerType.EmptyCatch)
                            {
                                EmptyCatch emptyCatch = new EmptyCatch();
                                vulnerabilities = emptyCatch.FindEmptyCatch(rootNode);
                                PrintNodes(filePath, vulnerabilities);
                            }
                            else if (scannerType == ScannerType.EmptyTry)
                            {
                                EmptyTryScanner emptyTryScanner = new EmptyTryScanner();
                                vulnerabilities = emptyTryScanner.FindEmptyTryStatements(rootNode);
                                PrintNodes(filePath, vulnerabilities);                            }
                            else if (scannerType == ScannerType.HardcodePassword)
                            {
                                CredsFinder credsFinder = new CredsFinder();
                                Tuple<List<SyntaxNode>, List<SyntaxTrivia>> hardcodeStatements = credsFinder.FindHardcodeCredentials(filePath,rootNode);
                                if (hardcodeStatements != null)
                                {
                                    //Syntax Nodes for hardcode statements
                                    PrintNodes(filePath, hardcodeStatements.Item1);
                                    //Syntax Trivias for hardcode comments
                                    PrintNodes(filePath, hardcodeStatements.Item2);
                                }
                            }
                            else if (scannerType == ScannerType.WeakPasswordConfig)
                            {
                                WeakPasswordValidator weakPasswordValidator = new WeakPasswordValidator();
                                vulnerabilities = weakPasswordValidator.FindWeakPasswords(filePath,rootNode);
                                PrintNodes(filePath, vulnerabilities);
                            }
                            else if (scannerType == ScannerType.InsecureCookie)
                            {
                                List<ASTCookie> inSecureCookies = CookieFlagScanner.GetMissingCookieStatements(filePath, rootNode);
                                if (inSecureCookies != null)
                                    PrintNodes(filePath, inSecureCookies);
                            }
                            else if (scannerType == ScannerType.OpenRedirect)
                            {
                                OpenRedirect openRedirect = new OpenRedirect();
                                vulnerabilities = openRedirect.FindOpenRedirect(filePath, rootNode);
                                PrintNodes(filePath, vulnerabilities);
                            }
                            else if (scannerType == ScannerType.WeakHashingConfig)
                            {
                                rootNode = CSharpSyntaxTree.ParseText(programLines).GetRoot();
                                WeakHashingValidator weakHashingValidator = new WeakHashingValidator();
                                vulnerabilities = weakHashingValidator.FindWeakHashing(filePath,rootNode);
                                PrintNodes(filePath, vulnerabilities);
                            }
                            else if (scannerType == ScannerType.Csrf)
                            {
                                rootNode = CSharpSyntaxTree.ParseText(programLines).GetRoot();
                                CsrfScanner csrfScanner = new CsrfScanner();
                                vulnerabilities = csrfScanner.FindCsrfVulnerabilities(filePath,rootNode);
                                PrintNodes(filePath, vulnerabilities);
                            }
                            else if (scannerType == ScannerType.Ldap)
                            {
                                rootNode = CSharpSyntaxTree.ParseText(programLines).GetRoot();
                                LDAPScanner ldapScanner = new LDAPScanner();
                                vulnerabilities = ldapScanner.FindLDAPVulnerabilities(filePath,rootNode);
                                PrintNodes(filePath, vulnerabilities);
                            }
                        }
                    }
                }
                catch (System.Exception ex)
                {
                    Console.WriteLine(ex.Message + "\n" + ex.StackTrace);
                }
            });
            thread.Start();
            thread.Join();
        }
        public enum ScannerType
        {
            HardcodePassword = 1,
            InsecureCookie = 2,
            OpenRedirect = 3,
            EmptyTry = 4,
            EmptyCatch = 5,
            WeakPasswordConfig = 6,
            WeakHashingConfig = 7,
            Csrf = 8,
            Ldap = 9,
            None = 0,
            Invalid = -1
        }
        static void Main(string[] args)
        {
            // Rename.Do();
            // return;
            while (true)
            {
                Console.WriteLine("\nPlease choose type of scanner");
                Console.WriteLine("1.Hard coded keys/password scanner");
                Console.WriteLine("2.Insecure cookie flag scanner");
                Console.WriteLine("3.OpenRedirect query scanner");
                Console.WriteLine("4.Empty try block scanner");
                Console.WriteLine("5.Empty catch block scanner");
                Console.WriteLine("6.Weak password configuration scanner");
                Console.WriteLine("7.Weak hashing configuration scanner");
                Console.WriteLine("8.Csrf scanner");
                Console.WriteLine("9.Ldap scanner");
                Console.WriteLine("0.Exit ");
                Console.WriteLine("Your option : ");
                string input = Console.ReadLine();
                //string input = "8";
                ScannerType scanner = ScannerType.Invalid;
                try
                {
                    scanner = (ScannerType)Enum.Parse(typeof(ScannerType), input);
                }
                catch
                {
                }
                // int.TryParse(input,out option);
                try
                {
                    switch (scanner)
                    {
                        case ScannerType.HardcodePassword:
                        case ScannerType.InsecureCookie:
                        case ScannerType.OpenRedirect:
                        case ScannerType.EmptyTry:
                        case ScannerType.EmptyCatch:
                        case ScannerType.WeakPasswordConfig:
                        case ScannerType.WeakHashingConfig:
                        case ScannerType.Csrf:
                        case ScannerType.Ldap:
                            Scanner(scanner);
                            break;
                        case ScannerType.None:
                            throw new InvalidOperationException();
                        default:
                            Console.WriteLine("Invalid option");
                            break;
                    }
                }
                catch
                {
                    break;
                }
            }
        }
        private static void PrintNodes(string filePath, List<SyntaxNode> syntaxNodeList)
        {
            if(syntaxNodeList != null && filePath != null)
                foreach (var item in syntaxNodeList)
                    Console.WriteLine(filePath + " (" + GetLineNumber(item) + ") : " + item.ToString());
        }

        private static void PrintNodes(string filePath, List<SyntaxTrivia> syntaxTriviaList)
        {
            if(syntaxTriviaList != null && filePath != null)
                foreach (var item in syntaxTriviaList)
                    Console.WriteLine(filePath + " (" + GetLineNumber(item) + ") : " + item.ToString());
        }

        private static void PrintNodes(string filePath, List<ASTCookie> aSTCookieList)
        {
            foreach (var item in aSTCookieList)
            {
                string missing = "";
                if (!item.IsHttpOnly)
                    missing = "HttpOnly";
                if (!item.IsSecure)
                    missing = string.IsNullOrEmpty(missing) ? "Secure" : (missing + ", Secure");
                missing += " Flag(s) missing ";
                Console.WriteLine(filePath + " : (" + GetLineNumber(item.CookieStatement) + ") : " + missing + "\n" + item.CookieStatement.ToString());
            }
        }
        private static string GetLineNumber(SyntaxNodeOrToken item) => item.SyntaxTree.GetLineSpan(item.FullSpan).StartLinePosition.ToLineString();
        private static string GetLineNumber(SyntaxTrivia item) => item.SyntaxTree.GetLineSpan(item.FullSpan).StartLinePosition.ToLineString();
        private static ASTNode CreateSyntaxTree(SyntaxNodeOrToken nodeOrToken)
        {
            var root = new ASTNode(GetSyntaxNodeOrTokenInfo(nodeOrToken));
            foreach (SyntaxNodeOrToken child in nodeOrToken.ChildNodesAndTokens())
            {
                root.AddChild(CreateSyntaxTree(child));
            }
            return root;
        }
        private static IDictionary<string, string> GetSyntaxNodeOrTokenInfo(SyntaxNodeOrToken nodeOrToken)
        {
            return nodeOrToken.IsNode
                ? GetSyntaxInfo(nodeOrToken.AsNode())
                : GetSyntaxInfo(nodeOrToken.AsToken());
        }
        private static IDictionary<string, string> GetSyntaxInfo<T>(T syntax)
        {
            var result = new Dictionary<string, string>();
            if (syntax is SyntaxNode node)
                result.Add("NodeKind", node.Kind().ToString());
            else if (syntax is SyntaxToken token)
                result.Add("TokenKind", token.Kind().ToString());
            PropertyInfo[] properties = syntax.GetType().GetProperties();
            foreach (PropertyInfo info in properties)
            {
                if (info.Name == "Language" || info.Name == "Parent" || info.Name == "ValueText"
                || info.Name == "Value" || info.Name == "SyntaxTree" || info.Name == "RawKind")
                    continue;
                result.Add(info.Name, info.GetValue(syntax)?.ToString());
            }
            return result;
        }
    }
}