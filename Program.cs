using System;
using System.IO;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using System.Collections.Generic;
using System.Reflection;

namespace ASTTask
{
    class Program
    {
        // static void GetOS()
        // {
        //     if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        //     {
        //         Path.Combine(Directory.GetCurrentDirectory(),"Examples");
        //     }
        // }
        static void Main(string[] args)
        {
            //Accessing Files under "Examples" directory
            try
            {
                string exampleDirectory /*= Directory.GetCurrentDirectory()+"\\Examples";
                exampleDirectory */= Path.Combine(Directory.GetCurrentDirectory(),"Examples");
                string[] fileNames = Directory.GetFiles(exampleDirectory);
                //fileNames = Directory.GetFiles(curDir).Where(obj=>obj.Contains("Redirect3")).ToArray();

                foreach(string filePath in fileNames)
                {
                    Console.WriteLine("Analysing {0}",filePath);
                    // Console.WriteLine("---------------------------------------------------------------------------------------------------");
                    //Web.Config file
                    if(filePath.EndsWith(".config",StringComparison.InvariantCultureIgnoreCase))
                    {
                        Console.WriteLine("--------------------- Cookie flag scanning started ---------------------");
                        string print = CookieFlagScanner.GetXMLMissingCookieStatements(filePath);
                        if(!string.IsNullOrEmpty(print))
                            Console.WriteLine(print);
                    }
                    else
                    {
                        string programLines = File.ReadAllText(filePath);
                        SyntaxNode rootNode= CSharpSyntaxTree.ParseText(programLines).GetRoot();
                        List<SyntaxNode> vulnerabilities = null;

                        //Finding empty catch blocks & printing FileName, Line no, Vulnerable code
                        Console.WriteLine("--------------------- Empty catch block scanning started ---------------------\n");
                        EmptyCatch emptyCatch = new EmptyCatch();
                        vulnerabilities = emptyCatch.FindEmptyCatch(rootNode);
                        PrintNodes(vulnerabilities);

                        //finding hard-coded keys/passwords
                        Console.WriteLine("--------------------- Hard-coded credentials scanning started ---------------------\n");
                        Tuple<List<SyntaxNode>,List<SyntaxTrivia>> hardcodeStatements = CredsFinder.FindHardcodeCredentials(filePath,rootNode);
                        if(hardcodeStatements !=null)
                        {
                            //SyntaxNodes for hardcode statements
                            PrintNodes(hardcodeStatements.Item1);
                            //SyntaxTrivias for hardcode comments
                            PrintNodes(hardcodeStatements.Item2);
                        }

                        //Finding Missing secure cookie flags
                        Console.WriteLine("--------------------- Cookie flag scanning started ---------------------\n");
                        List<ASTCookie> inSecureCookies = CookieFlagScanner.GetMissingCookieStatements(filePath,rootNode);
                        if(inSecureCookies !=null)
                            foreach (var item in inSecureCookies)
                            {
                                string missing = "";
                                if(!item.IsHttpOnly)
                                    missing = "HttpOnly";
                                if(!item.IsSecure)
                                    missing = string.IsNullOrEmpty(missing)?"Secure": (missing+", Secure");
                                missing += " Flag(s) missing ";
                                Console.WriteLine(missing +"\nLine : " + GetLineNumber(item.CookieStatement) + " : " + item.CookieStatement.ToString()+"\n");
                            }

                        //Finding OpenRedirect Vulnerabilities
                        Console.WriteLine("--------------------- Open Redirect scanning started ---------------------\n");
                        OpenRedirect openRedirect = new OpenRedirect();
                        vulnerabilities = openRedirect.FindOpenRedirect(filePath,rootNode);
                        PrintNodes(vulnerabilities);

                        //Finding WeakPassword Vulnerabilities
                        Console.WriteLine("--------------------- Weak Password scanning started ---------------------\n");
                        WeakPasswordValidator weakPasswordValidator  = new WeakPasswordValidator();
                        vulnerabilities  = weakPasswordValidator.FindWeakPasswords(filePath,rootNode);
                        PrintNodes(vulnerabilities);

                        //Finding Empty try block Vulnerabilities
                        Console.WriteLine("--------------------- Empty Try block scanning started ---------------------\n");
                        EmptyTryScanner emptyTryScanner  = new EmptyTryScanner();
                        var emptyTryStatements  = emptyTryScanner.FindEmptyTryStatements(rootNode);
                        PrintNodes(emptyTryStatements);
                    }
                    // Console.WriteLine("---------------------------------------------------------------------------------------------------");
                    Console.WriteLine("Analysing completed.\n");
                }
            }
            catch (System.Exception ex)
            {
                Console.WriteLine(ex.Message +"\n"+ex.StackTrace);
            }
        }
        private static void PrintNodes(List<SyntaxNode> syntaxNodeList)
        {
            if(syntaxNodeList != null)
                foreach (var item in syntaxNodeList)
                    Console.WriteLine("Line : " +GetLineNumber(item) + " : " + item.ToString());
        }

        private static void PrintNodes(List<SyntaxTrivia> syntaxTriviaList)
        {
            if(syntaxTriviaList != null)
                foreach (var item in syntaxTriviaList)
                    Console.WriteLine("Line : " +GetLineNumber(item) + " : " + item.ToString());
        }
        private static int GetLineNumber(SyntaxNodeOrToken item)=>item.SyntaxTree.GetLineSpan(item.FullSpan).StartLinePosition.Line + 1;
        private static int GetLineNumber(SyntaxTrivia item)=>item.SyntaxTree.GetLineSpan(item.FullSpan).StartLinePosition.Line + 1;
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