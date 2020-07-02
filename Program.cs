using System;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System.Reflection;
using Newtonsoft.Json;

namespace ASTTask
{
    class Program
    {
        static void Main(string[] args)
        {
            //Accessing Files under "Examples" directory
            try
            {
                string curDir=Directory.GetCurrentDirectory()+"\\Examples";
                string[] fileNames = Directory.GetFiles(curDir);
                fileNames = Directory.GetFiles(curDir).Where(obj=>obj.Contains("Scan")).ToArray();

                foreach(string fileName in fileNames)
                {
                    //Web.Config file
                    if(fileName.EndsWith(".xml",StringComparison.InvariantCultureIgnoreCase) || fileName.EndsWith(".xml",StringComparison.InvariantCultureIgnoreCase))
                    {
                        CookieFlagScanner.GetXMLMissingCookieStatements(fileName);
                    }
                    else
                    {
                        string programLines = File.ReadAllText(fileName);
                        //Forming syntax Tree
                        SyntaxNode syntaxNode= CSharpSyntaxTree.ParseText(programLines).GetRoot();

                        // Forming properties into AST object and printing them as JSON string
                        // ASTNode root = CreateSyntaxTree(syntaxNode);
                        // Console.WriteLine(JsonConvert.SerializeObject(root));

                        //Finding empty catch blocks & printing FileName, Line no, Vulnerable code
                        Console.WriteLine("Analysing {0}",fileName);
                        Console.WriteLine("---------------------------------------------------------");
                        List<SyntaxNodeOrToken> emptyCatchStatements = EmptyCatch.FindEmptyCatch(syntaxNode);
                        if(emptyCatchStatements !=null && emptyCatchStatements.Count>0)
                        {
                            foreach (var item in emptyCatchStatements)
                            {
                                Console.WriteLine("Line : "+GetLineNumber(item)+"\n "+item.ToFullString());
                            }
                        }
                        //finding hard-coded keys/passwords
                        Tuple<List<SyntaxNodeOrToken>,List<SyntaxTrivia>> hardcodeStatements = CredsFinder.FindHardcodeCredentials(syntaxNode);
                        if(hardcodeStatements !=null)
                        {
                            foreach (var item in hardcodeStatements.Item1)
                            {
                                if(item.Kind()==SyntaxKind.VariableDeclarator)
                                    Console.WriteLine("Line : " +GetLineNumber(item) + " : " + ((VariableDeclaratorSyntax)item).ToString());
                                else if(item.Kind()==SyntaxKind.StringLiteralExpression)
                                    Console.WriteLine("Line : " +GetLineNumber(item) + " : " + ((LiteralExpressionSyntax)item).ToString());
                            }
                            foreach (var item in hardcodeStatements.Item2)
                            {
                                    Console.WriteLine("Line : " +GetLineNumber(item) + " : " + item.ToString());
                            }
                        }

                        //Finding Missing secure cookie flags
                        List<SyntaxNode> inSecureCookies = CookieFlagScanner.GetMissingCookieStatements(fileName,syntaxNode);
                        if(inSecureCookies !=null)
                            foreach (var item in inSecureCookies)
                            {
                                Console.WriteLine("Line : " +GetLineNumber(item) + " : " + item.ToString());
                            }
                    }
                    Console.WriteLine("---------------------------------------------------------");
                    Console.WriteLine("Analysing completed.\n");
                }
            }
            catch (System.Exception ex)
            {
                Console.WriteLine(ex.Message +"\n"+ex.StackTrace);
            }
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
            {
                result.Add("NodeKind", node.Kind().ToString());
            }
            else if (syntax is SyntaxToken token)
            {
                result.Add("TokenKind", token.Kind().ToString());
            }
            PropertyInfo[] properties = syntax.GetType().GetProperties();
            foreach (PropertyInfo info in properties)
            {

                if (info.Name == "Language" || info.Name == "Parent" || info.Name == "ValueText"
                || info.Name == "Value" || info.Name == "SyntaxTree" || info.Name == "RawKind")
                {
                    continue;
                }
                result.Add(info.Name, info.GetValue(syntax)?.ToString());
            }
            return result;
        }
    }
}