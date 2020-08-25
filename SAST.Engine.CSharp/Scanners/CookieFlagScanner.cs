using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using System.Collections.Generic;
using System.Linq;
using System;
using System.IO;
using System.Xml;
using System.Xml.XPath;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Models;
using System.IO.Enumeration;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace SAST.Engine.CSharp.Scanners
{
    public class CookieFlagScanner : IScanner, IConfigScanner
    {
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath)
        {
            bool isSecure = false, isHttpOnly = false;
            string returnStatement = string.Empty;
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            XPathDocument doc = new XPathDocument(filePath);
            XPathNavigator element = doc.CreateNavigator().SelectSingleNode("configuration/system.web/httpCookies");
            if (element != null)
            {
                returnStatement = filePath + " : (" + ((IXmlLineInfo)element != null ? ((IXmlLineInfo)element).LineNumber : 0)
                + "," + ((IXmlLineInfo)element != null ? ((IXmlLineInfo)element).LinePosition : 0) + ") : {0}\n"
                + element.OuterXml.Trim();
                // element.MoveToNext();
                if (element.HasAttributes)
                {
                    element.MoveToFirstAttribute();
                    do
                    {
                        if (element.Name.Equals("httpOnlyCookies", StringComparison.InvariantCultureIgnoreCase))
                            isHttpOnly = bool.Parse(element.Value);
                        else if (element.Name.Equals("requireSSL", StringComparison.InvariantCultureIgnoreCase))
                            isSecure = bool.Parse(element.Value);
                    }
                    while (element.MoveToNextAttribute());
                }
                if (!isHttpOnly || !isSecure)
                {
                    string missing = "";
                    if (!isHttpOnly)
                        missing = "HttpOnly";
                    if (!isSecure)
                        missing = string.IsNullOrEmpty(missing) ? "Secure" : (missing + ", Secure");
                    missing += " Flag(s) missing ";
                    returnStatement = string.Format(returnStatement, missing);
                    var vulnerability = new VulnerabilityDetail()
                    {
                        FilePath = filePath,
                        CodeSnippet = element.OuterXml.Trim(),
                        LineNumber = (IXmlLineInfo)element != null ? ((IXmlLineInfo)element).LineNumber.ToString() + "," + ((IXmlLineInfo)element).LinePosition.ToString() : string.Empty,
                        Type = ScannerType.InsecureCookie,
                        Description = missing
                    };
                    vulnerabilities = new List<VulnerabilityDetail>() { vulnerability };
                }
            }
            return vulnerabilities;
        }
        private bool PropertyMatch(ExpressionSyntax expression, string propertyName)
        {
            bool propertyValue = false;
            if (expression.Kind() == SyntaxKind.SimpleAssignmentExpression)
            {
                var assignment = expression as AssignmentExpressionSyntax;
                if (assignment.Left is MemberAccessExpressionSyntax &&
                    (assignment.Left as MemberAccessExpressionSyntax).Name.ToString() == propertyName &&
                    assignment.Right.IsKind(SyntaxKind.TrueLiteralExpression))
                    propertyValue = true;
                else if (assignment.Left.ToString() == propertyName && assignment.Right.IsKind(SyntaxKind.TrueLiteralExpression))
                    propertyValue = true;
            }
            return propertyValue;
        }
        private Tuple<HashSet<SyntaxNode>, bool, bool> FindResponseStatements(SyntaxNode root, SemanticModel model)
        {
            bool isSecure = false;
            bool isHttpOnly = false;
            HashSet<SyntaxNode> allCookieNodes = new HashSet<SyntaxNode>();
            HashSet<SyntaxNode> InSecurenodes = new HashSet<SyntaxNode>();
            HashSet<ISymbol> respSYmbols = new HashSet<ISymbol>();
            //var compilation = project.GetCompilationAsync().Result;
            var assignmentExpr = root.DescendantNodes().Where(obj => obj.IsKind(SyntaxKind.SimpleAssignmentExpression)).Cast<AssignmentExpressionSyntax>();
            foreach (var assignment in assignmentExpr)
            {
                // var assignment = expr.Expression as AssignmentExpressionSyntax;
                //Console.WriteLine(assignment.Left);
                if (assignment.Left.IsKind(SyntaxKind.SimpleMemberAccessExpression))
                {
                    if ((assignment.Left as MemberAccessExpressionSyntax).Expression is IdentifierNameSyntax)
                        continue;
                    ISymbol symbol = model.GetSymbolInfo(assignment.Left).Symbol;
                    if (symbol != null && symbol.ToString().StartsWith("System.Web.HttpCookie."))
                    {
                        allCookieNodes.Add(assignment);
                        if (symbol.ToString() == "System.Web.HttpCookie.Secure")
                        {
                            isSecure = assignment.Right.Kind() == SyntaxKind.TrueLiteralExpression;
                            if (!isSecure)
                                InSecurenodes.Add(assignment);
                        }
                        else if (symbol.ToString() == "System.Web.HttpCookie.HttpOnly")
                        {
                            isHttpOnly = assignment.Right.Kind() == SyntaxKind.TrueLiteralExpression;
                            if (!isHttpOnly)
                                InSecurenodes.Add(assignment);
                        }
                    }
                }
                // foreach (var usage in assignment.ChildNodes())
                // {
                // ISymbol symbol = model.GetSymbolInfo(usage).Symbol;
                // ISymbol parentSymbol = model.GetSymbolInfo(usage.Parent).Symbol;
                // if(symbol!=null  && parentSymbol!=null
                //     &&/* symbol.ToString()==baseResponseFullName && */parentSymbol.ToString()=="System.Web.HttpResponse.Cookies")
                //     {
                //         var loop = usage;
                //         while(loop.IsKind(SyntaxKind.ExpressionStatement))
                //         {
                //             loop = loop.Parent;
                //             Console.WriteLine("Element Accessed {0} {1}",usage.Parent.Parent.Parent,usage.Parent.Parent.Kind());
                //         }
                //         Console.WriteLine("{0} {1} {2}",usage,usage.Parent,usage.Parent.Kind());
                //     }
                // }
            }
            // If no secure/Httponly assignment statements found, display all response assignment statements as vulnerable
            if ((!isSecure || !isHttpOnly) && InSecurenodes.Count == 0)
                InSecurenodes = new HashSet<SyntaxNode>(allCookieNodes);
            return new Tuple<HashSet<SyntaxNode>, bool, bool>(InSecurenodes, isSecure, isHttpOnly);
        }
        //public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string fileName, SemanticModel model, AdhocWorkspace workspace)
        //{
        //    Compilation compilation = workspace.CurrentSolution.Projects.First().GetCompilationAsync().Result;
        //    var abc = compilation.GetTypeByMetadataName("System.Web.HttpCookie");
        //    throw new ArgumentException();
        //}

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model, Solution solution = null)
        {
            //Compilation compilation = solution.Projects.First().GetCompilationAsync().Result;
            //var abc = compilation.GetTypeByMetadataName("System.Web.HttpCookie");

            //Variable Declaraions;
            List<SASTCookie> pendingCookieStatements = new List<SASTCookie>();
            List<SASTCookie> missingCookieStatements = new List<SASTCookie>();

            ////Adhoc Workspace creation
            //var workspace = new AdhocWorkspace();
            //var solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Create());
            //var project = workspace.AddProject("CookieFlagScanner", "C#");
            //project = project.AddMetadataReference(MetadataReference.CreateFromFile(filePath));
            //project = project.AddMetadataReferences(Utils.LoadMetadata(root));
            //workspace.TryApplyChanges(project.Solution);
            //var document = workspace.AddDocument(project.Id, "CookieFlagScanner", SourceText.From(root.ToString()));
            //var model = document.GetSemanticModelAsync().Result;
            //root = document.GetSyntaxRootAsync().Result;

            // Values are modifying in Response Object itself.
            foreach (var method in syntaxNode.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                Tuple<HashSet<SyntaxNode>, bool, bool> respStatements = FindResponseStatements(method, model);
                if (respStatements != null && !respStatements.Item2 && !respStatements.Item2 && respStatements.Item1.Count > 0)
                {
                    // Console.WriteLine("Secure flag unset {0}",respStatements.Item2);
                    // Console.WriteLine("HttpOnly flag unset {0}",respStatements.Item3);
                    foreach (var item in respStatements.Item1)
                    {
                        // Console.WriteLine("---- {0}",item.ToString());
                        missingCookieStatements.Add(new SASTCookie
                        {
                            CookieStatement = item,
                            IsSecure = respStatements.Item2,
                            IsHttpOnly = respStatements.Item3
                        });
                    }
                }
            }

            //Finding all declarations which are not having ObjectCreations and making them as pending statements
            var variableDecl = syntaxNode.DescendantNodes().OfType<VariableDeclarationSyntax>();
            foreach (var item in variableDecl)
            {
                ISymbol symbolQualifiedName = model.GetSymbolInfo(item.Type).Symbol;
                if (symbolQualifiedName != null &&
                    (symbolQualifiedName.ToString() == "System.Web.HttpCookie"
                    || symbolQualifiedName.ToString() == "System.Net.Http.Headers.CookieHeaderValue"
                    || symbolQualifiedName.ToString() == "Microsoft.Net.Http.Headers.CookieHeaderValue"
                    || symbolQualifiedName.ToString() == "Microsoft.AspNetCore.Http.CookieOptions"))
                {
                    foreach (var variable in item.Variables)
                    {
                        if (variable.Initializer != null && variable.Initializer.IsKind(SyntaxKind.EqualsValueClause) &&
                        !(variable.Initializer as EqualsValueClauseSyntax).Value.IsKind(SyntaxKind.ObjectCreationExpression))
                        {
                            pendingCookieStatements.Add(new SASTCookie() { CookieStatement = variable });
                            //Console.WriteLine("variableDecl {0} {1} {2}",variable.Initializer.Kind(),symbolQualifiedName,item);
                        }
                    }
                    //Console.WriteLine("variableDecl {0} {1} {2}",item.Kind(),symbolQualifiedName,item);
                }
            }

            // Cookie Object Declarations
            var objectCreations = syntaxNode.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
            foreach (var item in objectCreations)
            {
                ISymbol symbolQualifiedName = model.GetSymbolInfo((item as ObjectCreationExpressionSyntax).Type).Symbol;
                //Console.WriteLine("ObCreation {0} {1} {2}",item.Kind(),symbolQualifiedName,item);
                if (symbolQualifiedName != null &&
                    (symbolQualifiedName.ToString() == "System.Web.HttpCookie"
                    || symbolQualifiedName.ToString() == "System.Net.Http.Headers.CookieHeaderValue"
                    || symbolQualifiedName.ToString() == "Microsoft.Net.Http.Headers.CookieHeaderValue"
                    || symbolQualifiedName.ToString() == "Microsoft.AspNetCore.Http.CookieOptions"))
                {
                    bool isSecure = false;
                    bool isHttpOnly = false;
                    //If Object is declared using Initializer
                    if ((item as ObjectCreationExpressionSyntax).Initializer != null)
                    {
                        var initializer = (item as ObjectCreationExpressionSyntax).Initializer;
                        foreach (var assignment in initializer.Expressions)
                        {
                            if (assignment.Kind() == SyntaxKind.SimpleAssignmentExpression)
                            {
                                if ((assignment as AssignmentExpressionSyntax).Left.ToString() == "Secure")
                                    isSecure = PropertyMatch(assignment, "Secure");
                                else if ((assignment as AssignmentExpressionSyntax).Left.ToString() == "HttpOnly")
                                    isHttpOnly = PropertyMatch(assignment, "HttpOnly");
                            }
                        }
                    }
                    if (item.Parent.Kind() == SyntaxKind.Argument)
                    {
                        if (!isSecure || !isHttpOnly)
                            missingCookieStatements.Add(new SASTCookie()
                            {
                                CookieStatement = item,
                                IsSecure = isSecure,
                                IsHttpOnly = isHttpOnly
                            });
                    }
                    else if (item.Parent.Kind() == SyntaxKind.EqualsValueClause)
                    {
                        //Console.WriteLine("{0} S{1} H{2}",item,isSecure,isHttpOnly);
                        pendingCookieStatements.Add(new SASTCookie()
                        {
                            CookieStatement = item.Parent.Parent,
                            IsSecure = isSecure,
                            IsHttpOnly = isHttpOnly
                        });
                    }
                }
            }
            foreach (var item in pendingCookieStatements)
            {
                bool isSecure = item.IsSecure;
                bool isHttpOnly = item.IsHttpOnly;
                var declaredSymbol = item.CookieStatement.IsKind(SyntaxKind.ObjectCreationExpression)
                ? model.GetDeclaredSymbol(item.CookieStatement.Parent.Parent)
                : model.GetDeclaredSymbol((item.CookieStatement as VariableDeclaratorSyntax));
                var references = SymbolFinder.FindReferencesAsync(declaredSymbol, solution).Result;
                foreach (var location in references.First().Locations)
                {
                    var expression = syntaxNode.FindNode(location.Location.SourceSpan).Parent.Parent;
                    if (expression.Kind() == SyntaxKind.SimpleAssignmentExpression)
                    {
                        if (((expression as AssignmentExpressionSyntax).Left as MemberAccessExpressionSyntax).Name
                        .ToString() == "Secure")
                        {
                            isSecure = PropertyMatch(expression as AssignmentExpressionSyntax, "Secure");
                        }
                        else if (((expression as AssignmentExpressionSyntax).Left as MemberAccessExpressionSyntax).Name
                        .ToString() == "HttpOnly")
                            isHttpOnly = PropertyMatch(expression as AssignmentExpressionSyntax, "HttpOnly");
                    }
                }
                if (!isSecure || !isHttpOnly)
                    missingCookieStatements.Add(new SASTCookie()
                    {
                        CookieStatement = item.CookieStatement,
                        IsHttpOnly = isHttpOnly,
                        IsSecure = isSecure
                    });
            }
            return Map.ConvertToVulnerabilityList(filePath, missingCookieStatements, ScannerType.InsecureCookie).AsEnumerable();
        }

    }
}