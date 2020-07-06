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

namespace ASTTask
{
    internal class CookieFlagScanner
    {
        public static XMLCookie GetXMLMissingCookieStatements(string filePath)
        {
            XMLCookie xMLCookie = new XMLCookie();
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(filePath);
            XmlNode httpCookieNode = xmlDoc.DocumentElement.SelectSingleNode("system.web/httpCookies");
            if(httpCookieNode!=null)
            {
                foreach(XmlAttribute attribute in httpCookieNode.Attributes)
                {
                    if(attribute.Name.Equals("httpOnlyCookies"))
                        xMLCookie.IsHttpOnly=bool.Parse(attribute.Value);
                    else if(attribute.Name.Equals("requireSSL"))
                        xMLCookie.IsSecure=bool.Parse(attribute.Value);
                }
            }
            return xMLCookie;
        }
        public static List<SyntaxNode> GetMissingCookieStatements(string filePath,SyntaxNode root)
        {
            //Variable Declaraions;
            List<ASTCookie> pendingCookieStatements = new List<ASTCookie>();
            List<SyntaxNode> missingCookieStatements=new List<SyntaxNode>();

            //Adhoc Workspace creation
            var workspace = new AdhocWorkspace();
            var solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Create());
            var project = workspace.AddProject("CookieScanner", "C#");
            project = project.AddMetadataReference(MetadataReference.CreateFromFile(filePath));
            project = project.AddMetadataReferences(LoadMetadata(root));
            workspace.TryApplyChanges(project.Solution);
            var document = workspace.AddDocument(project.Id, "CookieScanner",SourceText.From(root.ToString()));
            var model = document.GetSemanticModelAsync().Result;
            root = document.GetSyntaxRootAsync().Result;

            // Values are modifying in Response Object itself.
            foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                Tuple<HashSet<SyntaxNode>,bool,bool> respStatements = FindResponseStatements(method, model,document.Project);
                if(respStatements!=null && !respStatements.Item2 && !respStatements.Item2 && respStatements.Item1.Count>0)
                {
                    // Console.WriteLine("Secure flag unset {0}",respStatements.Item2);
                    // Console.WriteLine("HttpOnly flag unset {0}",respStatements.Item3);
                    foreach (var item in respStatements.Item1)
                    {
                        // Console.WriteLine("---- {0}",item.ToString());
                        missingCookieStatements.Add(item);
                    }
                }
            }

            //Finding all declarations which are not having ObjectCreations and making them as pending statements
            var variableDecl = root.DescendantNodes(). OfType<VariableDeclarationSyntax>();
            foreach (var item in variableDecl)
            {
                ISymbol symbolQualifiedName = model.GetSymbolInfo(item.Type).Symbol;
                if( symbolQualifiedName!=null &&
                    (symbolQualifiedName.ToString() == "System.Web.HttpCookie"
                    || symbolQualifiedName.ToString() == "System.Net.Http.Headers.CookieHeaderValue"
                    || symbolQualifiedName.ToString() == "Microsoft.Net.Http.Headers.CookieHeaderValue"
                    || symbolQualifiedName.ToString() == "Microsoft.AspNetCore.Http.CookieOptions"))
                {
                    foreach (var variable in item.Variables)
                    {
                        if(variable.Initializer!=null && variable.Initializer.IsKind(SyntaxKind.EqualsValueClause) &&
                        !(variable.Initializer as EqualsValueClauseSyntax).Value.IsKind(SyntaxKind.ObjectCreationExpression))
                        {
                            pendingCookieStatements.Add(new ASTCookie() { cookieStatement = variable } );
                            //Console.WriteLine("variableDecl {0} {1} {2}",variable.Initializer.Kind(),symbolQualifiedName,item);
                        }
                    }
                    //Console.WriteLine("variableDecl {0} {1} {2}",item.Kind(),symbolQualifiedName,item);
                }
            }

            // Cookie Object Declarations
            var objectCreations = root.DescendantNodes(). OfType<ObjectCreationExpressionSyntax>();
            foreach (var item in objectCreations)
            {
                ISymbol symbolQualifiedName = model.GetSymbolInfo((item as ObjectCreationExpressionSyntax).Type).Symbol;
                //Console.WriteLine("ObCreation {0} {1} {2}",item.Kind(),symbolQualifiedName,item);
                if( symbolQualifiedName!=null &&
                    (symbolQualifiedName.ToString() == "System.Web.HttpCookie"
                    || symbolQualifiedName.ToString() == "System.Net.Http.Headers.CookieHeaderValue"
                    || symbolQualifiedName.ToString() == "Microsoft.Net.Http.Headers.CookieHeaderValue"
                    || symbolQualifiedName.ToString() == "Microsoft.AspNetCore.Http.CookieOptions"))
                {
                    bool isSecure = false;
                    bool isHttpOnly = false;
                    //If Object is declared using Initializer
                    if((item as ObjectCreationExpressionSyntax).Initializer !=null)
                    {
                        var initializer=(item as ObjectCreationExpressionSyntax).Initializer;
                        foreach (var assignment in initializer.Expressions)
                        {
                            if(assignment.Kind()== SyntaxKind.SimpleAssignmentExpression)
                            {
                                if((assignment as AssignmentExpressionSyntax).Left.ToString()=="Secure")
                                    isSecure = PropertyMatch(assignment,"Secure");
                                else if((assignment as AssignmentExpressionSyntax).Left.ToString()=="HttpOnly")
                                    isHttpOnly = PropertyMatch(assignment,"HttpOnly");
                            }
                        }
                    }
                    if(item.Parent.Kind()==SyntaxKind.Argument)
                    {
                        if(!isSecure || !isHttpOnly)
                            missingCookieStatements.Add(item);
                    }
                    else if(item.Parent.Kind()==SyntaxKind.EqualsValueClause)
                        pendingCookieStatements.Add(new ASTCookie(){
                            cookieStatement = item,
                            IsSecure = isSecure,
                            IsHttpOnly = isHttpOnly
                            });
                }
            }
            foreach (var item in pendingCookieStatements)
            {
                bool isSecure = item.IsSecure;
                bool isHttpOnly = item.IsHttpOnly;
                var declaredSymbol = item.cookieStatement.IsKind(SyntaxKind.ObjectCreationExpression)
                ? model.GetDeclaredSymbol(item.cookieStatement.Parent.Parent)
                : model.GetDeclaredSymbol((item.cookieStatement as VariableDeclaratorSyntax));
                var references = SymbolFinder.FindReferencesAsync(declaredSymbol,  document.Project.Solution).Result;
                foreach (var location in references.First().Locations)
                {
                    var expression = root.FindNode(location.Location.SourceSpan).Parent.Parent;
                    if(expression.Kind()== SyntaxKind.SimpleAssignmentExpression)
                    {
                        if(((expression as AssignmentExpressionSyntax).Left as MemberAccessExpressionSyntax).Name
                        .ToString()=="Secure")
                            {
                                isSecure = PropertyMatch(expression as AssignmentExpressionSyntax,"Secure");
                            }
                        else if(((expression as AssignmentExpressionSyntax).Left as MemberAccessExpressionSyntax).Name
                        .ToString()=="HttpOnly")
                            isHttpOnly = PropertyMatch(expression as AssignmentExpressionSyntax,"HttpOnly");
                    }
                }
                if(!isSecure || !isHttpOnly)
                    missingCookieStatements.Add(item.cookieStatement);
            }
            return missingCookieStatements;
        }
        public static MetadataReference[] LoadMetadata(SyntaxNode root)
        {
            List<MetadataReference> allMetadataReference = new List<MetadataReference>();
            List<UsingDirectiveSyntax> allNamespaces = root.DescendantNodes().OfType<UsingDirectiveSyntax>().ToList();
            foreach (var item in allNamespaces)
            {
                string assemblyFile=Directory.GetCurrentDirectory()+"\\Examples\\References\\"+item.Name.ToString()+".dll";
                if(File.Exists(assemblyFile))
                    allMetadataReference.Add(MetadataReference.CreateFromFile(assemblyFile));
            }
            return allMetadataReference.ToArray();
        }
        public static bool PropertyMatch(ExpressionSyntax expression,string propertyName)
        {
            bool propertyValue = false;
            if(expression.Kind()== SyntaxKind.SimpleAssignmentExpression)
            {
                var assignment = expression as AssignmentExpressionSyntax;
                if(assignment.Left is MemberAccessExpressionSyntax &&
                    (assignment.Left as MemberAccessExpressionSyntax).Name.ToString()==propertyName &&
                    assignment.Right.IsKind(SyntaxKind.TrueLiteralExpression))
                    propertyValue =true;
                else if(assignment.Left.ToString()==propertyName && assignment.Right.IsKind(SyntaxKind.TrueLiteralExpression))
                        propertyValue =true;
            }
            return propertyValue;
        }
        private static Tuple<HashSet<SyntaxNode>,bool,bool> FindResponseStatements(SyntaxNode root,SemanticModel model,Project project)
        {
            bool isSecure = false;
            bool isHttpOnly = false;
            HashSet<SyntaxNode> allCookieNodes=new HashSet<SyntaxNode>();
            HashSet<SyntaxNode> InSecurenodes = new HashSet<SyntaxNode>();
            HashSet<ISymbol> respSYmbols = new  HashSet<ISymbol>();
            var compilation = project.GetCompilationAsync().Result;
            var assignmentExpr = root.DescendantNodes().Where(obj=>obj.IsKind(SyntaxKind.SimpleAssignmentExpression)).Cast<AssignmentExpressionSyntax>();
            foreach (var assignment in assignmentExpr)
            {
                // var assignment = expr.Expression as AssignmentExpressionSyntax;
                //Console.WriteLine(assignment.Left);
                if(assignment.Left.IsKind(SyntaxKind.SimpleMemberAccessExpression))
                {
                    if((assignment.Left as MemberAccessExpressionSyntax).Expression is IdentifierNameSyntax)
                        continue;
                    ISymbol symbol = model.GetSymbolInfo(assignment.Left).Symbol;
                    if(symbol != null && symbol.ToString().StartsWith("System.Web.HttpCookie."))
                    {
                        allCookieNodes.Add(assignment);
                        if(symbol.ToString() == "System.Web.HttpCookie.Secure")
                        {
                            isSecure = assignment.Right.Kind()==SyntaxKind.TrueLiteralExpression;
                            if(!isSecure)
                                InSecurenodes.Add(assignment);
                        }
                        else if(symbol.ToString() == "System.Web.HttpCookie.HttpOnly")
                        {
                            isHttpOnly = assignment.Right.Kind()==SyntaxKind.TrueLiteralExpression;
                            if(!isHttpOnly)
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
            if((!isSecure || !isHttpOnly) && InSecurenodes.Count == 0)
                InSecurenodes = new HashSet<SyntaxNode>(allCookieNodes);
            return new Tuple<HashSet<SyntaxNode>, bool, bool>(InSecurenodes,isSecure,isHttpOnly);
        }
    }
    internal class ASTCookie
    {
        internal SyntaxNode cookieStatement{set;get;}
        internal bool IsSecure{set;get;}
        internal bool IsHttpOnly{set;get;}
    }
    internal class XMLCookie
    {
        internal bool IsSecure{set;get;}
        internal bool IsHttpOnly{set;get;}
    }
}