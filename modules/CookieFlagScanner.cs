using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using System.Collections.Generic;
using System.Linq;
using System;
using System.IO;

namespace ASTTask
{
    internal class CookieFlagScanner
    {
        public static List<SyntaxNode> GetAllSymbols(string filePath,SyntaxNode root)
        {
            //Variable Declaraions;
            List<Cookie> pendingCookieStatements = new List<Cookie>();
            List<SyntaxNode> missingCookieStatements=new List<SyntaxNode>();

            //Create new AdhocWorkspace
            var workspace = new AdhocWorkspace();
            //Create new solution
            var solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Create());
            //Create new project
            var project = workspace.AddProject("CookieScanner", "C#");
            project = project.AddMetadataReference(MetadataReference.CreateFromFile(filePath));
            project = project.AddMetadataReferences(LoadMetadata(root));
            //Add project to workspace
            workspace.TryApplyChanges(project.Solution);
            //Add document to workspace
            var document = workspace.AddDocument(project.Id, "CookieScanner",SourceText.From(root.ToString()));
            //Get the semantic model
            var model = document.GetSemanticModelAsync().Result;
            root = document.GetSyntaxRootAsync().Result;

            var objectCreations = root.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
            foreach (var item in objectCreations)
            {
                ISymbol symbolQualifiedName = model.GetSymbolInfo((item as ObjectCreationExpressionSyntax).Type).Symbol;
                //Console.WriteLine("ObCreation {0} {1} {2}",item.Kind(),symbolQualifiedName,item);
                if( symbolQualifiedName!=null && (symbolQualifiedName.ToString() == "System.Web.HttpCookie"
                    || symbolQualifiedName.ToString() == "Microsoft.Net.Http.Headers.CookieHeaderValue"))
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
                        pendingCookieStatements.Add(new Cookie(){
                            cookieStatement = item,
                            IsSecure = isSecure,
                            IsHttpOnly = isHttpOnly
                            });
                }
            }
            // var objectExpressionStatements = root.DescendantNodes().OfType<ExpressionStatementSyntax>();
            // foreach (var item in objectExpressionStatements)
            // {
            //     Console.WriteLine("ObjExp {0} {1}",item.Kind(),item);
            // }
            foreach (var item in pendingCookieStatements)
            {
                bool isSecure = item.IsSecure;
                bool isHttpOnly = item.IsHttpOnly;
                var declaredSymbol = model.GetDeclaredSymbol(item.cookieStatement.Parent.Parent);
                var references = SymbolFinder.FindReferencesAsync(declaredSymbol,  document.Project.Solution).Result;

                foreach (var location in references.First().Locations)
                {
                    var expression = root.FindNode(location.Location.SourceSpan).Parent.Parent;
                    if(expression.Kind()== SyntaxKind.SimpleAssignmentExpression)
                    {
                        if(((expression as AssignmentExpressionSyntax).Left as MemberAccessExpressionSyntax).Name
                        .ToString()=="Secure")
                            isSecure = PropertyMatch(expression as AssignmentExpressionSyntax,"Secure");
                        else if(((expression as AssignmentExpressionSyntax).Left as MemberAccessExpressionSyntax).Name
                        .ToString()=="HttpOnly")
                            isHttpOnly = PropertyMatch(expression as AssignmentExpressionSyntax,"HttpOnly");
                    }
                }
                if(!isSecure || !isHttpOnly)
                    missingCookieStatements.Add(item.cookieStatement);
            }
            // foreach (var item in missingCookieStatements)
            // {
            //     Console.WriteLine("Miss {0} {1}",item.Kind(),item);
            // }
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
    }
    internal class Cookie
    {
        internal SyntaxNode cookieStatement{set;get;}
        internal bool IsSecure{set;get;}
        internal bool IsHttpOnly{set;get;}
    }
}