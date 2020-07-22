using System;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace ASTTask
{
    internal class CsrfScanner
    {
        /*
        FIND THE WEAK PASSWORDS
        */
        SemanticModel model = null;
        AdhocWorkspace workspace = null;
        SyntaxNode rootNode = null;
        //POST, GET, PUT, PATCH, and DELETE
        private static string[] HttpVerbAttributes = new string[] {
            "System.Web.Mvc.HttpPostAttribute",
            "System.Web.Mvc.HttpDeleteAttribute",
            "System.Web.Mvc.HttpPutAttribute",
            "System.Web.Mvc.HttpPatchAttribute",

            "Microsoft.AspNetCore.Mvc.HttpPostAttribute",
            "Microsoft.AspNetCore.Mvc.HttpDeleteAttribute",
            "Microsoft.AspNetCore.Mvc.HttpPutAttribute",
            "Microsoft.AspNetCore.Mvc.HttpPatchAttribute",
            };
        // private static string[] ReturnTypeClasses = {
        //     "System.Web.Mvc.ActionResult",
        //     "Microsoft.AspNetCore.Mvc.IActionResult"
        //     };
        private static string[] CsrfTokenAttributes = {
            "System.Web.Mvc.ValidateAntiForgeryTokenAttribute",
            "Microsoft.AspNetCore.Mvc.ValidateAntiForgeryTokenAttribute",
            "Microsoft.AspNetCore.Mvc.AutoValidateAntiforgeryTokenAttribute"
            };
        private static string[] AnonymousAttribute = {
            "System.Web.Mvc.AllowAnonymousAttribute",
            "Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute"};
        //Recursive method to check base types.--> Not required because different types of Return statements will come.
        // private bool CheckReturnType(INamedTypeSymbol typeSymbol)
        // {
        //     // return true;
        //     if(typeSymbol ==null)
        //         return false;
        //     if(ReturnTypeClasses.Any(obj=>obj == typeSymbol.ToString()))
        //         return true;
        //     else if(typeSymbol.BaseType !=null && typeSymbol.BaseType.ToString()!="System.Object")
        //         return CheckReturnType(typeSymbol.BaseType);
        //     else if(typeSymbol.AllInterfaces !=null && typeSymbol.AllInterfaces.Count()>0)
        //         return typeSymbol.AllInterfaces.Any(baseInterface=> CheckReturnType(baseInterface));
        //     return false;
        // }
        private bool CheckHttbVerb(ITypeSymbol typeSymbol)
        {
            if(typeSymbol !=null )
                return HttpVerbAttributes.Any(obj => obj == typeSymbol.ToString());
            return false;
        }
        private bool CheckAnonymousAttribute(ITypeSymbol typeSymbol)
        {
            if(typeSymbol != null)
                return AnonymousAttribute.Any(obj => obj== typeSymbol.ToString());
            return false;
        }
        private bool CheckCsrfAttribute(ITypeSymbol typeSymbol)
        {
            if(typeSymbol !=null)
                return CsrfTokenAttributes.Any(obj => obj == typeSymbol.ToString());
            return false;
        }
        public List<SyntaxNode> FindCsrfVulnerabilities(string filePath, SyntaxNode root)
        {
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            workspace = new AdhocWorkspace();
            var solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Create());
            var project = workspace.AddProject("CsrfScanner", "C#");
            project = project.AddMetadataReference(MetadataReference.CreateFromFile(filePath));
            project = project.AddMetadataReferences(Utils.LoadMetadata(root));
            workspace.TryApplyChanges(project.Solution);
            var document = workspace.AddDocument(project.Id, "CsrfScanner",SourceText.From(root.ToString()));
            model = document.GetSemanticModelAsync().Result;
            var compilation = project.GetCompilationAsync().Result;
            rootNode = document.GetSyntaxRootAsync().Result;
            //Filter all class declarations with Attribute specification
            var attributeClassDeclarations = rootNode.DescendantNodes().OfType<ClassDeclarationSyntax>();
            foreach (var itemClass in attributeClassDeclarations)
            {
                bool IsCsrfAttributeExistsInClass = false;
                foreach (var attributeList in itemClass.AttributeLists)
                {
                    foreach (var attribute in attributeList.Attributes)
                    {
                        TypeInfo typeInfo = model.GetTypeInfo(attribute);
                        if(typeInfo.Type!=null && typeInfo.Type is ITypeSymbol)
                            IsCsrfAttributeExistsInClass = CheckCsrfAttribute(typeInfo.Type) || IsCsrfAttributeExistsInClass;
                        if(IsCsrfAttributeExistsInClass)
                            break;
                    }
                    if(IsCsrfAttributeExistsInClass)
                        break;
                }
                // If  Csrf Attribute is not found at Class Level, check in Method level.
                if(!IsCsrfAttributeExistsInClass)
                {
                    var methods = itemClass.DescendantNodes().OfType<MethodDeclarationSyntax>();
                    foreach (var method in methods) {
                    // Parallel.ForEach (methods, method => {
                        // Action method should be PUBLIC
                        if(!method.Modifiers.Any(modifier => modifier.IsKind(SyntaxKind.PublicKeyword)))
                            break;
                        var returnTypeSymbol = model.GetSymbolInfo(method.ReturnType).Symbol;
                        //if(CheckReturnType(returnTypeSymbol as INamedTypeSymbol))
                        {
                            bool hasHttpVerb = false;
                            bool hasCsrfAttribute = false;
                            bool hasAnonymousAttribute = false;
                            foreach (var attributeList in method.AttributeLists)
                            {
                                foreach (var attribute in attributeList.Attributes)
                                {
                                    TypeInfo typeInfo = model.GetTypeInfo(attribute);
                                    if(typeInfo.Type != null)
                                    {
                                        hasHttpVerb = CheckHttbVerb(typeInfo.Type) || hasHttpVerb;
                                        hasCsrfAttribute = CheckCsrfAttribute(typeInfo.Type) || hasCsrfAttribute;
                                        hasAnonymousAttribute = CheckAnonymousAttribute(typeInfo.Type) || hasAnonymousAttribute;
                                    }
                                    // else if(symbolInfo.CandidateSymbols.Count()>0)
                                    // {
                                    //     foreach (var candidateSymbol in symbolInfo.CandidateSymbols)
                                    //     {
                                    //         hasHttpVerb = CheckHttbVerb(symbolInfo.Symbol) || hasHttpVerb;
                                    //         hasCsrftAttribute = CheckCsrfAttribute(candidateSymbol) || hasCsrftAttribute;
                                    //     }
                                    // }
                                }
                            }
                            if(hasHttpVerb && !hasCsrfAttribute & !hasAnonymousAttribute)
                            {
                                lstVulnerableStatements.Add(method);
                            }
                        }
                    //});
                    }
                }
            }
            return lstVulnerableStatements;
        }
    }
}