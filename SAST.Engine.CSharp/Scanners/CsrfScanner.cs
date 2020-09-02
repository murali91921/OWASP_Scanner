using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class CsrfScanner : IScanner
    {
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
        private static string[] CsrfTokenAttributes = {
            "System.Web.Mvc.ValidateAntiForgeryTokenAttribute",
            "Microsoft.AspNetCore.Mvc.ValidateAntiForgeryTokenAttribute",
            "Microsoft.AspNetCore.Mvc.AutoValidateAntiforgeryTokenAttribute"
            };
        private static string[] AnonymousAttribute = {
            "System.Web.Mvc.AllowAnonymousAttribute",
            "Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute"};

        private bool CheckHttbVerb(ITypeSymbol typeSymbol)
        {
            if (typeSymbol != null)
                return HttpVerbAttributes.Any(obj => obj == typeSymbol.ToString());
            return false;
        }
        private bool CheckAnonymousAttribute(ITypeSymbol typeSymbol)
        {
            if (typeSymbol != null)
                return AnonymousAttribute.Any(obj => obj == typeSymbol.ToString());
            return false;
        }
        private bool CheckCsrfAttribute(ITypeSymbol typeSymbol)
        {
            if (typeSymbol != null)
                return CsrfTokenAttributes.Any(obj => obj == typeSymbol.ToString());
            return false;
        }
        IEnumerable<VulnerabilityDetail> IScanner.FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model, Solution solution = null)
        {
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            var attributeClassDeclarations = syntaxNode.DescendantNodes().OfType<ClassDeclarationSyntax>();
            foreach (var itemClass in attributeClassDeclarations)
            {
                bool IsCsrfAttributeExistsInClass = false;
                foreach (var attributeList in itemClass.AttributeLists)
                {
                    foreach (var attribute in attributeList.Attributes)
                    {
                        TypeInfo typeInfo = model.GetTypeInfo(attribute);
                        if (typeInfo.Type != null && typeInfo.Type is ITypeSymbol)
                            IsCsrfAttributeExistsInClass = CheckCsrfAttribute(typeInfo.Type) || IsCsrfAttributeExistsInClass;
                        if (IsCsrfAttributeExistsInClass)
                            break;
                    }
                    if (IsCsrfAttributeExistsInClass)
                        break;
                }
                // If  Csrf Attribute is not found at Class Level, check in Method level.
                if (!IsCsrfAttributeExistsInClass)
                {
                    var methods = itemClass.DescendantNodes().OfType<MethodDeclarationSyntax>();
                    foreach (var method in methods)
                    {
                        // Action method should be PUBLIC
                        if (!method.Modifiers.Any(modifier => modifier.IsKind(SyntaxKind.PublicKeyword)))
                            break;
                        var returnTypeSymbol = model.GetSymbolInfo(method.ReturnType).Symbol;
                        {
                            bool hasHttpVerb = false;
                            bool hasCsrfAttribute = false;
                            bool hasAnonymousAttribute = false;
                            foreach (var attributeList in method.AttributeLists)
                            {
                                foreach (var attribute in attributeList.Attributes)
                                {
                                    TypeInfo typeInfo = model.GetTypeInfo(attribute);
                                    if (typeInfo.Type != null)
                                    {
                                        hasHttpVerb = CheckHttbVerb(typeInfo.Type) || hasHttpVerb;
                                        hasCsrfAttribute = CheckCsrfAttribute(typeInfo.Type) || hasCsrfAttribute;
                                        hasAnonymousAttribute = CheckAnonymousAttribute(typeInfo.Type) || hasAnonymousAttribute;
                                    }
                                }
                            }
                            if (hasHttpVerb && !hasCsrfAttribute & !hasAnonymousAttribute)
                                lstVulnerableStatements.Add(method);
                        }
                    }
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, Enums.ScannerType.Csrf);
        }
    }
}