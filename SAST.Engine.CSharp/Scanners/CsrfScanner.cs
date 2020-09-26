using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    /// <summary>
    /// This Scanner to find Cross Site Request Forgery Vulnerabilities 
    /// </summary>
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

        /// <summary>
        /// This will verify <paramref name="typeSymbol"/> is HttpVerb Attribute or not
        /// </summary>
        /// <param name="typeSymbol"></param>
        /// <returns></returns>
        private bool CheckHttbVerbAttribute(ITypeSymbol typeSymbol)
        {
            if (typeSymbol != null)
                return HttpVerbAttributes.Any(obj => obj == typeSymbol.ToString());
            return false;
        }

        /// <summary>
        /// This will verify <paramref name="typeSymbol"/> is AllowAnonynous Attribute or not
        /// </summary>
        /// <param name="typeSymbol"></param>
        /// <returns></returns>
        private bool CheckAnonymousAttribute(ITypeSymbol typeSymbol)
        {
            if (typeSymbol != null)
                return AnonymousAttribute.Any(obj => obj == typeSymbol.ToString());
            return false;
        }

        /// <summary>
        /// This will verify <paramref name="typeSymbol"/> is ValidateAntiForgery Attribute or not.
        /// </summary>
        /// <param name="typeSymbol"></param>
        /// <returns></returns>
        private bool CheckCsrfAttribute(ITypeSymbol typeSymbol)
        {
            if (typeSymbol != null)
                return CsrfTokenAttributes.Any(obj => obj == typeSymbol.ToString());
            return false;
        }
        /// <summary>
        /// This method will find the vulnerabilities in <paramref name="syntaxNode"/>
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model, Solution solution = null)
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
                        ITypeSymbol typeSymbol = model.GetTypeSymbol(attribute);
                        if (typeSymbol != null)
                            IsCsrfAttributeExistsInClass = CheckCsrfAttribute(typeSymbol) || IsCsrfAttributeExistsInClass;
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
                        var returnTypeSymbol = model.GetSymbol(method.ReturnType);
                        {
                            bool hasHttpVerb = false;
                            bool hasCsrfAttribute = false;
                            bool hasAnonymousAttribute = false;
                            foreach (var attributeList in method.AttributeLists)
                            {
                                foreach (var attribute in attributeList.Attributes)
                                {
                                    ITypeSymbol typeSymbol = model.GetTypeSymbol(attribute);
                                    if (typeSymbol!= null)
                                    {
                                        hasHttpVerb = CheckHttbVerbAttribute(typeSymbol) || hasHttpVerb;
                                        hasCsrfAttribute = CheckCsrfAttribute(typeSymbol) || hasCsrfAttribute;
                                        hasAnonymousAttribute = CheckAnonymousAttribute(typeSymbol) || hasAnonymousAttribute;
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