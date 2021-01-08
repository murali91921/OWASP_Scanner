using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Constants;
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
            KnownType.System_Web_Mvc_HttpPostAttribute,
            KnownType.System_Web_Mvc_HttpDeleteAttribute,
            KnownType.System_Web_Mvc_HttpPutAttribute,
            KnownType.System_Web_Mvc_HttpPatchAttribute,
            KnownType.Microsoft_AspNetCore_Mvc_HttpPostAttribute,
            KnownType.Microsoft_AspNetCore_Mvc_HttpDeleteAttribute,
            KnownType.Microsoft_AspNetCore_Mvc_HttpPutAttribute,
            KnownType.Microsoft_AspNetCore_Mvc_HttpPatchAttribute,
            };
        private static string[] CsrfTokenAttributes = {
            KnownType.System_Web_Mvc_ValidateAntiForgeryTokenAttribute,
            KnownType.Microsoft_AspNetCore_Mvc_ValidateAntiForgeryTokenAttribute,
            KnownType.Microsoft_AspNetCore_Mvc_AutoValidateAntiforgeryTokenAttribute
            };
        private static string[] AnonymousAttribute = {
            KnownType.System_Web_Mvc_AllowAnonymousAttribute,
            KnownType.Microsoft_AspNetCore_Authorization_AllowAnonymousAttribute
            };

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
            List<SyntaxToken> lstVulnerableStatements = new List<SyntaxToken>();
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
                            bool hasHttpVerb = false, hasCsrfAttribute = false, hasAnonymousAttribute = false;
                            foreach (var attributeList in method.AttributeLists)
                            {
                                foreach (var attribute in attributeList.Attributes)
                                {
                                    ITypeSymbol typeSymbol = model.GetTypeSymbol(attribute);
                                    if (typeSymbol != null)
                                    {
                                        hasHttpVerb = CheckHttbVerbAttribute(typeSymbol) || hasHttpVerb;
                                        hasCsrfAttribute = CheckCsrfAttribute(typeSymbol) || hasCsrfAttribute;
                                        hasAnonymousAttribute = CheckAnonymousAttribute(typeSymbol) || hasAnonymousAttribute;
                                    }
                                }
                            }
                            if (hasHttpVerb && !hasCsrfAttribute & !hasAnonymousAttribute)
                                lstVulnerableStatements.Add(method.Identifier);
                        }
                    }
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, Enums.ScannerType.Csrf);
        }
    }
}