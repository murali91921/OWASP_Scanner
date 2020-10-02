using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp;
using SAST.Engine.CSharp.Contract;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class AuthorizeScanner : IScanner
    {
        private static string ActionResult_Interface = "Microsoft.AspNetCore.Mvc.IActionResult";
        private static string ActionResult_Class = "System.Web.Mvc.ActionResult";
        private static string[] Controller_Classes =
        {
            "System.Web.Mvc.Controller",
            "System.Web.Mvc.ControllerBase",
            "Microsoft.AspNetCore.Mvc.Controller",
            "Microsoft.AspNetCore.Mvc.ControllerBase"
        };
        private static string[] Authorize_Attribute =
        {
            "Microsoft.AspNetCore.Authorization.AuthorizeAttribute",
            "System.Web.Mvc.AuthorizeAttribute",
        };
        private static string[] Anonymous_Attibute =
        {
            "Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute",
            "System.Web.Mvc.AllowAnonymousAttribute",
        };

        /// <summary>
        /// Determines the vulnerabilities in <paramref name="syntaxNode"/>
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();

            var classDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<ClassDeclarationSyntax>();
            foreach (var classDeclaration in classDeclarations)
            {
                ITypeSymbol typeSymbol = model.GetDeclaredSymbol(classDeclaration);

                //Should Inherit from Controller class
                if (typeSymbol == null || !Utils.DerivesFromAny(typeSymbol, Controller_Classes))
                    continue;

                //If class have Authorize or Anonymous attribute, consider all methods are safe.
                if (!IsAuthorizeAttributeMissing(model, classDeclaration.AttributeLists))
                    continue;

                var methodDeclarations = classDeclaration.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>();
                foreach (var method in methodDeclarations)
                {
                    if (IsVulnerable(model, method))
                        syntaxNodes.Add(method.ReturnType);
                }
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.Authorize);
        }

        /// <summary>
        /// Determines whether <paramref name="methodDeclaration"/> is vulnerable or not.
        /// </summary>
        /// <param name="model"></param>
        /// <param name="methodDeclaration"></param>
        /// <returns></returns>
        private bool IsVulnerable(SemanticModel model, MethodDeclarationSyntax methodDeclaration)
        {
            if (!methodDeclaration.Modifiers.Any(obj => obj.IsKind(SyntaxKind.PublicKeyword)))
                return false;

            ITypeSymbol typeSymbol = model.GetTypeSymbol(methodDeclaration.ReturnType);
            if (typeSymbol == null)
                return false;

            if (!Utils.DerivesFrom(typeSymbol, ActionResult_Class) && !Utils.ImplementsFrom(typeSymbol, ActionResult_Interface))
                return false;

            //Check for Attributes
            if (!IsAuthorizeAttributeMissing(model, methodDeclaration.AttributeLists))
                return false;

            return true;
        }

        /// <summary>
        /// Returns true, If <paramref name="attributeList"/> missing Authorize,AllowAnonynous attributes. false, otherwise.
        /// </summary>
        /// <param name="model"></param>
        /// <param name="attributeList"></param>
        /// <returns></returns>
        private bool IsAuthorizeAttributeMissing(SemanticModel model, SyntaxList<AttributeListSyntax> attributeList)
        {
            bool hasAnonymous = false, hasAuthorize = false;
            foreach (var attributeSyntax in attributeList)
            {
                foreach (var attribute in attributeSyntax.Attributes)
                {
                    ITypeSymbol typeSymbol = model.GetTypeSymbol(attribute);
                    if (typeSymbol == null)
                        continue;

                    //Check Anonymous Attribute
                    if (!hasAnonymous)
                        hasAnonymous = Utils.DerivesFromAny(typeSymbol, Anonymous_Attibute);

                    //Check Authorize Attribute
                    if (!hasAuthorize)
                        hasAuthorize = Utils.DerivesFromAny(typeSymbol, Authorize_Attribute);
                }
            }
            //If missing both Attributes, consider as vulnerable.
            return !hasAuthorize && !hasAnonymous;
        }
    }
}
