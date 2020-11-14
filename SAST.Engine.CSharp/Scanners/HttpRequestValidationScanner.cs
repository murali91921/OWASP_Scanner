using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class HttpRequestValidationScanner : IScanner
    {
        private static string PostAttribute_Type = "System.Web.Mvc.HttpPostAttribute";
        private static string ValidateInputAttribute_Type = "System.Web.Mvc.ValidateInputAttribute";
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var methodDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>();
            foreach (var method in methodDeclarations)
            {
                if (method.ParameterList.Parameters.Count == 0 || method.AttributeLists.Count == 0)
                    continue;
                bool hasPost = false;
                bool hasInputValidated = false;
                foreach (var attributeList in method.AttributeLists)
                {
                    foreach (var attribute in attributeList.Attributes)
                    {
                        ITypeSymbol typeSymbol = model.GetTypeSymbol(attribute);
                        if (typeSymbol == null)
                            continue;
                        if (typeSymbol.ToString() == PostAttribute_Type)
                            hasPost = true;
                        else if (typeSymbol.ToString() == ValidateInputAttribute_Type)
                        {
                            AttributeArgumentSyntax argument = attribute.ArgumentList.Arguments.First();
                            if (argument == null)
                                continue;
                            var constantValue = model.GetConstantValue(argument.Expression);
                            if (constantValue.HasValue && constantValue.Value is bool value && value)
                                hasInputValidated = true;
                        }
                    }
                }
                if (hasPost && !hasInputValidated)
                    syntaxNodes.Add(method);
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.HttpRequestValidation);
        }
    }
}
