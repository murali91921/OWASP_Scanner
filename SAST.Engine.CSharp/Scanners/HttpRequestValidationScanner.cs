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
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
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
                        if (typeSymbol.ToString() == Constants.KnownType.System_Web_Mvc_HttpPostAttribute)
                            hasPost = true;
                        else if (typeSymbol.ToString() == Constants.KnownType.System_Web_Mvc_ValidateInputAttribute)
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
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, method, Enums.ScannerType.None));
            }
            return vulnerabilities;
        }
    }
}
