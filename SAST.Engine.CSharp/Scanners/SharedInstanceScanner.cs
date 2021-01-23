using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class SharedInstanceScanner : IScanner
    {
        private readonly string PartCreationPolicy_Attribute = Constants.KnownType.System_ComponentModel_Composition_PartCreationPolicyAttribute;

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var objectCreations = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var objectCreation in objectCreations)
            {
                var typeSymbol = model.GetTypeSymbol(objectCreation);
                if (typeSymbol == null)
                    continue;
                if (typeSymbol.DeclaringSyntaxReferences.Length == 0)
                    continue;

                if (!model.Compilation.SyntaxTrees.Any(obj => obj == typeSymbol.DeclaringSyntaxReferences[0].SyntaxTree))
                    continue;
                var semanticModel = model.Compilation.GetSemanticModel(typeSymbol.DeclaringSyntaxReferences[0].SyntaxTree);
                if (!(typeSymbol.DeclaringSyntaxReferences[0].GetSyntaxAsync().Result is ClassDeclarationSyntax declaration))
                    continue;

                if (declaration.AttributeLists.Count > 0)
                {
                    foreach (var attributeList in declaration.AttributeLists)
                    {
                        foreach (var attribute in attributeList.Attributes)
                        {
                            ITypeSymbol attributeSymbol = semanticModel.GetTypeSymbol(attribute.Name);
                            if (attributeSymbol == null || attributeSymbol.ToString() != PartCreationPolicy_Attribute || attribute.ArgumentList?.Arguments.Count == 0)
                                continue;

                            var optional = semanticModel.GetConstantValue(attribute.ArgumentList?.Arguments.First().Expression);
                            if (optional.HasValue && optional.Value is int value && value == 1)
                                vulnerabilities.Add(VulnerabilityDetail.Create(filePath, objectCreation, Enums.ScannerType.SharedInstance));
                        }
                    }
                }
            }
            return vulnerabilities;
        }
    }
}