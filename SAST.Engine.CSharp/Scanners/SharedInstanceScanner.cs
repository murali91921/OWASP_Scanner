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
        private readonly string PartCreationPolicy_Attribute = "System.ComponentModel.Composition.PartCreationPolicyAttribute";
        private readonly string CreationPolicy_Attribute = "System.ComponentModel.Composition.CreationPolicy";
        private readonly int CreationPolicy_Shared = 1;

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var objectCreations = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var objectCreation in objectCreations)
            {
                var typeSymbol = model.GetTypeSymbol(objectCreation);
                if (typeSymbol == null)
                    continue;
                if (typeSymbol.DeclaringSyntaxReferences.Length == 0)
                    continue;

                var semanticModel = model.Compilation.GetSemanticModel(typeSymbol.DeclaringSyntaxReferences[0].SyntaxTree);
                var declaration = typeSymbol.DeclaringSyntaxReferences[0].GetSyntaxAsync().Result as ClassDeclarationSyntax;
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
                                syntaxNodes.Add(objectCreation);
                        }
                    }
                }
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.SharedInstance);
        }
    }
}