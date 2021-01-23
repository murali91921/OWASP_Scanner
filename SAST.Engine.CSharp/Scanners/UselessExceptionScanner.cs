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
    internal class UselessExceptionScanner : IScanner
    {
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var objectCreations = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var objectCreation in objectCreations)
            {
                if (model.GetSymbol(objectCreation.Type) as INamedTypeSymbol == null || !Utils.DerivesFrom(model.GetSymbol(objectCreation.Type) as INamedTypeSymbol, Constants.KnownType.System_Exception))
                    continue;

                var parent = objectCreation.GetFirstNonParenthesizedParent();
                if (parent.IsKind(SyntaxKind.ExpressionStatement))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, objectCreation, Enums.ScannerType.UselessException));
            }
            return vulnerabilities;
        }
    }
}