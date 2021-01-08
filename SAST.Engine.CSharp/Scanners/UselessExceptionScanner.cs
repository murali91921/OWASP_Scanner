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
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var objectCreations = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var objectCreation in objectCreations)
            {
                var createdObjectType = model.GetSymbol(objectCreation.Type) as INamedTypeSymbol;
                if (createdObjectType == null || !Utils.DerivesFrom(createdObjectType, Constants.KnownType.System_Exception))
                    continue;

                var parent = objectCreation.GetFirstNonParenthesizedParent();
                if (parent.IsKind(SyntaxKind.ExpressionStatement))
                    syntaxNodes.Add(objectCreation);
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.UselessException);
        }
    }
}