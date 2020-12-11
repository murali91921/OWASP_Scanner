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
    internal class DestructorThrowScanner : IScanner
    {
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var destructorDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<DestructorDeclarationSyntax>();
            foreach (var destructor in destructorDeclarations)
            {
                var throwStatements = destructor.DescendantNodesAndSelf().Where(obj => obj is ThrowExpressionSyntax || obj is ThrowStatementSyntax);
                if (throwStatements.Count() > 0)
                    syntaxNodes.AddRange(throwStatements);
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.DestructorThrow);
        }
    }
}