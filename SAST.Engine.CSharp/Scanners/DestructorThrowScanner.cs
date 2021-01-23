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
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var destructorDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<DestructorDeclarationSyntax>();
            foreach (var destructor in destructorDeclarations)
            {
                var throwStatements = destructor.DescendantNodesAndSelf().Where(obj => obj is ThrowExpressionSyntax || obj is ThrowStatementSyntax);
                if (throwStatements.Any())
                    foreach (var throwStatement in throwStatements)
                        vulnerabilities.Add(VulnerabilityDetail.Create(filePath, throwStatement, Enums.ScannerType.DestructorThrow));
            }
            return vulnerabilities;
        }
    }
}