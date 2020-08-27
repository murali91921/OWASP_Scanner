using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class WeakCipherModeScanner : IScanner
    {
        static readonly string CipherModeType = "System.Security.Cryptography.CipherMode";
        static readonly string[] WeakCipherModes = { "ECB", "CBC", "OFB" };
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            var Nodes = syntaxNode.DescendantNodes().OfType<AssignmentExpressionSyntax>();
            foreach (var item in Nodes)
            {
                ITypeSymbol leftTypeSymbol = model.GetTypeInfo(item.Left).Type;
                if (leftTypeSymbol == null || leftTypeSymbol.ToString() != CipherModeType)
                    continue;

                var rightSyntax = item.Right as MemberAccessExpressionSyntax;
                if (rightSyntax == null)
                    continue;
                if (rightSyntax.Name.Identifier.ValueText == "ECB")
                    continue;

                SymbolInfo symbolInfo = model.GetSymbolInfo(rightSyntax.Expression);
                var rightSymbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                // if (rightSyntax == null || rightSymbol.OriginalDefinition.ToString() != CipherMode)
                //     continue;

                // lstVulnerableStatements.Add(item);
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, Enums.ScannerType.WeakCipherMode);
        }
    }
}