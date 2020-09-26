using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Mapper;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    /// <summary>
    /// This Scanner to find Empty Catch Vulnerabilities 
    /// </summary>
    internal class EmptyCatchScanner : IScanner
    {
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model, Solution solution = null)
        {
            var allCatchStatements = syntaxNode.DescendantNodes().OfType<CatchClauseSyntax>();
            var emptyCatchNodes = new List<SyntaxNode>();
            IEnumerator<CatchClauseSyntax> enumerator = allCatchStatements.GetEnumerator();
            while (enumerator.MoveNext())
            {
                var catchBlock = enumerator.Current.DescendantNodes().OfType<BlockSyntax>().First();
                if (catchBlock.DescendantNodes().Count() == 0)
                    emptyCatchNodes.Add(enumerator.Current);
            }
            return Map.ConvertToVulnerabilityList(filePath, emptyCatchNodes, ScannerType.EmptyCatch);
        }
    }
}