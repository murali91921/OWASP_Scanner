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
            var catchStatements = syntaxNode.DescendantNodes().OfType<CatchClauseSyntax>();
            var vulnerabilities = new List<VulnerabilityDetail>();
            foreach (var item in catchStatements)
            {
                if (!item.Block.DescendantNodes().Any())
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item, Enums.ScannerType.EmptyCatch));
            }
            return vulnerabilities;
        }
    }
}