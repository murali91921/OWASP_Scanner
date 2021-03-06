using Microsoft.CodeAnalysis;
using SAST.Engine.CSharp.Enums;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System.Linq;
using SAST.Engine.CSharp.Mapper;
using SAST.Engine.CSharp.Contract;

namespace SAST.Engine.CSharp.Scanners
{
    internal class EmptyTryScanner : IScanner
    {
        /// <summary>
        /// This method will find Empty try block Vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            var vulnerabilities = new List<VulnerabilityDetail>();
            var allTryStatements = syntaxNode.DescendantNodes().OfType<TryStatementSyntax>().GetEnumerator();
            while (allTryStatements.MoveNext())
            {
                var tryBlock = allTryStatements.Current.DescendantNodes().OfType<BlockSyntax>().First();
                if (tryBlock.DescendantNodes().Count() == 0)
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, tryBlock, ScannerType.EmptyTry));
            }
            return vulnerabilities;
        }
    }
}