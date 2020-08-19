using Microsoft.CodeAnalysis;
using SAST.Engine.CSharp.Enums;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Formatting;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System;
using System.Linq;
using SAST.Engine.CSharp.Mapper;
using System.IO;
using SAST.Engine.CSharp.Contract;

namespace SAST.Engine.CSharp.Scanners
{
    public class EmptyTryScanner : IScanner
    {
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            var emptyTryStatements = new List<SyntaxNode>();
            var allTryStatements = syntaxNode.DescendantNodes().OfType<TryStatementSyntax>().GetEnumerator();
            while (allTryStatements.MoveNext())
            {
                var tryBlock = allTryStatements.Current.DescendantNodes().OfType<BlockSyntax>().First();
                // Console.WriteLine(tryBlock.DescendantNodes().Count());
                if (tryBlock.DescendantNodes().Count() == 0)
                    emptyTryStatements.Add(tryBlock);
            }
            return Map.ConvertToVulnerabilityList(filePath, emptyTryStatements, ScannerType.EmptyTry);
        }
    }
}