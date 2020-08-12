using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Formatting;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System;
using System.Linq;

namespace ASTTask
{
    internal class EmptyTryScanner
    {

        public List<SyntaxNode> FindEmptyTryStatements(SyntaxNode rootNode)
        {
            var emptyTryStatements = new List<SyntaxNode>();
            var allTryStatements = rootNode.DescendantNodes().OfType<TryStatementSyntax>().GetEnumerator();
            while (allTryStatements.MoveNext())
            {
                var tryBlock = allTryStatements.Current.DescendantNodes().OfType<BlockSyntax>().First();
                // Console.WriteLine(tryBlock.DescendantNodes().Count());
                if (tryBlock.DescendantNodes().Count() == 0)
                    emptyTryStatements.Add(tryBlock);
            }
            return emptyTryStatements;
        }
    }
}