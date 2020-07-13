using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp.Formatting;
using System.Collections.Generic;
using System.Linq;

namespace ASTTask
{
    internal class EmptyCatch
    {

        public List<SyntaxNode> FindEmptyCatch(SyntaxNode rootNode)
        {
            var allCatchStatements = rootNode.DescendantNodes().OfType<CatchClauseSyntax>();
            var emptyCatchNodes = new List<SyntaxNode>();
            foreach (var item in allCatchStatements)
            {
                var catchBlock = item.DescendantNodes().OfType<BlockSyntax>().First();
                if(catchBlock.DescendantNodes().Count() == 0)
                    emptyCatchNodes.Add(item);
            }
            return emptyCatchNodes;
        }
    }
}