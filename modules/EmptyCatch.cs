using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using System.Collections.Generic;
using System.Linq;

namespace ASTTask
{
    internal class EmptyCatch
    {

    public static List<SyntaxNodeOrToken> FindEmptyCatch(SyntaxNodeOrToken rootNode)
    {
        var emptyCatchNodes=new List<SyntaxNodeOrToken>();
        emptyCatchNodes  = FindCatchNodes(rootNode).FindAll(obj=> IsTotallyEmptyCatch(obj));
        return emptyCatchNodes;
    }
    private static List<SyntaxNodeOrToken> FindCatchNodes(SyntaxNodeOrToken node)
    {
        var exceptions = new List<SyntaxNodeOrToken>();
        var isCatchBlock = node.IsKind(SyntaxKind.CatchClause);
        if (isCatchBlock)
        {
            //If catch block is identified, add it in exception list.
            exceptions.Add(node);
        }
        // Looping through all ChildNodes
        foreach (var result in node.ChildNodesAndTokens().Select(FindCatchNodes).Where(result => result != null))
        {
            exceptions.AddRange(result);
        }
        return exceptions;

    }

    private static bool IsTotallyEmptyCatch(SyntaxNodeOrToken catchBlock)
    {
        var block = catchBlock.ChildNodesAndTokens().First(t => t.Kind() == SyntaxKind.Block);
        var children = block.ChildNodesAndTokens();
        return (children.Count == 2 && children.Any(c => c.Kind() == SyntaxKind.OpenBraceToken) &&
                children.Any(c => c.Kind() == SyntaxKind.CloseBraceToken));
    }
    }
}