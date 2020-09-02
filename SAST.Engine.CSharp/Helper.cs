using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Linq;

namespace SAST.Engine.CSharp
{
    internal static class Helper
    {
        public static SyntaxNode RemoveParentheses(this SyntaxNode expression)
        {
            var currentExpression = expression;
            var parentheses = expression as ParenthesizedExpressionSyntax;
            while (parentheses != null)
            {
                currentExpression = parentheses.Expression;
                parentheses = currentExpression as ParenthesizedExpressionSyntax;
            }
            return currentExpression;
        }
        
        public static ISymbol GetSymbol(this SemanticModel model, SyntaxNode node)
        {
            SymbolInfo symbolInfo = model.GetSymbolInfo(node);
            return symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
        }

        public static ITypeSymbol GetTypeSymbol(this SemanticModel model, SyntaxNode node)
        {
            TypeInfo typeInfo = model.GetTypeInfo(node);
            return typeInfo.Type;
        }
    }
}
