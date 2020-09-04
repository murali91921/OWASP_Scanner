using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using System.Linq;

namespace SAST.Engine.CSharp
{
    internal static class HelperExtrensions
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

        public static string ToLineString(this LinePosition lineposition) => (lineposition.Line + 1) + "," + (lineposition.Character + 1);

        public static ISymbol GetSymbol(this SemanticModel model, SyntaxNode node)
        {
            SymbolInfo symbolInfo = model.GetSymbolInfo(node);
            return symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
        }

        public static ITypeSymbol GetTypeSymbol(this SemanticModel model, SyntaxNode node) => model.GetTypeInfo(node).Type;
    }
}
