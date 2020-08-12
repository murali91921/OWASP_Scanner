using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using static System.Console;

namespace ASTTask
{
    internal static class SyntaxNodeAnalyzerFactory
    {
        internal static ISyntaxNodeAnalyzer Create(SyntaxNode syntax)
        {
            switch (syntax)
            {
                case ArgumentListSyntax _:
                    return new ArgumentListSyntaxAnalyzer();
                case ArgumentSyntax _:
                    return new ArgumentSyntaxNodeAnalyzer();
                case BinaryExpressionSyntax _:
                    return new BinaryExpressionSyntaxAnalyzer();
                case ConditionalExpressionSyntax _:
                    return new ConditionalExpressionSyntaxAnalyzer();
                case ElementAccessExpressionSyntax _:
                    return new ElementAccessExpressionSyntaxAnalyzer();
                case IdentifierNameSyntax _:
                    return new IdentifierNameSyntaxAnalyzer();
                case InvocationExpressionSyntax _:
                    return new InvocationExpressionSyntaxAnalyzer();
                case LiteralExpressionSyntax _:
                    return new LiteralExpressionSyntaxAnalyzer();
                case MemberAccessExpressionSyntax _:
                    return new MemberAccessExpressionSyntaxAnalyzer();
                case ParameterSyntax _:
                    return new ParameterSyntaxNodeAnalyzer();
                case QueryExpressionSyntax _:
                    return new QueryExpressionSyntaxAnalyzer();
            }
            return new BaseSyntaxNodeAnalyzer<SyntaxNode>();
        }
    }
}