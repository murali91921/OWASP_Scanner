﻿using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using System.Linq;

namespace SAST.Engine.CSharp
{
    /// <summary>
    /// This class consists of Extension Methods used in application
    /// </summary>
    internal static class HelperExtrensions
    {
        /// <summary>
        /// This method will remove Parenthesis
        /// </summary>
        /// <param name="expression"></param>
        /// <returns></returns>
        public static SyntaxNode RemoveParenthesis(this SyntaxNode expression)
        {
            var currentExpression = expression;
            var parenthesis = expression as ParenthesizedExpressionSyntax;
            while (parenthesis != null)
            {
                currentExpression = parenthesis.Expression;
                parenthesis = currentExpression as ParenthesizedExpressionSyntax;
            }
            return currentExpression;
        }

        /// <summary>
        /// This method will give Line Number & Character Position for<paramref name="linePosition"/> object
        /// </summary>
        /// <param name="linePosition"></param>
        /// <returns>Line Number & Character Position as Cancatenated string</returns>
        public static string ToLineString(this LinePosition linePosition) => (linePosition.Line + 1) + "," + (linePosition.Character + 1);

        /// <summary>
        /// This Method will give ISymbol for <paramref name="node"/>
        /// </summary>
        /// <param name="model"></param>
        /// <param name="node"></param>
        /// <returns></returns>
        public static ISymbol GetSymbol(this SemanticModel model, SyntaxNode node)
        {
            SymbolInfo symbolInfo = model.GetSymbolInfo(node);
            return symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
        }

        /// <summary>
        /// This method will give ITypeSymbol of <paramref name="node"/>
        /// </summary>
        /// <param name="model"></param>
        /// <param name="node"></param>
        /// <returns></returns>
        public static ITypeSymbol GetTypeSymbol(this SemanticModel model, SyntaxNode node) => model.GetTypeInfo(node).Type;

        public static string GetName(this ExpressionSyntax expression) =>
        expression switch
        {
            MemberAccessExpressionSyntax memberAccess => memberAccess.Name.Identifier.ValueText,
            IdentifierNameSyntax identifierName => identifierName.Identifier.ValueText,
            _ => string.Empty
        };

    }
}
