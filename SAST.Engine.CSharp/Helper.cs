using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;
using System;
using System.Linq;
using System.Collections.Generic;

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
        /// This method will remove Parenthesis
        /// </summary>
        /// <param name="expression"></param>
        /// <returns></returns>
        public static ExpressionSyntax RemoveParenthesis(this ExpressionSyntax expression)
        {
            return (ExpressionSyntax)RemoveParenthesis(expression as SyntaxNode);
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

        public static bool IsTypeKind(this SemanticModel model, ExpressionSyntax expression, TypeKind typeKind)
        {
            var type = model.GetTypeInfo(expression).Type;
            return type != null && type.TypeKind == typeKind;
        }

        public static ITypeSymbol GetTypeSymbol(this ISymbol symbol)
        {
            if (symbol == null)
                return null;
            if (symbol is IFieldSymbol fieldSymbol)
                return fieldSymbol.Type;
            if (symbol is ILocalSymbol localSymbol)
                return localSymbol.Type;
            if (symbol is IPropertySymbol propertySymbol)
                return propertySymbol.Type;
            return null;
        }

        public static ITypeSymbol GetSymbolType(this ISymbol symbol)
        {
            if (symbol is ILocalSymbol localSymbol)
                return localSymbol.Type;
            else if (symbol is IFieldSymbol fieldSymbol)
                return fieldSymbol.Type;
            else if (symbol is IPropertySymbol propertySymbol)
                return propertySymbol.Type;
            else if (symbol is IParameterSymbol parameterSymbol)
                return parameterSymbol.Type;
            else if (symbol is IAliasSymbol aliasSymbol)
                return aliasSymbol.Target as ITypeSymbol;
            else
                return symbol as ITypeSymbol;
        }

        public static string GetName(this ExpressionSyntax expression) =>
        expression switch
        {
            MemberBindingExpressionSyntax memberBinding => memberBinding.Name.Identifier.ValueText,
            MemberAccessExpressionSyntax memberAccess => memberAccess.Name.Identifier.ValueText,
            IdentifierNameSyntax identifierName => identifierName.Identifier.ValueText,
            _ => string.Empty
        };

        public static string JoinStr<T>(this IEnumerable<T> enumerable, string separator, Func<T, string> selector) =>
            string.Join(separator, enumerable.Select(x => selector(x)));

        public static SyntaxNode GetFirstNonParenthesizedParent(this SyntaxNode node) =>
            node.GetSelfOrTopParenthesizedExpression().Parent;

        public static SyntaxNode GetSelfOrTopParenthesizedExpression(this SyntaxNode node)
        {
            var current = node;
            while (current?.Parent?.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.ParenthesizedExpression) ?? false)
                current = current.Parent;
            return current;
        }

        public static ExpressionSyntax GetSelfOrTopParenthesizedExpression(this ExpressionSyntax node) =>
             (ExpressionSyntax)GetSelfOrTopParenthesizedExpression((SyntaxNode)node);

        public static SyntaxToken? GetMethodCallIdentifier(this InvocationExpressionSyntax invocation)
        {
            if (invocation == null)
                return null;
            var expression = invocation.Expression;
            switch (expression.Kind())
            {
                case Microsoft.CodeAnalysis.CSharp.SyntaxKind.IdentifierName:
                    return ((IdentifierNameSyntax)expression).Identifier;
                case Microsoft.CodeAnalysis.CSharp.SyntaxKind.SimpleMemberAccessExpression:
                    return ((MemberAccessExpressionSyntax)expression).Name.Identifier;
                case Microsoft.CodeAnalysis.CSharp.SyntaxKind.MemberBindingExpression:
                    return ((MemberBindingExpressionSyntax)expression).Name.Identifier;
                default:
                    return null;
            }
        }

        public static bool IsPrimitiveType(this ITypeSymbol type)
        {
            return type.SpecialType switch
            {
                var specType when
                specType is SpecialType.System_Boolean ||
                specType is SpecialType.System_Byte ||
                specType is SpecialType.System_Char ||
                specType is SpecialType.System_Double ||
                specType is SpecialType.System_Int16 ||
                specType is SpecialType.System_Int32 ||
                specType is SpecialType.System_Int64 ||
                specType is SpecialType.System_UInt16 ||
                specType is SpecialType.System_UInt32 ||
                specType is SpecialType.System_UInt64 ||
                specType is SpecialType.System_IntPtr ||
                specType is SpecialType.System_UIntPtr ||
                specType is SpecialType.System_SByte ||
                specType is SpecialType.System_Single => true,
                _ => false,
            };
        }
    }
}
