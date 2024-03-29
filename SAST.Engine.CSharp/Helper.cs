﻿using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;
using System;
using System.Linq;
using System.Collections.Generic;
using Microsoft.CodeAnalysis.CSharp;
using System.Text;

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
            else if (symbol is IParameterSymbol parameterSymbol)
                return parameterSymbol.Type;
            else if (symbol is IAliasSymbol aliasSymbol)
                return aliasSymbol.Target as ITypeSymbol;
            else
                return symbol as ITypeSymbol;
        }

        //public static ITypeSymbol GetSymbolType(this ISymbol symbol)
        //{
        //    if (symbol is ILocalSymbol localSymbol)
        //        return localSymbol.Type;
        //    else if (symbol is IFieldSymbol fieldSymbol)
        //        return fieldSymbol.Type;
        //    else if (symbol is IPropertySymbol propertySymbol)
        //        return propertySymbol.Type;
        //    else if (symbol is IParameterSymbol parameterSymbol)
        //        return parameterSymbol.Type;
        //    else if (symbol is IAliasSymbol aliasSymbol)
        //        return aliasSymbol.Target as ITypeSymbol;
        //    else
        //        return symbol as ITypeSymbol;
        //}

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

        public static string JoinStr<T>(this IEnumerable<T> enumerable, string separator) =>
            string.Join(separator, enumerable.Select(x => x));

        public static SyntaxNode GetFirstNonParenthesizedParent(this SyntaxNode node) =>
            node.GetSelfOrTopParenthesizedExpression().Parent;

        public static SyntaxNode GetSelfOrTopParenthesizedExpression(this SyntaxNode node)
        {
            var current = node;
            while (current?.Parent?.IsKind(SyntaxKind.ParenthesizedExpression) ?? false)
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
            return (expression.Kind()) switch
            {
                SyntaxKind.IdentifierName => ((IdentifierNameSyntax)expression).Identifier,
                SyntaxKind.SimpleMemberAccessExpression => ((MemberAccessExpressionSyntax)expression).Name.Identifier,
                SyntaxKind.MemberBindingExpression => ((MemberBindingExpressionSyntax)expression).Name.Identifier,
                _ => null,
            };
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

        internal static bool IsNonStaticNonPublicDisposableField(this IFieldSymbol fieldSymbol) =>
            fieldSymbol != null &&
            !fieldSymbol.IsStatic &&
            (fieldSymbol.DeclaredAccessibility == Accessibility.Protected || fieldSymbol.DeclaredAccessibility == Accessibility.Private) &&
            IsDisposable(fieldSymbol);

        private static bool IsDisposable(this IFieldSymbol fieldSymbol) =>
            Utils.ImplementsFromAny(fieldSymbol.Type, Disposable_Type) ||
            fieldSymbol.Type.IsDisposableRefStruct();

        internal static bool IsDisposableRefStruct(this ITypeSymbol symbol) =>
            IsRefStruct(symbol) &&
            symbol.GetMembers("Dispose").Any(s => s is IMethodSymbol method && method.IsDisposeMethod());

        internal static bool IsRefStruct(this ITypeSymbol symbol) =>
            symbol != null &&
            symbol.TypeKind == TypeKind.Struct &&
            symbol.DeclaringSyntaxReferences.Length == 1 &&
            symbol.DeclaringSyntaxReferences[0].GetSyntax() is StructDeclarationSyntax structDeclaration &&
            structDeclaration.Modifiers.Any(Microsoft.CodeAnalysis.CSharp.SyntaxKind.RefKeyword);

        internal static bool IsDisposeMethod(this IMethodSymbol symbol) =>
            symbol.Name.Equals("Dispose") &&
            symbol.Arity == 0 &&
            symbol.Parameters.Length == 0 &&
            symbol.ReturnsVoid &&
            symbol.DeclaredAccessibility == Accessibility.Public;

        private static readonly string[] Disposable_Type = { Constants.KnownType.System_IDisposable, Constants.KnownType.System_IAsyncDisposable };

        internal static bool IsAnyKind(this SyntaxNode syntaxNode, SyntaxKind[] syntaxKinds) =>
            syntaxNode != null && syntaxKinds.Contains((SyntaxKind)syntaxNode.RawKind);

        internal static string GetStringValue(this SyntaxNode node) =>
            node != null &&
            node.IsKind(SyntaxKind.StringLiteralExpression) &&
            node is LiteralExpressionSyntax literal ? literal.Token.ValueText : null;

        internal static IEnumerable<string> SplitToWords(this string name)
        {
            bool IsFollowedByLower(int i) => i + 1 < name.Length && char.IsLower(name[i + 1]);
            if (name == null)
                yield break;
            var currentWord = new StringBuilder();
            var hasLower = false;

            for (var i = 0; i < name.Length; i++)
            {
                var c = name[i];
                if (!char.IsLetter(c))
                {
                    if (currentWord.Length > 0)
                    {
                        yield return currentWord.ToString();
                        currentWord.Clear();
                        hasLower = false;
                    }
                    continue;
                }

                if (char.IsUpper(c) && currentWord.Length > 0 && (hasLower || IsFollowedByLower(i)))
                {
                    yield return currentWord.ToString();
                    currentWord.Clear();
                    hasLower = false;
                }
                currentWord.Append(char.ToUpperInvariant(c));
                hasLower = hasLower || char.IsLower(c);
            }
            if (currentWord.Length > 0)
                yield return currentWord.ToString();
        }

        internal static SyntaxNode GetTopMostContainingMethod(this SyntaxNode node) =>
            node.AncestorsAndSelf().LastOrDefault(ancestor => ancestor is BaseMethodDeclarationSyntax || ancestor is PropertyDeclarationSyntax);

        public static bool IsMethodInvocation(this InvocationExpressionSyntax invocation, string type, string methodName, SemanticModel semanticModel) =>
            invocation.Expression.GetName() == methodName &&
            semanticModel.GetSymbol(invocation) is IMethodSymbol methodSymbol &&
            methodSymbol != null &&
            (methodSymbol.ContainingType.ToDisplayString() == type || methodSymbol.ContainingType.OriginalDefinition.ToDisplayString() == type);
    }
}
