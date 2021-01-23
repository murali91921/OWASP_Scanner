using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class CollectionSizeOrArrayLengthScanner : IScanner
    {
        private SemanticModel _model;
        private readonly static string message = "The {0} of '{1}' is always '>=0', so fix this test to get the real expected behavior.";
        private List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
        private string _filePath;

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            _model = model;
            _filePath = filePath;
            var binaryExpressions = syntaxNode.DescendantNodesAndSelf().OfType<BinaryExpressionSyntax>();
            foreach (var binaryExpression in binaryExpressions)
            {
                if (binaryExpression.IsKind(SyntaxKind.GreaterThanOrEqualExpression))
                    CheckCondition(binaryExpression.Left, binaryExpression.Right, binaryExpression);
                else if (binaryExpression.IsKind(SyntaxKind.LessThanOrEqualExpression))
                    CheckCondition(binaryExpression.Right, binaryExpression.Left, binaryExpression);
            }
            return vulnerabilities;
        }
        private void CheckCondition(ExpressionSyntax expressionValueNode, ExpressionSyntax constantValueNode, BinaryExpressionSyntax parentExpression)
        {
            if (!IsConstantZero(constantValueNode))
                return;

            var symbol = GetSymbol(expressionValueNode);
            if (symbol == null || !IsCollectionType(symbol))
                return;

            var symbolType = GetDeclaringTypeName(symbol);
            if (symbolType == null)
                return;
            vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, parentExpression, Enums.ScannerType.CollectionSizeOrArrayLength,
                string.Format(message, symbol.Name, symbolType)));
        }

        private string GetDeclaringTypeName(ISymbol symbol)
            => IsArrayLengthProperty(symbol) ? "Array" :
            IsEnumerableCountMethod(symbol) ? "IEnumerable<T>" :
            IsCollectionProperty(symbol) ? "ICollection" : null;

        private bool IsConstantZero(ExpressionSyntax expression)
        {
            var constant = _model.GetConstantValue(expression.RemoveParenthesis());
            return constant.HasValue && (constant.Value is int value) && value == 0;
        }

        private ISymbol GetSymbol(ExpressionSyntax expression)
        {
            while (true)
            {
                if (!(expression is ConditionalAccessExpressionSyntax conditionalAccess))
                    break;
                expression = conditionalAccess.WhenNotNull;
            }
            return _model.GetSymbol(expression);
        }

        private bool IsCollectionType(ISymbol symbol) =>
            IsArrayLengthProperty(symbol) || IsEnumerableCountMethod(symbol) || IsCollectionProperty(symbol);

        private static bool IsEnumerableCountMethod(ISymbol symbol) =>
            symbol is IMethodSymbol methodSymbol
            && methodSymbol != null
            && methodSymbol.Name == nameof(Enumerable.Count)
            && (HasExactlyNParameters(methodSymbol, 1) || HasExactlyNParameters(methodSymbol, 2))
            && methodSymbol.ContainingType.ToString() == Constants.KnownType.System_Linq_Enumerable;

        private static bool IsArrayLengthProperty(ISymbol symbol) =>
            symbol is IPropertySymbol propertySymbol
            && propertySymbol.ContainingType.ToString() == Constants.KnownType.System_Array
            && (propertySymbol.Name == nameof(Array.Length) || propertySymbol.Name == "LongLength");

        private static bool IsCollectionProperty(ISymbol symbol) =>
            symbol is IPropertySymbol propertySymbol
            && Utils.ImplementsFrom(propertySymbol.ContainingType, Constants.KnownType.System_Collections_Generic_ICollection_T)
            && propertySymbol.Name == nameof(ICollection<object>.Count);

        private static bool HasExactlyNParameters(IMethodSymbol methodSymbol, int parametersCount) =>
            (methodSymbol.MethodKind == MethodKind.Ordinary && methodSymbol.Parameters.Length == parametersCount)
            || (methodSymbol.MethodKind == MethodKind.ReducedExtension && methodSymbol.Parameters.Length == parametersCount - 1);
    }
}