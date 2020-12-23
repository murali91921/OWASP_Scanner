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
        private static readonly string ICollection_Type = "System.Collections.Generic.ICollection<T>";
        private static readonly string Enumerable_Type = "System.Linq.Enumerable";
        private static readonly string Array_Type = "System.Array";

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            _model = model;
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var binaryExpressions = syntaxNode.DescendantNodesAndSelf().OfType<BinaryExpressionSyntax>();
            foreach (var binaryExpression in binaryExpressions)
            {
                bool result = false;
                if (binaryExpression.IsKind(SyntaxKind.GreaterThanOrEqualExpression))
                    result = CheckCondition(binaryExpression.Left, binaryExpression.Right);
                else if (binaryExpression.IsKind(SyntaxKind.LessThanOrEqualExpression))
                    result = CheckCondition(binaryExpression.Right, binaryExpression.Left);
                else
                    continue;
                if (result)
                    syntaxNodes.Add(binaryExpression);
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.CollectionSizeOrArrayLength);
        }
        private bool CheckCondition(ExpressionSyntax expressionValueNode, ExpressionSyntax constantValueNode)
        {
            if (!IsConstantZero(constantValueNode))
                return false;

            var symbol = GetSymbol(expressionValueNode);
            if (symbol == null)
                return false;

            if (!IsCollectionType(symbol))
                return false;

            return true;
        }

        private bool IsConstantZero(ExpressionSyntax expression)
        {
            var constant = _model.GetConstantValue(expression.RemoveParenthesis());
            return constant.HasValue && (constant.Value is int) && (int)constant.Value == 0;
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
            && methodSymbol.ContainingType.ToString() == Enumerable_Type;

        private static bool IsArrayLengthProperty(ISymbol symbol) =>
            symbol is IPropertySymbol propertySymbol
            && propertySymbol.ContainingType.ToString() == Array_Type
            && (propertySymbol.Name == nameof(Array.Length) || propertySymbol.Name == "LongLength");

        private static bool IsCollectionProperty(ISymbol symbol) =>
            symbol is IPropertySymbol propertySymbol
            && Utils.ImplementsFrom(propertySymbol.ContainingType, ICollection_Type)
            && propertySymbol.Name == nameof(ICollection<object>.Count);

        private static bool HasExactlyNParameters(IMethodSymbol methodSymbol, int parametersCount) =>
            (methodSymbol.MethodKind == MethodKind.Ordinary && methodSymbol.Parameters.Length == parametersCount)
            || (methodSymbol.MethodKind == MethodKind.ReducedExtension && methodSymbol.Parameters.Length == parametersCount - 1);
    }
}