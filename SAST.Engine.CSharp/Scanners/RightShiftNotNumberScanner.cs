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
    internal class RightShiftNotNumberScanner : IScanner
    {
        SemanticModel _model = null;
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var binaryExpressions = syntaxNode.DescendantNodesAndSelf()
                .Where(expr => expr.IsKind(SyntaxKind.LeftShiftExpression) || expr.IsKind(SyntaxKind.RightShiftExpression))
                .OfType<BinaryExpressionSyntax>();
            var assignmentExpressions = syntaxNode.DescendantNodesAndSelf()
                .Where(expr => expr.IsKind(SyntaxKind.LeftShiftAssignmentExpression) || expr.IsKind(SyntaxKind.RightShiftAssignmentExpression))
                .OfType<AssignmentExpressionSyntax>();
            _model = model;

            foreach (var binary in binaryExpressions)
                if (CheckExpression(binary.Left, binary.Right))
                    syntaxNodes.Add(binary.Right);

            foreach (var assignment in assignmentExpressions)
                if (CheckExpression(assignment.Left, assignment.Right))
                    syntaxNodes.Add(assignment.Right);

            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.RightShiftNotNumber);
        }

        private bool CheckExpression(ExpressionSyntax left, ExpressionSyntax right)
            => !_model.IsTypeKind(right, TypeKind.Error) && NotInteger(_model, left, right);

        private static bool NotInteger(SemanticModel model, ExpressionSyntax left, ExpressionSyntax right)
            => model.IsTypeKind(left, TypeKind.Dynamic) && !IsConvertibleToInt(right, model);

        private static bool CanBeConvertedTo(ExpressionSyntax expression, ITypeSymbol type, SemanticModel model)
        {
            var conversion = model.ClassifyConversion(expression, type);
            return conversion.Exists && (conversion.IsIdentity || conversion.IsImplicit);
        }

        private static bool IsConvertibleToInt(ExpressionSyntax expression, SemanticModel model)
        {
            var intType = model.Compilation.GetTypeByMetadataName("System.Int32");
            return intType != null && CanBeConvertedTo(expression, intType, model);
        }
    }
}