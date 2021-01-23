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
        private readonly static string message = "Remove this erroneous shift, it will fail because {0} can't be implicitly converted to int.";
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var binaryExpressions = syntaxNode.DescendantNodesAndSelf()
                .Where(expr => expr.IsKind(SyntaxKind.LeftShiftExpression) || expr.IsKind(SyntaxKind.RightShiftExpression))
                .OfType<BinaryExpressionSyntax>();
            var assignmentExpressions = syntaxNode.DescendantNodesAndSelf()
                .Where(expr => expr.IsKind(SyntaxKind.LeftShiftAssignmentExpression) || expr.IsKind(SyntaxKind.RightShiftAssignmentExpression))
                .OfType<AssignmentExpressionSyntax>();
            _model = model;

            foreach (var binary in binaryExpressions)
                if (CheckExpression(binary.Left, binary.Right))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, binary.Right, Enums.ScannerType.RightShiftNotNumber,
                        string.Format(message, binary.Right)));

            foreach (var assignment in assignmentExpressions)
                if (CheckExpression(assignment.Left, assignment.Right))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, assignment.Right, Enums.ScannerType.RightShiftNotNumber,
                        string.Format(message, assignment.Right)));

            return vulnerabilities;
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
            var intType = model.Compilation.GetTypeByMetadataName(Constants.KnownType.System_Int32);
            return intType != null && CanBeConvertedTo(expression, intType, model);
        }
    }
}