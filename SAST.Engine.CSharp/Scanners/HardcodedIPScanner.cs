using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class HardcodedIPScanner : IScanner
    {
        private static readonly string[] IgnoredVariableNames =
        {
            "VERSION",
            "ASSEMBLY",
        };

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var literalExpressions = syntaxNode.DescendantNodesAndSelf().OfType<LiteralExpressionSyntax>();
            foreach (var item in literalExpressions)
            {
                try
                {
                    if (!item.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.StringLiteralExpression))
                        continue;
                    var literalValue = GetValueText(item);

                    if (literalValue == "::" || literalValue == "127.0.0.1" || !IPAddress.TryParse(literalValue, out var address))
                        continue;

                    if (address.AddressFamily == AddressFamily.InterNetwork && literalValue.Split('.').Length != 4)
                        continue;

                    var variableName = GetAssignedVariableName(item);
                    if (variableName != null && IgnoredVariableNames.Any(variableName.Contains))
                        continue;

                    if (HasAttributes(item))
                        continue;
                    syntaxNodes.Add(item);
                }
                catch { }
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.HardcodedIpAddress);
        }

        private static string GetAssignedVariableName(LiteralExpressionSyntax stringLiteral) =>
            stringLiteral.FirstAncestorOrSelf<SyntaxNode>(IsVariableIdentifier)?.ToString().ToUpperInvariant();

        private static string GetValueText(LiteralExpressionSyntax literalExpression) =>
            literalExpression.Token.ValueText;

        private static bool IsVariableIdentifier(SyntaxNode syntaxNode) =>
          syntaxNode is StatementSyntax ||
          syntaxNode is VariableDeclaratorSyntax ||
          syntaxNode is ParameterSyntax;

        private static bool HasAttributes(LiteralExpressionSyntax literalExpression) =>
            literalExpression.Ancestors().Any(expr => expr.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.Attribute));
    }
}