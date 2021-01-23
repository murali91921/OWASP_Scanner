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
    internal class SqlKeywordDelimitScanner : IScanner
    {
        private List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
        private readonly static string message = "Add a space before '{0}'.";
        public string _filePath;
        private static readonly IList<string> SqlStartQueryKeywords = new List<string>()
        {
            "ALTER",
            "BULK INSERT",
            "CREATE",
            "DELETE",
            "DROP",
            "EXEC",
            "EXECUTE",
            "GRANT",
            "INSERT",
            "MERGE",
            "READTEXT",
            "SELECT",
            "TRUNCATE",
            "UPDATE",
            "UPDATETEXT",
            "WRITETEXT"
        };
        private static readonly int SqlKeywordMinSize = SqlStartQueryKeywords
           .Select(s => s.Length)
           .OrderBy(i => i)
           .First();

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            _filePath = filePath;
            var binaryExpressions = syntaxNode.DescendantNodesAndSelf().OfType<BinaryExpressionSyntax>();
            foreach (var binaryExpression in binaryExpressions)
            {
                CheckBinary(binaryExpression);
            }
            return vulnerabilities;
        }

        public void CheckBinary(BinaryExpressionSyntax node)
        {
            if (node.IsKind(SyntaxKind.AddExpression) &&
                TryGetStringWrapper(node.Left, out var leftSide) &&
                TryGetStringWrapper(node.Right, out var rightSide) &&
                StartsWithSqlKeyword(leftSide.Text.Trim()))
            {
                var strings = new List<StringWrapper>
                {
                    leftSide,
                    rightSide
                };
                var onlyStringsInConcatenation = AddStringsToList(node, strings);
                if (!onlyStringsInConcatenation)
                    return;
                CheckSpaceBetweenStrings(strings);
            }
        }

        private void CheckSpaceBetweenStrings(List<StringWrapper> stringWrappers)
        {
            for (var i = 0; i < stringWrappers.Count - 1; i++)
            {
                var firstStringText = stringWrappers[i].Text;
                var secondString = stringWrappers[i + 1];
                var secondStringText = secondString.Text;
                if (firstStringText.Length > 0 && IsAlphaNumericOrAt(firstStringText.ToCharArray().Last()) &&
                    secondStringText.Length > 0 && IsAlphaNumericOrAt(secondStringText[0]))
                {
                    var word = secondStringText.Split(' ').FirstOrDefault();
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, secondString.Node, Enums.ScannerType.SqlKeywordDelimit, string.Format(message, word)));
                }
            }
        }

        private static bool TryGetStringWrapper(ExpressionSyntax expression, out StringWrapper stringWrapper)
        {
            if (expression is LiteralExpressionSyntax literal && literal.IsKind(SyntaxKind.StringLiteralExpression))
            {
                stringWrapper = new StringWrapper(literal, literal.Token.ValueText);
                return true;
            }
            else if (expression is InterpolatedStringExpressionSyntax interpolatedString)
            {
                var interpolatedStringText = interpolatedString.Contents.JoinStr("", content => content.ToString());
                stringWrapper = new StringWrapper(interpolatedString, interpolatedStringText);
                return true;
            }

            stringWrapper = null;
            return false;
        }

        /**
         * Returns
         * - true if all the found elements are string literals.
         * - false if, inside the chain of binary expressions, some elements are not string literals or
         * some binary expressions are not additions.
         */
        private static bool AddStringsToList(BinaryExpressionSyntax node, List<StringWrapper> strings)
        {
            // this is the left-most node of a concatenation chain
            // collect all string literals
            var parent = node.Parent;
            while (parent is BinaryExpressionSyntax concatenation)
            {
                if (concatenation.IsKind(SyntaxKind.AddExpression) &&
                    TryGetStringWrapper(concatenation.Right, out var stringWrapper))
                    strings.Add(stringWrapper);
                else
                    return false;
                parent = parent.Parent;
            }
            return true;
        }

        private static bool StartsWithSqlKeyword(string firstString) =>
            firstString.Length >= SqlKeywordMinSize &&
            SqlStartQueryKeywords.Any(s => firstString.StartsWith(s, StringComparison.OrdinalIgnoreCase));

        /**
         * The '@' symbol is used for named parameters. The '{' and '}' symbols are used in string interpolations.
         * We ignore other non-alphanumeric characters (e.g. '>','=') to avoid false positives.
         */
        private static bool IsAlphaNumericOrAt(char c) => char.IsLetterOrDigit(c) || c == '@' || c == '{' || c == '}';

        private class StringWrapper
        {
            public SyntaxNode Node { get; }
            public string Text { get; }

            internal StringWrapper(SyntaxNode node, string text)
            {
                Node = node;
                Text = text;
            }
        }
    }
}