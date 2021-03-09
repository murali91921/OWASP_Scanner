using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace SAST.Engine.CSharp.Scanners
{
    internal class ClearTextProtocolScanner : IScanner
    {
        private readonly List<VulnerabilityDetail> _vulnerabilities = new List<VulnerabilityDetail>();
        private string _filePath;
        private const string _messageFormat = "Using {0} protocol is insecure. Use {1} instead.";
        private const string _enableSslMessage = "EnableSsl should be set to true.";
        private const string _validServerPattern = "localhost|127.0.0.1|::1";
        private const string TelnetKey = "telnet";
        private const string EnableSslName = "EnableSsl";
        private static readonly Regex _httpRegex = CompileRegex(@$"^http:\/\/(?!{_validServerPattern}).");
        private static readonly Regex _ftpRegex = CompileRegex(@$"^ftp:\/\/.*@(?!{_validServerPattern})");
        private static readonly Regex _telnetRegex = CompileRegex(@$"^telnet:\/\/.*@(?!{_validServerPattern})");
        private static readonly Regex _telnetRegexForIdentifier = CompileRegex(@"Telnet(?![a-z])", false);
        private static readonly Dictionary<string, string> recommendedProtocols = new Dictionary<string, string>
        {
            {"telnet", "ssh"},
            {"ftp", "sftp, scp or ftps"},
            {"http", "https"},
            {"clear-text SMTP", "SMTP over SSL/TLS or SMTP with STARTTLS" }
        };

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            _filePath = filePath;

            var syntaxNodes = syntaxNode.DescendantNodesAndSelf().Where(node =>
            node.IsKind(SyntaxKind.StringLiteralExpression) || node.IsKind(SyntaxKind.InterpolatedStringExpression)
            || node.IsKind(SyntaxKind.ObjectCreationExpression)
            || node.IsKind(SyntaxKind.InvocationExpression)
            || node.IsKind(SyntaxKind.SimpleAssignmentExpression));
            foreach (var item in syntaxNodes)
            {
                if (item is InterpolatedStringExpressionSyntax interpolatedStringExpression)
                    VisitStringExpression(item);
                else if (item is LiteralExpressionSyntax literalExpression)
                    VisitStringExpression(item);
                else if (item is ObjectCreationExpressionSyntax objectCreation)
                    VisitObjectCreation(objectCreation);
                else if (item is InvocationExpressionSyntax invocationExpression)
                    VisitInvocationExpression(invocationExpression);
                else if (item is AssignmentExpressionSyntax assignmentExpression)
                    VisitAssignment(model, assignmentExpression);
            }
            return _vulnerabilities;
        }

        private void VisitStringExpression(SyntaxNode syntaxNode)
        {
            var text = GetText(syntaxNode);
            if (GetUnsafeProtocol(text) is { } unsafeProtocol)
                _vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, syntaxNode, Enums.ScannerType.ClearTextProtocol,
                     string.Format(_messageFormat, unsafeProtocol, recommendedProtocols[unsafeProtocol])));
        }

        private void VisitObjectCreation(ObjectCreationExpressionSyntax objectCreation)
        {
            if (_telnetRegexForIdentifier.IsMatch(objectCreation.Type.ToString()))
                _vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, objectCreation, Enums.ScannerType.ClearTextProtocol,
                    string.Format(_messageFormat, TelnetKey, recommendedProtocols[TelnetKey])));
        }

        private void VisitInvocationExpression(InvocationExpressionSyntax invocation)
        {
            if (_telnetRegexForIdentifier.IsMatch(invocation.Expression.ToString()))
                _vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, invocation, Enums.ScannerType.ClearTextProtocol,
                    string.Format(_messageFormat, TelnetKey, recommendedProtocols[TelnetKey])));
        }

        private void VisitAssignment(SemanticModel model, AssignmentExpressionSyntax assignment)
        {
            if (assignment.IsKind(SyntaxKind.SimpleAssignmentExpression)
                && assignment.Left is MemberAccessExpressionSyntax memberAccess
                && memberAccess.Name.ToString() == EnableSslName
                && model.GetSymbol(memberAccess) is { } symbol
                && Utils.DerivesFrom(symbol.ContainingType, Constants.KnownType.System_Net_FtpWebRequest)
                && model.GetConstantValue(assignment.Right).Value is bool enableSslValue
                && !enableSslValue)
            {
                _vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, assignment, Enums.ScannerType.ClearTextProtocol,
                    _enableSslMessage));
            }
        }

        private static string GetText(SyntaxNode node) =>
            node switch
            {
                InterpolatedStringExpressionSyntax interpolatedStringExpression => interpolatedStringExpression.Contents.JoinStr("", content => content.ToString()),
                LiteralExpressionSyntax literalExpression => literalExpression.Token.ValueText,
                _ => string.Empty
            };

        private static string GetUnsafeProtocol(string text) =>
            _httpRegex.IsMatch(text) ? "http" : _ftpRegex.IsMatch(text) ? "ftp" : _telnetRegex.IsMatch(text) ? "telnet" : null;

        private static Regex CompileRegex(string pattern, bool ignoreCase = true) =>
            new Regex(pattern, ignoreCase ? RegexOptions.Compiled | RegexOptions.IgnoreCase : RegexOptions.Compiled);
    }
}