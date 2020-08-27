using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp.Enums;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Core
{
    internal class NodeFactory
    {
        public NodeFactory(Solution solution) => _solution = solution;

        private Solution _solution;

        private static List<Tuple<ScannerType, string>> _Injectables = new List<Tuple<ScannerType, string>> {
            new Tuple<ScannerType, string>(ScannerType.XSS,"System.Web.HttpRequest.QueryString"),
        };
        private static List<Tuple<ScannerType, string>> _SanitizedMethods = new List<Tuple<ScannerType, string>> {
            new Tuple<ScannerType, string>(ScannerType.XSS,"System.Text.Encodings.Web.TextEncoder.Encode"),
            new Tuple<ScannerType, string>(ScannerType.XSS,"System.Web.HttpServerUtility.HtmlEncode"),
            new Tuple<ScannerType, string>(ScannerType.XSS,"System.Web.HttpUtility.HtmlEncode"),
            new Tuple<ScannerType, string>(ScannerType.XSS,"System.Web.Security.AntiXss.AntiXssEncoder.HtmlEncode"),
            new Tuple<ScannerType, string>(ScannerType.XSS,"System.Web.HttpServerUtility.UrlPathEncode"),
            new Tuple<ScannerType, string>(ScannerType.XSS,"System.Web.HttpUtility.UrlPathEncode"),
            new Tuple<ScannerType, string>(ScannerType.XSS,"System.Web.Security.AntiXss.AntiXssEncoder.UrlEncode"),
        };
        public bool IsVulnerable(SyntaxNode node, SemanticModel model, ISymbol callingSymbol = null)
        {
            if (node is IdentifierNameSyntax)
            {
                ITypeSymbol type = model.GetTypeInfo(node).Type;
                if (type == null)
                    return false;
                if (type.ToString() != "string" && type.ToString() != "System.String" && type.ToString() != "System.IO.StringWriter")
                    return false;
                bool vulnerable = false;
                SymbolInfo symbolInfo = model.GetSymbolInfo(node);
                ISymbol symbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                if (symbol == null || symbol.Equals(callingSymbol, SymbolEqualityComparer.Default))
                    return false;
                if (_solution != null)
                {
                    var references = SymbolFinder.FindReferencesAsync(symbol, _solution).Result;
                    foreach (var reference in references)
                    {
                        var currentNode = node.SyntaxTree.GetRoot().FindNode(reference.Definition.Locations.First().SourceSpan);
                        vulnerable = IsVulnerable(currentNode, model, null);
                        foreach (var refLocation in reference.Locations)
                        {
                            currentNode = node.SyntaxTree.GetRoot().FindNode(refLocation.Location.SourceSpan);
                            if (Utils.CheckSameMethod(currentNode, node) && currentNode.SpanStart < node.SpanStart)
                            {
                                var assignment = currentNode.Ancestors().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                                if (assignment != null)
                                {
                                    if (currentNode.SpanStart < assignment.Right.SpanStart)
                                        vulnerable = IsVulnerable(assignment.Right, model, symbol);
                                }
                                else
                                {
                                    var invocation = currentNode.Ancestors().OfType<InvocationExpressionSyntax>().FirstOrDefault();
                                    if (invocation == null || invocation.ArgumentList.Arguments.Count() == 1)
                                        continue;
                                    vulnerable = !IsSanitized(invocation, model, ScannerType.XSS);
                                }
                            }
                        }
                    }
                }
                return vulnerable;
            }
            else if (node is BinaryExpressionSyntax)
            {
                var left = IsVulnerable((node as BinaryExpressionSyntax).Left, model, callingSymbol);
                var right = IsVulnerable((node as BinaryExpressionSyntax).Right, model, callingSymbol);
                return left || right;
            }
            else if (node is VariableDeclaratorSyntax && (node as VariableDeclaratorSyntax).Initializer != null)
                return IsVulnerable((node as VariableDeclaratorSyntax).Initializer.Value, model);
            else if (node is AssignmentExpressionSyntax)
                return IsVulnerable((node as AssignmentExpressionSyntax).Right, model, null);
            else if (node is InterpolatedStringExpressionSyntax)
            {
                bool vulnerable = false;
                var contents = (node as InterpolatedStringExpressionSyntax).Contents.OfType<InterpolationSyntax>();
                foreach (var item in contents)
                    vulnerable = vulnerable || IsVulnerable(item.Expression, model, callingSymbol);
                return vulnerable;
            }
            else if (node is ElementAccessExpressionSyntax)
                return IsVulnerable((node as ElementAccessExpressionSyntax).Expression, model);
            else if (node is MemberAccessExpressionSyntax)
                return IsInjectable(node, model, ScannerType.XSS);
            else if (node is InvocationExpressionSyntax)
            {
                var invocation = node as InvocationExpressionSyntax;
                SymbolInfo symbolInfo = model.GetSymbolInfo(invocation);
                ISymbol symbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                if (symbol == null)
                    return false;
                if (symbol.Name == "ToString" && symbol.ContainingType.ToString() == "System.IO.StringWriter")
                {
                    var identifier = (invocation.Expression as MemberAccessExpressionSyntax).Expression;
                    return IsVulnerable(identifier, model);
                }
                else
                    return !IsSanitized(invocation, model, ScannerType.XSS);
            }
            else if (node is ParameterSyntax)
                return true;
            else
                return false;
        }
        

        internal static bool IsSanitized(InvocationExpressionSyntax node, SemanticModel model, ScannerType scannerType)
        {
            if (node is null)
                return false;
            ISymbol symbol = null;
            SymbolInfo symbolInfo = model.GetSymbolInfo(node);
            symbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
            if (symbol == null)
                return false;
            string method = symbol.ContainingType.ToString() + "." + symbol.Name.ToString();
            return GetSanitizedMethods(scannerType).Any(obj => obj == method);
        }

        private static bool IsInjectable(SyntaxNode node, SemanticModel model, ScannerType scannerType)
        {
            if (node is MemberAccessExpressionSyntax)
            {
                ISymbol symbol = null;
                SymbolInfo symbolInfo = model.GetSymbolInfo(node);
                symbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                if (symbol == null)
                    return false;
                string property = symbol.ContainingType.ToString() + "." + symbol.Name.ToString();
                return GetInjectableProperties(scannerType).Any(obj => obj == property);
            }
            return false;
        }

        internal static IEnumerable<string> GetInjectableProperties(ScannerType scannerType) => _Injectables.Where(obj => obj.Item1 == scannerType).Select(obj => obj.Item2).ToList();


        internal static IEnumerable<string> GetSanitizedMethods(ScannerType scannerType) => _SanitizedMethods.Where(obj => obj.Item1 == scannerType).Select(obj => obj.Item2).ToList();
    }
}