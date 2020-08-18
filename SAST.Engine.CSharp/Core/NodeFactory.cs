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
            //new Tuple<ScannerType, string>(ScannerType.XSS,"System.Web.HttpRequest.QueryString")
            //new Tuple<ScannerType, string>(ScannerType.XSS,"System.Web.HttpRequest.QueryString")
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
            //if (solution != null)
            //    _solution = solution;
            if (node is IdentifierNameSyntax)
            {
                ITypeSymbol type = model.GetTypeInfo(node).Type;
                if (type == null)
                    return false;
                if (type.ToString() != "string" && type.ToString() != "System.String" && type.ToString() != "System.IO.StringWriter")
                    return false;

                bool vulnerable = false;
                ISymbol symbol = model.GetSymbolInfo(node).Symbol;
                if (symbol == null)
                    return false;
                if (symbol.Equals(callingSymbol, SymbolEqualityComparer.Default))
                    return false;
                //symol
                if (_solution != null)
                {
                    var references = SymbolFinder.FindReferencesAsync(symbol, _solution).Result;
                    foreach (var reference in references)
                    {
                        var currentNode = node.SyntaxTree.GetRoot().FindNode(reference.Definition.Locations.First().SourceSpan);
                        vulnerable = IsVulnerable(currentNode, model, null);
                        // vulnerable = vulnerable || retVulnerable;
                        foreach (var refLocation in reference.Locations)
                        {
                            currentNode = node.SyntaxTree.GetRoot().FindNode(refLocation.Location.SourceSpan);
                            if (CheckSameBlock(currentNode, node) && currentNode.SpanStart < node.SpanStart)
                            {
                                // WriteLine(currentNode.Parent.Parent);

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
            {
                return IsVulnerable((node as VariableDeclaratorSyntax).Initializer.Value, model);
            }
            else if (node is AssignmentExpressionSyntax)
            {
                return IsVulnerable((node as AssignmentExpressionSyntax).Right, model, null);
            }
            else if (node is InterpolatedStringExpressionSyntax)
            {
                bool vulnerable = false;
                var contents = (node as InterpolatedStringExpressionSyntax).Contents.OfType<InterpolationSyntax>();
                foreach (var item in contents)
                {
                    vulnerable = vulnerable || IsVulnerable(item.Expression, model, callingSymbol);
                }
                return vulnerable;
            }
            else if (node is ElementAccessExpressionSyntax)
                return IsVulnerable((node as ElementAccessExpressionSyntax).Expression, model);
            else if (node is MemberAccessExpressionSyntax)
                return IsInjectable(node, model, ScannerType.XSS);
            else if (node is LiteralExpressionSyntax)
                return false;
            else if (node is InvocationExpressionSyntax)
            {
                var invocation = node as InvocationExpressionSyntax;
                SymbolInfo symbolInfo = model.GetSymbolInfo(invocation);
                ISymbol symbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.First();
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
        private bool CheckSameBlock(SyntaxNode first, SyntaxNode second)
        {
            MethodDeclarationSyntax block1 = first.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            var blocks = second.AncestorsAndSelf().OfType<MethodDeclarationSyntax>();
            bool ret = blocks.Any(blk => blk.IsEquivalentTo(block1));
            return ret;
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
                //Console.WriteLine();
            }
            //else if (node is InvocationExpressionSyntax)
            //{ }
            return false;
        }

        internal static IEnumerable<string> GetInjectableProperties(ScannerType scannerType)
        {
            //tuples.Add(new Tuple<ScannerType, string>(ScannerType.XSS, "System.Web.HttpRequest.QueryString"));
            //List<string> ret = new List<string>();
            //foreach (var tuple in tuples)
            //{
            //    if (tuple.Item1 == scannerType)
            //        ret.Add(tuple.Item2);
            //}
            return _Injectables.Where(obj => obj.Item1 == scannerType).Select(obj => obj.Item2).ToList();
            //return ret;
        }
        internal static IEnumerable<string> GetSanitizedMethods(ScannerType scannerType)
        {
            //tuples.Add(new Tuple<ScannerType, string>(ScannerType.XSS, "System.Web.HttpRequest.QueryString"));
            //List<string> ret = new List<string>();
            //foreach (var tuple in tuples)
            //{
            //    if (tuple.Item1 == scannerType)
            //        ret.Add(tuple.Item2);
            //}
            return _SanitizedMethods.Where(obj => obj.Item1 == scannerType).Select(obj => obj.Item2).ToList();
            //return ret;
        }

        //public void OnCompilationEnd(SyntaxNode syntaxNode, SemanticModel model)
        //{


        //    //foreach (var vulnerableSyntaxNode in VulnerableSyntaxNodes)
        //    {
        //        var canSuppress = false;
        //        //var sources = vulnerableSyntaxNode.Source;
        //        //foreach (var syntaxNode in sources)
        //        {
        //            var idsToMatchOn = syntaxNode.DescendantNodesAndSelf().OfType<IdentifierNameSyntax>();
        //            foreach (var identifierNameSyntax in idsToMatchOn)
        //            {
        //                var containingBlock = syntaxNode.FirstAncestorOrSelf<MethodDeclarationSyntax>();

        //                var idMatches = containingBlock
        //                    .DescendantNodes()
        //                    .OfType<IdentifierNameSyntax>()
        //                    .Where(p => p.Identifier.ValueText == syntaxNode.ToString())
        //                    .ToList<SyntaxNode>();

        //                var declarationMatches = containingBlock
        //                    .DescendantNodes()
        //                    .OfType<VariableDeclaratorSyntax>()
        //                    .Where(p => p.Identifier.ValueText == identifierNameSyntax.ToString())
        //                    .Select(p => p.Initializer.Value)
        //                    .ToList<SyntaxNode>();

        //                var matches = idMatches.Union(declarationMatches);
        //                var idModel = model;

        //                //foreach (var match in matches)
        //                //{
        //                //var indexNode = match.AncestorsAndSelf().FirstOrDefault();

        //                //while (!canSuppress && indexNode != containingBlock)
        //                //{
        //                //    var nodeAnalyzer = NodeFactory.Create(indexNode);
        //                //    canSuppress = nodeAnalyzer.CanSuppress(idModel, indexNode);

        //                //    indexNode = indexNode.Ancestors().FirstOrDefault();
        //                //}

        //                //if (canSuppress)
        //                //{
        //                //    break;
        //                //}
        //                //}

        //                if (canSuppress)
        //                {
        //                    break;
        //                }
        //            }

        //            //if (canSuppress)
        //            //{
        //            //    break;
        //            //}

        //        }

        //        //vulnerableSyntaxNode.Suppressed = canSuppress;
        //    }
        //}
    }
}