using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp.Enums;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Core
{
    /// <summary>
    /// This class will find check the node as vulenrability under XSS scanner only. It can be deredegned to support all scanner in Future.
    /// </summary>
    internal class NodeFactory
    {
        public NodeFactory(Solution solution) => _solution = solution;

        private readonly Solution _solution;

        private static readonly List<string> _Injectables = new List<string> {
            Constants.KnownType.System_Web_HttpRequest_QueryString };

        private static readonly List<string> _SanitizedMethods = new List<string> {
            Constants.KnownMethod.System_Text_Encodings_Web_TextEncoder_Encode,
            Constants.KnownMethod.System_Web_HttpServerUtility_HtmlEncode,
            Constants.KnownMethod.System_Web_HttpUtility_HtmlEncode,
            Constants.KnownMethod.System_Web_Security_AntiXss_AntiXssEncoder_HtmlEncode,
            Constants.KnownMethod.System_Web_HttpServerUtility_UrlPathEncode,
            Constants.KnownMethod.System_Web_HttpUtility_UrlPathEncode,
            Constants.KnownMethod.System_Web_Security_AntiXss_AntiXssEncoder_UrlEncode,
        };
        /// <summary>
        /// This method will verify the <paramref name="node"/> is vulnerable or not.
        /// </summary>
        /// <param name="node">SyntaxNode to verify</param>
        /// <param name="model">Semantic Model of syntaxNode</param>
        /// <param name="callingSymbol">This symbol will be used to remove more callings on same Symbol.</param>
        /// <returns></returns>
        public bool IsVulnerable(SyntaxNode node, SemanticModel model, ISymbol callingSymbol = null)
        {
            if (node is ReturnStatementSyntax returnStatement)
                return IsVulnerable(returnStatement.Expression, model);
            else if (node is IdentifierNameSyntax)
            {
                ITypeSymbol type = model.GetTypeSymbol(node);
                if (type == null || (type.SpecialType != SpecialType.System_String && type.ToString() != Constants.KnownType.System_IO_StringWriter
    ))
                    return false;
                ISymbol symbol = model.GetSymbol(node);
                if (symbol == null || symbol.Equals(callingSymbol, SymbolEqualityComparer.Default))
                    return false;
                if (_solution == null)
                    return false;
                bool vulnerable = false;
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
                                vulnerable = !IsSanitized(invocation, model);
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
            else if (node is AssignmentExpressionSyntax assignmentExpression)
                return IsVulnerable(assignmentExpression.Right, model, null);
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
                return IsInjectable(node, model);
            else if (node is InvocationExpressionSyntax)
            {
                var invocation = node as InvocationExpressionSyntax;
                ISymbol symbol = model.GetSymbol(invocation);
                if (symbol == null)
                    return false;
                if (symbol.ContainingType.ToString() + "." + symbol.Name.ToString() == Constants.KnownType.System_Web_Mvc_Controller_View)
                    return false;
                if (symbol.Name == "ToString" && symbol.ContainingType.ToString() == Constants.KnownType.System_IO_StringWriter)
                {
                    var identifier = (invocation.Expression as MemberAccessExpressionSyntax).Expression;
                    return IsVulnerable(identifier, model);
                }
                else
                    return !IsSanitized(invocation, model);
            }
            else if (node is ParameterSyntax)
                return true;
            else
                return false;
        }

        /// <summary>
        /// This method will verify the node is Injectable or not.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="model"></param>
        /// <returns></returns>
        internal static bool IsInjectable(SyntaxNode node, SemanticModel model)
        {
            if (node is MemberAccessExpressionSyntax)
            {
                ISymbol symbol = model.GetSymbol(node);
                if (symbol == null)
                    return false;
                string property = symbol.ContainingType.ToString() + "." + symbol.Name.ToString();
                return _Injectables.Any(obj => obj == property);
            }
            return false;
        }

        /// <summary>
        /// This method will verify InvocationExpression is Sanitized or not.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="model"></param>
        /// <param name="scannerType"></param>
        /// <returns></returns>
        internal static bool IsSanitized(InvocationExpressionSyntax node, SemanticModel model)
        {
            if (node is null)
                return false;
            ISymbol symbol = model.GetSymbol(node);
            if (symbol == null)
                return false;
            string method = symbol.ContainingType.ToString() + "." + symbol.Name.ToString();
            return _SanitizedMethods.Any(obj => obj == method);
        }
    }
}