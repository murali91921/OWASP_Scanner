using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class OpenRedirectScanner : IScanner
    {
        SemanticModel model = null;
        Solution solution = null;
        string _filePath;
        List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();

        private static readonly string[] Response_ReceiverType = {
            KnownType.System_Web_HttpResponse,
            KnownType.System_Web_Mvc_Controller ,
            KnownType.System_Web_HttpResponseBase,
            KnownType.Microsoft_AspNetCore_Http_Response,
            KnownType.Microsoft_AspNetCore_Http_HttpResponse ,
            KnownType.Microsoft_AspNetCore_Mvc_Controller,
            KnownType.Microsoft_AspNetCore_Mvc_ControllerBase
        };

        private static readonly string[] Redirect_MethodNames = {
            "RedirectPermanent",
            "Redirect"
        };

        /// <summary>
        /// This method will find Open Redirect Vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            //if (filePath.Contains("WebGoatCoins"))
            //    System.Console.WriteLine("WebGoatCoins");
            this.model = model;
            this.solution = solution;
            _filePath = filePath;
            var allRedirects = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>().Where(obj => obj.ToString().Contains("Redirect"));
            foreach (var item in allRedirects)
                FindOpenRedirect(item);
            return vulnerabilities;
        }

        /// <summary>
        /// This method will identify <paramref name="argument"/> is vulnerable or not.
        /// </summary>
        /// <param name="argument"></param>
        /// <returns></returns>
        private bool IsVulnerable(SyntaxNode argument)
        {
            switch (argument.Kind())
            {
                case SyntaxKind.AddExpression:
                    return IsAddExpression(argument);
                case SyntaxKind.InvocationExpression:
                case SyntaxKind.IdentifierName:
                    return !IsConditionExpression(argument); ;
                case SyntaxKind.ConditionalExpression:
                case SyntaxKind.StringLiteralExpression:
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Determines if <paramref name="syntaxNode"/> is AddExpression
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <returns></returns>
        private bool IsAddExpression(SyntaxNode syntaxNode)
        {
            if (syntaxNode.IsKind(SyntaxKind.AddExpression))
            {
                BinaryExpressionSyntax binaryExpression = (syntaxNode as BinaryExpressionSyntax);
                if (binaryExpression.Left.IsKind(SyntaxKind.StringLiteralExpression))
                    return false;
                else
                    return !IsConditionExpression(binaryExpression.Left);
            }
            return false;
        }

        /// <summary>
        /// Determines if <paramref name="syntaxNode"/> is Conditional Expression
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <returns></returns>
        private bool IsConditionExpression(SyntaxNode syntaxNode)
        {
            if (syntaxNode is InvocationExpressionSyntax)
                return true;
            else if (syntaxNode is IdentifierNameSyntax)
            {
                var ancestor = syntaxNode.Ancestors().Where(obj => obj is IfStatementSyntax || obj is ConditionalExpressionSyntax).ToList();
                if (ancestor.Count > 0)
                {
                    var Identifiers = ancestor[0].DescendantNodes().Where(obj => obj.IsKind(SyntaxKind.IdentifierName)).ToList();
                    if (Identifiers.Exists(obj => obj == syntaxNode))
                        return true;
                }
                ISymbol symbol = model.GetSymbol(syntaxNode);
                var refSymbols = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
                foreach (var referencedSymbol in refSymbols)
                {
                    foreach (var referencedLocation in referencedSymbol.Locations)
                    {
                        var refNode = referencedLocation.Location.SourceTree.GetRoot().FindNode(referencedLocation.Location.SourceSpan);
                        if (syntaxNode.Span.Start > refNode.Span.Start)
                        {
                            var ifStatements = refNode.Ancestors().OfType<IfStatementSyntax>();
                            var assignmentExpressions = refNode.Ancestors().OfType<AssignmentExpressionSyntax>();
                            if (assignmentExpressions.Count() > 0 && ifStatements.Count() > 0)
                                return true;
                        }
                    }
                }
            }
            else if (syntaxNode is ConditionalExpressionSyntax)
                return true;
            return false;
        }

        /// <summary>
        /// This method will find Open Redirect vulnerabilities in <paramref name="item"/>
        /// </summary>
        /// <param name="item"></param>
        private void FindOpenRedirect(InvocationExpressionSyntax item)
        {
            if (!(model.GetSymbol(item) is IMethodSymbol symbol))
                return;
            if (Redirect_MethodNames.Contains(symbol.Name) && Response_ReceiverType.Contains(symbol.ReceiverType.ToString())
                && item.ArgumentList.Arguments.Count > 0)
            {
                if (IsVulnerable(item.ArgumentList.Arguments.First().Expression))
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item.Parent, Enums.ScannerType.OpenRedirect));
            }
        }
    }
}