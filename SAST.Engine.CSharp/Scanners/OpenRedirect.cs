using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Mapper;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    public class OpenRedirectScanner : IScanner
    {
        SemanticModel model = null;
        SyntaxNode syntaxNode = null;
        Solution solution = null;
        List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();

        public void FindOpenRedirect(InvocationExpressionSyntax item)
        {
            IMethodSymbol symbol = null;
            var symbolInfo = model.GetSymbolInfo(item);
            if (symbolInfo.Symbol == null && symbolInfo.CandidateReason == CandidateReason.OverloadResolutionFailure)
                symbol = symbolInfo.CandidateSymbols.First() as IMethodSymbol;
            else
                symbol = symbolInfo.Symbol as IMethodSymbol;
            if (symbol != null && (symbol.Name == "Redirect" || symbol.Name == "RedirectPermanent")
                && (symbol.ReceiverType.ToString() == "System.Web.HttpResponse" || symbol.ReceiverType.ToString() == "Microsoft.AspNetCore.Http.Response"
                    || symbol.ReceiverType.ToString() == "System.Web.Mvc.Controller" || symbol.ReceiverType.ToString() == "System.Web.HttpResponseBase"
                    || symbol.ReceiverType.ToString() == "Microsoft.AspNetCore.Http.HttpResponse" || symbol.ReceiverType.ToString() == "Microsoft.AspNetCore.Mvc.Controller"
                    || symbol.ReceiverType.ToString() == "Microsoft.AspNetCore.Mvc.ControllerBase"))
            {
                if (item.ArgumentList.Arguments.Count > 0 && IsVulnerable(item.ArgumentList.Arguments.First().Expression))
                    lstVulnerableStatements.Add(item.Parent);
            }
        }

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            this.model = model;
            this.syntaxNode = syntaxNode;
            this.solution = solution;
            var allRedirects = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>().Where(obj => obj.ToString().Contains("Redirect"));
            foreach (var item in allRedirects)
                FindOpenRedirect(item);
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, ScannerType.OpenRedirect);
        }

        internal bool IsVulnerable(SyntaxNode argument)
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

        internal bool IsAddExpression(SyntaxNode syntaxNode)
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

        internal bool IsConditionExpression(SyntaxNode syntaxNode)
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
                SymbolInfo symbolInfo = model.GetSymbolInfo(syntaxNode);
                var refSymbols = SymbolFinder.FindReferencesAsync(symbolInfo.Symbol, solution).Result;
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
    }
}