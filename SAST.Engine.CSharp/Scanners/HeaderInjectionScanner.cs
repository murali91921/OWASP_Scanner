using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SAST.Engine.CSharp.Constants;
using System.Collections.Specialized;
using Microsoft.CodeAnalysis.FindSymbols;
using System.Collections.Immutable;

namespace SAST.Engine.CSharp.Scanners
{
    internal class HeaderInjectionScanner : IScanner
    {
        private static readonly string[] AddHeader_Methods = { KnownMethod.System_Web_HttpResponse_AppendHeader, KnownMethod.System_Web_HttpResponse_AddHeader };

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var invocations = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var invocationAdd in invocations)
            {
                if (invocationAdd.Expression.GetName() == "AppendHeader" || invocationAdd.Expression.GetName() == "AddHeader")
                {
                    var symbol = model.GetSymbol(invocationAdd);
                    if (symbol == null)
                        continue;
                    if (!AddHeader_Methods.Contains(symbol.ContainingType.ToString() + "." + symbol.Name.ToString()))
                        continue;
                    SyntaxNode valueArgument = null;
                    int index = 0;
                    foreach (var argument in invocationAdd.ArgumentList.Arguments)
                    {
                        if (argument.NameColon is null)
                        {
                            if (index == 1)
                                valueArgument = argument.Expression;
                        }
                        else if (argument.NameColon.Name.ToString() == "value")
                            valueArgument = argument.Expression;
                        index++;
                    }
                    if (Utils.IsVulnerable(valueArgument, model, solution, scannerType: Enums.ScannerType.HeaderInjection))
                        vulnerabilities.Add(VulnerabilityDetail.Create(filePath, valueArgument, Enums.ScannerType.HeaderInjection));
                }
                else if (invocationAdd.Expression.GetName() == "Add")
                {
                    if (invocationAdd.Expression is MemberAccessExpressionSyntax addMemberAccess
                        && addMemberAccess.Expression is MemberAccessExpressionSyntax headerMemberAccessExpression
                        && headerMemberAccessExpression.Name.ToString() == "Headers")
                    {
                        var symbolHeaders = model.GetSymbol(headerMemberAccessExpression);
                        if (symbolHeaders == null || symbolHeaders.ContainingType.ToString() + "." + symbolHeaders.Name.ToString() != KnownType.System_Web_HttpResponse_Headers)
                            continue;
                        var argument = invocationAdd.ArgumentList.Arguments.First().Expression;
                        var symbolArgument = model.GetSymbol(argument);

                        var references = SymbolFinder.FindReferencesAsync(symbolArgument, solution).Result;
                        foreach (var referenced in references)
                        {
                            foreach (var refLocation in referenced.Locations)
                            {
                                if (refLocation.Document.FilePath != filePath)
                                    continue;

                                var node = refLocation.Location.SourceTree.GetRoot().FindNode(refLocation.Location.SourceSpan);
                                if (node is ArgumentSyntax)
                                    continue;
                                var expressionStatement = node.AncestorsAndSelf().OfType<ExpressionStatementSyntax>().FirstOrDefault();
                                if (!(expressionStatement.Expression is InvocationExpressionSyntax invocationExpression))
                                    continue;
                                if (invocationAdd.SpanStart < invocationExpression.SpanStart)
                                    continue;
                                int index = 0;
                                SyntaxNode valueArgument = null;
                                foreach (var argumentString in invocationExpression.ArgumentList.Arguments)
                                {
                                    if (argumentString.NameColon is null)
                                    {
                                        if (index == 1)
                                            valueArgument = argumentString.Expression;
                                    }
                                    else if (argumentString.NameColon.Name.ToString() == "value")
                                        valueArgument = argumentString.Expression;
                                    index++;
                                }
                                var symbolValue = model.GetSymbol(valueArgument);
                                if (symbolValue == null)
                                    continue;
                                if (valueArgument != null && Utils.IsVulnerable(valueArgument, model, solution, scannerType: Enums.ScannerType.HeaderInjection))
                                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, valueArgument, Enums.ScannerType.HeaderInjection));
                            }
                        }
                    }
                }
            }
            return vulnerabilities;
        }
    }
}