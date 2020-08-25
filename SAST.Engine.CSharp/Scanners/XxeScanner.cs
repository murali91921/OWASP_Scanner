using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Formatting;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    public class XxeScanner : IScanner
    {
        SemanticModel model = null;
        Solution solution = null;
        SyntaxNode syntaxNode = null;

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            this.model = model;
            this.solution = solution;
            this.syntaxNode = syntaxNode;
            List<SyntaxNode> nodes = new List<SyntaxNode>();
            var methodDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>();
            foreach (var methodDeclaration in methodDeclarations)
            {
                var invocations = methodDeclaration.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
                foreach (var invocation in invocations)
                {
                    SymbolInfo symbolInfo = model.GetSymbolInfo(invocation);
                    ISymbol invocationSymbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                    if (invocationSymbol == null)
                        continue;
                    if (invocationSymbol.ContainingType.ToString() + "." + invocationSymbol.Name.ToString() == "System.Xml.XmlTextReader.Read")
                    {
                        Console.WriteLine("{0}\t{1}", IsVulnerableXmlTextReader(invocation), invocation.ToString());
                        Console.WriteLine(invocation.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().First().Identifier);
                    }
                    else if (invocationSymbol.ContainingType.ToString() + "." + invocationSymbol.Name.ToString() == "System.Xml.XmlReader.Create")
                    {
                        if (invocation.ArgumentList.Arguments.Count() >= 2)
                        {

                            Console.WriteLine("{0}\t{1}", IsVulnerableXmlReader(invocation), invocation.ToString());
                            Console.WriteLine(invocation.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().First().Identifier);

                        }
                    }
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, nodes, Enums.ScannerType.XSS);
        }
        private bool IsVulnerableXmlTextReader(InvocationExpressionSyntax invocationExpression)
        {
            bool vulnerable = false;
            if ((invocationExpression.Expression as MemberAccessExpressionSyntax).Expression is IdentifierNameSyntax identifierName)
            {
                vulnerable = true;
                SymbolInfo symbolInfo = model.GetSymbolInfo(identifierName);
                ISymbol xmlTextReaderSymbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                var referencedSymbols = SymbolFinder.FindReferencesAsync(xmlTextReaderSymbol, solution).Result;
                foreach (var referencedSymbol in referencedSymbols)
                {
                    foreach (var referenceLocation in referencedSymbol.Locations)
                    {
                        if (referenceLocation.Location.SourceSpan.Start >= invocationExpression.SpanStart)
                            continue;
                        var currentNode = syntaxNode.FindNode(referenceLocation.Location.SourceSpan);
                        if (!IsSameBlock(currentNode, invocationExpression))
                            continue;
                        var assignment = currentNode.AncestorsAndSelf().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                        if (assignment == null)
                            continue;
                        if (currentNode.SpanStart < assignment.Right.SpanStart)
                        {
                            symbolInfo = model.GetSymbolInfo(assignment.Left);
                            ISymbol symbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                            if (symbol == null)
                                continue;
                            if (symbol.Name.ToString() == "ProhibitDtd")
                                vulnerable = assignment.Right.Kind() == SyntaxKind.FalseLiteralExpression;
                            else if (symbol.Name.ToString() == "DtdProcessing")
                                vulnerable = (assignment.Right as MemberAccessExpressionSyntax).Name.ToString() == "Parse";
                        }
                    }
                    //return vulnerable;
                }
            }
            return vulnerable;
        }

        private bool IsVulnerableXmlReader(InvocationExpressionSyntax invocation)
        {
            bool vulnerable = false;
            foreach (var argument in invocation.ArgumentList.Arguments)
            {
                ITypeSymbol argumentSymbol = model.GetTypeInfo(argument.Expression).Type;
                if (argumentSymbol == null || argumentSymbol.ToString() != "System.Xml.XmlReaderSettings")
                    continue;
                vulnerable = IsVulnerableSettings(argument.Expression, invocation.Span);
            }
            return vulnerable;
        }

        private bool IsVulnerableSettings(SyntaxNode settingNode, TextSpan textSpan)
        {
            bool vulnerable = false;
            if (settingNode is null || IsNullObject(settingNode))
                return vulnerable;
            if (settingNode is ObjectCreationExpressionSyntax objectCreation)
            {
                if (objectCreation.Initializer == null)
                    return false;
                foreach (var item in objectCreation.Initializer.Expressions)
                {
                    if (item is AssignmentExpressionSyntax assign)
                    {
                        if (assign.Left.ToString().Contains("DtdProcessing") || assign.Left.ToString().Contains("ProhibitDtd"))
                            vulnerable = IsVulnerableSettings(assign, assign.Span);
                    }
                }
            }
            else if (settingNode is IdentifierNameSyntax)
            {
                SymbolInfo symbolInfo = model.GetSymbolInfo(settingNode);
                ISymbol settingSymbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                var referencedSymbols = SymbolFinder.FindReferencesAsync(settingSymbol, solution).Result;
                foreach (var refSymbol in referencedSymbols)
                {
                    vulnerable = IsVulnerableSettings(refSymbol.Definition.Locations.First().SourceTree.GetRoot().FindNode(
                        refSymbol.Definition.Locations.First().SourceSpan), refSymbol.Definition.Locations.First().SourceSpan);
                    foreach (var refLocation in refSymbol.Locations)
                    {
                        if (refLocation.Location.SourceSpan.Start >= settingNode.SpanStart)
                            continue;
                        var currentNode = syntaxNode.FindNode(refLocation.Location.SourceSpan);
                        if (!IsSameBlock(currentNode, settingNode))
                            continue;
                        var assignment = currentNode.AncestorsAndSelf().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                        if (assignment == null || currentNode.SpanStart >= assignment.Right.SpanStart)
                            continue;
                        vulnerable = IsVulnerableSettings(assignment, assignment.Span);
                        //symbolInfo = model.GetSymbolInfo(assignment.Left);
                        //ISymbol symbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                        //if (symbol == null)
                        //    continue;
                        //if (symbol.Name.ToString() == "ProhibitDtd")
                        //    vulnerable = assignment.Right.Kind() == SyntaxKind.FalseLiteralExpression;
                        //else if (symbol.Name.ToString() == "DtdProcessing")
                        //    vulnerable = (assignment.Right as MemberAccessExpressionSyntax).Name.ToString() == "Parse";
                    }
                }
            }
            else if (settingNode is AssignmentExpressionSyntax assignmentExpression)
            {
                SymbolInfo symbolInfo = model.GetSymbolInfo(assignmentExpression.Left);
                ISymbol symbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                if (symbol == null)
                    return false;
                else if (symbol.ToString() == "System.Xml.XmlReaderSettings")
                    return IsVulnerableSettings(assignmentExpression.Right, assignmentExpression.Span);
                else if (symbol.ToString() == "System.Xml.XmlReaderSettings.DtdProcessing")
                    return (assignmentExpression.Right as MemberAccessExpressionSyntax).Name.ToString() == "Parse";
                else if (symbol.ToString() == "System.Xml.XmlReaderSettings.ProhibitDtd")
                {
                    if (assignmentExpression.Right is LiteralExpressionSyntax)
                        return assignmentExpression.Right.Kind() == SyntaxKind.FalseLiteralExpression;
                }
            }
            else if (settingNode is VariableDeclaratorSyntax variableDeclarator)
            {
                if (variableDeclarator.Initializer != null)
                    vulnerable = IsVulnerableSettings(variableDeclarator.Initializer.Value, variableDeclarator.Span);
            }
            return vulnerable;
        }

        private bool IsNullObject(SyntaxNode node)
        {
            return node.Kind() == SyntaxKind.NullLiteralExpression;
        }
        private bool IsSameBlock(SyntaxNode first, SyntaxNode second)
        {
            var firstMethodBlock = first.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            var secondMethodBlock = second.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            if (firstMethodBlock == secondMethodBlock)
                return true;
            return false;
        }
    }
}