using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Formatting;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;
using SAST.Engine.CSharp.Mapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class XxeScanner : IScanner
    {
        SemanticModel model = null;
        Solution solution = null;
        SyntaxNode syntaxNode = null;

        /// <summary>
        /// Determines the vulnerabilities in <paramref name="syntaxNode"/>
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            this.model = model;
            this.solution = solution;
            this.syntaxNode = syntaxNode;
            List<SyntaxNode> vulnerableNodes = new List<SyntaxNode>();
            var methodDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>();
            foreach (var methodDeclaration in methodDeclarations)
            {
                var invocations = methodDeclaration.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
                foreach (var invocation in invocations)
                {
                    IMethodSymbol invocationSymbol = model.GetSymbol(invocation) as IMethodSymbol;
                    if (invocationSymbol == null)
                        continue;
                    if (invocationSymbol.ReceiverType.ToString() + "." + invocationSymbol.Name.ToString() == KnownMethod.System_Xml_XmlTextReader_Read)
                    {
                        if (IsVulnerableXmlTextReader(invocation))
                            vulnerableNodes.Add(invocation);
                        continue;
                    }
                    if (invocationSymbol.ReceiverType.ToString() + "." + invocationSymbol.Name.ToString() == KnownMethod.System_Xml_XmlReader_Create)
                    {
                        if (invocation.ArgumentList.Arguments.Count() < 1)
                            continue;
                        if (IsVulnerableXmlReader(invocation))
                            vulnerableNodes.Add(invocation);
                    }
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, vulnerableNodes, Enums.ScannerType.XXE);
        }

        /// <summary>
        /// Determines <paramref name="invocationExpression"/> is vulnerable by XMLTextReader or not.
        /// </summary>
        /// <param name="invocationExpression"></param>
        /// <returns></returns>
        private bool IsVulnerableXmlTextReader(InvocationExpressionSyntax invocationExpression)
        {
            bool vulnerable = false;
            if ((invocationExpression.Expression as MemberAccessExpressionSyntax).Expression is IdentifierNameSyntax identifierName)
            {
                vulnerable = true;
                ISymbol xmlTextReaderSymbol = model.GetSymbol(identifierName);
                var referencedSymbols = SymbolFinder.FindReferencesAsync(xmlTextReaderSymbol, solution).Result;
                foreach (var referencedSymbol in referencedSymbols)
                {
                    foreach (var referenceLocation in referencedSymbol.Locations)
                    {
                        if (referenceLocation.Location.SourceSpan.Start >= invocationExpression.SpanStart)
                            continue;
                        var currentNode = syntaxNode.FindNode(referenceLocation.Location.SourceSpan);
                        if (!Utils.CheckSameMethod(currentNode, invocationExpression))
                            continue;
                        var assignment = currentNode.AncestorsAndSelf().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                        if (assignment == null)
                            continue;
                        if (currentNode.SpanStart < assignment.Right.SpanStart)
                        {
                            ISymbol symbol = model.GetSymbol(assignment.Left);
                            if (symbol == null)
                                continue;
                            if (symbol.Name == "ProhibitDtd")
                                vulnerable = assignment.Right.Kind() == SyntaxKind.FalseLiteralExpression;
                            else if (symbol.Name == "DtdProcessing")
                                vulnerable = (assignment.Right as MemberAccessExpressionSyntax).Name.ToString() == "Parse";
                        }
                    }
                }
            }
            return vulnerable;
        }

        /// <summary>
        /// Determines <paramref name="invocation"/> is vulnerable by XMLReader or not.
        /// </summary>
        /// <param name="invocation"></param>
        /// <returns></returns>
        private bool IsVulnerableXmlReader(InvocationExpressionSyntax invocation)
        {
            bool vulnerable = false;
            foreach (var argument in invocation.ArgumentList.Arguments)
            {
                ITypeSymbol argumentSymbol = model.GetTypeInfo(argument.Expression).Type;
                if (argumentSymbol == null || argumentSymbol.ToString() != KnownType.System_Xml_XmlReaderSettings)
                    continue;
                vulnerable = IsVulnerableSettings(argument.Expression);
            }
            return vulnerable;
        }

        /// <summary>
        /// Determines <paramref name="settingNode"/> is have vulnerable settings or not
        /// </summary>
        /// <param name="settingNode"></param>
        /// <param name="textSpan"></param>
        /// <returns></returns>
        private bool IsVulnerableSettings(SyntaxNode settingNode)
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
                            vulnerable = IsVulnerableSettings(assign);
                    }
                }
            }
            else if (settingNode is IdentifierNameSyntax)
            {
                ISymbol settingSymbol = model.GetSymbol(settingNode);
                var referencedSymbols = SymbolFinder.FindReferencesAsync(settingSymbol, solution).Result;
                foreach (var refSymbol in referencedSymbols)
                {
                    vulnerable = IsVulnerableSettings(refSymbol.Definition.Locations.First().SourceTree.GetRoot().FindNode(
                        refSymbol.Definition.Locations.First().SourceSpan));
                    foreach (var refLocation in refSymbol.Locations)
                    {
                        if (refLocation.Location.SourceSpan.Start >= settingNode.SpanStart)
                            continue;
                        var currentNode = syntaxNode.FindNode(refLocation.Location.SourceSpan);
                        if (!Utils.CheckSameMethod(currentNode, settingNode))
                            continue;
                        var assignment = currentNode.AncestorsAndSelf().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                        if (assignment == null || currentNode.SpanStart >= assignment.Right.SpanStart)
                            continue;
                        vulnerable = IsVulnerableSettings(assignment);
                    }
                }
            }
            else if (settingNode is AssignmentExpressionSyntax assignmentExpression)
            {
                ISymbol symbol = model.GetSymbol(assignmentExpression.Left);
                if (symbol == null)
                    return false;
                else if (symbol.ToString() == KnownType.System_Xml_XmlReaderSettings)
                    return IsVulnerableSettings(assignmentExpression.Right);
                else if (symbol.ToString() == KnownType.System_Xml_XmlReaderSettings_DtdProcessing)
                    return (assignmentExpression.Right as MemberAccessExpressionSyntax).Name.ToString() == "Parse";
                else if (symbol.ToString() == KnownType.System_Xml_XmlReaderSettings_ProhibitDtd && (assignmentExpression.Right is LiteralExpressionSyntax))
                    return assignmentExpression.Right.Kind() == SyntaxKind.FalseLiteralExpression;
            }
            else if (settingNode is VariableDeclaratorSyntax variableDeclarator && variableDeclarator.Initializer != null)
                vulnerable = IsVulnerableSettings(variableDeclarator.Initializer.Value);
            return vulnerable;
        }

        /// <summary>
        /// Determines <paramref name="node"/> is NullLiteral or not.
        /// </summary>
        /// <param name="node"></param>
        /// <returns></returns>
        private bool IsNullObject(SyntaxNode node) => node.Kind() == SyntaxKind.NullLiteralExpression;
    }
}