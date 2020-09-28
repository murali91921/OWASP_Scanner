using SAST.Engine.CSharp.Enums;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using SAST.Engine.CSharp.Contract;
using static System.Console;
using SAST.Engine.CSharp.Mapper;
using System.IO;

namespace SAST.Engine.CSharp.Scanners
{
    internal class XPathScanner : IScanner
    {
        SemanticModel model = null;
        Solution solution = null;
        SyntaxNode syntaxNode = null;

        private static string[] MethodsToCheck = {
            "System.Xml.XmlDocument.SelectSingleNode",
            "System.Xml.XmlDocument.SelectNodes",
            "System.Xml.XmlNode.SelectSingleNode",
            "System.Xml.XmlNode.SelectNodes",
            "System.Xml.XPath.XPathNavigator.SelectSingleNode",
            "System.Xml.XPath.XPathNavigator.Select",
            "System.Xml.XPath.XPathNavigator.Compile",
            "System.Xml.XPath.XPathNavigator.Evaluate",
            "System.Xml.XPath.XPathExpression.Compile",
            "System.Xml.Linq.XNode.XPathSelectElement",
            "System.Xml.Linq.XNode.XPathSelectElements",
            "System.Xml.Linq.XNode.XPathEvaluate",
            "System.Xml.XPath.Extensions.XPathSelectElement",
            "System.Xml.XPath.Extensions.XPathSelectElements",
            "System.Xml.XPath.Extensions.XPathEvaluate"
        };

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
            this.solution = solution;
            this.model = model;
            this.syntaxNode = syntaxNode;
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            HashSet<SyntaxNode> lstVulnerableCheck = new HashSet<SyntaxNode>();
            var methods = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var method in methods)
            {
                IMethodSymbol symbol = model.GetSymbol(method) as IMethodSymbol;
                if (symbol == null)
                    continue;
                if (!MethodsToCheck.Any(obj => obj == symbol.ReceiverType.OriginalDefinition.ToString() + "." + symbol.Name.ToString()))
                    continue;
                foreach (var argument in method.ArgumentList.Arguments)
                {
                    ITypeSymbol typeSymbol = model.GetTypeSymbol(argument.Expression);
                    if (typeSymbol == null)
                        continue;
                    if (typeSymbol.SpecialType == SpecialType.System_String)
                    {
                        lstVulnerableCheck.Add(argument.Expression);
                        break;
                    }
                }
            }
            foreach (var item in lstVulnerableCheck)
            {
                if (IsVulnerable(item))
                    lstVulnerableStatements.Add(item.Parent);
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, ScannerType.XPath);
        }

        /// <summary>
        /// Determines <paramref name="node"/> is vulnerable or not.
        /// </summary>
        /// <param name="node"></param>
        /// <param name="callingSymbol"></param>
        /// <returns></returns>
        private bool IsVulnerable(SyntaxNode node, ISymbol callingSymbol = null)
        {
            if (node is IdentifierNameSyntax)
            {
                ITypeSymbol type = model.GetTypeSymbol(node);
                if (type == null || type.SpecialType != SpecialType.System_String)
                    return false;
                bool vulnerable = false;
                ISymbol symbol = model.GetSymbol(node);
                if (symbol == null || symbol.Equals(callingSymbol, SymbolEqualityComparer.Default))
                    return false;
                var references = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
                foreach (var reference in references)
                {
                    var currentNode = syntaxNode.FindNode(reference.Definition.Locations.First().SourceSpan);
                    vulnerable = IsVulnerable(currentNode);
                    foreach (var refLocation in reference.Locations)
                    {
                        currentNode = syntaxNode.FindNode(refLocation.Location.SourceSpan);
                        if (Utils.CheckSameMethod(currentNode, node) && currentNode.SpanStart < node.SpanStart)
                        {
                            var assignment = currentNode.Ancestors().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                            if (assignment == null)
                                continue;
                            if (currentNode.SpanStart < assignment.Right.SpanStart)
                                vulnerable = IsVulnerable(assignment.Right, symbol);
                        }
                    }
                }
                return vulnerable;
            }
            else if (node is BinaryExpressionSyntax)
            {
                var left = IsVulnerable((node as BinaryExpressionSyntax).Left, callingSymbol);
                var right = IsVulnerable((node as BinaryExpressionSyntax).Right, callingSymbol);
                return left || right;
            }
            else if (node is VariableDeclaratorSyntax && (node as VariableDeclaratorSyntax).Initializer != null)
                return IsVulnerable((node as VariableDeclaratorSyntax).Initializer.Value);
            else if (node is AssignmentExpressionSyntax)
                return IsVulnerable((node as AssignmentExpressionSyntax).Right);
            else if (node is InterpolatedStringExpressionSyntax)
            {
                bool vulnerable = false;
                var contents = (node as InterpolatedStringExpressionSyntax).Contents.OfType<InterpolationSyntax>();
                foreach (var item in contents)
                    vulnerable = vulnerable || IsVulnerable(item.Expression, callingSymbol);
                return vulnerable;
            }
            else if (node is ParameterSyntax)
                return true;
            else
                return false;
        }
    }
}