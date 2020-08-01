using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using static System.Console;

namespace ASTTask
{
    internal class XPathScanner
    {
        SemanticModel model = null;
        AdhocWorkspace workspace = null;
        SyntaxNode rootNode = null;
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
        public List<SyntaxNode> FindVulnerabilities(string filePath, SyntaxNode root)
        {
            // CSharpParseOptions options = CSharpParseOptions.Default
            //     .WithFeatures(new[] { new KeyValuePair<string, string>("flow-analysis", "")
            //     });
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            HashSet<SyntaxNode> lstVulnerableCheck = new HashSet<SyntaxNode>();
            workspace = new AdhocWorkspace();
            //var solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Create());
            var project = workspace.AddProject("XPathInjectionScanner", "C#");
            project = project.AddMetadataReference(MetadataReference.CreateFromFile(filePath));
            project = project.AddMetadataReferences(Utils.LoadMetadata(root));
            workspace.TryApplyChanges(project.Solution);
            //workspace.TryApplyChanges(project.Solution.WithProjectParseOptions(project.Id,options));
            var document = workspace.AddDocument(project.Id, "XPathInjectionScanner",SourceText.From(root.ToString()));
            model = document.GetSemanticModelAsync().Result;
            var compilation = project.GetCompilationAsync().Result;
            rootNode = document.GetSyntaxRootAsync().Result;
            var methods = rootNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var method in methods)
            {
                SymbolInfo symbolInfo = model.GetSymbolInfo(method);
                IMethodSymbol symbol = null;
                if(symbolInfo.Symbol != null)
                    symbol = symbolInfo.Symbol as IMethodSymbol;
                else if(symbolInfo.CandidateSymbols.Count()>0)
                    symbol = symbolInfo.CandidateSymbols.First() as IMethodSymbol;
                if(symbol == null)
                    continue;
                if(!MethodsToCheck.Any(obj=> obj == symbol.ReceiverType.OriginalDefinition.ToString()+"."+symbol.Name.ToString()))
                    continue;
                // WriteLine("{1} {0}", method, Program.GetLineNumber(method));
                foreach(var argument in method.ArgumentList.Arguments)
                {
                    ITypeSymbol typeSymbol = model.GetTypeInfo(argument.Expression).Type;
                    if(typeSymbol==null)
                        continue;
                    if(typeSymbol.ToString()=="string")
                    {
                        lstVulnerableCheck.Add(argument.Expression);
                        break;
                    }
                }
            }
            foreach (var item in lstVulnerableCheck)
            {
                if(IsVulnerable(item))
                    lstVulnerableStatements.Add(item.Parent);
                // WriteLine("Check {0} {1}", Program.GetLineNumber(item), item);
            }
            return lstVulnerableStatements;
        }
        private bool IsVulnerable(SyntaxNode node,ISymbol callingSymbol = null)
        {
            if(node is IdentifierNameSyntax)
            {
                ITypeSymbol type = model.GetTypeInfo(node).Type;
                if(type.ToString() != "string")
                    return false;

                bool vulnerable = false;
                ISymbol symbol = model.GetSymbolInfo(node).Symbol;
                if(symbol == null)
                    return false;
                if(symbol.Equals(callingSymbol,SymbolEqualityComparer.Default))
                    return false;

                var references = SymbolFinder.FindReferencesAsync(symbol,workspace.CurrentSolution).Result;
                foreach (var reference in references)
                {
                    var currentNode = rootNode.FindNode(reference.Definition.Locations.First().SourceSpan);
                    vulnerable = IsVulnerable(currentNode);
                    // vulnerable = vulnerable || retVulnerable;
                    foreach (var refLocation in reference.Locations)
                    {
                        currentNode = rootNode.FindNode(refLocation.Location.SourceSpan);
                        if(CheckSameBlock(currentNode, node) && currentNode.SpanStart < node.SpanStart)
                        {
                            // WriteLine(currentNode.Parent.Parent);
                            // WriteLine(node.Parent);
                            var assignment = currentNode.Ancestors().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                            if(assignment==null)
                                continue;
                            if(currentNode.SpanStart < assignment.Right.SpanStart)
                            {
                             //   WriteLine("{0} {1} {2} {3}",assignment.Right,assignment.Right.SpanStart, currentNode , currentNode.SpanStart);
                                vulnerable = IsVulnerable(assignment.Right,symbol);
                            }
                            // vulnerable = vulnerable || retVulnerable;
                        }
                    }
                }
                return vulnerable;
            }
            else if(node is BinaryExpressionSyntax)
            {
                var left = IsVulnerable((node as BinaryExpressionSyntax).Left,callingSymbol);
                var right = IsVulnerable((node as BinaryExpressionSyntax).Right,callingSymbol);
                return left || right;
            }
            else if(node is VariableDeclaratorSyntax && (node as VariableDeclaratorSyntax).Initializer!=null)
            {
                return IsVulnerable((node as VariableDeclaratorSyntax).Initializer.Value);
            }
            else if(node is AssignmentExpressionSyntax)
            {
                return IsVulnerable((node as AssignmentExpressionSyntax).Right);
            }
            else if(node is InterpolatedStringExpressionSyntax)
            {
                bool vulnerable = false;
                var contents = (node as InterpolatedStringExpressionSyntax).Contents.OfType<InterpolationSyntax>();
                foreach (var item in contents)
                {
                    vulnerable = vulnerable || IsVulnerable(item.Expression,callingSymbol);
                }
                return vulnerable;
            }
            else if(node is LiteralExpressionSyntax)
                return false;
            else if(node is ParameterSyntax)
                return true;
            else
                return false;
        }
        private bool CheckSameBlock(SyntaxNode first, SyntaxNode second)
        {
            BlockSyntax block1 = first.Ancestors().OfType<BlockSyntax>().FirstOrDefault();
            var blocks = second.Ancestors().OfType<BlockSyntax>();
            bool ret = blocks.Any(blk => blk.IsEquivalentTo(block1));
            return ret;
        }
    }
}