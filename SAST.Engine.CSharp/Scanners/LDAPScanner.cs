using SAST.Engine.CSharp.Enums;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using static System.Console;
using SAST.Engine.CSharp.Mapper;
using System.IO;
using SAST.Engine.CSharp.Contract;

namespace SAST.Engine.CSharp.Scanners
{
    public class LDAPScanner : IScanner
    {
        SemanticModel model;
        private static string DirectorySearcher = "System.DirectoryServices.DirectorySearcher";
        private static string LdapFilterEncode = "Microsoft.Security.Application.Encoder.LdapFilterEncode";
        private static string filter = "System.DirectoryServices.DirectorySearcher.Filter";
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            this.model = model;
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            List<SyntaxNode> lstVulnerableCheck = new List<SyntaxNode>();

            var classDeclarations = syntaxNode.DescendantNodes().OfType<ClassDeclarationSyntax>();
            //var classDeclarations = rootNode.DescendantNodes().OfType<LambdaExpressionSyntax>();
            foreach (var classDeclare in classDeclarations)
            {
                var objectCreationExpressions = classDeclare.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
                foreach (var objectCreation in objectCreationExpressions)
                {
                    ISymbol symbol = model.GetSymbolInfo(objectCreation.Type).Symbol;
                    if (symbol != null && symbol.ToString() == DirectorySearcher)
                    {
                        // WriteLine(symbol);
                        // WriteLine(objectCreation);
                        if (objectCreation.Initializer?.Expressions.Count > 0)
                        {
                            var filterStatement = objectCreation.Initializer?.Expressions.OfType<AssignmentExpressionSyntax>()
                            .FirstOrDefault(p => (p.Left as IdentifierNameSyntax)?.Identifier.ValueText == "Filter");
                            if (filterStatement != null)
                            {
                                lstVulnerableCheck.Add(filterStatement.Right);
                            }
                        }

                        if (objectCreation.ArgumentList?.Arguments.Count() > 0)
                        {
                            foreach (var argument in objectCreation.ArgumentList.Arguments)
                            {
                                ITypeSymbol argumentType = model.GetTypeInfo(argument.Expression).Type;
                                if (argumentType.ToString() == "string" || argument.Expression is BinaryExpressionSyntax)
                                {
                                    lstVulnerableCheck.Add(argument.Expression);
                                }
                            }
                        }
                    }
                }

                // Checking all assignments
                var assignmentExpressions = classDeclare.DescendantNodes().OfType<AssignmentExpressionSyntax>();
                foreach (var assignment in assignmentExpressions)
                {
                    var leftAssign = assignment.Left as MemberAccessExpressionSyntax;
                    if (leftAssign != null)
                    {
                        var leftSymbol = model.GetSymbolInfo(leftAssign).Symbol;
                        if (leftSymbol != null && leftSymbol.ToString() == filter)
                        {
                            lstVulnerableCheck.Add(assignment.Right);
                        }
                    }
                }
            }
            foreach (var item in lstVulnerableCheck)
            {
                if (item is IdentifierNameSyntax)
                {
                    SyntaxNode vulnerable = null;
                    // WriteLine("--- {0} {1}", item, IsVulnerable(item) ? "Yes" : "No");
                    ISymbol symbol = model.GetSymbolInfo(item).Symbol;
                    var references = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
                    foreach (var reference in references)
                    {
                        SyntaxNode definition = syntaxNode.FindNode(reference.Definition.Locations.First().SourceSpan);
                        if ((definition as VariableDeclaratorSyntax).Initializer != null)
                            vulnerable = (definition as VariableDeclaratorSyntax).Initializer.Value;
                        foreach (var refLocation in reference.Locations)
                        {
                            if (item.SpanStart >= refLocation.Location.SourceSpan.Start)
                            {
                                var node = syntaxNode.FindNode(refLocation.Location.SourceSpan).Ancestors().FirstOrDefault(obj =>
                                    obj.IsKind(SyntaxKind.SimpleAssignmentExpression)) as AssignmentExpressionSyntax;
                                if (node != null && node.Left.ToString() == item.ToString())
                                    vulnerable = node.Right;
                            }
                        }
                    }
                    if (IsVulnerable(vulnerable))
                        lstVulnerableStatements.Add(vulnerable.Ancestors().First(obj => obj.IsKind(SyntaxKind.ExpressionStatement)
                            || obj.IsKind(SyntaxKind.VariableDeclarator)));

                }
                else
                {
                    if (IsVulnerable(item))
                        lstVulnerableStatements.Add(item.Ancestors().First(obj => obj.IsKind(SyntaxKind.ExpressionStatement)
                            || obj.IsKind(SyntaxKind.VariableDeclarator)));
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, ScannerType.Ldap);
        }
        public bool IsVulnerable(SyntaxNode node)
        {
            if (node is BinaryExpressionSyntax)
            {
                // return  IsVulnerable((node as BinaryExpressionSyntax).Right) && IsVulnerable((node as BinaryExpressionSyntax).Left);
                var left = IsVulnerable((node as BinaryExpressionSyntax).Left);
                var right = IsVulnerable((node as BinaryExpressionSyntax).Right);
                return right || left;
            }
            else if (node is InvocationExpressionSyntax)
            {
                ISymbol symbol = model.GetSymbolInfo(node).Symbol;
                if (symbol == null)
                    return true;
                return !(symbol.ContainingType.ToString() + "." + symbol.Name.ToString() == LdapFilterEncode);
            }
            else if (node is LiteralExpressionSyntax)
                return false;
            else
                return true;
        }
        public List<SyntaxNode> VulnerableNodes(SyntaxNode node)
        {
            List<SyntaxNode> lstNode = new List<SyntaxNode>();
            if (node.IsKind(SyntaxKind.IdentifierName) || node.IsKind(SyntaxKind.InvocationExpression) || node.IsKind(SyntaxKind.SimpleMemberAccessExpression))
                lstNode.Add(node);
            else
                foreach (var item in node.ChildNodes())
                {
                    if (item.IsKind(SyntaxKind.IdentifierName) || item.IsKind(SyntaxKind.InvocationExpression) || item.IsKind(SyntaxKind.SimpleMemberAccessExpression))
                        lstNode.Add(item);
                    else
                        lstNode.AddRange(VulnerableNodes(item));
                }
            return lstNode;
        }

    }
}