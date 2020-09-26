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
    internal class LDAPScanner : IScanner
    {
        SemanticModel model;
        private static readonly string DirectorySearcher = "System.DirectoryServices.DirectorySearcher";
        private static readonly string LdapFilterEncode = "Microsoft.Security.Application.Encoder.LdapFilterEncode";
        private static readonly string filter = "System.DirectoryServices.DirectorySearcher.Filter";
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            this.model = model;
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            List<SyntaxNode> lstVulnerableCheck = new List<SyntaxNode>();

            var classDeclarations = syntaxNode.DescendantNodes().OfType<ClassDeclarationSyntax>();
            foreach (var classDeclare in classDeclarations)
            {
                var objectCreationExpressions = classDeclare.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
                foreach (var objectCreation in objectCreationExpressions)
                {
                    ISymbol symbol = model.GetSymbol(objectCreation.Type);
                    if (symbol != null && symbol.ToString() == DirectorySearcher)
                    {
                        if (objectCreation.Initializer?.Expressions.Count > 0)
                        {
                            var filterStatement = objectCreation.Initializer?.Expressions.OfType<AssignmentExpressionSyntax>().FirstOrDefault(p =>
                                (p.Left as IdentifierNameSyntax)?.Identifier.ValueText == "Filter");
                            if (filterStatement != null)
                                lstVulnerableCheck.Add(filterStatement.Right);
                        }
                        if (objectCreation.ArgumentList?.Arguments.Count() > 0)
                            foreach (var argument in objectCreation.ArgumentList.Arguments)
                            {
                                ITypeSymbol argumentType = model.GetTypeSymbol(argument.Expression);
                                if (argumentType.SpecialType == SpecialType.System_String || argument.Expression is BinaryExpressionSyntax)
                                    lstVulnerableCheck.Add(argument.Expression);
                            }
                    }
                }

                var assignmentExpressions = classDeclare.DescendantNodes().OfType<AssignmentExpressionSyntax>();
                foreach (var assignment in assignmentExpressions)
                {
                    if (assignment.Left is MemberAccessExpressionSyntax leftAssign)
                    {
                        var leftSymbol = model.GetSymbol(leftAssign);
                        if (leftSymbol != null && leftSymbol.ToString() == filter)
                            lstVulnerableCheck.Add(assignment.Right);
                    }
                }
            }
            foreach (var item in lstVulnerableCheck)
            {
                if (item is IdentifierNameSyntax)
                {
                    SyntaxNode vulnerable = null;
                    ISymbol symbol = model.GetSymbol(item);
                    var references = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
                    foreach (var reference in references)
                    {
                        SyntaxNode definition = syntaxNode.FindNode(reference.Definition.Locations.First().SourceSpan);
                        if ((definition as VariableDeclaratorSyntax).Initializer != null)
                            vulnerable = (definition as VariableDeclaratorSyntax).Initializer.Value;
                        foreach (var refLocation in reference.Locations)
                            if (item.SpanStart >= refLocation.Location.SourceSpan.Start)
                            {
                                var node = syntaxNode.FindNode(refLocation.Location.SourceSpan).Ancestors().FirstOrDefault(obj =>
                                    obj.IsKind(SyntaxKind.SimpleAssignmentExpression)) as AssignmentExpressionSyntax;
                                if (node != null && node.Left.ToString() == item.ToString())
                                    vulnerable = node.Right;
                            }
                    }
                    if (vulnerable != null && IsVulnerable(vulnerable))
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
            if (node is BinaryExpressionSyntax binaryExpression)
            {
                var left = IsVulnerable(binaryExpression.Left);
                var right = IsVulnerable(binaryExpression.Right);
                return right || left;
            }
            else if (node is InvocationExpressionSyntax)
            {
                ISymbol symbol = model.GetSymbol(node);
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