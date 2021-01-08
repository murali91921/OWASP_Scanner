using SAST.Engine.CSharp.Enums;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using SAST.Engine.CSharp.Mapper;
using System.IO;
using SAST.Engine.CSharp.Constants;
using SAST.Engine.CSharp.Contract;

namespace SAST.Engine.CSharp.Scanners
{
    internal class LDAPScanner : IScanner
    {
        private SemanticModel _model;
        /// <summary>
        /// This method will find the LDAP vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            this._model = model;
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            List<SyntaxNode> lstVulnerableCheck = new List<SyntaxNode>();

            var classDeclarations = syntaxNode.DescendantNodes().OfType<ClassDeclarationSyntax>();
            foreach (var classDeclare in classDeclarations)
            {
                var objectCreationExpressions = classDeclare.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
                foreach (var objectCreation in objectCreationExpressions)
                {
                    ISymbol symbol = model.GetSymbol(objectCreation.Type);
                    if (symbol != null && symbol.ToString() == KnownType.System_DirectoryServices_DirectorySearcher)
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
                        if (leftSymbol != null && leftSymbol.ToString() == KnownType.System_DirectoryServices_DirectorySearcher_Filter)
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
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, ScannerType.LdapInjection);
        }

        /// <summary>
        /// This method will identify <paramref name="node"/> is vulnerable or not.
        /// </summary>
        /// <param name="node"></param>
        /// <returns></returns>
        private bool IsVulnerable(SyntaxNode node)
        {
            if (node is BinaryExpressionSyntax binaryExpression)
            {
                var left = IsVulnerable(binaryExpression.Left);
                var right = IsVulnerable(binaryExpression.Right);
                return right || left;
            }
            else if (node is InvocationExpressionSyntax)
            {
                ISymbol symbol = _model.GetSymbol(node);
                if (symbol == null)
                    return true;
                return !(symbol.ContainingType.ToString() + "." + symbol.Name.ToString() == KnownMethod.Microsoft_Security_Application_Encoder_LdapFilterEncode);
            }
            else if (node is LiteralExpressionSyntax)
                return false;
            else
                return true;
        }
    }
}