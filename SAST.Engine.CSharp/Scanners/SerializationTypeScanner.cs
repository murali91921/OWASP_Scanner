using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class SerializationTypeScanner : IScanner
    {
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
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();

            var objectCreationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var objectCreation in objectCreationExpressions)
            {
                //serializer = new XmlSerializer(t)
                //IMethodSymbol=
                //ITypeSymbol;
                ITypeSymbol typeSymbol = model.GetTypeSymbol(objectCreation);
                if (typeSymbol == null || typeSymbol.ToString() != KnownType.System_Xml_Serialization_XmlSerializer)
                    continue;
                if (objectCreation.ArgumentList == null || objectCreation.ArgumentList.Arguments.Count() == 0)
                    continue;
                int index = 0;
                foreach (var item in objectCreation.ArgumentList.Arguments)
                {
                    if (item.NameColon == null && index == 0)
                    {
                        if (IsVulnerable(item.Expression, model, solution))
                            syntaxNodes.Add(item);
                    }
                    else if (item.NameColon.Name.ToString() == "type")
                    {
                        if (IsVulnerable(item.Expression, model, solution))
                            syntaxNodes.Add(item);
                    }
                }
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.SerializationType);
        }

        /// <summary>
        /// determines whether <paramref name="expression"/> is vulnerable or not.
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        private bool IsVulnerable(SyntaxNode expression, SemanticModel model, Solution solution)
        {
            if (expression is TypeOfExpressionSyntax typeOfExpression)
                return false;
            else if (expression is InvocationExpressionSyntax invocation)
            {
                if (invocation.Expression is MemberAccessExpressionSyntax memberAccessExpression)
                {
                    ISymbol memberSymbol = model.GetSymbol(memberAccessExpression.Expression);
                    if (memberSymbol == null)
                        return false;
                    if (memberSymbol.ToString() == KnownType.System_Type && memberAccessExpression.Name.ToString() == "GetType")
                        return true;
                }
                return false;
            }
            else if (expression is VariableDeclaratorSyntax variableDeclarator)
            {
                return IsVulnerable(variableDeclarator.Initializer.Value, model, solution);
            }
            else if (expression is IdentifierNameSyntax identifierName)
            {
                ITypeSymbol typeSymbol = model.GetTypeSymbol(identifierName);
                if (typeSymbol == null || typeSymbol.ToString() != KnownType.System_Type)
                    return false;

                ISymbol symbol = model.GetSymbol(identifierName);
                bool vulnerable = false;
                var referencedSymbols = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
                foreach (var reference in referencedSymbols)
                {
                    var currentNode = reference.Definition.Locations.First().SourceTree.GetRoot().FindNode(reference.Definition.Locations.First().SourceSpan);
                    vulnerable = IsVulnerable(currentNode, model, solution);
                    foreach (var refLocation in reference.Locations)
                    {
                        currentNode = reference.Definition.Locations.First().SourceTree.GetRoot().FindNode(refLocation.Location.SourceSpan);
                        if (currentNode.SpanStart < expression.SpanStart && Utils.CheckSameMethod(currentNode, expression))
                        {
                            var assignment = currentNode.Ancestors().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                            if (assignment == null)
                                continue;
                            if (currentNode.SpanStart < assignment.Right.SpanStart)
                                vulnerable = IsVulnerable(assignment.Right, refLocation.Document.GetSemanticModelAsync().Result, solution);
                        }
                    }
                }
                return vulnerable;
            }
            return false;
        }
    }
}
