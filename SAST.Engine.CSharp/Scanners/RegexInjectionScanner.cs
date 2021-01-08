using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class RegexInjectionScanner : IScanner
    {
        private static string[] Match_Methods =
        {
            KnownMethod.System_Text_RegularExpressions_Regex_IsMatch,
            KnownMethod.System_Text_RegularExpressions_Regex_Match,
            KnownMethod.System_Text_RegularExpressions_Regex_Matches
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
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            syntaxNodes.AddRange(FindObjectCreations(syntaxNode, model, solution));
            syntaxNodes.AddRange(FindInvocations(syntaxNode, model, solution));
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.RegexInjection);
        }

        private IEnumerable<SyntaxNode> FindObjectCreations(SyntaxNode syntaxNode, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var objectCreations = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var objectCreation in objectCreations)
            {
                ITypeSymbol objectTypeSymbol = model.GetTypeSymbol(objectCreation) as ITypeSymbol;
                if (objectTypeSymbol == null)
                    continue;
                if (objectTypeSymbol.ToString() != "System.Text.RegularExpressions.Regex")
                    continue;
                if (objectCreation.ArgumentList == null)
                    continue;
                int index = -1;
                foreach (var item in objectCreation.ArgumentList.Arguments)
                {
                    index++;
                    if ((item.NameColon == null && index == 0) ||
                        (item.NameColon != null && item.NameColon.Name.ToString() == "pattern"))
                    {
                        ITypeSymbol typeSymbol = model.GetTypeSymbol(item.Expression);
                        if (typeSymbol.SpecialType != SpecialType.System_String)
                            continue;
                        if (Utils.IsVulnerable(item.Expression, model, solution, null, null, Enums.ScannerType.RegexInjection))
                            syntaxNodes.Add(item);
                    }
                }
            }
            return syntaxNodes;
        }

        private IEnumerable<SyntaxNode> FindInvocations(SyntaxNode syntaxNode, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var invocationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var invocationExpression in invocationExpressions)
            {
                IMethodSymbol methodSymbol = model.GetSymbol(invocationExpression) as IMethodSymbol;
                if (methodSymbol == null)
                    continue;
                if (!Match_Methods.Contains(methodSymbol.ContainingType.ToString() + "." + methodSymbol.Name))
                    continue;
                if (invocationExpression.ArgumentList == null)
                    continue;
                int index = -1;
                foreach (var item in invocationExpression.ArgumentList.Arguments)
                {
                    index++;
                    if ((item.NameColon == null && index == 1) ||
                        (item.NameColon != null && item.NameColon.Name.ToString() == "pattern"))
                    {
                        ITypeSymbol typeSymbol = model.GetTypeSymbol(item.Expression);
                        if (typeSymbol.SpecialType != SpecialType.System_String)
                            continue;
                        if (Utils.IsVulnerable(item.Expression, model, solution, null, null, Enums.ScannerType.RegexInjection))
                            syntaxNodes.Add(item);
                    }
                }
            }
            return syntaxNodes;
        }
    }
}