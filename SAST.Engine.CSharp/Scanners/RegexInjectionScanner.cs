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
        private static readonly string[] Match_Methods =
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
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            vulnerabilities.AddRange(FindObjectCreations(filePath, syntaxNode, model, solution));
            vulnerabilities.AddRange(FindInvocations(filePath, syntaxNode, model, solution));
            return vulnerabilities;
        }

        private IEnumerable<VulnerabilityDetail> FindObjectCreations(string filePath, SyntaxNode syntaxNode, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var objectCreations = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var objectCreation in objectCreations)
            {
                ITypeSymbol objectTypeSymbol = model.GetTypeSymbol(objectCreation);
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
                        if (Utils.IsVulnerable(item.Expression, model, solution, null, Enums.ScannerType.RegexInjection))
                            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item, Enums.ScannerType.PropertyAccessor));
                    }
                }
            }
            return vulnerabilities;
        }

        private IEnumerable<VulnerabilityDetail> FindInvocations(string filePath, SyntaxNode syntaxNode, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var invocationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var invocationExpression in invocationExpressions)
            {
                if (!(model.GetSymbol(invocationExpression) is IMethodSymbol methodSymbol))
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
                        if (Utils.IsVulnerable(item.Expression, model, solution, null, Enums.ScannerType.RegexInjection))
                            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item, Enums.ScannerType.RegexInjection));
                    }
                }
            }
            return vulnerabilities;
        }
    }
}