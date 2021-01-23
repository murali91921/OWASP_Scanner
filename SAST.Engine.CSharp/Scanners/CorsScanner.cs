using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Immutable;

namespace SAST.Engine.CSharp.Scanners
{
    internal class CorsScanner : IScanner
    {
        /// <summary>
        /// Determines the Cors AllowAnyOrigin vulnerabilities in <paramref name="syntaxNode"/>
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var invocations = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            //System.Console.WriteLine(filePath);
            foreach (var item in invocations)
            {
                if (!item.ToString().Contains("AllowAnyOrigin"))
                    continue;

                ISymbol symbol = model.GetSymbol(item);
                if (symbol == null || symbol is IErrorTypeSymbol)
                    continue;

                if (symbol.ContainingType.ToString() == Constants.KnownType.Microsoft_AspNetCore_Cors_Infrastructure_CorsPolicyBuilder
                    && symbol.Name.ToString() == "AllowAnyOrigin")
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item, Enums.ScannerType.CorsAllowAnyOrigin));
            }
            return vulnerabilities;
        }
    }
}