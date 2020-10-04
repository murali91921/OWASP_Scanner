using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using System.Linq;
using System.Collections.Generic;

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
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var invocations = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocations)
            {
                if (!item.ToString().Contains("AllowAnyOrigin"))
                    continue;

                ISymbol symbol = model.GetSymbol(item);
                if (symbol == null || symbol is IErrorTypeSymbol)
                    continue;

                if (symbol.ContainingType.ToString() == "Microsoft.AspNetCore.Cors.Infrastructure.CorsPolicyBuilder"
                    && symbol.Name.ToString() == "AllowAnyOrigin")
                    syntaxNodes.Add(item);
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.CorsAllowAnyOrigin);
        }
    }
}