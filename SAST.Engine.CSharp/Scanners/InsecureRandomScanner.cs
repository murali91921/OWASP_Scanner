using SAST.Engine.CSharp.Enums;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using SAST.Engine.CSharp.Constants;

namespace SAST.Engine.CSharp.Scanners
{
    /// <summary>
    /// This Scanner to find Insecure Random Vulnerabilities 
    /// </summary>
    internal class InsecureRandomScanner : IScanner
    {
        private readonly static string[] RandomMethods = {
            KnownMethod.System_Random_Next,
            KnownMethod.System_Random_NextDouble,
            KnownMethod.System_Random_NextBytes
        };

        /// <summary>
        /// This method will find Insecure Random Vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var invocations = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var method in invocations)
            {
                ISymbol symbol = model.GetSymbol(method);
                if (symbol == null)
                    continue;
                if (RandomMethods.Contains(symbol.ContainingType.ToString() + "." + symbol.Name.ToString()))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, method, ScannerType.InsecureRandom));
            }
            return vulnerabilities;
        }
    }
}