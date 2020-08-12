using SAST.Engine.CSharp.Enums;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using SAST.Engine.CSharp.Contract;
using static System.Console;
using SAST.Engine.CSharp.Mapper;

namespace SAST.Engine.CSharp.Scanners
{
    public class InsecureRandomScanner : IScanner
    {
        // private static string RandomClass = "System.Random";
        private static string[] RandomMethods = {
            "System.Random.Next",
            "System.Random.NextDouble",
            "System.Random.NextBytes"};

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            List<SyntaxNode> lstVulnerableCheck = new List<SyntaxNode>();
            // var objectCreationExpressions = rootNode.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
            // foreach (var objectCreation in objectCreationExpressions)
            // {
            //     IMethodSymbol symbol = model.GetSymbolInfo(objectCreation).Symbol as IMethodSymbol;
            //     if(symbol.ContainingType.ToString() == RandomClass && symbol.MethodKind == MethodKind.Constructor)
            //         lstVulnerableStatements.Add(objectCreation);
            // }
            var invocations = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var method in invocations)
            {
                IMethodSymbol symbol = model.GetSymbolInfo(method).Symbol as IMethodSymbol;
                string symbolMethod = symbol == null ? null : symbol.ContainingType.ToString() + "." + symbol.Name.ToString();
                if (RandomMethods.Any(obj => obj == symbolMethod))
                    lstVulnerableStatements.Add(method);
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, ScannerType.InsecureRandom);
        }

    }
}