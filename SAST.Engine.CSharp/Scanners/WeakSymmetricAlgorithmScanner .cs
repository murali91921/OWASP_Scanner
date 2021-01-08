using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;
using SAST.Engine.CSharp.Mapper;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class WeakSymmetricAlgorithmScanner : IScanner
    {
        private static readonly string[] WeakAlgorithmTypes = {
            KnownType.System_Security_Cryptography_TripleDESCryptoServiceProvider,
            KnownType.System_Security_Cryptography_DESCryptoServiceProvider,
            KnownType.System_Security_Cryptography_RC2CryptoServiceProvider
        };

        private static readonly string[] WeakAlgorithmMethods = {
            KnownMethod.System_Security_Cryptography_DES_Create,
            KnownMethod.System_Security_Cryptography_RC2_Create,
            KnownMethod.System_Security_Cryptography_TripleDES_Create
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
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            var Nodes = syntaxNode.DescendantNodes().Where(obj => obj.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.ObjectCreationExpression)
                                                               || obj.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.InvocationExpression));
            foreach (var item in Nodes)
            {
                if (item is InvocationExpressionSyntax invocation)
                {
                    if (!invocation.ToString().Contains("Create"))
                        continue;
                    ISymbol symbol = model.GetSymbol(invocation);
                    if (symbol == null)
                        continue;
                    if (WeakAlgorithmMethods.Any(obj => obj == symbol.ContainingType.ToString() + "." + symbol.Name.ToString()))
                        lstVulnerableStatements.Add(item);
                }
                else if (item is ObjectCreationExpressionSyntax objectCreation)
                {
                    if (Utils.DerivesFromAny(model.GetTypeSymbol(item), WeakAlgorithmTypes))
                        lstVulnerableStatements.Add(item);
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, Enums.ScannerType.WeakSymmetricAlgorithm);
        }
    }
}