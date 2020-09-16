using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class WeakSymmetricAlgorithmScanner : IScanner
    {
        private static readonly string[] WeakAlgorithmTypes = {
            "System.Security.Cryptography.TripleDESCryptoServiceProvider",
            "System.Security.Cryptography.DESCryptoServiceProvider",
            "System.Security.Cryptography.RC2CryptoServiceProvider"
        };

        private static readonly string[] WeakAlgorithmMethods = {
            "System.Security.Cryptography.DES.Create",
            "System.Security.Cryptography.RC2.Create",
            "System.Security.Cryptography.TripleDES.Create"
        };

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
                    TypeInfo typeInfo = model.GetTypeInfo(item);
                    if (Utils.DerivesFromAny(typeInfo.Type, WeakAlgorithmTypes))
                        lstVulnerableStatements.Add(item);
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, Enums.ScannerType.WeakSymmetricAlgorithm);
        }
    }
}