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
        static readonly string[] WeakAlgorithms = {
            "System.Security.Cryptography.TripleDESCryptoServiceProvider",
            "System.Security.Cryptography.DESCryptoServiceProvider",
            "System.Security.Cryptography.RC2CryptoServiceProvider"
        };
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            var Nodes = syntaxNode.DescendantNodes().Where(obj => obj.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.ObjectCreationExpression)
                                                               || obj.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.InvocationExpression));
            foreach (var item in Nodes)
            {
                TypeInfo typeInfo = model.GetTypeInfo(item);
                if (typeInfo.Type == null)
                    continue;
                if (Utils.DerivesFromAny(typeInfo.Type, WeakAlgorithms))
                    lstVulnerableStatements.Add(item);
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, Enums.ScannerType.WeakSymmetricAlgorithm);
        }
    }
}
