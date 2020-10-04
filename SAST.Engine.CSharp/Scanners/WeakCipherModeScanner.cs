using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    /// <summary>
    /// This scanner was not developed thoroughly.
    /// </summary>
    internal class WeakCipherModeScanner : IScanner
    {
        private static string AesManaged_Class = "System.Security.Cryptography.AesManaged";
        private static string RSAEncryptPadding_Class = "System.Security.Cryptography.RSAEncryptionPadding";
        private static string[] RSAEncrypt_Methods = {
            "System.Security.Cryptography.RSACryptoServiceProvider.Encrypt",
            "System.Security.Cryptography.RSA.Encrypt",
            "System.Security.Cryptography.RSA.TryEncrypt"
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

            //Filtering AesManaged object creations
            var objectCreations = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var item in objectCreations)
            {
                ITypeSymbol typeSymbol = model.GetTypeSymbol(item);
                if (typeSymbol == null)
                    continue;
                if (typeSymbol.ToString() == AesManaged_Class)
                    syntaxNodes.Add(item);
            }

            //Filtering Encrypt,TryEncrypt Invocations
            var invocations = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var invocation in invocations)
            {
                if (!invocation.Expression.ToString().Contains("Encrypt"))
                    continue;

                ISymbol symbol = model.GetSymbol(invocation);
                if (symbol == null)
                    continue;

                if (!RSAEncrypt_Methods.Contains(symbol.ContainingType.ToString() + "." + symbol.Name))
                    continue;

                foreach (var item in invocation.ArgumentList.Arguments)
                {
                    ITypeSymbol typeSymbol = model.GetTypeSymbol(item.Expression);
                    if (typeSymbol == null)
                        continue;
                    if (typeSymbol.SpecialType == SpecialType.System_Boolean)
                    {
                        var optional = model.GetConstantValue(item.Expression);
                        if (optional.HasValue && optional.Value is bool value && !value)
                            syntaxNodes.Add(item);
                    }
                    else if (typeSymbol.ToString() == RSAEncryptPadding_Class)
                    {
                        symbol = model.GetSymbol(item.Expression);
                        if (symbol == null)
                            continue;

                        if (symbol.ToString() == RSAEncryptPadding_Class + ".Pkcs1")
                            syntaxNodes.Add(item);
                    }
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.WeakCipherModePadding);
        }
    }
}