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
        private static string RSAEncryptPadding_Class = "System.Security.Cryptography.RSAEncryptionPadding";
        private static string[] Rijndael_AesManaged_Class = {
            "System.Security.Cryptography.AesManaged",
            "System.Security.Cryptography.RijndaelManaged"
        };
        private static string[] RSAEncrypt_Methods = {
            "System.Security.Cryptography.RSACryptoServiceProvider.Encrypt",
            "System.Security.Cryptography.RSACryptoServiceProvider.TryEncrypt",
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
                if (Rijndael_AesManaged_Class.Contains(typeSymbol.ToString()))
                    syntaxNodes.Add(item);
            }

            //Filtering Encrypt,TryEncrypt Invocations
            var invocations = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var invocation in invocations)
            {
                if (!invocation.Expression.ToString().Contains("Encrypt"))
                    continue;
                if (!invocation.Expression.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.SimpleMemberAccessExpression))
                    continue;
                var memberAccess = invocation.Expression as MemberAccessExpressionSyntax;
                ISymbol symbol = model.GetSymbol(memberAccess.Expression);
                if (symbol == null)
                    continue;
                ITypeSymbol memberAccessType = symbol is ILocalSymbol local ? local.Type
                    : symbol is IFieldSymbol field ? field.Type
                    : symbol is IPropertySymbol property ? property.Type : null;

                if (memberAccessType == null)
                    continue;

                if (!RSAEncrypt_Methods.Contains(memberAccessType.ToString() + "." + memberAccess.Name))
                    continue;

                foreach (var item in invocation.ArgumentList.Arguments)
                {
                    ISymbol argSymbol = model.GetSymbol(item.Expression);
                    ITypeSymbol typeSymbol = model.GetTypeSymbol(item.Expression);
                    if (typeSymbol == null)
                        continue;
                    if (typeSymbol.SpecialType == SpecialType.System_Boolean)
                    {
                        var optional = model.GetConstantValue(item.Expression);
                        if (optional.HasValue && optional.Value is bool value && !value)
                        {
                            syntaxNodes.Add(item);
                            break;
                        }
                    }
                    else if (item.Expression is MemberAccessExpressionSyntax memberAccessExpression
                        && memberAccessExpression.Name.ToString() == "Pkcs1")
                    {
                        typeSymbol = model.GetTypeSymbol(memberAccessExpression.Expression);
                        if (typeSymbol == null)
                            continue;
                        if (typeSymbol.ToString() == RSAEncryptPadding_Class)
                            syntaxNodes.Add(item);
                    }
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.WeakCipherModePadding);
        }
    }
}