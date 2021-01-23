using SAST.Engine.CSharp.Enums;
using System;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System.Reflection;
using SAST.Engine.CSharp.Mapper;
using System.IO;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;

namespace SAST.Engine.CSharp.Scanners
{
    internal class WeakHashingValidator : IScanner
    {
        static readonly string[] WeakTypes = {
            KnownType.System_Security_Cryptography_SHA1,
            KnownType.System_Security_Cryptography_MD5,
            KnownType.System_Security_Cryptography_DSA,
            KnownType.System_Security_Cryptography_RIPEMD160,
            KnownType.System_Security_Cryptography_HMACSHA1,
            KnownType.System_Security_Cryptography_HMACMD5,
            KnownType.System_Security_Cryptography_HMACRIPEMD160,
            KnownType.System_Security_Cryptography_Rfc2898DeriveBytes
            };

        static readonly string[] ParameteredHashings = {
            KnownMethod.System_Security_Cryptography_CryptoConfig_CreateFromName,
            KnownMethod.System_Security_Cryptography_HashAlgorithm_Create,
            KnownMethod.System_Security_Cryptography_KeyedHashAlgorithm_Create,
            KnownMethod.System_Security_Cryptography_AsymmetricAlgorithm_Create,
            KnownMethod.System_Security_Cryptography_HMAC_Create
            };
        static readonly string[] ParameterNames = {
            "SHA1",
            "MD5",
            "DSA",
            "HMACMD5",
            "HMACRIPEMD160",
            "RIPEMD160",
            "RIPEMD160Managed"
        };
        static readonly string[] QualifiedPropertyNames = {
            KnownType.System_Security_Cryptography_HashAlgorithmName_MD5,
            KnownType.System_Security_Cryptography_HashAlgorithmName_SHA1
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
            var syntaxNodes = syntaxNode.DescendantNodes().Where(obj => obj.IsKind(SyntaxKind.InvocationExpression)
                                                    || obj.IsKind(SyntaxKind.ObjectCreationExpression));
            foreach (var item in syntaxNodes)
            {
                if (item is ObjectCreationExpressionSyntax objectCreation)
                {
                    var typeSymbol = model.GetTypeSymbol(objectCreation);
                    if (Utils.DerivesFromAny(typeSymbol, WeakTypes))
                    {
                        if (objectCreation.ArgumentList == null)
                            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, objectCreation, ScannerType.WeakHashingConfig));
                        else
                            foreach (var argument in objectCreation.ArgumentList.Arguments)
                            {
                                var argSymbol = model.GetSymbol(argument.Expression);
                                if (argSymbol != null && QualifiedPropertyNames.Contains(argSymbol.ToString()))
                                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, objectCreation, ScannerType.WeakHashingConfig));
                            }
                    }
                }
                else if (item is InvocationExpressionSyntax invocation)
                {
                    if (model.GetSymbol(invocation) is IMethodSymbol methodSymbol)
                        if (Utils.DerivesFromAny(methodSymbol.ReturnType, WeakTypes) || CheckWeakHashingCreation(methodSymbol, invocation.ArgumentList))
                            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item, ScannerType.WeakHashingConfig));
                }
            }
            return vulnerabilities;
        }

        /// <summary>
        /// Determines <paramref name="methodSymbol"/> have WeakHashing or not.
        /// </summary>
        /// <param name="methodSymbol"></param>
        /// <param name="argumentList"></param>
        /// <returns></returns>
        private static bool CheckWeakHashingCreation(IMethodSymbol methodSymbol, ArgumentListSyntax argumentList)
        {
            if (argumentList != null && methodSymbol?.ContainingType != null && methodSymbol.Name != null)
            {
                var methodFullName = methodSymbol.ContainingType + methodSymbol.Name;
                if (argumentList.Arguments.Count == 0)
                    return methodFullName == KnownMethod.System_Security_Cryptography_HMAC_Create;
                if (argumentList.Arguments.Count > 1 || !argumentList.Arguments.First().Expression.IsKind(SyntaxKind.StringLiteralExpression))
                    return false;
                if (!ParameteredHashings.Contains(methodFullName))
                    return false;
                var literalExpressionSyntax = (LiteralExpressionSyntax)argumentList.Arguments.First().Expression;
                return ParameterNames.Any(alg => alg.Equals(literalExpressionSyntax.Token.ValueText, StringComparison.Ordinal));
            }
            return false;
        }
    }
}