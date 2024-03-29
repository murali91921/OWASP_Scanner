﻿using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Constants;
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
        private readonly static string[] Rijndael_AesManaged_Class = {
            KnownType.System_Security_Cryptography_AesManaged,
            KnownType.System_Security_Cryptography_RijndaelManaged
        };
        private readonly static string[] RSAEncrypt_Methods = {
            KnownMethod.System_Security_Cryptography_RSACryptoServiceProvider_Encrypt,
            KnownMethod.System_Security_Cryptography_RSACryptoServiceProvider_TryEncrypt,
            KnownMethod.System_Security_Cryptography_RSA_Encrypt,
            KnownMethod.System_Security_Cryptography_RSA_TryEncrypt
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

            //Filtering AesManaged object creations
            var objectCreations = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var item in objectCreations)
            {
                ITypeSymbol typeSymbol = model.GetTypeSymbol(item);
                if (typeSymbol == null)
                    continue;
                if (Rijndael_AesManaged_Class.Contains(typeSymbol.ToString()))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item, Enums.ScannerType.WeakCipherModePadding));
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
                ITypeSymbol memberAccessType = symbol.GetTypeSymbol();
                if (memberAccessType == null)
                    continue;

                if (!RSAEncrypt_Methods.Contains(memberAccessType.ToString() + "." + memberAccess.Name))
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
                        {
                            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item, Enums.ScannerType.WeakCipherModePadding));
                            break;
                        }
                    }
                    else if (item.Expression is MemberAccessExpressionSyntax memberAccessExpression && memberAccessExpression.Name.ToString() == "Pkcs1")
                    {
                        typeSymbol = model.GetTypeSymbol(memberAccessExpression.Expression);
                        if (typeSymbol == null)
                            continue;
                        if (typeSymbol.ToString() == KnownType.System_Security_Cryptography_RSAEncryptionPadding)
                            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item, Enums.ScannerType.WeakCipherModePadding));
                    }
                }
            }
            return vulnerabilities;
        }
    }
}