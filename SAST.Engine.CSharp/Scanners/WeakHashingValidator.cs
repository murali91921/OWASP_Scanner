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

namespace SAST.Engine.CSharp.Scanners
{
    public class WeakHashingValidator : IScanner
    {
        static readonly string[] WeakTypes = {
            "System.Security.Cryptography.SHA1",
            "System.Security.Cryptography.MD5",
            "System.Security.Cryptography.DSA",
            "System.Security.Cryptography.RIPEMD160",
            "System.Security.Cryptography.HMACSHA1",
            "System.Security.Cryptography.HMACMD5",
            "System.Security.Cryptography.HMACRIPEMD160",
            "System.Security.Cryptography.Rfc2898DeriveBytes"
            };
        static readonly string[] ParameterlessHashings = { "System.Security.Cryptography.HMAC.Create" };
        static readonly string[] ParameteredHashings = {
            "System.Security.Cryptography.CryptoConfig.CreateFromName",
            "System.Security.Cryptography.HashAlgorithm.Create",
            "System.Security.Cryptography.KeyedHashAlgorithm.Create",
            "System.Security.Cryptography.AsymmetricAlgorithm.Create",
            "System.Security.Cryptography.HMAC.Create"
            };
        static readonly string[] ParameterNames = { "SHA1", "MD5", "DSA", "HMACMD5", "HMACRIPEMD160", "RIPEMD160", "RIPEMD160Managed" };
        static readonly string[] QualifiedPropertyNames = {"System.Security.Cryptography.HashAlgorithmName.MD5",
            "System.Security.Cryptography.HashAlgorithmName.SHA1"};
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            var syntaxNodes = syntaxNode.DescendantNodes().Where(obj => obj.IsKind(SyntaxKind.InvocationExpression)
                                                    || obj.IsKind(SyntaxKind.ObjectCreationExpression));
            foreach (var item in syntaxNodes)
            {
                // Console.WriteLine(item);
                if (item is ObjectCreationExpressionSyntax)
                {
                    ObjectCreationExpressionSyntax objectCreation = item as ObjectCreationExpressionSyntax;
                    var typeInfo = model.GetTypeInfo(objectCreation);
                    if (Utils.DerivesFromAny(typeInfo.ConvertedType, WeakTypes))
                    {
                        if (objectCreation.ArgumentList == null)
                            lstVulnerableStatements.Add(objectCreation);
                        else
                        {
                            foreach (var argument in objectCreation.ArgumentList.Arguments)
                            {
                                var argSymbol = model.GetSymbolInfo(argument.Expression);
                                // Console.WriteLine(objectCreation);
                                // Console.WriteLine(argSymbol.Symbol);
                                if (argSymbol.Symbol != null && QualifiedPropertyNames.Any(name => name == argSymbol.Symbol.ToString()))
                                    lstVulnerableStatements.Add(objectCreation);
                            }
                        }
                    }
                }
                else
                {
                    InvocationExpressionSyntax invocation = item as InvocationExpressionSyntax;
                    if (model.GetSymbolInfo((item as InvocationExpressionSyntax).Expression).Symbol is IMethodSymbol methodSymbol)
                        if (Utils.DerivesFromAny(methodSymbol.ReturnType, WeakTypes) || CheckWeakHashingCreation(methodSymbol, invocation.ArgumentList))
                        {
                            lstVulnerableStatements.Add(item);
                        }
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, ScannerType.WeakHashingConfig);
        }
        private static bool CheckWeakHashingCreation(IMethodSymbol methodSymbol, ArgumentListSyntax argumentList)
        {
            if (argumentList != null && methodSymbol?.ContainingType != null && methodSymbol.Name != null)
            {
                var methodFullName = $"{methodSymbol.ContainingType}.{methodSymbol.Name}";
                if (argumentList.Arguments.Count == 0)
                    return ParameterlessHashings.Contains(methodFullName);
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