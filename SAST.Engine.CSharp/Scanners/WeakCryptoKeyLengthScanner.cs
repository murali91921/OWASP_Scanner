﻿using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text.RegularExpressions;

namespace SAST.Engine.CSharp.Scanners
{
    internal class WeakCryptoKeyLengthScanner : IScanner
    {
        private SemanticModel _model = null;
        private static readonly string message = "Use a key length of at least {0} bits for cipher algorithm.";
        private static readonly string uselessAssignmentInfo = "This assignment does not update the underlying key size.";

        private static readonly int MinimumKeyLength = 2048;
        private static readonly int MinimumECKeyLength = 224;
        private static readonly Regex NamedEllipticCurve = new Regex("^(secp|sect|prime|c2tnb|c2pnb|brainpoolP|B-|K-|P-)(?<KeyLength>\\d+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly string[] Org_BouncyCastle_Crypto_Generators_ParametersGenerators = {
            KnownType.Org_BouncyCastle_Crypto_Generators_DHParametersGenerator,
            KnownType.Org_BouncyCastle_Crypto_Generators_DsaParametersGenerator
        };
        private static readonly string[] BouncyCastleCurveClasses = {
            KnownType.Org_BouncyCastle_Asn1_Nist_NistNamedCurves,
            KnownType.Org_BouncyCastle_Asn1_Sec_SecNamedCurves,
            KnownType.Org_BouncyCastle_Asn1_TeleTrust_TeleTrusTNamedCurves,
            KnownType.Org_BouncyCastle_Asn1_X9_ECNamedCurveTable,
            KnownType.Org_BouncyCastle_Asn1_X9_X962NamedCurves
        };
        private static readonly string[] SystemSecurityCryptographyDsaRsa ={
            KnownType.System_Security_Cryptography_DSA,
            KnownType.System_Security_Cryptography_RSA
        };
        private static readonly string[] SystemSecurityCryptographyCurveClasses = {
            KnownType.System_Security_Cryptography_ECDiffieHellman,
            KnownType.System_Security_Cryptography_ECDsa
        };

        /// <summary>
        /// Determines the vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        int messageKeyLength = 0;
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            _model = model;
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();

            //Invocation Expressions
            var invocationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var invocation in invocationExpressions)
            {
                ISymbol symbol = model.GetSymbol(invocation);
                if (symbol == null)
                    continue;
                SyntaxNode vulnerableNode = null;

                switch (symbol.Name)
                {
                    case "Create":
                        vulnerableNode = CheckAlgorithmCreation(symbol.ContainingType, invocation.ArgumentList?.Arguments.FirstOrDefault());
                        break;
                    case "GenerateKey":
                        vulnerableNode = CheckSystemSecurityEllipticCurve(symbol.ContainingType, invocation.ArgumentList?.Arguments.FirstOrDefault());
                        break;
                    case "GetByName":
                        vulnerableNode = CheckBouncyCastleEllipticCurve(symbol.ContainingType, invocation.ArgumentList?.Arguments.FirstOrDefault());
                        break;
                    case "Init":
                        vulnerableNode = CheckBouncyCastleParametersGenerators(symbol.ContainingType, invocation.ArgumentList);
                        break;
                    default:
                        break;
                }
                if (vulnerableNode != null)
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, vulnerableNode, Enums.ScannerType.WeakCryptoKeyLength, string.Format(message, messageKeyLength)));
            }

            //Object Creations
            var objectCreationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var objectCreation in objectCreationExpressions)
            {
                ITypeSymbol containingType = model.GetTypeSymbol(objectCreation);
                if (containingType == null)
                    continue;
                SyntaxNode vulnerableNode;
                if (CheckSystemSecurityCryptographyAlgorithms(containingType, objectCreation.ArgumentList))
                    vulnerableNode = objectCreation;
                else
                {
                    vulnerableNode = CheckSystemSecurityEllipticCurve(containingType, objectCreation.ArgumentList?.Arguments.FirstOrDefault());
                    if (vulnerableNode == null)
                        vulnerableNode = CheckBouncyCastleKeyGenerationParameters(containingType, objectCreation.ArgumentList);
                }
                if (vulnerableNode != null)
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, vulnerableNode, Enums.ScannerType.WeakCryptoKeyLength, string.Format(message, messageKeyLength)));
            }

            //Property Assignments
            var assignments = syntaxNode.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>();
            foreach (var assignment in assignments)
            {
                SyntaxNode leftSyntaxNode = assignment.Left;
                ITypeSymbol typeSymbol = null;

                if (leftSyntaxNode is IdentifierNameSyntax identifierName && identifierName.ToString() == "KeySize")
                {
                    if (assignment.Parent is InitializerExpressionSyntax initializer && initializer.Parent is ObjectCreationExpressionSyntax objectCreation)
                        typeSymbol = model.GetTypeSymbol(objectCreation);
                }
                else if (leftSyntaxNode is MemberAccessExpressionSyntax memberAccess && memberAccess.Name.ToString() == "KeySize")
                    typeSymbol = model.GetTypeSymbol(memberAccess.Expression);

                if (typeSymbol == null)
                    continue;

                if (Utils.DerivesFrom(typeSymbol, KnownType.System_Security_Cryptography_DSACryptoServiceProvider) ||
                    Utils.DerivesFrom(typeSymbol, KnownType.System_Security_Cryptography_RSACryptoServiceProvider) ||
                    CheckGenericDsaRsaCryptographyAlgorithms(typeSymbol, assignment.Right))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, assignment, Enums.ScannerType.WeakCryptoKeyLength, string.Format(message, MinimumKeyLength) + uselessAssignmentInfo));
            }
            return vulnerabilities;
        }

        /// <summary>
        /// Checking whether Algorithm.Create() method is Vulenrable or not.If yes, return vulenrable Expression, else null.
        /// </summary>
        /// <param name="containingType"></param>
        /// <param name="argument"></param>
        /// <returns></returns>
        private SyntaxNode CheckAlgorithmCreation(ITypeSymbol containingType, ArgumentSyntax argument)
        {
            if (argument == null || containingType == null)
                return null;

            if (Utils.DerivesFromAny(containingType, SystemSecurityCryptographyDsaRsa) && IsInvalidCommonKeyLength(argument.Expression))
                return argument;
            else
                return CheckSystemSecurityEllipticCurve(containingType, argument);
        }

        /// <summary>
        /// Checking whether <paramref name="argument"/> is weak for System.Security.EllipticCurve Encryption Algorithm.
        /// </summary>
        /// <param name="containingType"></param>
        /// <param name="argument"></param>
        /// <returns></returns>
        private SyntaxNode CheckSystemSecurityEllipticCurve(ITypeSymbol containingType, ArgumentSyntax argument)
        {
            if (argument == null || containingType == null || !Utils.DerivesFromAny(containingType, SystemSecurityCryptographyCurveClasses))
                return null;

            var paramSymbol = _model.GetSymbol(argument.Expression);
            if (paramSymbol == null)
                return null;

            return IsInvalidCurveNameKeyLength(paramSymbol.Name) ? argument : null;
        }

        /// <summary>
        /// Checking whether <paramref name="argument"/> is weak for Org.BouncyCastle Curves.
        /// </summary>
        /// <param name="containingType"></param>
        /// <param name="argument"></param>
        /// <returns></returns>
        private SyntaxNode CheckBouncyCastleEllipticCurve(ITypeSymbol containingType, ArgumentSyntax argument)
        {
            if (argument == null || containingType == null || !Utils.DerivesFromAny(containingType, BouncyCastleCurveClasses))
                return null;

            var param = _model.GetConstantValue(argument.Expression);
            if (param.HasValue && param.Value is string curveId)
                return IsInvalidCurveNameKeyLength(curveId) ? argument : null;

            return null;
        }

        /// <summary>
        /// Determines the vulnerablity in <paramref name="argumentList"/> for Parameter Generators Org.BouncyCastle package.
        /// </summary>
        /// <param name="containingType"></param>
        /// <param name="argumentList"></param>
        /// <returns></returns>
        private SyntaxNode CheckBouncyCastleParametersGenerators(ITypeSymbol containingType, ArgumentListSyntax argumentList)
        {
            if (argumentList == null || containingType == null)
                return null;

            ArgumentSyntax argument = null;
            foreach (var item in argumentList.Arguments)
            {
                if (item.NameColon is null)
                {
                    argument = item;
                    break;
                }
                else if (item.NameColon.Name.ToString() == "size")
                {
                    argument = item;
                    break;
                }
            }

            if (argument == null || !Utils.DerivesFromAny(containingType, Org_BouncyCastle_Crypto_Generators_ParametersGenerators))
                return null;

            if (IsInvalidCommonKeyLength(argument.Expression))
                return argument;

            return null;
        }

        /// <summary>
        /// Determines the vulnerablity in <paramref name="argumentList"/> for RsaKeyGenerationParameters Org.BouncyCastle package.
        /// 
        /// </summary>
        /// <param name="containingType"></param>
        /// <param name="objectCreation"></param>
        /// <returns></returns>
        private SyntaxNode CheckBouncyCastleKeyGenerationParameters(ITypeSymbol containingType, ArgumentListSyntax ArgumentList)
        {
            if (ArgumentList == null)
                return null;
            ArgumentSyntax argument = null;
            int i = 0;
            foreach (var item in ArgumentList?.Arguments)
            {
                if (item.NameColon is null)
                {
                    if (i == 2)
                    {
                        argument = item;
                        break;
                    }
                }
                else if (item.NameColon.Name.ToString() == "strength")
                {
                    argument = item;
                    break;
                }
                i++;
            }

            if (argument != null && Utils.DerivesFrom(containingType, KnownType.Org_BouncyCastle_Crypto_Parameters_RsaKeyGenerationParameters)
                && IsInvalidCommonKeyLength(argument.Expression))
                return argument;
            return null;
        }

        /// <summary>
        /// Checking <paramref name="argumentList"/> is vulnerable or not according to <paramref name="containingType"/>
        /// </summary>
        /// <param name="containingType"></param>
        /// <param name="argumentList"></param>
        /// <returns></returns>
        private bool CheckSystemSecurityCryptographyAlgorithms(ITypeSymbol containingType, ArgumentListSyntax argumentList)
        {
            // DSACryptoServiceProvider is always not safe as it has maximum key size of 1024
            // RSACryptoServiceProvider constructors are not safe as they have a default key size of 1024
            if (Utils.DerivesFrom(containingType, KnownType.System_Security_Cryptography_DSACryptoServiceProvider)
                || (Utils.DerivesFrom(containingType, KnownType.System_Security_Cryptography_RSACryptoServiceProvider) && HasDefaultSize(argumentList?.Arguments)))
                return true;
            var argument = argumentList?.Arguments.FirstOrDefault();
            return CheckGenericDsaRsaCryptographyAlgorithms(containingType, argument?.Expression);
        }

        /// <summary>
        /// Checking <paramref name="keyLengthSyntax"/> is vulnerable according to <paramref name="containingType"/>
        /// </summary>
        /// <param name="containingType"></param>
        /// <param name="keyLengthSyntax"></param>
        /// <returns></returns>
        private bool CheckGenericDsaRsaCryptographyAlgorithms(ITypeSymbol containingType, SyntaxNode keyLengthSyntax) =>
            Utils.DerivesFromAny(containingType, SystemSecurityCryptographyDsaRsa)
                && keyLengthSyntax != null && IsInvalidCommonKeyLength(keyLengthSyntax);

        /// <summary>
        /// Checking <paramref name="curveName"/> is Invalid or not.
        /// </summary>
        /// <param name="curveName"></param>
        /// <returns></returns>
        private bool IsInvalidCurveNameKeyLength(string curveName)
        {
            var match = NamedEllipticCurve.Match(curveName);
            if (match.Success && int.TryParse(match.Groups["KeyLength"].Value, out var keyLength) && keyLength < MinimumECKeyLength)
            {
                messageKeyLength = MinimumECKeyLength;
                return true;
            }
            return false;
        }

        /// <summary>
        /// Checking <paramref name="keyLengthSyntax"/> is vulnerable or not
        /// </summary>
        /// <param name="keyLengthSyntax"></param>
        /// <returns></returns>
        private bool IsInvalidCommonKeyLength(SyntaxNode keyLengthSyntax)
        {
            var optionalKeyLength = _model.GetConstantValue(keyLengthSyntax);
            messageKeyLength = MinimumKeyLength;
            return optionalKeyLength.HasValue && optionalKeyLength.Value is int keyLength && keyLength < MinimumKeyLength;
        }

        /// <summary>
        /// Checking <paramref name="arguments"/> is vulnerable or not 
        /// </summary>
        /// <param name="arguments"></param>
        /// <returns></returns>
        private bool HasDefaultSize(SeparatedSyntaxList<ArgumentSyntax>? arguments)
        {
            return arguments == null || arguments?.Count == 0
                || (arguments?.Count == 1 && _model.GetTypeSymbol(arguments?[0].Expression) is ITypeSymbol type
                && Utils.DerivesFrom(type, KnownType.System_Security_Cryptography_CspParameters));
        }
    }
}