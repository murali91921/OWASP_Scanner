using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text.RegularExpressions;

namespace SAST.Engine.CSharp.Scanners
{
    internal class WeakCryptoKeyLengthScanner : IScanner
    {
        private SemanticModel _model = null;

        private static readonly int MinimumKeyLength = 2048;
        private static readonly int MinimumECKeyLength = 224;
        private static readonly Regex NamedEllipticCurve = new Regex("^(secp|sect|prime|c2tnb|c2pnb|brainpoolP|B-|K-|P-)(?<KeyLength>\\d+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static readonly string System_Security_Cryptography_DSACryptoServiceProvider = "System.Security.Cryptography.DSACryptoServiceProvider";
        private static readonly string System_Security_Cryptography_RSACryptoServiceProvider = "System.Security.Cryptography.RSACryptoServiceProvider";
        private static readonly string Org_BouncyCastle_Crypto_Parameters_RsaKeyGenerationParameters = "Org.BouncyCastle.Crypto.Parameters.RsaKeyGenerationParameters";
        private static readonly string System_Security_Cryptography_CspParameters = "System.Security.Cryptography.CspParameters";
        private static readonly ImmutableArray<string> Org_BouncyCastle_Crypto_Generators_ParametersGenerators =
            ImmutableArray.Create(
                "Org.BouncyCastle.Crypto.Generators.DHParametersGenerator",
                "Org.BouncyCastle.Crypto.Generators.DsaParametersGenerator");
        private static readonly ImmutableArray<string> BouncyCastleCurveClasses =
            ImmutableArray.Create(
                "Org.BouncyCastle.Asn1.Nist.NistNamedCurves",
                "Org.BouncyCastle.Asn1.Sec.SecNamedCurves",
                "Org.BouncyCastle.Asn1.TeleTrust.TeleTrusTNamedCurves",
                "Org.BouncyCastle.Asn1.X9.ECNamedCurveTable",
                "Org.BouncyCastle.Asn1.X9.X962NamedCurves");
        private static readonly ImmutableArray<string> SystemSecurityCryptographyDsaRsa =
            ImmutableArray.Create(
                "System.Security.Cryptography.DSA",
                "System.Security.Cryptography.RSA");
        private static readonly ImmutableArray<string> SystemSecurityCryptographyCurveClasses =
            ImmutableArray.Create(
                "System.Security.Cryptography.ECDiffieHellman",
                "System.Security.Cryptography.ECDsa");

        /// <summary>
        /// Determines the vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            _model = model;
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();

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
                    syntaxNodes.Add(vulnerableNode);
            }

            //Object Creations
            var objectCreationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var objectCreation in objectCreationExpressions)
            {
                ITypeSymbol containingType = model.GetTypeSymbol(objectCreation);
                if (containingType == null)
                    continue;
                SyntaxNode vulnerableNode = null;
                if (CheckSystemSecurityCryptographyAlgorithms(containingType, objectCreation.ArgumentList))
                    vulnerableNode = objectCreation;
                else
                {
                    vulnerableNode = CheckSystemSecurityEllipticCurve(containingType, objectCreation.ArgumentList?.Arguments.FirstOrDefault());

                    if (vulnerableNode == null)
                        vulnerableNode = CheckBouncyCastleKeyGenerationParameters(containingType, objectCreation.ArgumentList);
                }
                if (vulnerableNode != null)
                    syntaxNodes.Add(vulnerableNode);
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
                {
                    if (Utils.DerivesFrom(typeSymbol, System_Security_Cryptography_DSACryptoServiceProvider) ||
                        Utils.DerivesFrom(typeSymbol, System_Security_Cryptography_RSACryptoServiceProvider))
                        syntaxNodes.Add(assignment);
                    else
                    {
                        if (CheckGenericDsaRsaCryptographyAlgorithms(typeSymbol, assignment.Right))
                            syntaxNodes.Add(assignment);
                    }
                }
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.WeakCryptoKeyLength);
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

            if (Utils.DerivesFromAny(containingType, SystemSecurityCryptographyDsaRsa.ToArray()) && IsInvalidCommonKeyLength(argument.Expression))
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
            if (argument == null || containingType == null || !Utils.DerivesFromAny(containingType, SystemSecurityCryptographyCurveClasses.ToArray()))
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
            if (argument == null || containingType == null || !Utils.DerivesFromAny(containingType, BouncyCastleCurveClasses.ToArray()))
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

            if (argument == null || !Utils.DerivesFromAny(containingType, Org_BouncyCastle_Crypto_Generators_ParametersGenerators.ToArray()))
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

            if (argument != null && Utils.DerivesFrom(containingType, Org_BouncyCastle_Crypto_Parameters_RsaKeyGenerationParameters)
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
            if (Utils.DerivesFrom(containingType, System_Security_Cryptography_DSACryptoServiceProvider)
                || (Utils.DerivesFrom(containingType, System_Security_Cryptography_RSACryptoServiceProvider) && HasDefaultSize(argumentList?.Arguments)))
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
            Utils.DerivesFromAny(containingType, SystemSecurityCryptographyDsaRsa.ToArray())
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
                return true;
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
                && Utils.DerivesFrom(type, System_Security_Cryptography_CspParameters));
        }
    }
}