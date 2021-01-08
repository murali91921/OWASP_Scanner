using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Constants;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class PasswordLockoutScanner : IScanner
    {
        /// <summary>
        /// Detremines Password Lockout vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> vulnerabilities = new List<SyntaxNode>();
            var invocationExpressions = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocationExpressions)
            {
                var memberAccess = item.Expression as MemberAccessExpressionSyntax;
                if (memberAccess == null)
                    continue;
                if (!memberAccess.ToString().Contains("PasswordSignIn"))
                    continue;

                ISymbol symbol = model.GetSymbol(memberAccess);
                if (symbol == null)
                    continue;

                if (symbol.ContainingNamespace.ToString() != KnownType.Microsoft_AspNet_Identity_Owin &&
                    symbol.ContainingNamespace.ToString() != KnownType.Microsoft_AspNetCore_Identity)
                    continue;
                int argCount = symbol.Name == "CheckPasswordSignInAsync" ? 3 : 4;
                string parameterName = symbol.ContainingNamespace.ToString() == KnownType.Microsoft_AspNet_Identity_Owin ? "shouldLockout" : "lockoutOnFailure";
                if (item.ArgumentList == null || item.ArgumentList.Arguments.Count < argCount)
                    continue;
                int i = -1;
                foreach (var argument in item.ArgumentList.Arguments)
                {
                    i++;
                    if (argument.NameColon == null && i != argCount - 1)
                        continue;
                    else if (argument.NameColon != null && argument.NameColon.Name.ToString() != parameterName)
                        continue;

                    var lockoutValue = model.GetConstantValue(argument.Expression);
                    if (lockoutValue.HasValue && lockoutValue.Value is bool value && !value)
                        vulnerabilities.Add(argument);
                    break;
                }
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, vulnerabilities, Enums.ScannerType.PasswordLockout);
        }
    }
}