using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class PasswordLockoutScanner : IScanner
    {
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
                if (symbol.ContainingNamespace.ToString() == "Microsoft.AspNet.Identity.Owin")
                {
                    var args = item.ArgumentList;
                    if (args == null || args.Arguments.Count < 4)
                        continue;
                    int i = -1;
                    foreach (var argument in args.Arguments)
                    {
                        i++;
                        if (argument.NameColon == null && i != 3)
                            continue;
                        else if (argument.NameColon != null && argument.NameColon.Name.ToString() != "shouldLockout")
                            continue;
                        var lockoutValue = model.GetConstantValue(argument.Expression);
                        if (lockoutValue.HasValue && lockoutValue.Value is bool value && !value)
                            vulnerabilities.Add(argument);
                        break;
                    }
                }
                //Under Development
                //else if ()
                //{ }
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, vulnerabilities, Enums.ScannerType.PasswordLockout);
        }
    }
}