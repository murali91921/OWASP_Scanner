using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class LdapSecureConnectionScanner : IScanner
    {
        private readonly static int[] UnsafeAuthenticationTypes ={
            0, //None
            16 //Anonymous
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
            var objectCreationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var objectCreation in objectCreationExpressions)
            {
                ITypeSymbol typeSymbol = model.GetTypeSymbol(objectCreation);
                if (typeSymbol == null || typeSymbol.ToString() != KnownType.System_DirectoryServices_DirectoryEntry)
                    continue;
                if (objectCreation.ArgumentList == null || objectCreation.ArgumentList.Arguments.Count < 4)
                    continue;
                // We're considering Argument length of 4 only
                // public DirectoryEntry (string path, string username, string password, System.DirectoryServices.AuthenticationTypes authenticationType);
                int index = -1;
                foreach (var item in objectCreation.ArgumentList.Arguments)
                {
                    index++;
                    if (item.NameColon == null && index == 3)
                    {
                        if (IsVulnerable(model, item.Expression))
                            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item, Enums.ScannerType.LdapSecureConnection));
                    }
                    else if (item.NameColon != null && item.NameColon.Name.ToString() == "authenticationType")
                    {
                        if (IsVulnerable(model, item.Expression))
                            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item, Enums.ScannerType.LdapSecureConnection));
                    }
                }
            }

            var assignmentExpressions = syntaxNode.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>();
            foreach (var assignmentExpression in assignmentExpressions)
            {
                ISymbol symbol = model.GetSymbol(assignmentExpression.Left);
                if (symbol == null || symbol.ToString() != KnownType.System_DirectoryServices_DirectoryEntry_AuthenticationType)
                    continue;
                if (IsVulnerable(model, assignmentExpression.Right))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, assignmentExpression.Right, Enums.ScannerType.LdapSecureConnection));
            }
            return vulnerabilities;
        }

        /// <summary>
        /// Determines whether <paramref name="expression"/> is vulnerable or not.
        /// </summary>
        /// <param name="model"></param>
        /// <param name="expression"></param>
        /// <returns></returns>
        private bool IsVulnerable(SemanticModel model, ExpressionSyntax expression)
            => model.GetConstantValue(expression) is { } constantValue
            && constantValue.HasValue && constantValue.Value is int authType
            && UnsafeAuthenticationTypes.Contains(authType);
    }
}
