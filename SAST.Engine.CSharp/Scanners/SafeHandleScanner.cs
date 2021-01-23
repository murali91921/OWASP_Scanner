using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Constants;
using SAST.Engine.CSharp.Contract;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class SafeHandleScanner : IScanner
    {
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var invocationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocationExpressions)
            {
                if (item.Expression is MemberAccessExpressionSyntax memberAccess)
                {
                    if (memberAccess.Name.ToString() != "DangerousGetHandle")
                        continue;
                    ITypeSymbol typeSymbol = model.GetTypeSymbol(memberAccess.Expression);
                    if (typeSymbol == null)
                        continue;
                    if (typeSymbol.ToString() == KnownType.System_Runtime_InteropServices_SafeHandle)
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, item, Enums.ScannerType.SafeHandle));
                }
                else if (item.Expression is MemberBindingExpressionSyntax memberBinding)
                {
                    if (memberBinding.Name.ToString() != "DangerousGetHandle")
                        continue;
                    if (item.Parent is ConditionalAccessExpressionSyntax conditionalAccess)
                    {
                        ITypeSymbol typeSymbol = model.GetTypeSymbol(conditionalAccess.Expression);
                        if (typeSymbol == null)
                            continue;
                        if (typeSymbol.ToString() == KnownType.System_Runtime_InteropServices_SafeHandle)
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, conditionalAccess, Enums.ScannerType.SafeHandle));
                    }
                }
            }
            return vulnerabilities;
        }
    }
}