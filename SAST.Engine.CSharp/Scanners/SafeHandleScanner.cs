using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class SafeHandleScanner : IScanner
    {
        private static string SafeHandle_Type = "System.Runtime.InteropServices.SafeHandle";
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
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
                    if (typeSymbol.ToString() == SafeHandle_Type)
                        syntaxNodes.Add(item);
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
                        if (typeSymbol.ToString() == SafeHandle_Type)
                            syntaxNodes.Add(conditionalAccess);
                    }
                }
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.SafeHandle);
        }
    }
}