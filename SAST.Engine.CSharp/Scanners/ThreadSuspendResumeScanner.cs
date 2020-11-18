using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class ThreadSuspendResumeScanner : IScanner
    {
        private static string[] Thread_Methods =
        {
            "System.Threading.Thread.Suspend",
            "System.Threading.Thread.Resume"
        };
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var invocationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var invocation in invocationExpressions)
            {
                IMethodSymbol methodSymbol = model.GetSymbol(invocation) as IMethodSymbol;
                if (methodSymbol == null)
                    continue;
                if (Thread_Methods.Contains(methodSymbol.ContainingType + "." + methodSymbol.Name))
                    syntaxNodes.Add(invocation.Parent);
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.ThreadSuspendResume);
        }
    }
}