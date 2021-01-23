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
        private readonly static string[] Thread_Methods =
        {
            Constants.KnownMethod.System_Threading_Thread_Suspend,
            Constants.KnownMethod.System_Threading_Thread_Resume
        };
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var invocationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var invocation in invocationExpressions)
            {
                if (!(model.GetSymbol(invocation) is IMethodSymbol methodSymbol))
                    continue;
                if (Thread_Methods.Contains(methodSymbol.ContainingType + "." + methodSymbol.Name))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, invocation.Parent, Enums.ScannerType.ThreadSuspendResume));
            }
            return vulnerabilities;
        }
    }
}