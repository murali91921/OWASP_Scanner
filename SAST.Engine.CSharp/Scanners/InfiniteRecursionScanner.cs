using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Microsoft.CodeAnalysis.FlowAnalysis;

namespace SAST.Engine.CSharp.Scanners
{
    internal class InfiniteRecursionScanner : IScanner
    {
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var methods = syntaxNode.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>();
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.None);
        }
        private static void CheckForNoExitMethod(SemanticModel model, SyntaxNode method)
        {
            var symbol = model.GetDeclaredSymbol(method);
            ControlFlowGraph controlFlowGraph = null;
            SyntaxNode body = null;
            if (method is MethodDeclarationSyntax methodDeclaration)
                body = (SyntaxNode)methodDeclaration.Body ?? methodDeclaration.ExpressionBody;
            else if (method is LocalFunctionStatementSyntax localFunction)
                body = (SyntaxNode)localFunction.Body ?? localFunction.ExpressionBody;

            if (symbol == null || body == null)
                return;
            controlFlowGraph = ControlFlowGraph.Create(body, model);
        }
    }
}