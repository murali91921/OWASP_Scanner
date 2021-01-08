using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    /// <summary>
    /// This Scanner to find Command Injection Vulnerabilities
    /// </summary>
    internal class CommandInjectionScanner : IScanner
    {
        string _filePath;
        SyntaxNode _syntaxNode;
        SemanticModel _model = null;
        Solution _solution = null;
        List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();

        /// <summary>
        /// This method will find the Vulnerabilities in <paramref name="syntaxNode"/>
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            _filePath = filePath;
            _syntaxNode = syntaxNode;
            _model = model;
            _solution = solution;
            vulnerabilities.AddRange(FindProcessExpressions());
            vulnerabilities.AddRange(FindProcessInfoExpressions());
            vulnerabilities.AddRange(FindStartInfoAssignments());
            return vulnerabilities;
        }

        /// <summary>
        /// This method will find the Expressions caused by Process Class
        /// </summary>
        /// <returns></returns>
        private IEnumerable<VulnerabilityDetail> FindProcessExpressions()
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var invocationExpressions = _syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocationExpressions)
            {
                ISymbol symbol = _model.GetSymbol(item);
                if (symbol == null || symbol.ContainingType.ToString() + "." + symbol.Name.ToString() != Constants.KnownMethod.System_Diagnostics_Process_Start
                    || item.ArgumentList.Arguments.Count == 0)
                    continue;

                var argumentExpression = item.ArgumentList?.Arguments[0].Expression;
                ITypeSymbol typeSymbol = _model.GetTypeSymbol(argumentExpression);
                if (typeSymbol == null || typeSymbol.ToString() == Constants.KnownType.System_Diagnostics_ProcessStartInfo)
                    continue;
                if (item.ArgumentList?.Arguments.Count == 1)
                {
                    if (Utils.IsVulnerable(argumentExpression, _model, _solution))
                        syntaxNodes.Add(item);
                    continue;
                }

                int index = 0;
                bool vulnerable = false;
                foreach (var argument in item.ArgumentList.Arguments)
                {
                    if (argument.NameColon is null)
                    {
                        if (index <= 1)
                            vulnerable = Utils.IsVulnerable(argument.Expression, _model, _solution);
                    }
                    else if (argument.NameColon.Name.ToString() == "fileName" || argument.NameColon.Name.ToString() == "arguments")
                        vulnerable = Utils.IsVulnerable(argument.Expression, _model, _solution);

                    if (vulnerable)
                    {
                        syntaxNodes.Add(item);
                        break;
                    }
                    index++;
                }
            }
            return Map.ConvertToVulnerabilityList(_filePath, syntaxNodes, Enums.ScannerType.CommandInjection);
        }

        /// <summary>
        /// This method will find the Expressions caused by ProcessInfo Class
        /// </summary>
        /// <returns></returns>
        private IEnumerable<VulnerabilityDetail> FindProcessInfoExpressions()
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var objectCreations = _syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var item in objectCreations)
            {
                ITypeSymbol typeSymbol = _model.GetTypeSymbol(item);
                if (typeSymbol == null || typeSymbol.ToString() != Constants.KnownType.System_Diagnostics_ProcessStartInfo)
                    continue;

                if (item.ArgumentList == null || item.ArgumentList?.Arguments.Count == 0)
                    continue;

                foreach (var argument in item.ArgumentList?.Arguments)
                    if (Utils.IsVulnerable(argument.Expression, _model, _solution, null))
                        syntaxNodes.Add(argument);
            }
            return Map.ConvertToVulnerabilityList(_filePath, syntaxNodes, Enums.ScannerType.CommandInjection);
        }
        private IEnumerable<VulnerabilityDetail> FindStartInfoAssignments()
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var assignments = _syntaxNode.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>();
            foreach (var assignment in assignments)
            {
                ISymbol symbol = _model.GetSymbol(assignment.Left);
                if (symbol == null)
                    continue;
                if (symbol.ToString() != Constants.KnownType.System_Diagnostics_ProcessStartInfo_FileName
                    && symbol.ToString() != Constants.KnownType.System_Diagnostics_ProcessStartInfo_Arguments)
                    continue;
                if (Utils.IsVulnerable(assignment.Right, _model, _solution, null))
                    syntaxNodes.Add(assignment);
            }
            return Map.ConvertToVulnerabilityList(_filePath, syntaxNodes, Enums.ScannerType.CommandInjection);
        }
    }
}