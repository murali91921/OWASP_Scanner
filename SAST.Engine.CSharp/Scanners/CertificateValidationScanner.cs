using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class CertificateValidationScanner : IScanner
    {
        private static readonly string[] CallbackDelegates = {
            "System.Net.ServicePointManager.ServerCertificateValidationCallback",
            "System.Net.Http.WebRequestHandler.ServerCertificateValidationCallback",
            "System.Net.HttpWebRequest.ServerCertificateValidationCallback",
            "System.Net.Http.HttpClientHandler.ServerCertificateCustomValidationCallback"
        };
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var assignmentExpressions = syntaxNode.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>();
            foreach (var assignment in assignmentExpressions)
            {
                //Console.WriteLine(assignment);
                if (!assignment.ToString().Contains("ServerCertificateValidationCallback") &&
                    !assignment.ToString().Contains("ServerCertificateCustomValidationCallback"))
                    continue;
                ISymbol symbol = Utils.GetSymbol(assignment.Left, model);
                if (symbol == null)
                    continue;
                if (!CallbackDelegates.Any(obj => obj == symbol.ContainingType.ToString() + "." + symbol.Name.ToString()))
                    continue;
                var rightNode = GetBody(assignment.Right);
                if (rightNode == null)
                    continue;
                var rightValue = model.GetConstantValue(rightNode);
                if (rightValue.Value is bool value && value)
                {
                    Console.WriteLine("::::"+assignment);
                    syntaxNodes.Add(assignment.Left);
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.CertificateValidation);
        }
        private SyntaxNode GetBody(SyntaxNode rightNode)
        {
            if (rightNode == null)
                return null;
            SyntaxNode body;
            switch (rightNode)
            {
                case ParenthesizedLambdaExpressionSyntax lambda:
                    body = lambda.Body;
                    break;
                case AnonymousMethodExpressionSyntax anonymous:
                    body = anonymous.Body;
                    break;
                default:
                    return null;
            }
            if (body is BlockSyntax block && block.Statements.Count == 1)
                if (block.Statements.First() is ReturnStatementSyntax ret)
                    return ret.Expression;
            body = body.RemoveParentheses();
            return body;
        }
    }
}