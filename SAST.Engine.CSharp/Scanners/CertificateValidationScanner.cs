using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System;
using System.Collections.Generic;
using System.Linq;

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

        /// <summary>
        /// This variable stores the visited methods to avoid recursive calls.
        /// </summary>
        private HashSet<ISymbol> _visitedMethodSymbols = new HashSet<ISymbol>();

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var assignmentExpressions = syntaxNode.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>();
            foreach (var assignment in assignmentExpressions)
            {
                if (!assignment.ToString().Contains("ServerCertificateValidationCallback") && !assignment.ToString().Contains("ServerCertificateCustomValidationCallback"))
                    continue;
                ISymbol symbol = model.GetSymbol(assignment.Left);
                if (symbol == null)
                    continue;
                if (!CallbackDelegates.Any(obj => obj == symbol.ContainingType.ToString() + "." + symbol.Name.ToString()))
                    continue;
                //if (assignment.Right.ToString().Contains("FindCompliantRecursive"))
                    if (IsVulnerable(assignment.Right, model))
                        syntaxNodes.Add(assignment);
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
                    return rightNode;
            }
            if (body is BlockSyntax block && block.Statements.Count == 1 && block.Statements.First() is ReturnStatementSyntax ret)
                return ret.Expression;
            body = body.RemoveParentheses();
            return body;
        }

        private bool IsVulnerable(SyntaxNode syntaxNode, SemanticModel model)
        {
            bool returnConditionalOrFalse = false;
            syntaxNode = GetBody(syntaxNode);

            if (syntaxNode is IdentifierNameSyntax || syntaxNode is InvocationExpressionSyntax)
            {
                ISymbol methodSymbol = model.GetSymbol(syntaxNode);
                if (methodSymbol == null || methodSymbol.DeclaringSyntaxReferences.Count() > 1)
                    return false;
                var syntaxReference = methodSymbol.DeclaringSyntaxReferences.First();
                SemanticModel methodModel = model.Compilation.GetSemanticModel(syntaxReference.SyntaxTree);
                if (!_visitedMethodSymbols.Any(obj => obj.Equals(methodSymbol)))
                    return IsVulnerable(syntaxReference.GetSyntaxAsync().Result, methodModel);
            }
            else if (syntaxNode is MethodDeclarationSyntax methodDeclaration)
            {
                if (methodDeclaration.Body != null || methodDeclaration.ExpressionBody != null)
                {
                    ISymbol callingsymbol = model.GetDeclaredSymbol(methodDeclaration);
                    _visitedMethodSymbols.Add(callingsymbol);
                    if (methodDeclaration.Body != null)
                    {
                        var returnStatements = methodDeclaration.Body.DescendantNodes().OfType<ReturnStatementSyntax>();
                        foreach (var item in returnStatements)
                        {
                            var invocation = item.Expression.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>().FirstOrDefault();
                            if (invocation != null)
                            {
                                ISymbol calledsymbol = model.GetSymbol(invocation);
                                // If invocation is Recursive call
                                if (_visitedMethodSymbols.Any(obj => obj == calledsymbol))
                                    continue;
                            }
                            if (IsConditionalOrFalse(item.Expression, model))
                            {
                                returnConditionalOrFalse = true;
                                break;
                            }
                        }
                    }
                    else if (!(methodDeclaration.ExpressionBody is null))
                    {
                        returnConditionalOrFalse = IsConditionalOrFalse(methodDeclaration.ExpressionBody.Expression, model);
                    }
                    _visitedMethodSymbols.Remove(callingsymbol);
                    //return returnConditionalOrFalse;
                }
            }
            else if (syntaxNode is PropertyDeclarationSyntax propertyDeclaration)
            {
                var getAccessor = propertyDeclaration.AccessorList.Accessors.FirstOrDefault(obj => obj.IsKind(SyntaxKind.GetAccessorDeclaration));
                if (getAccessor != null)
                {
                    if (!(getAccessor.Body is null))
                    {
                        var returnStatements = getAccessor.Body.DescendantNodes().OfType<ReturnStatementSyntax>();
                        foreach (var item in returnStatements)
                            if (IsConditionalOrFalse(item.Expression, model))
                            {
                                returnConditionalOrFalse = true;
                                break;
                            }
                        //if (!returnConditionalOrFalse)
                        //{
                        //    var catchClauses = getAccessor.Body.DescendantNodesAndSelf().OfType<CatchClauseSyntax>();
                        //}
                    }
                    else if (!(getAccessor.ExpressionBody is null))
                        returnConditionalOrFalse = IsConditionalOrFalse(getAccessor.ExpressionBody.Expression, model);
                }
            }
            else
                returnConditionalOrFalse = IsConditionalOrFalse(syntaxNode, model);
            return !returnConditionalOrFalse;
        }
        private bool IsConditionalOrFalse(SyntaxNode expression, SemanticModel model)
        {
            expression = GetBody(expression);
            if (expression is IdentifierNameSyntax || expression is InvocationExpressionSyntax)
            {
                return !IsVulnerable(expression, model);
            }
            else if (expression is ConditionalExpressionSyntax conditionalExpression)
            {
                bool TrueResult = IsVulnerable(conditionalExpression.WhenTrue, model);
                bool falseResult = IsVulnerable(conditionalExpression.WhenFalse, model);
                return TrueResult && falseResult;
            }
            else if (expression is IfStatementSyntax ifStatement)
            {
                bool trueResult = IsVulnerable(ifStatement.Statement, model);
                bool falseResult = false;
                if (ifStatement.Else != null)
                {
                    falseResult = IsVulnerable(ifStatement.Else.Statement, model);
                    return trueResult && falseResult;
                }
                else
                {
                    return trueResult;
                }

            }
            var returnValue = model.GetConstantValue(expression);
            // If expression is have boolean value as true;
            if (returnValue.HasValue)
            {
                if (returnValue.Value is null || (returnValue.Value is bool value && value))
                    return false;
            }
            return true;
        }
    }
}