using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    /// <summary>
    /// This Scanner to find Certificate Validation Vulnerabilities 
    /// </summary>
    internal class CertificateValidationScanner : IScanner
    {
        private static readonly string[] CallbackDelegates = {
            Constants.KnownType.System_Net_ServicePointManager_ServerCertificateValidationCallback,
            Constants.KnownType.System_Net_Http_WebRequestHandler_ServerCertificateValidationCallback,
            Constants.KnownType.System_Net_HttpWebRequest_ServerCertificateValidationCallback,
            Constants.KnownType.System_Net_Http_HttpClientHandler_ServerCertificateCustomValidationCallback
        };

        /// <summary>
        /// This variable stores the visited methods to avoid recursive calls.
        /// </summary>
        private HashSet<ISymbol> _visitedMethodSymbols = new HashSet<ISymbol>();

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
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var assignmentExpressions = syntaxNode.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>();
            foreach (var assignment in assignmentExpressions)
            {
                if (!assignment.ToString().Contains("ServerCertificateValidationCallback")
                    && !assignment.ToString().Contains("ServerCertificateCustomValidationCallback"))
                    continue;

                ISymbol symbol = model.GetSymbol(assignment.Left);
                if (symbol == null)
                    continue;

                if (!CallbackDelegates.Contains(symbol.ContainingType.ToString() + "." + symbol.Name.ToString()))
                    continue;

                if (IsVulnerable(assignment.Right, model))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, assignment, Enums.ScannerType.CertificateValidation));
            }
            return vulnerabilities;
        }

        /// <summary>
        /// Get the expression of SyntaxNode for ParenthesizedLambdaExpressionSyntax,AnonymousMethodExpressionSyntax
        /// </summary>
        /// <param name="rightNode"></param>
        /// <returns></returns>
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
            body = body.RemoveParenthesis();
            return body;
        }

        /// <summary>
        /// This method will verify whether <paramref name="syntaxNode"/> is vulnerable or not.
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="model"></param>
        /// <returns></returns>
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
                if (!model.Compilation.ContainsSyntaxTree(syntaxReference.SyntaxTree))
                    return false;
                SemanticModel methodModel = model.Compilation.GetSemanticModel(syntaxReference.SyntaxTree);
                if (!_visitedMethodSymbols.Any(obj => obj.Equals(methodSymbol, SymbolEqualityComparer.Default)))
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
                                if (_visitedMethodSymbols.Any(obj => obj.Equals(calledsymbol, SymbolEqualityComparer.Default)))
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
                        returnConditionalOrFalse = IsConditionalOrFalse(methodDeclaration.ExpressionBody.Expression, model);
                    _visitedMethodSymbols.Remove(callingsymbol);
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
                    }
                    else if (!(getAccessor.ExpressionBody is null))
                        returnConditionalOrFalse = IsConditionalOrFalse(getAccessor.ExpressionBody.Expression, model);
                }
            }
            else
                returnConditionalOrFalse = IsConditionalOrFalse(syntaxNode, model);
            return !returnConditionalOrFalse;
        }

        /// <summary>
        /// This mwthod will verify <paramref name="expression"/> is Conditional Expression or False Literal Expression
        /// </summary>
        /// <param name="expression"></param>
        /// <param name="model"></param>
        /// <returns></returns>
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
                    return trueResult;
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