using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;
using System;
using System.Linq;
using System.Collections.Generic;

namespace SAST.Engine.CSharp.Scanners
{
    internal class JWTSignatureScanner : IScanner
    {
        private static readonly string[] ValidationProps = {
            "RequireSignedTokens",
            "ValidateIssuerSigningKey"
        };
        private static readonly string[] DecodeMethods = {
            "Decode",
            "DecodeToObject"
        };

        /// <summary>
        /// This method will FInd JWT Token vulnerabilities from assignments.
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="model"></param>
        /// <param name="vulnerabilities"></param>
        private void FindTokenParameters(SyntaxNode syntaxNode, SemanticModel model, ref List<VulnerabilityDetail> vulnerabilities)
        {
            var assignments = syntaxNode.DescendantNodes().OfType<AssignmentExpressionSyntax>();
            foreach (var assignment in assignments)
            {
                if (!ValidationProps.Any(obj => assignment.Left.ToString().Contains(obj)))
                    continue;

                var leftSymbol = model.GetSymbol(assignment.Left);
                if (leftSymbol == null || !(leftSymbol.ContainingNamespace.ToString() == KnownType.Microsoft_IdentityModel_Tokens))
                    continue;

                var constant = model.GetConstantValue(assignment.Right);
                //If right side if assignment is false or constant value as false
                if (constant.HasValue && constant.Value is bool value && !value)
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, assignment, Enums.ScannerType.JWTValidation));
            }
        }

        /// <summary>
        /// This method will find JWT Decode Method vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="model"></param>
        /// <param name="vulnerabilities"></param>
        private void FindDecoders(SyntaxNode syntaxNode, SemanticModel model, ref List<VulnerabilityDetail> vulnerabilities)
        {
            var invocations = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocations)
            {
                if (!DecodeMethods.Any(obj => item.Expression.ToString().Contains(obj)))
                    continue;
                ISymbol symbol = model.GetSymbol(item.Expression);
                if (symbol == null)
                    continue;
                if (!Utils.ImplementsFrom(symbol.ContainingType, KnownType.JWT_IJwtDecoder))
                    continue;
                if (!DecodeMethods.Contains(symbol.Name))
                    continue;
                if (item.ArgumentList.Arguments.Count == 1)
                {
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, Enums.ScannerType.JWTValidation));
                    continue;
                }

                bool vulnerable = false;
                int i = -1;
                foreach (var argument in item.ArgumentList.Arguments)
                {
                    i++;
                    if (argument.NameColon != null && argument.NameColon.Name.ToString() != "verify")
                        continue;
                    if (argument.NameColon == null && i != 2)
                        continue;
                    ITypeSymbol typeSymbol = model.GetTypeSymbol(argument.Expression);
                    if (typeSymbol == null || typeSymbol.SpecialType != SpecialType.System_Boolean)
                        continue;
                    var constant = model.GetConstantValue(argument.Expression);
                    if (constant.HasValue && constant.Value is bool value && !value)
                        vulnerable = true;
                }
                if (vulnerable)
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, Enums.ScannerType.JWTValidation));
            }
        }

        /// <summary>
        /// This method will find JWT Builder vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="model"></param>
        /// <param name="vulnerabilities"></param>
        /// <param name="solution"></param>
        private void FindBuilders(SyntaxNode syntaxNode, SemanticModel model, ref List<VulnerabilityDetail> vulnerabilities, Solution solution)
        {
            var invocations = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocations)
            {
                if (!item.ToString().Contains("Decode"))
                    continue;
                ISymbol symbol = model.GetSymbol(item);
                if (symbol == null || symbol.ContainingType.ToString() + "." + symbol.Name.ToString() != KnownMethod.JWT_Builder_JwtBuilder_Decode)
                    continue;

                if (IsVulnerable((item.Expression as MemberAccessExpressionSyntax).Expression, model, solution))
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, Enums.ScannerType.JWTValidation));
            }
        }

        /// <summary>
        /// This will identify the <paramref name="syntaxNode"/> vulnerable or not
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        private bool IsVulnerable(SyntaxNode syntaxNode, SemanticModel model, Solution solution)
        {
            bool vulnerable = true;
            ISymbol symbol;
            switch (syntaxNode.Kind())
            {
                case SyntaxKind.InvocationExpression:
                    symbol = model.GetSymbol(syntaxNode);
                    if (symbol.Name == "MustVerifySignature")
                        vulnerable = false;
                    //else if (symbol.Name == "DoNotVerifySignature")
                    //    vulnerable = true;
                    else if (symbol.Name == "WithVerifySignature")
                    {
                        var invocation = syntaxNode as InvocationExpressionSyntax;
                        var argumentValue = model.GetConstantValue(invocation.ArgumentList.Arguments.First().Expression);
                        if (!argumentValue.HasValue)
                            vulnerable = false;
                        else if (argumentValue.Value is bool value && value)
                            vulnerable = false;
                    }
                    else if (symbol.DeclaringSyntaxReferences.Count() > 0)
                    {
                        SyntaxReference syntaxReference = symbol.DeclaringSyntaxReferences.First();
                        var declaration = syntaxReference.GetSyntaxAsync().Result;
                        var methodModel = model.Compilation.GetSemanticModel(syntaxReference.SyntaxTree);
                        vulnerable = IsVulnerable(declaration, methodModel, solution);
                    }
                    return vulnerable;
                case SyntaxKind.IdentifierName:
                    symbol = model.GetSymbol(syntaxNode);
                    if (symbol.DeclaringSyntaxReferences.Length > 0)
                    {
                        SyntaxReference syntaxReference = symbol.DeclaringSyntaxReferences.First();
                        vulnerable = IsVulnerable(syntaxReference.GetSyntax(), model.Compilation.GetSemanticModel(syntaxReference.SyntaxTree), solution);
                    }
                    var referencedSymbols = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
                    foreach (var referencedSymbol in referencedSymbols)
                        foreach (var referenceLocation in referencedSymbol.Locations)
                            if (referenceLocation.Location.SourceSpan.Start < syntaxNode.SpanStart)
                            {
                                syntaxNode = referenceLocation.Location.SourceTree.GetRootAsync().Result.FindNode(referenceLocation.Location.SourceSpan);
                                vulnerable = IsVulnerable(syntaxNode, model.Compilation.GetSemanticModel(referenceLocation.Location.SourceTree), solution);
                            }
                    return vulnerable;
                case SyntaxKind.VariableDeclarator:
                    var variableDeclarator = syntaxNode as VariableDeclaratorSyntax;
                    return IsVulnerable(variableDeclarator.Initializer.Value, model, solution);
                case SyntaxKind.ParenthesizedExpression:
                    var parenthesized = syntaxNode as ParenthesizedExpressionSyntax;
                    return IsVulnerable(parenthesized.Expression, model, solution);
                case SyntaxKind.MethodDeclaration:
                    var methodDeclaration = syntaxNode as MethodDeclarationSyntax;
                    if (methodDeclaration.Body != null)
                    {
                        var returnStatements = methodDeclaration.Body.DescendantNodes().OfType<ReturnStatementSyntax>();
                        foreach (var item in returnStatements)
                            if (!IsVulnerable(item.Expression, model, solution))
                            {
                                vulnerable = false;
                                break;
                            }
                    }
                    else if (methodDeclaration.ExpressionBody != null)
                        vulnerable = IsVulnerable(methodDeclaration.ExpressionBody.Expression, model, solution);
                    return vulnerable;
                case SyntaxKind.LocalFunctionStatement:
                    var localFunctionStatement = syntaxNode as LocalFunctionStatementSyntax;
                    if (localFunctionStatement.Body != null)
                    {
                        var returnStatements = localFunctionStatement.Body.DescendantNodes().OfType<ReturnStatementSyntax>();
                        foreach (var item in returnStatements)
                            if (!IsVulnerable(item.Expression, model, solution))
                            {
                                vulnerable = false;
                                break;
                            }
                    }
                    else if (localFunctionStatement.ExpressionBody != null)
                        vulnerable = IsVulnerable(localFunctionStatement.ExpressionBody.Expression, model, solution);
                    return vulnerable;
                case SyntaxKind.ConditionalExpression:
                    var conditionalExpression = syntaxNode as ConditionalExpressionSyntax;
                    if (!IsVulnerable(conditionalExpression.WhenTrue, model, solution))
                        vulnerable = false;
                    else if (!IsVulnerable(conditionalExpression.WhenFalse, model, solution))
                        vulnerable = false;
                    return vulnerable;
                default:
                    return vulnerable;
            }
        }
        private string _filePath;

        /// <summary>
        /// This method will find the JWT Signature Vulnerabilities 
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            _filePath = filePath;
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();

            //Microsoft.IdentityModel.Tokens
            FindTokenParameters(syntaxNode, model, ref vulnerabilities);

            //JWT.Net IJwtDecoder
            FindDecoders(syntaxNode, model, ref vulnerabilities);

            //JWT.Net JwtBuilder
            FindBuilders(syntaxNode, model, ref vulnerabilities, solution);
            return vulnerabilities;
        }
    }
}