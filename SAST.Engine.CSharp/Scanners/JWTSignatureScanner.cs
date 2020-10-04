using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp.Contract;
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
        private static readonly string IdentityModel_Tokens = "Microsoft.IdentityModel.Tokens";
        private static readonly string IJwtDecoder_Interface = "JWT.IJwtDecoder";

        /// <summary>
        /// This method will FInd JWT Token vulnerabilities from assignments.
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="model"></param>
        /// <param name="vulnerabilities"></param>
        private void FindTokenParameters(SyntaxNode syntaxNode, SemanticModel model, ref List<SyntaxNode> vulnerabilities)
        {
            var assignments = syntaxNode.DescendantNodes().OfType<AssignmentExpressionSyntax>();
            foreach (var assignment in assignments)
            {
                if (!ValidationProps.Any(obj => assignment.Left.ToString().Contains(obj)))
                    continue;

                var leftSymbol = model.GetSymbol(assignment.Left);
                if (leftSymbol == null || !(leftSymbol.ContainingNamespace.ToString() == IdentityModel_Tokens))
                    continue;

                var constant = model.GetConstantValue(assignment.Right);
                //If right side if assignment is false or constant value as false
                if (constant.HasValue && constant.Value is bool value && !value)
                    vulnerabilities.Add(assignment);
            }
        }

        /// <summary>
        /// This method will find JWT Decode Method vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="model"></param>
        /// <param name="vulnerabilities"></param>
        private void FindDecoders(SyntaxNode syntaxNode, SemanticModel model, ref List<SyntaxNode> vulnerabilities)
        {
            var invocations = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocations)
            {
                if (!DecodeMethods.Any(obj => item.Expression.ToString().Contains(obj)))
                    continue;
                ISymbol symbol = model.GetSymbol(item.Expression);
                if (symbol == null)
                    continue;
                if (!Utils.ImplementsFrom(symbol.ContainingType, IJwtDecoder_Interface))
                    continue;
                if (!DecodeMethods.Contains(symbol.Name))
                    continue;
                bool vulnerable = false;
                foreach (var argument in item.ArgumentList.Arguments)
                {
                    ITypeSymbol typeSymbol = model.GetTypeSymbol(argument.Expression);
                    if (typeSymbol.SpecialType != SpecialType.System_Boolean)
                        continue;
                    var constant = model.GetConstantValue(argument.Expression);
                    if (constant.HasValue && constant.Value is bool value && !value)
                        vulnerable = true;
                }
                if (vulnerable)
                    vulnerabilities.Add(item);
            }
        }

        /// <summary>
        /// This method will find JWT Builder vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="model"></param>
        /// <param name="vulnerabilities"></param>
        /// <param name="solution"></param>
        private void FindBuilders(SyntaxNode syntaxNode, SemanticModel model, ref List<SyntaxNode> vulnerabilities, Solution solution)
        {
            var invocations = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocations)
            {
                if (!item.ToString().Contains("Decode"))
                    continue;
                ISymbol symbol = model.GetSymbol(item);
                if (symbol == null || symbol.ContainingType.ToString() + "." + symbol.Name.ToString() != "JWT.Builder.JwtBuilder.Decode")
                    continue;
                //bool vulnerable = true;
                if (IsVulnerable((item.Expression as MemberAccessExpressionSyntax).Expression, model, solution))
                    vulnerabilities.Add(item);
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
            List<SyntaxNode> vulnerabilities = new List<SyntaxNode>();

            //Microsoft.IdentityModel.Tokens
            FindTokenParameters(syntaxNode, model, ref vulnerabilities);

            //JWT.Net IJwtDecoder
            FindDecoders(syntaxNode, model, ref vulnerabilities);

            //JWT.Net JwtBuilder
            FindBuilders(syntaxNode, model, ref vulnerabilities, solution);
            return Mapper.Map.ConvertToVulnerabilityList(filePath, vulnerabilities.OrderBy(obj => obj.Span).ToList(), Enums.ScannerType.JWTValidation);
        }
    }
}