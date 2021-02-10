using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SAST.Engine.CSharp.Constants;

namespace SAST.Engine.CSharp.Scanners
{
    internal class EnableDebugModeScanner : IScanner
    {
        private static readonly string[] MethodsToCheck = {
            KnownMethod.Microsoft_AspNetCore_Builder_DeveloperExceptionPageExtensions_UseDeveloperExceptionPage,
            KnownMethod.Microsoft_AspNetCore_Builder_DatabaseErrorPageExtensions_UseDatabaseErrorPage
        };

        private static readonly string[] IsDevelopment_Methods = {
            KnownMethod.Microsoft_AspNetCore_Hosting_HostingEnvironmentExtensions_IsDevelopment,
            KnownMethod.Microsoft_Extensions_Hosting_HostEnvironmentEnvExtensions_IsDevelopment
        };

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();

            var invocations = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var invocation in invocations)
            {
                if (invocation.Expression.GetName() != "UseDeveloperExceptionPage" && invocation.Expression.GetName() != "UseDatabaseErrorPage")
                    continue;

                var methodSymbol = model.GetSymbol(invocation) as IMethodSymbol;
                if (methodSymbol == null || !MethodsToCheck.Contains(methodSymbol.ContainingType.ToString() + "." + methodSymbol.Name))
                    continue;

                if (IsInvokedConditionally(invocation, model))
                    continue;

                vulnerabilities.Add(VulnerabilityDetail.Create(filePath, invocation, Enums.ScannerType.EnableDebugMode));
            }
            return vulnerabilities;
        }

        private static bool IsInvokedConditionally(InvocationExpressionSyntax invocation, SemanticModel model) =>
            invocation.FirstAncestorOrSelf<StatementSyntax>() is { } invocationStatement
            && invocationStatement.Ancestors().Any(node => IsDevelopmentCheck(node, model));

        private static bool IsDevelopmentCheck(SyntaxNode node, SemanticModel model) =>
            node is IfStatementSyntax ifStatement
            && ifStatement.Condition.RemoveParenthesis() is InvocationExpressionSyntax condition
            && IsValidationMethod(condition, model);

        private static bool IsValidationMethod(SyntaxNode condition, SemanticModel model) =>
            model.GetSymbol(condition) is IMethodSymbol methodSymbol
            && IsDevelopment_Methods.Contains(methodSymbol.ContainingType.ToString() + "." + methodSymbol.Name);
    }
}