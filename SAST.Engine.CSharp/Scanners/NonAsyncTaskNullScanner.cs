using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class NonAsyncTaskNullScanner : IScanner
    {
        private static readonly string[] TaskTypes = {
            KnownType.System_Threading_Tasks_Task,
            KnownType.System_Threading_Tasks_Task_TResult
        };
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var nullLiteralExpressions = syntaxNode.DescendantNodesAndSelf().Where(obj => obj.IsKind(SyntaxKind.NullLiteralExpression)).OfType<LiteralExpressionSyntax>();
            foreach (var nullLiteral in nullLiteralExpressions)
            {
                SyntaxNode expression = nullLiteral.GetFirstNonParenthesizedParent();
                if (!expression.IsKind(SyntaxKind.ArrowExpressionClause) && !expression.IsKind(SyntaxKind.ReturnStatement))
                    continue;

                var enclosingMember = GetEnclosingMember(nullLiteral);
                if (enclosingMember == null || enclosingMember.IsKind(SyntaxKind.VariableDeclaration))
                    continue;
                if (IsInvalidEnclosingSymbolContext(enclosingMember, model))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, nullLiteral, Enums.ScannerType.NonAsyncTaskNull));
            }
            return vulnerabilities;
        }

        protected static bool IsInvalidEnclosingSymbolContext(SyntaxNode enclosingMember, SemanticModel model)
        {
            var enclosingMemberSymbol = model.GetDeclaredSymbol(enclosingMember) ?? model.GetSymbol(enclosingMember);
            var enclosingMemberMethodSymbol = enclosingMemberSymbol as IMethodSymbol;

            return enclosingMemberSymbol != null
                && IsTaskReturnType(enclosingMemberSymbol, enclosingMemberMethodSymbol)
                && !IsSafeTaskReturnType(enclosingMemberMethodSymbol);
        }

        private static bool IsTaskReturnType(ISymbol symbol, IMethodSymbol methodSymbol)
        {
            return GetReturnType() is INamedTypeSymbol namedTypeSymbol
                && Utils.DerivesFromAny(namedTypeSymbol.ConstructedFrom, TaskTypes);

            ITypeSymbol GetReturnType() =>
                methodSymbol != null ? methodSymbol.ReturnType : symbol.GetTypeSymbol();
        }

        private static bool IsSafeTaskReturnType(IMethodSymbol methodSymbol) => methodSymbol != null && methodSymbol.IsAsync;

        private static SyntaxNode GetEnclosingMember(LiteralExpressionSyntax literal)
        {
            foreach (var ancestor in literal.Ancestors())
            {
                switch (ancestor.Kind())
                {
                    case SyntaxKind.ParenthesizedLambdaExpression:
                    case SyntaxKind.SimpleLambdaExpression:
                    case SyntaxKind.VariableDeclaration:
                    case SyntaxKind.PropertyDeclaration:
                    case SyntaxKind.MethodDeclaration:
                    case SyntaxKind.LocalFunctionStatement:
                        return ancestor;
                }
            }
            return null;
        }
    }
}