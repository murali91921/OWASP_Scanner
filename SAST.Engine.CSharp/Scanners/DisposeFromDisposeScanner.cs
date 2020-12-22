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
    internal class DisposeFromDisposeScanner : IScanner
    {
        private static readonly string DisposeMethodExplicitName = "System.IDisposable.Dispose";

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var invocationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();

            foreach (var invocation in invocationExpressions)
            {
                if (invocation.Expression is MemberAccessExpressionSyntax memberAccess &&
                    model.GetSymbol(memberAccess.Expression) is IFieldSymbol invocationTarget &&
                    invocationTarget.IsNonStaticNonPublicDisposableField() &&
                    IsDisposeMethodCalled(invocation, model) &&
                    IsDisposableClassOrStruct(invocationTarget.ContainingType) &&
                    !IsCalledInsideDispose(invocation, model))

                    syntaxNodes.Add(invocation);
            }

            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.DisposeFromDispose);
        }

        private static bool IsDisposeMethodCalled(InvocationExpressionSyntax invocation, SemanticModel model)
        {
            if (!(model.GetSymbol(invocation) is IMethodSymbol methodSymbol) ||
                !methodSymbol.IsDisposeMethod())
                return false;

            var disposeMethodSignature = (IMethodSymbol)model.Compilation
                .GetSpecialType(SpecialType.System_IDisposable)
                .GetMembers("Dispose")
                .SingleOrDefault();

            if (disposeMethodSignature == null)
                return false;

            return methodSymbol.Equals(methodSymbol.ContainingType.FindImplementationForInterfaceMember(disposeMethodSignature)) ||
                methodSymbol.ContainingType.IsDisposableRefStruct();
        }

        private static bool IsDisposableClassOrStruct(INamedTypeSymbol type) =>
            ImplementsDisposable(type) ||
            type.IsDisposableRefStruct();

        private static bool IsCalledInsideDispose(InvocationExpressionSyntax invocation, SemanticModel model) =>
            model.GetEnclosingSymbol(invocation.SpanStart) is IMethodSymbol enclosingMethodSymbol &&
            IsMethodMatchingDisposeMethodName(enclosingMethodSymbol);

        private static bool IsMethodMatchingDisposeMethodName(IMethodSymbol enclosingMethodSymbol) =>
            enclosingMethodSymbol.Name == "Dispose" ||
            enclosingMethodSymbol.ExplicitInterfaceImplementations.Any() && enclosingMethodSymbol.Name == DisposeMethodExplicitName;

        private static bool ImplementsDisposable(INamedTypeSymbol containingType) =>
            Utils.ImplementsFrom(containingType, "System.IDisposable");
    }
}