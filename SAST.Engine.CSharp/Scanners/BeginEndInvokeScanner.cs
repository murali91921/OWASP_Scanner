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
    internal class BeginEndInvokeScanner : IScanner
    {
        const string BeginInvoke = "BeginInvoke";

        private static readonly SyntaxKind[] ParentDeclarationKinds =  {
            SyntaxKind.AnonymousMethodExpression,
            SyntaxKind.ClassDeclaration,
            SyntaxKind.CompilationUnit,
            SyntaxKind.ConstructorDeclaration,
            SyntaxKind.ConversionOperatorDeclaration,
            SyntaxKind.DestructorDeclaration,
            SyntaxKind.InterfaceDeclaration,
            SyntaxKind.MethodDeclaration,
            SyntaxKind.OperatorDeclaration,
            SyntaxKind.ParenthesizedLambdaExpression,
            SyntaxKind.PropertyDeclaration,
            SyntaxKind.SimpleLambdaExpression,
            SyntaxKind.StructDeclaration,
            SyntaxKind.LocalFunctionStatement,
        };
        private SemanticModel _model = null;

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxToken> syntaxTokens = new List<SyntaxToken>();
            var invocationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var invocation in invocationExpressions)
            {
                if (!invocation.Expression.ToString().Contains(BeginInvoke))
                    continue;
                _model = model;
                if (GetCallbackArg(invocation) is { } callbackArg
                && GetMethodSymbol(invocation) is { } methodSymbol
                && methodSymbol.Name == BeginInvoke
                && IsDelegate(methodSymbol)
                && (callbackArg.IsKind(SyntaxKind.NullLiteralExpression) || !CallbackMayContainEndInvoke(callbackArg))
                && !ParentMethodContainsEndInvoke(invocation))
                {
                    syntaxTokens.Add((SyntaxToken)invocation.GetMethodCallIdentifier());
                }
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxTokens, Enums.ScannerType.BeginEndInvoke);
        }

        private IMethodSymbol GetMethodSymbol(InvocationExpressionSyntax invocationExpression) =>
            invocationExpression.GetMethodCallIdentifier() is SyntaxToken identifier &&
            _model.GetSymbol(identifier.Parent) is IMethodSymbol symbol
                ? symbol : null;

        private ExpressionSyntax GetCallbackArg(InvocationExpressionSyntax invocationExpression)
        {
            if (invocationExpression.ArgumentList.Arguments.Count >= 2)
            {
                var callbackArgPos = invocationExpression.ArgumentList.Arguments.Count - 2;
                var callbackArg = GetArgumentExpressionByNameOrPosition(invocationExpression, "callback", callbackArgPos)
                    ?.RemoveParenthesis();
                return callbackArg;
            }
            return null;
        }

        private ExpressionSyntax GetArgumentExpressionByNameOrPosition(InvocationExpressionSyntax invocationExpression, string argumentName, int argumentPosition)
        {
            var arguments = invocationExpression.ArgumentList.Arguments;
            var argumentByName = arguments.FirstOrDefault(a => a.NameColon?.Name.Identifier.Text == argumentName);
            if (argumentByName != null)
                return argumentByName.Expression;
            return argumentPosition < arguments.Count ? arguments[argumentPosition].Expression : null;
        }

        private SyntaxNode GetInitializer(IdentifierNameSyntax identifier)
        {
            var declaringReference = _model.GetSymbol(identifier).DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax();
            if (declaringReference is VariableDeclaratorSyntax variableDeclarator && variableDeclarator.Initializer is EqualsValueClauseSyntax equalsValueClause)
                return equalsValueClause.Value.RemoveParenthesis();
            return null;
        }

        private static SyntaxNode GetFirstArgument(ObjectCreationExpressionSyntax objectCreation) =>
            objectCreation.ArgumentList.Arguments.Count == 1 ? objectCreation.ArgumentList.Arguments[0].Expression : null;

        private static SyntaxNode GetDeclaration(IMethodSymbol methodSymbol) =>
            methodSymbol?.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax();

        private bool CallbackMayContainEndInvoke(SyntaxNode callbackArg)
        {
            callbackArg = callbackArg.RemoveParenthesis();
            if (callbackArg.IsKind(SyntaxKind.IdentifierName))
                callbackArg = GetInitializer((IdentifierNameSyntax)callbackArg);

            if (callbackArg.IsKind(SyntaxKind.ObjectCreationExpression))
                callbackArg = GetFirstArgument((ObjectCreationExpressionSyntax)callbackArg);

            if (callbackArg != null && _model.GetSymbol(callbackArg) is IMethodSymbol methodSymbol)
                callbackArg = GetDeclaration(methodSymbol);

            if (callbackArg != null && ParentDeclarationKinds.Contains(callbackArg.Kind()))
                return GetEndInvokeList(callbackArg, null).Count > 0;

            return true;
        }

        private bool ParentMethodContainsEndInvoke(SyntaxNode node)
        {
            var memberAccess = (node as InvocationExpressionSyntax).Expression as MemberAccessExpressionSyntax;
            ISymbol beginSymbol = _model.GetSymbol(memberAccess.Expression);
            var parentDeclaration = node.AncestorsAndSelf()
                .FirstOrDefault(ancestor => ParentDeclarationKinds.Contains(ancestor.Kind()));
            return GetEndInvokeList(parentDeclaration, beginSymbol).Count > 0;
        }

        private static bool IsDelegate(IMethodSymbol methodSymbol) => methodSymbol.ReceiverType?.TypeKind == TypeKind.Delegate;

        private List<InvocationExpressionSyntax> GetEndInvokeList(SyntaxNode parentDeclaration, ISymbol beginSymbol)
        {
            var endInvokeList = new List<InvocationExpressionSyntax>();
            var walker = new InvocationWalker(parentDeclaration, invocationExpression =>
            {
                var methodSymbol = GetMethodSymbol(invocationExpression);
                if (methodSymbol?.Name == "EndInvoke" && IsDelegate(methodSymbol))
                {
                    if (beginSymbol == null)
                        endInvokeList.Add(invocationExpression);
                    else
                    {
                        var memberAccess = invocationExpression.Expression as MemberAccessExpressionSyntax;
                        ISymbol endSymbol = _model.GetSymbol(memberAccess.Expression);
                        if (endSymbol.Equals(beginSymbol, SymbolEqualityComparer.Default))
                            endInvokeList.Add(invocationExpression);
                    }
                }
            });
            walker.SafeVisit(parentDeclaration);
            return endInvokeList;
        }
    }
    class InvocationWalker : CSharpSyntaxWalker
    {
        private readonly SyntaxNode parentDeclaration;

        private readonly Action<InvocationExpressionSyntax> action;

        public InvocationWalker(SyntaxNode parentDeclaration, Action<InvocationExpressionSyntax> action)
        {
            this.parentDeclaration = parentDeclaration;
            this.action = action;
        }

        public override void VisitInvocationExpression(InvocationExpressionSyntax node)
        {
            action.Invoke(node);
            base.VisitInvocationExpression(node);
        }

        public override void VisitAnonymousMethodExpression(AnonymousMethodExpressionSyntax node) =>
            OnlyOnParent(node, () => base.VisitAnonymousMethodExpression(node));

        public override void VisitConstructorDeclaration(ConstructorDeclarationSyntax node) =>
            OnlyOnParent(node, () => base.VisitConstructorDeclaration(node));

        public override void VisitDestructorDeclaration(DestructorDeclarationSyntax node) =>
            OnlyOnParent(node, () => base.VisitDestructorDeclaration(node));

        public override void VisitMethodDeclaration(MethodDeclarationSyntax node) =>
            OnlyOnParent(node, () => base.VisitMethodDeclaration(node));

        public override void VisitParenthesizedLambdaExpression(ParenthesizedLambdaExpressionSyntax node) =>
            OnlyOnParent(node, () => base.VisitParenthesizedLambdaExpression(node));

        public override void VisitSimpleLambdaExpression(SimpleLambdaExpressionSyntax node) =>
            OnlyOnParent(node, () => base.VisitSimpleLambdaExpression(node));

        private void OnlyOnParent<T>(T node, Action action) where T : SyntaxNode
        {
            if (parentDeclaration == node)
                action.Invoke();
        }

        public bool SafeVisit(SyntaxNode syntaxNode)
        {
            try
            {
                Visit(syntaxNode);
                return true;
            }
            catch (InsufficientExecutionStackException)
            {
                return false;
            }
        }
    }
}