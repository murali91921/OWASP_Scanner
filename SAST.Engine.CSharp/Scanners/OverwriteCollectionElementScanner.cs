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
    internal class OverwriteCollectionElementScanner : IScanner
    {
        private static readonly SyntaxKind[] identifierOrLiteral_SyntaxKinds =  {
            SyntaxKind.IdentifierName,
            SyntaxKind.StringLiteralExpression,
            SyntaxKind.NumericLiteralExpression,
            SyntaxKind.CharacterLiteralExpression,
            SyntaxKind.NullLiteralExpression,
            SyntaxKind.TrueLiteralExpression,
            SyntaxKind.FalseLiteralExpression,
        };

        private static string[] GenericCollection_Types = {
            "System.Collections.Generic.IDictionary<TKey, TValue>",
            "System.Collections.Generic.ICollection<T>"
        };

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var expressionStatements = syntaxNode.DescendantNodesAndSelf().OfType<ExpressionStatementSyntax>();
            foreach (var statement in expressionStatements)
            {
                var collectionIdentifier = GetCollectionIdentifier(statement);
                var indexOrKey = GetIndexOrKey(statement);

                if (collectionIdentifier == null || indexOrKey == null
                    || !IsIdentifierOrLiteral(indexOrKey) || !IsDictionaryOrCollection(collectionIdentifier, model))
                    continue;

                var previousSet = GetPreviousStatements(statement)
                    .TakeWhile(IsSameCollection(collectionIdentifier))
                    .FirstOrDefault(IsSameIndexOrKey(indexOrKey));

                if (previousSet != null)
                    syntaxNodes.Add(statement);
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.OverwriteCollectionElement);
        }

        private SyntaxNode GetCollectionIdentifier(ExpressionStatementSyntax statement)
        {
            var assignmentOrInvocation = GetAssignmentOrInvocation(statement);

            if (assignmentOrInvocation is InvocationExpressionSyntax invocation)
                return GetInvokedMethodContainer(invocation).RemoveParenthesis();
            else if (assignmentOrInvocation is AssignmentExpressionSyntax assignment)
            {
                var elementAccess = assignment.Left as ElementAccessExpressionSyntax;
                return GetIdentifier(elementAccess?.Expression.RemoveParenthesis()).RemoveParenthesis();
            }
            else
                return null;
        }
        private static SyntaxNode GetAssignmentOrInvocation(StatementSyntax statement)
        {
            if (!(statement is ExpressionStatementSyntax expressionStatement))
                return null;
            var expression = expressionStatement.Expression;

            return expression.IsKind(SyntaxKind.ConditionalAccessExpression)
                ? ((ConditionalAccessExpressionSyntax)expression).WhenNotNull
                : expression;
        }
        private static SyntaxNode GetInvokedMethodContainer(InvocationExpressionSyntax invocation)
        {
            var expression = invocation.Expression.RemoveParenthesis();
            if (expression is MemberAccessExpressionSyntax memberAccess)
                return memberAccess.Name.ToString() == "Add" && invocation.ArgumentList?.Arguments.Count != 1 ? memberAccess.Expression : null;
            else if (expression is MemberBindingExpressionSyntax)
                return (expression.Parent.Parent as ConditionalAccessExpressionSyntax)?.Expression;
            else
                return null;
        }

        private SyntaxNode GetIndexOrKey(ExpressionStatementSyntax statement) =>
            GetIndexOrKeyArgument(statement)?.Expression.RemoveParenthesis();

        private static ArgumentSyntax GetIndexOrKeyArgument(StatementSyntax statement)
        {
            var assignmentOrInvocation = GetAssignmentOrInvocation(statement);
            if (assignmentOrInvocation is InvocationExpressionSyntax invocation)
                return invocation.ArgumentList.Arguments.ElementAtOrDefault(0);
            else if (assignmentOrInvocation is AssignmentExpressionSyntax assignment)
                return assignment.Left is ElementAccessExpressionSyntax elementAccess ? elementAccess.ArgumentList.Arguments.ElementAtOrDefault(0) : null;
            else
                return null;
        }

        private static SyntaxNode GetIdentifier(ExpressionSyntax expression) =>
            expression is MemberAccessExpressionSyntax memberAccess ? memberAccess.Name : expression is IdentifierNameSyntax ? expression : null;

        private bool IsIdentifierOrLiteral(SyntaxNode syntaxNode) => syntaxNode.IsAnyKind(identifierOrLiteral_SyntaxKinds);

        private bool IsDictionaryOrCollection(SyntaxNode identifier, SemanticModel semanticModel)
        {
            var identifierType = semanticModel.GetTypeSymbol(identifier);
            return identifierType == null ? false : (Utils.ImplementsFromAny(identifierType, GenericCollection_Types));
        }
        private static IEnumerable<ExpressionStatementSyntax> GetPreviousStatements(ExpressionStatementSyntax statement)
        {
            var previousStatements = statement.Parent.ChildNodes()
                .OfType<ExpressionStatementSyntax>()
                .TakeWhile(x => x != statement)
                .Reverse();

            return statement.Parent is ExpressionStatementSyntax parentStatement
                ? previousStatements.Union(GetPreviousStatements(parentStatement))
                : previousStatements;
        }
        private Func<ExpressionStatementSyntax, bool> IsSameCollection(SyntaxNode collectionIdentifier) =>
           statement =>
               GetCollectionIdentifier(statement) is SyntaxNode identifier &&
               identifier.ToString() == collectionIdentifier.ToString();

        private Func<ExpressionStatementSyntax, bool> IsSameIndexOrKey(SyntaxNode indexOrKey) =>
           statement => GetIndexOrKey(statement)?.ToString() == indexOrKey.ToString();
    }
}