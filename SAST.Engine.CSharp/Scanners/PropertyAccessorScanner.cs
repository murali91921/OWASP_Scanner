using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Collections.Immutable;

namespace SAST.Engine.CSharp.Scanners
{
    internal class PropertyAccessorScanner : IScanner
    {

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNodeOrToken> syntaxNodes = new List<SyntaxNodeOrToken>();
            IEnumerable<SyntaxNode> classDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<ClassDeclarationSyntax>();
            classDeclarations = classDeclarations.Union(syntaxNode.DescendantNodesAndSelf().OfType<StructDeclarationSyntax>());

            foreach (var declaration in classDeclarations)
            {
                var symbol = (INamedTypeSymbol)model.GetDeclaredSymbol(declaration);
                if (symbol == null)
                    continue;

                var fields = symbol.GetMembers().Where(m => m.Kind == SymbolKind.Field).OfType<IFieldSymbol>();
                if (!fields.Any())
                    continue;

                var properties = GetExplictlyDeclaredProperties(symbol);
                if (!properties.Any())
                    continue;

                var propertyToField = new PropertyToField(fields);
                var allPropertyData = CollectPropertyData(properties, model.Compilation);

                // Check that if there is a single matching field name it is used by the property
                foreach (var data in allPropertyData)
                {
                    var expectedField = propertyToField.GetMatchingField(data.PropertySymbol);
                    if (expectedField != null)
                    {
                        SyntaxNodeOrToken unsafeNodeOrToken = null;
                        if (!data.IgnoreGetter)
                        {
                            unsafeNodeOrToken = CheckExpectedFieldIsUsed(data.PropertySymbol.GetMethod, expectedField, data.ReadFields);
                            if (unsafeNodeOrToken != null)
                                syntaxNodes.Add(unsafeNodeOrToken);
                        }
                        if (!data.IgnoreSetter)
                        {
                            unsafeNodeOrToken = CheckExpectedFieldIsUsed(data.PropertySymbol.SetMethod, expectedField, data.UpdatedFields);
                            if (unsafeNodeOrToken != null)
                                syntaxNodes.Add(unsafeNodeOrToken);
                        }
                    }
                }
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.PropertyAccessor);
        }

        private IEnumerable<FieldData> FindFieldAssignments(IPropertySymbol property, Compilation compilation)
        {
            if (!(property.SetMethod?.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is AccessorDeclarationSyntax setter))
                return Enumerable.Empty<FieldData>();

            var assignments = new Dictionary<IFieldSymbol, FieldData>();
            FillAssignments(assignments, compilation, setter, true);

            if (assignments.Count == 0
                && (setter.ExpressionBody?.Expression ?? SingleInvocation(setter.Body)) is { } expression
                && FindInvokedMethod(compilation, property.ContainingType, expression) is MethodDeclarationSyntax invokedMethod)
                FillAssignments(assignments, compilation, invokedMethod, false);

            return assignments.Values;
        }

        private IEnumerable<FieldData> FindFieldReads(IPropertySymbol property, Compilation compilation)
        {
            if (!(property.GetMethod?.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is AccessorDeclarationSyntax getter))
                return Enumerable.Empty<FieldData>();

            var reads = new Dictionary<IFieldSymbol, FieldData>();
            FillReads(getter, true);

            if (reads.Count == 0
                && (getter.ExpressionBody?.Expression ?? SingleReturn(getter.Body)) is InvocationExpressionSyntax returnExpression
                && FindInvokedMethod(compilation, property.ContainingType, returnExpression) is MethodDeclarationSyntax invokedMethod)
                FillReads(invokedMethod, false);

            return reads.Values;

            void FillReads(SyntaxNode root, bool useFieldLocation)
            {
                var notAssigned = root.DescendantNodes().OfType<ExpressionSyntax>().Where(n => !IsLeftSideOfAssignment(n));
                foreach (var expression in notAssigned)
                {
                    var readField = ExtractFieldFromExpression(AccessorKind.Getter, expression, compilation, useFieldLocation);

                    if (readField.HasValue && !reads.ContainsKey(readField.Value.Field))
                        reads.Add(readField.Value.Field, readField.Value);
                }
            }
        }

        private bool ShouldIgnoreAccessor(IMethodSymbol accessorMethod)
        {
            if (!(accessorMethod?.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is AccessorDeclarationSyntax accessor))
                return true;

            if (accessor.Body == null)
                return accessor.DescendantNodes().FirstOrDefault() is ArrowExpressionClauseSyntax arrowClause
                    && arrowClause.Expression.DescendantNodesAndSelf().Any(obj => obj.IsKind(SyntaxKind.ThrowExpression) || obj.IsKind(SyntaxKind.ThrowStatement));

            return (accessor.Body.DescendantNodes().Count(n => n is StatementSyntax) == 1 &&
                accessor.Body.DescendantNodes().Count(n => n is ThrowStatementSyntax) == 1);
        }

        private static bool ImplementsExplicitGetterOrSetter(IPropertySymbol property) =>
            (property.SetMethod?.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is AccessorDeclarationSyntax setter && setter.DescendantNodes().Any()) ||
            (property.GetMethod?.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax() is AccessorDeclarationSyntax getter && getter.DescendantNodes().Any());

        private static void FillAssignments(IDictionary<IFieldSymbol, FieldData> assignments, Compilation compilation, SyntaxNode root, bool useFieldLocation)
        {
            foreach (var node in root.DescendantNodes())
            {
                FieldData? foundField = null;
                if (node is AssignmentExpressionSyntax assignment &&
                    (node.IsKind(SyntaxKind.SimpleAssignmentExpression) || node.IsKind(SyntaxKind.CoalesceAssignmentExpression)))
                    foundField = assignment.Left.DescendantNodesAndSelf().OfType<ExpressionSyntax>()
                        .Select(x => ExtractFieldFromExpression(AccessorKind.Setter, x, compilation, useFieldLocation))
                        .FirstOrDefault(x => x != null);

                else if (node is ArgumentSyntax argument &&
                    (argument.RefOrOutKeyword.IsKind(SyntaxKind.RefKeyword) || argument.RefOrOutKeyword.IsKind(SyntaxKind.OutKeyword)))
                    foundField = ExtractFieldFromExpression(AccessorKind.Setter, argument.Expression, compilation, useFieldLocation);

                if (foundField.HasValue && !assignments.ContainsKey(foundField.Value.Field))
                    assignments.Add(foundField.Value.Field, foundField.Value);
            }
        }

        private static ExpressionSyntax SingleReturn(SyntaxNode body)
        {
            if (body == null)
                return null;

            var returns = body.DescendantNodes().OfType<ReturnStatementSyntax>();
            return returns.Count() == 1 ? returns.Single().Expression : null;
        }

        private static ExpressionSyntax SingleInvocation(SyntaxNode body)
        {
            if (body == null)
                return null;

            var expressions = body.DescendantNodes().OfType<InvocationExpressionSyntax>().Select(x => x.Expression);
            if (expressions.Count() == 1)
            {
                var expr = expressions.Single();
                if (expr is IdentifierNameSyntax ||
                    (expr is MemberAccessExpressionSyntax member && member.Expression is ThisExpressionSyntax))
                    return expr;
            }
            return null;
        }

        private static FieldData? ExtractFieldFromExpression(AccessorKind accessorKind, ExpressionSyntax expression, Compilation compilation, bool useFieldLocation)
        {
            var semanticModel = compilation.GetSemanticModel(expression.SyntaxTree);
            if (semanticModel == null)
                return null;

            expression = expression.RemoveParenthesis();

            if (expression is IdentifierNameSyntax &&
                semanticModel.GetSymbol(expression) is IFieldSymbol field)
                return new FieldData(accessorKind, field, expression, useFieldLocation);

            else if (expression is MemberAccessExpressionSyntax member &&
                member.Expression is ThisExpressionSyntax &&
                semanticModel.GetSymbol(expression) is IFieldSymbol field2)
                return new FieldData(accessorKind, field2, member.Name, useFieldLocation);

            return null;
        }

        private static bool IsLeftSideOfAssignment(ExpressionSyntax expression)
        {
            expression = expression.RemoveParenthesis();
            return IsAssignmentLeft(expression) || (expression.Parent is ExpressionSyntax parent && IsAssignmentLeft(parent));
        }

        private static bool IsAssignmentLeft(ExpressionSyntax expression)
        {
            var topParenthesizedExpression = expression.GetSelfOrTopParenthesizedExpression();
            return topParenthesizedExpression.Parent.IsKind(SyntaxKind.SimpleAssignmentExpression) &&
                topParenthesizedExpression.Parent is AssignmentExpressionSyntax assignment &&
                assignment.Left == topParenthesizedExpression;
        }

        private static SyntaxNode FindInvokedMethod(Compilation compilation, INamedTypeSymbol containingType, SyntaxNode expression) =>
            compilation.GetSemanticModel(expression.SyntaxTree) is { } semanticModel
            && semanticModel.GetSymbolInfo(expression).Symbol is { } invocationSymbol
            && invocationSymbol.ContainingType == containingType
            && invocationSymbol.DeclaringSyntaxReferences.Length == 1
            && invocationSymbol.DeclaringSyntaxReferences.Single().GetSyntax() is { } invokedMethod
            ? invokedMethod
            : null;

        private IEnumerable<IPropertySymbol> GetExplictlyDeclaredProperties(INamedTypeSymbol symbol) =>
            symbol.GetMembers()
                .Where(m => m.Kind == SymbolKind.Property)
                .OfType<IPropertySymbol>()
                .Where(p => ImplementsExplicitGetterOrSetter(p));

        private SyntaxNodeOrToken CheckExpectedFieldIsUsed(IMethodSymbol methodSymbol, IFieldSymbol expectedField, ImmutableArray<FieldData> actualFields)
        {
            var expectedFieldIsUsed = actualFields.Any(a => a.Field == expectedField);
            if (!expectedFieldIsUsed || !actualFields.Any())
                return GetEffectedNodeOrToken(actualFields, methodSymbol);
            else
                return null;

            SyntaxNodeOrToken GetEffectedNodeOrToken(ImmutableArray<FieldData> fields, IMethodSymbol method)
            {
                SyntaxNodeOrToken effectedNodeOrToken = null;
                if (fields.Count(x => x.UseFieldLocation) == 1)
                    effectedNodeOrToken = fields.First().LocationNode;
                else
                {
                    effectedNodeOrToken = method?.Locations.First().SourceTree.GetRoot().FindNode(method.Locations.First().SourceSpan);
                    effectedNodeOrToken = ((SyntaxNode)effectedNodeOrToken) is AccessorDeclarationSyntax accessor ? accessor.Keyword : effectedNodeOrToken;
                }
                return effectedNodeOrToken;
            }
        }

        private IList<PropertyData> CollectPropertyData(IEnumerable<IPropertySymbol> properties, Compilation compilation)
        {
            IList<PropertyData> allPropertyData = new List<PropertyData>();
            foreach (var property in properties)
            {
                var readFields = FindFieldReads(property, compilation);
                var updatedFields = FindFieldAssignments(property, compilation);
                var ignoreGetter = ShouldIgnoreAccessor(property.GetMethod);
                var ignoreSetter = ShouldIgnoreAccessor(property.SetMethod);
                var data = new PropertyData(property, readFields, updatedFields, ignoreGetter, ignoreSetter);
                allPropertyData.Add(data);
            }
            return allPropertyData;
        }

        private readonly struct PropertyData
        {
            public PropertyData(IPropertySymbol propertySymbol, IEnumerable<FieldData> read, IEnumerable<FieldData> updated,
                bool ignoreGetter, bool ignoreSetter)
            {
                PropertySymbol = propertySymbol;
                ReadFields = read.ToImmutableArray();
                UpdatedFields = updated.ToImmutableArray();
                IgnoreGetter = ignoreGetter;
                IgnoreSetter = ignoreSetter;
            }

            public IPropertySymbol PropertySymbol { get; }

            public ImmutableArray<FieldData> ReadFields { get; }

            public ImmutableArray<FieldData> UpdatedFields { get; }

            public bool IgnoreGetter { get; }

            public bool IgnoreSetter { get; }
        }

        private enum AccessorKind
        {
            Getter,
            Setter
        }

        private struct FieldData
        {
            public FieldData(AccessorKind accessor, IFieldSymbol field, SyntaxNode locationNode, bool useFieldLocation)
            {
                AccessorKind = accessor;
                Field = field;
                LocationNode = locationNode;
                UseFieldLocation = useFieldLocation;
            }

            public AccessorKind AccessorKind { get; }

            public IFieldSymbol Field { get; }

            public SyntaxNode LocationNode { get; }

            public bool UseFieldLocation { get; }
        }

        private class PropertyToField
        {
            private readonly IDictionary<IFieldSymbol, string> fieldToNameMap;

            public PropertyToField(IEnumerable<IFieldSymbol> fields)
                => fieldToNameMap = fields.ToDictionary(f => f, f => GetCanonicalFieldName(f.Name));

            public IFieldSymbol GetMatchingField(IPropertySymbol propertySymbol)
            {
                var standardisedPropertyName = GetCanonicalFieldName(propertySymbol.Name);
                var matchingFields = fieldToNameMap.Keys
                    .Where(k => AreCanonicalNamesEqual(fieldToNameMap[k], standardisedPropertyName));

                if (matchingFields.Count() != 1)
                    return null;

                return matchingFields.First();
            }

            private static string GetCanonicalFieldName(string name) =>
                name.Replace("_", string.Empty);

            private static bool AreCanonicalNamesEqual(string name1, string name2) =>
                name1.Equals(name2, StringComparison.OrdinalIgnoreCase);
        }
    }
}