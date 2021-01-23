using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.CSharp;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using SAST.Engine.CSharp.Constants;
using Microsoft.CodeAnalysis.FindSymbols;

namespace SAST.Engine.CSharp.Scanners
{
    internal class DisposableMemberScanner : IScanner
    {
        private readonly static string[] Disposable_Types =
        {
            KnownType.System_IO_FileStream,
            KnownType.System_IO_BinaryReader,
            KnownType.System_IO_StreamReader,
            KnownType.System_IO_StreamWriter,
            KnownType.System_Net_WebClient,
            KnownType.System_Net_Sockets_TcpClient,
            KnownType.System_Net_Sockets_UdpClient,
            KnownType.System_Drawing_Image,
            KnownType.System_Drawing_Bitmap,
            KnownType.System_IO_Stream
        };
        private readonly static string[] DisposeMethods = { "Dispose", "Close" };
        private readonly static string[] FactoryMethods =
        {
            KnownMethod.System_IO_File_Create,
            KnownMethod.System_IO_File_Open,
            KnownMethod.System_Drawing_Image_FromFile,
            KnownMethod.System_Drawing_Image_FromStream
        };

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var variableDeclarators = syntaxNode.DescendantNodesAndSelf().OfType<VariableDeclaratorSyntax>();
            foreach (var variableDeclarator in variableDeclarators)
            {
                //Ignore Public Fields, Properties
                ISymbol symbol = model.GetDeclaredSymbol(variableDeclarator);
                if (symbol == null)
                    continue;
                if ((symbol.Kind == SymbolKind.Field || symbol.Kind == SymbolKind.Property) && symbol.DeclaredAccessibility == Accessibility.Public)
                    continue;

                //Consider Disposable types & object types
                ITypeSymbol typeSymbol = symbol.GetTypeSymbol();
                if (typeSymbol == null)
                    continue;
                if (!Disposable_Types.Contains(typeSymbol.ToString()) && typeSymbol.SpecialType != SpecialType.System_Object)
                    continue;

                List<NodeAndModel> typesDeclarationsAndModels = symbol.DeclaringSyntaxReferences
                    .Where(obj => model.Compilation.ContainsSyntaxTree(obj.SyntaxTree)).Select(r => new NodeAndModel
                    {
                        Node = r.GetSyntax(),
                        Model = model.Compilation.GetSemanticModel(r.SyntaxTree)
                    })
                    .ToList();

                var trackedNodesAndSymbols = new HashSet<NodeAndSymbol>();
                foreach (var item in typesDeclarationsAndModels)
                {
                    TrackInitializedLocalsAndPrivateFields(item.Node, item.Model, trackedNodesAndSymbols);
                    TrackAssignmentsToLocalsAndPrivateFields(symbol, solution, trackedNodesAndSymbols);
                }

                if (trackedNodesAndSymbols.Any())
                {
                    var excludedSymbols = new HashSet<ISymbol>();
                    foreach (var referenced in SymbolFinder.FindReferencesAsync(symbol, solution).Result)
                    {
                        foreach (var referenceLocation in referenced.Locations)
                        {
                            if (referenceLocation.Location.IsInMetadata)
                                continue;
                            var node = referenceLocation.Location.SourceTree.GetRootAsync().Result.FindNode(referenceLocation.Location.SourceSpan);
                            if (!model.Compilation.ContainsSyntaxTree(referenceLocation.Location.SourceTree))
                                continue;
                            var Model = model.Compilation.GetSemanticModel(referenceLocation.Location.SourceTree);

                            ExcludeDisposedAndClosedLocalsAndPrivateFields(node, Model, excludedSymbols);
                            ExcludeReturnedPassedAndAliasedLocalsAndPrivateFields(node, Model, excludedSymbols);
                        }
                    }

                    foreach (var trackedNodeAndSymbol in trackedNodesAndSymbols)
                        if (!excludedSymbols.Contains(trackedNodeAndSymbol.Symbol))
                            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, trackedNodeAndSymbol.Node, Enums.ScannerType.None));
                }
            }
            return vulnerabilities;
        }

        private void TrackInitializedLocalsAndPrivateFields(SyntaxNode typeDeclaration, SemanticModel semanticModel, ISet<NodeAndSymbol> trackedNodesAndSymbols)
        {
            var localVariableDeclarations = typeDeclaration.
                AncestorsAndSelf()
                .OfType<LocalDeclarationStatementSyntax>()
                .Where(localDeclaration => localDeclaration.UsingKeyword.Value == null)
                .Select(localDeclaration => localDeclaration.Declaration);

            var fieldVariableDeclarations = typeDeclaration
                .AncestorsAndSelf()
                .OfType<FieldDeclarationSyntax>()
                .Where(fieldDeclaration => !fieldDeclaration.Modifiers.Any() || fieldDeclaration.Modifiers.Any(SyntaxKind.PrivateKeyword))
                .Select(fieldDeclaration => fieldDeclaration.Declaration);

            var variableDeclarations = localVariableDeclarations.Concat(fieldVariableDeclarations);

            foreach (var declaration in variableDeclarations)
            {
                var trackedVariables = declaration.Variables.Where(obj => typeDeclaration.Equals(obj))
                    .Where(v => v.Initializer != null && IsInstantiation(v.Initializer.Value, semanticModel));
                foreach (var variableNode in trackedVariables)
                    trackedNodesAndSymbols.Add(new NodeAndSymbol { Node = variableNode, Symbol = semanticModel.GetDeclaredSymbol(variableNode) });
            }
        }

        private void TrackAssignmentsToLocalsAndPrivateFields(ISymbol symbol, Solution solution, ISet<NodeAndSymbol> trackedNodesAndSymbols)
        {
            var referencedSymbols = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
            foreach (var referencedSymbol in referencedSymbols)
            {
                foreach (var referenceLocation in referencedSymbol.Locations)
                {
                    SyntaxNode node = referenceLocation.Location.SourceTree.GetRoot().FindNode(referenceLocation.Location.SourceSpan);

                    var assignment = node.AncestorsAndSelf().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                    if (assignment == null || assignment.Parent is UsingStatementSyntax)
                        continue;

                    SemanticModel currentModel = referenceLocation.Document.GetSemanticModelAsync().Result;
                    if (!currentModel.Compilation.ContainsSyntaxTree(referenceLocation.Location.SourceTree))
                        continue;

                    SemanticModel model = currentModel.Compilation.GetSemanticModel(referenceLocation.Location.SourceTree);
                    ISymbol assignedSymbol = model.GetSymbol(assignment.Left);
                    if (assignedSymbol == null || !assignedSymbol.Equals(symbol, SymbolEqualityComparer.Default))
                        continue;

                    if (assignment.Parent.IsKind(SyntaxKind.UsingStatement) || !IsInstantiation(assignment.Right, model))
                        continue;

                    var leftReferencedSymbol = model.GetSymbol(assignment.Left);
                    if (leftReferencedSymbol == null || !leftReferencedSymbol.Equals(symbol, SymbolEqualityComparer.Default))
                        continue;

                    if (IsLocalOrPrivateField(leftReferencedSymbol))
                        trackedNodesAndSymbols.Add(new NodeAndSymbol { Node = assignment, Symbol = leftReferencedSymbol });
                }
            }
        }

        private static void ExcludeDisposedAndClosedLocalsAndPrivateFields(SyntaxNode typeDeclaration, SemanticModel semanticModel, ISet<ISymbol> excludedSymbols)
        {
            var invocationsAndConditionalAccesses = typeDeclaration
                .AncestorsAndSelf()
                .OfType<ExpressionStatementSyntax>()
                .Where(n => n.Expression.IsKind(SyntaxKind.InvocationExpression) || n.Expression.IsKind(SyntaxKind.ConditionalAccessExpression))
                .Select(expr => expr.Expression);

            foreach (var invocationOrConditionalAccess in invocationsAndConditionalAccesses)
            {
                SimpleNameSyntax name = null;
                ExpressionSyntax expression = null;

                if (invocationOrConditionalAccess is InvocationExpressionSyntax invocation)
                {
                    var memberAccessNode = invocation.Expression as MemberAccessExpressionSyntax;
                    name = memberAccessNode?.Name;
                    expression = memberAccessNode?.Expression;
                }
                else if (invocationOrConditionalAccess is ConditionalAccessExpressionSyntax conditionalAccess)
                {
                    if (!(conditionalAccess.WhenNotNull is InvocationExpressionSyntax conditionalInvocation))
                        continue;

                    var memberBindingNode = conditionalInvocation.Expression as MemberBindingExpressionSyntax;
                    name = memberBindingNode?.Name;
                    expression = conditionalAccess.Expression;
                }
                if (name == null || !DisposeMethods.Contains(name.Identifier.Text))
                    continue;

                var referencedSymbol = semanticModel.GetSymbol(expression);
                if (referencedSymbol != null && IsLocalOrPrivateField(referencedSymbol))
                    excludedSymbols.Add(referencedSymbol);
            }
        }

        private static void ExcludeReturnedPassedAndAliasedLocalsAndPrivateFields(SyntaxNode typeDeclaration, SemanticModel semanticModel, ISet<ISymbol> excludedSymbols)
        {
            var identifiersAndSimpleMemberAccesses = typeDeclaration
                .AncestorsAndSelf()
                .Where(n => n.IsKind(SyntaxKind.IdentifierName) ||
                            n.IsKind(SyntaxKind.Argument) ||
                            n.IsKind(SyntaxKind.SimpleMemberAccessExpression));

            foreach (var identifierOrSimpleMemberAccess in identifiersAndSimpleMemberAccesses)
            {
                SyntaxNode expression = null;
                if (identifierOrSimpleMemberAccess.IsKind(SyntaxKind.IdentifierName))
                    expression = (IdentifierNameSyntax)identifierOrSimpleMemberAccess;
                else if (identifierOrSimpleMemberAccess.IsKind(SyntaxKind.SimpleMemberAccessExpression))
                {

                    var memberAccess = (MemberAccessExpressionSyntax)identifierOrSimpleMemberAccess;
                    if (!memberAccess.Expression.IsKind(SyntaxKind.ThisExpression))
                        continue;
                    expression = memberAccess;
                }
                else if (identifierOrSimpleMemberAccess.IsKind(SyntaxKind.Argument))
                    expression = identifierOrSimpleMemberAccess as ArgumentSyntax;

                if (!IsStandaloneExpression(expression))
                    continue;

                var referencedSymbol = semanticModel.GetSymbol(expression is ArgumentSyntax ? (expression as ArgumentSyntax).Expression : expression);
                if (referencedSymbol != null && IsLocalOrPrivateField(referencedSymbol))
                    excludedSymbols.Add(referencedSymbol);
            }
        }

        private static bool IsLocalOrPrivateField(ISymbol symbol) => symbol.Kind == SymbolKind.Local ||
                (symbol.Kind == SymbolKind.Field && symbol.DeclaredAccessibility == Accessibility.Private);

        private static bool IsStandaloneExpression(SyntaxNode expression)
        {
            var parentAsAssignment = expression.Parent as AssignmentExpressionSyntax;
            return !(expression.Parent is ExpressionSyntax) ||
                (parentAsAssignment != null && object.ReferenceEquals(expression, parentAsAssignment.Right)) ||
                expression is ArgumentSyntax ||
                expression.Parent is ArgumentSyntax;
        }

        private static bool IsInstantiation(ExpressionSyntax expression, SemanticModel model)
        {
            bool result =
                IsNewTrackedTypeObjectCreation(expression, model) ||
                IsDisposableRefStructCreation(expression, model) ||
                IsFactoryMethodInvocation(expression, model);
            return result;
        }

        private static bool IsNewTrackedTypeObjectCreation(ExpressionSyntax expression, SemanticModel model)
        {
            if (!expression.IsKind(SyntaxKind.ObjectCreationExpression))
                return false;

            var type = model.GetTypeSymbol(expression);
            if (!Disposable_Types.Contains(type.ToString()))
                return false;

            bool result = model.GetSymbol(expression) is IMethodSymbol;
            //!constructor.Parameters.Any(param => Utils.ImplementsFrom(param.Type, "System.IDisposable"));
            return result;
        }

        private static bool IsDisposableRefStructCreation(ExpressionSyntax expression, SemanticModel model)
        {
            if (!expression.IsKind(SyntaxKind.ObjectCreationExpression))
                return false;

            var type = model.GetTypeSymbol(expression);
            return type.TypeKind == TypeKind.Struct && type.IsRefLikeType
                && type.GetMembers().OfType<IMethodSymbol>().Any(ms => ms.Name == "Dispose");
        }

        private static bool IsFactoryMethodInvocation(ExpressionSyntax expression, SemanticModel model)
        {
            if (!(expression is InvocationExpressionSyntax invocation))
                return false;

            if (!(model.GetSymbol(invocation) is IMethodSymbol methodSymbol))
                return false;

            var methodName = methodSymbol.ContainingType.ToDisplayString() + "." + methodSymbol.Name;
            return FactoryMethods.Contains(methodName);
        }

        private class NodeAndModel
        {
            internal SyntaxNode Node { get; set; }
            internal SemanticModel Model { get; set; }
        }
        private class NodeAndSymbol
        {
            internal SyntaxNode Node { get; set; }
            internal ISymbol Symbol { get; set; }
        }
    }
}