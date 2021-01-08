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
    internal class IDisposableImplementScanner : IScanner
    {
        private static string[] Disposable_Types =
        {
            KnownType.System_IDisposable,
            KnownType.System_IAsyncDisposable
        };
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxToken> syntaxTokens = new List<SyntaxToken>();
            var typeDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<TypeDeclarationSyntax>();
            foreach (var typeDeclaration in typeDeclarations)
            {
                //Interface Declaration not required to scan
                if (typeDeclaration is InterfaceDeclarationSyntax)
                    continue;

                //Exclude other than class.
                //Don't consider if class implemneted Disposable.
                ITypeSymbol typeSymbol = model.GetDeclaredSymbol(typeDeclaration);
                if (typeSymbol.TypeKind != TypeKind.Class && typeSymbol.TypeKind != TypeKind.Struct)
                    continue;
                if (Utils.ImplementsFromAny(typeSymbol, Disposable_Types))
                    continue;

                //Filter Disposablefields
                var disposableFields = typeSymbol.GetMembers().OfType<IFieldSymbol>().Where(fs => IsNonStaticNonPublicDisposableField(fs));
                if (disposableFields.Count() == 0)
                    continue;

                //Filter Field Initializations inside all methods
                var fieldInitializations = typeSymbol.GetMembers()
                    .OfType<IMethodSymbol>()
                    .SelectMany(m => GetAssignmentsToFieldsIn(m, model.Compilation))
                    .Where(f => disposableFields.Contains(f)).Distinct();
                disposableFields = disposableFields.Union(fieldInitializations);
                //disposableFields = disposableFields.Where(IsOwnerSinceDeclaration).Union(fieldInitializations);

                if (disposableFields.Any())
                    syntaxTokens.Add(typeDeclaration.Identifier);
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxTokens, Enums.ScannerType.IDisposableImplement);
        }

        private static bool IsNonStaticNonPublicDisposableField(IFieldSymbol fieldSymbol) =>
            fieldSymbol != null
            && !fieldSymbol.IsStatic
            && (fieldSymbol.DeclaredAccessibility == Accessibility.Protected || fieldSymbol.DeclaredAccessibility == Accessibility.Private);
        //&& IsDisposableField(fieldSymbol);

        private static bool IsDisposableField(IFieldSymbol fieldSymbol) =>
            Disposable_Types.Contains(fieldSymbol.Type.ToString())
            || Utils.ImplementsFromAny(fieldSymbol.Type, Disposable_Types);
        //            || IsDisposableRefStruct(fieldSymbol.Type);

        private static bool IsDisposableRefStruct(ITypeSymbol symbol) =>
            IsRefStruct(symbol) &&
            symbol.GetMembers("Dispose").OfType<IMethodSymbol>().Any(method => IsDisposeMethod(method));

        private static bool IsRefStruct(ITypeSymbol symbol) =>
            symbol != null &&
            symbol.TypeKind == TypeKind.Struct &&
            symbol.DeclaringSyntaxReferences.Length == 1 &&
            symbol.DeclaringSyntaxReferences[0].GetSyntax() is StructDeclarationSyntax structDeclaration &&
            structDeclaration.Modifiers.Any(SyntaxKind.RefKeyword);

        private static bool IsDisposeMethod(IMethodSymbol methodSymbol) =>
            methodSymbol.Name.Equals("Dispose") &&
            methodSymbol.Arity == 0 &&
            methodSymbol.Parameters.Length == 0 &&
            methodSymbol.ReturnsVoid &&
            methodSymbol.DeclaredAccessibility == Accessibility.Public;

        private static IEnumerable<IFieldSymbol> GetAssignmentsToFieldsIn(ISymbol m, Compilation compilation)
        {
            if (m.DeclaringSyntaxReferences.Length != 1
                || !(m.DeclaringSyntaxReferences[0].GetSyntax() is BaseMethodDeclarationSyntax method)
                || (method.Body == null && method.ExpressionBody == null))
                return Enumerable.Empty<IFieldSymbol>();

            return method.DescendantNodes()
                .OfType<AssignmentExpressionSyntax>()
                .Where(n => n.IsKind(SyntaxKind.SimpleAssignmentExpression) && n.Right is ObjectCreationExpressionSyntax)
                .Where(n => compilation.ContainsSyntaxTree(n.SyntaxTree))
                .Select(n => compilation.GetSemanticModel(method.SyntaxTree).GetSymbol(n.Left))
                .OfType<IFieldSymbol>();
        }

        private static bool IsOwnerSinceDeclaration(ISymbol symbol) =>
            symbol.DeclaringSyntaxReferences.SingleOrDefault()?.GetSyntax() is VariableDeclaratorSyntax varDeclarator
            && varDeclarator.Initializer?.Value is ObjectCreationExpressionSyntax;
    }
}