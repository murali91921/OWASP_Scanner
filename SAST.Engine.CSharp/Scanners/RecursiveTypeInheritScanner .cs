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
    internal class RecursiveTypeInheritScanner : IScanner
    {
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var typeDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<TypeDeclarationSyntax>();
            foreach (var typeDeclaration in typeDeclarations)
            {
                var typeSymbol = model.GetDeclaredSymbol(typeDeclaration);
                if (typeSymbol == null || !typeSymbol.IsGenericType)
                    continue;

                var baseTypes = GetBaseTypes(typeSymbol);
                if (baseTypes.Any(t => t.IsGenericType && HasRecursiveGenericSubstitution(t, typeSymbol)))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, typeDeclaration, Enums.ScannerType.RecursiveTypeInheritance));
            }
            return vulnerabilities;
        }

        private static IEnumerable<INamedTypeSymbol> GetBaseTypes(INamedTypeSymbol typeSymbol)
        {
            var interfaces = typeSymbol.Interfaces.Where(obj => obj.IsGenericType);
            return typeSymbol.TypeKind == TypeKind.Class
                ? interfaces.Concat(new[] { typeSymbol.BaseType })
                : interfaces;
        }

        private static bool HasRecursiveGenericSubstitution(INamedTypeSymbol typeSymbol, INamedTypeSymbol declaredType)
        {
            bool HasSubstitutedTypeArguments(INamedTypeSymbol type) => type.TypeArguments.OfType<INamedTypeSymbol>().Any();
            bool IsSameAsDeclaredType(INamedTypeSymbol type) => type.OriginalDefinition.Equals(declaredType) && HasSubstitutedTypeArguments(type);
            bool ContainsRecursiveGenericSubstitution(IEnumerable<ITypeSymbol> types) => types.OfType<INamedTypeSymbol>()
                .Any(type => IsSameAsDeclaredType(type) || ContainsRecursiveGenericSubstitution(type.TypeArguments));
            return ContainsRecursiveGenericSubstitution(typeSymbol.TypeArguments);
        }
    }
}