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
    internal class PartCreationPolicyNonExportScanner : IScanner
    {
        private static readonly string PartCreationPolicyAttribute_Type = "System.ComponentModel.Composition.PartCreationPolicyAttribute";
        private static readonly string InheritedExportAttribute_Type = "System.ComponentModel.Composition.InheritedExportAttribute";
        private static readonly string ExportAttribute_Type = "System.ComponentModel.Composition.ExportAttribute";

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNodeOrToken> syntaxTokens = new List<SyntaxNodeOrToken>();
            var classDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<ClassDeclarationSyntax>();
            foreach (var classDeclaration in classDeclarations)
            {
                if (classDeclaration.AttributeLists.Count == 0)
                    continue;

                var classSymbol = model.GetDeclaredSymbol(classDeclaration);
                if (classSymbol == null)
                    continue;

                if (!HasPartCreationPolicyAttribute(classSymbol))
                    continue;

                if (classSymbol.GetAttributes().Any(attr => Utils.DerivesFrom(attr.AttributeClass, ExportAttribute_Type)) || HasInheritExportAttribute(classSymbol))
                    continue;

                syntaxTokens.Add(classDeclaration.Identifier);
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxTokens, Enums.ScannerType.PartCreationPolicyNonExport);
        }

        private static bool HasPartCreationPolicyAttribute(ITypeSymbol classSymbol) =>
            classSymbol.GetAttributes().Any(attr =>
                attr.AttributeClass?.ToString() == PartCreationPolicyAttribute_Type);

        private static bool HasInheritExportAttribute(ITypeSymbol classSymbol)
        {
            if (classSymbol.GetAttributes().Any(attr => Utils.ImplementsFrom(attr.AttributeClass, InheritedExportAttribute_Type)))
                return true;
            else if (classSymbol.BaseType != null && HasInheritExportAttribute(classSymbol.BaseType))
                return true;
            else
                return (classSymbol.AllInterfaces.Any(inter => HasInheritExportAttribute(inter)));
        }
    }
}