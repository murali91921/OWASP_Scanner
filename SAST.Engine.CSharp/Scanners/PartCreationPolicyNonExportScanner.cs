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
    internal class PartCreationPolicyNonExportScanner : IScanner
    {
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var classDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<ClassDeclarationSyntax>();
            foreach (var classDeclaration in classDeclarations)
            {
                if (classDeclaration.AttributeLists.Count == 0)
                    continue;

                var classSymbol = model.GetDeclaredSymbol(classDeclaration);
                if (classSymbol == null || !HasPartCreationPolicyAttribute(classSymbol))
                    continue;

                if (classSymbol.GetAttributes().Any(attr => Utils.DerivesFrom(attr.AttributeClass,KnownType.System_ComponentModel_Composition_ExportAttribute)) || HasInheritExportAttribute(classSymbol))
                    continue;

                vulnerabilities.Add(VulnerabilityDetail.Create(filePath, classDeclaration.Identifier, Enums.ScannerType.PartCreationPolicyNonExport));
            }
            return vulnerabilities;
        }

        private static bool HasPartCreationPolicyAttribute(ITypeSymbol classSymbol) =>
            classSymbol.GetAttributes().Any(attr =>
                attr.AttributeClass?.ToString() == KnownType.System_ComponentModel_Composition_PartCreationPolicyAttribute);

        private static bool HasInheritExportAttribute(ITypeSymbol classSymbol)
        {
            if (classSymbol.GetAttributes().Any(attr => Utils.ImplementsFrom(attr.AttributeClass, KnownType.System_ComponentModel_Composition_InheritedExportAttribute)))
                return true;
            else if (classSymbol.BaseType != null && HasInheritExportAttribute(classSymbol.BaseType))
                return true;
            else
                return (classSymbol.AllInterfaces.Any(inter => HasInheritExportAttribute(inter)));
        }
    }
}