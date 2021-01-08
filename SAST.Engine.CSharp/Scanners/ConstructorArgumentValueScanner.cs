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
    internal class ConstructorArgumentValueScanner : IScanner
    {
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var properties = syntaxNode.DescendantNodesAndSelf().OfType<PropertyDeclarationSyntax>();
            foreach (var property in properties)
            {
                var propertySymbol = model.GetDeclaredSymbol(property);
                var unsafeNode = CheckConstructorArgumentProperty(property, propertySymbol);
                if (unsafeNode != null)
                    syntaxNodes.Add(unsafeNode);
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.ConstructorArgumentValue);
        }

        private static SyntaxNode CheckConstructorArgumentProperty(SyntaxNode propertyDeclaration, IPropertySymbol propertySymbol)
        {
            if (propertySymbol == null)
                return null;

            var constructorArgumentAttribute = GetConstructorArgumentAttributeOrDefault(propertySymbol);
            if (constructorArgumentAttribute == null || constructorArgumentAttribute.ConstructorArguments.Length != 1)
                return null;

            var specifiedName = constructorArgumentAttribute.ConstructorArguments[0].Value.ToString();
            if (!GetAllParentClassConstructorArgumentNames(propertyDeclaration).Any(n => n == specifiedName))
            {
                var attributeSyntax = (AttributeSyntax)constructorArgumentAttribute.ApplicationSyntaxReference.GetSyntax();
                return attributeSyntax.ArgumentList.Arguments[0];
            }

            return null;
        }

        private static AttributeData GetConstructorArgumentAttributeOrDefault(IPropertySymbol propertySymbol)
            => propertySymbol.GetAttributes().Where(attr => attr.AttributeClass?.ToString() == Constants.KnownType.System_Windows_Markup_ConstructorArgumentAttribute).FirstOrDefault();

        private static IEnumerable<string> GetAllParentClassConstructorArgumentNames(SyntaxNode propertyDeclaration)
        {
            return propertyDeclaration
                .FirstAncestorOrSelf<ClassDeclarationSyntax>()
                .Members
                .OfType<ConstructorDeclarationSyntax>()
                .SelectMany(x => x.ParameterList.Parameters)
                .Select(x => x.Identifier.ValueText);
        }
    }
}