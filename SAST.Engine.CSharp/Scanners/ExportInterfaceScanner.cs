using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class ExportInterfaceScanner : IScanner
    {
        private static string[] ExportTypes =
        {
            Constants.KnownType.System_ComponentModel_Composition_ExportAttribute,
            Constants.KnownType.System_ComponentModel_Composition_InheritedExportAttribute
        };
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var classDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<ClassDeclarationSyntax>();
            foreach (var item in classDeclarations)
            {
                if (item.AttributeLists != null && item.AttributeLists.Count == 0)
                    continue;
                foreach (var attributeList in item.AttributeLists)
                {
                    foreach (var attribute in attributeList.Attributes)
                    {
                        //Export
                        var exportSymbol = model.GetTypeSymbol(attribute);
                        if (exportSymbol == null || !ExportTypes.Contains(exportSymbol.ToString()))
                            continue;
                        if (attribute.ArgumentList == null || attribute.ArgumentList.Arguments.Count == 0)
                            continue;
                        TypeOfExpressionSyntax typeOfExpression = null;
                        if (attribute.ArgumentList.Arguments.Count == 1)
                            typeOfExpression = attribute.ArgumentList.Arguments[0].Expression as TypeOfExpressionSyntax;
                        else if (attribute.ArgumentList.Arguments.Count == 2)
                        {
                            int i = -1;
                            foreach (var attributeArgument in attribute.ArgumentList.Arguments)
                            {
                                i++;
                                if (i == 1 && attributeArgument.NameColon == null)
                                {
                                    typeOfExpression = attributeArgument.Expression as TypeOfExpressionSyntax;
                                    break;
                                }
                                else if (attributeArgument.NameColon != null && attributeArgument.NameColon.Name.ToString() == "contractType")
                                {
                                    typeOfExpression = attributeArgument.Expression as TypeOfExpressionSyntax;
                                    break;
                                }
                            }
                        }
                        if (typeOfExpression != null && ValidateType(model, typeOfExpression.Type, item))
                            syntaxNodes.Add(attribute);
                    }
                }
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.ExportInterface);
        }

        private static bool BaseTypeEquals(ITypeSymbol classSymbol, string baseType)
        {
            if (classSymbol == null)
                return false;
            else if (classSymbol.ToString() == baseType || Utils.DerivesFrom(classSymbol, baseType) || Utils.ImplementsFrom(classSymbol, baseType))
                return true;
            else
                return false;
        }
        private static bool ValidateType(SemanticModel model, TypeSyntax typeSyntax, ClassDeclarationSyntax classDeclaration)
        {
            ITypeSymbol typeSymbol = model.GetTypeSymbol(typeSyntax);
            if (typeSymbol == null)
                return false;

            ITypeSymbol classSymbol = model.GetDeclaredSymbol(classDeclaration);
            if (BaseTypeEquals(classSymbol, typeSymbol.ToString()))
                return false;

            return true;
        }
    }
}
