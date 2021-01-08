using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Constants;
using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SAST.Engine.CSharp.Scanners
{
    internal class SerializationConstructorScanner : IScanner
    {
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var classDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<ClassDeclarationSyntax>();
            foreach (var classDeclaration in classDeclarations)
            {
                //Class should implement ISerializable interface
                var classSymbol = model.GetDeclaredSymbol(classDeclaration);
                if (classSymbol == null || !Utils.ImplementsFrom(classSymbol as ITypeSymbol, KnownType.System_Runtime_Serialization_ISerializable))
                    continue;

                //Class should have Serializable Attribute
                bool hasSerializableAttribute = false;
                foreach (var attributeList in classDeclaration.AttributeLists)
                {
                    foreach (var attributeSyntax in attributeList.Attributes)
                    {
                        ITypeSymbol typeSymbol = model.GetTypeSymbol(attributeSyntax);
                        if (typeSymbol != null && typeSymbol.ToString() == KnownType.System_SerializableAttribute)
                            hasSerializableAttribute = true;
                    }
                }

                if (!hasSerializableAttribute)
                {
                    if (classDeclaration.Modifiers.Any(obj => obj.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.PublicKeyword)))
                        syntaxNodes.Add(classDeclaration);
                    continue;
                }
                //Constructor should exists with 2 Parameters
                var constructorDeclarations = classDeclaration.DescendantNodesAndSelf().OfType<ConstructorDeclarationSyntax>();
                ConstructorDeclarationSyntax constructorDeclaration = null;
                foreach (var item in constructorDeclarations)
                {
                    if (item.ParameterList.Parameters.Count == 2)
                    {
                        //Parameter types should be SerializationInfo & StreamingContext and order also need to be consider
                        var param = item.ParameterList.Parameters[0];
                        ITypeSymbol paramTypeSymbol = model.GetTypeSymbol(param.Type);
                        if (paramTypeSymbol == null || paramTypeSymbol.ToString() != KnownType.System_Runtime_Serialization_SerializationInfo)
                            continue;
                        param = item.ParameterList.Parameters[1];
                        paramTypeSymbol = model.GetTypeSymbol(param.Type);
                        if (paramTypeSymbol == null || paramTypeSymbol.ToString() != KnownType.System_Runtime_Serialization_StreamingContext)
                            continue;
                        constructorDeclaration = item;
                        break;
                    }
                }

                if (constructorDeclaration == null)
                {
                    if (!classDeclaration.Modifiers.Any(obj => obj.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.InternalKeyword)))
                        syntaxNodes.Add(classDeclaration);
                    continue;
                }

                //Validating Access Modifiers of Class and Constructors
                //If class is sealed, private constuctor is safe.
                if (classSymbol.IsSealed)
                {
                    if (!constructorDeclaration.Modifiers.Any(obj => obj.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.PrivateKeyword)))
                        syntaxNodes.Add(constructorDeclaration);
                }
                //If class is notsealed, protected constuctor is safe.
                //If constructor have more modifiers like protected internal, constructor is unsafe. 
                else
                {
                    if (!constructorDeclaration.Modifiers.Any(obj => obj.IsKind(Microsoft.CodeAnalysis.CSharp.SyntaxKind.ProtectedKeyword)) || constructorDeclaration.Modifiers.Count > 1)
                        syntaxNodes.Add(constructorDeclaration);
                }
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.SerializationConstructor);
        }
    }
}
