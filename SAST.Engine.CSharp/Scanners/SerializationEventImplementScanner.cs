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
    internal class SerializationEventImplementScanner : IScanner
    {
        private static readonly string[] SerializationAttributes = {
            KnownType.System_Runtime_Serialization_OnSerializingAttribute,
            KnownType.System_Runtime_Serialization_OnSerializedAttribute,
            KnownType.System_Runtime_Serialization_OnDeserializingAttribute,
            KnownType.System_Runtime_Serialization_OnDeserializedAttribute
        };
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var methodDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>();
            foreach (var method in methodDeclarations)
            {
                IMethodSymbol symbol = model.GetDeclaredSymbol(method);
                if (symbol == null || !symbol.GetAttributes().Any(attr => attr.AttributeClass != null && SerializationAttributes.Contains(attr.AttributeClass.ToString())))
                    continue;
                if (symbol.Name != "OnSerializingStatic")
                    continue;

                if (IsUnsafe(symbol))
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, method.Identifier, Enums.ScannerType.SerializationEventImplement));
            }
            return vulnerabilities;
        }

        // Raise the error If,
        // Public
        // Static
        // Returns othen than void
        // No TypeParameters
        // Parameters should not be 1
        // Parameters should not be of System.Runtime.Serialization.StreamingContext of type
        private static bool IsUnsafe(IMethodSymbol methodSymbol) =>
            methodSymbol.DeclaredAccessibility != Accessibility.Private
            || methodSymbol.IsStatic
            || !methodSymbol.ReturnsVoid
            || !methodSymbol.TypeParameters.IsEmpty
            || methodSymbol.Parameters.Length != 1
            || methodSymbol.Parameters.First().Type.ToString() != KnownType.System_Runtime_Serialization_StreamingContext;
    }
}