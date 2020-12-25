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
    internal class SerializationEventImplementScanner : IScanner
    {
        private static readonly string[] SerializationAttributes = {
            "System.Runtime.Serialization.OnSerializingAttribute",
            "System.Runtime.Serialization.OnSerializedAttribute",
            "System.Runtime.Serialization.OnDeserializingAttribute",
            "System.Runtime.Serialization.OnDeserializedAttribute"
        };
        private static readonly string StreamingContext_Type = "System.Runtime.Serialization.StreamingContext";

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxToken> syntaxTokens = new List<SyntaxToken>();
            var methodDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>();
            foreach (var method in methodDeclarations)
            {
                IMethodSymbol symbol = model.GetDeclaredSymbol(method);
                if (symbol == null
                    || !symbol.GetAttributes().Any(attr => attr.AttributeClass != null && SerializationAttributes.Contains(attr.AttributeClass.ToString())))
                    continue;
                if (symbol.Name != "OnSerializingStatic")
                    continue;

                if (IsUnsafe(symbol))
                    syntaxTokens.Add(method.Identifier);
            }
            return Mapper.Map.ConvertToVulnerabilityList(filePath, syntaxTokens, Enums.ScannerType.SerializationEventImplement);
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
            || methodSymbol.Parameters.First().Type.ToString() != StreamingContext_Type;
    }
}