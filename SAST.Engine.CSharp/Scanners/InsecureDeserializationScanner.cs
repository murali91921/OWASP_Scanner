using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Newtonsoft.Json;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Mapper;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;

namespace SAST.Engine.CSharp.Scanners
{
    internal class InsecureDeserializationScanner : IScanner
    {
        SyntaxNode _syntaxNode;
        string _filePath;
        SemanticModel _model;
        static readonly string[] InsecureBinaryDeserializationMethods ={
            "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize",
            "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.UnsafeDeserialize",
            "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.UnsafeDeserializeMethodResponse"
        };
        static readonly string JsonSerializerSettings_TypeNameHandling = "Newtonsoft.Json.JsonSerializerSettings.TypeNameHandling";

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            _model = model;
            _syntaxNode = syntaxNode;
            _filePath = filePath;
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            vulnerabilities.AddRange(FindVulnerableProperties());
            vulnerabilities.AddRange(FindVulnerableSettings());
            vulnerabilities.AddRange(FindVulnerableObjectCreations());
            return vulnerabilities;
            //if (InsecureBinaryDeserializationMethods.Any(obj => obj == symbol.ContainingType.ToString() + "." + symbol.Name.ToString()))
        }
        private List<VulnerabilityDetail> FindVulnerableProperties()
        {
            List<SyntaxNode> vulnerabilities = new List<SyntaxNode>();
            var attributeArguments = _syntaxNode.DescendantNodesAndSelf().OfType<AttributeSyntax>();
            foreach (var argument in attributeArguments)
            {
                ITypeSymbol typeSymbol = Utils.GetTypeSymbol(argument.Name, _model);
                if (typeSymbol == null || typeSymbol.ToString() != "Newtonsoft.Json.JsonPropertyAttribute")
                    continue;
                foreach (var item in argument.ArgumentList.Arguments)
                {
                    if (item.NameEquals.Name.ToString() == "TypeNameHandling")
                    {
                        Optional<object> value = _model.GetConstantValue(item.Expression);
                        ISymbol symbol = Utils.GetSymbol(item.Expression, _model);
                        if (value.HasValue && ((int)value.Value != 0))
                        {
                            vulnerabilities.Add(item);
                            break;
                        }
                    }
                }
            }
            return Map.ConvertToVulnerabilityList(_filePath, vulnerabilities, ScannerType.InsecureDeserialization);
        }
        private List<VulnerabilityDetail> FindVulnerableSettings()
        {
            List<SyntaxNode> vulnerabilities = new List<SyntaxNode>();
            var assignments = _syntaxNode.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>();
            foreach (var item in assignments)
            {
                ISymbol symbol = Utils.GetSymbol(item.Left, _model);
                if (symbol == null || symbol.ToString() != JsonSerializerSettings_TypeNameHandling)
                    continue;
                ITypeSymbol typeSymbol = Utils.GetTypeSymbol(item.Right, _model);
                if (typeSymbol == null || typeSymbol.ToString() != "Newtonsoft.Json.TypeNameHandling")
                    continue;
                Optional<object> value = _model.GetConstantValue(item.Right is CastExpressionSyntax cast ? cast.Expression : item.Right);
                if (!value.HasValue)
                    vulnerabilities.Add(item);
                else if ((int)value.Value != 0)
                    vulnerabilities.Add(item);
            }
            return Map.ConvertToVulnerabilityList(_filePath, vulnerabilities, ScannerType.InsecureDeserialization);
        }
        private List<VulnerabilityDetail> FindVulnerableObjectCreations()
        {
            List<SyntaxNode> vulnerabilities = new List<SyntaxNode>();
            var objectCreations = _syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var item in objectCreations)
            {
                ITypeSymbol typeSymbol = Utils.GetTypeSymbol(item, _model);
                if (typeSymbol == null || typeSymbol.ToString() != "System.Web.Script.Serialization.JavaScriptSerializer")
                    continue;
                var argument = item.ArgumentList.Arguments.FirstOrDefault();
                if (argument != null && Utils.GetTypeSymbol(argument.Expression, _model) != null)
                    vulnerabilities.Add(item);
            }
            return Map.ConvertToVulnerabilityList(_filePath, vulnerabilities, ScannerType.InsecureDeserialization);
        }
    }
}