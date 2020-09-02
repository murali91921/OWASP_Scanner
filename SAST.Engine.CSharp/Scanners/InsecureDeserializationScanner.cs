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

        private static readonly string[] _insecureMethods ={
            "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize",
            "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.UnsafeDeserialize",
            "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.UnsafeDeserializeMethodResponse",
            "System.Messaging.BinaryMessageFormatter.Read",
            "System.Runtime.Serialization.Formatters.Soap.SoapFormatter.Deserialize",
            "System.Web.UI.ObjectStateFormatter.Deserialize",
            "System.Runtime.Serialization.XmlObjectSerializer.ReadObject",
            "System.Runtime.Serialization.NetDataContractSerializer.Deserialize",
            "System.Runtime.Serialization.NetDataContractSerializer.ReadObject",
            "System.Runtime.Serialization.DataContractSerializer.ReadObject",
            "System.Runtime.Serialization.DataContractJsonSerializer.ReadObject",
            "System.Runtime.Serialization.DataContractSerializer.ReadObject",
            "System.Runtime.Serialization.Json.DataContractJsonSerializer.ReadObject",
            "System.Xml.Serialization.XmlSerializer.Deserialize",
            "System.Messaging.XmlMessageFormatter.Read",
            "System.Web.UI.LosFormatter.Deserialize",
            "fastJSON.JSON.ToObject",
            "ServiceStack.Text.JsonSerializer.DeserializeFromString",
            "ServiceStack.Text.JsonSerializer.DeserializeFromReader",
            "ServiceStack.Text.JsonSerializer.DeserializeFromStream",
            "ServiceStack.Text.TypeSerializer.DeserializeFromString",
            "ServiceStack.Text.TypeSerializer.DeserializeFromReader",
            "ServiceStack.Text.TypeSerializer.DeserializeFromStream",
            "ServiceStack.Text.CsvSerializer.DeserializeFromString",
            "ServiceStack.Text.CsvSerializer.DeserializeFromReader",
            "ServiceStack.Text.CsvSerializer.DeserializeFromStream",
            "ServiceStack.Text.XmlSerializer.DeserializeFromString",
            "ServiceStack.Text.XmlSerializer.DeserializeFromReader",
            "ServiceStack.Text.XmlSerializer.DeserializeFromStream"
        };
        private static readonly string[] _insecureObjectCreation = {
            "System.Runtime.Serialization.DataContractSerializer",
            "System.Runtime.Serialization.Json.DataContractJsonSerializer",
            "System.Xml.Serialization.XmlSerializer",
            "System.Resources.ResourceReader"
        };

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            _model = model;
            _syntaxNode = syntaxNode;
            _filePath = filePath;
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            vulnerabilities.AddRange(FindVulnerableAttributes());
            vulnerabilities.AddRange(FindVulnerableAssignments());
            vulnerabilities.AddRange(FindVulnerableObjectCreations());
            vulnerabilities.AddRange(FindVulnerableInvocations());
            return vulnerabilities;
        }

        private List<VulnerabilityDetail> FindVulnerableAttributes()
        {
            List<SyntaxNode> vulnerabilities = new List<SyntaxNode>();
            var attributeArguments = _syntaxNode.DescendantNodesAndSelf().OfType<AttributeSyntax>();
            foreach (var argument in attributeArguments)
            {
                ITypeSymbol typeSymbol = _model.GetTypeSymbol(argument.Name);
                if (typeSymbol == null || typeSymbol.ToString() != "Newtonsoft.Json.JsonPropertyAttribute")
                    continue;
                foreach (var item in argument.ArgumentList.Arguments)
                {
                    if (item.NameEquals.Name.ToString() == "TypeNameHandling")
                    {
                        Optional<object> value = _model.GetConstantValue(item.Expression);
                        ISymbol symbol = _model.GetSymbol(item.Expression);
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

        private List<VulnerabilityDetail> FindVulnerableAssignments()
        {
            List<SyntaxNode> vulnerabilities = new List<SyntaxNode>();
            var assignments = _syntaxNode.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>();
            foreach (var item in assignments)
            {
                ISymbol symbol = _model.GetSymbol(item.Left);
                if (symbol == null || symbol.ToString() != "Newtonsoft.Json.JsonSerializerSettings.TypeNameHandling")
                    continue;
                ITypeSymbol typeSymbol = _model.GetTypeSymbol(item.Right);
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
                ITypeSymbol typeSymbol = _model.GetTypeSymbol(item);
                if (typeSymbol == null)
                    continue;
                if (_insecureObjectCreation.Any(obj => obj == typeSymbol.ToString()))
                {
                    vulnerabilities.Add(item);
                    continue;
                }
                else if (typeSymbol.ToString() == "System.Web.Script.Serialization.JavaScriptSerializer")
                {
                    var argument = item.ArgumentList.Arguments.FirstOrDefault();
                    if (argument != null && _model.GetTypeSymbol(argument.Expression) != null)
                        vulnerabilities.Add(item);
                }
            }
            return Map.ConvertToVulnerabilityList(_filePath, vulnerabilities, ScannerType.InsecureDeserialization);
        }

        private List<VulnerabilityDetail> FindVulnerableInvocations()
        {
            List<SyntaxNode> vulnerabilities = new List<SyntaxNode>();
            var invocationExpressions = _syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocationExpressions)
            {
                ISymbol symbol = _model.GetSymbol(item);
                if (symbol != null && _insecureMethods.Any(obj => obj == symbol.ContainingType + "." + symbol.Name))
                    vulnerabilities.Add(item);
            }
            return Map.ConvertToVulnerabilityList(_filePath, vulnerabilities, ScannerType.InsecureDeserialization);
        }
    }
}