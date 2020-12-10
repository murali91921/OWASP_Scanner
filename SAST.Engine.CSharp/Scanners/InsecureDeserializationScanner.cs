using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Mapper;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis.CSharp;

namespace SAST.Engine.CSharp.Scanners
{
    /// <summary>
    /// This Scanner to find Insecure Deserialization Vulnerabilities 
    /// </summary>
    internal class InsecureDeserializationScanner : IScanner
    {
        SyntaxNode _syntaxNode;
        SemanticModel _model;
        Solution _solution;
        string _filePath;

        private static readonly string[] Sink_TypeFilterLevel_Props = {
            "System.Runtime.Remoting.Channels.SoapServerFormatterSinkProvider.TypeFilterLevel",
            "System.Runtime.Remoting.Channels.BinaryServerFormatterSinkProvider.TypeFilterLevel",
            "System.Runtime.Remoting.Channels.SoapServerFormatterSink.TypeFilterLevel",
            "System.Runtime.Remoting.Channels.BinaryServerFormatterSink.TypeFilterLevel"
        };

        private static readonly string[] Binder_Props = {
            "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Binder",
            "System.Runtime.Serialization.NetDataContractSerializer.Binder",
            "System.Runtime.Serialization.Formatters.Soap.SoapFormatter.Binder"
        };

        private static readonly string[] BinaryFormatter_Methods = {
            "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.Deserialize",
            "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.UnsafeDeserialize",
            "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter.UnsafeDeserializeMethodResponse",
            "System.Runtime.Serialization.NetDataContractSerializer.Deserialize",
            "System.Runtime.Serialization.NetDataContractSerializer.ReadObject",
            "System.Runtime.Serialization.Formatters.Soap.SoapFormatter.Deserialize",
        };

        private static readonly string[] _insecureMethods = {
            "System.Messaging.BinaryMessageFormatter.Read",
            "System.Web.UI.ObjectStateFormatter.Deserialize",
            "System.Runtime.Serialization.XmlObjectSerializer.ReadObject",
            "System.Runtime.Serialization.DataContractJsonSerializer.ReadObject",
            "System.Runtime.Serialization.Json.DataContractJsonSerializer.ReadObject",
            "System.Xml.Serialization.XmlSerializer.Deserialize",
            "System.Messaging.XmlMessageFormatter.Read",
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
            "System.Runtime.Serialization.Json.DataContractJsonSerializer",
            "System.Xml.Serialization.XmlSerializer",
            "System.Resources.ResourceReader"
        };

        /// <summary>
        /// This method will find Insecure Deserialization Vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            _model = model;
            _syntaxNode = syntaxNode;
            _filePath = filePath;
            _solution = solution;
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            vulnerabilities.AddRange(FindVulnerableAttributes());
            vulnerabilities.AddRange(FindVulnerableAssignments());
            vulnerabilities.AddRange(FindVulnerableObjectCreations());
            vulnerabilities.AddRange(FindVulnerableInvocations(model));
            return vulnerabilities;
        }

        /// <summary>
        /// This method will find Insecure Settings by Attibute
        /// </summary>
        /// <returns></returns>
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

        /// <summary>
        /// This method will find Insecure Setting by Serializer Properties Vulnerabilities
        /// </summary>
        /// <returns></returns>
        private List<VulnerabilityDetail> FindVulnerableAssignments()
        {
            List<SyntaxNode> vulnerabilities = new List<SyntaxNode>();
            var assignments = _syntaxNode.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>();
            foreach (var item in assignments)
            {
                ISymbol symbol = _model.GetSymbol(item.Left);
                //SoapServerFormatterSinkProvider
                if (symbol == null)
                    continue;
                if (symbol.ToString() == "Newtonsoft.Json.JsonSerializerSettings.TypeNameHandling")
                {
                    ITypeSymbol typeSymbol = _model.GetTypeSymbol(item.Right);
                    if (typeSymbol == null || typeSymbol.ToString() != "Newtonsoft.Json.TypeNameHandling")
                        continue;
                    Optional<object> value = _model.GetConstantValue(item.Right is CastExpressionSyntax cast ? cast.Expression : item.Right);
                    if (!value.HasValue)
                        vulnerabilities.Add(item);
                    else if ((int)value.Value != 0)
                        vulnerabilities.Add(item);
                }
                else if (Sink_TypeFilterLevel_Props.Contains(symbol.ToString()))
                {
                    ITypeSymbol typeSymbol = _model.GetTypeSymbol(item.Right);
                    if (typeSymbol == null || typeSymbol.ToString() != "System.Runtime.Serialization.Formatters.TypeFilterLevel")
                        continue;
                    Optional<object> value = _model.GetConstantValue(item.Right is CastExpressionSyntax cast ? cast.Expression : item.Right);
                    if (!value.HasValue)
                        vulnerabilities.Add(item);
                    else if ((int)value.Value == 3)
                        vulnerabilities.Add(item);
                }

            }
            return Map.ConvertToVulnerabilityList(_filePath, vulnerabilities, ScannerType.InsecureDeserialization);
        }

        /// <summary>
        /// This method will find the Insecure Serializer Object Creations
        /// </summary>
        /// <returns></returns>
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
                if (typeSymbol.ToString() == "System.Web.UI.LosFormatter")
                {
                    if (IsVulnerable_LosFormatter(item))
                        vulnerabilities.Add(item);
                }
                else if (typeSymbol.ToString() == "System.Web.Script.Serialization.JavaScriptSerializer")
                {
                    if (item.ArgumentList == null)
                    {
                        vulnerabilities.Add(item);
                        continue;
                    }
                    var argument = item.ArgumentList.Arguments.FirstOrDefault();
                    if (argument == null || argument.Expression.Kind() == SyntaxKind.NullLiteralExpression)
                    {
                        vulnerabilities.Add(item);
                        continue;
                    }
                    typeSymbol = _model.GetTypeSymbol(argument.Expression);
                    if (typeSymbol == null)
                        continue;
                    if (typeSymbol.ToString() == "System.Web.Script.Serialization.SimpleTypeResolver"
                        || IsVulnerable_Resolver(typeSymbol))
                        vulnerabilities.Add(item);
                }
            }
            return Map.ConvertToVulnerabilityList(_filePath, vulnerabilities, ScannerType.InsecureDeserialization);
        }

        /// <summary>
        /// This method will find the Insecure Deserialization Methods.
        /// </summary>
        /// <returns></returns>
        private List<VulnerabilityDetail> FindVulnerableInvocations(SemanticModel model)
        {
            List<SyntaxNode> vulnerabilities = new List<SyntaxNode>();
            var invocationExpressions = _syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocationExpressions)
            {
                ISymbol symbol = _model.GetSymbol(item);
                if (symbol == null)
                    continue;
                if (BinaryFormatter_Methods.Contains(symbol.ContainingType + "." + symbol.Name))
                {
                    if (item.Expression is MemberAccessExpressionSyntax memberAccess
                        && IsVulnerable_BinaryFormatter(memberAccess.Expression, model))
                        vulnerabilities.Add(item);
                }
                else if (_insecureMethods.Contains(symbol.ContainingType + "." + symbol.Name))
                {
                    vulnerabilities.Add(item);
                }
            }
            return Map.ConvertToVulnerabilityList(_filePath, vulnerabilities, ScannerType.InsecureDeserialization);
        }

        /// <summary>
        /// Detremines whether <paramref name="node"/> is vulnerable
        /// </summary>
        /// <param name="node"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        private bool IsVulnerable_BinaryFormatter(SyntaxNode node, SemanticModel model)
        {
            bool vulnerable = true;
            if (node is IdentifierNameSyntax identifierName)
            {
                ISymbol symbol = model.GetSymbol(identifierName);
                var syntaxReference = symbol.DeclaringSyntaxReferences.FirstOrDefault();
                if (syntaxReference != null)
                {
                    vulnerable = IsVulnerable_BinaryFormatter(syntaxReference.GetSyntaxAsync().Result,
                        model.Compilation.GetSemanticModel(syntaxReference.SyntaxTree));
                }
                var referencedSymbols = SymbolFinder.FindReferencesAsync(symbol, _solution).Result;
                foreach (var referencedSymbol in referencedSymbols)
                {
                    foreach (var referenceLocation in referencedSymbol.Locations)
                    {
                        if (!referenceLocation.Location.IsInSource || node.SyntaxTree.FilePath != referenceLocation.Document.FilePath)
                            continue;
                        var currentNode = node.SyntaxTree.GetRoot().FindNode(referenceLocation.Location.SourceSpan);
                        if (Utils.CheckSameMethod(currentNode, node) && currentNode.SpanStart < node.SpanStart)
                        {
                            var assignment = currentNode.Ancestors().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                            if (assignment == null)
                                continue;
                            ISymbol assignSymbol = model.GetSymbol(assignment.Left);
                            if (assignSymbol == null)
                                continue;
                            if (Binder_Props.Contains(assignSymbol.ToString()))
                                vulnerable = IsVulnerable_BinaryFormatter(assignment, model);
                        }
                    }
                }
                return vulnerable;
            }
            else if (node is ObjectCreationExpressionSyntax objectCreation)
            {
                //If no Initializer found
                if (objectCreation.Initializer == null)
                    return vulnerable;
                else
                {
                    foreach (var item in objectCreation.Initializer.Expressions)
                        if (item is AssignmentExpressionSyntax assignment && assignment.Left.ToString() == "Binder")
                        {
                            vulnerable = IsVulnerable_BinaryFormatter(assignment, model);
                            break;
                        }
                }
            }
            else if (node is AssignmentExpressionSyntax assignmentExpression)
            {
                ITypeSymbol typeSymbol = model.GetTypeSymbol(assignmentExpression.Right);
                if (typeSymbol == null)
                    return true;
                return IsVulnerable_Binder(typeSymbol);
            }
            else if (node is VariableDeclaratorSyntax variableDeclarator)
            {
                if (variableDeclarator.Initializer == null)
                    return false;
                return IsVulnerable_BinaryFormatter(variableDeclarator.Initializer.Value, model);
            }
            return vulnerable;
        }

        private bool IsVulnerable_LosFormatter(ObjectCreationExpressionSyntax objectCreation)
        {
            if (objectCreation.ArgumentList == null || objectCreation.ArgumentList.Arguments.Count != 2)
                return true;

            SyntaxNode firstArgument = null;
            int i = -1;
            foreach (var argument in objectCreation.ArgumentList.Arguments)
            {
                i++;
                if ((argument.NameColon is null && i == 0) ||
                    (argument.NameColon != null && argument.NameColon.Name.ToString() == "enableMac"))
                {
                    firstArgument = argument.Expression;
                    break;
                }
            }
            if (firstArgument is null)
                return true;
            var optional = _model.GetConstantValue(firstArgument);
            //value can be resolved at runtime
            if (!optional.HasValue)
                return true;
            if (optional.Value is bool value && !value)
                return true;
            return false;
        }

        private bool IsVulnerable_Binder(ITypeSymbol typeSymbol)
        {
            var BindMethodDeclaration = GetBindToTypeMethodDeclaration(typeSymbol);
            if (BindMethodDeclaration == null)
                return false;

            return !(BindMethodDeclaration.DescendantNodes().OfType<ThrowStatementSyntax>().Any()
                || BindMethodDeclaration.DescendantNodes().OfType<ExpressionSyntax>().Any(expression => expression.IsKind(SyntaxKind.ThrowExpression))
                || BindMethodDeclaration.DescendantNodes().OfType<ReturnStatementSyntax>().Any(returnStatement => returnStatement.Expression.IsKind(SyntaxKind.NullLiteralExpression)));
        }

        private bool IsVulnerable_Resolver(ITypeSymbol typeSymbol)
        {
            var BindMethodDeclaration = GetResolveTypeMethodDeclaration(typeSymbol);
            if (BindMethodDeclaration == null)
                return false;

            return !(BindMethodDeclaration.DescendantNodes().OfType<ThrowStatementSyntax>().Any()
                || BindMethodDeclaration.DescendantNodes().OfType<ExpressionSyntax>().Any(expression => expression.IsKind(SyntaxKind.ThrowExpression))
                || BindMethodDeclaration.DescendantNodes().OfType<ReturnStatementSyntax>().Any(returnStatement => returnStatement.Expression.IsKind(SyntaxKind.NullLiteralExpression)));
        }

        private MethodDeclarationSyntax GetBindToTypeMethodDeclaration(ITypeSymbol symbol)
        {
            return symbol.DeclaringSyntaxReferences.SelectMany(syntaxReference => syntaxReference.GetSyntax().DescendantNodes())
                .OfType<MethodDeclarationSyntax>()
                .FirstOrDefault(declaration => IsBindToType(declaration));
        }

        private MethodDeclarationSyntax GetResolveTypeMethodDeclaration(ITypeSymbol symbol)
        {
            return symbol.DeclaringSyntaxReferences.SelectMany(syntaxReference => syntaxReference.GetSyntax().DescendantNodes())
                .OfType<MethodDeclarationSyntax>()
                .FirstOrDefault(declaration => IsResolveType(declaration));
        }

        private bool IsBindToType(MethodDeclarationSyntax methodDeclaration)
        {
            var model = _model.Compilation.GetSemanticModel(methodDeclaration.GetReference().SyntaxTree);
            if (methodDeclaration.Identifier.Text != "BindToType" || methodDeclaration.ParameterList.Parameters.Count != 2)
                return false;
            ITypeSymbol typeSymbol = model.GetTypeSymbol(methodDeclaration.ReturnType);
            if (typeSymbol == null || typeSymbol.ToString() != "System.Type")
                return false;
            typeSymbol = model.GetTypeSymbol(methodDeclaration.ParameterList.Parameters[0].Type);
            if (typeSymbol == null || typeSymbol.SpecialType != SpecialType.System_String)
                return false;
            typeSymbol = model.GetTypeSymbol(methodDeclaration.ParameterList.Parameters[1].Type);
            if (typeSymbol == null || typeSymbol.SpecialType != SpecialType.System_String)
                return false;
            return true;
        }

        private bool IsResolveType(MethodDeclarationSyntax methodDeclaration)
        {
            var model = _model.Compilation.GetSemanticModel(methodDeclaration.GetReference().SyntaxTree);
            if (methodDeclaration.Identifier.Text != "ResolveType" || methodDeclaration.ParameterList.Parameters.Count != 1)
                return false;
            ITypeSymbol typeSymbol = model.GetTypeSymbol(methodDeclaration.ReturnType);
            if (typeSymbol == null || typeSymbol.ToString() != "System.Type")
                return false;
            typeSymbol = model.GetTypeSymbol(methodDeclaration.ParameterList.Parameters[0].Type);
            if (typeSymbol == null || typeSymbol.SpecialType != SpecialType.System_String)
                return false;
            return true;
        }
    }
}


/*
 **1. System.Runtime.Serialization.Formatters.Binary.BinaryFormatter – Deserialize, UnsafeDeserialize,UnsafeDeserializeMethodResponse
 **2. System.Runtime.Serialization.Formatters.Soap.SoapFormatter – Deserialize 
 **3. System.Web.UI.ObjectStateFormatter- Deserialize
 **4. System.Runtime.Serialization.NetDataContractSerializer – Deserialize, ReadObject
 **5. System.Web.UI.LosFormatter – Deserialize
 *6. Pending System.Workflow.ComponentModel.Activity – Load
 
 **7. SoapServerFormatterSinkProvider,
 *-----------SoapClientFormatterSinkProvider,
 **BinaryServerFormatterSinkProvider,
 *-----------BinaryClientFormatterSinkProvider,
 *-----------SoapClientFormatterSink,
 *SoapServerFormatterSink,
 *-----------BinaryClientFormatterSink,
 *BinaryServerFormatterSink – unsafe if used across an insecure channel or if used to talk to an untrusted party
 
 *8.Done System.Resource.ResourceReader – unsafe if used to read an untrusted resource string or stream
 *9. Not found Dll to resolve. Microsoft.Web.Design.Remote.ProxyObject – DecodeValue, DecodeSerializedObject
 *10.Done System.Web.Script.Serialization.JavaScriptSerializer – unsafe if used to deserialize an untrusted stream with a JavaScriptTypeResolver set
 *11.Done NewtonSoft / JSON.Net JSonSerializer – unsafe if the TypeNameHandling property is set to any value other than “None”
 *12.Done ServiceStack.Text – unsafe if used to deserialize an object whose membership graph can contain a member of type “Object”
 */
