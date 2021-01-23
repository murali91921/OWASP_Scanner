using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Constants;
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
            KnownType.System_Runtime_Remoting_Channels_SoapServerFormatterSinkProvider_TypeFilterLevel,
            KnownType.System_Runtime_Remoting_Channels_BinaryServerFormatterSinkProvider_TypeFilterLevel,
            KnownType.System_Runtime_Remoting_Channels_SoapServerFormatterSink_TypeFilterLevel,
            KnownType.System_Runtime_Remoting_Channels_BinaryServerFormatterSink_TypeFilterLevel
        };

        private static readonly string[] Binder_Props = {
            KnownType.System_Runtime_Serialization_Formatters_Binary_BinaryFormatter_Binder,
            KnownType.System_Runtime_Serialization_NetDataContractSerializer_Binder,
            KnownType.System_Runtime_Serialization_Formatters_Soap_SoapFormatter_Binder
        };

        private static readonly string[] BinaryFormatter_Methods = {
            KnownMethod.System_Runtime_Serialization_Formatters_Binary_BinaryFormatter_Deserialize,
            KnownMethod.System_Runtime_Serialization_Formatters_Binary_BinaryFormatter_UnsafeDeserializeMethodResponse,
            KnownMethod.System_Runtime_Serialization_Formatters_Binary_BinaryFormatter_UnsafeDeserialize,
            KnownMethod.System_Runtime_Serialization_Formatters_Soap_SoapFormatter_Deserialize,
            KnownMethod.System_Runtime_Serialization_NetDataContractSerializer_Deserialize,
            KnownMethod.System_Runtime_Serialization_NetDataContractSerializer_ReadObject,
        };

        private static readonly string[] _insecureMethods = {
            KnownMethod.System_Messaging_BinaryMessageFormatter_Read,
            KnownMethod.System_Web_UI_ObjectStateFormatter_Deserialize,
            KnownMethod.System_Runtime_Serialization_XmlObjectSerializer_ReadObject,
            KnownMethod.System_Runtime_Serialization_DataContractJsonSerializer_ReadObject,
            KnownMethod.System_Runtime_Serialization_Json_DataContractJsonSerializer_ReadObject,
            KnownMethod.System_Xml_Serialization_XmlSerializer_Deserialize,
            KnownMethod.System_Messaging_XmlMessageFormatter_Read,
            KnownMethod.fastJSON_JSON_ToObject,
            KnownMethod.ServiceStack_Text_JsonSerializer_DeserializeFromString,
            KnownMethod.ServiceStack_Text_JsonSerializer_DeserializeFromReader,
            KnownMethod.ServiceStack_Text_JsonSerializer_DeserializeFromStream,
            KnownMethod.ServiceStack_Text_TypeSerializer_DeserializeFromString,
            KnownMethod.ServiceStack_Text_TypeSerializer_DeserializeFromReader,
            KnownMethod.ServiceStack_Text_TypeSerializer_DeserializeFromStream,
            KnownMethod.ServiceStack_Text_CsvSerializer_DeserializeFromString,
            KnownMethod.ServiceStack_Text_CsvSerializer_DeserializeFromReader,
            KnownMethod.ServiceStack_Text_CsvSerializer_DeserializeFromStream,
            KnownMethod.ServiceStack_Text_XmlSerializer_DeserializeFromString,
            KnownMethod.ServiceStack_Text_XmlSerializer_DeserializeFromReader,
            KnownMethod.ServiceStack_Text_XmlSerializer_DeserializeFromStream
        };
        private static readonly string[] _insecureObjectCreation = {
            KnownType.System_Runtime_Serialization_Json_DataContractJsonSerializer,
            KnownType.System_Xml_Serialization_XmlSerializer,
            KnownType.System_Resources_ResourceReader
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
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var attributeArguments = _syntaxNode.DescendantNodesAndSelf().OfType<AttributeSyntax>();
            foreach (var argument in attributeArguments)
            {
                ITypeSymbol typeSymbol = _model.GetTypeSymbol(argument.Name);
                if (typeSymbol == null || typeSymbol.ToString() != KnownType.Newtonsoft_Json_JsonPropertyAttribute)
                    continue;
                foreach (var item in argument.ArgumentList.Arguments)
                {
                    if (item.NameEquals.Name.ToString() == "TypeNameHandling")
                    {
                        Optional<object> value = _model.GetConstantValue(item.Expression);
                        if (value.HasValue && ((int)value.Value != 0))
                        {
                            vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, ScannerType.InsecureDeserialization));
                            break;
                        }
                    }
                }
            }
            return vulnerabilities;
        }

        /// <summary>
        /// This method will find Insecure Setting by Serializer Properties Vulnerabilities
        /// </summary>
        /// <returns></returns>
        private List<VulnerabilityDetail> FindVulnerableAssignments()
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var assignments = _syntaxNode.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>();
            foreach (var item in assignments)
            {
                ISymbol symbol = _model.GetSymbol(item.Left);
                //SoapServerFormatterSinkProvider
                if (symbol == null)
                    continue;
                if (symbol.ToString() == KnownType.Newtonsoft_Json_JsonSerializerSettings_TypeNameHandling)
                {
                    ITypeSymbol typeSymbol = _model.GetTypeSymbol(item.Right);
                    if (typeSymbol == null || typeSymbol.ToString() != KnownType.Newtonsoft_Json_TypeNameHandling)
                        continue;
                    Optional<object> optional = _model.GetConstantValue(item.Right is CastExpressionSyntax cast ? cast.Expression : item.Right);
                    if (!optional.HasValue || (optional.Value is int value && value != 0))
                        vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, ScannerType.InsecureDeserialization));
                }
                else if (Sink_TypeFilterLevel_Props.Contains(symbol.ToString()))
                {
                    ITypeSymbol typeSymbol = _model.GetTypeSymbol(item.Right);
                    if (typeSymbol == null || typeSymbol.ToString() != KnownType.System_Runtime_Serialization_Formatters_TypeFilterLevel)
                        continue;
                    Optional<object> optional = _model.GetConstantValue(item.Right is CastExpressionSyntax cast ? cast.Expression : item.Right);
                    if (!optional.HasValue || (optional.Value is int value && value == 3))
                        vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, ScannerType.InsecureDeserialization));
                }
            }
            return vulnerabilities;
        }

        /// <summary>
        /// This method will find the Insecure Serializer Object Creations
        /// </summary>
        /// <returns></returns>
        private List<VulnerabilityDetail> FindVulnerableObjectCreations()
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var objectCreations = _syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var item in objectCreations)
            {
                ITypeSymbol typeSymbol = _model.GetTypeSymbol(item);
                if (typeSymbol == null)
                    continue;
                if (_insecureObjectCreation.Any(obj => obj == typeSymbol.ToString()))
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, ScannerType.InsecureDeserialization));
                else if (typeSymbol.ToString() == KnownType.System_Web_UI_LosFormatter)
                {
                    if (IsVulnerable_LosFormatter(item))
                        vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, ScannerType.InsecureDeserialization));
                }
                else if (typeSymbol.ToString() == KnownType.System_Web_Script_Serialization_JavaScriptSerializer)
                {
                    if (item.ArgumentList == null)
                    {
                        vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, ScannerType.InsecureDeserialization));
                        continue;
                    }
                    var argument = item.ArgumentList.Arguments.FirstOrDefault();
                    if (argument == null || argument.Expression.Kind() == SyntaxKind.NullLiteralExpression)
                    {
                        vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, ScannerType.InsecureDeserialization));
                        continue;
                    }
                    typeSymbol = _model.GetTypeSymbol(argument.Expression);
                    if (typeSymbol == null)
                        continue;
                    if (typeSymbol.ToString() == KnownType.System_Web_Script_Serialization_SimpleTypeResolver || IsVulnerable_Resolver(typeSymbol))
                        vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, ScannerType.InsecureDeserialization));
                }
            }
            return vulnerabilities;
        }

        /// <summary>
        /// This method will find the Insecure Deserialization Methods.
        /// </summary>
        /// <returns></returns>
        private List<VulnerabilityDetail> FindVulnerableInvocations(SemanticModel model)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var invocationExpressions = _syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocationExpressions)
            {
                ISymbol symbol = _model.GetSymbol(item);
                if (symbol == null)
                    continue;
                if (BinaryFormatter_Methods.Contains(symbol.ContainingType + "." + symbol.Name))
                {
                    if (item.Expression is MemberAccessExpressionSyntax memberAccess && IsVulnerable_BinaryFormatter(memberAccess.Expression, model))
                        vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, ScannerType.InsecureDeserialization));
                }
                else if (_insecureMethods.Contains(symbol.ContainingType + "." + symbol.Name))
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, item, ScannerType.InsecureDeserialization));
            }
            return vulnerabilities;
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
            if (typeSymbol == null || typeSymbol.ToString() != KnownType.System_Type)
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
            if (typeSymbol == null || typeSymbol.ToString() != KnownType.System_Type)
                return false;
            typeSymbol = model.GetTypeSymbol(methodDeclaration.ParameterList.Parameters[0].Type);
            if (typeSymbol == null || typeSymbol.SpecialType != SpecialType.System_String)
                return false;
            return true;
        }
    }
}