using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using static System.Console;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using SAST.Engine.CSharp.Constants;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp;
using SAST.Engine.CSharp.Mapper;
using SAST.Engine.CSharp.Core;
using SAST.Engine.CSharp.Enums;
using System.Linq;
using SAST.Engine.CSharp.Parser;

namespace SAST.Engine.CSharp.Scanners
{
    internal class XssScanner : IScanner, ICSHtmlScanner
    {
        private ScannerType scannerType;
        public XssScanner(ScannerType paramScannerType) => scannerType = paramScannerType;

        private readonly static string[] DataRetrievalMethods = {
            KnownMethod.System_Data_Common_DbDataReader_GetString,
            KnownMethod.System_Data_SqlClient_SqlCommand_ExecuteScalar
            };
        private readonly static string[] ControllerClassNames = {
            KnownType.Microsoft_AspNetCore_Mvc_ControllerBase,
            KnownType.System_Web_Mvc_Controller
            };
        private readonly static string[] HttpVerbAttributes = {
            KnownType.System_Web_Mvc_HttpGetAttribute,
            KnownType.System_Web_Mvc_HttpPostAttribute,
            KnownType.System_Web_Mvc_HttpDeleteAttribute,
            KnownType.System_Web_Mvc_HttpPutAttribute,
            KnownType.System_Web_Mvc_HttpPatchAttribute,
            KnownType.Microsoft_AspNetCore_Mvc_HttpGetAttribute,
            KnownType.Microsoft_AspNetCore_Mvc_HttpPostAttribute,
            KnownType.Microsoft_AspNetCore_Mvc_HttpDeleteAttribute,
            KnownType.Microsoft_AspNetCore_Mvc_HttpPutAttribute,
            KnownType.Microsoft_AspNetCore_Mvc_HttpPatchAttribute
            };
        private readonly static string[] WebFormsRepsonseMethods = {
            KnownMethod.System_Web_HttpResponse_Write,
            KnownMethod.System_Web_HttpResponseBase_Write,
            KnownMethod.System_Web_UI_ClientScriptManager_RegisterStartupScript,
            KnownMethod.System_Web_UI_ClientScriptManager_RegisterClientScriptBlock,
            KnownMethod.System_Web_UI_Page_RegisterStartupScript,
            KnownMethod.System_Web_UI_Page_RegisterClientScriptBlock
        };
        private readonly static string[] WebFormsControlProperties = {
            KnownType.System_Web_UI_WebControls_CheckBox_Text,
            KnownType.System_Web_UI_WebControls_CompareValidator_Text,
            KnownType.System_Web_UI_WebControls_CustomValidator_Text,
            KnownType.System_Web_UI_WebControls_HyperLink_Text,
            KnownType.System_Web_UI_WebControls_HyperLink_NavigateUrl,
            KnownType.System_Web_UI_WebControls_Label_Text,
            KnownType.System_Web_UI_WebControls_LinkButton_Text,
            KnownType.System_Web_UI_WebControls_Literal_Text,
            KnownType.System_Web_UI_WebControls_RadioButton_Text,
            KnownType.System_Web_UI_WebControls_RadioButton_GroupName,
            KnownType.System_Web_UI_WebControls_RangeValidator_Text,
            KnownType.System_Web_UI_WebControls_RegularExpressionValidator_Text,
            KnownType.System_Web_UI_WebControls_RequiredFieldValidator_Text,
            KnownType.System_Web_UI_WebControls_TableCell_Text,
            KnownType.System_Web_UI_WebControls_Calendar_Caption,
            KnownType.System_Web_UI_WebControls_Table_Caption,
            KnownType.System_Web_UI_WebControls_Panel_GroupingText,
            KnownType.System_Web_UI_HtmlControls_HtmlContainerControl,
            KnownType.System_Web_UI_WebControls_InnerHtml,
            KnownType.System_Web_UI_Control_ID
            };
        Solution solution;

        public IEnumerable<VulnerabilityDetail> FindVulnerabilities(string filePath)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            string[] content = CSHtmlParser.GetContent(filePath);
            if (content == null || content.Length == 0)
                return vulnerabilities;

            string[] sourceExpr = {
                @"\@Html\.Raw\(((?<Value>[A-Za-z0-9.]+))\)",
                @"\@MvcHtmlString\.Create\(((?<Value>[A-Za-z0-9.]+))\)",
                //@"\@Html\.CheckBox\(((?<Value>[A-Za-z0-9.]+))\)",
                //@"\@Html\.CheckBoxFor\(((?<Value>[A-Za-z0-9.]+))\)",
                //@"\@Html\.RadioButton\(((?<Value>[A-Za-z0-9.]+))\)",
                //@"\@Html\.Raw\(((?<Value>[A-Za-z0-9.]+))\)",
                //@"\@Html\.Raw\(((?<Value>[A-Za-z0-9.]+))\)",
                //@"\@Html\.Raw\(((?<Value>[A-Za-z0-9.]+))\)",
                //@"\@Html\.Raw\(((?<Value>[A-Za-z0-9.]+))\)"

                //"RadioButtonFor", "DropDownList", "DropDownListFor",
                //"Hidden", "HiddenFor", "Password", "PasswordFor",
                //"Editor", "EditorFor", "EditorForModel","EnumDropDownListFor",
                //"ListBox", "ListBoxFor 
            };
            string[] EncodeMethods = {
                KnownMethod.System_Web_HttpUtility_HtmlEncode,
                KnownMethod.HttpUtility_HtmlEncode,
                "Html.Encode"
            };
            int lineNum = 0;
            foreach (var line in content)
            {
                lineNum++;
                foreach (var expression in sourceExpr)
                {
                    var matches = Regex.Matches(line, expression);
                    foreach (Match match in matches)
                    {
                        if (match == null)
                            continue;
                        //if (!EncodeMethods.Any(obj => match.Groups["Value"].Value.Contains(obj)))
                        //vulnerabilities.Add(VulnerabilityDetail.Create(filePath, element, Enums.ScannerType.XSS));
                        //vulnerabilities.Add(new VulnerabilityDetail()
                        //    {
                        //        CodeSnippet = match.Groups["Value"].Value,
                        //        FilePath = filePath,
                        //        LineNumber = lineNum + "," + match.Groups["Value"].Index,
                        //        Type = ScannerType.XSS,
                        //        SubType = ScannerSubType.DomXSS
                        //    });
                    }
                }
            }
            return vulnerabilities;
        }

        /// <summary>
        /// Determines the vulnerabilities in <paramref name="syntaxNode"/>
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            this.solution = solution;
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var classes = syntaxNode.DescendantNodesAndSelf().OfType<ClassDeclarationSyntax>();
            foreach (var classItem in classes)
            {
                List<SyntaxNode> reflectedXSSExpressions = new List<SyntaxNode>();
                List<SyntaxNode> storedXSSExpressions = new List<SyntaxNode>();
                List<SyntaxNode> vulnerableCheck = FindCauseVulnerabililties(classItem, model);
                NodeFactory nodeFactory = new NodeFactory(solution);
                foreach (var node in vulnerableCheck)
                {
                    if (nodeFactory.IsVulnerable(node, model))
                    {
                        if (scannerType == ScannerType.StoredXSS)
                        {
                            if (IsVulnerable(node, model))
                                vulnerabilities.Add(VulnerabilityDetail.Create(filePath, node, ScannerType.StoredXSS));
                        }
                        else if (scannerType == ScannerType.ReflectedXSS)
                            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, node, ScannerType.ReflectedXSS));
                    }
                }
            }
            return vulnerabilities;
        }

        /// <summary>
        /// This method will filter the syntaxNodes in <paramref name="classItem"/> which can cause vulnerables.
        /// </summary>
        /// <param name="classItem"></param>
        /// <param name="model"></param>
        /// <returns></returns>
        private List<SyntaxNode> FindCauseVulnerabililties(ClassDeclarationSyntax classItem, SemanticModel model)
        {
            List<SyntaxNode> lstVulnerableCheck = new List<SyntaxNode>();
            var classSymbol = model.GetDeclaredSymbol(classItem);
            //MVC Controllers and actions
            if (Utils.DerivesFromAny(classSymbol, ControllerClassNames))
            {
                var methodsWithParameters = classItem.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>()
                    .Where(method => !method.ParameterList.Parameters.Count.Equals(0))
                    .Where(method => method.Modifiers.ToString().Equals("public"));
                foreach (MethodDeclarationSyntax method in methodsWithParameters)
                {
                    bool verbExists = false;
                    if (method.AttributeLists.Count() == 0)
                        continue;
                    foreach (var attributeList in method.AttributeLists)
                    {
                        foreach (var attribute in attributeList.Attributes)
                        {
                            TypeInfo typeInfo = model.GetTypeInfo(attribute.Name);
                            if (typeInfo.Type == null)
                                continue;
                            if (HttpVerbAttributes.Contains(typeInfo.Type.ToString()))
                                verbExists = true;
                            if (verbExists)
                                break;
                        }
                        if (verbExists)
                            break;
                    }
                    if (!verbExists)
                        continue;
                    if (method.ExpressionBody != null)
                    {
                        lstVulnerableCheck.Add(method.ExpressionBody.Expression);
                        continue;
                    }
                    if (method.Body == null /*|| method.Body.Statements.OfType<ReturnStatementSyntax>().Count() == 0*/)
                        continue;
                    foreach (var item in method.Body.Statements.OfType<ReturnStatementSyntax>())
                        lstVulnerableCheck.Add(item);
                    foreach (var item in method.DescendantNodes().OfType<AssignmentExpressionSyntax>())
                    {
                        if (item.Left is MemberAccessExpressionSyntax viewBagExpression)
                        {
                            ISymbol symbol = model.GetSymbol(viewBagExpression.Expression);
                            if (symbol == null)
                                continue;
                            if (symbol.ToString() == KnownType.System_Web_Mvc_ControllerBase_ViewBag)
                                lstVulnerableCheck.Add(item.Right);
                        }
                        else if (item.Left is ElementAccessExpressionSyntax dataExpression)
                        {
                            ISymbol symbol = model.GetSymbol(dataExpression.Expression);
                            if (symbol == null)
                                continue;
                            if (symbol.ToString() == KnownType.System_Web_Mvc_ControllerBase_ViewData
                                || symbol.ToString() == KnownType.System_Web_Mvc_ControllerBase_TempData)
                                lstVulnerableCheck.Add(item.Right);
                        }
                    }
                }
            }
            //WebForms methods
            else
            {
                foreach (var invocation in classItem.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>())
                {
                    if (!(model.GetSymbol(invocation) is IMethodSymbol symbol))
                        continue;
                    if (!WebFormsRepsonseMethods.Any(name => name == symbol.ReceiverType.ToString() + "." + symbol.Name.ToString()))
                        continue;
                    foreach (var argument in invocation.ArgumentList.Arguments)
                    {
                        var argumentType = model.GetTypeInfo(argument.Expression);
                        if (argumentType.Type == null)
                            continue;
                        if (argumentType.Type.SpecialType == SpecialType.System_String)
                            lstVulnerableCheck.Add(argument.Expression);
                        else if (argumentType.Type.ToString() == "char[]" && argument.Expression is InvocationExpressionSyntax)
                        {
                            if ((argument.Expression as InvocationExpressionSyntax).Expression is MemberAccessExpressionSyntax currentExpression && currentExpression.Name.ToString() == "ToCharArray")
                            {
                                TypeInfo typeInfo = model.GetTypeInfo(currentExpression);
                                if (typeInfo.Type == null)
                                    continue;
                                if (typeInfo.Type.SpecialType == SpecialType.System_String)
                                    lstVulnerableCheck.Add(currentExpression.Expression);
                            }
                        }
                    }
                }
                foreach (var assignment in classItem.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>())
                {
                    ISymbol symbol = model.GetSymbol(assignment.Left);
                    if (symbol == null)
                    {
                        if (!(assignment.Left is MemberAccessExpressionSyntax member))
                            continue;

                        symbol = model.GetSymbol(member.Expression);
                        if (symbol == null)
                            continue;
                        else if (WebFormsControlProperties.Any(obj => obj == symbol.ToString() + "." + member.Name))
                            lstVulnerableCheck.Add(assignment.Right);
                    }
                    if (WebFormsControlProperties.Any(obj => obj == symbol.ToString()))
                        lstVulnerableCheck.Add(assignment.Right);
                }
            }
            return lstVulnerableCheck;
        }

        /// <summary>
        /// Checking for Stored XSS
        /// </summary>
        /// <param name="syntaxNode">Expression to check </param>
        /// <param name="model">SemanticModel of document</param>
        /// <param name="callingSymbol"></param>
        /// <returns></returns>
        private bool IsVulnerable(SyntaxNode syntaxNode, SemanticModel model, ISymbol callingSymbol = null)
        {
            ISymbol symbol = null;
            bool isVulnerable = false;
            switch (syntaxNode.Kind())
            {
                case SyntaxKind.IdentifierName:
                    TypeInfo typeInfo = model.GetTypeInfo(syntaxNode);
                    if (typeInfo.Type == null)
                        return false;

                    if (typeInfo.Type.SpecialType != SpecialType.System_String && typeInfo.Type.SpecialType != SpecialType.System_Object)
                        return false;

                    symbol = model.GetSymbol(syntaxNode);
                    if (symbol == null)
                        return false;
                    var references = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
                    foreach (var referencedSymbol in references)
                    {
                        isVulnerable = IsVulnerable(referencedSymbol.Definition.Locations.First().SourceTree.GetRoot()
                            .FindNode(referencedSymbol.Definition.Locations.First().SourceSpan), model);
                        foreach (var referenceLocation in referencedSymbol.Locations)
                        {
                            if (syntaxNode.SpanStart <= referenceLocation.Location.SourceSpan.Start)
                                continue;
                            var assigment = syntaxNode.SyntaxTree.GetRoot().FindNode(referenceLocation.Location.SourceSpan)
                                .AncestorsAndSelf().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                            if (assigment == null)
                                continue;
                            if (assigment.Left.ToString() == syntaxNode.ToString())
                                isVulnerable = IsVulnerable(assigment.Right, model, symbol);
                        }
                    }
                    return isVulnerable;
                case SyntaxKind.InvocationExpression:
                    isVulnerable = false;
                    symbol = model.GetSymbol(syntaxNode);
                    if (symbol == null)
                        return false;

                    var invocation = syntaxNode as InvocationExpressionSyntax;
                    if (DataRetrievalMethods.Any(method => method == symbol.ContainingType.ToString() + "." + symbol.Name.ToString()))
                        return true;
                    if (symbol.ContainingType.ToString() + "." + symbol.Name.ToString() == KnownMethod.System_Convert_ToString)
                        return IsVulnerable(invocation.ArgumentList.Arguments.First().Expression, model);
                    else if (symbol.ContainingType.ToString() + "." + symbol.Name.ToString() == KnownMethod.object_ToString)
                        return IsVulnerable((invocation.Expression as MemberAccessExpressionSyntax).Expression, model);
                    if (NodeFactory.IsSanitized(invocation, model))
                        return false;
                    foreach (var syntaxReference in symbol.DeclaringSyntaxReferences)
                    {
                        SemanticModel currentModel = null;
                        foreach (var project in solution.Projects)
                            if (project.GetCompilationAsync().Result.ContainsSyntaxTree(syntaxReference.SyntaxTree))
                                currentModel = project.GetCompilationAsync().Result.GetSemanticModel(syntaxReference.SyntaxTree);
                        if (currentModel == null || !(syntaxReference.GetSyntax() is MethodDeclarationSyntax methodDeclarationSyntax) || methodDeclarationSyntax.Body == null)
                            continue;
                        if (methodDeclarationSyntax.ExpressionBody != null)
                            return IsVulnerable(methodDeclarationSyntax.ExpressionBody.Expression, currentModel);
                        if (methodDeclarationSyntax.Body == null)
                            continue;
                        var returnStatements = methodDeclarationSyntax.Body.Statements.OfType<ReturnStatementSyntax>();
                        foreach (var returnStatement in returnStatements)
                            isVulnerable = IsVulnerable(returnStatement.Expression, currentModel);
                    }
                    return isVulnerable;
                case SyntaxKind.SimpleAssignmentExpression:
                    var assignmentExpression = syntaxNode as AssignmentExpressionSyntax;
                    return IsVulnerable(assignmentExpression.Right, model);
                case SyntaxKind.AddExpression:
                    var addExpression = syntaxNode as BinaryExpressionSyntax;
                    var left = IsVulnerable(addExpression.Left, model, callingSymbol);
                    var right = IsVulnerable(addExpression.Right, model, callingSymbol);
                    return left || right;
                case SyntaxKind.VariableDeclarator:
                    var variableDeclarator = syntaxNode as VariableDeclaratorSyntax;
                    if (variableDeclarator.Initializer != null)
                        return IsVulnerable(variableDeclarator.Initializer.Value, model);
                    return false;
                case SyntaxKind.Parameter:
                    return false;
                default:
                    return false;
            }
        }
    }
}