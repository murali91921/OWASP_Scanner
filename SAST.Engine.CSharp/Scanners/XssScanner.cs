using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using static System.Console;
using System.Collections.Generic;
using System.Text.RegularExpressions;
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
        private static string[] DataRetrievalMethods = {
            "System.Data.Common.DbDataReader.GetString",
            "System.Data.SqlClient.SqlCommand.ExecuteScalar"
            };
        private static string[] ControllerClassNames = {
            "Microsoft.AspNetCore.Mvc.ControllerBase",
            "System.Web.Mvc.Controller"
            };
        private static string[] HttpVerbAttributes = {
            "System.Web.Mvc.HttpGetAttribute",
            "System.Web.Mvc.HttpPostAttribute",
            "System.Web.Mvc.HttpDeleteAttribute",
            "System.Web.Mvc.HttpPutAttribute",
            "System.Web.Mvc.HttpPatchAttribute",
            "Microsoft.AspNetCore.Mvc.HttpGetAttribute",
            "Microsoft.AspNetCore.Mvc.HttpPostAttribute",
            "Microsoft.AspNetCore.Mvc.HttpDeleteAttribute",
            "Microsoft.AspNetCore.Mvc.HttpPutAttribute",
            "Microsoft.AspNetCore.Mvc.HttpPatchAttribute",
            };
        private static string[] WebFormsRepsonseMethods = {
                "System.Web.HttpResponse.Write",
                "System.Web.HttpResponseBase.Write",
                "System.Web.UI.ClientScriptManager.RegisterStartupScript",      //2
                "System.Web.UI.ClientScriptManager.RegisterClientScriptBlock",   //2
                "System.Web.UI.Page.RegisterStartupScript",     //1
                "System.Web.UI.Page.RegisterClientScriptBlock"  //1
            };
        private static string[] WebFormsControlProperties = {
                "System.Web.UI.WebControls.CheckBox.Text",
                "System.Web.UI.WebControls.CompareValidator.Text",
                "System.Web.UI.WebControls.CustomValidator.Text",
                "System.Web.UI.WebControls.HyperLink.Text",
                "System.Web.UI.WebControls.HyperLink.NavigateUrl",
                "System.Web.UI.WebControls.Label.Text",
                "System.Web.UI.WebControls.LinkButton.Text",
                "System.Web.UI.WebControls.Literal.Text",
                "System.Web.UI.WebControls.RadioButton.Text",
                "System.Web.UI.WebControls.RadioButton.GroupName",
                "System.Web.UI.WebControls.RangeValidator.Text",
                "System.Web.UI.WebControls.RegularExpressionValidator.Text",
                "System.Web.UI.WebControls.RequiredFieldValidator.Text",
                "System.Web.UI.WebControls.TableCell.Text",
                "System.Web.UI.WebControls.Calendar.Caption",
                "System.Web.UI.WebControls.Table.Caption",
                "System.Web.UI.WebControls.Panel.GroupingText",
                "System.Web.UI.HtmlControls.HtmlContainerControl",
                "System.Web.UI.WebControls.InnerHtml",
                "System.Web.UI.Control.ID"
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
                "System.Web.HttpUtility.HtmlEncode",
                "HttpUtility.HtmlEncode",
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
                        if (!EncodeMethods.Any(obj => match.Groups["Value"].Value.Contains(obj)))
                            vulnerabilities.Add(new VulnerabilityDetail()
                            {
                                CodeSnippet = match.Groups["Value"].Value,
                                FilePath = filePath,
                                LineNumber = lineNum + "," + match.Groups["Value"].Index,
                                Type = ScannerType.XSS,
                                SubType = ScannerSubType.DomXSS
                            });
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
                        if (IsVulnerable(node, model))
                            storedXSSExpressions.Add(node);
                        else
                            reflectedXSSExpressions.Add(node);
                    }
                }
                if (reflectedXSSExpressions.Count > 0)
                    vulnerabilities.AddRange(Map.ConvertToVulnerabilityList(filePath, reflectedXSSExpressions, ScannerType.XSS, ScannerSubType.ReflectedXSS));
                if (storedXSSExpressions.Count > 0)
                    vulnerabilities.AddRange(Map.ConvertToVulnerabilityList(filePath, storedXSSExpressions, ScannerType.XSS, ScannerSubType.StoredXSS));
            }
            //vulnerabilities.AddRange();
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
                            if (symbol.ToString() == "System.Web.Mvc.ControllerBase.ViewBag")
                                lstVulnerableCheck.Add(item.Right);
                        }
                        else if (item.Left is ElementAccessExpressionSyntax dataExpression)
                        {
                            ISymbol symbol = model.GetSymbol(dataExpression.Expression);
                            if (symbol == null)
                                continue;
                            if (symbol.ToString() == "System.Web.Mvc.ControllerBase.ViewData"
                                || symbol.ToString() == "System.Web.Mvc.ControllerBase.TempData")
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
                    IMethodSymbol symbol = model.GetSymbol(invocation) as IMethodSymbol;
                    if (symbol == null)
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
                            var currentExpression = (argument.Expression as InvocationExpressionSyntax).Expression as MemberAccessExpressionSyntax;
                            if (currentExpression != null && currentExpression.Name.ToString() == "ToCharArray")
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
                        var member = assignment.Left as MemberAccessExpressionSyntax;
                        if (member == null)
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
                    if (symbol.ContainingType.ToString() + "." + symbol.Name.ToString() == "System.Convert.ToString")
                        return IsVulnerable(invocation.ArgumentList.Arguments.First().Expression, model);
                    else if (symbol.ContainingType.ToString() + "." + symbol.Name.ToString() == "object.ToString")
                        return IsVulnerable((invocation.Expression as MemberAccessExpressionSyntax).Expression, model);
                    if (NodeFactory.IsSanitized(syntaxNode as InvocationExpressionSyntax, model, SAST.Engine.CSharp.Enums.ScannerType.XSS))
                        return false;
                    foreach (var syntaxReference in symbol.DeclaringSyntaxReferences)
                    {
                        var methodDeclarationSyntax = syntaxReference.GetSyntax() as MethodDeclarationSyntax;
                        SemanticModel currentModel = null;
                        foreach (var project in solution.Projects)
                            if (project.GetCompilationAsync().Result.ContainsSyntaxTree(syntaxReference.SyntaxTree))
                                currentModel = project.GetCompilationAsync().Result.GetSemanticModel(syntaxReference.SyntaxTree);
                        if (currentModel == null || methodDeclarationSyntax == null || methodDeclarationSyntax.Body == null)
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