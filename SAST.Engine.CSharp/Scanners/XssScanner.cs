using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Formatting;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using static System.Console;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp;
using SAST.Engine.CSharp.Mapper;
using SAST.Engine.CSharp.Core;
using System.ComponentModel;
using System;
using Microsoft.CodeAnalysis.FindSymbols;
using System.IO.Enumeration;
using SAST.Engine.CSharp.Models;
using System.Net.Http.Headers;
using System.Runtime.InteropServices.WindowsRuntime;
using SAST.Engine.CSharp.Enums;

namespace ASTTask
{
    public class XssScanner : IScanner
    {
        //private static string[] encodingMethods = {
        //    "System.Text.Encodings.Web.TextEncoder.Encode",
        //    "HttpContext.Server.HtmlEncode"
        //   };

        #region Variable,Property Declarations
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
                "System.Web.UI.ClientScriptManager.RegisterClientScriptBloc",   //2
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
        //SemanticModel model;
        Solution solution;
        #endregion
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
        private List<SyntaxNode> FindCauseVulnerabililties(ClassDeclarationSyntax classItem, SemanticModel model)
        {
            List<SyntaxNode> lstVulnerableCheck = new List<SyntaxNode>();
            var classSymbol = model.GetDeclaredSymbol(classItem);
            //MVC Controllers and actions
            if (Utils.DerivesFromAny(classSymbol, ControllerClassNames))
            {
                var methodsWithParameters = classItem.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>()
                    .Where(method => !method.ParameterList.Parameters.Count.Equals(0))
                    .Where(method => method.Modifiers.ToString().Equals("public"))
                    .Where(method => method.ReturnType.ToString().Equals("string"));
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
                            if (HttpVerbAttributes.Any(obj => obj == typeInfo.Type.ToString()))
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
                    if (method.Body == null || method.Body.Statements.OfType<ReturnStatementSyntax>().Count() == 0)
                        continue;
                    foreach (var item in method.Body.Statements.OfType<ReturnStatementSyntax>())
                    {
                        WriteLine(item.Expression);
                        lstVulnerableCheck.Add(item.Expression); ;
                    }
                }
            }
            //WebForms methods
            else
            {
                foreach (var invocation in classItem.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>())
                {
                    SymbolInfo symbolInfo = model.GetSymbolInfo(invocation);
                    IMethodSymbol symbol = (symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault()) as IMethodSymbol;
                    // WriteLine(symbol);
                    if (symbol == null)   
                        continue;
                    if (!WebFormsRepsonseMethods.Any(name => name == symbol.ReceiverType.ToString() + "." + symbol.Name.ToString()))
                        continue;
                    foreach (var argument in invocation.ArgumentList.Arguments)
                    {
                        var argumentType = model.GetTypeInfo(argument.Expression);
                        if (argumentType.Type == null)
                            continue;
                        if (argumentType.Type.ToString() == "string" || argumentType.Type.ToString() == "System.String")
                            lstVulnerableCheck.Add(argument.Expression);
                        else if (argumentType.Type.ToString() == "char[]" && argument.Expression is InvocationExpressionSyntax)
                        {
                            var currentExpression = (argument.Expression as InvocationExpressionSyntax).Expression as MemberAccessExpressionSyntax;
                            if (currentExpression != null && currentExpression.Name.ToString() == "ToCharArray")
                            {
                                TypeInfo typeInfo = model.GetTypeInfo(currentExpression);
                                if (typeInfo.Type == null)
                                    continue;
                                if (typeInfo.Type.ToString() == "string" || typeInfo.Type.ToString() == "System.String")
                                    lstVulnerableCheck.Add(currentExpression.Expression);
                            }
                        }
                    }
                }
                foreach (var assignment in classItem.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>())
                {
                    SymbolInfo symbolInfo = model.GetSymbolInfo(assignment.Left);
                    ISymbol symbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                    if (symbol == null)
                    {
                        var member = assignment.Left as MemberAccessExpressionSyntax;
                        if (member == null)
                            continue;
                        else
                        {
                            symbolInfo = model.GetSymbolInfo(member.Expression);
                            symbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                            if (symbol == null)
                                continue;
                            else if (WebFormsControlProperties.Any(obj => obj == symbol.ToString() + "." + member.Name))
                            {
                                lstVulnerableCheck.Add(assignment.Right);
                            }
                        }
                    }
                    if (WebFormsControlProperties.Any(obj => obj == symbol.ToString()))
                        lstVulnerableCheck.Add(assignment.Right);
                }
            }
            return lstVulnerableCheck;
        }
        //private List<VulnerabilityDetail> FindStoredXSS(string filePath, ClassDeclarationSyntax classItem, SemanticModel model)
        //{
        //    List<VulnerableNode> lstVulnerableCheck = new List<VulnerableNode>();
        //    var classSymbol = model.GetDeclaredSymbol(classItem);
        //    //MVC Controllers and actions
        //    if (Utils.DerivesFromAny(classSymbol, ControllerClassNames))
        //    {
        //        var methodsWithParameters = classItem.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>()
        //            .Where(method => !method.ParameterList.Parameters.Count.Equals(0))
        //            .Where(method => method.Modifiers.ToString().Equals("public"))
        //            .Where(method => method.ReturnType.ToString().Equals("string"));
        //        foreach (MethodDeclarationSyntax method in methodsWithParameters)
        //        {
        //            bool verbExists = false;
        //            if (method.AttributeLists.Count() == 0)
        //                continue;
        //            foreach (var attributeList in method.AttributeLists)
        //            {
        //                foreach (var attribute in attributeList.Attributes)
        //                {
        //                    TypeInfo typeInfo = model.GetTypeInfo(attribute.Name);
        //                    if (typeInfo.Type == null)
        //                        continue;
        //                    if (HttpVerbAttributes.Any(obj => obj == typeInfo.Type.ToString()))
        //                    {
        //                        verbExists = true;
        //                        break;
        //                    }
        //                }
        //                if (verbExists)
        //                    break;
        //            }
        //            if (!verbExists)
        //                continue;
        //            if (method.Body.Statements.OfType<ReturnStatementSyntax>().Count() == 0)
        //                continue;
        //            var returnStatements = method.Body.Statements.OfType<ReturnStatementSyntax>();
        //            foreach (var item in returnStatements)
        //            {
        //                WriteLine(item.Expression);
        //                lstVulnerableCheck.Add(new VulnerableNode(item.Expression)); ;
        //            }
        //        }
        //    }
        //    //WebForms methods
        //    else
        //    {
        //        foreach (var invocation in classItem.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>())
        //        {
        //            SymbolInfo symbolInfo = model.GetSymbolInfo(invocation);
        //            IMethodSymbol symbol = (symbolInfo.Symbol == null ? symbolInfo.CandidateSymbols.FirstOrDefault() : symbolInfo.Symbol) as IMethodSymbol;
        //            // WriteLine(symbol);
        //            if (symbol == null)
        //                continue;
        //            if (WebFormsRepsonseMethods.Any(name => name == symbol.ReceiverType.ToString() + "." + symbol.Name.ToString()))
        //            {
        //                foreach (var argument in invocation.ArgumentList.Arguments)
        //                {
        //                    var argumentType = model.GetTypeInfo(argument.Expression);
        //                    if (argumentType.Type == null)
        //                        continue;
        //                    if (argumentType.Type.ToString() == "string" || argumentType.Type.ToString() == "System.String")
        //                        lstVulnerableCheck.Add(new VulnerableNode(argument.Expression));
        //                    else if (argumentType.Type.ToString() == "char[]" && argument.Expression is InvocationExpressionSyntax)
        //                    {
        //                        var currentExpression = (argument.Expression as InvocationExpressionSyntax).Expression as MemberAccessExpressionSyntax;
        //                        if (currentExpression != null && currentExpression.Name.ToString() == "ToCharArray")
        //                        {
        //                            TypeInfo typeInfo = model.GetTypeInfo(currentExpression);
        //                            if (typeInfo.Type == null)
        //                                continue;
        //                            if (typeInfo.Type.ToString() == "string" || typeInfo.Type.ToString() == "System.String")
        //                                lstVulnerableCheck.Add(new VulnerableNode(currentExpression.Expression));
        //                        }
        //                    }
        //                }
        //            }
        //        }
        //        foreach (var assignment in classItem.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>())
        //        {
        //            SymbolInfo symbolInfo = model.GetSymbolInfo(assignment.Left);
        //            ISymbol symbol = symbolInfo.Symbol == null ? symbolInfo.CandidateSymbols.FirstOrDefault() : symbolInfo.Symbol;
        //            if (symbol == null)
        //            {
        //                var member = assignment.Left as MemberAccessExpressionSyntax;
        //                if (member == null)
        //                    continue;
        //                else
        //                {
        //                    symbolInfo = model.GetSymbolInfo(member.Expression);
        //                    symbol = symbolInfo.Symbol == null ? symbolInfo.CandidateSymbols.FirstOrDefault() : symbolInfo.Symbol;
        //                    if (symbol == null)
        //                        continue;
        //                    else if (WebFormsControlProperties.Any(obj => obj == symbol.ToString() + "." + member.Name))
        //                    {
        //                        lstVulnerableCheck.Add(new VulnerableNode(assignment.Right));
        //                    }
        //                }
        //            }
        //            if (WebFormsControlProperties.Any(obj => obj == symbol.ToString()))
        //                lstVulnerableCheck.Add(new VulnerableNode(assignment.Right));
        //        }
        //    }
        //    //var lstVulnerableStatements = new List<SyntaxNode>();
        //    //var nodeFactory = new NodeFactory(solution);
        //    lstVulnerableCheck.ForEach(obj =>
        //        obj.IsVulnerable = IsVulnerable(obj.Node, model)
        //    );
        //    lstVulnerableCheck.RemoveAll(obj => !obj.IsVulnerable);
        //    return Map.ConvertToVulnerabilityList(filePath, lstVulnerableCheck.Select(obj => obj.Node).ToList(), SAST.Engine.CSharp.Enums.ScannerType.XSS,
        //        SAST.Engine.CSharp.Enums.ScannerSubType.StoredXSS);
        //}
        private void FindDOMXSS()
        { }
        /// <summary>
        /// Checking for Stored XSS
        /// </summary>
        /// <param name="syntaxNode">Expression to check </param>
        /// <param name="model">SemanticModel of document</param>
        /// <param name="callingSymbol"></param>
        /// <returns></returns>
        private bool IsVulnerable(SyntaxNode syntaxNode, SemanticModel model, ISymbol callingSymbol = null)
        {
            SymbolInfo symbolInfo;
            ISymbol symbol = null;
            bool isVulnerable = false;
            switch (syntaxNode.Kind())
            {
                case SyntaxKind.IdentifierName:
                    TypeInfo typeInfo = model.GetTypeInfo(syntaxNode);
                    if (typeInfo.Type == null)
                        return false;
                    if (typeInfo.Type.ToString() != "string" && typeInfo.Type.ToString() != "System.String"
                        && typeInfo.Type.ToString() != "System.Object" && typeInfo.Type.ToString() != "object")
                        return false;
                    symbolInfo = model.GetSymbolInfo(syntaxNode);
                    symbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                    if (symbol == null)
                        return false;
                    var references = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
                    foreach (var referencedSymbol in references)
                    {
                        isVulnerable = IsVulnerable(referencedSymbol.Definition.Locations.First().SourceTree.GetRoot().FindNode(referencedSymbol.Definition.Locations.First().SourceSpan), model);
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
                            //if (isVulnerable)
                            //    break;
                        }
                        //if (isVulnerable)
                        //    break;
                    }
                    return isVulnerable;
                case SyntaxKind.InvocationExpression:
                    isVulnerable = false;
                    symbolInfo = model.GetSymbolInfo(syntaxNode);
                    symbol = symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
                    if (symbol == null)
                        return false;
                    var invocation = syntaxNode as InvocationExpressionSyntax;
                    List<string> DataRetrievalMethods = new List<string> {
                        "System.Data.Common.DbDataReader.GetString",
                        "System.Data.SqlClient.SqlCommand.ExecuteScalar"
                        };
                    if (DataRetrievalMethods.Any(method => method == symbol.ContainingType.ToString() + "." + symbol.Name.ToString()))
                    {
                        return true;
                    }
                    if (symbol.ContainingType.ToString() + "." + symbol.Name.ToString() == "System.Convert.ToString")
                    {
                        return IsVulnerable(invocation.ArgumentList.Arguments.First().Expression, model);
                    }
                    else if (symbol.ContainingType.ToString() + "." + symbol.Name.ToString() == "object.ToString")
                    {
                        var member = invocation.Expression as MemberAccessExpressionSyntax;
                        return IsVulnerable(member.Expression, model);
                    }
                    if (NodeFactory.IsSanitized(syntaxNode as InvocationExpressionSyntax, model, SAST.Engine.CSharp.Enums.ScannerType.XSS))
                        return false;
                    foreach (var syntaxReference in symbol.DeclaringSyntaxReferences)
                    {
                        var methodDeclarationSyntax = syntaxReference.GetSyntax() as MethodDeclarationSyntax;
                        WriteLine(syntaxReference.SyntaxTree);
                        SemanticModel currentModel = null;
                        foreach (var project in solution.Projects)
                        {
                            if (project.GetCompilationAsync().Result.ContainsSyntaxTree(syntaxReference.SyntaxTree))
                                currentModel = project.GetCompilationAsync().Result.GetSemanticModel(syntaxReference.SyntaxTree);
                        }
                        if (currentModel == null || methodDeclarationSyntax == null || methodDeclarationSyntax.Body == null)
                            continue;
                        if (methodDeclarationSyntax.ExpressionBody != null)
                        {
                            isVulnerable = IsVulnerable(methodDeclarationSyntax.ExpressionBody.Expression, currentModel);
                            continue;
                        }
                        if (methodDeclarationSyntax.Body == null)
                            continue;
                        var returnStatements = methodDeclarationSyntax.Body.Statements.OfType<ReturnStatementSyntax>();
                        foreach (var returnStatement in returnStatements)
                        {
                            isVulnerable = IsVulnerable(returnStatement.Expression, currentModel);
                        }
                    }
                    return isVulnerable;
                case SyntaxKind.SimpleAssignmentExpression:
                    var assignmentExpression = syntaxNode as AssignmentExpressionSyntax;
                    return IsVulnerable(assignmentExpression.Right, model);
                case SyntaxKind.AddExpression:
                    var addExpression = syntaxNode as BinaryExpressionSyntax;
                    var left = IsVulnerable((addExpression as BinaryExpressionSyntax).Left, model, callingSymbol);
                    var right = IsVulnerable((addExpression as BinaryExpressionSyntax).Right, model, callingSymbol);
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
            return false;
        }
        private static string[] CommandExecuteMethods = {
            "System.Data.",
            };

        private bool IsDataBaseRetrievalMethod(SyntaxNode syntaxNode)
        {
            if (syntaxNode is InvocationExpressionSyntax)
            {
                return true;
            }
            return false;
        }
    }
}