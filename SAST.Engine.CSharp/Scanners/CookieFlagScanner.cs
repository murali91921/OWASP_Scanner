using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Parser;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using System.Xml.XPath;

namespace SAST.Engine.CSharp.Scanners
{
    /*
     * Scenarios
     * Variable declaration with Object creation -> no initializer
     * Variable declaration with Object creation, initializer
     * Variable declaration with another variable
     * Variable declaration with another method calling(may be same assembly, diff assembly)
     * Variable assigned with object creation -> no initilizer(means data changes)
     * Variable assigned with Object creation, initializer
     * Variable assigned with another variable
     * Variable assigned with another method calling(may be available in source code, or assembly)
     * Parameter is passing to method by Object Creation -> no initializer
     * Parameter is passing to method by Object Creation, initializer
     */

    /// <summary>
    /// This Scanner to find Cookie Flag Vulnerabilities 
    /// </summary>
    internal class CookieFlagScanner : IScanner, IConfigScanner
    {
        const string HttpCookies_Node = "configuration/system.web/httpCookies";
        private ScannerType scannerType;
        private readonly static string[] Cookie_Classes = {
            Constants.KnownType.System_Web_HttpCookie,
            Constants.KnownType.System_Net_Http_Headers_CookieHeaderValue,
            Constants.KnownType.Microsoft_AspNetCore_Http_CookieOptions,
            Constants.KnownType.Microsoft_Net_Http_Headers_SetCookieHeaderValue
        };

        public CookieFlagScanner(ScannerType paramScannerType) => scannerType = paramScannerType;

        #region IConfigScanner

        /// <summary>
        /// This method will find the Cookie Flag Vulnerabilities
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath)
        {
            bool enabled = false;
            //string returnStatement = string.Empty;
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            try
            {
                XPathNavigator element = XMLParser.CreateNavigator(filePath, HttpCookies_Node);
                if (element != null)
                {
                    if (element.HasAttributes)
                    {
                        string elementName = scannerType == ScannerType.MissingHttpOnlyCookie ? "httpOnlyCookies" : "requireSSL";
                        element.MoveToFirstAttribute();
                        do
                        {
                            if (element.Name.Equals(elementName, StringComparison.InvariantCultureIgnoreCase))
                            {
                                enabled = bool.Parse(element.Value);
                                break;
                            }
                        }
                        while (element.MoveToNextAttribute());
                        element.MoveToParent();
                    }
                    if (!enabled)
                        vulnerabilities = new List<VulnerabilityDetail>() { VulnerabilityDetail.Create(filePath, element, scannerType) };
                }
            }
            catch
            {

            }
            return vulnerabilities;
        }

        #endregion

        #region IScanner

        /// <summary>
        /// This method will find the Cookie Flag vulnerabilities
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model, Solution solution = null)
        {
            List<SyntaxNode> vulnerabilities = new List<SyntaxNode>();
            var methodDeclarations = syntaxNode.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>();
            foreach (var method in methodDeclarations)
            {
                if (!filePath.EndsWith("ForgotPassword.aspx.cs"))
                    continue;
                //Set the propertyName based on scannerSubType parameter, this value will be usedful for Property check.
                string propertyName = scannerType == ScannerType.MissingHttpOnlyCookie ? "HttpOnly" : "Secure";

                // Checking Variable Declarations
                var variableDeclarations = method.DescendantNodesAndSelf().OfType<VariableDeclarationSyntax>();
                foreach (var item in variableDeclarations)
                {
                    ITypeSymbol typeSymbol = model.GetTypeSymbol(item.Type);
                    if (typeSymbol == null || !Cookie_Classes.Contains(typeSymbol.ToString()))
                        continue;
                    //Considering the Cookie Type variables only.
                    foreach (var variableDeclarator in item.Variables)
                    {
                        ISymbol symbol = model.GetDeclaredSymbol(variableDeclarator);

                        SyntaxNode vulnerableNode = variableDeclarator;

                        bool propertyChange = false, isVulnerable = true;
                        if (variableDeclarator.Initializer != null && variableDeclarator.Initializer.Value.RemoveParenthesis() is ObjectCreationExpressionSyntax objectCreation)
                        {
                            if (objectCreation.Initializer != null && objectCreation.Initializer.Expressions.Count > 0)
                                foreach (var initializerExpression in objectCreation.Initializer?.Expressions)
                                {
                                    var assignmentExpression = initializerExpression as AssignmentExpressionSyntax;
                                    if (assignmentExpression.Left.ToString() != propertyName)
                                        continue;
                                    propertyChange = true;
                                    var rightConstant = model.GetConstantValue(assignmentExpression.Right.RemoveParenthesis());
                                    // If constant value is true then consider as safe,
                                    if (rightConstant.HasValue && rightConstant.Value is bool value && value)
                                        isVulnerable = false;
                                    // If constant value is false or no constant value, consider as not safe.
                                    else
                                        vulnerabilities.Add(assignmentExpression);
                                    //vulnerabilities.Add(VulnerabilityDetail.Create(filePath, assignmentExpression, scannerType));
                                }
                        }
                        var referencedSymbols = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
                        foreach (var referencedSymbol in referencedSymbols)
                        {
                            foreach (var referenceLocation in referencedSymbol.Locations)
                            {
                                if (!referenceLocation.Location.IsInSource)
                                    continue;
                                var assignNode = referenceLocation.Location.SourceTree.GetRoot().FindNode(referenceLocation.Location.SourceSpan);
                                var assignmentExpression = assignNode.AncestorsAndSelf().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                                if (assignmentExpression == null)
                                    continue;

                                ISymbol propertySymbol = model.GetSymbol(assignmentExpression.Left);
                                ITypeSymbol propertyTypeSymbol = model.GetTypeSymbol(assignmentExpression.Left);
                                if (assignNode.SpanStart > assignmentExpression.Right.SpanStart)
                                    continue;

                                #region Property Assign Check

                                if (propertyTypeSymbol.SpecialType == SpecialType.System_Boolean
                                    && Cookie_Classes.Any(obj => obj + "." + propertyName == propertySymbol.ToString()))
                                {
                                    propertyChange = true;
                                    var rightConstant = model.GetConstantValue(assignmentExpression.Right.RemoveParenthesis());
                                    // If constant value is true then consider as safe
                                    if (rightConstant.HasValue && rightConstant.Value is bool value && value)
                                        isVulnerable = false;
                                    // If constant value is false or Othe expression then consider as unsafe
                                    else
                                    {
                                        vulnerabilities.Add(assignmentExpression);
                                        //vulnerabilities.Add(VulnerabilityDetail.Create(filePath, assignmentExpression, scannerType));
                                        isVulnerable = true;
                                    }
                                }

                                #endregion

                                #region Object Assign Check

                                if (Cookie_Classes.Contains(propertyTypeSymbol.ToString())
                                    && assignmentExpression.Right is ObjectCreationExpressionSyntax objectCreationExpression)
                                {
                                    if (isVulnerable && !propertyChange)
                                        vulnerabilities.Add(vulnerableNode);
                                    //vulnerabilities.Add(VulnerabilityDetail.Create(filePath, vulnerableNode, scannerType));
                                    isVulnerable = true;
                                    propertyChange = false;
                                    vulnerableNode = objectCreationExpression;
                                    if (objectCreationExpression.Initializer != null && objectCreationExpression.Initializer.Expressions.Count > 0)
                                    {
                                        foreach (var initializerExpression in objectCreationExpression.Initializer?.Expressions)
                                        {
                                            //Console.WriteLine(initializerExpression);
                                            var propertyAssignmentExpression = initializerExpression as AssignmentExpressionSyntax;
                                            if (propertyAssignmentExpression.Left.ToString() != propertyName)
                                                continue;
                                            propertyChange = false;
                                            var rightConstant = model.GetConstantValue(propertyAssignmentExpression.Right.RemoveParenthesis());
                                            // If constant value is true then consider as safe,
                                            if (rightConstant.HasValue && rightConstant.Value is bool value && value)
                                                isVulnerable = false;
                                            // If constant value is false or no constant value, consider as not safe.
                                            else
                                            {
                                                propertyChange = true;
                                                vulnerabilities.Add(propertyAssignmentExpression);
                                                //vulnerabilities.Add(VulnerabilityDetail.Create(filePath, propertyAssignmentExpression, scannerType));
                                            }
                                        }
                                    }
                                }
                                #endregion
                            }
                            if (isVulnerable && !propertyChange && vulnerableNode != null)
                                vulnerabilities.Add(vulnerableNode);
                            //vulnerabilities.Add(VulnerabilityDetail.Create(filePath, vulnerableNode, scannerType));
                        }
                    }
                }

                // Invocations
                var invocations = method.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
                foreach (var item in invocations)
                {
                    foreach (var argument in item.ArgumentList.Arguments)
                    {
                        ITypeSymbol typeSymbol = model.GetTypeSymbol(argument.Expression);
                        if (typeSymbol == null || !Cookie_Classes.Contains(typeSymbol.ToString()))
                            continue;
                        if (argument.Expression.RemoveParenthesis() is ObjectCreationExpressionSyntax objectCreation)
                        {
                            SyntaxNode vulnerableNode = argument.Expression.RemoveParenthesis();
                            bool vulnerable = true;
                            if (objectCreation.Initializer != null && objectCreation.Initializer.Expressions.Count > 0)
                                foreach (var initializerExpression in objectCreation.Initializer?.Expressions)
                                {
                                    //Console.WriteLine(initializerExpression);
                                    var assignmentExpression = initializerExpression as AssignmentExpressionSyntax;
                                    if (assignmentExpression.Left.ToString() != propertyName)
                                        continue;
                                    var rightConstant = model.GetConstantValue(assignmentExpression.Right.RemoveParenthesis());
                                    // If constant value is false or no constant value, consider as not safe.
                                    if (rightConstant.HasValue && rightConstant.Value is bool value && value)
                                        vulnerable = false;
                                    else
                                        vulnerableNode = assignmentExpression;
                                }
                            if (vulnerable)
                                vulnerabilities.Add(vulnerableNode);
                            //vulnerabilities.Add(VulnerabilityDetail.Create(filePath, vulnerableNode, scannerType));
                        }
                    }
                }

                //Checking property assignments other than Cookie variable property assignments.
                //Ex: Response.Cookies[0].Secure = false;
                var assignmentExpressions = method.DescendantNodesAndSelf().OfType<AssignmentExpressionSyntax>();
                foreach (var item in assignmentExpressions)
                {
                    if (item.Parent.Kind() == SyntaxKind.ObjectInitializerExpression)
                        continue;
                    ISymbol symbol = model.GetSymbol(item.Left);
                    if (symbol == null || !Cookie_Classes.Any(obj => obj + "." + propertyName == symbol.ToString()))
                        continue;
                    {
                        var rightConstant = model.GetConstantValue(item.Right.RemoveParenthesis());
                        // If constant value is false or no constant value, consider as not safe.
                        if (rightConstant.HasValue && rightConstant.Value is bool value && !value)
                        {
                            if (!vulnerabilities.Contains(item))
                                vulnerabilities.Add(item);
                        }
                    }
                }
            }
            return vulnerabilities.Any() ? vulnerabilities.Select(obj => VulnerabilityDetail.Create(filePath, obj, scannerType)) : Enumerable.Empty<VulnerabilityDetail>();
        }
        #endregion
    }
}