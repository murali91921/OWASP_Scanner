using SAST.Engine.CSharp.Enums;
using System;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using SAST.Engine.CSharp.Constants;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;

namespace SAST.Engine.CSharp.Scanners
{
    internal class WeakPasswordValidator : IScanner
    {
        private static int MINIMUM_PASSWORD_LENGTH = 8;

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
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            //Filter all property declarations
            var properties = syntaxNode.DescendantNodes().OfType<PropertyDeclarationSyntax>();
            foreach (var item in properties)
            {
                bool IsPassword = false;
                bool IsWeak = true;
                foreach (var attributeList in item.AttributeLists)
                {
                    foreach (var attribute in attributeList.Attributes)
                    {
                        ITypeSymbol type = model.GetTypeSymbol(attribute);
                        if (type != null && type.ToString() == KnownType.System_ComponentModel_DataAnnotations_DataType
                                && attribute.ArgumentList != null && attribute.ArgumentList.Arguments.First().ToString() == "DataType.Password")
                            IsPassword = true;
                        if (type != null && type.ToString() == KnownType.System_ComponentModel_DataAnnotations_StringLengthAttribute)
                        {
                            // Console.WriteLine("Min Length");
                            if (attribute.ArgumentList != null && attribute.ArgumentList.Arguments.Any(obj => obj.ToString().Contains("MinimumLength")))
                            {
                                var minimumLengthAttrib = attribute.ArgumentList.Arguments.First(obj => obj.ToString().Contains("MinimumLength"));
                                if ((minimumLengthAttrib.NameColon != null && minimumLengthAttrib.NameColon.Name.ToString() == "MinimumLength")
                                || (minimumLengthAttrib.NameEquals != null && minimumLengthAttrib.NameEquals.Name.ToString() == "MinimumLength"))
                                {
                                    if (minimumLengthAttrib.Expression is LiteralExpressionSyntax)
                                        IsWeak = int.Parse(minimumLengthAttrib.Expression.ToString()) < MINIMUM_PASSWORD_LENGTH;
                                }
                            }
                        }
                    }
                }
                if (IsPassword && IsWeak)
                    lstVulnerableStatements.Add(item);
            }
            if (lstVulnerableStatements.Count == 0)
            {
                // Finding the statements of Configure method calling with Lambda Expression
                var coreLengthStatements = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>().Where(obj =>
                                                    obj.ToString().Contains("Configure")).ToList();
                if (coreLengthStatements.Count > 0)
                {
                    SyntaxNode tempIdentity = null;
                    //bool PasswordoptionsExists = false;
                    //bool IsPassword = false;
                    bool IsWeak = true;
                    foreach (var item in coreLengthStatements)
                    {
                        //IsPassword = false;
                        IsWeak = true;
                        //tempIdentity = null;
                        var typeSymbol = model.GetTypeSymbol(item);
                        if (typeSymbol != null && typeSymbol.ToString() == KnownType.Microsoft_Extensions_DependencyInjection_IServiceCollection)
                        {
                            //Console.WriteLine("Type");
                            // var passwordOptions = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Identity.IdentityOptions");
                            // var references = SymbolFinder.FindReferencesAsync(passwordOptions,project.Solution).Result;
                            var typeArguments = item.DescendantNodes().OfType<TypeArgumentListSyntax>();
                            string typeOfOptions = string.Empty;
                            if (typeArguments.Count() > 0)
                            {
                                var typeOfOptionsTypeInfo = model.GetTypeSymbol(typeArguments.First().Arguments.First());
                                if (typeOfOptionsTypeInfo != null)
                                    typeOfOptions = model.GetTypeSymbol(typeArguments.First().Arguments.First()).ToString();
                            }
                            if (typeOfOptions == KnownType.Microsoft_AspNetCore_Identity_IdentityOptions)
                            {
                                var assignments = item.DescendantNodes().OfType<AssignmentExpressionSyntax>().Where(obj =>
                                                                obj.Right is LiteralExpressionSyntax && obj.Left.ToString().Contains("Password.RequiredLength"));
                                if (assignments.Count() > 0)
                                {
                                    int requestedLength = int.Parse(assignments.First().Right.ToString());
                                    if (requestedLength >= MINIMUM_PASSWORD_LENGTH)
                                        IsWeak = false;
                                }
                                else
                                    IsWeak = true;
                                if (IsWeak && tempIdentity == null)
                                    tempIdentity = item;
                            }
                            else if (typeOfOptions == KnownType.Microsoft_AspNetCore_Identity_PasswordOptions)
                            {
                                var assignments = item.DescendantNodes().OfType<AssignmentExpressionSyntax>().Where(obj =>
                                                                obj.Right is LiteralExpressionSyntax && obj.Left.ToString().Contains("RequiredLength"));
                                if (assignments.Count() > 0)
                                {
                                    int requestedLength = int.Parse(assignments.First().Right.ToString());
                                    if (requestedLength >= MINIMUM_PASSWORD_LENGTH)
                                        IsWeak = false;
                                }
                                else
                                    IsWeak = true;
                                tempIdentity = IsWeak ? item : null;
                                break;
                            }
                            else
                                continue;
                            // if(IsPassword && IsWeak)
                            // {
                            //     lstVulnerableStatements.Add(tempIdentity==null ? item : tempIdentity);
                            //     break;
                            // }
                        }
                        // Console.WriteLine(item);
                    }
                    if (tempIdentity != null)
                    {
                        lstVulnerableStatements.Add(tempIdentity);
                    }
                }
            }
            if (lstVulnerableStatements.Count == 0)
            {
                var declarationSyntaxes = syntaxNode.DescendantNodes().OfType<VariableDeclaratorSyntax>();
                // var passwordValidator = compilation.GetTypeByMetadataName("Microsoft.AspNet.Identity.PasswordValidator");
                // var referencedSymbols_1 = SymbolFinder.FindReferencesAsync(passwordValidator,project.Solution).Result;

                foreach (var declarationSyntax in declarationSyntaxes)
                {
                    bool IsWeak = true;
                    IEnumerable<ReferencedSymbol> referencedSymbols = null;
                    var symbol = model.GetDeclaredSymbol(declarationSyntax);
                    if (symbol == null)
                        continue;

                    ITypeSymbol typeSymbol = symbol.GetTypeSymbol();
                    if (typeSymbol == null || typeSymbol.ToString() != KnownType.Microsoft_AspNet_Identity_PasswordValidator)
                        continue;

                    referencedSymbols = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
                    var objectCreation = declarationSyntax.DescendantNodes().OfType<ObjectCreationExpressionSyntax>().FirstOrDefault();
                    if (objectCreation != null && objectCreation.Initializer != null)
                    {
                        foreach (var expression in objectCreation.Initializer.Expressions)
                        {
                            var assignment = expression as AssignmentExpressionSyntax;
                            if (assignment.Left.ToString() == "RequiredLength" && assignment.Right is LiteralExpressionSyntax)
                            {
                                if (int.Parse(assignment.Right.ToString()) > MINIMUM_PASSWORD_LENGTH)
                                    IsWeak = false;
                            }
                        }
                        // declarationSyntax.Initializer is ObjectCreationExpressionSyntax
                    }
                    if (referencedSymbols != null && referencedSymbols.Count() > 0)
                    {
                        foreach (var refSymbol in referencedSymbols)
                        {
                            foreach (var refLocation in refSymbol.Locations)
                            {
                                var refNode = syntaxNode.FindNode(refLocation.Location.SourceSpan);
                                var assignment = refNode.Ancestors().OfType<AssignmentExpressionSyntax>().First();
                                {
                                    if ((assignment.Left as MemberAccessExpressionSyntax).Name.ToString() == "RequiredLength" && assignment.Right is LiteralExpressionSyntax)
                                    {
                                        if (int.Parse(assignment.Right.ToString()) > MINIMUM_PASSWORD_LENGTH)
                                            IsWeak = false;
                                        if (IsWeak)
                                        {
                                            lstVulnerableStatements.Add(assignment);
                                            IsWeak = false;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (IsWeak)
                    {
                        lstVulnerableStatements.Add(declarationSyntax);
                    }
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, ScannerType.WeakPasswordConfig);
        }
    }
}