﻿using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis.CSharp;

namespace SAST.Engine.CSharp
{
    /// <summary>
    /// This class will implement Utilities.
    /// </summary>
    internal static class Utils
    {
        internal static readonly string[] AvailableExtensions = { ".cs", ".cshtml", ".html", ".aspx", ".ascx", ".config", ".sln", ".csproj" };
        internal static readonly string[] SourceCodeFileExtensions = { ".cs" };
        internal static readonly string[] ConfigurationFileExtensions = { ".config" };
        internal static readonly string[] MarkupFileExtensions = { ".cshtml", ".html", ".aspx", ".ascx" };
        internal static readonly string[] ProjectFileExtensions = { ".csproj" };
        internal static readonly Dictionary<Enums.ScannerSubType, string> ScannerSubTypeDescriptions = new Dictionary<Enums.ScannerSubType, string>{
            {Enums.ScannerSubType.StoredXSS, "Stored XSS"},
            {Enums.ScannerSubType.ReflectedXSS, "Reflected XSS"},
            {Enums.ScannerSubType.DomXSS, "Dom based XSS"},
            {Enums.ScannerSubType.FAWeakCookie, "Weak Cookie"},
            {Enums.ScannerSubType.FACookielessMode, "Cookieless Mode"},
            {Enums.ScannerSubType.FACrossAppRedirect, "Cross App Redirect"},
            {Enums.ScannerSubType.FAInsecureCookie, "Insecure Cookie"},
            {Enums.ScannerSubType.SecureFlag, "Secure flag"},
            {Enums.ScannerSubType.HttpOnlyFlag, "HttpOnly flag"},
            {Enums.ScannerSubType.None, string.Empty}
        };
        internal static readonly Dictionary<Enums.ScannerType, string> ScannerDescriptions = new Dictionary<Enums.ScannerType, string>{
            {Enums.ScannerType.Csrf, "Cross site request forgery attack"},
            {Enums.ScannerType.EmptyCatch, "Empty catch block"},
            {Enums.ScannerType.EmptyTry, "Empty try block"},
            {Enums.ScannerType.HardcodePassword, "Hard coded credentials"},
            {Enums.ScannerType.InsecureCookie, "Cookie missing flag(s)"},
            {Enums.ScannerType.InsecureRandom, "Weak random generation"},
            {Enums.ScannerType.LdapInjection, "Ldap injection"},
            {Enums.ScannerType.OpenRedirect, "Open redirect"},
            {Enums.ScannerType.SqlInjection, "Sql injection"},
            {Enums.ScannerType.WeakHashingConfig, "Weak hashing configuration"},
            {Enums.ScannerType.WeakPasswordConfig, "Weak password configuration"},
            {Enums.ScannerType.XPath, "Xpath injection"},
            {Enums.ScannerType.XSS, "Cross Site Scripting attack"},
            {Enums.ScannerType.XXE, "XML external entity injection"},
            {Enums.ScannerType.FormsAuthentication, "Forms Authentication"},
            {Enums.ScannerType.MachineKeyClearText, "Machine Key Cleartext"},
            {Enums.ScannerType.WeakSymmetricAlgorithm, "Weak Symmetric Algorithm"},
            {Enums.ScannerType.WeakCipherModePadding, "Weak Cipher Mode & Padding"},
            {Enums.ScannerType.InsecureDeserialization, "Insecure Deserialization"},
            {Enums.ScannerType.CommandInjection, "Command Injection"},
            {Enums.ScannerType.FilePathInjection, "File Path Injection"},
            {Enums.ScannerType.CertificateValidation, "Certificate Validation Disabled"},
            {Enums.ScannerType.JWTValidation, "JWT Signature Validation Disabled"},
            {Enums.ScannerType.HTTPHeaderChecking, "HTTP Header Checking Disabled"},
            {Enums.ScannerType.EventValidation, "Event Validation Disabled"},
            {Enums.ScannerType.ViewStateMac, "View State Mac Disabled"},
            {Enums.ScannerType.PasswordLockout, "Password Lockout Disabled"},
            {Enums.ScannerType.Authorize, "Authorize attribute missing"},
            {Enums.ScannerType.CorsAllowAnyOrigin, "Cors Allow Origin Wildcard"},
            {Enums.ScannerType.WeakCryptoKeyLength, "Cryptographic keys should be robust"},
            {Enums.ScannerType.SerializationType, "Insecure Deserialization type"},
            {Enums.ScannerType.LdapSecureConnection, "Ldap Authentication should be Secure"},
        };
        internal static readonly Dictionary<Enums.ScannerType, Enums.Severity> ScannerTypeSeverity = new Dictionary<Enums.ScannerType, Enums.Severity>{
            {Enums.ScannerType.Csrf, Enums.Severity.Medium},
            {Enums.ScannerType.EmptyCatch, Enums.Severity.Information},
            {Enums.ScannerType.EmptyTry, Enums.Severity.Information},
            {Enums.ScannerType.HardcodePassword, Enums.Severity.High},
            //{Enums.ScannerType.InsecureCookie, Enums.Severity.Low},
            {Enums.ScannerType.InsecureRandom, Enums.Severity.Medium},
            {Enums.ScannerType.LdapInjection, Enums.Severity.High},
            {Enums.ScannerType.OpenRedirect, Enums.Severity.Medium},
            {Enums.ScannerType.SqlInjection, Enums.Severity.Critical},
            {Enums.ScannerType.WeakHashingConfig, Enums.Severity.Medium},
            {Enums.ScannerType.WeakPasswordConfig, Enums.Severity.Low},
            {Enums.ScannerType.XPath, Enums.Severity.Medium},
            //{Enums.ScannerType.XSS, Enums.Severity.Medium},
            {Enums.ScannerType.XXE, Enums.Severity.Medium},
            //{Enums.ScannerType.FormsAuthentication, Enums.Severity.High},
            {Enums.ScannerType.MachineKeyClearText, Enums.Severity.High},
            {Enums.ScannerType.WeakSymmetricAlgorithm, Enums.Severity.High},
            {Enums.ScannerType.WeakCipherModePadding, Enums.Severity.High},
            {Enums.ScannerType.InsecureDeserialization, Enums.Severity.High},
            {Enums.ScannerType.CommandInjection, Enums.Severity.High},
            {Enums.ScannerType.FilePathInjection, Enums.Severity.High},
            {Enums.ScannerType.CertificateValidation, Enums.Severity.High},
            {Enums.ScannerType.JWTValidation, Enums.Severity.High},
            {Enums.ScannerType.HTTPHeaderChecking, Enums.Severity.Medium},
            {Enums.ScannerType.EventValidation, Enums.Severity.Medium},
            {Enums.ScannerType.ViewStateMac, Enums.Severity.Medium},
            {Enums.ScannerType.PasswordLockout, Enums.Severity.Medium},
            {Enums.ScannerType.Authorize, Enums.Severity.Medium},
            {Enums.ScannerType.CorsAllowAnyOrigin, Enums.Severity.Medium},
            {Enums.ScannerType.WeakCryptoKeyLength, Enums.Severity.Medium},
            {Enums.ScannerType.SerializationType, Enums.Severity.High},
            {Enums.ScannerType.LdapSecureConnection, Enums.Severity.High},
        };
        internal static readonly Dictionary<Enums.ScannerSubType, Enums.Severity> ScannerSubTypeSeverity = new Dictionary<Enums.ScannerSubType, Enums.Severity>{
            //XSS
            {Enums.ScannerSubType.DomXSS, Enums.Severity.Medium},
            {Enums.ScannerSubType.ReflectedXSS, Enums.Severity.Medium},
            {Enums.ScannerSubType.StoredXSS, Enums.Severity.Medium},
            //Forms Authentication
            {Enums.ScannerSubType.FAWeakCookie, Enums.Severity.High},
            {Enums.ScannerSubType.FACookielessMode, Enums.Severity.Medium},
            {Enums.ScannerSubType.FACrossAppRedirect, Enums.Severity.Medium},
            {Enums.ScannerSubType.FAInsecureCookie, Enums.Severity.Medium},
            //Cookie Flag
            {Enums.ScannerSubType.HttpOnlyFlag, Enums.Severity.Low},
            {Enums.ScannerSubType.SecureFlag, Enums.Severity.Low}
        };

        /// <summary>
        /// This method will give the List of MetaDataReferences using Physical Assenmbly to MetaDatReference Object
        /// </summary>
        /// <param name="MetadataReferences"></param>
        internal static void LoadMetadata(out List<MetadataReference> MetadataReferences)
        {
            MetadataReferences = new List<MetadataReference>();
            string directory = AppDomain.CurrentDomain.BaseDirectory;
            string[] assemblyPaths = Directory.GetFiles(Path.Combine(directory, "Resources"));
            foreach (var assemblyFile in assemblyPaths)
                if (File.Exists(assemblyFile))
                {
                    try
                    {
                        MetadataReferences.Add(MetadataReference.CreateFromFile(assemblyFile));
                    }
                    catch
                    { }
                }
        }

        /// <summary>
        /// This method will check <paramref name="typeSymbol"/> is derived from any of <paramref name="baseTypes"/>
        /// </summary>
        /// <param name="typeSymbol"></param>
        /// <param name="baseTypes"></param>
        /// <returns></returns>
        internal static bool DerivesFromAny(ITypeSymbol typeSymbol, string[] baseTypes)
        {
            if (baseTypes == null && baseTypes.Count() == 0)
                return false;
            while (typeSymbol != null)
            {
                if (baseTypes.Contains(typeSymbol.ToString()))
                    return true;
                typeSymbol = typeSymbol.BaseType?.ConstructedFrom;
            }
            return false;
        }

        /// <summary>
        /// This method will check <paramref name="typeSymbol"/> is derived from <paramref name="baseType"/>
        /// </summary>
        /// <param name="typeSymbol"></param>
        /// <param name="baseType"></param>
        /// <returns></returns>
        internal static bool DerivesFrom(ITypeSymbol typeSymbol, string baseType)
        {
            if (string.IsNullOrWhiteSpace(baseType))
                return false;
            while (typeSymbol != null)
            {
                if (baseType.Equals(typeSymbol.ToString()))
                    return true;
                typeSymbol = typeSymbol.BaseType?.ConstructedFrom;
            }
            return false;
        }

        /// <summary>
        /// This method will check <paramref name="typeSymbol"/> is implemented from any of <paramref name="baseTypes"/>
        /// </summary>
        /// <param name="typeSymbol"></param>
        /// <param name="baseTypes"></param>
        /// <returns></returns>
        internal static bool ImplementsFromAny(ITypeSymbol typeSymbol, string[] baseTypes)
        {
            if (baseTypes == null && baseTypes.Count() == 0)
                return false;
            if (typeSymbol.AllInterfaces.Any(interSymbol => baseTypes.Any(typeName => typeName == interSymbol.ToString())))
                return true;
            return false;
        }

        /// <summary>
        /// This method will check <paramref name="typeSymbol"/> is implemented from <paramref name="baseType"/>
        /// </summary>
        /// <param name="typeSymbol"></param>
        /// <param name="baseType"></param>
        /// <returns></returns>
        internal static bool ImplementsFrom(ITypeSymbol typeSymbol, string baseType)
        {
            if (string.IsNullOrWhiteSpace(baseType))
                return false;
            if (typeSymbol.AllInterfaces.Any(obj => obj.ToString() == baseType))
                return true;
            return false;
        }

        /// <summary>
        /// This method will return true, If both SyntaxNodes in same Method. 
        /// </summary>
        /// <param name="first"></param>
        /// <param name="second"></param>
        /// <returns></returns>
        internal static bool CheckSameMethod(SyntaxNode first, SyntaxNode second)
        {
            var firstMethod = first.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            var secondMethod = second.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            if (firstMethod != null && secondMethod != null)
                return firstMethod.Equals(secondMethod);

            var firstConstructor = first.AncestorsAndSelf().OfType<ConstructorDeclarationSyntax>().FirstOrDefault();
            var secondConstructor = second.AncestorsAndSelf().OfType<ConstructorDeclarationSyntax>().FirstOrDefault();
            if (firstConstructor != null && secondConstructor != null)
                return firstConstructor.Equals(secondConstructor);

            var firstProp = first.AncestorsAndSelf().OfType<PropertyDeclarationSyntax>().FirstOrDefault();
            var secondProp = second.AncestorsAndSelf().OfType<PropertyDeclarationSyntax>().FirstOrDefault();
            if (firstProp != null && secondProp != null)
                return firstProp.Equals(secondProp);
            return false;
        }

        /// <summary>
        /// This method wiil check whether the SyntaxNode is vulnerable or not
        /// </summary>
        /// <param name="node"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <param name="callingSymbol"></param>
        /// <param name="parameterNode"></param>
        /// <returns></returns>
        public static bool IsVulnerable(SyntaxNode node, SemanticModel model, Solution solution = null, ISymbol callingSymbol = null, SyntaxNode parameterNode = null)
        {
            if (node is IdentifierNameSyntax)
            {
                ITypeSymbol type = model.GetTypeInfo(node).Type;
                if (type == null || type.SpecialType != SpecialType.System_String)
                    return false;
                bool vulnerable = false;
                ISymbol symbol = model.GetSymbol(node);
                if (symbol == null || symbol.Equals(callingSymbol, SymbolEqualityComparer.Default))
                    return false;
                var references = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
                foreach (var reference in references)
                {
                    var currentNode = reference.Definition.Locations.First().SourceTree.GetRoot().FindNode(reference.Definition.Locations.First().SourceSpan);
                    vulnerable = IsVulnerable(currentNode, model, solution, callingSymbol);
                    foreach (var refLocation in reference.Locations)
                    {
                        currentNode = reference.Definition.Locations.First().SourceTree.GetRoot().FindNode(refLocation.Location.SourceSpan);
                        if (currentNode.SpanStart < node.SpanStart && CheckSameMethod(currentNode, node))
                        {
                            var assignment = currentNode.Ancestors().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                            if (assignment == null)
                                continue;
                            if (currentNode.SpanStart < assignment.Right.SpanStart)
                                vulnerable = IsVulnerable(assignment.Right, refLocation.Document.GetSemanticModelAsync().Result, solution, symbol, node);
                        }
                    }
                }
                return vulnerable;
            }
            else if (node is BinaryExpressionSyntax)
            {
                var left = IsVulnerable((node as BinaryExpressionSyntax).Left, model, solution, callingSymbol);
                var right = IsVulnerable((node as BinaryExpressionSyntax).Right, model, solution, callingSymbol);
                return left || right;
            }
            else if (node is VariableDeclaratorSyntax variableDeclarator && variableDeclarator.Initializer != null)
                return IsVulnerable(variableDeclarator.Initializer.Value, model, solution, callingSymbol);
            else if (node is AssignmentExpressionSyntax)
                return IsVulnerable((node as AssignmentExpressionSyntax).Right, model, solution, callingSymbol);
            else if (node is InterpolatedStringExpressionSyntax)
            {
                bool vulnerable = false;
                var contents = (node as InterpolatedStringExpressionSyntax).Contents.OfType<InterpolationSyntax>();
                foreach (var item in contents)
                {
                    vulnerable = vulnerable || IsVulnerable(item.Expression, model, solution, callingSymbol);
                    if (vulnerable)
                        break;
                }
                return vulnerable;
            }
            else if (node is InvocationExpressionSyntax invocation)
            {
                IMethodSymbol symbol = model.GetSymbol(invocation.Expression) as IMethodSymbol;
                if (symbol == null)
                    return true;
                bool isVulnerable = false;
                if (symbol.Locations.Count() > 0)
                {
                    foreach (var location in symbol.Locations)
                    {
                        if (location.IsInSource)
                        {
                            SemanticModel invocationModel = model.Compilation.GetSemanticModel(location.SourceTree);
                            MethodDeclarationSyntax methodDeclaration = location.SourceTree.GetRoot().FindNode(location.SourceSpan) as MethodDeclarationSyntax;
                            if (methodDeclaration.Body != null)
                            {
                                isVulnerable = false;
                                var returnStatements = methodDeclaration.Body.DescendantNodes().OfType<ReturnStatementSyntax>();
                                //Atleast one Return statements exists, then set isVulnerable to True, other wise method may contain Exceptions;
                                if (returnStatements.Count() > 0)
                                    isVulnerable = true;
                                foreach (var item in returnStatements)
                                {
                                    if (!IsVulnerable(item.Expression, invocationModel, solution, null, null))
                                    {
                                        //If any statement is not vulnerable, then treat the method as Safe & break the loop.
                                        isVulnerable = false;
                                        break;
                                    }
                                }
                            }
                            else if (methodDeclaration.ExpressionBody != null)
                                if (!IsVulnerable(methodDeclaration.ExpressionBody.Expression, invocationModel, solution, null, null))
                                {
                                    //If any statement is not vulnerable, then treat the method as Safe & break the loop.
                                    isVulnerable = false;
                                    break;
                                }
                        }
                    }
                }
                return isVulnerable;
            }
            else if (node is ParameterSyntax)
                return true;
            else
                return false;
        }
        //static C2<int> c2 = new C2<int>();
    }
    //class C1<T>
    //{
    //}
    //class C2<T> : C1<C2<C2<T>>> // Noncompliant
    //{
    //}
}