using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis.CSharp;

namespace SAST.Engine.CSharp
{
    internal static class Utils
    {
        internal static readonly string[] AvailableExtensions = { ".txt", ".cs", ".cshtml", ".aspx", ".ascx", ".config", ".sln", ".csproj" };
        internal static readonly string[] SourceCodeFileExtensions = { ".cs", ".txt" };
        internal static readonly string[] ConfigurationFileExtensions = { ".config" };
        internal static readonly string[] MarkupFileExtensions = { ".cshtml", ".aspx", ".ascx", ".html" };
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
            {Enums.ScannerType.Ldap, "Ldap injection"},
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
            {Enums.ScannerType.WeakCipherMode, "Weak Cipher Mode"},
            {Enums.ScannerType.InsecureDeserialization, "Insecure Deserialization"},
            {Enums.ScannerType.CommandInjection, "Command Injection"},
            {Enums.ScannerType.FilePathInjection, "File Path Injection"},
            {Enums.ScannerType.CertificateValidation, "Certificate Validation Disabled"},
            {Enums.ScannerType.JWTValidation, "JWT Signature Validation Disabled"},
            {Enums.ScannerType.HTTPHeaderChecking, "HTTP Header Checking Disabled"},
            {Enums.ScannerType.EventValidation, "Event Validation Disabled"},
            {Enums.ScannerType.ViewStateMac, "View State Mac Disabled"},
            {Enums.ScannerType.PasswordLockout, "Password Lockout Disabled"},
        };
        internal static readonly Dictionary<Enums.ScannerType, Enums.Severity> ScannerTypeSeverity = new Dictionary<Enums.ScannerType, Enums.Severity>{
            {Enums.ScannerType.Csrf, Enums.Severity.Medium},
            {Enums.ScannerType.EmptyCatch, Enums.Severity.Information},
            {Enums.ScannerType.EmptyTry, Enums.Severity.Information},
            {Enums.ScannerType.HardcodePassword, Enums.Severity.High},
            //{Enums.ScannerType.InsecureCookie, Enums.Severity.Low},
            {Enums.ScannerType.InsecureRandom, Enums.Severity.Medium},
            {Enums.ScannerType.Ldap, Enums.Severity.High},
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
            {Enums.ScannerType.WeakCipherMode, Enums.Severity.High},
            {Enums.ScannerType.InsecureDeserialization, Enums.Severity.High},
            {Enums.ScannerType.CommandInjection, Enums.Severity.High},
            {Enums.ScannerType.FilePathInjection, Enums.Severity.High},
            {Enums.ScannerType.CertificateValidation, Enums.Severity.High},
            {Enums.ScannerType.JWTValidation, Enums.Severity.High},
            {Enums.ScannerType.HTTPHeaderChecking, Enums.Severity.Medium},
            {Enums.ScannerType.EventValidation, Enums.Severity.Medium},
            {Enums.ScannerType.ViewStateMac, Enums.Severity.Medium},
            {Enums.ScannerType.PasswordLockout, Enums.Severity.Medium},
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
        internal static void LoadMetadata(out List<MetadataReference> MetadataReferences)
        {
            MetadataReferences = new List<MetadataReference>();
            string directory = AppDomain.CurrentDomain.BaseDirectory;
            // Console.WriteLine(System.Reflection.Assembly.GetExecutingAssembly().Location);
            // Console.WriteLine();
            string[] assemblyPaths = Directory.GetFiles(Path.Combine(directory, "Resources"));
            foreach (var assemblyFile in assemblyPaths)
                if (File.Exists(assemblyFile))
                    MetadataReferences.Add(MetadataReference.CreateFromFile(assemblyFile));
        }

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
        internal static bool ImplementsFromAny(ITypeSymbol typeSymbol, string[] baseTypes)
        {
            if (baseTypes == null && baseTypes.Count() == 0)
                return false;
            if (typeSymbol.AllInterfaces.Any(interSymbol => baseTypes.Any(typeName => typeName == interSymbol.ToString())))
                return true;
            return false;
        }

        internal static bool CheckSameMethod(SyntaxNode first, SyntaxNode second)
        {
            MethodDeclarationSyntax firstBlock = first.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            MethodDeclarationSyntax secondBlock = second.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            return firstBlock.IsEquivalentTo(secondBlock);
        }

        public static bool IsVulnerable(SyntaxNode node, SemanticModel model, Solution solution = null, ISymbol callingSymbol = null, SyntaxNode parameterNode = null)
        {
            if (node is IdentifierNameSyntax)
            {
                ITypeSymbol type = model.GetTypeInfo(node).Type;
                if (type.ToString() != "string" && type.ToString() != "System.String")
                    return false;
                string str = "=";
                bool vulnerable = false;
                ISymbol symbol = model.GetSymbolInfo(node).Symbol;
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
            else if (node is ParameterSyntax)
                return true;
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
                            //bool sameObject = methodDeclaration.ParameterList.Parameters.First().Modifiers.Any(obj => obj.Kind() == SyntaxKind.OutKeyword || obj.Kind() == SyntaxKind.OutKeyword);
                            //Filtering abstract methods and no paramater methods & if Extension method, parameter checking starts from Index 1.
                            //int i = symbol.IsExtensionMethod ? 1 : 0;
                            //if ((methodDeclaration.Body != null || methodDeclaration.ExpressionBody != null) && invocation.ArgumentList.Arguments.Count > i)
                            //{
                            //    foreach (var item in invocation.ArgumentList.Arguments)
                            //    {
                            //        if (item.Expression.ToString() == parameterNode.ToString())
                            //        {
                            //            //Parameters are retrieving from Array or from NameColon.
                            //            if (item.NameColon == null)
                            //                arrayList.Add(methodDeclaration.ParameterList.Parameters[i]);
                            //            else
                            //                arrayList.Add(methodDeclaration.ParameterList.Parameters.First(obj => obj.Identifier.ToString() == item.NameColon.Name.ToString()));
                            //        }
                            //        i++;
                            //    }
                            //}
                            if (methodDeclaration.Body != null)
                            {
                                isVulnerable = false;
                                var returnStatements = methodDeclaration.Body.DescendantNodes().OfType<ReturnStatementSyntax>();
                                //Atleast one Return statements exists, then set isVulnerable to True other wise methid may contain Exceptions;
                                if (returnStatements.Count() > 0)
                                    isVulnerable = true;
                                foreach (var item in returnStatements)
                                {
                                    //item.Expression
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
            else
                return false;
        }
        public static List<ISymbol> VisitedSymbols = new List<ISymbol>();
    }
}