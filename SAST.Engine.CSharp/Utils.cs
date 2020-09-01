using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

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
            {Enums.ScannerSubType.StoredXSS, "Stored xss"},
            {Enums.ScannerSubType.ReflectedXSS, "Reflected xss"},
            {Enums.ScannerSubType.DomXSS, "Dom based xss"},
            {Enums.ScannerSubType.FAWeakCookie, "Weak Cookie"},
            {Enums.ScannerSubType.None, null}
        };
        internal static readonly Dictionary<Enums.ScannerType, string> ScannerDescriptions = new Dictionary<Enums.ScannerType, string>{
            {Enums.ScannerType.Csrf, "Cross site request forgery attack"},
            {Enums.ScannerType.EmptyCatch, "Empty catch block"},
            {Enums.ScannerType.EmptyTry, "Empty try block"},
            {Enums.ScannerType.HardcodePassword, "Hard coded credentials"},
            {Enums.ScannerType.InsecureCookie, "Cookie missing secure/httpOnly flag(s)"},
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
        };
        internal static readonly Dictionary<Enums.ScannerType, Enums.Severity> ScannerSeverity = new Dictionary<Enums.ScannerType, Enums.Severity>{
            {Enums.ScannerType.Csrf, Enums.Severity.Medium},
            {Enums.ScannerType.EmptyCatch, Enums.Severity.Information},
            {Enums.ScannerType.EmptyTry, Enums.Severity.Information},
            {Enums.ScannerType.HardcodePassword, Enums.Severity.High},
            {Enums.ScannerType.InsecureCookie, Enums.Severity.Low},
            {Enums.ScannerType.InsecureRandom, Enums.Severity.Medium},
            {Enums.ScannerType.Ldap, Enums.Severity.High},
            {Enums.ScannerType.OpenRedirect, Enums.Severity.Medium},
            {Enums.ScannerType.SqlInjection, Enums.Severity.Critical},
            {Enums.ScannerType.WeakHashingConfig, Enums.Severity.Medium},
            {Enums.ScannerType.WeakPasswordConfig, Enums.Severity.Low},
            {Enums.ScannerType.XPath, Enums.Severity.Medium},
            {Enums.ScannerType.XSS, Enums.Severity.Medium},
            {Enums.ScannerType.XXE, Enums.Severity.Medium},
            {Enums.ScannerType.FormsAuthentication, Enums.Severity.High},
            {Enums.ScannerType.MachineKeyClearText, Enums.Severity.High},
            {Enums.ScannerType.WeakSymmetricAlgorithm, Enums.Severity.High},
            {Enums.ScannerType.WeakCipherMode, Enums.Severity.High},
            {Enums.ScannerType.InsecureDeserialization, Enums.Severity.High},
            {Enums.ScannerType.FilePathInjection, Enums.Severity.High},
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

        internal static bool CheckSameMethod(SyntaxNode first, SyntaxNode second)
        {
            MethodDeclarationSyntax firstBlock = first.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            MethodDeclarationSyntax secondBlock = second.AncestorsAndSelf().OfType<MethodDeclarationSyntax>().FirstOrDefault();
            return firstBlock.IsEquivalentTo(secondBlock);
        }

        internal static ISymbol GetSymbol(SyntaxNode node, SemanticModel model)
        {
            SymbolInfo symbolInfo = model.GetSymbolInfo(node);
            return symbolInfo.Symbol ?? symbolInfo.CandidateSymbols.FirstOrDefault();
        }

        internal static ITypeSymbol GetTypeSymbol(SyntaxNode node, SemanticModel model)
        {
            TypeInfo typeInfo = model.GetTypeInfo(node);
            return typeInfo.Type;
        }

        public static bool IsVulnerable(SyntaxNode node, SemanticModel model, Solution solution = null, ISymbol callingSymbol = null)
        {
            if (node is IdentifierNameSyntax)
            {
                ITypeSymbol type = model.GetTypeInfo(node).Type;
                if (type.ToString() != "string" && type.ToString() != "System.String")
                    return false;

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
                        if (currentNode.SpanStart < node.SpanStart && Utils.CheckSameMethod(currentNode, node))
                        {
                            var assignment = currentNode.Ancestors().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                            if (assignment == null)
                                continue;
                            if (currentNode.SpanStart < assignment.Right.SpanStart)
                                vulnerable = IsVulnerable(assignment.Right, model, solution, symbol);
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
            else
                return false;
        }
    }

    public static class LinePositionExtension
    {
        public static string ToLineString(this LinePosition lineposition) => (lineposition.Line + 1) + "," + (lineposition.Character + 1);
    }
}