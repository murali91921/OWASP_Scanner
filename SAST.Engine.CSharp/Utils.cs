using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

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
            {Enums.ScannerType.XSS, "Croos site scripting attack"},
            {Enums.ScannerType.XXE, "XML external entity injection"},
            {Enums.ScannerType.FormsAuthentication, "Forms Authentication"},
            {Enums.ScannerType.MachineKeyClearText, "Machine Key Cleartext"},
            {Enums.ScannerType.WeakSymmetricAlgorithm, "Weak Symmetric Algorithm"}
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
            {Enums.ScannerType.WeakSymmetricAlgorithm, Enums.Severity.High}
        };
        public static void LoadMetadata(out List<MetadataReference> MetadataReferences)
        {
            MetadataReferences = new List<MetadataReference>();
            string directory = Path.GetDirectoryName(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName);
            //Console.WriteLine(directory);
            string[] assemblyPaths = Directory.GetFiles(Path.Combine(directory, "Resources"));
            foreach (var assemblyFile in assemblyPaths)
                if (File.Exists(assemblyFile))
                    MetadataReferences.Add(MetadataReference.CreateFromFile(assemblyFile));
        }
        public static bool DerivesFromAny(ITypeSymbol typeSymbol, string[] baseTypes)
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
    }

    public static class LinePositionExtension
    {
        public static string ToLineString(this LinePosition lineposition) => (lineposition.Line + 1) + "," + (lineposition.Character + 1);
    }
}