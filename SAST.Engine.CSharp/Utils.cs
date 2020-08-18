using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
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
        internal static readonly string[] MarkupFileExtensions = { ".cshtml", ".aspx", ".ascx" };
        internal static readonly string[] ProjectFileExtensions = { ".csproj" };

        public static void LoadMetadata(out List<MetadataReference> MetadataReferences)
        {
            MetadataReferences = new List<MetadataReference>();
            string[] assemblyPaths = Directory.GetFiles(Path.Combine(Directory.GetCurrentDirectory(), "Examples", "References"));
            foreach (var assemblyFile in assemblyPaths)
            {
                if (File.Exists(assemblyFile))
                    MetadataReferences.Add(MetadataReference.CreateFromFile(assemblyFile));
            }
            //if (required_mscolib)
            //{
            //    string assemblyFile = Path.Combine(Directory.GetCurrentDirectory(), "Examples", "References", "mscorlib.dll");
            //    if (File.Exists(assemblyFile))
            //        allMetadataReference.Add(MetadataReference.CreateFromFile(assemblyFile));
            //}
            //return allMetadataReference.ToArray();
        }
        public static bool DerivesFromAny(ITypeSymbol typeSymbol, string[] baseTypes)
        {
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