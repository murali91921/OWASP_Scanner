using System;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;

namespace ASTTask
{
    internal class Utils
    {
        public static MetadataReference[] LoadMetadata(SyntaxNode root,bool required_mscolib = false)
        {
            List<MetadataReference> allMetadataReference = new List<MetadataReference>();
            List<UsingDirectiveSyntax> allNamespaces = root.DescendantNodes().OfType<UsingDirectiveSyntax>().ToList();
            foreach (var item in allNamespaces)
            {
                string assemblyFile = Path.Combine(Directory.GetCurrentDirectory(),"Examples","References",item.Name.ToString() + ".dll");
                if(File.Exists(assemblyFile))
                    allMetadataReference.Add(MetadataReference.CreateFromFile(assemblyFile));
            }
            if(required_mscolib)
            {
                string assemblyFile = Path.Combine(Directory.GetCurrentDirectory(),"Examples","References","mscorlib.dll");
                if(File.Exists(assemblyFile))
                    allMetadataReference.Add(MetadataReference.CreateFromFile(assemblyFile));
            }
            return allMetadataReference.ToArray();
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
}