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
        public static MetadataReference[] LoadMetadata(SyntaxNode root)
        {
            List<MetadataReference> allMetadataReference = new List<MetadataReference>();
            List<UsingDirectiveSyntax> allNamespaces = root.DescendantNodes().OfType<UsingDirectiveSyntax>().ToList();
            foreach (var item in allNamespaces)
            {
                string assemblyFile =Path.Combine(Directory.GetCurrentDirectory(),"Examples","References",item.Name.ToString() + ".dll");
                if(File.Exists(assemblyFile))
                    allMetadataReference.Add(MetadataReference.CreateFromFile(assemblyFile));
            }
            //allMetadataReference.Add(MetadataReference.CreateFromFile(typeof(object).Assembly.Location));
            return allMetadataReference.ToArray();
        }
    }
}