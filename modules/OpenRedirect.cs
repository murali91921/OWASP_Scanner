using System;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System.Reflection;
using Newtonsoft.Json;

namespace ASTTask
{
    internal class OpenRedirect
    {
        /*
        FIND THE REDIRECT METHODS
        And If parameter is identifier then check the references above the Redirect statement, then identifier have any
        If parameter is condition, then not vulnerability
        */
        public static void FindOpenRedirect(string filePath, SyntaxNode rootNode)
        {
            var workspace = new AdhocWorkspace();
            var solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Create());
            var project = workspace.AddProject("CookieScanner", "C#");
            project = project.AddMetadataReference(MetadataReference.CreateFromFile(filePath));
            project = project.AddMetadataReferences(LoadMetadata(rootNode));
            workspace.TryApplyChanges(project.Solution);
            var document = workspace.AddDocument(project.Id, "CookieScanner",SourceText.From(rootNode.ToString()));
            var model = document.GetSemanticModelAsync().Result;
            var compilation= project.GetCompilationAsync().Result;
            rootNode = document.GetSyntaxRootAsync().Result;
            //var allRedirects = compilation.GetSymbolsWithName("Redirect",SymbolFilter.Member);
            var allRedirects = rootNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            var restype = compilation.GetTypeByMetadataName("System.Web.HttpResponse");
            foreach (var item in allRedirects)
            {
                //ISymbol symbol= model.GetSymbolInfo(item).Symbol;
                var symbols= SymbolFinder.FindReferencesAsync(restype,document.Project.Solution).Result;
                foreach (var symbol in symbols)
                {
                    Console.WriteLine("{0} {1}",symbol.Definition.ToString(),symbol.Locations.Count());
                }
                Console.WriteLine("{0} {1}",item.ToString(),item.Kind());
            }
        }
        private static MetadataReference[] LoadMetadata(SyntaxNode root)
        {
            List<MetadataReference> allMetadataReference = new List<MetadataReference>();
            List<UsingDirectiveSyntax> allNamespaces = root.DescendantNodes().OfType<UsingDirectiveSyntax>().ToList();
            foreach (var item in allNamespaces)
            {
                string assemblyFile = Directory.GetCurrentDirectory() + "\\Examples\\References\\" + item.Name.ToString() + ".dll";
                if(File.Exists(assemblyFile))
                    allMetadataReference.Add(MetadataReference.CreateFromFile(assemblyFile));
            }
            return allMetadataReference.ToArray();
        }
    }
}