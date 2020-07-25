using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using static System.Console;

namespace ASTTask
{
    internal class InsecureRandomScanner
    {
        SemanticModel model = null;
        AdhocWorkspace workspace = null;
        SyntaxNode rootNode = null;
        // private static string RandomClass = "System.Random";
        private static string[] RandomMethods = {
            "System.Random.Next",
            "System.Random.NextDouble",
            "System.Random.NextBytes"};
        public List<SyntaxNode> FindVulnerabilities(string filePath, SyntaxNode root)
        {
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            List<SyntaxNode> lstVulnerableCheck = new List<SyntaxNode>();
            workspace = new AdhocWorkspace();
            var solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Create());
            var project = workspace.AddProject("InsecureRandomScanner", "C#");
            project = project.AddMetadataReference(MetadataReference.CreateFromFile(filePath));
            project = project.AddMetadataReferences(Utils.LoadMetadata(root));
            workspace.TryApplyChanges(project.Solution);
            var document = workspace.AddDocument(project.Id, "InsecureRandomScanner",SourceText.From(root.ToString()));
            model = document.GetSemanticModelAsync().Result;
            var compilation = project.GetCompilationAsync().Result;
            rootNode = document.GetSyntaxRootAsync().Result;
            // var objectCreationExpressions = rootNode.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();
            // foreach (var objectCreation in objectCreationExpressions)
            // {
            //     IMethodSymbol symbol = model.GetSymbolInfo(objectCreation).Symbol as IMethodSymbol;
            //     if(symbol.ContainingType.ToString() == RandomClass && symbol.MethodKind == MethodKind.Constructor)
            //         lstVulnerableStatements.Add(objectCreation);
            // }
            var invocations = rootNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
            foreach (var method in invocations)
            {
                IMethodSymbol symbol = model.GetSymbolInfo(method).Symbol as IMethodSymbol;
                string symbolMethod = symbol == null ? null : symbol.ContainingType.ToString() + "." + symbol.Name.ToString();
                if(RandomMethods.Any(obj=> obj== symbolMethod))
                    lstVulnerableStatements.Add(method);
            }
            return lstVulnerableStatements;
        }
    }
}