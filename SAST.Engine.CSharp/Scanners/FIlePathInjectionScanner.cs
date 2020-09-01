using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class FIlePathInjectionScanner : IScanner
    {
        internal static readonly string[] insecureMethods = {
            "System.IO.Directory.Exists",
            "System.IO.FileInfo.CopyTo",
            "System.IO.FileInfo.MoveTo",
            "System.IO.FileInfo.Replace",
            "System.IO.File.AppendAllLines",
            "System.IO.File.AppendAllText",
            "System.IO.File.AppendText",
            "System.IO.File.Copy",
            "System.IO.File.Create",
            "System.IO.File.CreateText",
            "System.IO.File.Delete",
            "System.IO.File.Exists",
            "System.IO.File.Move",
            "System.IO.File.Open",
            "System.IO.File.OpenRead",
            "System.IO.File.OpenText",
            "System.IO.File.OpenWrite",
            "System.IO.File.ReadAllBytes",
            "System.IO.File.ReadAllLines",
            "System.IO.File.ReadAllText",
            "System.IO.File.ReadLines",
            "System.IO.File.WriteAllBytes",
            "System.IO.File.WriteAllLines",
            "System.IO.File.WriteAllText",
        };
        internal static readonly string[] ParameterNames = {
            "path",
            "sourceFileName",
            "destFileName",
            "destinationFileName",
            "destinationBackupFileName"
        };

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var objectCreations = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var item in objectCreations)
            {
                ITypeSymbol typeSymbol = Utils.GetTypeSymbol(item, model);
                if (typeSymbol == null || typeSymbol.ToString() != "System.IO.FileInfo")
                    continue;
                syntaxNodes.Add(item);
            }
            var invocationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocationExpressions)
            {
                ISymbol symbol = Utils.GetSymbol(item, model);
                if (symbol == null || !insecureMethods.Any(obj => obj == symbol.ContainingType.ToString() + "." + symbol.Name.ToString()))
                    continue;
                int index = 0;
                bool vulnerable = false;
                foreach (var argument in item.ArgumentList.Arguments)
                {
                    if (argument.NameColon == null)
                    {
                        if (symbol.Name.ToString() == "Replace" || symbol.Name.ToString() == "Copy" || symbol.Name.ToString() == "Move")
                            vulnerable = Utils.IsVulnerable(argument.Expression, model, solution, null);
                        else if (symbol.Name.ToString() == "WriteAllText" || symbol.Name.ToString() == "AppendAllText")
                            vulnerable = index >= 1 ? vulnerable : Utils.IsVulnerable(argument.Expression, model, solution, null);
                        else
                            vulnerable = Utils.IsVulnerable(argument.Expression, model, solution, null);
                    }
                    else if (ParameterNames.Any(obj => obj == argument.NameColon.Name.ToString()))
                        vulnerable = Utils.IsVulnerable(argument.Expression, model, solution, null);
                    if (vulnerable)
                    {
                        syntaxNodes.Add(item);
                        if (symbol.Name.ToString() == "Replace" || symbol.Name.ToString() == "Copy" || symbol.Name.ToString() == "Move"
                            || symbol.Name.ToString() == "WriteAllText" || symbol.Name.ToString() == "AppendAllText")
                            break;
                    }
                    index++;
                }
            }
            return Map.ConvertToVulnerabilityList(filePath, syntaxNodes, Enums.ScannerType.FilePathInjection);
        }
    }
}