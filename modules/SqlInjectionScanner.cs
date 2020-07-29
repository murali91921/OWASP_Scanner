using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using static System.Console;

namespace ASTTask
{
    internal class SqlInjectionScanner
    {
        SemanticModel model = null;
        AdhocWorkspace workspace = null;
        SyntaxNode rootNode = null;
        // private static string RandomClass = "System.Random";
        private static string[] CommandClasses = {
            "System.Data.Common.DbCommand",
            "System.Data.IDbCommand",
            "System.Data.SqlClient.SqlCommand",
            "System.Data.OleDb.OleDbCommand",
            "System.Data.Odbc.OdbcCommand",
            "System.Data.OracleClient.OracleCommand",
            "System.Data.SQLite.SQLiteCommand"
            };
        private static string[] CommandTextProperties = {
            "System.Data.Common.DbCommand.CommandText",
            "System.Data.IDbCommand.CommandText",
            "System.Data.SqlClient.SqlCommand.CommandText",
            "System.Data.OleDb.OleDbCommand.CommandText",
            "System.Data.Odbc.OdbcCommand.CommandText",
            "System.Data.OracleClient.OracleCommand.CommandText",
            "System.Data.SQLite.SQLiteCommand.CommandText"
            };

        public List<SyntaxNode> FindVulnerabilities(string filePath, SyntaxNode root)
        {
            CSharpParseOptions options = CSharpParseOptions.Default
                .WithFeatures(new[] { new KeyValuePair<string, string>("flow-analysis", "")
                });
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            HashSet<SyntaxNode> lstVulnerableCheck = new HashSet<SyntaxNode>();
            workspace = new AdhocWorkspace();
            //var solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Create());
            var project = workspace.AddProject("SqlInjectionScanner", "C#");
            project = project.AddMetadataReference(MetadataReference.CreateFromFile(filePath));
            project = project.AddMetadataReferences(Utils.LoadMetadata(root));
            workspace.TryApplyChanges(project.Solution.WithProjectParseOptions(project.Id,options));
            var document = workspace.AddDocument(project.Id, "SqlInjectionScanner",SourceText.From(root.ToString()));
            model = document.GetSemanticModelAsync().Result;
            var compilation = project.GetCompilationAsync().Result;
            rootNode = document.GetSyntaxRootAsync().Result;
            var objectCreationExpressions = rootNode.DescendantNodes().OfType<ObjectCreationExpressionSyntax>();

            // foreach (var item in rootNode.DescendantNodes().OfType<MethodDeclarationSyntax>())
            // {
            //     ControlFlowGraph controlFlowGraph = ControlFlowGraph.Create(item,model);
            //     foreach (var block in controlFlowGraph.Blocks)
            //     {
            //         foreach (var operation in block.Operations)
            //         {
            //         WriteLine(operation.Syntax.ToString());
            //         }

            //         WriteLine(block);
            //     }
            // }

            foreach (var objectCreation in objectCreationExpressions)
            {
                ITypeSymbol typeSymbol = model.GetTypeInfo(objectCreation).Type as ITypeSymbol;
                if(typeSymbol == null)
                    continue;
                if(!CommandClasses.Any(obj=> obj == typeSymbol.ToString()))
                    continue;
                if(objectCreation.ArgumentList != null && objectCreation.ArgumentList.Arguments.Count>0)
                {
                    foreach (var item in objectCreation.ArgumentList.Arguments)
                    {
                        if(model.GetTypeInfo(item.Expression).Type.ToString() == "string")
                        {
                            lstVulnerableCheck.Add(item.Expression);
                            // WriteLine(item.Expression);
                        }
                    }
                }
                if(objectCreation.Initializer !=null)
                {
                    var commandTextInitializer = objectCreation.Initializer.Expressions.OfType<AssignmentExpressionSyntax>().FirstOrDefault(
                        obj=>(obj.Left as IdentifierNameSyntax).Identifier.ValueText=="CommandText");
                    if(commandTextInitializer != null)
                    {
                        lstVulnerableCheck.Add(commandTextInitializer.Right);
                        // WriteLine(commandTextInitializer);
                    }
                }
            }
            // WriteLine("Assignments");
            var assignments = rootNode.DescendantNodes().OfType<AssignmentExpressionSyntax>().Where(
                obj => obj.Left.ToString().Contains("CommandText") && !obj.IsKind(SyntaxKind.ObjectInitializerExpression)).ToList();
            foreach (var item in assignments)
            {
                IPropertySymbol symbol = model.GetSymbolInfo(item.Left).Symbol as IPropertySymbol;
                if(CommandTextProperties.Any(obj => obj == symbol.ToString()))
                {
                    // WriteLine(item.Right);
                    lstVulnerableCheck.Add((item as AssignmentExpressionSyntax).Right);
                }
            }
            foreach (var item in lstVulnerableCheck)
            {
                if(IsVulnerable(item))
                    lstVulnerableStatements.Add(item.Parent);
                //     WriteLine("Vulnerable {0}:{1}", Program.GetLineNumber(item.Parent), item.Parent);
                // else
                //     WriteLine("Not Vulnerable {0}:{1}",Program.GetLineNumber(item.Parent), item.Parent);

            }
            return lstVulnerableStatements;
        }
        private bool IsVulnerable(SyntaxNode node,ISymbol callingSymbol = null)
        {
            if(node is IdentifierNameSyntax)
            {
                ITypeSymbol type = model.GetTypeInfo(node).Type;
                if(type.ToString() != "string")
                    return false;

                bool vulnerable = false;
                ISymbol symbol = model.GetSymbolInfo(node).Symbol;
                if(symbol == null)
                    return false;
                if(symbol.Equals(callingSymbol,SymbolEqualityComparer.Default))
                    return false;

                var references = SymbolFinder.FindReferencesAsync(symbol,workspace.CurrentSolution).Result;
                foreach (var reference in references)
                {
                    var currentNode = rootNode.FindNode(reference.Definition.Locations.First().SourceSpan);
                    vulnerable = IsVulnerable(currentNode);
                    // vulnerable = vulnerable || retVulnerable;
                    foreach (var refLocation in reference.Locations)
                    {
                        currentNode = rootNode.FindNode(refLocation.Location.SourceSpan);
                        if(CheckSameBlock(currentNode, node) && currentNode.SpanStart < node.SpanStart)
                        {
                            // WriteLine(currentNode.Parent.Parent);
                            // WriteLine(node.Parent);
                            var assignment = currentNode.Ancestors().OfType<AssignmentExpressionSyntax>().FirstOrDefault();
                            if(assignment==null)
                                continue;
                            if(currentNode.SpanStart < assignment.Right.SpanStart)
                            {
                             //   WriteLine("{0} {1} {2} {3}",assignment.Right,assignment.Right.SpanStart, currentNode , currentNode.SpanStart);
                                vulnerable = IsVulnerable(assignment.Right,symbol);
                            }
                            // vulnerable = vulnerable || retVulnerable;
                        }
                    }
                }
                return vulnerable;
            }
            else if(node is BinaryExpressionSyntax)
            {
                var left = IsVulnerable((node as BinaryExpressionSyntax).Left,callingSymbol);
                var right = IsVulnerable((node as BinaryExpressionSyntax).Right,callingSymbol);
                return left || right;
            }
            else if(node is VariableDeclaratorSyntax && (node as VariableDeclaratorSyntax).Initializer!=null)
            {
                return IsVulnerable((node as VariableDeclaratorSyntax).Initializer.Value);
            }
            else if(node is AssignmentExpressionSyntax)
            {
                return IsVulnerable((node as AssignmentExpressionSyntax).Right);
            }
            else if(node is InterpolatedStringExpressionSyntax)
            {
                bool vulnerable = false;
                var contents = (node as InterpolatedStringExpressionSyntax).Contents.OfType<InterpolationSyntax>();
                foreach (var item in contents)
                {
                    vulnerable = vulnerable || IsVulnerable(item.Expression);
                }
                return vulnerable;
            }
            else if(node is LiteralExpressionSyntax)
                return false;
            else if(node is ParameterSyntax)
                return true;
            else
                return false;
        }
        private bool CheckSameBlock(SyntaxNode first, SyntaxNode second)
        {
            BlockSyntax block1 = first.Ancestors().OfType<BlockSyntax>().FirstOrDefault();
            var blocks = second.Ancestors().OfType<BlockSyntax>();
            bool ret = blocks.Any(blk => blk.IsEquivalentTo(block1));
            return ret;
        }
    }
}