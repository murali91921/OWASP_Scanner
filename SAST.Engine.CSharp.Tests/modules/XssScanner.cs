using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.CopyAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.DisposeAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.PointsToAnalysis;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow.ValueContentAnalysis;
using Microsoft.CodeAnalysis.Operations;
using Microsoft.CodeAnalysis.CodeActions;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using static System.Console;

namespace ASTTask
{
    public class XssScanner
    {
        SemanticModel model = null;
        AdhocWorkspace workspace = null;
        SyntaxNode rootNode = null;
        private static string[] encodingMethods = {
            "System.Text.Encodings.Web.TextEncoder.Encode",
            "HttpContext.Server.HtmlEncode"
            };
        private static string[] ControllerClassNames = {
            "Microsoft.AspNetCore.Mvc.ControllerBase",
            "System.Web.Mvc.Controller"
            };
        private static string[] WebFormsRepsonseMethods = {
                "System.Web.HttpResponse.Write",
                "System.Web.HttpResponseBase.Write",
                "System.Web.UI.ClientScriptManager.RegisterStartupScript",      //2
                "System.Web.UI.ClientScriptManager.RegisterClientScriptBloc",   //2
                "System.Web.UI.Page.RegisterStartupScript",     //1
                "System.Web.UI.Page.RegisterClientScriptBlock"  //1
            };
        private static string[] WebFormsControlFieldNames = {
                "System.Web.UI.WebControls.CheckBox.Text",
                "System.Web.UI.WebControls.CompareValidator.Text",
                "System.Web.UI.WebControls.CustomValidator.Text",
                "System.Web.UI.WebControls.HyperLink.Text",
                "System.Web.UI.WebControls.HyperLink.NavigateUrl",
                "System.Web.UI.WebControls.Label.Text",
                "System.Web.UI.WebControls.LinkButton.Text",
                "System.Web.UI.WebControls.Literal.Text",
                "System.Web.UI.WebControls.RadioButton.Text",
                "System.Web.UI.WebControls.RadioButton.GroupName",
                "System.Web.UI.WebControls.RangeValidator.Text",
                "System.Web.UI.WebControls.RegularExpressionValidator.Text",
                "System.Web.UI.WebControls.RequiredFieldValidator.Text",
                "System.Web.UI.WebControls.TableCell.Text",
                "System.Web.UI.WebControls.Calendar.Caption",
                "System.Web.UI.WebControls.Table.Caption",
                "System.Web.UI.WebControls.Panel.GroupingText",
                "System.Web.UI.HtmlControls.HtmlContainerControl",
                "System.Web.UI.WebControls.InnerHtml",
                "System.Web.UI.Control.ID"
            };

        public List<SyntaxNode> FindVulnerabilities(string filePath, SyntaxNode root)
        {
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            HashSet<SyntaxNode> lstVulnerableCheck = new HashSet<SyntaxNode>();
            workspace = new AdhocWorkspace();
            //var solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Create());
            var project = workspace.AddProject("XssScanner", "C#");
            project = project.AddMetadataReference(MetadataReference.CreateFromFile(filePath));
            project = project.AddMetadataReferences(Utils.LoadMetadata(root));
            workspace.TryApplyChanges(project.Solution);
            var document = workspace.AddDocument(project.Id, "XssScanner",SourceText.From(root.ToString()));
            model = document.GetSemanticModelAsync().Result;
            var compilation = project.GetCompilationAsync().Result;
            this.rootNode = document.GetSyntaxRootAsync().Result;

            // CSharpParseOptions options = CSharpParseOptions.Default.WithFeatures(new[] { new KeyValuePair<string, string>("flow-analysis", "")});
            // workspace.TryApplyChanges(project.Solution.WithProjectParseOptions(project.Id,options));

            // ControlFlowGraph controlFlowGraph = ControlFlowGraph.Create(rootNode.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>().First(),model);
            // foreach (var basicBlock in controlFlowGraph.Blocks)
            // {
            //     if(basicBlock.Kind==BasicBlockKind.Block)
            //     {
            //         Write("\n IsReachable {0} {1}",basicBlock.IsReachable,basicBlock.Predecessors.Count());
            //         Write(" Kind {0}",basicBlock.Kind);
            //         Write(" ConditionKind {0}",basicBlock.ConditionKind);
            //         Write(" ConditionalSuccessor {0}",basicBlock.ConditionalSuccessor==null?ControlFlowBranchSemantics.None : basicBlock.ConditionalSuccessor.Semantics);
            //         Write(" FallThroughSuccessor {0}",basicBlock.FallThroughSuccessor==null?ControlFlowBranchSemantics.None : basicBlock.FallThroughSuccessor.Semantics);
            //         WriteLine(" BranchValue.Syntax {0}",basicBlock.BranchValue==null?null :basicBlock.BranchValue.Syntax);
            //         WriteLine("------Operations---");
            //         foreach (var operation in basicBlock.Operations)
            //         {
            //             if(operation.Syntax is ExpressionStatementSyntax || operation.Syntax is VariableDeclaratorSyntax )
            //                 WriteLine("{0}",operation.Syntax.ToFullString());
            //         }
            //     }
            // }

            var classes = rootNode.DescendantNodesAndSelf().OfType<ClassDeclarationSyntax>();

            // Webforms
            foreach (var classItem in classes)
            {
                var invocations = classItem.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
                foreach(var invocation in invocations)
                {
                    SymbolInfo symbolInfo = model.GetSymbolInfo(invocation);
                    IMethodSymbol symbol = (symbolInfo.Symbol==null? (symbolInfo.CandidateSymbols.Count()==0 ? null : symbolInfo.CandidateSymbols.First())
                            : symbolInfo.Symbol) as IMethodSymbol;
                    // WriteLine(symbol);
                    if(symbol == null)
                        continue;
                    if(WebFormsRepsonseMethods.Any(name => name == symbol.ReceiverType.ToString()+"."+symbol.Name.ToString()))
                    {
                        foreach(var argument in invocation.ArgumentList.Arguments)
                        {
                            var argumentType = model.GetTypeInfo(argument.Expression);
                            if(argumentType.Type == null)
                                continue;
                            if(argumentType.Type.ToString() == "string")
                                lstVulnerableCheck.Add(argument.Expression);
                            else if(argumentType.Type.ToString() == "char[]" && argument.Expression is InvocationExpressionSyntax)
                                lstVulnerableCheck.Add((argument.Expression as InvocationExpressionSyntax).Expression);
                                // WriteLine(argument.Expression);
                                // WriteLine(argumentType.Type);
                        }
                    }
                }
            }
            foreach (var item in lstVulnerableCheck)
            {
                if(IsVulnerable(item))
                    WriteLine("{0} {1}",Program.GetLineNumber(item),item);
            }
            #region MVC
            // MVC Controllers
            //  if (classes == null)
            // {
            //     foreach (var item in classes)
            //     {
            //         if(item.BaseList == null)
            //             continue;
            //         var classSymbol = model.GetDeclaredSymbol(item);
            //         if(classSymbol==null && !Utils.DerivesFromAny(classSymbol,ControllerClassNames))
            //             continue;
            //         var methodsWithParameters = item.DescendantNodesAndSelf().OfType<MethodDeclarationSyntax>()
            //             .Where(method => !method.ParameterList.Parameters.Count.Equals(0))
            //             .Where(method => method.Modifiers.ToString().Equals("public"))
            //             .Where(method => method.ReturnType.ToString().Equals("string"));
            //         foreach (MethodDeclarationSyntax method in methodsWithParameters)
            //         {
            //             SyntaxList<StatementSyntax> methodStatements = method.Body.Statements;
            //             IEnumerable<InvocationExpressionSyntax> methodInvocations = method.DescendantNodes().OfType<InvocationExpressionSyntax>();

            //             var returnStatements = method.DescendantNodesAndSelf().OfType<ReturnStatementSyntax>();
            //             if (!returnStatements.Any())
            //                 continue;
            //             if(methodStatements.Count()==0)
            //                 continue;
            //             DataFlowAnalysis flow = model.AnalyzeDataFlow(methodStatements.First(), methodStatements.Last());
            //             IEnumerable<ISymbol> sensibleVariables = flow.DataFlowsIn
            //                 .Union(flow.VariablesDeclared.Except(flow.AlwaysAssigned))
            //                 .Union(flow.WrittenInside)
            //                 .Intersect(flow.WrittenOutside);
            //             if (!sensibleVariables.Count().Equals(0))
            //             {
            //                 foreach (ISymbol sensibleVariable in sensibleVariables)
            //                 {
            //                     if(sensibleVariable.ToString() != "string" )
            //                     continue;
            //                     bool sensibleVariableIsEncoded = false;
            //                     foreach (InvocationExpressionSyntax methodInvocation in methodInvocations)
            //                     {
            //                         SymbolInfo symbolInfo = model.GetSymbolInfo(methodInvocation);
            //                         if(symbolInfo.Symbol == null && symbolInfo.CandidateSymbols.Count()==0)
            //                             continue;
            //                         IMethodSymbol symbol = (symbolInfo.Symbol == null ? symbolInfo.CandidateSymbols.First() : symbolInfo.Symbol) as IMethodSymbol;
            //                         if(!encodingMethods.Any(obj => obj == symbol.ReceiverType.ToString() + "." + symbol.Name.ToString()))
            //                             continue;
            //                         SeparatedSyntaxList<ArgumentSyntax> arguments = methodInvocation.ArgumentList.Arguments;
            //                         if (!arguments.Count.Equals(0))
            //                         {
            //                             if ((arguments.First().Expression as IdentifierNameSyntax).Identifier.ToString()== sensibleVariable.Name.ToString())
            //                             {
            //                                 sensibleVariableIsEncoded = true;
            //                             }
            //                         }
            //                     }
            //                     if (!sensibleVariableIsEncoded)
            //                     {
            //                         foreach (var returnStatement in returnStatements)
            //                             lstVulnerableStatements.Add(returnStatement);
            //                     }
            //                 }
            //             }
            //         }
            //     }
            // }
            #endregion
            // Returning
            return lstVulnerableStatements;
       }
        private bool IsVulnerable(SyntaxNode syntaxNode,ISymbol callingSymbol = null)
        {
            // foreach (var vulnerableSyntaxNode in node)
            {
                var canSuppress = false;
                // var sources = node;
                // foreach (var syntaxNode in sources)
                {
                    var idsToMatchOn = syntaxNode.DescendantNodesAndSelf().OfType<IdentifierNameSyntax>();
                    foreach (var identifierNameSyntax in idsToMatchOn)
                    {
                        var containingBlock = syntaxNode.FirstAncestorOrSelf<MethodDeclarationSyntax>();

                        var idMatches = containingBlock
                            .DescendantNodes()
                            .OfType<IdentifierNameSyntax>()
                            .Where(p => p.Identifier.ValueText == syntaxNode.ToString())
                            .ToList<SyntaxNode>();

                        var declarationMatches = containingBlock
                            .DescendantNodes()
                            .OfType<VariableDeclaratorSyntax>()
                            .Where(p => p.Identifier.ValueText == identifierNameSyntax.ToString())
                            .Select(p => p.Initializer.Value)
                            .ToList<SyntaxNode>();

                        var matches = idMatches.Union(declarationMatches);
                        // var idModel = context.Compilation.GetSemanticModel(syntaxNode.SyntaxTree);

                        foreach (var match in matches)
                        {
                            var indexNode = match.AncestorsAndSelf().FirstOrDefault();

                            while (!canSuppress && indexNode != containingBlock)
                            {
                                var nodeAnalyzer = SyntaxNodeAnalyzerFactory.Create(indexNode);
                                canSuppress = nodeAnalyzer.CanSuppress(idModel, indexNode, pumaContext.DiagnosticId);

                                indexNode = indexNode.Ancestors().FirstOrDefault();
                            }

                            if (canSuppress)
                            {
                                break;
                            }
                        }

                        if (canSuppress)
                        {
                            break;
                        }
                    }
                }
                return canSuppress;
            }
        }
    }
}