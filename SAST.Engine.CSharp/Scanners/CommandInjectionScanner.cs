using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System;
using System.Collections.Generic;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class CommandInjectionScanner : IScanner
    {
        string _filePath;
        SyntaxNode _syntaxNode;
        SemanticModel _model = null;
        Solution _solution = null;
        List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            _filePath = filePath;
            _syntaxNode = syntaxNode;
            _model = model;
            _solution = solution;
            vulnerabilities.AddRange(FindProcessExpressons());
            //vulnerabilities.AddRange(FindProcessInfoExpressons());
            return vulnerabilities;
        }

        private IEnumerable<VulnerabilityDetail> FindProcessExpressons()
        {
            List<SyntaxNode> syntaxNodes = new List<SyntaxNode>();
            var invocationExpressions = _syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocationExpressions)
            {
                ISymbol symbol = _model.GetSymbol(item);
                if (symbol == null || symbol.ContainingType.ToString() + "." + symbol.Name.ToString() != "System.Diagnostics.Process.Start")
                    continue;
                if (item.ArgumentList?.Arguments.Count == 0)
                    continue;
                var argumentExpression = item.ArgumentList?.Arguments[0].Expression;
                ITypeSymbol typeSymbol = _model.GetTypeSymbol(argumentExpression);
                if (typeSymbol == null || typeSymbol.ToString() == "System.Diagnostics.ProcessStartInfo")
                    continue;
                if (item.ArgumentList?.Arguments.Count == 1)
                {
                    if (Utils.IsVulnerable(argumentExpression, _model, _solution))
                        syntaxNodes.Add(item);
                    continue;
                }
                int index = 0;
                bool vulnerable = false;
                foreach (var argument in item.ArgumentList.Arguments)
                {
                    if (argument.NameColon is null)
                    {
                        if (index <= 1)
                            vulnerable = Utils.IsVulnerable(argument.Expression, _model, _solution);
                    }
                    else if (argument.NameColon.Name.ToString() == "fileName" || argument.NameColon.Name.ToString() == "arguments")
                    {
                        vulnerable = Utils.IsVulnerable(argument.Expression, _model, _solution);
                    }
                    if (vulnerable)
                    {
                        syntaxNodes.Add(item);
                        break;
                    }
                    index++;
                }
            }
            return Map.ConvertToVulnerabilityList(_filePath, syntaxNodes, Enums.ScannerType.CommandInjection);
        }

        private IEnumerable<VulnerabilityDetail> FindProcessInfoExpressons()
        {
            List<MyClass> syntaxNodes = new List<MyClass>();
            var objectCreations = _syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var item in objectCreations)
            {
                ITypeSymbol typeSymbol = _model.GetTypeSymbol(item);
                if (typeSymbol == null || typeSymbol.ToString() != "System.Diagnostics.ProcessStartInfo")
                    continue;
                if (item.Initializer?.Expressions.Count == 0 && item.ArgumentList?.Arguments.Count == 0)
                    continue;

                if (item.ArgumentList?.Arguments.Count > 0)
                {
                    //foreach (var argument in item.ArgumentList?.Arguments)
                    {
                        //if (Utils.IsVulnerable(argument.Expression, _model, _solution, null))
                        {
                            syntaxNodes.Add(new MyClass() { node = item, Source = item.ArgumentList.Arguments.ToList().Select(p => p.Expression).ToList<SyntaxNode>() });
                            break;
                        }
                    }
                }
                else if (item.Initializer?.Expressions.Count > 0)
                {
                    MyClass myclass = new MyClass() { node = item };

                    foreach (var expression in item.Initializer?.Expressions)
                    {
                        if (expression is AssignmentExpressionSyntax assignment)
                        {
                            if (assignment.Left.ToString() != "FileName" && assignment.Left.ToString() != "Arguments")
                                continue;
                            //if (Utils.IsVulnerable(assignment.Right, _model, _solution, null))
                            {
                                myclass.Source.Add(expression);
                                //break;
                            }
                        }
                    }
                }
            }

            foreach (var vulnerableSyntaxNode in syntaxNodes)
            {
                var canSuppress = false;
                var sources = vulnerableSyntaxNode.Source;
                foreach (var syntaxNode in sources)
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
                        var idModel = _model.Compilation.GetSemanticModel(syntaxNode.SyntaxTree);

                        foreach (var match in matches)
                        {
                            var indexNode = match.AncestorsAndSelf().FirstOrDefault();
                            Console.WriteLine($"{Map.GetLineNumber(match)} : {match}");
                            while (!canSuppress && indexNode != containingBlock)
                            {
                                Console.WriteLine($"{Map.GetLineNumber(indexNode)} : {indexNode}");
                                var nodeAnalyzer = SyntaxNodeAnalyzerFactory.Create(indexNode);
                                canSuppress = nodeAnalyzer.CanSuppress(idModel, indexNode);

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

                    if (canSuppress)
                    {
                        break;
                    }

                }

                vulnerableSyntaxNode.Suppressed = canSuppress;
            }
            return Map.ConvertToVulnerabilityList(_filePath, syntaxNodes, Enums.ScannerType.CommandInjection);
        }

        class MyClass
        {
            public MyClass()
            {
                Source = new List<SyntaxNode>();
            }
            public List<SyntaxNode> Source { get; set; }
            public SyntaxNode node { get; set; }
            public bool Suppressed { get; set; }
        }
        internal static class SyntaxNodeAnalyzerFactory
        {
            internal static ISyntaxNodeAnalyzer Create(SyntaxNode syntax)
            {
                switch (syntax)
                {
                    //case ArgumentListSyntax _:
                    //    return new ArgumentListSyntaxAnalyzer();
                    //case ArgumentSyntax _:
                    //    return new ArgumentSyntaxNodeAnalyzer();
                    //case BinaryExpressionSyntax _:
                    //    return new BinaryExpressionSyntaxAnalyzer();
                    //case ConditionalExpressionSyntax _:
                    //    return new ConditionalExpressionSyntaxAnalyzer();
                    //case ElementAccessExpressionSyntax _:
                    //    return new ElementAccessExpressionSyntaxAnalyzer();
                    case IdentifierNameSyntax _:
                        return new IdentifierNameSyntaxAnalyzer();
                    case InvocationExpressionSyntax _:
                        return new InvocationExpressionSyntaxAnalyzer();
                        //case LiteralExpressionSyntax _:
                        //    return new LiteralExpressionSyntaxAnalyzer();
                        //case MemberAccessExpressionSyntax _:
                        //    return new MemberAccessExpressionSyntaxAnalyzer();
                        //case ParameterSyntax _:
                        //    return new ParameterSyntaxNodeAnalyzer();
                        //case QueryExpressionSyntax _:
                        //    return new QueryExpressionSyntaxAnalyzer();
                }

                return new BaseSyntaxNodeAnalyzer<SyntaxNode>();
            }
        }
        internal interface ISyntaxNodeAnalyzer
        {
            bool CanSuppress(SemanticModel model, SyntaxNode syntax);
            bool CanIgnore(SemanticModel model, SyntaxNode syntax);
        }

        internal interface ISyntaxNodeAnalyzer<T> : ISyntaxNodeAnalyzer
        {

        }
        internal class BaseSyntaxNodeAnalyzer<T> : ISyntaxNodeAnalyzer<T>
        {
            public virtual bool CanSuppress(SemanticModel model, SyntaxNode syntax)
            {
                return false;
            }

            public virtual bool CanIgnore(SemanticModel model, SyntaxNode syntax)
            {
                return false;
            }
        }
        internal class IdentifierNameSyntaxAnalyzer : BaseSyntaxNodeAnalyzer<IdentifierNameSyntax>
        {
            //private readonly ISanitizedSourceAnalyzer _sanitizedSourceAnalyzer;
            //private readonly ISafeSyntaxTypeAnalyzer _safeSyntaxTypeAnalyzer;

            internal IdentifierNameSyntaxAnalyzer()
            //: this(
            //      new SanitizedSourceAnalyzer(),
            //      new SafeSyntaxTypeAnalyzer())
            {

            }

            //internal IdentifierNameSyntaxAnalyzer(ISanitizedSourceAnalyzer sanitizedSourceAnalyzer, ISafeSyntaxTypeAnalyzer safeSyntaxTypeAnalyzer)
            //{
            //    _sanitizedSourceAnalyzer = sanitizedSourceAnalyzer;
            //    _safeSyntaxTypeAnalyzer = safeSyntaxTypeAnalyzer;
            //}

            public override bool CanIgnore(SemanticModel model, SyntaxNode syntax)
            {
                var identifierNameSyntax = syntax as IdentifierNameSyntax;
                var symbolInfo = model.GetSymbolInfo(identifierNameSyntax);

                return base.CanIgnore(model, syntax);
            }

            public override bool CanSuppress(SemanticModel model, SyntaxNode syntax)
            {
                var identifierNameSyntax = syntax as IdentifierNameSyntax;
                var symbolInfo = model.GetSymbolInfo(identifierNameSyntax);


                return base.CanSuppress(model, syntax);
            }
        }
        internal class InvocationExpressionSyntaxAnalyzer : BaseSyntaxNodeAnalyzer<InvocationExpressionSyntax>
        {
            //private readonly ISanitizedSourceAnalyzer _sanitizedSourceAnalyzer;
            private readonly ISyntaxNodeAnalyzer<SyntaxNode> _analyzer;
            private readonly IIsArgumentOnlyExpression _argsOnlyInvocationExpression;

            internal InvocationExpressionSyntaxAnalyzer()
                : this(new IsArgumentOnlyExpression(),
                      new SyntaxNodeAnalyzer())
            {

            }

            internal InvocationExpressionSyntaxAnalyzer(IsArgumentOnlyExpression isArgumentOnlyExpression, ISyntaxNodeAnalyzer<SyntaxNode> syntaxNodeAnalyzer)
            {
                _argsOnlyInvocationExpression = isArgumentOnlyExpression;
                _analyzer = syntaxNodeAnalyzer;
            }

            public override bool CanSuppress(SemanticModel model, SyntaxNode syntax)
            {
                var invocationExpressionSyntax = syntax as InvocationExpressionSyntax;

                //if (_sanitizedSourceAnalyzer.IsSymbolSanitized(model.GetSymbolInfo(invocationExpressionSyntax), ruleId))
                //    return true;

                var argsSafe = CanSuppressArguments(model, invocationExpressionSyntax.ArgumentList);

                var isArgsOnlyExpression = _argsOnlyInvocationExpression.Execute(model, invocationExpressionSyntax);

                if (isArgsOnlyExpression)
                    return argsSafe;

                var isBodySafe = CanSuppressExpression(model, invocationExpressionSyntax.Expression);

                return argsSafe && isBodySafe;
            }

            private bool CanSuppressExpression(SemanticModel model, SyntaxNode expression)
            {
                return _analyzer.CanIgnore(model, expression) || _analyzer.CanSuppress(model, expression);
            }

            private bool CanSuppressArguments(SemanticModel model, ArgumentListSyntax argumentList)
            {
                if (!argumentList.Arguments.Any())
                    return true;

                var args = argumentList.Arguments;

                return args.All(p => _analyzer.CanIgnore(model, p.Expression) || _analyzer.CanSuppress(model, p.Expression));
            }
        }

        internal interface IIsArgumentOnlyExpression
        {
            bool Execute(SemanticModel model, InvocationExpressionSyntax syntax);
        }

        public class IsArgumentOnlyExpression : IIsArgumentOnlyExpression
        {
            public bool Execute(SemanticModel model, InvocationExpressionSyntax syntax)
            {
                if (ContainsArgumentOnlyMethodName(syntax))
                {
                    var symbol = model.GetSymbolInfo(syntax).Symbol as IMethodSymbol;
                    if (symbol != null)
                    {
                        return IsArgumentOnlyMethod(symbol);
                    }
                }

                return false;
            }

            private bool ContainsArgumentOnlyMethodName(InvocationExpressionSyntax syntax) => syntax.ToString().Contains("MapPath") || syntax.ToString().Contains("string.Format") || syntax.ToString().Contains("String.Format");

            private bool IsArgumentOnlyMethod(IMethodSymbol symbol)
            {
                return symbol.ContainingNamespace.ToString() + "." + symbol.Name.ToString() == "System.Web.HttpRequest.MapPath"
                    || symbol.ContainingNamespace.ToString() + "." + symbol.Name.ToString() == "System.Web.HttpServerUtility.MapPath"
                    || symbol.ContainingNamespace.ToString() + "." + symbol.Name.ToString() == "string.Format";
            }
        }
        internal class SyntaxNodeAnalyzer : BaseSyntaxNodeAnalyzer<SyntaxNode>
        {
            public override bool CanIgnore(SemanticModel model, SyntaxNode syntax)
            {
                var expressionSyntaxAnalyzer = SyntaxNodeAnalyzerFactory.Create(syntax);

                return expressionSyntaxAnalyzer.CanIgnore(model, syntax);
            }

            public override bool CanSuppress(SemanticModel model, SyntaxNode syntax)
            {
                var expressionSyntaxAnalyzer = SyntaxNodeAnalyzerFactory.Create(syntax);

                return expressionSyntaxAnalyzer.CanSuppress(model, syntax);
            }
        }
    }
}