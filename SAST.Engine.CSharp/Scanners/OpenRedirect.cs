using SAST.Engine.CSharp.Enums;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;

namespace SAST.Engine.CSharp.Scanners
{
    public class OpenRedirectScanner : IScanner
    {
        SemanticModel model = null;
        SyntaxNode syntaxNode = null;
        Solution solution = null;
        public void FindOpenRedirect(InvocationExpressionSyntax item)
        {
            //Get the symbol Info from Semanticmodel
            IMethodSymbol symbol = null;
            var symbolInfo = model.GetSymbolInfo(item);
            if (symbolInfo.Symbol == null && symbolInfo.CandidateReason == CandidateReason.OverloadResolutionFailure)
                symbol = symbolInfo.CandidateSymbols.First() as IMethodSymbol;
            else
                symbol = symbolInfo.Symbol as IMethodSymbol;
            //Console.WriteLine(symbol);

            if (symbol != null && (symbol.Name == "Redirect" || symbol.Name == "RedirectPermanent")
                && (symbol.ReceiverType.ToString() == "System.Web.HttpResponse" || symbol.ReceiverType.ToString() == "Microsoft.AspNetCore.Http.Response"
                    || symbol.ReceiverType.ToString() == "System.Web.Mvc.Controller" || symbol.ReceiverType.ToString() == "System.Web.HttpResponseBase"
                    || symbol.ReceiverType.ToString() == "Microsoft.AspNetCore.Http.HttpResponse" || symbol.ReceiverType.ToString() == "Microsoft.AspNetCore.Mvc.Controller"
                    || symbol.ReceiverType.ToString() == "Microsoft.AspNetCore.Mvc.ControllerBase"))
            {
                //Console.WriteLine("{0} {1}",symbol.ToString(),item.Kind());
                if (item.ArgumentList.Arguments.Count > 0)
                {
                    var argument = item.ArgumentList.Arguments.First();
                    {
                        // bool vulnerable = IsVulnerable(argument.Expression);
                        // if(vulnerable)
                        //     // Console.WriteLine("\nVulnerable found \t:{0} {1} {2}",vulnerable,item,argument.Expression);
                        //     Console.WriteLine("\nVulnerable found \t:{0}",item.Parent);
                        // else
                        //     Console.WriteLine("\nNo vulnerable found\t\t:{0}",item.Parent);
                        if (IsVulnerable(argument.Expression))
                            lstVulnerableStatements.Add(item.Parent);
                    }
                }
            }
        }
        List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            //Filter all method invocation with Redirect string

            this.model = model;
            this.syntaxNode = syntaxNode;
            this.solution = solution;
            var allRedirects = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>().Where(obj => obj.ToString().Contains("Redirect"));
            foreach (var item in allRedirects)
            {
                FindOpenRedirect(item);
            }
            return Map.ConvertToVulnerabilityList(filePath, lstVulnerableStatements, ScannerType.OpenRedirect);
        }
        /*
        Argument can be
        1.string                            -- Implemented
        2.cancatenated as
                "string" + InputVariable    -- Implemented
                InputVariable + "string"    -- Implemented
                Method(param) + "string"    -- Implemented
        3.Conditional Expression as ternary -- Implemented;
        4.Method Invocation                 -- Implemented
        */
        internal bool IsVulnerable(SyntaxNode argument)
        {
            switch (argument.Kind())
            {
                //If it is static string
                case SyntaxKind.StringLiteralExpression:
                    return false;
                //If it is concatenation of two or strings/variables
                case SyntaxKind.AddExpression:
                    return IsAddExpression(argument);
                //If it is method calling
                case SyntaxKind.InvocationExpression:
                    return !IsConditionExpression(argument);
                case SyntaxKind.ConditionalExpression:
                    return false;
                case SyntaxKind.IdentifierName:
                    return !IsConditionExpression(argument); ;
            }
            // var nonLiteralExpresssions = argument.ChildNodes().Where(obj=>!(obj is LiteralExpressionSyntax));
            // if(nonLiteralExpresssions.Count()==0)
            // {
            //     return false;
            // }
            // bool result = false;
            // foreach (var item in nonLiteralExpresssions)
            // {
            //     result = result || !IsConditionExpression(item);;
            // }
            return true;
        }
        internal bool IsAddExpression(SyntaxNode syntaxNode)
        {
            if (syntaxNode.IsKind(SyntaxKind.AddExpression))
            {
                BinaryExpressionSyntax binaryExpression = (syntaxNode as BinaryExpressionSyntax);
                // If left is static string, then it is not vulnerable.
                if (binaryExpression.Left.IsKind(SyntaxKind.StringLiteralExpression))
                    return false;
                // If left is method calling, then check for method vulnerable.
                // If left is an identifier, then check for identifier vulnerable
                else
                    return !IsConditionExpression(binaryExpression.Left);
            }
            return false;
        }
        internal bool IsConditionExpression(SyntaxNode syntaxNode)
        {
            // Method was there. this method may contain conditional or it may have to call another methods within body.
            if (syntaxNode is InvocationExpressionSyntax)
                return true;
            else if (syntaxNode is IdentifierNameSyntax)
            {
                var ancestor = syntaxNode.Ancestors().Where(obj => obj is IfStatementSyntax || obj is ConditionalExpressionSyntax).ToList();
                if (ancestor.Count > 0)
                {
                    var Identifiers = ancestor[0].DescendantNodes().Where(obj => obj.IsKind(SyntaxKind.IdentifierName)).ToList();
                    if (Identifiers.Exists(obj => obj == syntaxNode))
                        return true;
                }
                SymbolInfo symbolInfo = model.GetSymbolInfo(syntaxNode);
                var refSymbols = SymbolFinder.FindReferencesAsync(symbolInfo.Symbol, solution).Result;
                foreach (var referencedSymbol in refSymbols)
                {
                    foreach (var referencedLocation in referencedSymbol.Locations)
                    {
                        var refNode = syntaxNode.FindNode(referencedLocation.Location.SourceSpan);
                        //Get the statements before the current Response.Redirect statements only
                        if (syntaxNode.Span.Start > refNode.Span.Start)
                        {
                            var ifStatements = refNode.Ancestors().OfType<IfStatementSyntax>();
                            var assignmentExpressions = refNode.Ancestors().OfType<AssignmentExpressionSyntax>();
                            if (assignmentExpressions.Count() > 0 && ifStatements.Count() > 0)
                            {
                                // Console.WriteLine(refNode.Parent.Parent + " : " + syntaxNode.Span + " : " + refNode.Span + " : " + refNode.FullSpan);
                                return true;
                            }
                        }
                    }
                }
            }
            // For tenran
            else if (syntaxNode is ConditionalExpressionSyntax)
                return true;
            return false;
        }

        /*
        System.Web.Response                 Redirect(input)
        System.Web.Response                 Redirect(input, true)
        System.Web.Response                 RedirectPermanent(input)
        System.Web.Response                 RedirectPermanent(input, true)
        Microsoft.AspNetCore.Http.Response  Redirect(input)
        Microsoft.AspNetCore.Http.Response  Redirect(input, true)
        */
    }
}