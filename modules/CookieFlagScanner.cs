using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System.Linq;
using System;
using System.Text.RegularExpressions;

namespace ASTTask
{
    internal class CookieFlagScanner
    {
        public static List<SyntaxNodeOrToken> FindInsecureCookies(SyntaxNode rootNode)
        {
            List<SyntaxNodeOrToken> insecureCookies=new List<SyntaxNodeOrToken>();
            //Looping through All variable declarators
            foreach (var declarator in rootNode.DescendantNodes().OfType<VariableDeclaratorSyntax>())
            {
                //Checking whether declarator have object creation or not
                if(declarator.DescendantNodes().Any(obj => obj is ObjectCreationExpressionSyntax))
                {
                    ObjectCreationExpressionSyntax objectCreator = declarator.DescendantNodes().OfType<ObjectCreationExpressionSyntax>().FirstOrDefault();
                    // if(objectCreator.ChildNodesAndTokens()[0].Identifier.ToString()=="CookieHeaderValue" ||
                    //     objectCreator.Identifier.ToString()=="HttpCookie" )
                    Console.WriteLine(declarator.Span.Start+" : "+ declarator.Identifier.ToString() + " " + objectCreator.Type);
                }
            }
            return insecureCookies;
        }
    }
}