using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System;
using System.Text.RegularExpressions;

namespace ASTTask
{
    internal class CredsFinder
    {
        static string[] SecretKeywords=new string[] {@"\w*password\w*",@"\w*pass\w*",@"\w*secret\w*",@"\w*key\w*"};
        //static string[] SecretKeywords=new string[] {@"\w*password\w*",@"\w*pass\w*",@"\w*secret\w*",@"\w*key\w*"};
        static Dictionary<string,string> secretPatterns = new Dictionary<string, string>{
            {"AWS_ACCESS_KEY_ID","(?=.*[A-Z])(?=.*[0-9])[A-Z0-9]{20}"},
            {"AWS_SECRET_ACCESS_KEY","(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])[A-Za-z0-9+/]{40}"}
            };
        public static List<SyntaxNodeOrToken> FindHardcodeCredentials(SyntaxNodeOrToken nodeOrToken)
        {
            //Calling method to find all hardcode strings
            List<SyntaxNodeOrToken> secretStrings=new List<SyntaxNodeOrToken>();
            List<SyntaxNodeOrToken> hardcoreStringNodes= FindHardcodeStrings(nodeOrToken);

            //Checking strings are Passwords, secret keys or not.
            foreach (var item in hardcoreStringNodes)
            {
                VariableDeclarationSyntax variableDeclarationSyntax= (VariableDeclarationSyntax)item;
                foreach (var varItem in variableDeclarationSyntax.Variables)
                {
                    //Calling method  to find identifier is password/secret or not.
                    if(IsPasswordIdentifier(varItem.Identifier.ToString()))
                        secretStrings.Add(varItem);

                    if(varItem.ChildNodesAndTokens().Count>1)
                    //Calling method  to find value is password/secret or not.
                    if(IsPasswordValue(varItem.ChildNodesAndTokens()[1].ChildNodesAndTokens()[1].ToString()))
                        secretStrings.Add(varItem.ChildNodesAndTokens()[1].ChildNodesAndTokens()[1]);
                }
            }
            return secretStrings;
        }

        //Method to check identifier is matches with secret keywords patterns
        public static bool IsPasswordIdentifier(string stringIdentifier)
        {
            foreach (var SecretKeywordItem in SecretKeywords)
            {
                if(Regex.IsMatch(stringIdentifier.ToLower(),SecretKeywordItem))
                    return true;
            }
            return false;
        }

        //Method to check value is matches with secret patterns
        public static bool IsPasswordValue(string stringValue)
        {
            foreach (var pattern in secretPatterns)
            {
                //Console.WriteLine(stringIdentifier.ToLower()+" : "+SecretKeywordItem);
                if(Regex.IsMatch(stringValue,pattern.Value))
                    return true;
            }
            return false;
        }

        private static List<SyntaxNodeOrToken> FindHardcodeStrings(SyntaxNodeOrToken nodeOrToken)
        {
            //Finding all hardcode strings
            List<SyntaxNodeOrToken> result=new List<SyntaxNodeOrToken>();
            foreach (SyntaxNodeOrToken child in nodeOrToken.ChildNodesAndTokens())
            {
                //Finding string variable declarations
                if(child.Kind() == SyntaxKind.VariableDeclaration &&
                (((VariableDeclarationSyntax)child).Type.ToString() == "string"||
                ((VariableDeclarationSyntax)child).Type.ToString() == "String"
                ))
                    result.Add(child);
                else
                    result.AddRange(FindHardcodeStrings(child));
            }
            return result;
        }
    }
}