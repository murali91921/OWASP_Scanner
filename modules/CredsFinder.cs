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
        static string[] SecretKeywords=new string[] {@".*(password|passwd|pwd|)$",@"\w*secret\w*",@"\w*key\w*",
                            @".*(api|gitlab|github|slack|google|client)_?(key|token|secret)$"};
        // https://github.com/dxa4481/truffleHogRegexes/blob/master/truffleHogRegexes/regexes.json
        // https://github.com/l4yton/RegHex
        static Dictionary<string,string> secretPatterns = new Dictionary<string, string>{
            {"Slack Token 32","(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"},
            {"RSA private key","-----BEGIN RSA PRIVATE KEY-----"},
            {"SSH (DSA) private key","-----BEGIN DSA PRIVATE KEY-----"},
            {"SSH (EC) private key","-----BEGIN EC PRIVATE KEY-----"},
            {"PGP private key block","-----BEGIN PGP PRIVATE KEY BLOCK-----"},
            {"Amazon AWS Access Key ID","AKIA[0-9A-Z]{16}"},
            {"Facebook Access Token","EAACEdEose0cBA[0-9A-Za-z]+"},
            {"Facebook OAuth","[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]"},
            {"GitHub","[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]"},
            {"Generic API Key","[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]"},
            {"Generic Secret","[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]"},
            {"Google API Key","AIza[0-9A-Za-z\\-_]{35}"},
            {"Google Gmail API Key","AIza[0-9A-Za-z\\-_]{35}"},
            {"Google Gmail OAuth","[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com"},
            {"Google OAuth Access Token","ya29\\.[0-9A-Za-z\\-_]+"},
            {"Heroku API Key","[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"},
            {"MailChimp API Key","[0-9a-f]{32}-us[0-9]{1,2}"},
            {"Mailgun API Key","key-[0-9a-zA-Z]{32}"},
            {"Password in URL","[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]"},
            {"PayPal Braintree Access Token","access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"},
            {"Picatic API Key","sk_live_[0-9a-z]{32}"},
            {"Slack Webhook","https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"},
            {"Stripe API Key","sk_live_[0-9a-zA-Z]{24}"},
            {"Stripe Restricted API Key","rk_live_[0-9a-zA-Z]{24}"},
            {"Square Access Token","sq0atp-[0-9A-Za-z\\-_]{22}"},
            {"Square OAuth Secret","sq0csp-[0-9A-Za-z\\-_]{43}"},
            {"Twilio API Key","SK[0-9a-fA-F]{32}"},

            {"Artifactory API Token","(?:\\s|=|:|\"|^)AKC[a-zA-Z0-9]{10,}"},
            {"Artifactory Password","(?:\\s|=|:|\"|^)AP[\\dABCDEF][a-zA-Z0-9]{8,}"},
            {"Authorization Basic","basic [a-zA-Z0-9_\\-:\\.=]+"},
            {"Authorization Bearer","bearer [a-zA-Z0-9_\\-\\.=]+"},
            {"AWS Client ID","(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"},
            {"AWS Secret Key","(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\\/+]{40}['\"]"},
            {"Base64","(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+/]+={0,2}"},
            {"Cloudinary Basic Auth","cloudinary:\\/\\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+"},
            {"Facebook Client ID","(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}"},
            {"Facebook Secret Key","(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}"},
            {"Google Cloud Platform API","(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]"},
            {"LinkedIn Client ID","(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]"},
            {"LinkedIn Secret Key","(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]"},
            //{"MD5 Hash","[a-f0-9]{32}"},
            {"Slack Token","xox[baprs]-([0-9a-zA-Z]{10,48})?"},
            {"Twitter Oauth","[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]"},
            {"Twitter Secret Key","(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}"},
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
                    // Calling method  to find identifier is password/secret or not.
                    if(IsPasswordIdentifier(varItem.Identifier.ToString()))
                        secretStrings.Add(varItem);

                    // Calling method to find value is matching with secret patterns.
                    if(varItem.ChildNodesAndTokens().Count>1)
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
                if(Regex.IsMatch(stringIdentifier,SecretKeywordItem))
                    return true;
            }
            return false;
        }

        //Method to check value is matches with secret patterns
        public static bool IsPasswordValue(string stringValue)
        {
            foreach (var pattern in secretPatterns)
            {
                if(Regex.IsMatch(stringValue,pattern.Value))
                {
                    //Console.WriteLine(pattern.Key,pattern.Value);
                    return true;
                }
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
                ((VariableDeclarationSyntax)child).Type.ToString() == "String") &&
                child.ChildNodesAndTokens().Count>2)
                    result.Add(child);
                else
                    result.AddRange(FindHardcodeStrings(child));
            }
            return result;
        }
    }
}