using System.Collections;
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace ASTTask
{
    internal class CredsFinder
    {
        static string[] SecretKeywords=new string[] {
            @"\w*(password|passwd|pwd|pass)\w*",
            @"\w*secret\w*",
            @"\w*key\w*",
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

        public static Tuple<List<SyntaxNodeOrToken>,List<SyntaxTrivia>> FindHardcodeCredentials(string filePath, SyntaxNode rootNode)
        {
            // Creating Adhoc Workspace
            var workspace = new AdhocWorkspace();
            var solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Create());
            var project = workspace.AddProject("CredsFinder", "C#");
            project = project.AddMetadataReference(MetadataReference.CreateFromFile(filePath));
            workspace.TryApplyChanges(project.Solution);
            var document = workspace.AddDocument(project.Id, "CredsFinder",SourceText.From(rootNode.ToString()));
            var model = document.GetSemanticModelAsync().Result;
            rootNode = document.GetSyntaxRootAsync().Result;

            List<SyntaxNodeOrToken> secretStrings=new List<SyntaxNodeOrToken>();
            List<SyntaxTrivia> secretComments = new List<SyntaxTrivia>();

            // List<SyntaxNodeOrToken> hardcoreStringNodes= FindHardcodeStrings(rootNode);
            IEnumerable<VariableDeclaratorSyntax> hardcoreStringNodes= rootNode.DescendantNodes().OfType<VariableDeclaratorSyntax>();
            //Checking strings are Passwords, secret keys or not.
            foreach (var item in hardcoreStringNodes)
            {
                // VariableDeclarationSyntax variableDeclarationSyntax = (VariableDeclarationSyntax)item;
                // foreach (var varItem in variableDeclarationSyntax.Variables)
                {
                    // Finding sensitive variable names
                    // Variable name should matches with keywords, and variable value is not empty,and expression  should have Literal("").
                    ISymbol symbol = model.GetDeclaredSymbol(item);
                    TypeInfo typeInfo = model.GetTypeInfo(item);
                    if(symbol != null)
                    {
                        bool isString = (symbol is IFieldSymbol && (symbol as IFieldSymbol).Type.ToString().ToLower()=="string")
                                    || (symbol is ILocalSymbol && (symbol as ILocalSymbol).Type.ToString().ToLower()=="string");
                        if(isString)
                        {
                            if(item.Initializer!=null && item.Initializer is EqualsValueClauseSyntax)
                            {
                                if((item.Initializer as EqualsValueClauseSyntax).Value is LiteralExpressionSyntax)
                                {
                                    var literalExpression=(item.Initializer as EqualsValueClauseSyntax).Value as LiteralExpressionSyntax;
                                    if(!string.IsNullOrEmpty(literalExpression.ToString().Trim('"',' ')))
                                            secretStrings.Add(item);
                                }
                            }
                            var references = SymbolFinder.FindReferencesAsync(symbol,document.Project.Solution).Result;
                            List<SyntaxNode> allStatements = new List<SyntaxNode>();
                            foreach (var reference in references)
                            {
                                foreach (var referenceLocation in reference.Locations)
                                {
                                    string stringValue = string.Empty;
                                    // Console.WriteLine(rootNode.FindNode(referenceLocation.Location.SourceSpan).Parent);
                                    var presentStatement = rootNode.FindNode(referenceLocation.Location.SourceSpan).Parent;
                                    if(presentStatement is AssignmentExpressionSyntax &&  (presentStatement as AssignmentExpressionSyntax).Right is LiteralExpressionSyntax)
                                    {
                                        stringValue = (presentStatement as AssignmentExpressionSyntax).Right.ToString();
                                        if(!string.IsNullOrEmpty(stringValue.Trim('"',' ')))
                                            secretStrings.Add(presentStatement);
                                    }
                                    else if(presentStatement is BinaryExpressionSyntax)
                                    {
                                        BinaryExpressionSyntax condition = presentStatement as BinaryExpressionSyntax;
                                        if(((condition.Right is LiteralExpressionSyntax && condition.Left is IdentifierNameSyntax)
                                        ||(condition.Left is LiteralExpressionSyntax && condition.Right is IdentifierNameSyntax)))
                                        {
                                            stringValue = (condition.Right is LiteralExpressionSyntax) ? condition.Right.ToString() : condition.Left.ToString();
                                            if(!string.IsNullOrEmpty(stringValue.Trim('"',' ')))
                                                secretStrings.Add(presentStatement);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Finding sensitive stored values
                    // if(varItem.ChildNodesAndTokens().Count>1 &&  IsSecretValue(varItem.ChildNodesAndTokens()[1].ChildNodesAndTokens()[1].ToString()))
                    //     secretStrings.Add(varItem.ChildNodesAndTokens()[1].ChildNodesAndTokens()[1]);
                }
            }
            //Finding Sensitive comments
            List<SyntaxTrivia> commentNodes = FindComments(rootNode);
            foreach (var item in commentNodes)
            {
                string commentText = "";
                switch (item.Kind())
                {
                    case SyntaxKind.SingleLineCommentTrivia:
                        commentText = item.ToString().TrimStart('/');
                        break;
                    case SyntaxKind.MultiLineCommentTrivia:
                        commentText = item.ToString();
                        commentText = commentText.Substring(2, commentText.Length-4);
                        break;
                }
                if(IsSecretValue(commentText))
                    secretComments.Add(item);
            }
            return Tuple.Create(secretStrings,secretComments);
        }

        //Check string variable name matches with secret keywords patterns
        public static bool IsSecretVariable(string variable)
        {
            foreach (var SecretKeywordItem in SecretKeywords)
            {
                if(Regex.IsMatch(variable,SecretKeywordItem,RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        //Check string value is matches with secret patterns
        public static bool IsSecretValue(string stringValue)
        {
            foreach (var pattern in secretPatterns)
            {
                if(Regex.IsMatch(stringValue,pattern.Value))
                {
                    //Console.WriteLine("{0} : {1}",stringValue,pattern.Value);
                    return true;
                }
            }
            return false;
        }

        //Finding non-empty single/multi line comments in source code
        private static List<SyntaxTrivia> FindComments(SyntaxNode rootNode)
        {
            List<SyntaxTrivia> hardcodeComments=new List<SyntaxTrivia>();
            var commentNodes = from commentNode in rootNode.DescendantTrivia()
            where commentNode.IsKind(SyntaxKind.MultiLineCommentTrivia) || commentNode.IsKind(SyntaxKind.SingleLineCommentTrivia)
            select commentNode;
            foreach (var commentNode in commentNodes)
            {
                string commentText = "";
                switch (commentNode.Kind())
                {
                    case SyntaxKind.SingleLineCommentTrivia:
                        commentText = commentNode.ToString().TrimStart('/');
                        break;
                    case SyntaxKind.MultiLineCommentTrivia:
                        commentText = commentNode.ToString();
                        commentText = commentText.Substring(2, commentText.Length-4);
                        break;
                }
                if(!commentText.Trim().Equals(string.Empty))
                    hardcodeComments.Add(commentNode);
            }
            return hardcodeComments;
        }
        private static List<SyntaxNodeOrToken> FindHardcodeStrings(SyntaxNode rootNode)
        {
            //Finding all hardcode strings
            List<SyntaxNodeOrToken> result=new List<SyntaxNodeOrToken>();
            var stringNodes = from stringNode in ((SyntaxNode)rootNode).DescendantNodes()
                                where stringNode.IsKind(SyntaxKind.VariableDeclaration)
                                select stringNode;
            foreach (SyntaxNode child in stringNodes)
            {
                //Finding string variable declarations
                if((((VariableDeclarationSyntax)child).Type.ToString() == "string"|| ((VariableDeclarationSyntax)child).Type.ToString() == "String")
                /*&& child.ChildNodesAndTokens()[1].ChildNodesAndTokens().Count>1*/)
                {
                    result.Add(child);
                }
            }
            return result;
        }
    }
}