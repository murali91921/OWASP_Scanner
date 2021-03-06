using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Mapper;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace SAST.Engine.CSharp.Scanners
{
    /// <summary>
    /// This Scanner to find Hardcoded Credential Vulnerabilities.<br></br>
    /// For references <see href="https://github.com/dxa4481/truffleHogRegexes/blob/master/truffleHogRegexes/regexes.json"/>,<br></br>
    /// <see href="https://github.com/l4yton/RegHex"/>
    /// </summary>
    internal class CredsFinder : IScanner
    {
        static readonly string[] SecretKeywords = new string[] {
            @"\w*(password|passwd|pwd|pass)\w*",
            @"\w*secret\w*",
            @"\w*key\w*",
            @".*(api|gitlab|github|slack|google|client)_?(key|token|secret)$"};
        static readonly Dictionary<string, string> secretPatterns = new Dictionary<string, string>{
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
            {"Slack Token","xox[baprs]-([0-9a-zA-Z]{10,48})?"},
            {"Twitter Oauth","[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]"},
            {"Twitter Secret Key","(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}"},
        };

        List<SyntaxNode> secretStrings = new List<SyntaxNode>();
        List<SyntaxTrivia> secretComments = new List<SyntaxTrivia>();
        SemanticModel model;
        Solution solution;
        SyntaxNode syntaxNode;

        /// <summary>
        /// Finding the Hardcoded strings in <paramref name="variableDeclarator"/>
        /// </summary>
        /// <param name="variableDeclarator"></param>
        private void FindHardcodeStringNodes(VariableDeclaratorSyntax variableDeclarator)
        {
            // Finding sensitive variable names
            // Variable name should matches with keywords, and variable value is not empty,and expression should have Literal("").
            ISymbol symbol = model.GetDeclaredSymbol(variableDeclarator);
            if (symbol == null)
                return;

            //VariableDeclarationSyntax declarationSyntax = variableDeclarator.AncestorsAndSelf().OfType<VariableDeclarationSyntax>().FirstOrDefault();
            //if (declarationSyntax == null)
            //    return;
            ITypeSymbol typeSymbol = symbol.GetTypeSymbol();
            if (typeSymbol == null || typeSymbol.SpecialType != SpecialType.System_String)
                return;

            if (variableDeclarator.Initializer != null && variableDeclarator.Initializer is EqualsValueClauseSyntax equalsValue
            && equalsValue.Value.IsKind(SyntaxKind.StringLiteralExpression))
            {
                var literalExpression = equalsValue.Value;
                if (!string.IsNullOrEmpty(literalExpression.ToString().Trim('"', ' ')))
                    if (/*IsSecretVariable(symbol.Name) || */IsSecretValue(literalExpression.ToString()))
                        secretStrings.Add(variableDeclarator);
            }
            var references = SymbolFinder.FindReferencesAsync(symbol, solution).Result;
            foreach (var reference in references)
            {
                foreach (var referenceLocation in reference.Locations)
                {
                    string stringValue = string.Empty;
                    var presentStatement = referenceLocation.Location.SourceTree.GetRoot().FindNode(referenceLocation.Location.SourceSpan).Parent;
                    if (presentStatement is AssignmentExpressionSyntax assignment && assignment.Right.IsKind(SyntaxKind.StringLiteralExpression))
                    {
                        stringValue = assignment.Right.ToString();
                        if (!string.IsNullOrEmpty(stringValue.Trim('"', ' ')))
                            if (/*IsSecretVariable(symbol.Name) || */IsSecretValue(stringValue.ToString()))
                                secretStrings.Add(presentStatement);
                    }
                    //else if (presentStatement is BinaryExpressionSyntax binaryExpression && !presentStatement.Parent.IsKind(SyntaxKind.Argument))
                    //{
                    //    if (((binaryExpression.Right is LiteralExpressionSyntax && binaryExpression.Left is IdentifierNameSyntax)
                    //    || (binaryExpression.Left is LiteralExpressionSyntax && binaryExpression.Right is IdentifierNameSyntax)))
                    //    {
                    //        stringValue = (binaryExpression.Right is LiteralExpressionSyntax) ? binaryExpression.Right.ToString() : binaryExpression.Left.ToString();
                    //        if (!string.IsNullOrEmpty(stringValue.Trim('"', ' ')))
                    //            if (IsSecretVariable(symbol.Name))
                    //                secretStrings.Add(presentStatement);
                    //    }
                    //}
                }
            }
        }

        /// <summary>
        /// This method will check <paramref name="variable"/> is matches with patterns
        /// </summary>
        /// <param name="variable"></param>
        /// <returns></returns>
        private static bool IsSecretVariable(string variable)
        {
            foreach (var SecretKeywordItem in SecretKeywords)
                if (Regex.IsMatch(variable, SecretKeywordItem, RegexOptions.IgnoreCase))
                    return true;
            return false;
        }

        /// <summary>
        /// This method will check <paramref name="stringValue"/> is matches with Patterns
        /// </summary>
        /// <param name="stringValue"></param>
        /// <returns></returns>
        private static bool IsSecretValue(string stringValue)
        {
            foreach (var pattern in secretPatterns)
                if (Regex.IsMatch(stringValue, pattern.Value))
                    return true;
            return false;
        }

        /// <summary>
        /// This method will returns text in <paramref name="commentNode"/>
        /// </summary>
        /// <param name="commentNode"></param>
        /// <returns></returns>
        private string FindCommentText(SyntaxTrivia commentNode)
        {
            string commentText = string.Empty;
            switch (commentNode.Kind())
            {
                case SyntaxKind.SingleLineCommentTrivia:
                    commentText = commentNode.ToString().TrimStart('/');
                    break;
                case SyntaxKind.MultiLineCommentTrivia:
                    commentText = commentNode.ToString();
                    commentText = commentText.Substring(2, commentText.Length - 4);
                    break;
            }
            return commentText;
        }

        /// <summary>
        /// This method will return Comment Nodes in <paramref name="rootNode"/>
        /// </summary>
        /// <param name="rootNode"></param>
        /// <returns>List of Comment Trivia</returns>
        private List<SyntaxTrivia> FindComments(SyntaxNode rootNode)
        {
            List<SyntaxTrivia> hardcodeComments = new List<SyntaxTrivia>();
            var commentNodes = from commentNode in rootNode.DescendantTrivia()
                               where commentNode.IsKind(SyntaxKind.MultiLineCommentTrivia) || commentNode.IsKind(SyntaxKind.SingleLineCommentTrivia)
                               select commentNode;
            foreach (var commentNode in commentNodes)
            {
                string commentText = FindCommentText(commentNode);
                if (!commentText.Trim().Equals(string.Empty))
                    hardcodeComments.Add(commentNode);
            }
            return hardcodeComments;
        }

        /// <summary>
        /// This method will find Vulnerabilities in <paramref name="syntaxNode"/>
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model, Solution solution = null)
        {
            this.model = model;
            this.syntaxNode = syntaxNode;
            this.solution = solution;
            var variableDeclarators = syntaxNode.DescendantNodes().OfType<VariableDeclaratorSyntax>();
            //Checking strings are Passwords, secret keys or not.
            foreach (var variableDeclarator in variableDeclarators)
                FindHardcodeStringNodes(variableDeclarator);

            //Finding Sensitive comments
            List<SyntaxTrivia> commentNodes = FindComments(syntaxNode);
            foreach (var commentNode in commentNodes)
            {
                string commentText = FindCommentText(commentNode);
                if (IsSecretValue(commentText))
                    secretComments.Add(commentNode);
            }
            var vulnerabilityList = Map.ConvertToVulnerabilityList(filePath, secretStrings, ScannerType.HardcodePassword);
            vulnerabilityList.AddRange(Map.ConvertToVulnerabilityList(filePath, secretComments, ScannerType.HardcodePassword));
            return vulnerabilityList;
        }
    }
}