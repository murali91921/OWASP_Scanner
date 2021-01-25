using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.FindSymbols;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Mapper;
using System;
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
        private static readonly string MessageFormatCredential = @"""{0}"" detected here, make sure this is not a hard-coded credential.";
        private static readonly string MessageUriUserInfo = "Review this hard-coded URI, which contain credentials.";
        private static readonly string DefaultCredentialWords = "password, passwd, pwd, passphrase";
        private static readonly Regex passwordValuePattern;
        private static readonly string Rfc3986_Unreserved = "-._~";
        private static readonly string Rfc3986_Pct = "%";
        private static readonly string Rfc3986_SubDelims = "!$&'()*+,;=";
        private static readonly string UriPasswordSpecialCharacters = Rfc3986_Unreserved + Rfc3986_Pct + Rfc3986_SubDelims;
        private static readonly char CredentialSeparator = ';';
        private static readonly string uriUserInfoPart = @"[\w\d" + Regex.Escape(UriPasswordSpecialCharacters) + @"]+";
        private static readonly Regex uriUserInfoPattern = new Regex(@"\w+:\/\/(?<Login>" + uriUserInfoPart + "):(?<Password>" + uriUserInfoPart + ")@", RegexOptions.Compiled);
        private static readonly Regex validCredentialPattern = new Regex(@"^\?|:\w+|\{\d+[^}]*\}|""|'$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private static IEnumerable<string> splitCredentialWords;

        private string _filePath;
        static CredsFinder()
        {
            splitCredentialWords = DefaultCredentialWords.ToUpperInvariant()
                   .Split(',')
                   .Select(x => x.Trim())
                   .Where(x => x.Length != 0)
                   .ToList();
            passwordValuePattern = new Regex(string.Format(@"\b(?<credential>{0})\s*[:=]\s*(?<suffix>.+)$",
                    string.Join("|", splitCredentialWords.Select(Regex.Escape))), RegexOptions.Compiled | RegexOptions.IgnoreCase);
        }

        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model, Solution solution = null)
        {
            _filePath = filePath;
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            FindVariableDeclarators(syntaxNode, model, ref vulnerabilities);
            FindAssignments(syntaxNode, model, ref vulnerabilities);
            FindStringLiterals(syntaxNode, model, ref vulnerabilities);
            FindAddExpressions(syntaxNode, model, ref vulnerabilities);
            FindInterpolatedStrings(syntaxNode, model, ref vulnerabilities);
            //FindInvocations(syntaxNode, model, ref vulnerabilities);
            if (vulnerabilities.Any())
                vulnerabilities.ForEach(vul => vul.FilePath = filePath);
            return vulnerabilities;
        }

        private void FindVariableDeclarators(SyntaxNode syntaxNode, SemanticModel model, ref List<VulnerabilityDetail> vulnerabilities)
        {
            var variableDeclarators = syntaxNode.DescendantNodes().OfType<VariableDeclaratorSyntax>();
            foreach (var declarator in variableDeclarators)
            {
                if (!IsStringType(declarator, model))
                    continue;
                string variableValue = declarator.Initializer?.Value.GetStringValue(); ;
                if (string.IsNullOrWhiteSpace(variableValue) || variableValue.Contains(" "))
                    continue;
                var bannedWords = FindCredentialWords(declarator.Identifier.ValueText, variableValue);
                if (bannedWords.Any())
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, declarator, ScannerType.HardcodePassword, string.Format(MessageFormatCredential, bannedWords.JoinStr(", "))));
                else if (ContainsUriUserInfo(variableValue))
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, declarator, ScannerType.HardcodePassword, MessageUriUserInfo));
            }
        }

        private void FindAssignments(SyntaxNode syntaxNode, SemanticModel model, ref List<VulnerabilityDetail> vulnerabilities)
        {
            var assignments = syntaxNode.DescendantNodes().OfType<AssignmentExpressionSyntax>();
            foreach (var assignment in assignments)
            {
                if (!IsStringType(assignment, model))
                    continue;
                string variableValue = assignment.Right.GetStringValue();
                if (string.IsNullOrWhiteSpace(variableValue) || variableValue.Contains(" "))
                    continue;
                var bannedWords = FindCredentialWords((assignment.Left as IdentifierNameSyntax)?.Identifier.ValueText, variableValue);
                if (bannedWords.Any())
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, assignment, ScannerType.HardcodePassword, string.Format(MessageFormatCredential, bannedWords.JoinStr(", "))));
                else if (ContainsUriUserInfo(variableValue))
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, assignment, ScannerType.HardcodePassword, MessageUriUserInfo));
            }
        }

        private void FindStringLiterals(SyntaxNode syntaxNode, SemanticModel model, ref List<VulnerabilityDetail> vulnerabilities)
        {
            var literals = syntaxNode.DescendantNodes().OfType<LiteralExpressionSyntax>().Where(obj => obj.IsKind(SyntaxKind.StringLiteralExpression));
            foreach (var literal in literals)
            {
                if (!ShouldConsider(literal, model))
                    continue;
                string variableValue = literal.GetStringValue();
                if (string.IsNullOrWhiteSpace(variableValue) || variableValue.Contains(" "))
                    continue;
                var bannedWords = FindCredentialWords(null, variableValue);
                if (bannedWords.Any())
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, literal, ScannerType.HardcodePassword, string.Format(MessageFormatCredential, bannedWords.JoinStr(", "))));

                else if (ContainsUriUserInfo(variableValue))
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, literal, ScannerType.HardcodePassword, MessageUriUserInfo));
            }
        }

        private void FindAddExpressions(SyntaxNode syntaxNode, SemanticModel model, ref List<VulnerabilityDetail> vulnerabilities)
        {
            var binaryExpressions = syntaxNode.DescendantNodes().OfType<BinaryExpressionSyntax>().Where(obj => obj.IsKind(SyntaxKind.AddExpression));
            foreach (var binaryExpression in binaryExpressions)
            {
                var left = binaryExpression.Left is BinaryExpressionSyntax precedingAdd && precedingAdd.IsKind(SyntaxKind.AddExpression) ? precedingAdd.Right : binaryExpression.Left;
                var leftConst = model.GetConstantValue(left);
                if (!leftConst.HasValue || !(leftConst.Value is string leftValue))
                    continue;
                var rightConst = model.GetConstantValue(binaryExpression.Right);
                if (!rightConst.HasValue || !(rightConst.Value is string rightValue))
                    continue;

                string variableValue = leftValue + rightValue;

                if (string.IsNullOrWhiteSpace(variableValue) || variableValue.Contains(" "))
                    continue;

                var bannedWords = FindCredentialWords(null, variableValue);
                if (bannedWords.Any())
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, binaryExpression, ScannerType.HardcodePassword, string.Format(MessageFormatCredential, bannedWords.JoinStr(", "))));
                else if (ContainsUriUserInfo(variableValue))
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, binaryExpression, ScannerType.HardcodePassword, MessageUriUserInfo));
            }
        }

        private void FindInterpolatedStrings(SyntaxNode syntaxNode, SemanticModel model, ref List<VulnerabilityDetail> vulnerabilities)
        {

            var interpolatedStrings = syntaxNode.DescendantNodes().OfType<InterpolatedStringExpressionSyntax>();
            foreach (var interpolatedString in interpolatedStrings)
            {
                string variableValue = interpolatedString.Contents.JoinStr(null, x => x switch
                {
                    InterpolationSyntax interpolation => model.GetConstantValue(interpolation.Expression) is { } optional
                        && optional.HasValue && optional.Value is string value ? value : null,
                    InterpolatedStringTextSyntax text => text.TextToken.ToString(),
                    _ => null
                } ?? CredentialSeparator.ToString());

                if (string.IsNullOrWhiteSpace(variableValue) || variableValue.Contains(" "))
                    continue;

                var bannedWords = FindCredentialWords(null, variableValue);
                if (bannedWords.Any())
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, interpolatedString, ScannerType.HardcodePassword, string.Format(MessageFormatCredential, bannedWords.JoinStr(", "))));
                else if (ContainsUriUserInfo(variableValue))
                    vulnerabilities.Add(VulnerabilityDetail.Create(_filePath, interpolatedString, ScannerType.HardcodePassword, MessageUriUserInfo));
            }
        }

        //private void FindInvocations(SyntaxNode syntaxNode, SemanticModel model, ref List<VulnerabilityDetail> vulnerabilities)
        //{
        //    var invocations = syntaxNode.DescendantNodes().OfType<InvocationExpressionSyntax>();
        //    foreach (var invocation in invocations)
        //    {
        //        string variableValue;


        //        var allArgs = invocation.ArgumentList.Arguments.Select(x
        //            => model.GetConstantValue(x.Expression) is { } optional && optional.Value is string constValue ? constValue : CredentialSeparator.ToString());
        //        if (!allArgs.Any())
        //            continue;
        //        try
        //        {
        //            variableValue = string.Format(allArgs.First(), allArgs.Skip(1).ToArray());
        //        }
        //        catch (FormatException)
        //        {
        //            variableValue = null;
        //        }
        //        if (string.IsNullOrWhiteSpace(variableValue))
        //            continue;

        //        var bannedWords = FindCredentialWords(null, variableValue);
        //        if (bannedWords.Any())
        //        {
        //            vulnerabilities.Add(new VulnerabilityDetail()
        //            {
        //                CodeSnippet = invocation.ToString(),
        //                LineNumber = Map.GetLineNumber(invocation),
        //                Type = ScannerType.HardcodePassword,
        //                Description = string.Format(MessageFormatCredential, bannedWords.JoinStr(", "))
        //            });
        //        }
        //        else if (ContainsUriUserInfo(variableValue))
        //        {
        //            vulnerabilities.Add(new VulnerabilityDetail()
        //            {
        //                CodeSnippet = invocation.ToString(),
        //                LineNumber = Map.GetLineNumber(invocation),
        //                Type = ScannerType.HardcodePassword,
        //                Description = MessageUriUserInfo
        //            });
        //        }
        //    }
        //}

        private static bool IsStringType(VariableDeclaratorSyntax declarator, SemanticModel model) =>
            declarator.Initializer?.Value is LiteralExpressionSyntax literalExpression
            && literalExpression.IsKind(SyntaxKind.StringLiteralExpression)
            && model.GetDeclaredSymbol(declarator) is ISymbol symbol
            && symbol != null
            && symbol.GetTypeSymbol() is ITypeSymbol typeSymbol
            && typeSymbol != null
            && typeSymbol.SpecialType == SpecialType.System_String;

        private static bool IsStringType(AssignmentExpressionSyntax assignment, SemanticModel model) =>
        assignment.IsKind(SyntaxKind.SimpleAssignmentExpression)
        && assignment.Right.IsKind(SyntaxKind.StringLiteralExpression)
        && model.GetTypeSymbol(assignment.Left) is ITypeSymbol typesymbol
        && typesymbol != null
        && typesymbol.SpecialType == SpecialType.System_String;

        private static bool ShouldConsider(LiteralExpressionSyntax literal, SemanticModel semanticModel) =>
            literal.IsKind(SyntaxKind.StringLiteralExpression) &&
            ShouldConsider(literal.GetTopMostContainingMethod(), literal, semanticModel);

        private static bool ShouldConsider(SyntaxNode method, SyntaxNode current, SemanticModel semanticModel)
        {
            while (current != null && current != method)
            {
                switch (current.Kind())
                {
                    case SyntaxKind.VariableDeclarator:
                    case SyntaxKind.SimpleAssignmentExpression:
                    case SyntaxKind.InvocationExpression:
                    case SyntaxKind.AddExpression:
                        return false;
                    case SyntaxKind.Argument:
                        return !(current.Parent.Parent is InvocationExpressionSyntax invocation && invocation.IsMethodInvocation(Constants.KnownType.System_String, "Format", semanticModel));
                    default:
                        current = current.Parent;
                        break;
                }
            }
            return true;
        }

        private IEnumerable<string> FindCredentialWords(string variableName, string variableValue)
        {
            var credentialWordsFound = variableName
                .SplitToWords()
                .Intersect(splitCredentialWords)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (credentialWordsFound.Any(x => variableValue.IndexOf(x, StringComparison.InvariantCultureIgnoreCase) >= 0))
                return Enumerable.Empty<string>();

            var match = passwordValuePattern.Match(variableValue);
            if (match.Success)
            {
                if (!IsValidCredential(match.Groups["suffix"].Value))
                    credentialWordsFound.Add(match.Groups["credential"].Value);
            }
            else if (secretPatterns.Any(pattern => Regex.IsMatch(variableValue, pattern.Value)))
                credentialWordsFound.Add(variableValue);
            return credentialWordsFound.Select(x => x.ToLowerInvariant());
        }

        private bool ContainsUriUserInfo(string variableValue)
        {
            var match = uriUserInfoPattern.Match(variableValue);
            return match.Success
                && match.Groups["Password"].Value is { } password
                && !string.Equals(match.Groups["Login"].Value, password, System.StringComparison.OrdinalIgnoreCase)
                && password != CredentialSeparator.ToString()
                && !validCredentialPattern.IsMatch(password);
        }

        private bool IsValidCredential(string suffix)
        {
            var candidateCredential = suffix.Split(CredentialSeparator).First().Trim();
            return string.IsNullOrWhiteSpace(candidateCredential) || validCredentialPattern.IsMatch(candidateCredential);
        }

        static readonly Dictionary<string, string> secretPatterns = new Dictionary<string, string>{
            {"Slack Token 32","(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"},
            {"RSA private key","-----BEGIN RSA PRIVATE KEY-----"},
            {"SSH (DSA) private key","-----BEGIN DSA PRIVATE KEY-----"},
            {"SSH (EC) private key","-----BEGIN EC PRIVATE KEY-----"},
            {"PGP private key block","-----BEGIN PGP PRIVATE KEY BLOCK-----"},
            {"OPENSSH private key","-----BEGIN OPENSSH PRIVATE KEY-----" },
            {"Private key","-----BEGIN PRIVATE KEY-----"},
            {"public","-----BEGIN PUBLIC KEY-----"},
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
    }
}