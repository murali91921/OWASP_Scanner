using Microsoft.CodeAnalysis;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Models;
using System.Collections.Generic;
using System.IO;

namespace SAST.Engine.CSharp.Mapper
{
    public static class Map
    {
        public static List<VulnerabilityDetail> ConvertToVulnerabilityList<T>(string filePath, List<T> syntaxList, ScannerType type, ScannerSubType scannerSubType = ScannerSubType.None)
        {
            var vulnerabilityList = new List<VulnerabilityDetail>();
            if (syntaxList == null || syntaxList.Count == 0)
                return vulnerabilityList;
            if (syntaxList is List<SASTCookie> astCookie)
                ConvertFromSASTCookie<T>(filePath, astCookie, vulnerabilityList);
            else if (syntaxList is List<SyntaxNode> syntaxNodeList)
                foreach (var item in syntaxNodeList)
                {
                    vulnerabilityList.Add(new VulnerabilityDetail
                    {
                        FilePath = filePath,
                        CodeSnippet = item.ToString(),
                        LineNumber = GetLineNumber(item),
                        Type = type.ToString(),
                        Vulnerability = scannerSubType == ScannerSubType.None ? type.ToString() : scannerSubType.ToString()
                    });
                }
            else if (syntaxList is List<SyntaxTrivia> syntaxTriviaList)
                foreach (var item in syntaxTriviaList)
                {
                    vulnerabilityList.Add(new VulnerabilityDetail
                    {
                        FilePath = filePath,
                        CodeSnippet = item.ToString(),
                        LineNumber = GetLineNumber(item),
                        Type = ScannerType.InsecureCookie.ToString(),
                        Vulnerability = ScannerType.InsecureCookie.ToString()
                    });
                }
            return vulnerabilityList;
        }

        private static void ConvertFromSASTCookie<T>(string filePath, List<SASTCookie> astCookie, List<VulnerabilityDetail> vulnerabilityList)
        {
            foreach (var item in astCookie)
            {
                string missing = "";
                if (!item.IsHttpOnly)
                    missing = "HttpOnly";
                if (!item.IsSecure)
                    missing = string.IsNullOrEmpty(missing) ? "Secure" : (missing + ", Secure");
                missing += " Flag(s) missing ";

                vulnerabilityList.Add(new VulnerabilityDetail
                {
                    FilePath = filePath,
                    CodeSnippet = item.CookieStatement.ToString(),
                    LineNumber = GetLineNumber(item.CookieStatement),
                    Type = ScannerType.InsecureCookie.ToString(),
                    Vulnerability = missing
                });
            }
        }

        internal static string GetLineNumber(SyntaxNodeOrToken item) => item.SyntaxTree.GetLineSpan(item.FullSpan).StartLinePosition.ToLineString();

        private static string GetLineNumber(SyntaxTrivia item) => item.SyntaxTree.GetLineSpan(item.FullSpan).StartLinePosition.ToLineString();
    }
}