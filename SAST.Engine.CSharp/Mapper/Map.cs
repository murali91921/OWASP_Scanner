using Microsoft.CodeAnalysis;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Models;
using System.Collections.Generic;
using System.IO;

namespace SAST.Engine.CSharp.Mapper
{
    public static class Map
    {
        internal static List<VulnerabilityDetail> ConvertToVulnerabilityList<T>(string filePath, List<T> syntaxList, ScannerType scannerType, ScannerSubType scannerSubType = ScannerSubType.None)
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
                        Type = scannerType,
                        SubType =scannerSubType
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
                        Type = ScannerType.InsecureCookie,
                    });
                }
            return vulnerabilityList;
        }

        internal static void ConvertFromSASTCookie<T>(string filePath, List<SASTCookie> astCookie, List<VulnerabilityDetail> vulnerabilityList)
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
                    Type = ScannerType.InsecureCookie,
                    Description = missing
                });
            }
        }

        internal static string GetLineNumber(SyntaxNodeOrToken item) => item.SyntaxTree.GetLineSpan(item.Span).StartLinePosition.ToLineString();

        internal static string GetLineNumber(SyntaxTrivia item) => item.SyntaxTree.GetLineSpan(item.Span).StartLinePosition.ToLineString();
    }
}