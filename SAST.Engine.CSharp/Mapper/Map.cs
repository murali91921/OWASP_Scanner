using Microsoft.CodeAnalysis;
using SAST.Engine.CSharp.Enums;
using System.Collections.Generic;
using System.Linq;
using System;

namespace SAST.Engine.CSharp.Mapper
{
    public static class Map
    {
        /// <summary>
        /// Convert the SyntaxNode to VulnerabilityDetail objects
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="filePath">File Path of source file</param>
        /// <param name="syntaxList">Vulnerable SyntaxNodes </param>
        /// <param name="scannerType">Type of Scanner</param>
        /// <param name="scannerSubType">SubType of Scanner</param>
        /// <returns>List of Vulnerability Details </returns>
        internal static List<VulnerabilityDetail> ConvertToVulnerabilityList<T>(string filePath, List<T> syntaxList, ScannerType scannerType, ScannerSubType scannerSubType = ScannerSubType.None)
        {
            Type itemType = typeof(T);
            if (!(itemType == typeof(SyntaxNodeOrToken) || itemType == typeof(SyntaxTrivia) || itemType == typeof(SyntaxNode)))
                throw new InvalidCastException($"{typeof(T)} is not valid.");

            var vulnerabilityList = new List<VulnerabilityDetail>();
            if (syntaxList == null || syntaxList.Count == 0)
                return vulnerabilityList;

            if (syntaxList is List<SyntaxNodeOrToken> syntaxNodeOrTokenList)
            {
                syntaxNodeOrTokenList = syntaxNodeOrTokenList.OrderBy(obj => obj.Span).ToList();
                foreach (var item in syntaxNodeOrTokenList)
                {
                    vulnerabilityList.Add(new VulnerabilityDetail
                    {
                        FilePath = filePath,
                        CodeSnippet = item.ToString(),
                        LineNumber = GetLineNumber(item),
                        Type = scannerType,
                        SubType = scannerSubType
                    });
                }
            }
            else if (syntaxList is List<SyntaxTrivia> syntaxTriviaList)
            {
                syntaxTriviaList = syntaxTriviaList.OrderBy(obj => obj.Span).ToList();
                foreach (var item in syntaxTriviaList)
                {
                    vulnerabilityList.Add(new VulnerabilityDetail
                    {
                        FilePath = filePath,
                        CodeSnippet = item.ToString(),
                        LineNumber = GetLineNumber(item),
                        Type = scannerType,
                        SubType = scannerSubType
                    });
                }
            }
            else if (syntaxList is List<SyntaxToken> syntaxTokenList)
            {
                syntaxTokenList = syntaxTokenList.OrderBy(obj => obj.Span).ToList();
                foreach (var item in syntaxTokenList)
                {
                    vulnerabilityList.Add(new VulnerabilityDetail
                    {
                        FilePath = filePath,
                        CodeSnippet = item.ToString(),
                        LineNumber = GetLineNumber(item),
                        Type = scannerType,
                        SubType = scannerSubType
                    });
                }
            }
            else if (syntaxList is List<SyntaxNode> syntaxNodeList)
            {
                syntaxNodeList = syntaxNodeList.OrderBy(obj => obj.Span).ToList();
                foreach (var item in syntaxNodeList)
                {
                    vulnerabilityList.Add(new VulnerabilityDetail
                    {
                        FilePath = filePath,
                        CodeSnippet = item.ToString(),
                        LineNumber = GetLineNumber(item),
                        Type = scannerType,
                        SubType = scannerSubType
                    });
                }
            }

            return vulnerabilityList;
        }

        /// <summary>
        /// Get the Line Number of SyntaxNode or Token
        /// </summary>
        /// <param name="syntaxNodeOrToken">SyntaNode or Token</param>
        /// <returns>Line Number, Character Postion as cancatenated string</returns>
        internal static string GetLineNumber(SyntaxNodeOrToken syntaxNodeOrToken) => syntaxNodeOrToken.SyntaxTree.GetLineSpan(syntaxNodeOrToken.Span).StartLinePosition.ToLineString();

        /// <summary>
        /// Get the Line Number of Comment Node
        /// </summary>
        /// <param name="syntaxTrivia">SyntaxTrivia</param>
        /// <returns>Line Number, Character Postion as cancatenated string</returns>
        internal static string GetLineNumber(SyntaxTrivia syntaxTrivia) => syntaxTrivia.SyntaxTree.GetLineSpan(syntaxTrivia.Span).StartLinePosition.ToLineString();
    }
}