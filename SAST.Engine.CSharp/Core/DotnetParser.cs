﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;
using System.Xml.XPath;
using System.Diagnostics;
using System.Reflection;
using System.Security.Permissions;
using System.Text.RegularExpressions;

namespace SAST.Engine.CSharp.Parser
{
    internal class DotnetParser
    {
        static readonly string ProjectPattern = "^Project\\(\"{(?<TypeId>[A-F0-9-]+)}\"\\) = \"(?<Name>.*?)\", \"(?<Path>.*?)\", \"{(?<Id>[A-F0-9-]+)}\""
            + @"(?<Sections>(.|\n|\r)*?)" + @"EndProject(\n|\r)";
        internal static IEnumerable<string> ParseSolution(string solutionFilePath)
        {
            var list = new List<string>();
            if (!File.Exists(solutionFilePath))
                return list;
            string slnText = File.ReadAllText(solutionFilePath);
            if (string.IsNullOrWhiteSpace(slnText))
                return list;
            var matches = Regex.Matches(slnText, ProjectPattern, RegexOptions.Multiline);
            foreach (Match match in matches)
            {
                if (match != null)
                {
                    string projectPath = Path.GetFullPath(match.Groups["Path"].Value, Path.GetDirectoryName(solutionFilePath));
                    if (File.Exists(projectPath) && !string.IsNullOrWhiteSpace(File.ReadAllTextAsync(projectPath).Result))
                        list.Add(Path.GetFullPath(match.Groups["Path"].Value, Path.GetDirectoryName(solutionFilePath)));
                }
            }
            return list;
        }
        internal static IEnumerable<string> GetAttributes(string projectPath, string nodePath, string attributeName, string[] extensions)
        {
            List<string> sourceFiles = new List<string>();
            if (!File.Exists(projectPath) || string.IsNullOrWhiteSpace(File.ReadAllText(projectPath)))
                return sourceFiles;
            XmlTextReader reader = new XmlTextReader(projectPath)
            {
                Namespaces = false
            };
            XPathDocument document = new XPathDocument(reader);
            XPathNavigator navigator = document.CreateNavigator();
            XPathNodeIterator nodes = navigator.Select(nodePath);
            while (nodes.MoveNext())
            {
                nodes.Current.MoveToFirstAttribute();
                do
                {
                    if (nodes.Current.Name.Equals(attributeName, System.StringComparison.OrdinalIgnoreCase)
                        && extensions.Any(obj => obj == (Path.GetExtension(nodes.Current.Value.ToLower()))))
                    {
                        string sourceFilePath = Path.GetFullPath(nodes.Current.Value, Path.GetDirectoryName(projectPath));
                        if (File.Exists(sourceFilePath) && !string.IsNullOrWhiteSpace(File.ReadAllText(sourceFilePath)))
                            sourceFiles.Add(sourceFilePath);
                        break;
                    }
                }
                while (nodes.Current.MoveToNextAttribute());
            }
            return sourceFiles;
        }

    }
}