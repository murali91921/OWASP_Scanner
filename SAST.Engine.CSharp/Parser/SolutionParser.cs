using System;
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
    /// <summary>
    /// This class will be used to parse & get the required information from Solution file(s).
    /// </summary>
    internal class SolutionParser
    {
        private static readonly string ProjectPattern = "^Project\\(\"{(?<TypeId>[A-F0-9-]+)}\"\\) = \"(?<Name>.*?)\", \"(?<Path>.*?)\", \"{(?<Id>[A-F0-9-]+)}\""
            + @"(?<Sections>(.|\n|\r)*?)" + @"EndProject(\n|\r)";

        /// <summary>
        /// This method will Parse the Solution File to find the Project File Paths
        /// </summary>
        /// <param name="solutionFilePath">File path of solution</param>
        /// <returns>List Project File Paths</returns>
        internal static IEnumerable<string> ParseSolution(string solutionFilePath)
        {
            var list = new List<string>();
            if (!File.Exists(solutionFilePath))
                return list;
            string slnText = File.ReadAllText(solutionFilePath);
            if (string.IsNullOrWhiteSpace(slnText))
                return list;
            var matches = Regex.Matches(slnText, ProjectPattern, RegexOptions.Multiline);
            string solutionDirectory = Path.GetDirectoryName(Path.GetFullPath(solutionFilePath));
            foreach (Match match in matches)
            {
                if (match != null)
                {
                    string projectPath = Path.GetFullPath(match.Groups["Path"].Value, solutionDirectory);
                    if (File.Exists(projectPath) && !string.IsNullOrWhiteSpace(File.ReadAllTextAsync(projectPath).Result))
                        list.Add(Path.GetFullPath(match.Groups["Path"].Value, solutionDirectory));
                }
            }
            return list;
        }
    }
}