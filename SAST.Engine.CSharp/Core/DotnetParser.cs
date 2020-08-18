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
    //internal class SASTProject
    //{
    //    public string Name { get; set; }
    //    public string Path { get; set; }
    //}
    internal class DotnetParser
    {
        static readonly string ProjectPattern = "^Project\\(\"{(?<TypeId>[A-F0-9-]+)}\"\\) = \"(?<Name>.*?)\", \"(?<Path>.*?)\", \"{(?<Id>[A-F0-9-]+)}\""
            + @"(?<Sections>(.|\n|\r)*?)" + @"EndProject(\n|\r)";
        static readonly string ProjectSectionPattern = @"ProjectSection(?<Record>(.|\n|\r)*?)EndProjectSection";
        internal static IEnumerable<string> ParseSolution(string solutionFilePath)
        {
            if (!File.Exists(solutionFilePath))
                new ArgumentNullException("Invalid file path", new ArgumentNullException());
            string slnText = File.ReadAllText(solutionFilePath);
            var matches = Regex.Matches(slnText, ProjectPattern, RegexOptions.Multiline);
            var list = new List<string>();
            foreach (Match match in matches)
            {
                if (match != null)
                {
                    string projectpath = match.Groups["Path"].Value;
                    list.Add(Path.GetFullPath(projectpath, Path.GetDirectoryName(solutionFilePath)));
                }
            }
            return list;
        }
        internal static IEnumerable<string> GetAttributes(string projectPath, string nodePath, string attributeName, string[] extensions)
        {
            List<string> sourceFiles = new List<string>();
            if (string.IsNullOrEmpty(projectPath) || !File.Exists(projectPath))
                return sourceFiles;
            try
            {
                XmlTextReader reader = new XmlTextReader(projectPath);
                reader.Namespaces = false;
                XPathDocument document = new XPathDocument(reader);
                XPathNavigator navigator = document.CreateNavigator();
                //XPathNodeIterator nodes = navigator.Select("//book");
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
                            if (File.Exists(sourceFilePath))
                                sourceFiles.Add(sourceFilePath);
                            break;
                        }
                    }
                    while (nodes.Current.MoveToNextAttribute());
                }
            }
            catch
            { }
            return sourceFiles;
        }

    }
}