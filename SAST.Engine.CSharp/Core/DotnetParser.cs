using Microsoft.Build.Construction;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Xml;
using System.Xml.XPath;

namespace SAST.Engine.CSharp.Core
{
    internal class DotnetParser
    {
        internal static IEnumerable<string> ParseSolution(string solutionFilePath)
        {
            SolutionFile solutionFile = SolutionFile.Parse(solutionFilePath);
            List<string> keyValues = new List<string>();
            if (solutionFile.ProjectsByGuid.Count > 0)
            {
                foreach (var pair in solutionFile.ProjectsByGuid)
                    keyValues.Add(pair.Value.AbsolutePath);
            }
            return keyValues.AsEnumerable();
        }
        internal static IEnumerable<string> GetSourceFiles(string projectPath, string nodePath, string attributeName, string[] extensions)
        {
            List<string> sourceFiles = new List<string>();
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
                        string sourceFilePath = Path.GetDirectoryName(projectPath) + Path.DirectorySeparatorChar + nodes.Current.Value;
                        if (File.Exists(sourceFilePath))
                            sourceFiles.Add(sourceFilePath);
                        break;
                    }
                }
                while (nodes.Current.MoveToNextAttribute());
            }
            return sourceFiles.AsEnumerable();
        }
    }
}
