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
    /// This class will be used to parse & get the required information from XML config files
    /// </summary>
    internal class XMLParser
    {
        /// <summary>
        /// Get the attribute values in xml config file
        /// </summary>
        /// <param name="projectPath">File Path of Project</param>
        /// <param name="nodePath">Xpath of node</param>
        /// <param name="attributeName">Required attribute name</param>
        /// <param name="extensions">Pass the file path extensions to filter </param>
        /// <returns>List of filepath strings found under the nodepath & attribute</returns>
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