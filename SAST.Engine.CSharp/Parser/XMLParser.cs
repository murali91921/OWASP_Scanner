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
        internal static IEnumerable<string> GetAttributes(string projectPath, string nodePath, string attributeName, string[] extensions = null)
        {
            List<string> values = new List<string>();
            if (!File.Exists(projectPath) || string.IsNullOrWhiteSpace(File.ReadAllText(projectPath)))
                return values;
            XmlTextReader reader = new XmlTextReader(projectPath)
            {
                Namespaces = false
            };
            XPathDocument document = new XPathDocument(reader);
            XPathNavigator navigator = document.CreateNavigator();
            XPathNodeIterator nodes = navigator.Select(nodePath);
            string projectpath = Path.GetDirectoryName(Path.GetFullPath(projectPath));
            while (nodes.MoveNext())
            {
                nodes.Current.MoveToFirstAttribute();
                do
                {
                    if (extensions == null || string.IsNullOrEmpty(attributeName))
                    {
                        values.Add(nodes.Current.InnerXml);
                        break;
                    }

                    if (extensions != null && !string.IsNullOrEmpty(attributeName)
                        && nodes.Current.Name.Equals(attributeName, System.StringComparison.OrdinalIgnoreCase)
                        && extensions.Any(obj => obj == (Path.GetExtension(nodes.Current.Value.ToLower()))))
                    {
                        string sourceFilePath = Path.GetFullPath(nodes.Current.Value, projectpath);
                        if (File.Exists(sourceFilePath) && !string.IsNullOrWhiteSpace(File.ReadAllText(sourceFilePath)))
                            values.Add(sourceFilePath);
                        break;
                    }

                }
                while (nodes.Current.MoveToNextAttribute());
            }
            return values;
        }

        /// <summary>
        /// Creates Navigator in the <paramref name="filePath"/> by searching <paramref name="node"/>
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="node"></param>
        /// <returns>null if any exception occurs or node is not available in <paramref name="filePath"/></returns>
        internal static XPathNavigator CreateNavigator(string filePath, string node)
        {
            XPathNavigator element = null;
            try
            {
                XPathDocument doc = new XPathDocument(filePath);
                element = doc.CreateNavigator().SelectSingleNode(node);
            }
            catch
            {
            }
            return element;
        }
    }
}