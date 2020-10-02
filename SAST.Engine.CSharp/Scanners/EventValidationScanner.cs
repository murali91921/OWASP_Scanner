using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Parser;
using System;
using System.Collections.Generic;
using System.Xml;
using System.Xml.XPath;

namespace SAST.Engine.CSharp.Scanners
{
    internal class EventValidationScanner : IConfigScanner
    {
        const string Pages_Node = "configuration/system.web/pages";

        /// <summary>
        /// This method will find Page Event Validation Vulnerabilities
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            XPathNavigator element = XMLParser.CreateNavigator(filePath, Pages_Node);
            if (element != null && element.HasAttributes)
            {
                element.MoveToFirstAttribute();
                do
                {
                    if (element.Name.Equals("enableEventValidation", StringComparison.OrdinalIgnoreCase))
                    {
                        if (element.Value.Equals("false", StringComparison.OrdinalIgnoreCase))
                            vulnerabilities.Add(
                            new VulnerabilityDetail()
                            {
                                FilePath = filePath,
                                CodeSnippet = element.OuterXml.Trim(),
                                LineNumber = (IXmlLineInfo)element != null ? ((IXmlLineInfo)element).LineNumber.ToString() + "," + ((IXmlLineInfo)element).LinePosition.ToString() : string.Empty,
                                Type = Enums.ScannerType.EventValidation,
                                SubType = Enums.ScannerSubType.None
                            });
                        break;
                    }
                }
                while (element.MoveToNextAttribute());
            }
            return vulnerabilities;
        }
    }
}