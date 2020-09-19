using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.XPath;

namespace SAST.Engine.CSharp.Scanners
{
    internal class EventValidationScanner : IConfigScanner
    {
        const string Pages_Node="configuration/system.web/pages";

        /// <summary>
        /// Default value is true, so when enableEventValidation is set to false, consider as vulnerable.
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            XPathDocument xPathDocument = new XPathDocument(filePath);

            XPathNavigator element = xPathDocument.CreateNavigator().SelectSingleNode(Pages_Node);
            if (element != null && element.HasAttributes)
            {
                bool vulnerable = false;
                element.MoveToFirstAttribute();
                do
                {
                    if (element.Name.Equals("enableEventValidation", StringComparison.OrdinalIgnoreCase))
                    {
                        if (element.Value.Equals("false", StringComparison.OrdinalIgnoreCase))
                            vulnerable = true;
                        break;
                    }
                }
                while (element.MoveToNextAttribute());

                if (vulnerable)
                    vulnerabilities.Add(
                    new VulnerabilityDetail()
                    {
                        FilePath = filePath,
                        CodeSnippet = element.OuterXml.Trim(),
                        LineNumber = (IXmlLineInfo)element != null ? ((IXmlLineInfo)element).LineNumber.ToString() + "," + ((IXmlLineInfo)element).LinePosition.ToString() : string.Empty,
                        Type = Enums.ScannerType.EventValidation,
                        SubType = Enums.ScannerSubType.None
                    });
            }
            return vulnerabilities;
        }
    }
}
