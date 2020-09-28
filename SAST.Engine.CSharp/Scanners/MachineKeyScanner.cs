using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Xml;
using System.Xml.XPath;

namespace SAST.Engine.CSharp.Scanners
{
    internal class MachineKeyScanner : IConfigScanner
    {
        private const string Forms_Node = "configuration/system.web/authentication[@mode='Forms']/forms";
 
        /// <summary>
        /// This method will find Machine key Vulnerabilities.
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            XPathDocument doc = new XPathDocument(filePath);
            XPathNavigator element = doc.CreateNavigator().SelectSingleNode(Forms_Node);
            if (element != null && element.HasAttributes)
            {
                element.MoveToFirstAttribute();
                do
                {
                    if (element.Name.Equals("validationKey", StringComparison.InvariantCultureIgnoreCase) ||
                        element.Name.Equals("decryptionKey", StringComparison.InvariantCultureIgnoreCase))
                    {
                        if (!element.Value.Contains("AutoGenerate"))
                            vulnerabilities.Add(
                                new VulnerabilityDetail()
                                {
                                    FilePath = filePath,
                                    CodeSnippet = element.OuterXml.Trim(),
                                    LineNumber = (IXmlLineInfo)element != null ? ((IXmlLineInfo)element).LineNumber.ToString() + "," + ((IXmlLineInfo)element).LinePosition.ToString()
                                            : string.Empty,
                                    Type = Enums.ScannerType.MachineKeyClearText
                                });
                    }
                }
                while (element.MoveToNextAttribute());
            }
            return vulnerabilities;
        }
    }
}