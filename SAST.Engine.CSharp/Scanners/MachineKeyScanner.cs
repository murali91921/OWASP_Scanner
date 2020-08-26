using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.XPath;

namespace SAST.Engine.CSharp.Scanners
{
    internal class MachineKeyScanner : IConfigScanner
    {
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath)
        {
            bool vulnerable = false;
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            XPathDocument doc = new XPathDocument(filePath);
            XPathNavigator element = doc.CreateNavigator().SelectSingleNode("configuration/system.web/authentication[@mode='Forms']/forms");
            if (element != null && element.HasAttributes)
            {
                element.MoveToFirstAttribute();
                do
                {
                    if (element.Name.Equals("validationKey", StringComparison.InvariantCultureIgnoreCase) ||
                        element.Name.Equals("decryptionKey", StringComparison.InvariantCultureIgnoreCase))
                    {
                        vulnerable = !element.Value.Contains("AutoGenerate");
                        break;
                    }
                }
                while (element.MoveToNextAttribute());
            }
            if (vulnerable)
                vulnerabilities = new List<VulnerabilityDetail>()
                    {
                        new VulnerabilityDetail()
                        {
                            FilePath = filePath,
                            CodeSnippet = element.OuterXml.Trim(),
                            LineNumber = (IXmlLineInfo)element != null ? ((IXmlLineInfo)element).LineNumber.ToString() + "," + ((IXmlLineInfo)element).LinePosition.ToString()
                                : string.Empty,
                            Type = Enums.ScannerType.MachineKeyClearText
                        }
                    };
            return vulnerabilities;






            //validationKey = "abc";
            //decryptionKey = "def";
            //var attribute = element.Attribute("validationKey");
            //var flag = attribute != null && !attribute.Value.Contains("AutoGenerate");

            ////Check the decryptionKey element for "AutoGenerate"
            //if (!flag)
            //{
            //    attribute = element.Attribute("decryptionKey");
            //    flag = attribute != null && !attribute.Value.Contains("AutoGenerate");
            //}

            ////Send the diagnostic warning if identified cleartext key
            //if (flag)
            //{
            //    var lineInfo = config.GetProductionLineInfo(element, SEARCH_EXPRESSION);
            //    VulnerableAdditionalText.Push(new DiagnosticInfo(config.Source.Path, lineInfo.LineNumber, element.ToString()));
            //}
        }
    }
}
