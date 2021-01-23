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
                            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, element, Enums.ScannerType.EventValidation));
                        break;
                    }
                }
                while (element.MoveToNextAttribute());
            }
            return vulnerabilities;
        }
    }
}