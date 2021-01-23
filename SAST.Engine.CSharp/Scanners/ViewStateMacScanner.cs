using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Parser;
using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.XPath;

namespace SAST.Engine.CSharp.Scanners
{
    internal class ViewStateMacScanner : IConfigScanner
    {
        const string Pages_Node = "configuration/system.web/pages";

        /// <summary>
        /// Determines ViewstateMac Vulnerabilities.
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            XPathNavigator element = XMLParser.CreateNavigator(filePath, Pages_Node);
            if (element != null && element.HasAttributes)
            {
                bool vulnerable = false;
                element.MoveToFirstAttribute();
                do
                {
                    if (element.Name.Equals("enableViewStateMac", StringComparison.OrdinalIgnoreCase))
                    {
                        if (element.Value.Equals("false", StringComparison.OrdinalIgnoreCase))
                            vulnerable = true;
                        break;
                    }
                }
                while (element.MoveToNextAttribute());

                if (vulnerable)
                    vulnerabilities.Add(VulnerabilityDetail.Create(filePath, element, Enums.ScannerType.ViewStateMac));

            }
            return vulnerabilities;
        }
    }
}