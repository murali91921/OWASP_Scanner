﻿using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Parser;
using System;
using System.Collections.Generic;
using System.Xml;
using System.Xml.XPath;

namespace SAST.Engine.CSharp.Scanners
{
    internal class HTTPHeaderCheckingScanner : IConfigScanner
    {
        const string HttpRuntime_Node = "configuration/system.web/httpRuntime";

        /// <summary>
        /// This method to find HTTP Header Vulnerabilities.
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            XPathNavigator element = XMLParser.CreateNavigator(filePath, HttpRuntime_Node);
            if (element != null && element.HasAttributes)
            {
                element.MoveToFirstAttribute();
                do
                {
                    if (element.Name.Equals("enableHeaderChecking", StringComparison.OrdinalIgnoreCase))
                    {
                        if (element.Value.Equals("false", StringComparison.OrdinalIgnoreCase))
                            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, element, Enums.ScannerType.HTTPHeaderChecking));
                        break;
                    }
                }
                while (element.MoveToNextAttribute());
            }
            return vulnerabilities;
        }
    }
}
