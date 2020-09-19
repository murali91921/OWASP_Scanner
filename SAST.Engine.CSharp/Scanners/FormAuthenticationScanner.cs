using SAST.Engine.CSharp.Contract;
using System;
using System.Collections.Generic;
using System.Xml;
using System.Xml.XPath;

namespace SAST.Engine.CSharp.Scanners
{
    internal class FormAuthenticationScanner : IConfigScanner
    {
        const string Forms_Node = "configuration/system.web/authentication[@mode='Forms']/forms";
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            XPathDocument xPathDocument = new XPathDocument(filePath);
            FindWeakProtection(filePath, xPathDocument, ref vulnerabilities);
            FindCrossAppRedirect(filePath, xPathDocument, ref vulnerabilities);
            FindCookielessMode(filePath, xPathDocument, ref vulnerabilities);
            FindRequireSsl(filePath, xPathDocument, ref vulnerabilities);
            return vulnerabilities;
        }

        /// <summary>
        /// Protection will be weak when the value is not 'All'
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="xPathDocument"></param>
        /// <param name="vulnerabilities"></param>
        private void FindWeakProtection(string filePath, XPathDocument xPathDocument, ref List<VulnerabilityDetail> vulnerabilities)
        {
            XPathNavigator element = xPathDocument.CreateNavigator().SelectSingleNode(Forms_Node);
            if (element != null && element.HasAttributes)
            {
                bool vulnerable = false;
                element.MoveToFirstAttribute();
                do
                {
                    if (element.Name.Equals("Protection", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!element.Value.Equals("All", StringComparison.OrdinalIgnoreCase))
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
                        Type = Enums.ScannerType.FormsAuthentication,
                        SubType = Enums.ScannerSubType.FAWeakCookie
                    });
            }
        }

        /// <summary>
        /// Default value of enableCrossAppRedirects is false, if enableCrossAppRedirects is True,then it is vulnerable.
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="xPathDocument"></param>
        /// <param name="vulnerabilities"></param>
        private void FindCrossAppRedirect(string filePath, XPathDocument xPathDocument, ref List<VulnerabilityDetail> vulnerabilities)
        {
            XPathNavigator element = xPathDocument.CreateNavigator().SelectSingleNode(Forms_Node);
            if (element != null && element.HasAttributes)
            {
                bool vulnerable = false;
                element.MoveToFirstAttribute();
                do
                {
                    if (element.Name.Equals("enableCrossAppRedirects", StringComparison.OrdinalIgnoreCase))
                    {
                        if (element.Value.Equals("True", StringComparison.OrdinalIgnoreCase))
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
                        Type = Enums.ScannerType.FormsAuthentication,
                        SubType = Enums.ScannerSubType.FACrossAppRedirect
                    });
            }
        }

        /// <summary>
        /// Default value of is cookieless is UseDeviceProfile,which can allow URL based tracking. Add vulenrability in all cases except value of UseCookies
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="xPathDocument"></param>
        /// <param name="vulnerabilities"></param>
        private void FindCookielessMode(string filePath, XPathDocument xPathDocument, ref List<VulnerabilityDetail> vulnerabilities)
        {
            XPathNavigator element = xPathDocument.CreateNavigator().SelectSingleNode(Forms_Node);
            if (element != null && element.HasAttributes)
            {
                bool vulnerable = true;
                element.MoveToFirstAttribute();
                do
                {
                    if (element.Name.Equals("cookieless", StringComparison.InvariantCultureIgnoreCase))
                    {
                        if (!element.Value.Equals("UseCookies", StringComparison.InvariantCultureIgnoreCase))
                            vulnerable = false;
                        break;
                    }
                }
                while (element.MoveToNextAttribute());
                if (vulnerable)
                {
                    //If cookieless is not defined, then consider Forms Node.
                    if (!element.Name.Equals("cookieless", StringComparison.InvariantCultureIgnoreCase))
                        element.MoveToParent();
                    vulnerabilities.Add(
                    new VulnerabilityDetail()
                    {
                        FilePath = filePath,
                        CodeSnippet = element.OuterXml.Trim(),
                        LineNumber = (IXmlLineInfo)element != null ? ((IXmlLineInfo)element).LineNumber.ToString() + "," + ((IXmlLineInfo)element).LinePosition.ToString() : string.Empty,
                        Type = Enums.ScannerType.FormsAuthentication,
                        SubType = Enums.ScannerSubType.FACookielessMode
                    });
                }
            }
        }

        /// <summary>
        /// Default value is false, which is vulnerable & Add vulenrability if value set to true also.
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="xPathDocument"></param>
        /// <param name="vulnerabilities"></param>
        private void FindRequireSsl(string filePath, XPathDocument xPathDocument, ref List<VulnerabilityDetail> vulnerabilities)
        {
            XPathNavigator element = xPathDocument.CreateNavigator().SelectSingleNode(Forms_Node);
            if (element != null && element.HasAttributes)
            {
                bool vulnerable = true;
                element.MoveToFirstAttribute();
                do
                {
                    if (element.Name.Equals("requireSSL", StringComparison.InvariantCultureIgnoreCase))
                    {
                        if (element.Value.Equals("True", StringComparison.InvariantCultureIgnoreCase))
                            vulnerable = false;
                        break;
                    }
                }
                while (element.MoveToNextAttribute());
                if (vulnerable)
                {
                    //If requireSSL is not defined, then consider Forms Node.
                    if (!element.Name.Equals("requireSSL", StringComparison.InvariantCultureIgnoreCase))
                        element.MoveToParent();
                    vulnerabilities.Add(
                    new VulnerabilityDetail()
                    {
                        FilePath = filePath,
                        CodeSnippet = element.OuterXml.Trim(),
                        LineNumber = (IXmlLineInfo)element != null ? ((IXmlLineInfo)element).LineNumber.ToString() + "," + ((IXmlLineInfo)element).LinePosition.ToString() : string.Empty,
                        Type = Enums.ScannerType.FormsAuthentication,
                        SubType = Enums.ScannerSubType.FAInsecureCookie
                    });
                }
            }
        }
    }
}