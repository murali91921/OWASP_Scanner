using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Parser;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using System.Xml.XPath;

namespace SAST.Engine.CSharp.Scanners
{
    internal class FormAuthenticationScanner : IConfigScanner
    {
        const string Forms_Node = "configuration/system.web/authentication[@mode='Forms']/forms";
        private Enums.ScannerType scannerType;

        public FormAuthenticationScanner(Enums.ScannerType paramScannerType) => scannerType = paramScannerType;

        /// <summary>
        /// This method will find the Form Authentication vulnerabilities
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath)
        {
            //List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            VulnerabilityDetail vulnerability = null;
            XPathNavigator element = XMLParser.CreateNavigator(filePath, Forms_Node);
            if (element == null)
                return Enumerable.Empty<VulnerabilityDetail>();
            if (scannerType == Enums.ScannerType.MissingCookieProtectionFormsAuthentication)
                vulnerability = FindVulnerabilities(filePath, element, false, "Protection", "All");
            else if (scannerType == Enums.ScannerType.MissingCrossAppRedirectsFormsAuthentication)
                vulnerability = FindVulnerabilities(filePath, element, false, "enableCrossAppRedirects", "True");
            else if (scannerType == Enums.ScannerType.MissingCookielessFormsAuthentication)
                vulnerability = FindVulnerabilities(filePath, element, true, "cookieless", "UseCookies");
            else if (scannerType == Enums.ScannerType.MissingRequireSSLFormsAuthentication)
                vulnerability = FindVulnerabilities(filePath, element, true, "requireSSL", "True");
            return vulnerability == null ? Enumerable.Empty<VulnerabilityDetail>() : new List<VulnerabilityDetail> { vulnerability };
        }

        private VulnerabilityDetail FindVulnerabilities(string filePath, XPathNavigator element, bool defaultVulnerable, string elementName, string elementValue)
        {
            bool vulnerable = defaultVulnerable;
            if (element != null && element.HasAttributes)
            {
                element.MoveToFirstAttribute();
                do
                {
                    if (element.Name.Equals(elementName, StringComparison.OrdinalIgnoreCase))
                    {
                        if (!element.Value.Equals(elementValue, StringComparison.OrdinalIgnoreCase))
                            vulnerable = !defaultVulnerable;
                        break;
                    }
                }
                while (element.MoveToNextAttribute());
            }
            if (vulnerable)
            {
                if (defaultVulnerable && !element.Name.Equals(elementName, StringComparison.InvariantCultureIgnoreCase))
                    element.MoveToParent();
                return VulnerabilityDetail.Create(filePath, element, scannerType);
            }
            return null;
        }

        /// <summary>
        /// This method will find Protection vulnerabilities in Forms Authentication Node.
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="xPathDocument"></param>
        /// <param name="vulnerabilities"></param>
        //private VulnerabilityDetail FindWeakProtection(string filePath, XPathNavigator element, bool defaultVulnerable, string elementName, string elementValue)
        //{
        //    bool vulnerable = defaultVulnerable;//false;
        //    if (element != null && element.HasAttributes)
        //    {
        //        element.MoveToFirstAttribute();
        //        do
        //        {
        //            if (element.Name.Equals("Protection", StringComparison.OrdinalIgnoreCase))
        //            {
        //                if (!element.Value.Equals("All", StringComparison.OrdinalIgnoreCase))
        //                    vulnerable = true;
        //                break;
        //            }
        //        }
        //        while (element.MoveToNextAttribute());
        //    }
        //    if (vulnerable)
        //        VulnerabilityDetail.Create(filePath, element, Enums.ScannerType.FormsAuthentication));
        //}

        /// <summary>
        /// This method will find Cross App Redirect vulnerabilities in Forms Authentication Node.
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="xPathDocument"></param>
        /// <param name="vulnerabilities"></param>
        //private void FindCrossAppRedirect(string filePath, XPathNavigator element, ref List<VulnerabilityDetail> vulnerabilities)
        //{
        //    if (element != null && element.HasAttributes)
        //    {
        //        bool vulnerable = false;
        //        element.MoveToFirstAttribute();
        //        do
        //        {
        //            if (element.Name.Equals("enableCrossAppRedirects", StringComparison.OrdinalIgnoreCase))
        //            {
        //                if (element.Value.Equals("True", StringComparison.OrdinalIgnoreCase))
        //                    vulnerable = true;
        //                break;
        //            }
        //        }
        //        while (element.MoveToNextAttribute());
        //        if (vulnerable)
        //            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, element, Enums.ScannerType.FormsAuthentication));
        //    }
        //}

        /// <summary>
        /// This method will find Cookie vulnerabilities in Forms Authentication Node.
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="xPathDocument"></param>
        /// <param name="vulnerabilities"></param>
        //private void FindCookielessMode(string filePath, XPathNavigator element, ref List<VulnerabilityDetail> vulnerabilities)
        //{
        //    if (element != null && element.HasAttributes)
        //    {
        //        bool vulnerable = true;
        //        element.MoveToFirstAttribute();
        //        do
        //        {
        //            if (element.Name.Equals("cookieless", StringComparison.InvariantCultureIgnoreCase))
        //            {
        //                if (!element.Value.Equals("UseCookies", StringComparison.InvariantCultureIgnoreCase))
        //                    vulnerable = false;
        //                break;
        //            }
        //        }
        //        while (element.MoveToNextAttribute());
        //        if (vulnerable)
        //        {
        //            //If cookieless is not defined, then consider Forms Node.
        //            if (!element.Name.Equals("cookieless", StringComparison.InvariantCultureIgnoreCase))
        //                element.MoveToParent();
        //            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, element, Enums.ScannerType.FormsAuthentication));
        //        }
        //    }
        //}

        /// <summary>
        /// This method will find SSL vulnerabilities in Forms Authentication Node.
        /// </summary>
        /// <param name="filePath"></param>
        /// <param name="xPathDocument"></param>
        /// <param name="vulnerabilities"></param>
        //private void FindRequireSsl(string filePath, XPathNavigator element, ref List<VulnerabilityDetail> vulnerabilities)
        //{
        //    if (element != null && element.HasAttributes)
        //    {
        //        bool vulnerable = true;
        //        element.MoveToFirstAttribute();
        //        do
        //        {
        //            if (element.Name.Equals("requireSSL", StringComparison.InvariantCultureIgnoreCase))
        //            {
        //                if (element.Value.Equals("True", StringComparison.InvariantCultureIgnoreCase))
        //                    vulnerable = false;
        //                break;
        //            }
        //        }
        //        while (element.MoveToNextAttribute());
        //        if (vulnerable)
        //        {
        //            //If requireSSL is not defined, then consider Forms Node.
        //            if (!element.Name.Equals("requireSSL", StringComparison.InvariantCultureIgnoreCase))
        //                element.MoveToParent();
        //            vulnerabilities.Add(VulnerabilityDetail.Create(filePath, element, Enums.ScannerType.FormsAuthentication));
        //        }
        //    }
        //}
    }
}