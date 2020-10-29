using Microsoft.CodeAnalysis;
using System;
using System.Collections.Generic;
using System.Text;

namespace SAST.Engine.CSharp.Contract
{
    /// <summary>
    /// Defines the methods to scan Cshtml source code
    /// </summary>
    public interface ICSHtmlScanner
    {
        IEnumerable<VulnerabilityDetail> FindVulnerabilities(string filePath);
    }
}
