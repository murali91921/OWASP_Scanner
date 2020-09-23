using System;
using System.Collections.Generic;
using System.Text;

namespace SAST.Engine.CSharp.Contract
{
    /// <summary>
    /// Defines the methods to scan xml config files. Example app.config, web.config etc.
    /// </summary>
    internal interface IConfigScanner
    {
        IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath);
    }
}
