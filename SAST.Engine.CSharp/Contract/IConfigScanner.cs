using System;
using System.Collections.Generic;
using System.Text;

namespace SAST.Engine.CSharp.Contract
{
    internal interface IConfigScanner
    {
        IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath);
    }
}
