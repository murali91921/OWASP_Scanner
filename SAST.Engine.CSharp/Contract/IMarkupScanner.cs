using System;
using System.Collections.Generic;
using System.Text;

namespace SAST.Engine.CSharp.Contract
{
    internal interface IMarkupScanner
    {
        IEnumerable<VulnerabilityDetail> FindVulnerabilties(string filePath);
    }
}
