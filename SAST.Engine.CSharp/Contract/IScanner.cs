using Microsoft.CodeAnalysis;
using System;
using System.Collections.Generic;
using System.Text;

namespace SAST.Engine.CSharp.Contract
{
    /// <summary>
    /// Defines the methods to scan CSharp source code
    /// </summary>
    internal interface IScanner
    {
        IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null);
    }
}
