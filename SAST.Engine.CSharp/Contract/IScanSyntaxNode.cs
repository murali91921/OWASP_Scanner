using Microsoft.CodeAnalysis;
using System.Collections.Generic;

namespace SAST.Engine.CSharp.Contract
{
    public interface IScanner
    {
        List<VulnerabilityDetail> ScanSyntaxNode(string filePath, SyntaxNode root);
    }
}