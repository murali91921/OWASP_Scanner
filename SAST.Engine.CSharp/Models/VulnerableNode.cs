using Microsoft.CodeAnalysis;
using SAST.Engine.CSharp.Enums;
using System;
using System.Collections.Generic;
using System.Text;

namespace SAST.Engine.CSharp.Models
{
    public class VulnerableNode
    {
        public VulnerableNode(SyntaxNode expression) => Expression = expression;
        
        public SyntaxNode Expression { set; get; }
        
        public bool IsVulnerable { set; get; }
        
        public ScannerSubType VulnerabileSubType { set; get; }
    }
}
