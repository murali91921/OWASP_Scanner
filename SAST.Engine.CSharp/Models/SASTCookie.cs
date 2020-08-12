using Microsoft.CodeAnalysis;

namespace SAST.Engine.CSharp.Models
{
    internal class SASTCookie
    {
        internal SyntaxNode CookieStatement { set; get; }
        internal bool IsSecure { set; get; }
        internal bool IsHttpOnly { set; get; }
    }
}