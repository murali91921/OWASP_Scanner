using System;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;
using System.Reflection;
using Newtonsoft.Json;

namespace ASTTask
{
    internal class OpenRedirect
    {
        /*
        FIND THE REDIRECT METHODS
        And If parameter is identifier then check the references above the Redirect statement, then identifier have any
        If parameter is condition, then not vulnerability
        */
    }
}