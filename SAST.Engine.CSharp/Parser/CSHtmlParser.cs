using System;
using System.Collections.Generic;
using System.IO;

namespace SAST.Engine.CSharp.Parser
{
    public static class CSHtmlParser
    {
        public static string[] GetContent(string filePath)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(filePath))
                    return null;
                if (!File.Exists(filePath))
                    return null;
                if (filePath.EndsWith(".cshtml", StringComparison.OrdinalIgnoreCase))
                    return File.ReadAllLines(filePath);
                return null;
            }
            catch
            {
                return null;
            }
        }
    }
}