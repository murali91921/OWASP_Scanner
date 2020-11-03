using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using SAST.Engine.CSharp.Core;
using System.Xml.Serialization;

namespace SAST.Engine.CSharp.Tests
{
    public class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("usage : dotnet run -\"Path\"\nPath should be Folder or file");
                Console.WriteLine("Example : dotnet run -\"D:\\Examples\"");
                return;
            }
            string path = args[0].TrimStart('-');
            path = path.TrimEnd('\\');
            if (!Directory.Exists(path) && !File.Exists(path))
            {
                Console.WriteLine($"{path} is invalid");
                return;
            }
            IEnumerable<VulnerabilityDetail> vulnerabilities = null;
            SASTApp sASTApp = new SASTApp();
            if (Directory.Exists(path))
                sASTApp.LoadFolder(path);
            else if (File.Exists(path))
                sASTApp.LoadFiles(new string[] { path });
            
            vulnerabilities = sASTApp.Scan(Enums.ScannerType.RegexInjection);
            if (vulnerabilities != null)
                foreach (var item in vulnerabilities)
                    Console.WriteLine("\n" + item);
        }
    }
}