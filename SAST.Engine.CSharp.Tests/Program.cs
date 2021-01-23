using System;
using System.Net.Http;
using System.IO;
using System.Collections.Generic;
using SAST.Engine.CSharp.Core;
using System.Text.Json;
using System.Linq;
using Newtonsoft.Json;

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
            string argPath = path;
            path = path.TrimEnd('\\');
            if (!Directory.Exists(path) && !File.Exists(path))
            {
                Console.WriteLine($"{argPath} is invalid");
                return;
            }
            IEnumerable<VulnerabilityDetail> vulnerabilities;
            SASTApp sASTApp = new SASTApp();
            if (Directory.Exists(path))
                sASTApp.LoadFolder(path);
            else if (File.Exists(path))
                sASTApp.LoadFiles(new string[] { path });
            vulnerabilities = sASTApp.ScanAll();
            //File.Create(@"F:\Proto Geek\Task 1\Examples\output.txt");
            if (vulnerabilities != null)
                foreach (var vul in vulnerabilities)
                {
                    File.AppendAllText(@"F:\Proto Geek\Task 1\Examples\output.txt", vul.ToString() + "\n");
                    //Console.WriteLine("\n" + vul);
                }
            Console.WriteLine("Press any key to Exit");
            Console.ReadKey();
        }
    }
}