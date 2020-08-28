using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;

namespace SAST.Engine.CSharp.Tests
{
    class Program
    {
        static void LoadFiles(string[] projectPaths)
        {
            Core.SASTApp sASTApp = new Core.SASTApp();
            if (sASTApp.LoadFiles(projectPaths))
            {
                IEnumerable<VulnerabilityDetail> vulnerabilities = sASTApp.Scan(Enums.ScannerType.XSS);
                foreach (var item in vulnerabilities)
                {
                    Console.WriteLine(item.ToString());
                }
            }
            else
                Console.WriteLine("Unable to load the files");
        }
        static string[] GetExamples(string path)
        {
            FileAttributes fileAttributes = File.GetAttributes(path);
            if (!fileAttributes.HasFlag(FileAttributes.Directory))
                return new string[] { path };
            else
                return Directory.EnumerateFiles(path, "*", SearchOption.TopDirectoryOnly).ToArray();
        }
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("usage : dotnet run -\"Path\"\nPath should be Folder or file");
                Console.WriteLine("Example : dotnet run -\"C:\\Examples\"");
                return;
            }
            string path = args[0].TrimStart('-');
            if (!Directory.Exists(path) && !File.Exists(path))
            {
                Console.WriteLine($"{path} is invalid");
                return;
            }
            string[] files = GetExamples(path);
            foreach (var file in files)
                LoadFiles(new string[] { file });
        }
    }
}