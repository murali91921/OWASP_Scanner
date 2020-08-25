using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using Microsoft.CodeAnalysis;

namespace SAST.Engine.CSharp.Tests
{
    class Program
    {
        //static ServiceCollection serviceCollection = new ServiceCollection();
        //static ServiceProvider serviceProvider;

        static string[] GetExamples(string path)
        {
            FileAttributes fileAttributes = File.GetAttributes(path);
            if (!fileAttributes.HasFlag(FileAttributes.Directory))
                return new string[] { path };
            else
                return Directory.EnumerateFiles(path, "*", SearchOption.TopDirectoryOnly)
                .Where(obj => obj.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
                || obj.EndsWith(".config", StringComparison.OrdinalIgnoreCase)
                || obj.EndsWith(".cs", StringComparison.OrdinalIgnoreCase)).ToArray();
        }
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("usage : dotnet run -Path\nPath should be Folder or file");
                Console.WriteLine("Example : dotnet run -\"C:\\Examples\"");
                return;
            }
            string Path = args[0].TrimStart('-');
            string[] files = GetExamples(Path);
            foreach (var file in files)
                LoadFiles(new string[] { file });
        }
        static void LoadFiles(string[] projectPaths)
        {
            Core.SASTApp sASTApp = new Core.SASTApp();
            if (sASTApp.LoadFiles(projectPaths))
            {
                IEnumerable<VulnerabilityDetail> vulnerabilities = sASTApp.ScanAll();
                foreach (var item in vulnerabilities)
                {
                    Console.WriteLine(item.ToString());
                }
            }
            else
                Console.WriteLine("Unable to load the files");
        }
    }
}