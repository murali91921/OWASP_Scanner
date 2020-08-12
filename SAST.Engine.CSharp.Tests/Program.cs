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

        static IEnumerable<string> GetExamples()
        {
            string exampleDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Examples");
            //string exampleDirectory = Path.Combine(Directory.GetParent(".").Parent.Parent.ToString(), "Examples");
            IEnumerable<string> fileNames = Directory.EnumerateFiles(exampleDirectory, "*", SearchOption.TopDirectoryOnly)
                .Where(obj => obj.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
                || obj.EndsWith(".config", StringComparison.OrdinalIgnoreCase)
                || obj.EndsWith(".cs", StringComparison.OrdinalIgnoreCase));
            //fileNames = fileNames.Where(obj => obj.Contains("XPath")).ToArray();
            return fileNames;
        }
        static void Main(string[] args)
        {
            Program program = new Program();
            string[] files;

            files = new string[] { @"C:\Users\Ceaselez\source\repos\MVCWebApplication1\MVCWebApplication1.sln" };
            //program.LoadFiles(files);

            //files = new string[] { @"C:\Users\Ceaselez\source\repos\CoreMVCWebApplication1\CoreMVCWebApplication1\CoreMVCWebApplication1.csproj" };
            files = new string[] { @"C:\Users\Ceaselez\source\repos\MVCWebApplication1\WebApplication1\WebApplication1.csproj" };
            //program.LoadFiles(files);

            files = GetExamples().ToArray();
            foreach (var item in files)
            {
                program.LoadFiles(new string[] { item });
            }
        }
        void LoadFiles(string[] projectPaths)
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