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
            //fileNames = fileNames.Where(obj => obj.Contains("XssExample2")).ToArray();
            return fileNames;
        }
        static void Main(string[] args)
        {
            Program program = new Program();
            //string[] files = { Path.Combine(Directory.GetCurrentDirectory(), "Examples", "MVCWebApplication1", "MVCWebApplication1.sln") };
            //string[] files = { Path.Combine(Directory.GetCurrentDirectory(), "Examples", "MVCWebApplication1", "WebApplication1", "WebApplication1.csproJ") };
            string[] files = { Path.Combine(Directory.GetCurrentDirectory(), "Examples", "WebApplication3", "WebApplication3.sln") };
            LoadFiles(files);
            files = GetExamples().ToArray();
            LoadFiles(files);
            return;
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