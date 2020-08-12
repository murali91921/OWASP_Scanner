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
            //fileNames = fileNames.Where(obj => obj.Contains("config")).ToArray();
            return fileNames;
        }
        static void Main(string[] args)
        {
            //IEnumerable<string> fileNames = GetExamples();
            //foreach (string filePath in fileNames)
            //{
            //    //Console.WriteLine(filePath);
            //    //Console.ReadLine();
            //    Core.SASTApp sASTApp = new Core.SASTApp();
            //    if (sASTApp.LoadFiles(new string[] { filePath }))
            //    {
            //        IEnumerable<VulnerabilityDetail> vulnerabilities = sASTApp.ScanAll();
            //        foreach (var item in vulnerabilities)
            //        {
            //            Console.WriteLine(item.ToString());
            //        }
            //    }
            //    else
            //        Console.WriteLine("Unable to load the files");
            //}
            string solutionFile;
            Program program = new Program();

            //solutionFile = @"C:\Users\Ceaselez\source\repos\ConsoleCoreHashApp1\ConsoleCoreHashApp1.sln";
            //program.LoadSolution(solutionFile);

            //solutionFile = @"C:\Users\Ceaselez\source\repos\ConsoleHashingApp1\ConsoleHashingApp1.sln";
            //program.LoadSolution(solutionFile);

            solutionFile = @"C:\Users\Ceaselez\source\repos\MVCWebApplication1\MVCWebApplication1.sln";
            program.LoadSolution(solutionFile);

            string[] projects = { @"C:\Users\Ceaselez\source\repos\CoreMVCWebApplication1\CoreMVCWebApplication1\CoreMVCWebApplication1.csproj" };
            //program.LoadProjects(projects);

            projects = new string[] { @"C:\Users\Ceaselez\source\repos\MVCWebApplication1\WebApplication1\WebApplication1.csproj" };
            program.LoadProjects(projects);

            //projects = new string[] { @"C:\Users\Ceaselez\source\repos\WebApplication1\WebApplication1\WebApplication1.csproj" };
            //program.LoadProjects(projects);

        }
        void LoadProjects(string[] projectPaths)
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
        void LoadSolution(string solutionFile)
        {
            Core.SASTApp sASTApp = new Core.SASTApp();
            if (sASTApp.LoadFiles(new string[] { solutionFile }))
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