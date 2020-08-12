using Microsoft.CodeAnalysis;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Scanners;

namespace SAST.Engine.CSharp.Core
{
    public class SASTApp : ISASTApp, IDisposable
    {
        static SASTApp()
        {
            //MSBuildLocator.RegisterDefaults();
            //if (instance == null)
            //    instance = Microsoft.Build.Locator.MSBuildLocator.RegisterDefaults();
        }
        AdhocWorkspace workspace;
        private List<MetadataReference> metadataReferences;
        public bool LoadFiles(string[] filePaths)
        {
            if (filePaths == null || filePaths.Count() == 0)
                return false;
            //if (!filePaths.Any(file => string.IsNullOrEmpty(file)))
            //    return false;
            if (!filePaths.Any(file => !string.IsNullOrEmpty(file) && Utils.AvailableExtensions.Any(ext => Path.GetExtension(file).ToLower() == ext)))
                return false;

            Utils.LoadMetadata(out metadataReferences);

            workspace = new AdhocWorkspace();

            if (filePaths.Any(file => Path.GetExtension(file).ToLower() == ".sln"))
            {
                var solutionFiles = filePaths.Where(file => Path.GetExtension(file).ToLower() == ".sln").ToArray();
                if (solutionFiles.Count() > 1)
                    return false;
                return LoadSolution(solutionFiles[0]);
            }
            else if (filePaths.Any(file => Path.GetExtension(file).ToLower() == ".csproj"))
            {
                var projectFiles = filePaths.Where(file => Path.GetExtension(file).ToLower() == ".csproj").ToArray();
                SolutionInfo solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Default);
                workspace.AddSolution(solutionInfo);
                return LoadProjects(projectFiles);
            }
            else
            {
                if (!(filePaths.Any(file => Utils.ConfigurationFileExtensions.Any(ext => ext == Path.GetExtension(file).ToLower())) ||
                    filePaths.Any(file => Utils.MarkupFileExtensions.Any(ext => ext == Path.GetExtension(file).ToLower())) ||
                    filePaths.Any(file => Utils.SourceCodeFileExtensions.Any(ext => ext == Path.GetExtension(file).ToLower()))))
                    return false;
                List<string> files = new List<string>();
                foreach (var item in filePaths)
                {
                    if (Utils.SourceCodeFileExtensions.Any(ext => ext == Path.GetExtension(item).ToLower()))
                        files.Add(item);
                    else if (Utils.MarkupFileExtensions.Any(ext => ext == Path.GetExtension(item).ToLower()))
                        files.Add(item);
                    else if (Utils.ConfigurationFileExtensions.Any(ext => ext == Path.GetExtension(item).ToLower()))
                        files.Add(item);
                }
                if (files.Count() == 0)
                    return false;
                SolutionInfo solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Default);
                workspace.AddSolution(solutionInfo);
                ProjectInfo projectInfo = ProjectInfo.Create(ProjectId.CreateNewId(), VersionStamp.Default, Path.GetRandomFileName(), Path.GetRandomFileName(),
                    LanguageNames.CSharp, metadataReferences: metadataReferences);
                workspace.AddProject(projectInfo);
                LoadSourceFiles(projectInfo.Id, files);
                return true;
            }
        }

        private bool LoadSourceFiles(ProjectId projectId, IEnumerable<string> sourceFiles)
        {
            if (projectId == null)
                return false;
            if (sourceFiles == null || sourceFiles.Count() == 0)
                return false;
            Solution solution = workspace.CurrentSolution;
            foreach (var source in sourceFiles)
            {
                if (Utils.SourceCodeFileExtensions.Any(ext => ext == Path.GetExtension(source).ToLower()))
                {
                    solution = solution.AddDocument(DocumentId.CreateNewId(projectId), Path.GetFileName(source), File.ReadAllText(source), filePath: source);
                }
                else if (Utils.ConfigurationFileExtensions.Concat(Utils.MarkupFileExtensions).Any(ext => ext == Path.GetExtension(source).ToLower()))
                {
                    solution = solution.AddAdditionalDocument(DocumentId.CreateNewId(projectId), Path.GetFileName(source), File.ReadAllText(source), filePath: source);
                    //solution = solution.AddAdditionalDocument(DocumentId.CreateNewId(projectId), Path.GetFileName(source), File.ReadAllText(source), filePath: source);
                }
            }
            workspace.TryApplyChanges(solution);
            return true;
        }

        private bool LoadProjects(string[] projectPaths)
        {
            bool result = false;
            if (projectPaths == null || projectPaths.Count() == 0 || projectPaths.Any(path => string.IsNullOrWhiteSpace(path)))
                return false;
            foreach (var projectPath in projectPaths)
            {
                ProjectInfo projectInfo = ProjectInfo.Create(ProjectId.CreateNewId(), VersionStamp.Default, Path.GetFileName(projectPath), Path.GetFileName(projectPath),
                    LanguageNames.CSharp, projectPath, metadataReferences: metadataReferences);
                workspace.AddProject(projectInfo);
                List<string> sourceFilePaths = new List<string>();
                sourceFilePaths.AddRange(DotnetParser.GetSourceFiles(projectPath, "/Project/ItemGroup/Compile", "Include", Utils.SourceCodeFileExtensions));
                sourceFilePaths.AddRange(DotnetParser.GetSourceFiles(projectPath, "/Project/ItemGroup/Content", "Include", Utils.MarkupFileExtensions.Union(Utils.ConfigurationFileExtensions).ToArray()));
                //sourceFilePaths.AddRange(DotnetParser.GetSourceFiles(projectPath, "/Project/ItemGroup/Content", "Include", Utils.ConfigurationFileExtensions));
                result = result || LoadSourceFiles(projectInfo.Id, sourceFilePaths);
            }
            return result;
        }
        //private Workspace AddAdditionalDocuments(Workspace workspace)
        //{
        //    if (workspace.CurrentSolution != null)
        //    {
        //        foreach (var project in workspace.CurrentSolution.Projects)
        //        {

        //            XmlTextReader reader = new XmlTextReader(project.FilePath);
        //            reader.Namespaces = false;
        //            XPathDocument document = new XPathDocument(reader);
        //            XPathNavigator navigator = document.CreateNavigator();
        //            //XPathNodeIterator nodes = navigator.Select("//book");
        //            XPathNodeIterator nodes = navigator.Select("/Project/ItemGroup/Content");
        //            while (nodes.MoveNext())
        //            {
        //                nodes.Current.MoveToFirstAttribute();
        //                do
        //                {
        //                    Console.WriteLine(nodes.Current.Name + "," + nodes.Current.Value);
        //                    if (string.Compare(nodes.Current.Name, "Include", true) == 0
        //                        && AdditionalExtensions.Any(obj => obj.EndsWith(Path.GetExtension(nodes.Current.Value.ToLower()))))
        //                    {
        //                        string additionalDocument = Path.GetDirectoryName(project.FilePath) + Path.DirectorySeparatorChar + nodes.Current.Value;
        //                        Console.WriteLine(additionalDocument);
        //                        Solution solution = workspace.CurrentSolution.AddAdditionalDocument(DocumentId.CreateNewId(project.Id), Path.GetFileName(additionalDocument),
        //                            File.ReadAllText(additionalDocument), filePath: additionalDocument);
        //                        workspace.TryApplyChanges(solution);
        //                        break;
        //                    }
        //                }
        //                while (nodes.Current.MoveToNextAttribute());
        //            }
        //        }
        //    }
        //    return workspace;
        //}
        private bool LoadSolution(string solutionPath)
        {
            IEnumerable<string> projects = DotnetParser.ParseSolution(solutionPath);
            if (projects.Count() == 0)
                return false;
            SolutionInfo solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Default, solutionPath);
            workspace.AddSolution(solutionInfo);
            return LoadProjects(projects.ToArray());
        }
        public IEnumerable<VulnerabilityDetail> ScanAll()
        {
            if (workspace == null || workspace.CurrentSolution == null || workspace.CurrentSolution.Projects == null || workspace.CurrentSolution.Projects.Count() == 0)
                return null;
            else
            {
                List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
                //Console.WriteLine("-------------------------------------------");
                foreach (Project project in workspace.CurrentSolution.Projects)
                {
                    if (project.AdditionalDocuments.Count() > 0)
                    {
                        foreach (var item in project.AdditionalDocuments)
                        {
                            foreach (var scannerType in Enum.GetValues(typeof(ScannerType)).Cast<ScannerType>())
                            {
                                if (Utils.ConfigurationFileExtensions.Any(ext => ext == Path.GetExtension(item.FilePath)))
                                {
                                    IConfigScanner configScanner = ConfigScan(scannerType);
                                    if (configScanner == null)
                                        continue;
                                    vulnerabilities.AddRange(configScanner.FindVulnerabilties(item.FilePath));
                                    //Console.WriteLine("{0} {1} {2}", "IConfigScanner", item.FilePath, scannerType);
                                }
                                else if (Utils.MarkupFileExtensions.Any(ext => ext == Path.GetExtension(item.FilePath)))
                                {
                                    //IConfigScanner configScanner = ConfigScan(scannerType);
                                    //if (configScanner == null)
                                    //    continue;
                                    //vulnerabilities.AddRange(configScanner.FindVulnerabilties(item.FilePath));
                                    //Console.WriteLine("{0} {1} {2}", "IMarkupScanner", item.FilePath, scannerType);
                                }
                            }
                        }
                    }
                    if (project.Documents != null)
                        foreach (var document in project.Documents)
                        {
                            var model = document.GetSemanticModelAsync().Result;
                            var syntaxNode = document.GetSyntaxRootAsync().Result;
                            foreach (var scannerType in Enum.GetValues(typeof(ScannerType)).Cast<ScannerType>())
                            {
                                IScanner scanner = Scan(scannerType);
                                if (scanner == null)
                                    continue;
                                vulnerabilities.AddRange(scanner.FindVulnerabilties(syntaxNode, document.FilePath, model, workspace.CurrentSolution));
                                //Console.WriteLine("{0} {1} {2}", "IScanner", document.FilePath, scannerType);
                                //vulnerabilities.AddRange(new CookieFlagScanner().FindVulnerabilties(syntaxNode, Path.GetFileName(document.FilePath), model, workspace));
                            }
                        }
                    else
                        break;
                }
                return vulnerabilities;
            }
        }
        private IScanner Scan(ScannerType scannerType)
        {
            return scannerType switch
            {
                ScannerType.Csrf => new CsrfScanner(),
                ScannerType.EmptyCatch => new EmptyCatchScanner(),
                ScannerType.EmptyTry => new EmptyTryScanner(),
                ScannerType.HardcodePassword => new CredsFinder(),
                ScannerType.InsecureCookie => new CookieFlagScanner(),
                ScannerType.InsecureRandom => new InsecureRandomScanner(),
                ScannerType.Ldap => new LDAPScanner(),
                ScannerType.OpenRedirect => new OpenRedirectScanner(),
                ScannerType.SqlInjection => new SqlInjectionScanner(),
                ScannerType.WeakHashingConfig => new WeakHashingValidator(),
                ScannerType.WeakPasswordConfig => new WeakPasswordValidator(),
                ScannerType.XPath => new XPathScanner(),
                _ => null,
            };
        }
        private IConfigScanner ConfigScan(ScannerType scannerType)
        {
            return scannerType switch
            {
                ScannerType.InsecureCookie => new CookieFlagScanner(),
                _ => null,
            };
        }
        public void Dispose()
        {
            workspace.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
