using Microsoft.CodeAnalysis;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Scanners;
using SAST.Engine.CSharp.Parser;
using ASTTask;
using Microsoft.CodeAnalysis.CSharp;

namespace SAST.Engine.CSharp.Core
{
    public class SASTApp : ISASTApp, IDisposable
    {
        AdhocWorkspace workspace;
        static List<MetadataReference> metadataReferences;

        static SASTApp()
        {
            Utils.LoadMetadata(out metadataReferences);
        }

        public bool LoadFiles(string[] filePaths)
        {
            if (filePaths == null || filePaths.Count() == 0)
                return false;
            //if (!filePaths.Any(file => string.IsNullOrEmpty(file)))
            //    return false;
            if (!filePaths.Any(file => !string.IsNullOrEmpty(file) && Utils.AvailableExtensions.Any(ext => Path.GetExtension(file).ToLower() == ext)))
                return false;

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
                    LanguageNames.CSharp);
                workspace.AddProject(projectInfo);
                LoadSourceFiles(projectInfo.Id, files);
                ResolveReferences();
                return true;
            }
        }

        private void ResolveReferences()
        {
            if (workspace == null || workspace.CurrentSolution == null || workspace.CurrentSolution.ProjectIds.Count() == 0)
                return;
            bool dependencyMayExists = workspace.CurrentSolution.ProjectIds.Count() > 1;
            //if (!dependencyMayExists)
            //    return;
            Solution solution = workspace.CurrentSolution;
            foreach (var parentProject in solution.Projects)
            {
                solution = solution.AddMetadataReferences(parentProject.Id, metadataReferences);
                if (!dependencyMayExists)
                    continue;
                if (parentProject.FilePath == null)
                    continue;
                IEnumerable<string> projectReferencePaths = DotnetParser.GetAttributes(parentProject.FilePath, "/Project/ItemGroup/ProjectReference", "Include", Utils.ProjectFileExtensions);
                if (projectReferencePaths == null || projectReferencePaths.Count() == 0)
                    continue;
                List<ProjectReference> references = new List<ProjectReference>();
                foreach (var item in projectReferencePaths)
                {
                    var childProject = solution.Projects.First(obj => obj.FilePath == item);
                    if (childProject != null)
                        solution = solution.AddProjectReference(parentProject.Id, new ProjectReference(childProject.Id));
                }
            }
            workspace.TryApplyChanges(solution);
            //DotnetParser.GetSourceFiles(projectPath, "/Project/ItemGroup/Compile", "Include", Utils.SourceCodeFileExtensions));
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
            //bool result = false;
            if (projectPaths == null || projectPaths.Count() == 0 || projectPaths.Any(path => string.IsNullOrWhiteSpace(path)))
                return false;
            foreach (var projectPath in projectPaths)
            {
                ProjectInfo projectInfo = ProjectInfo.Create(ProjectId.CreateNewId(), VersionStamp.Default, Path.GetFileNameWithoutExtension(projectPath), Path.GetFileNameWithoutExtension(projectPath),
                    LanguageNames.CSharp, projectPath);
                Solution solution = workspace.CurrentSolution.AddProject(projectInfo);
                List<string> sourceFilePaths = new List<string>();
                sourceFilePaths.AddRange(DotnetParser.GetAttributes(projectPath, "/Project/ItemGroup/Compile", "Include", Utils.SourceCodeFileExtensions));
                sourceFilePaths.AddRange(DotnetParser.GetAttributes(projectPath, "/Project/ItemGroup/Content", "Include", Utils.MarkupFileExtensions.Union(Utils.ConfigurationFileExtensions).ToArray()));
                //sourceFilePaths.AddRange(DotnetParser.GetSourceFiles(projectPath, "/Project/ItemGroup/Content", "Include", Utils.ConfigurationFileExtensions));
                workspace.TryApplyChanges(solution);
                LoadSourceFiles(projectInfo.Id, sourceFilePaths);
                ResolveReferences();
            }
            return true;
        }

        private bool LoadSolution(string solutionPath)
        {
            //if (!Microsoft.Build.Locator.MSBuildLocator.IsRegistered)
            //    Microsoft.Build.Locator.MSBuildLocator.RegisterDefaults();
            var projects = DotnetParser.ParseSolution(solutionPath);
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
                foreach (Project project in workspace.CurrentSolution.Projects)
                {
                    if (project.AdditionalDocuments.Count() > 0)
                    {
                        foreach (var item in project.AdditionalDocuments)
                        {
                            foreach (var scannerType in Enum.GetValues(typeof(ScannerType)).Cast<ScannerType>())
                            {
                                if (Utils.ConfigurationFileExtensions.Any(ext => ext == Path.GetExtension(item.FilePath).ToLower()))
                                {
                                    IConfigScanner configScanner = ConfigScan(scannerType);
                                    if (configScanner == null)
                                        continue;
                                    vulnerabilities.AddRange(configScanner.FindVulnerabilties(item.FilePath));
                                }
                                //else if (Utils.MarkupFileExtensions.Any(ext => ext == Path.GetExtension(item.FilePath).ToLower()))
                                //{
                                //    IConfigScanner markupScanner = MarkupScan(scannerType);
                                //    if (markupScanner == null)
                                //        continue;
                                //}
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
                ScannerType.XSS => new XssScanner(),
                ScannerType.XXE => new XxeScanner(),
                _ => null,
            };
        }

        private IConfigScanner ConfigScan(ScannerType scannerType)
        {
            return scannerType switch
            {
                ScannerType.FormsAuthentication => new FormsAuthenticationScanner(),
                ScannerType.InsecureCookie => new CookieFlagScanner(),
                ScannerType.MachineKeyClearText => new MachineKeyScanner(),
                _ => null,
            };
        }

        private IConfigScanner MarkupScan(ScannerType scannerType)
        {
            return scannerType switch
            {
                //ScannerType.XSS => new XssScanner(),
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
