using Microsoft.CodeAnalysis;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System;
using SAST.Engine.CSharp.Enums;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Scanners;
using SAST.Engine.CSharp.Parser;
using Microsoft.CodeAnalysis.CSharp;
using Antlr4.Runtime;
using System.Xml.XPath;
using System.Xml;

namespace SAST.Engine.CSharp.Core
{
    /// <summary>
    /// This class will load the Solution, Projects or CSharp source files into Memory and scan the vulnerabilities on each Source File & Config files.
    /// </summary>
    public class SASTApp : ISASTApp
    {
        List<AdhocWorkspace> workspaces;
        AdhocWorkspace currentWorkspace;
        static List<MetadataReference> metadataReferences;

        /// <summary>
        /// This constructor will load required assemblies into Memory.
        /// </summary>
        static SASTApp() => Utils.LoadMetadata(out metadataReferences);

        /// <summary>
        /// Load the all the Csharp Files in the <paramref name="folderName"/> into Memory.
        /// </summary>
        /// <param name="folderName">Folder Path of Solution, Projects or Chsarp source files</param>
        /// <returns></returns>
        public bool LoadFolder(string folderPath)
        {
            if (string.IsNullOrEmpty(folderPath) || !Directory.Exists(folderPath))
                return false;
            IEnumerable<string> sourcefiles = Directory.EnumerateFiles(folderPath, "*.*", SearchOption.AllDirectories);
            if (sourcefiles.Count() > 0)
                return LoadFiles(sourcefiles.ToArray());
            return false;
        }

        /// <summary>
        /// Load the all the Solutions, Projects, Csharp Files in the <paramref name="filePaths"/> into Memory.
        /// </summary>
        /// <param name="filePaths">File Path of Solution, Projects or Chsarp source files</param>
        /// <returns></returns>
        public bool LoadFiles(string[] filePaths)
        {
            if (filePaths == null || filePaths.Count() == 0)
                return false;
            if (!filePaths.Any(file => !string.IsNullOrEmpty(file) && Utils.AvailableExtensions.Any(ext => Path.GetExtension(file).ToLower() == ext)))
                return false;

            workspaces = new List<AdhocWorkspace>();
            if (filePaths.Any(file => file.EndsWith(".sln", StringComparison.OrdinalIgnoreCase)))
            {
                var solutionFiles = filePaths.Where(file => Path.GetExtension(file).ToLower() == ".sln").ToArray();
                if (solutionFiles.Count() == 0)
                    return false;

                //workspaces = new List<AdhocWorkspace>();
                foreach (var item in solutionFiles)
                {
                    currentWorkspace = new AdhocWorkspace();
                    LoadSolution(item);
                    workspaces.Add(currentWorkspace);
                }

                foreach (var workspace in workspaces)
                {
                    foreach (var project in workspace.CurrentSolution.Projects)
                    {
                        var documentPaths = project.Documents.Select(obj => obj.FilePath);
                        var tempPaths = filePaths.ToList();
                        tempPaths.RemoveAll(obj => documentPaths.Contains(obj));
                        tempPaths.Remove(project.FilePath);
                        filePaths = tempPaths.ToArray();
                    }
                }
                if (filePaths.Length == 0)
                    return true;
            }
            else if (filePaths.Any(file => file.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase)))
            {
                currentWorkspace = new AdhocWorkspace();
                var projectFiles = filePaths.Where(file => Path.GetExtension(file).ToLower() == ".csproj").ToArray();
                SolutionInfo solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Default);
                currentWorkspace.AddSolution(solutionInfo);
                if (LoadProjects(projectFiles))
                {
                    //workspaces = new List<AdhocWorkspace>();
                    foreach (var project in currentWorkspace.CurrentSolution.Projects)
                    {
                        var documentPaths = project.Documents.Select(obj => obj.FilePath);
                        var tempPaths = filePaths.ToList();
                        tempPaths.RemoveAll(obj => documentPaths.Contains(obj));
                        tempPaths.Remove(project.FilePath);
                        filePaths = tempPaths.ToArray();
                    }
                    workspaces.Add(currentWorkspace);
                    return true;
                }
                else
                    return false;
            }
           if (filePaths.Any(file =>
                Utils.ConfigurationFileExtensions.Any(ext => file.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) ||
                Utils.SourceCodeFileExtensions.Any(ext => file.EndsWith(ext, StringComparison.OrdinalIgnoreCase)) ||
                Utils.MarkupFileExtensions.Any(ext => file.EndsWith(ext, StringComparison.OrdinalIgnoreCase))))
            {
                List<string> files = new List<string>();
                foreach (var item in filePaths)
                {
                    if (Utils.SourceCodeFileExtensions.Any(ext => ext == Path.GetExtension(item).ToLower())
                        || Utils.MarkupFileExtensions.Any(ext => ext == Path.GetExtension(item).ToLower())
                        || Utils.ConfigurationFileExtensions.Any(ext => ext == Path.GetExtension(item).ToLower()))
                        files.Add(item);
                }
                if (files.Count() == 0)
                    return false;
                currentWorkspace = new AdhocWorkspace();
                SolutionInfo solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Default);
                currentWorkspace.AddSolution(solutionInfo);
                ProjectInfo projectInfo = ProjectInfo.Create(ProjectId.CreateNewId(), VersionStamp.Default, Path.GetRandomFileName(), Path.GetRandomFileName(),
                    LanguageNames.CSharp);
                currentWorkspace.AddProject(projectInfo);
                LoadSourceFiles(projectInfo.Id, files);
                ResolveReferences();
                workspaces.Add(currentWorkspace);
                return true;
            }
            return false;
        }

        /// <summary>
        /// This Method will resolve Project References and adding the Required Assemblies to each Project.
        /// </summary>
        private void ResolveReferences()
        {
            if (currentWorkspace == null || currentWorkspace.CurrentSolution == null || currentWorkspace.CurrentSolution.ProjectIds.Count() == 0)
                return;
            //Finding atleast one Dependency exists between projects or not.
            bool dependencyMayExists = currentWorkspace.CurrentSolution.ProjectIds.Count() > 1;

            Solution solution = currentWorkspace.CurrentSolution;
            foreach (var parentProject in solution.Projects)
            {
                //Adding required assemblies to Project.
                solution = solution.AddMetadataReferences(parentProject.Id, metadataReferences);
                if (!dependencyMayExists)
                    continue;
                if (parentProject.FilePath == null)
                    continue;
                //Finding the ProjectReferences in Project File
                IEnumerable<string> projectReferencePaths = XMLParser.GetAttributes(parentProject.FilePath, "/Project/ItemGroup/ProjectReference", "Include", Utils.ProjectFileExtensions);
                if (projectReferencePaths == null || projectReferencePaths.Count() == 0)
                    continue;
                List<ProjectReference> references = new List<ProjectReference>();
                foreach (var item in projectReferencePaths)
                {
                    //Finding the Project References by comparing FilePath attribute in ProjectFile and in Workspace.
                    var childProject = solution.Projects.FirstOrDefault(obj => obj.FilePath == item);
                    if (childProject != null)
                        solution = solution.AddProjectReference(parentProject.Id, new ProjectReference(childProject.Id));
                }
            }
            //Applying the changes made.
            currentWorkspace.TryApplyChanges(solution);
        }

        /// <summary>
        /// Loading the source Files into workspace Project.
        /// </summary>
        /// <param name="projectId">ProjectId in workspace</param>
        /// <param name="sourceFiles">Source files paths,(.cs, .config files)</param>
        /// <returns></returns>
        private bool LoadSourceFiles(ProjectId projectId, IEnumerable<string> sourceFiles)
        {
            if (projectId == null)
                return false;
            if (sourceFiles == null || sourceFiles.Count() == 0)
                return false;
            Solution solution = currentWorkspace.CurrentSolution;
            foreach (var source in sourceFiles)
            {
                //Checking source file exists or no & file have content or not.
                if (!File.Exists(source) || string.IsNullOrWhiteSpace(File.ReadAllText(source)))
                    continue;
                try
                {
                    if (Utils.SourceCodeFileExtensions.Any(ext => ext == Path.GetExtension(source).ToLower()))
                        solution = solution.AddDocument(DocumentId.CreateNewId(projectId), Path.GetFileName(source), File.ReadAllText(source), filePath: source);
                    else if (Utils.ConfigurationFileExtensions.Concat(Utils.MarkupFileExtensions).Any(ext => ext == Path.GetExtension(source).ToLower()))
                        solution = solution.AddAdditionalDocument(DocumentId.CreateNewId(projectId), Path.GetFileName(source), File.ReadAllText(source), filePath: source);
                }
                catch
                { }
            }
            currentWorkspace.TryApplyChanges(solution);
            return true;
        }

        /// <summary>
        /// Load the Projects into workspace Solution
        /// </summary>
        /// <param name="projectPaths">File paths of Projects</param>
        /// <returns></returns>
        private bool LoadProjects(string[] projectPaths)
        {
            if (projectPaths == null || projectPaths.Count() == 0 || projectPaths.Any(path => string.IsNullOrWhiteSpace(path)))
                return false;
            foreach (var projectPath in projectPaths)
            {
                if (!File.Exists(projectPath) || string.IsNullOrWhiteSpace(File.ReadAllText(projectPath)))
                    continue;
                //Cretaing ProjectInfo
                ProjectInfo projectInfo = ProjectInfo.Create(ProjectId.CreateNewId(), VersionStamp.Default, Path.GetFileNameWithoutExtension(projectPath), Path.GetFileNameWithoutExtension(projectPath),
                    LanguageNames.CSharp, projectPath);
                //Adding the Project to workspace Solution.
                Solution solution = currentWorkspace.CurrentSolution.AddProject(projectInfo);
                List<string> sourceFilePaths = new List<string>();

                //Checking for NetStandard, NetCore because if Project targeting NetStandard, NetCore, we should include all directories under Project Directory
                IEnumerable<string> frameworks = XMLParser.GetAttributes(projectPath, "/Project/PropertyGroup/TargetFramework", null, null);
                if (frameworks == null || frameworks.Count() == 0)
                {
                    sourceFilePaths.AddRange(XMLParser.GetAttributes(projectPath, "/Project/ItemGroup/Compile", "Include", Utils.SourceCodeFileExtensions));
                    sourceFilePaths.AddRange(XMLParser.GetAttributes(projectPath, "/Project/ItemGroup/Content", "Include", Utils.MarkupFileExtensions.Union(Utils.ConfigurationFileExtensions).ToArray()));
                }
                else
                {
                    string directory = Path.GetDirectoryName(projectPath);
                    foreach (var item in Utils.SourceCodeFileExtensions)
                    {
                        sourceFilePaths.AddRange(Directory.EnumerateFiles(directory, "*" + item, SearchOption.AllDirectories));
                    }
                    foreach (var item in Utils.MarkupFileExtensions)
                    {
                        sourceFilePaths.AddRange(Directory.EnumerateFiles(directory, "*" + item, SearchOption.AllDirectories));
                    }
                    foreach (var item in Utils.ConfigurationFileExtensions)
                    {
                        sourceFilePaths.AddRange(Directory.EnumerateFiles(directory, "*" + item, SearchOption.AllDirectories));
                    }
                }
                currentWorkspace.TryApplyChanges(solution);
                //Loading the source Files (.cs,.config ) to add them in Project.
                LoadSourceFiles(projectInfo.Id, sourceFilePaths);
            }
            ResolveReferences();
            return true;
        }

        /// <summary>
        /// Loads the solution into workspace
        /// </summary>
        /// <param name="solutionPath">File path of solution</param>
        /// <returns></returns>
        private bool LoadSolution(string solutionPath)
        {
            if (!File.Exists(solutionPath) || string.IsNullOrWhiteSpace(File.ReadAllText(solutionPath)))
                return false;
            //Finding the projects from Solution File
            var projects = SolutionParser.ParseSolution(solutionPath);
            if (projects.Count() == 0)
                return false;
            //Create solution & adding to workspace
            SolutionInfo solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Default, solutionPath);
            currentWorkspace.AddSolution(solutionInfo);
            //Loading the Projects into Solution.
            return LoadProjects(projects.ToArray());
        }

        /// <summary>
        /// This method will find all types of vulnearbilies in entire Solution.
        /// </summary>
        /// <returns>List of Vulnerabilities</returns>
        public IEnumerable<VulnerabilityDetail> ScanAll()
        {
            if (workspaces == null || workspaces.Count == 0)
                return null;
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            foreach (var scannerType in Enum.GetValues(typeof(ScannerType)).Cast<ScannerType>())
            {
                IEnumerable<VulnerabilityDetail> currentVulnerabilities = Scan(scannerType);
                vulnerabilities.AddRange(currentVulnerabilities);
            }
            return vulnerabilities;
        }

        /// <summary>
        /// This method will specific type of vulnerability in entire Solution.
        /// </summary>
        /// <param name="scannerType">Specific type of vulnerability</param>
        /// <returns>List of Vulnerabilities</returns>
        public IEnumerable<VulnerabilityDetail> Scan(ScannerType scannerType)
        {
            if (workspaces == null || workspaces.Count == 0)
                return null;

            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            foreach (var workspace in workspaces)
            {
                foreach (Project project in workspace.CurrentSolution.Projects)
                {
                    if (project.AdditionalDocuments.Count() > 0)
                    {
                        foreach (var item in project.AdditionalDocuments)
                        {
                            if (Utils.ConfigurationFileExtensions.Any(ext => ext == Path.GetExtension(item.FilePath).ToLower()))
                            {
                                IConfigScanner configScanner = GetConfigScanner(scannerType);
                                if (configScanner == null)
                                    continue;
                                vulnerabilities.AddRange(configScanner.FindVulnerabilties(item.FilePath));
                            }
                            else if ((Utils.MarkupFileExtensions.Any(ext => ext == Path.GetExtension(item.FilePath).ToLower())))
                            {
                                ICSHtmlScanner cSHtmlScanner = GetCshtmlScanner(scannerType);
                                if (cSHtmlScanner == null)
                                    continue;
                                vulnerabilities.AddRange(cSHtmlScanner.FindVulnerabilities(item.FilePath));
                            }
                        }
                    }
                    if (project.Documents != null)
                        foreach (var document in project.Documents)
                        {
                            IScanner scanner = GetScanner(scannerType);
                            if (scanner == null)
                                continue;
                            vulnerabilities.AddRange(scanner.FindVulnerabilties(document.GetSyntaxRootAsync().Result, document.FilePath,
                                document.GetSemanticModelAsync().Result, workspace.CurrentSolution));
                        }
                    else
                        break;
                }
            }
            return vulnerabilities;
        }

        /// <summary>
        /// This wiil create the required IScanner object based on ScannerType
        /// </summary>
        /// <param name="scannerType"></param>
        /// <returns>IScanner Object</returns>
        private IScanner GetScanner(ScannerType scannerType)
        {
            return scannerType switch
            {
                ScannerType.Csrf => new CsrfScanner(),
                ScannerType.EmptyCatch => new EmptyCatchScanner(),
                ScannerType.EmptyTry => new EmptyTryScanner(),
                ScannerType.HardcodePassword => new CredsFinder(),
                ScannerType.InsecureCookie => new CookieFlagScanner(),
                ScannerType.InsecureRandom => new InsecureRandomScanner(),
                ScannerType.LdapInjection => new LDAPScanner(),
                ScannerType.OpenRedirect => new OpenRedirectScanner(),
                ScannerType.SqlInjection => new SqlInjectionScanner(),
                ScannerType.WeakHashingConfig => new WeakHashingValidator(),
                ScannerType.WeakPasswordConfig => new WeakPasswordValidator(),
                ScannerType.XPath => new XPathScanner(),
                ScannerType.XSS => new XssScanner(),
                ScannerType.XXE => new XxeScanner(),
                ScannerType.WeakSymmetricAlgorithm => new WeakSymmetricAlgorithmScanner(),
                ScannerType.WeakCipherModePadding => new WeakCipherModeScanner(),
                ScannerType.InsecureDeserialization => new InsecureDeserializationScanner(),
                ScannerType.CommandInjection => new CommandInjectionScanner(),
                ScannerType.FilePathInjection => new FilePathInjectionScanner(),
                ScannerType.CertificateValidation => new CertificateValidationScanner(),
                ScannerType.JWTValidation => new JWTSignatureScanner(),
                ScannerType.PasswordLockout => new PasswordLockoutScanner(),
                ScannerType.Authorize => new AuthorizeScanner(),
                ScannerType.CorsAllowAnyOrigin => new CorsScanner(),
                ScannerType.WeakCryptoKeyLength => new WeakCryptoKeyLengthScanner(),
                ScannerType.SerializationType => new SerializationTypeScanner(),
                ScannerType.LdapSecureConnection => new LdapSecureConnectionScanner(),
                ScannerType.RegexInjection => new RegexInjectionScanner(),
                ScannerType.HttpRequestValidation => new HttpRequestValidationScanner(),
                ScannerType.SerializationConstructor => new SerializationConstructorScanner(),
                ScannerType.HardcodedIpAddress => new HardcodedIPScanner(),
                ScannerType.ExportInterface => new ExportInterfaceScanner(),
                ScannerType.ThreadSuspendResume => new ThreadSuspendResumeScanner(),
                ScannerType.SafeHandle => new SafeHandleScanner(),
                ScannerType.RecursiveTypeInheritance => new RecursiveTypeInheritScanner(),
                ScannerType.IDisposableImplement => new IDisposableImplementScanner(),
                ScannerType.DisposableMember => new DisposableMemberScanner(),
                _ => null,
            };
        }

        /// <summary>
        /// This wiil create the required IConfigScanner object based on ScannerType
        /// </summary>
        /// <param name="scannerType"></param>
        /// <returns>IConfigScanner Object</returns>
        private IConfigScanner GetConfigScanner(ScannerType scannerType)
        {
            return scannerType switch
            {
                ScannerType.FormsAuthentication => new FormAuthenticationScanner(),
                ScannerType.InsecureCookie => new CookieFlagScanner(),
                ScannerType.MachineKeyClearText => new MachineKeyScanner(),
                ScannerType.HTTPHeaderChecking => new HTTPHeaderCheckingScanner(),
                ScannerType.EventValidation => new EventValidationScanner(),
                ScannerType.ViewStateMac => new ViewStateMacScanner(),
                _ => null,
            };
        }

        /// <summary>
        /// This wiil create the required ICSHtmlScanner object based on ScannerType
        /// </summary>
        /// <param name="scannerType"></param>
        /// <returns>ICSHtmlScanner object</returns>
        private ICSHtmlScanner GetCshtmlScanner(ScannerType scannerType)
        {
            return scannerType switch
            {
                ScannerType.XSS => new XssScanner(),
                _ => null,
            };
        }

    }
}
