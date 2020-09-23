using System;
using System.Collections.Generic;
using System.Text;

namespace SAST.Engine.CSharp.Contract
{    
     /// <summary>
     /// Defines the methods to scan the Solution, Projects, and Csharp Source Files
     /// </summary>
    interface ISASTApp
    {
        /// <summary>
        /// Loading the files into SAST Scanner App
        /// </summary>
        /// <param name="filePaths">provide the file paths of Csharp Source files</param>
        /// <returns>true if loaded ,otherwise false </returns>
        bool LoadFiles(string[] filePaths);

        /// <summary>
        /// Scan all types of scanners in solution, projects or source files.
        /// </summary>
        /// <returns>List of vulnerabilities found</returns>
        IEnumerable<VulnerabilityDetail> ScanAll();

        /// <summary>
        /// Scan specific type of scanner in solution, projects or source files.
        /// </summary>
        /// <param name="scannerType">Pass specific type of Scanner</param>
        /// <returns></returns>
        IEnumerable<VulnerabilityDetail> Scan(Enums.ScannerType scannerType);
    }
}
