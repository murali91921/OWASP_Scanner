using System;
using System.Collections.Generic;
using System.Text;

namespace SAST.Engine.CSharp.Contract
{
    interface ISASTApp
    {
        /// <summary>
        /// Loading the files into SAST Scanner App
        /// </summary>
        /// <param name="filePaths">provide the file paths of CS file.</param>
        /// <returns>true if loaded ,otherwise false </returns>
        bool LoadFiles(string[] filePaths);
        /// <summary>
        /// Loading the files into SAST Scanner App
        /// </summary>
        /// <param name="solutionPath">provide the file path of Solution file.</param>
        /// <returns>true if loaded ,otherwise false </returns>
        //bool LoadSolution(string solutionPath);
        /// <summary>
        /// Loading the files into SAST Scanner App
        /// </summary>
        /// <param name="projectPaths">provide the file paths of Project file.</param>
        /// <returns>true if loaded ,otherwise false </returns>
        //bool LoadProjects(string[] projectPaths);
        /// <summary>
        /// Loading the files into SAST Scanner App
        /// </summary>
        /// <returns>List of vulnerabilities found</returns>
        IEnumerable<VulnerabilityDetail> ScanAll();
    }
}
