using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Mapper;
using System;
using System.Collections.Generic;
using SAST.Engine.CSharp.Constants;
using System.Linq;

namespace SAST.Engine.CSharp.Scanners
{
    internal class FilePathInjectionScanner : IScanner
    {
        private static readonly string[] insecureMethods = {
           KnownMethod.System_IO_Directory_Exists,
           KnownMethod.System_IO_FileInfo_CopyTo,
           KnownMethod.System_IO_FileInfo_MoveTo,
           KnownMethod.System_IO_FileInfo_Replace,
           KnownMethod.System_IO_File_AppendAllLines,
           KnownMethod.System_IO_File_AppendAllText,
           KnownMethod.System_IO_File_AppendText,
           KnownMethod.System_IO_File_Copy,
           KnownMethod.System_IO_File_Create,
           KnownMethod.System_IO_File_CreateText,
           KnownMethod.System_IO_File_Delete,
           KnownMethod.System_IO_File_Exists,
           KnownMethod.System_IO_File_Move,
           KnownMethod.System_IO_File_Open,
           KnownMethod.System_IO_File_OpenRead,
           KnownMethod.System_IO_File_OpenText,
           KnownMethod.System_IO_File_OpenWrite,
           KnownMethod.System_IO_File_ReadAllBytes,
           KnownMethod.System_IO_File_ReadAllLines,
           KnownMethod.System_IO_File_ReadAllText,
           KnownMethod.System_IO_File_ReadLines,
           KnownMethod.System_IO_File_WriteAllBytes,
           KnownMethod.System_IO_File_WriteAllLines,
           KnownMethod.System_IO_File_WriteAllText,
        };
        private static readonly string[] ParameterNames = {
            "path",
            "sourceFileName",
            "destFileName",
            "destinationFileName",
            "destinationBackupFileName"
        };

        /// <summary>
        /// This Scanner to find File Path Vulnerabilities 
        /// </summary>
        /// <param name="syntaxNode"></param>
        /// <param name="filePath"></param>
        /// <param name="model"></param>
        /// <param name="solution"></param>
        /// <returns></returns>
        public IEnumerable<VulnerabilityDetail> FindVulnerabilties(SyntaxNode syntaxNode, string filePath, SemanticModel model = null, Solution solution = null)
        {
            List<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();
            var objectCreations = syntaxNode.DescendantNodesAndSelf().OfType<ObjectCreationExpressionSyntax>();
            foreach (var item in objectCreations)
            {
                ITypeSymbol typeSymbol = model.GetTypeSymbol(item);
                if (typeSymbol == null || typeSymbol.ToString() != KnownType.System_IO_FileInfo)
                    continue;
                if (item.ArgumentList != null && item.ArgumentList.Arguments.Count == 1)
                {
                    typeSymbol = model.GetTypeSymbol(item.ArgumentList.Arguments[0].Expression);
                    if (typeSymbol == null || typeSymbol.SpecialType != SpecialType.System_String)
                        continue;
                    if (Utils.IsVulnerable(item.ArgumentList.Arguments[0].Expression, model, solution))
                        vulnerabilities.Add(VulnerabilityDetail.Create(filePath,item,Enums.ScannerType.FilePathInjection));
                }
            }
            var invocationExpressions = syntaxNode.DescendantNodesAndSelf().OfType<InvocationExpressionSyntax>();
            foreach (var item in invocationExpressions)
            {
                ISymbol symbol = model.GetSymbol(item);
                if (symbol == null)
                    continue;
                if (!insecureMethods.Any(obj => obj == symbol.ContainingType.ToString() + "." + symbol.Name.ToString()))
                    continue;
                int index = 0;
                bool vulnerable = false;
                foreach (var argument in item.ArgumentList.Arguments)
                {
                    if (argument.NameColon == null)
                    {
                        if (symbol.Name.ToString() == "Replace" || symbol.Name.ToString() == "Copy" || symbol.Name.ToString() == "Move")
                            vulnerable = Utils.IsVulnerable(argument.Expression, model, solution, null);
                        else if (symbol.Name.ToString() == "WriteAllText" || symbol.Name.ToString() == "AppendAllText")
                            vulnerable = index >= 1 ? vulnerable : Utils.IsVulnerable(argument.Expression, model, solution, null);
                        else
                            vulnerable = Utils.IsVulnerable(argument.Expression, model, solution, null);
                    }
                    else if (ParameterNames.Any(obj => obj == argument.NameColon.Name.ToString()))
                        vulnerable = Utils.IsVulnerable(argument.Expression, model, solution, null);
                    if (vulnerable)
                    {
                        vulnerabilities.Add(VulnerabilityDetail.Create(filePath,item,Enums.ScannerType.FilePathInjection));
                        if (symbol.Name.ToString() == "Replace" || symbol.Name.ToString() == "Copy" || symbol.Name.ToString() == "Move"
                            || symbol.Name.ToString() == "WriteAllText" || symbol.Name.ToString() == "AppendAllText")
                            break;
                    }
                    index++;
                }
            }
            return vulnerabilities;
        }
    }
}