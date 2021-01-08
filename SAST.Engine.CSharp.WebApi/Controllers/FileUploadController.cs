using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SAST.Engine.CSharp.Core;

namespace SAST.Engine.CSharp.WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [RequestFormLimits(MultipartBodyLengthLimit = long.MaxValue)]
    public class SASTController : ControllerBase
    {
        private readonly FileConfiguration _fileConfiguration;
        public SASTController(FileConfiguration fileConfiguration)
        {
            _fileConfiguration = fileConfiguration;
        }

        [HttpGet]
        [Route("ScanAll")]
        public string ScanGet()
        {
            return "Use Post method to Scan the C# source code.";
        }

        [HttpPost]
        [Route("ScanAll")]
        [RequestFormLimits(MultipartBodyLengthLimit = long.MaxValue)]
        [RequestSizeLimit(long.MaxValue)]
        public async Task<string> ScanPost([FromForm] IFormFile File)
        {
            if (File == null)
            {
                Response.StatusCode = 400;
                return "Please provide File parameter";
            }
            FileInfo fileInfo = new FileInfo(File.FileName);
            if (string.IsNullOrEmpty(fileInfo.Extension) || fileInfo.Extension.ToLower() != ".zip")
                return "Please upload zip file only";
            else
            {
                string result = string.Empty;
                //Create directory to extract
                try
                {
                    var extractDirectory = Path.Combine(_fileConfiguration.DirectoryPath, Path.GetFileNameWithoutExtension(File.FileName));
                    var filePath = Path.Combine(_fileConfiguration.DirectoryPath, File.FileName);

                    if (!Directory.Exists(_fileConfiguration.DirectoryPath))
                        Directory.CreateDirectory(_fileConfiguration.DirectoryPath);

                    if (Directory.Exists(extractDirectory))
                        Directory.Delete(extractDirectory, true);

                    //Store zip file to Directory
                    using (var stream = new FileStream(filePath, FileMode.Create))
                    {
                        File.CopyTo(stream);
                    }

                    //Etraction of Files to Folder
                    ZipFile.ExtractToDirectory(filePath, extractDirectory);

                    //Scanning of Files
                    SASTApp sASTApp = new SASTApp();
                    if (Directory.Exists(extractDirectory) && sASTApp.LoadFolder(extractDirectory))
                    {
                        Response.StatusCode = 200;
                        IEnumerable<VulnerabilityDetail> vulnerabilities = sASTApp.ScanAll();
                        if (vulnerabilities == null || !vulnerabilities.Any())
                            result = "No Vulnerabilities found";
                        else
                            result = Newtonsoft.Json.JsonConvert.SerializeObject(vulnerabilities);
                    }
                }
                catch (PathTooLongException _)
                {
                    Response.StatusCode = 400;
                    result = "File Name was too long, Please upload with short name";
                }
                catch (InvalidDataException _)
                {
                    Response.StatusCode = 400;
                    result = "Unable to extract files from corrupted zip File.";
                }
                catch (Exception otherException)
                {
                    Response.StatusCode = 400;
                    result = otherException.ToString();
                }
                return result;
            }
        }
    }
}