using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using SAST.Engine.CSharp.Core;
using System.Xml.Serialization;

namespace SAST.Engine.CSharp.Tests
{
    public class Program
    {
        //static void ScanFiles(string[] projectPaths)
        //{
        //    Core.SASTApp sASTApp = new Core.SASTApp();
        //    if (sASTApp.LoadFiles(projectPaths))
        //    {
        //        //You can scan all scanners by calling sASTApp.ScanAll() method in below expression
        //        IEnumerable<VulnerabilityDetail> vulnerabilities = new List<VulnerabilityDetail>();//
        //        vulnerabilities = sASTApp.ScanAll();
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.CertificateValidation);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.CommandInjection);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.CorsAllowAnyOrigin);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.Csrf);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.EmptyCatch);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.EmptyTry);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.EventValidation);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.FilePathInjection);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.FormsAuthentication);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.HardcodePassword);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.HTTPHeaderChecking);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.InsecureCookie);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.InsecureDeserialization);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.InsecureRandom);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.JWTValidation);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.Ldap);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.MachineKeyClearText);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.OpenRedirect);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.SqlInjection);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.ViewStateMac);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.PasswordLockout);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.WeakCipherModePadding);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.WeakCryptoKeyLength);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.WeakHashingConfig);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.WeakPasswordConfig);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.WeakSymmetricAlgorithm);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.XPath);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.XSS);
        //        //vulnerabilities = sASTApp.Scan(Enums.ScannerType.XXE);
        //        //IEnumerable<VulnerabilityDetail> vulnerabilities = sASTApp.ScanAll();
        //        foreach (var item in vulnerabilities)
        //        {
        //            Console.WriteLine("\n" + item.ToString());
        //        }
        //    }
        //    else
        //        Console.WriteLine("Unable to load the files");
        //}

        //static string[] GetExamples(string path)
        //{
        //    FileAttributes fileAttributes = File.GetAttributes(path);
        //    if (!fileAttributes.HasFlag(FileAttributes.Directory))
        //        return new string[] { path };
        //    else
        //        return Directory.EnumerateFiles(path, "*", SearchOption.TopDirectoryOnly).ToArray();
        //}

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("usage : dotnet run -\"Path\"\nPath should be Folder or file");
                Console.WriteLine("Example : dotnet run -\"D:\\Examples\"");
                return;
            }
            string path = args[0].TrimStart('-');
            path = path.TrimEnd('\\');
            if (!Directory.Exists(path) && !File.Exists(path))
            {
                Console.WriteLine($"{path} is invalid");
                return;
            }

            IEnumerable<VulnerabilityDetail> vulnerabilities = null;
            if (Directory.Exists(path))
            {
                SASTApp sASTApp = new SASTApp();
                if (sASTApp.LoadFolder(path))
                    vulnerabilities = sASTApp.Scan(Enums.ScannerType.SerializationType);
            }
            else if (File.Exists(path))
            {
                SASTApp sASTApp = new SASTApp();
                if (sASTApp.LoadFiles(new string[] { path }))
                    vulnerabilities = sASTApp.Scan(Enums.ScannerType.SerializationType);
            }
            if (vulnerabilities != null)
                foreach (var item in vulnerabilities)
                    Console.WriteLine("\n" + item);
        }
    }
}