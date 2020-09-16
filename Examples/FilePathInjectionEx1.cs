using System.IO;

namespace Example
{
    public static class FilePathInjectionEx1
    {
        static void method(string srcfile, string destFile, string destBackupFile)
        {
            StringWriter sw = new StringWriter();
            sw.Close();
            byte[] bytes = new byte[int.MaxValue];
            //Directory.Exists(srcfile);
            FileInfo fileInfo = new FileInfo(srcfile);
            //destFile = "\Temp.txt";
            destFile = cleanInput(destFile);
            //destFile = cleanInput(out destFile);
            //destFile = destFile.cleanInput("sub");
            fileInfo.CopyTo(destFile);
            fileInfo.MoveTo(destFile);
            fileInfo.Replace(destFile, destBackupFile);
            fileInfo.Replace(destinationBackupFileName: destBackupFile, destinationFileName: destFile);
            File.AppendAllLines(destFile, null);
            //File.AppendAllLinesAsync(destFile,null);
            File.AppendAllText(destFile, "");
            //File.AppendAllTextAsync(destFile,"")
            File.AppendText(destFile);
            File.Copy(srcfile, destFile);
            File.Copy(destFileName: destFile, sourceFileName: srcfile);
            File.Create(destFile);
            File.CreateText(destFile);
            File.Delete(destFile);
            File.Exists(destFile);
            File.Move(srcfile, destFile);
            File.Move(destFileName: srcfile, sourceFileName: destFile);
            File.Open(destFile, FileMode.Open);
            File.OpenRead(destFile);
            File.OpenText(destFile);
            File.OpenWrite(destFile);
            File.ReadAllBytes(destFile);
            //File.ReadAllBytesAsync(destFile);
            File.ReadAllLines(destFile);
            //File.ReadAllLinesAsync(destFile);
            File.ReadAllText(destFile);
            //File.ReadAllTextAsync(destFile);
            File.ReadLines(destFile);
            File.WriteAllBytes(destFile, bytes);
            //File.WriteAllBytesAsync(destFile, bytes);
            File.WriteAllLines(destFile, null);
            //File.WriteAllLinesAsync(destFile, bytes);
            File.WriteAllText(destFile, "");
            //File.WriteAllTextAsync(destFile);
        }
        static string cleanInput(string str)
        {
			string[] loop = { @"C:\", @"D:\", @"E:\" };
            foreach (var item in loop)
            {
                if (str.StartsWith(item))
                    //return str;
				throw new ArgumentNullException();
            }
            if (str.EndsWith(".txt"))
                return "\temp";
            else
                return str;
        }
        static string cleanInput(out string str)
        {
            str = string.Empty;
            if (str.EndsWith(".txt"))
                return str;
            else
                return "/temp";
        }
        static string cleanInput(this string str, string sub)
        {
            str = string.Empty;
            if (str.EndsWith(".txt"))
                return str;
            else
                return "/temp";
        }
    }
}