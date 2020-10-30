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
            FileInfo fileInfo = new FileInfo("");   //Unsafe
            //destFile = "\Temp.txt";
            //destFile = cleanInput(destFile);
            //destFile = cleanInput(out destFile);
            //destFile = destFile.cleanInput("sub");
            fileInfo.CopyTo(destFile);	//Unsafe
            fileInfo.MoveTo(destFile);	//Unsafe
            fileInfo.Replace(destFile, destBackupFile);//Unsafe
            fileInfo.Replace(destinationBackupFileName: destBackupFile, destinationFileName: destFile);//Unsafe
            File.AppendAllLines(destFile, null);//Unsafe
            //File.AppendAllLinesAsync(destFile,null);
            File.AppendAllText(destFile, "");//Unsafe
            //File.AppendAllTextAsync(destFile,"")
            File.AppendText(destFile);//Unsafe
            File.Copy(srcfile, destFile);//Unsafe
            File.Copy(destFileName: destFile, sourceFileName: srcfile);//Unsafe
            File.Create(destFile);//Unsafe
            File.CreateText(destFile);//Unsafe
            File.Delete(destFile);//Unsafe
            File.Exists(destFile);//Unsafe
            File.Move(srcfile, destFile);//Unsafe
            File.Move(destFileName: srcfile, sourceFileName: destFile);//Unsafe
            File.Open(destFile, FileMode.Open);//Unsafe
            File.OpenRead(destFile);//Unsafe
            File.OpenText(destFile);//Unsafe
            File.OpenWrite(destFile);//Unsafe
            File.ReadAllBytes(destFile);//Unsafe
            //File.ReadAllBytesAsync(destFile);
            File.ReadAllLines(destFile);//Unsafe
            //File.ReadAllLinesAsync(destFile);
            File.ReadAllText(destFile);//Unsafe
            //File.ReadAllTextAsync(destFile);
            File.ReadLines(destFile);//Unsafe
            File.WriteAllBytes(destFile, bytes);//Unsafe
            //File.WriteAllBytesAsync(destFile, bytes);
            File.WriteAllLines(destFile, null);//Unsafe
            //File.WriteAllLinesAsync(destFile, bytes);
            File.WriteAllText(destFile, "");//Unsafe
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