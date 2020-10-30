using System.Diagnostics;
using System.Security;

namespace Example
{
    public static class CommandInjectionEx1
    {
        public static string cleanInput(this string param)
        {
            if (param.Contains(".."))
                return "/tmp/";
            return param.Trim();
        }

        public static string cleanInput(this string param, string check)
        {
            if (param.Contains(check))
                return "/tmp/";
            return param.Trim();
        }

        public static string cleanInput(this string param, int length)
        {
            if (param.Length > length)
                return "/tmp/";
            return param.Trim();
        }
        static ProcessStartInfo processStart = new ProcessStartInfo();
        static void method2(string param1, string param2)
        {
            processStart = new ProcessStartInfo();
            param1 = this.cleanInput(param1);
            param1 = param1.Substring(2);
            param1 = param1.cleanInput();
            Process process = Process.Start(param1);
            //Unsafe all
            processStart = new ProcessStartInfo(param1);
            processStart = new ProcessStartInfo(param1, param2);
            processStart = new ProcessStartInfo { FileName = param1 };
            processStart = new ProcessStartInfo { FileName = param1, Arguments = param2 };
            processStart = new ProcessStartInfo { Arguments = param2 };
        }
        public static string cleanInput(string param)
        {
            if (param.Contains(".."))
                return "/tmp/";
            return param.Trim();
        }
    }
}
