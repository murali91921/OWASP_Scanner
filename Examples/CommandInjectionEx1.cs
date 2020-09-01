using System.Diagnostics;
using System.Security;

namespace Example
{
    class CommandInjectionEx1
    {
        static ProcessStartInfo processStart = new ProcessStartInfo();
        static Process process = new Process();
        static void method(string param1, string param2)
        {
            process.Start();
            Process.Start(processStart);

            //Unsafe all
            Process.Start(param1);
            Process.Start(param1, "", new SecureString(), "domain");
            Process.Start(param1, param2);
            Process.Start(fileName: param1, userName: "", arguments: param2, password: new SecureString(), domain: "domain");
        }
        static void method2(string param1, string param2)
        {
            processStart = new ProcessStartInfo();

            //Unsafe all
            processStart = new ProcessStartInfo(param1);
            processStart = new ProcessStartInfo(param1, param2);
            processStart = new ProcessStartInfo { FileName = param1 };
            processStart = new ProcessStartInfo { FileName = param1, Arguments = param2 };
            processStart = new ProcessStartInfo { Arguments = param2 };
        }
    }
}
