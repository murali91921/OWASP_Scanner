using System;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Task_1
{
    class Program
    {
        static void Main(string[] args)
        {
            //Sample Program
            string ProgramCode=@"using System;
            namespace Task_1
            {
                class Program
                {
                    static void Main(string[] args)
                    {
                        Console.WriteLine(""Hello World!"");
                    }
                }
            }";

            Console.WriteLine(ProgramCode);
            //Forming Syntax Tree
            SyntaxTree syntaxTree= CSharpSyntaxTree.ParseText(ProgramCode);
            CompilationUnitSyntax root= syntaxTree.GetCompilationUnitRoot();

            //Printing Members in Program
            Console.WriteLine("Kind : "+root.Kind().ToString());
            Console.WriteLine("Members : "+root.Members.Count);
            Console.WriteLine("Usings :"+root.Usings.Count);
            foreach (UsingDirectiveSyntax usingDirective in root.Usings)
                Console.WriteLine(usingDirective.Name);

            MemberDeclarationSyntax firstMember = root.Members[0];
            Console.WriteLine($"The first member is a {firstMember.Kind()}.");
            var helloWorldDeclaration = (NamespaceDeclarationSyntax)firstMember;
            // </Snippet4>

            // <Snippet5>
            Console.WriteLine($"There are {helloWorldDeclaration.Members.Count} members declared in this namespace.");
            Console.WriteLine($"The first member is a {helloWorldDeclaration.Members[0].Kind()}.");
            // </Snippet5>

            // <Snippet6>
            var programDeclaration = (ClassDeclarationSyntax)helloWorldDeclaration.Members[0];
            Console.WriteLine($"There are {programDeclaration.Members.Count} members declared in the {programDeclaration.Identifier} class.");
            Console.WriteLine($"The first member is a {programDeclaration.Members[0].Kind()}.");
            var mainDeclaration = (MethodDeclarationSyntax)programDeclaration.Members[0];
            // </Snippet6>

            // <Snippet7>
            Console.WriteLine("Method"+mainDeclaration.Identifier+" returns "+"mainDeclaration.ReturnType");
            foreach (ParameterSyntax item in mainDeclaration.ParameterList.Parameters)
                Console.WriteLine("\tParameter "+item.Identifier+" of type "+item.Type);
            Console.WriteLine("Body: "+ mainDeclaration.Body.ToFullString());
        }
    }
}
