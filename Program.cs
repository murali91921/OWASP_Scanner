using System.IO;
using System;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace Task_1
{
    class Program
    {
        static void Main(string[] args)
        {
            string curDir=Directory.GetCurrentDirectory()+"\\Examples";
            Console.WriteLine(curDir);
            string[] fileNames = Directory.GetFiles(curDir);

            foreach(string fileName in fileNames)
            {
                Console.WriteLine(fileName);
                string programLines = File.ReadAllText(fileName);
                //Console.WriteLine(programLines);
                //Forming Syntax Tree
                SyntaxTree syntaxTree= CSharpSyntaxTree.ParseText(programLines);
                CompilationUnitSyntax root= syntaxTree.GetCompilationUnitRoot();

                //Printing Members in Program
                Console.WriteLine("Kind : "+root.Kind().ToString());
                Console.WriteLine("Members : "+root.Members.Count);
                Console.WriteLine("Usings :"+root.Usings.Count);
                foreach (UsingDirectiveSyntax usingDirective in root.Usings)
                    Console.WriteLine(usingDirective.Name);

                MemberDeclarationSyntax firstMember = root.Members[0];
                Console.WriteLine("Kind : "+firstMember.Kind());
                var helloWorldDeclaration = (NamespaceDeclarationSyntax)firstMember;

                Console.WriteLine(helloWorldDeclaration.Members.Count+" members declared in this namespace.");
                foreach (var classes in helloWorldDeclaration.Members)
                {
                    Console.WriteLine( (classes as ClassDeclarationSyntax).Identifier +":" +classes.Kind());
                    if(classes.Kind()== SyntaxKind.ClassDeclaration)
                    {
                        ClassDeclarationSyntax classDeclarationSyntax=(ClassDeclarationSyntax)classes;
                        foreach (var classMember in classDeclarationSyntax.Members)
                        {
                            switch(classMember.Kind())
                            {
                                case SyntaxKind.MethodDeclaration :
                                    MethodDeclarationSyntax method= classMember as MethodDeclarationSyntax;
                                    Console.WriteLine("Method "+method.Identifier+" ,returns "+method.ReturnType);
                                    foreach (ParameterSyntax item in method.ParameterList.Parameters)
                                        Console.WriteLine("Parameter '"+item.Identifier+"' of type '"+item.Type+"'");
                                    //Console.WriteLine("\tBody: "+ mainDeclaration.Body.ToFullString());
                                break;
                                case SyntaxKind.FieldDeclaration:
                                    FieldDeclarationSyntax field = classMember as FieldDeclarationSyntax;
                                    foreach (VariableDeclaratorSyntax item in field.Declaration.Variables)
                                    {
                                    Console.WriteLine("Field : "+item.Identifier+" " +field.Declaration.Type);                                
                                        
                                    }
                                break;
                            
                        }
                    }
                }
                    Console.WriteLine();
            }
        }
    }
}
}