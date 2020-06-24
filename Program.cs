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
            //Accessig Files under "Examples" directory
            try
            {
                string curDir=Directory.GetCurrentDirectory()+"\\Examples";
                string[] fileNames = Directory.GetFiles(curDir);

                foreach(string fileName in fileNames)
                {
                    string programLines = File.ReadAllText(fileName);
                    //Forming Syntax Tree
                    SyntaxTree syntaxTree= CSharpSyntaxTree.ParseText(programLines);
                    CompilationUnitSyntax root= syntaxTree.GetCompilationUnitRoot();

                    //Printing Members in Program
                    Console.WriteLine("Usings :"+root.Usings.Count);
                    foreach (UsingDirectiveSyntax usingDirective in root.Usings)
                        Console.WriteLine("Using : "+usingDirective.Name);

                    //Namespace Declarartion
                    MemberDeclarationSyntax firstMember = root.Members[0];
                    var namespaceDeclarationSyntax = (NamespaceDeclarationSyntax)firstMember;

                        Console.WriteLine("Namespace :"+ namespaceDeclarationSyntax.Name);
                    Console.WriteLine(namespaceDeclarationSyntax.Members.Count+" members declared in this namespace.");
                    //looping all members under namespace
                    foreach (var classes in namespaceDeclarationSyntax.Members)
                    {
                        if(classes.Kind()== SyntaxKind.ClassDeclaration)
                        {
                            //Parsing of Class
                            ClassDeclarationSyntax classDeclarationSyntax=(ClassDeclarationSyntax)classes;
                            Console.WriteLine("\nClass :"+classDeclarationSyntax.Identifier);
                            foreach (var classMember in classDeclarationSyntax.Members)
                            {
                                switch(classMember.Kind())
                                {
                                    case SyntaxKind.MethodDeclaration :
                                    //Parsing of Methods
                                        MethodDeclarationSyntax method= classMember as MethodDeclarationSyntax;
                                        Console.WriteLine("Method : "+method.Identifier+" , "+method.ReturnType);
                                        foreach (ParameterSyntax item in method.ParameterList.Parameters)
                                            Console.WriteLine("  Parameter : "+item.Identifier+" , "+item.Type);
                                        Console.WriteLine("  Body Length : "+ method.Body.ToFullString().Length);
                                    break;
                                    case SyntaxKind.FieldDeclaration:
                                    //Parsing of Fields
                                        FieldDeclarationSyntax field = classMember as FieldDeclarationSyntax;
                                        foreach (VariableDeclaratorSyntax item in field.Declaration.Variables)
                                            Console.WriteLine("Field : "+item.Identifier+" , " +field.Declaration.Type);
                                    break;
                                    case SyntaxKind.PropertyDeclaration:
                                    //Parsing of Properties
                                        PropertyDeclarationSyntax property = classMember as PropertyDeclarationSyntax;
                                        Console.WriteLine("Property : "+property.Identifier+" , " +property.Type);
                                    break;
                                }
                            }
                            Console.WriteLine();
                        }
                        else if(classes.Kind()== SyntaxKind.InterfaceDeclaration)
                        {
                            //Parsing Interface
                            InterfaceDeclarationSyntax interfaceDeclarationSyntax=(InterfaceDeclarationSyntax)classes;
                            Console.WriteLine("Interface :"+interfaceDeclarationSyntax.Identifier);
                            foreach (var interfaceMember in interfaceDeclarationSyntax.Members)
                            {
                                switch(interfaceMember.Kind())
                                {
                                    //Parsing of Methods
                                    case SyntaxKind.MethodDeclaration :
                                        MethodDeclarationSyntax method= interfaceMember as MethodDeclarationSyntax;
                                        Console.WriteLine("Method : "+method.Identifier+" , "+method.ReturnType);
                                        foreach (ParameterSyntax item in method.ParameterList.Parameters)
                                            Console.WriteLine("  Parameter : "+item.Identifier+" , "+item.Type);
                                    break;
                                    case SyntaxKind.PropertyDeclaration:
                                    //Parsing of Properties
                                        PropertyDeclarationSyntax field = interfaceMember as PropertyDeclarationSyntax;
                                        Console.WriteLine("Field : "+field.Identifier+" , " +field.Type);
                                    break;
                            }
                            }
                        }
                        else if(classes.Kind()== SyntaxKind.StructDeclaration)
                        {
                            //Parsing Structs
                            StructDeclarationSyntax structDeclarationSyntax=(StructDeclarationSyntax)classes;
                            Console.WriteLine("\nStruct :"+structDeclarationSyntax.Identifier);
                            foreach (var structMember in structDeclarationSyntax.Members)
                            {
                                switch(structMember.Kind())
                                {
                                    case SyntaxKind.MethodDeclaration :
                                    //Parsing of Methods
                                        MethodDeclarationSyntax method= structMember as MethodDeclarationSyntax;
                                        Console.WriteLine("Method : "+method.Identifier+" , "+method.ReturnType);
                                        foreach (ParameterSyntax item in method.ParameterList.Parameters)
                                            Console.WriteLine("  Parameter : "+item.Identifier+" , "+item.Type);
                                        Console.WriteLine("  Body Length : "+method.Body.ToFullString().Length);
                                    break;
                                    //Parsing of Fields
                                    case SyntaxKind.FieldDeclaration:
                                        FieldDeclarationSyntax fieldDeclarationSyntax= structMember as FieldDeclarationSyntax;
                                        foreach (VariableDeclaratorSyntax item in fieldDeclarationSyntax.Declaration.Variables)
                                            Console.WriteLine("Field : "+item.Identifier+" , "+fieldDeclarationSyntax.Declaration.Type);
                                    break;
                                    //Parsing of Properties
                                    case SyntaxKind.PropertyDeclaration:
                                        PropertyDeclarationSyntax property = structMember as PropertyDeclarationSyntax;
                                        Console.WriteLine("Property : "+property.Identifier+" , " +property.Type);
                                    break;
                                    //Parsing of EventFields
                                    case SyntaxKind.EventFieldDeclaration:
                                        EventFieldDeclarationSyntax eventField = structMember as EventFieldDeclarationSyntax;
                                        foreach (VariableDeclaratorSyntax item in eventField.Declaration.Variables)
                                            Console.WriteLine("EventField : "+item.Identifier+" , "+eventField.Declaration.Type);
                                    break;
                               }
                            }
                        }
                    }
                    //End pf Each File
                    Console.WriteLine("---------------------------------");
                }
            }
            catch (System.Exception ex)
            {
                Console.WriteLine("Error Occurred"+ex.Message);
            }
        }
    }
}