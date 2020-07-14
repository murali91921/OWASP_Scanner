using System;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;
using Microsoft.CodeAnalysis.FindSymbols;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using System.Collections.Generic;

namespace ASTTask
{
    internal class WeakPasswordValidator
    {
        /*
        FIND THE WEAK PASSWORDS
        */
        SemanticModel model = null;
        AdhocWorkspace workspace = null;
        SyntaxNode rootNode = null;
        static int MINIMUM_PASSWORD_LENGTH = 8;
        public List<SyntaxNode> FindWeakPasswords(string filePath, SyntaxNode rootNode)
        {
            List<SyntaxNode> lstVulnerableStatements = new List<SyntaxNode>();
            workspace = new AdhocWorkspace();
            var solutionInfo = SolutionInfo.Create(SolutionId.CreateNewId(), VersionStamp.Create());
            var project = workspace.AddProject("WeakPasswordValidator", "C#");
            project = project.AddMetadataReference(MetadataReference.CreateFromFile(filePath));
            project = project.AddMetadataReferences(Utils.LoadMetadata(rootNode));
            workspace.TryApplyChanges(project.Solution);
            var document = workspace.AddDocument(project.Id, "WeakPasswordValidator",SourceText.From(rootNode.ToString()));
            model = document.GetSemanticModelAsync().Result;
            var compilation= project.GetCompilationAsync().Result;
            rootNode = document.GetSyntaxRootAsync().Result;
            this.rootNode = rootNode;
            //Filter all property declarations
            {
                var properties = rootNode.DescendantNodes().OfType<PropertyDeclarationSyntax>();
                foreach (var item in properties)
                {
                    bool IsPassword = false;
                    bool IsWeak = true;
                    foreach(var attributeList in item.AttributeLists)
                    {
                        foreach (var attribute in attributeList.Attributes)
                        {
                            ITypeSymbol type = model.GetTypeInfo(attribute).Type;
                            //Console.WriteLine(type);
                            if(type!=null && type.ToString()=="System.ComponentModel.DataAnnotations.DataType"
                                    && attribute.ArgumentList!=null && attribute.ArgumentList.Arguments.First().ToString()=="DataType.Password")
                                    IsPassword = true;
                            if(type !=null && type.ToString()=="System.ComponentModel.DataAnnotations.StringLengthAttribute")
                            {
                                // Console.WriteLine("Min Length");
                                if(attribute.ArgumentList !=null && attribute.ArgumentList.Arguments.Any(obj=>obj.ToString().Contains("MinimumLength")))
                                {
                                    var minimumLengthAttrib = attribute.ArgumentList.Arguments.First(obj => obj.ToString().Contains("MinimumLength"));
                                    if((minimumLengthAttrib.NameColon !=null && minimumLengthAttrib.NameColon.Name.ToString()=="MinimumLength")
                                    || (minimumLengthAttrib.NameEquals !=null && minimumLengthAttrib.NameEquals.Name.ToString()=="MinimumLength"))
                                    {
                                        if(minimumLengthAttrib.Expression is LiteralExpressionSyntax)
                                            IsWeak = int.Parse(minimumLengthAttrib.Expression.ToString()) < MINIMUM_PASSWORD_LENGTH;
                                    }
                                }
                            }
                        }
                    }
                    if(IsPassword && IsWeak)
                    lstVulnerableStatements.Add(item);
                }
            }
            if(lstVulnerableStatements.Count==0)
            {
                // Finding the statements of Configure method calling with Lambda Expression
                var coreLengthStatements = rootNode.DescendantNodes().OfType<InvocationExpressionSyntax>().Where(obj=>
                                                    obj.ToString().Contains("Configure")).ToList();
                if(coreLengthStatements.Count > 0)
                {
                    SyntaxNode tempIdentity = null;
                    //bool PasswordoptionsExists = false;
                    //bool IsPassword = false;
                    bool IsWeak = true;
                    foreach (var item in coreLengthStatements)
                    {
                        //IsPassword = false;
                        IsWeak = true;
                        //tempIdentity = null;
                        var typeInfo = model.GetTypeInfo(item);
                        if(typeInfo.Type !=null && typeInfo.Type.ToString() == "Microsoft.Extensions.DependencyInjection.IServiceCollection")
                        {
                            //Console.WriteLine("Type");
                            // var passwordOptions = compilation.GetTypeByMetadataName("Microsoft.AspNetCore.Identity.IdentityOptions");
                            // var references = SymbolFinder.FindReferencesAsync(passwordOptions,project.Solution).Result;
                            var typeArguments = item.DescendantNodes().OfType<TypeArgumentListSyntax>();
                            string typeOfOptions = string.Empty;
                            if(typeArguments.Count()>0)
                            {
                                var typeOfOptionsTypeInfo = model.GetTypeInfo(typeArguments.First().Arguments.First());
                                if(typeOfOptionsTypeInfo.Type != null)
                                    typeOfOptions = model.GetTypeInfo(typeArguments.First().Arguments.First()).Type.ToString();
                            }
                            if(typeOfOptions == "Microsoft.AspNetCore.Identity.IdentityOptions")
                            {
                                // IsPassword = true;
                                var assignments = item.DescendantNodes().OfType<AssignmentExpressionSyntax>().Where(obj=>
                                                                obj.Right is LiteralExpressionSyntax && obj.Left.ToString().Contains("Password.RequiredLength"));
                                if(assignments.Count()>0)
                                {
                                    int requestedLength = int.Parse(assignments.First().Right.ToString());
                                    if(requestedLength >= MINIMUM_PASSWORD_LENGTH)
                                        IsWeak = false;
                                }
                                else
                                    IsWeak = true;
                                if(IsWeak && tempIdentity == null)
                                    tempIdentity = item;
                                //Console.WriteLine("Identity");
                            }
                            else if(typeOfOptions == "Microsoft.AspNetCore.Identity.PasswordOptions")
                            {
                                //PasswordoptionsExists = true;
                                //IsPassword = true;
                                var assignments = item.DescendantNodes().OfType<AssignmentExpressionSyntax>().Where(obj=>
                                                                obj.Right is LiteralExpressionSyntax && obj.Left.ToString().Contains("RequiredLength"));
                                if(assignments.Count()>0)
                                {
                                    int requestedLength = int.Parse(assignments.First().Right.ToString());
                                    if(requestedLength >= MINIMUM_PASSWORD_LENGTH)
                                        IsWeak = false;
                                }
                                else
                                    IsWeak = true;
                                // tempIdentity = null;
                                if(IsWeak)
                                    tempIdentity = item;
                                else
                                    tempIdentity = null;
                                break;
                                //Console.WriteLine("Password");
                            }
                            else
                                continue;
                            // if(IsPassword && IsWeak)
                            // {
                            //     lstVulnerableStatements.Add(tempIdentity==null ? item : tempIdentity);
                            //     break;
                            // }
                        }
                        // Console.WriteLine(item);
                    }
                    if(tempIdentity != null)
                    {
                        lstVulnerableStatements.Add(tempIdentity);
                    }
                }
            }
            if(lstVulnerableStatements.Count == 0)
            {
                var declarationSyntaxes = rootNode.DescendantNodes().OfType<VariableDeclaratorSyntax>();
                // var passwordValidator = compilation.GetTypeByMetadataName("Microsoft.AspNet.Identity.PasswordValidator");
                // var referencedSymbols_1 = SymbolFinder.FindReferencesAsync(passwordValidator,project.Solution).Result;

                foreach (var declarationSyntax in declarationSyntaxes)
                {
                    bool IsWeak = true;
                    IEnumerable<ReferencedSymbol> referencedSymbols = null;
                    ISymbol symbol = model.GetDeclaredSymbol(declarationSyntax);
                    if(symbol is IFieldSymbol && (symbol as IFieldSymbol).Type.ToString() == "Microsoft.AspNet.Identity.PasswordValidator")
                    {
                        IFieldSymbol iFieldSymbol = symbol as IFieldSymbol;
                        referencedSymbols = SymbolFinder.FindReferencesAsync(iFieldSymbol,workspace.CurrentSolution).Result;
                    }
                    else if(symbol is ILocalSymbol && (symbol as ILocalSymbol).Type.ToString() == "Microsoft.AspNet.Identity.PasswordValidator")
                    {
                        ILocalSymbol iLocalSymbol = symbol as ILocalSymbol;
                        // Console.WriteLine(iLocalSymbol.Type);
                        referencedSymbols = SymbolFinder.FindReferencesAsync(iLocalSymbol, workspace.CurrentSolution).Result;
                        //Console.WriteLine(referencedSymbols.Count());
                    }
                    else
                        continue;
                    var objectCreation = declarationSyntax.DescendantNodes().OfType<ObjectCreationExpressionSyntax>().FirstOrDefault();
                    if(objectCreation != null && objectCreation.Initializer != null)
                    {
                        foreach (var expression in  objectCreation.Initializer.Expressions)
                        {
                            var assignment = expression as AssignmentExpressionSyntax; 
                            if(assignment.Left.ToString()=="RequiredLength" && assignment.Right is LiteralExpressionSyntax)
                            {
                                if(int.Parse(assignment.Right.ToString()) > MINIMUM_PASSWORD_LENGTH)
                                    IsWeak = false;
                            }
                        }
                        // declarationSyntax.Initializer is ObjectCreationExpressionSyntax
                    }
                    if(referencedSymbols != null && referencedSymbols.Count()>0)
                    {
                        foreach (var refSymbol in referencedSymbols)
                        {
                            foreach (var refLocation in refSymbol.Locations)
                            {
                                var refNode = rootNode.FindNode(refLocation.Location.SourceSpan);
                                var assignment = refNode.Ancestors().OfType<AssignmentExpressionSyntax>().First();
                                {
                                    if ((assignment.Left as MemberAccessExpressionSyntax).Name.ToString() == "RequiredLength" && assignment.Right is LiteralExpressionSyntax)
                                    {
                                        if(int.Parse(assignment.Right.ToString()) > MINIMUM_PASSWORD_LENGTH)
                                            IsWeak = false;
                                        if(IsWeak)
                                        {
                                            lstVulnerableStatements.Add(assignment);
                                            IsWeak = false;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if(IsWeak)
                    {
                        lstVulnerableStatements.Add(declarationSyntax);
                    }
                }
            }
            return lstVulnerableStatements;
        }
    }
}