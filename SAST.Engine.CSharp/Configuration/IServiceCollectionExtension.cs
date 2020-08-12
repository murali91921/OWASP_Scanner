using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.CodeAnalysis;
using SAST.Engine.CSharp.Contract;
using SAST.Engine.CSharp.Scanners;

namespace SAST.Engine.CSharp.Configuration
{
    public static class IServiceCollectionExtension
    {
        public static void AddCSharpEngine(this IServiceCollection services)
        {
            services.AddSingleton<IScanSyntaxNode, CookieFlagScanner>();
            services.AddSingleton<IScanSyntaxNode, CredsFinder>();
            services.AddSingleton<IScanSyntaxNode, CsrfScanner>();
            services.AddSingleton<IScanSyntaxNode, EmptyCatch>();
            services.AddSingleton<IScanSyntaxNode, EmptyTryScanner>();
            services.AddSingleton<IScanSyntaxNode, InsecureRandomScanner>();
            services.AddSingleton<IScanSyntaxNode, LDAPScanner>();
            services.AddSingleton<IScanSyntaxNode, OpenRedirect>();
            services.AddSingleton<IScanSyntaxNode, SqlInjectionScanner>();
            services.AddSingleton<IScanSyntaxNode, WeakHashingValidator>();
            services.AddSingleton<IScanSyntaxNode, WeakPasswordValidator>();
            services.AddSingleton<IScanSyntaxNode, XPathScanner>();
            //services.AddSingleton<IScanFile, CookieFlagScanner>();
        }
    }
}
