using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Cors.Infrastructure;
using System;

namespace CoreMVCWebApplication4
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            CorsPolicy corsPolicy = new CorsPolicy();

            CorsPolicyBuilder corsPolicyBuilder = new CorsPolicyBuilder();
            corsPolicyBuilder.AllowAnyOrigin();
            corsPolicy = corsPolicyBuilder.Build();

            services.AddCors(options =>
            {
                options.AddPolicy(name: "Policy1", corsPolicy);
                options.AddPolicy(name: "Policy2", builder => builder.AllowAnyOrigin());
            });
        }
    }
}
