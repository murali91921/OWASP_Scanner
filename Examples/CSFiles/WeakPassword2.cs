using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace AspNetCoreExample
{
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<IdentityOptions>(options =>
            {
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.SignIn.RequireConfirmedEmail = true;
                options.User.RequireUniqueEmail = true;

                // options.Password.RequireDigit = true;
                // options.Password.RequireLowercase = true;
                // options.Password.RequireNonAlphanumeric = true;
                // options.Password.RequireUppercase = true;
                // options.Password.RequiredLength = 10;
                // options.Password.RequiredUniqueChars = 1;
            });
            services.Configure<PasswordOptions>(options =>
            {
                options.RequireDigit = true;
                options.RequireLowercase = true;
                options.RequireNonAlphanumeric = true;
                options.RequireUppercase = true;
                //options.RequiredLength = 3;
                options.RequiredUniqueChars = 1;
            });
            // services.Configure<IdentityOptions>(options =>
            // {
                // options.Lockout.MaxFailedAccessAttempts = 5;
                // options.SignIn.RequireConfirmedEmail = true;
                // options.User.RequireUniqueEmail = true;
            // });
        }
    }
}
//One Scenario -> What if Developer sets the RequiredLength value from a method(means dynamic).