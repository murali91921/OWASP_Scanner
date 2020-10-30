//using System;
using Microsoft.AspNet.Identity;

namespace MVCIdentityExample
{
    public class ApplicationUserManager
    {
        PasswordValidator passwordValidatorGlobal = new PasswordValidator
        {
            RequiredLength = 6,
            RequireNonLetterOrDigit = true,
            RequireDigit = true,
            RequireLowercase = true,
            RequireUppercase = true,
        };

        public void Create()
        {
            // Configure validation logic for passwords
            PasswordValidator passwordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            Microsoft.AspNet.Identity.PasswordValidator passwordValidator1 = new Microsoft.AspNet.Identity.PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true
            };
            passwordValidator1.RequireDigit = true;
            passwordValidator1.RequireLowercase = true;
            passwordValidator1.RequireUppercase = true;
            passwordValidator1.RequiredLength = 7;

            PasswordValidator passwordValidator2 = new PasswordValidator();
            passwordValidator2.RequiredLength = 6;
            passwordValidator2.RequireNonLetterOrDigit = true;
            passwordValidator2.RequireDigit = true;
            passwordValidator2.RequireLowercase = true;
            passwordValidator2.RequireUppercase = true;
        }
    }
}
