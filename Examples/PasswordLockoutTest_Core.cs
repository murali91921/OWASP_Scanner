using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using CoreMVCWebApplication4.Areas.Identity.Data;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CoreMVCWebApplication4.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LoginModel : PageModel
    {
        private readonly UserManager<CoreMVCWebApplication4User> _userManager;
        private readonly SignInManager<CoreMVCWebApplication4User> _signInManager;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(SignInManager<CoreMVCWebApplication4User> signInManager,
            ILogger<LoginModel> logger,
            UserManager<CoreMVCWebApplication4User> userManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl = returnUrl ?? Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: false);
                result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, lockoutOnFailure: false, isPersistent: true);
                result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, true, lockoutOnFailure: false);
                result = await _signInManager.PasswordSignInAsync(lockoutOnFailure: false, isPersistent: true, userName: Input.Email, password: Input.Password);

                CoreMVCWebApplication4User user = new CoreMVCWebApplication4User();
                user.Email = Input.Email;
                result = await _signInManager.CheckPasswordSignInAsync(user, Input.Password, lockoutOnFailure: false);
                result = await _signInManager.CheckPasswordSignInAsync(lockoutOnFailure: false, user: user, password: Input.Password);
                result = await _signInManager.CheckPasswordSignInAsync(user: user, lockoutOnFailure: false, password: Input.Password);
                result = await _signInManager.CheckPasswordSignInAsync(user, Input.Password, false);

                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    return LocalRedirect(returnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    return RedirectToPage("./Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }
    }
}
namespace CoreMVCWebApplication4.Areas.Identity.Data
{
    // Add profile data for application users by adding properties to the CoreMVCWebApplication4User class
    public class CoreMVCWebApplication4User : IdentityUser
    {
    }
}

namespace CoreMVCWebApplication4.Data
{
    public class CoreMVCWebApplication4Context : IdentityDbContext<CoreMVCWebApplication4User>
    {
        public CoreMVCWebApplication4Context(DbContextOptions<CoreMVCWebApplication4Context> options)
            : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            // Customize the ASP.NET Identity model and override the defaults if needed.
            // For example, you can rename the ASP.NET Identity table names and more.
            // Add your customizations after calling base.OnModelCreating(builder);
        }
    }
}