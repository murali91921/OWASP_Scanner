using Microsoft.AspNetCore.Mvc;
//While opening this source code in visual studio, remove the following namespaces
using Microsoft.AspNetCore.Http.Abstractions;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Mvc.Core;

namespace CoreMVCWebApplication1.Controllers
{
    public class HomeController : Controller
    {
        public HomeController()
        {

        }

        public IActionResult Index(string externalUrl)
        {
            Response.Redirect(externalUrl);
            return View();
        }

        public IActionResult Privacy(string returnUrl)
        {
            Redirect(returnUrl);
            return View();
        }
    }
}
