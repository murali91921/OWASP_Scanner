using Microsoft.AspNetCore.Mvc;
//Un used namespaces
using Microsoft.AspNetCore.Mvc.Core;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using System.Net.Http;

namespace CoreWebApplication2.Controllers
{
    public class HomeController : Controller
    {
        [HttpPost]
        [AutoValidateAntiforgeryToken]
        public JsonResult Method1()
        {
            JsonResult json = new JsonResult(string.Empty);
            return json;
        }

        [HttpPost]
        public HttpResponseMessage Method2()
        {
            return new HttpResponseMessage(System.Net.HttpStatusCode.Accepted);
        }

        [ValidateAntiForgeryToken]
        [HttpPatch]
        public IActionResult Privacy()
        {
            return View();
        }

        [HttpDelete]
        [AllowAnonymous]
        public ViewResult Error()
        {
            return View("Error");
        }
    }

    [ValidateAntiForgeryToken]
    public class AdminController : Controller
    {
        [HttpPost]
        public JsonResult Method1()
        {
            JsonResult json = new JsonResult(string.Empty);
            return json;
        }
    }
}