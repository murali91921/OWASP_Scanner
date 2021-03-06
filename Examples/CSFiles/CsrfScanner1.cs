using System.Net.Http;
using System.Web.Mvc;

namespace WebApplication1.Controllers
{
    [ValidateAntiForgeryToken]
    public class IndexController : Controller
    {
        [HttpPost]
        public ActionResult Index()
        {
            return View();
        }
    }
    //[ValidateAntiForgeryToken]
    public class HomeController : Controller
    {
        [HttpPost]
        public ActionResult Index()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Action1(string externalUrl)
        {
            ViewBag.Message = "Your application description page.";
            Redirect(externalUrl);
            return View();
        }

        [HttpPatch]
        [ValidateAntiForgeryToken]
        [AllowAnonymous]
        public ActionResult Action2(string externalUrl)
        {
            ViewBag.Message = "Your application description page.";
            Redirect(externalUrl);
            return View();
        }

        [AllowAnonymous]
        [HttpPost]
        public ActionResult Action3(string returnUrl)
        {
            ViewBag.Message = returnUrl;
            Response.Redirect(returnUrl);
            return View();
        }

        [HttpGet, ValidateAntiForgeryToken]
        public ViewResult Action4(string returnUrl)
        {
            ViewBag.Message = "Your contact page.";
            Response.Redirect(returnUrl);
            return View();
        }
    }
}