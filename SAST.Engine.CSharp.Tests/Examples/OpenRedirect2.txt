using System.Web;
using System.Web.Mvc;

namespace MVCWebApplication1.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About(string externalUrl)
        {
            ViewBag.Message = "Your application description page.";
            Redirect(externalUrl);
            return View();
        }

        public ActionResult Contact(string returnUrl)
        {
            ViewBag.Message = "Your contact page.";
            if(string.IsNullOrEmpty(returnUrl))
                Response.Redirect("http://localsite.com");
            else
                Response.Redirect(returnUrl);
            return View();
        }
    }
}