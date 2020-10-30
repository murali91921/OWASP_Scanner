using System.Net.Http;
using System.Web.Mvc;

namespace WebApplication1.Controllers
{
    [Authorize]
    public class IndexController : Controller
    {
        [HttpPost]
        public ActionResult Index()
        {
            return View();
        }
		
		[AllowAnonymous]
        [HttpPost]
        public ActionResult Index2()
        {
            return View();
        }
    }
    
	[AllowAnonymous]
    public class Index2Controller : Controller
    {
        [HttpPost]
        public ActionResult Index()
        {
            return View();
        }
        
		[HttpPost]
		[Authorize]
        public ActionResult Index2()
        {
            return View();
        }
    }

    public class HomeController : Controller
    {
        [Authorize]
        public ActionResult Action1()
        {
            return View();
        }

		[Authorize]
        public string Action2()
        {
            return "Content";
        }

        [AllowAnonymous]
        public ActionResult Action3(string externalUrl)
        {
            ViewBag.Message = "Your application description page.";
            return View();
        }
		
        [AllowAnonymous]
        public string Action4(string externalUrl)
        {
            ViewBag.Message = "Your application description page.";
            return "Content Message";
        }
		
        [HttpPost]
		public string Action5(string externalUrl)
        {
            ViewBag.Message = "Your application description page.";
            return "Content Message";
        }
		
        [HttpPost]
		public ActionResult Action6(string externalUrl)
        {
            ViewBag.Message = "Your application description page.";
            return View();
        }
	}
}