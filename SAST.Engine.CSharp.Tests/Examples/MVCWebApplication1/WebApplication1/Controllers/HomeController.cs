//using System.Net.Http;
using System.Web.Mvc;
using DAL;
using Microsoft.Security.Application;

namespace WebApplication1.Controllers
{
    //[ValidateAntiForgeryToken]
    //public class IndexController : Controller
    //{
    //    [HttpPost]
    //    public ActionResult Index()
    //    {
    //        return View();
    //    }
    //}
    //[ValidateAntiForgeryToken]
    public class HomeController : Controller
    {
        //[HttpPost]
        //public ActionResult Index()
        //{
        //    return View();
        //}

        //[HttpPost]
        //[ValidateAntiForgeryToken]
        //public ActionResult Action1(string externalUrl)
        //{
        //    ViewBag.Message = "Your application description page.";
        //    Redirect(externalUrl);
        //    return View();
        //}

        //[HttpPatch]
        //[ValidateAntiForgeryToken]
        //[AllowAnonymous]
        //public ActionResult Action2(string externalUrl)
        //{
        //    ViewBag.Message = "Your application description page.";
        //    Redirect(externalUrl);
        //    return View();
        //}

        //[AllowAnonymous]
        //[HttpPost]
        //public ActionResult Action3(string returnUrl)
        //{
        //    ViewBag.Message = "Your contact page.";
        //    Response.Redirect(returnUrl);
        //    return View();
        //}

        //[HttpGet, ValidateAntiForgeryToken]
        //public ViewResult Action4(string returnUrl)
        //{
        //    ViewBag.Message = "Your contact page.";
        //    Response.Redirect(returnUrl);
        //    return View();
        //}
        //[HttpPost]
        //public string Action7(string employeeName)
        //{
        //    string emp;
        //    emp = employeeName.Substring(0, 10);
        //    //emp = EmployeeDAL.GetEmployeeDesignation(employeeName);
        //    //emp = Encoder.HtmlEncode(emp);
        //    return emp;
        //}

        [HttpPost]
        public string Action8(string employeeName)
        {
            string emp;
            //emp = employeeName.Substring(0, 10);
            emp = EmployeeDAL.GetEmployeeDesignation(employeeName);
            //emp = Encoder.HtmlEncode(emp);
            return emp;
        }

        //public string Action8(string employeeName)
        //{
        //    string emp;
        //    emp = employeeName.Substring(0, 10);
        //    emp = EmployeeDAL.GetEmployeeDesignation(employeeName);
        //    return emp;
        //}
    }
}