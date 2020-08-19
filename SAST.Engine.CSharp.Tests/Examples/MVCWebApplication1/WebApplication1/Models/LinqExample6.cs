using System.Web.Mvc;
using System.Text.Encodings.Web;

namespace VulnerableApp
{
    public class TestController : Controller
    {
        [HttpGet]
        public string Get1(int sensibleData)
        {
            return "value " + sensibleData;
        }

        [HttpGet]
        public string Get2(string sensibleData)
        {
            string temporary_variable = HtmlEncoder.Default.Encode(sensibleData);
            return "value " + temporary_variable;
        }

        [HttpGet]
        public string Get3(string sensibleData)
        {
            return "value " + HtmlEncoder.Default.Encode(sensibleData);
        }

        [HttpGet]
        public string Get4(string sensibleData)
        {
            return HtmlEncoder.Default.Encode("value " + sensibleData);
        }

        [HttpGet]
        public string Get5(string sensibleData)
        {
            sensibleData = HtmlEncoder.Default.Encode("value " + sensibleData);
            return "value " + HtmlEncoder.Default.Encode(sensibleData);
        }

        [HttpGet]
        private string Get6(int sensibleData)
        {
            return "value " + sensibleData;
        }

        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }
    }
}