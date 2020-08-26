using System.Web.Mvc;
using System.Text.Encodings.Web;

namespace VulnerableApp
{
    public class StoredXSSController : Controller
    {
        // [HttpGet]
        // public string Get1(int sensibleData)
        // {
        //     return "value " + sensibleData;
        // }

        [HttpGet]
        public string Get2(string sensibleData)
        {
            if(!(sensibleData==""))
            {
                sensibleData = string.Empty;
            }
            else
            {
                //sensibleData= "Sensible String";
            }
            string temporary_variable = HtmlEncoder.Default.Encode(sensibleData);
            temporary_variable = sensibleData;
            return "value " + sensibleData;
        }
        // [HttpGet]
        // public string Get3(string sensibleData)
        // {
        //     return "value " + HtmlEncoder.Default.Encode(sensibleData);
        // }

        // [HttpGet]
        // public string Get4(string sensibleData)
        // {
        //     return HtmlEncoder.Default.Encode("value " + sensibleData);
        // }

        // [HttpGet]
        // public string Get5(string sensibleData)
        // {
        //     sensibleData = HtmlEncoder.Default.Encode("value " + sensibleData);
        //     return "value " + HtmlEncoder.Default.Encode(sensibleData);
        // }

        // [HttpGet]
        // private string Get6(int sensibleData)
        // {
        //     return "value " + sensibleData;
        // }

        // public ActionResult Login(string returnUrl)
        // {
        //     ViewBag.ReturnUrl = returnUrl;
        //     return View();
        // }
    }
}