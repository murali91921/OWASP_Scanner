using System.IO;
using System.Linq;
using System.Net;
using System.Web.Mvc;

namespace MVC
{
    public class FooBarController : Controller
    {
        [HttpPost] // Noncompliant
        [ValidateInput(false)]
        public string Purchase(string input)
        {
            return input;
        }

        [HttpPost] // Noncompliant
        public string PurchaseSomethingElse(string input)
        {
            return input;
        }
    }
    public class InSecureFooBarController : Controller
    {
        [HttpPost]
        [ValidateInput(true)] // Compliant
        public string Purchase(string input)
        {
            return input;
        }
    }
}