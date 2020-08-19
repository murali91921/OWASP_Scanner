using System.DirectoryServices;
using System.Web.Mvc;

namespace WebApplicationDotNetCore.Controllers
{
    public class RSPEC2078LDAPInjectionNoncompliantController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
        public ActionResult Authenticate(string user, string pass)
        {
            directorySearch.Filter = "(&(uid=" + user + ")(userPassword=" + pass + "))"; // Noncompliant

            // If the special value "*)(uid=*))(|(uid=*" is passed as user, authentication is bypassed
            // Indeed, if it is passed as a user, the filter becomes:
            // (&(uid=*)(uid=*))(|(uid=*)(userPassword=...))
            // as uid=* match all users, it is equivalent to:
            // (|(uid=*)(userPassword=...))
            // again, as uid=* match all users, the filter becomes useless

            return Content(directorySearch.FindOne() != null ? "success" : "fail");
        }
    }
}