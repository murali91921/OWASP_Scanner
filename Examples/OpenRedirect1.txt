using System;
using System.Web;

namespace OpenRedirect1
{
    public partial class MyForm : System.Web.UI.Page
    {
        // Not Vulnerable method
        protected void Page_Load(object sender, EventArgs e)
        {
            Response.Redirect("https://example.org/1.html"); 			// Not Vulnerable
            string input = Request.Form["Website"];
            if (string.IsNullOrEmpty(input))
            {
                Response.Redirect(input + "?id=2");      				// Not Vulnerable
                Response.Redirect("https://example.org/3.html"); 		// Not Vulnerable
            }
            Response.Redirect("https://example.org/4.html" + CheckInput(input)); // Not Vulnerable
            Response.Redirect(input + "?id=5");      					// Vulnerable
            Response.Redirect("http://example.org/5.html?" + input); 	// Not Vulnerable
        }

        public string CheckInput(string str)
        {
            return str;
        }

        //Vulnerable method
        protected void Button_Click(object sender, EventArgs e, HttpRequest Request, HttpResponse response)
        {
            string inputVul = Request.Form["url"];
            if(inputVul.StartsWith("https"))
                inputVul = inputVul + "?Secure=true";
            Response.Redirect(inputVul); // Not Vulnerable
        }

        //Not Vulnerable method
        protected void Button1_Click(object sender, EventArgs e)
        {
            string input = Request.Form["url"];
            Response.Redirect(input.StartsWith("https//:www.localsite.com/") ? input : "/Index.html"); // Not Vulnerable
        }
    }
}