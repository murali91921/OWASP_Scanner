
// using System;
// using System.Web;

// namespace OpenRedirect1
// {
//     public partial class MyForm
//     {
//         // Not Vulnerable method
//         protected void Page_Load(object sender, EventArgs e, string request, HttpResponse response)
//         {
//             string input = request;
//             if (string.IsNullOrWhiteSpace(input))
//             {
//                 Console.WriteLine("Input is Null");
//                 //response.Redirect("https://example1.org/login.html"); // Not Vulnerable
//             }
//             //response.Redirect("https://example2.org/login.html" + CheckInput(input)); // Not Vulnerable
//             //response.Redirect(input + "?id=3");      // Vulnerable
//             response.Redirect(CheckInput(input) + "?id=4"); // Not Vulnerable
//         }

//         public string CheckInput(string str)
//         {
//             return str;
//         }

//         //Vulnerable method
//         protected void Button_Click(object sender, EventArgs e, HttpRequest Request, HttpResponse response)
//         {
//             string inputVul = Request.Form["url"];
//             this.Response.Redirect(inputVul);
//         }

//         //Not Vulnerable method
//         protected void Button1_Click(object sender, EventArgs e, HttpRequest Request, HttpResponse response)
//         {
//             string input = Request.Form["url"];
//             this.Response.Redirect(input.StartsWith("https//:www.localsite.com/") ? input : "/Index.html");
//         }
//     }
// }