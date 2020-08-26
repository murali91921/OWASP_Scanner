using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Web.UI.HtmlControls;
using System.IO;
using System.Text;
using System;

// Following usings are used for loading the assemblies only.
using mscorlib;

namespace VulnerableApp
{
    public class XssExample2
    {
        public static HttpRequest Request = null;
        /*public static void Run1(string input)
        {
            input = Request.QueryString[0];
            var temp = new Control(); temp.ID = input;
        }
        public static void Run2(string input)
        {
            input = Request.QueryString[0];
            var temp = new Label(); temp.Text = input;
        }
        public static void Run3(string input)
        {
            input = Request.QueryString[0];
            System.Web.UI.WebControls.HyperLink temp = System.Web.UI.WebControls.HyperLink(); temp.NavigateUrl = input;
            temp.Text = input;
        }
        public static void Run4(string input)
        {
            input = Request.QueryString[0];
            var temp = new LinkButton(); temp.Text = input;
        }
        public static void Run5(string input)
        {
            input = Request.QueryString[0];
            var temp = new Literal(); temp.Text = input;
        }
        public static void Run6(string input)
        {
            input = Request.QueryString[0];
            var temp = new CheckBox(); temp.Text = input;
        }
        public static void Run7(string input)
        {
            input = Request.QueryString[0];
            var temp = new RadioButton(); temp.Text = input;
            temp.GroupName = input;
        }
        public static void Run8(string input)
        {
            input = Request.QueryString[0];
            var temp = new Calendar(); temp.Caption = input;
        }
        public static void Run10(string input)
        {
            input = Request.QueryString[0];
            var temp = new Table(); temp.Caption = input;
        }
        public static void Run11(string input)
        {
            input = Request.QueryString[0];
            var temp = new Panel(); temp.GroupingText = input;
        }
        public static void Run12(string input)
        {
            input = Request.QueryString[0];
            var temp = new HtmlElement(); temp.InnerHtml = input;
        }
        public static void Run13(string input)
        {
            input = Request.QueryString[0];
            // input = new Page().Server.HtmlEncode(Request.QueryString[0]);
            var inputLocal = input;
            var temp = new Page();
            temp.ClientScript.RegisterStartupScript(input, input, input);
            temp.ClientScript.RegisterClientScriptBlock(inputLocal, inputLocal, inputLocal);
            temp.RegisterStartupScript(input, input);
            temp.RegisterClientScriptBlock(input, input);
            int inputInt = 100;
            temp.Response.Write(inputInt);
            temp.Response.Write(input);
            temp.Response.Write(input.ToCharArray(), 0, 1);
        }*/
        public static void Run14(string input)
        {
            input = Request.QueryString[0];
            // var temp1 = new HyperLink();
			// temp1.NavigateUrl = Encoder.UrlPathEncode(input);
			// var temp2 = new Label();
			// temp2.Text = new Page().Server.HtmlEncode(input);
            var temp3 = new Label();
            // var sw = new System.IO.StringWriter();
            var page = new Page();
            // page.Server.HtmlEncode(input, sw);
            page.Server.HtmlEncode(input);
            //temp3.Text = sw.ToString();
            temp3.Text = input;
        }
    }
}