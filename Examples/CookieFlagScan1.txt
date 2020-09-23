using System;
using System.IO;
using System.Web;

namespace CookeFlagScan1
{
   class CFSClassExample1
    {
        //Snippet 1
        public void Snippet1(HttpResponse Response, DateTime date)
        {
            HttpCookie cookieResponse = (Response.Cookies[0]);
            cookieResponse.Secure = false;
            cookieResponse.HttpOnly = true;

            foreach (string s in Response.Cookies.AllKeys)
            {
                Response.Cookies[s].Value = DateTime.Now > date ? DateTime.Now.ToString() : DateTime.Now.AddHours(1).ToString();
                bool secu = Response.Cookies[s].Secure;
                Response.Cookies[s].Secure = false;
                Response.Cookies[s].HttpOnly = true;
                Console.WriteLine(secu);
            }
            Response.Cookies.Add(
                ((new System.Web.HttpCookie("key1", "value1")
                {
                    Expires = DateTime.Now,
                    Secure = (false),
                })));
        }

        //Snippet 2
        public void Snippet2(HttpResponse Response)
        {
            Response.Cookies.Add(
                new HttpCookie("key2", "value2")
                {
                    Secure = true,
                });
        }

        //Snippet 3
        public void Snippet3()
        {
            HttpCookie objHttpCookie3 = new HttpCookie("key3", "value3")
            {
                Path = "/",
                HttpOnly = true,
            };
            objHttpCookie3.Secure = false;
        }
        //Snippet 4
        public void Snippet4()
        {
            var objHttpCookie4 = new HttpCookie("key4", "value4")
            {
                Path = "/",
                HttpOnly = true,
            };
            objHttpCookie4.Secure = true;
        }
        //Snippet 5
        public void Snippet5()
        {
            var objHttpCookie5 = new HttpCookie("key5", "value5");
            objHttpCookie5.Secure = true;
            objHttpCookie5.HttpOnly = false;
        }

        //Snippet 6
        public void Snippet6()
        {
            HttpCookie objHttpCookie6 = new HttpCookie("key6", "value6");
            objHttpCookie6.Secure = false;
            objHttpCookie6.HttpOnly = true;
        }
        //
        public void CreateCookie()
        {
            HttpCookie cookie1 = new HttpCookie("key6");
            HttpCookie cookie2 = new HttpCookie("key6") { Secure = false };
            HttpCookie cookie3 = new HttpCookie("key6") { Secure = true };
            HttpCookie cookie4 = new HttpCookie("key6");
            cookie4.Secure = false;
            cookie4.Secure = true;
        }
    }
}