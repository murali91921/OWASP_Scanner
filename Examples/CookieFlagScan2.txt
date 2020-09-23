using System;
using System.IO;
using System.Net.Http.Headers;
using System.Net.Http;
using System.Net;
using System.Web;
using System.Web.UI;

namespace CFSNSExample2
{
public class CFSClassExample2 : Page
{

        //Snippet 1
        public HttpResponseMessage Snippet1()
        {
            var resp = new HttpResponseMessage();
            System.Net.Http.Headers.CookieHeaderValue cookie = new System.Net.Http.Headers.CookieHeaderValue("CookieName11", "CookieVal11");
            CookieHeaderValue cookie1 = new CookieHeaderValue("CookieName12", "CookieVal12");
            cookie.Expires = DateTimeOffset.Now.AddDays(1);
            cookie.Path = "/";
            // cookie.Secure = false;
            cookie.HttpOnly = true;
            cookie1.Secure = true;
            cookie1.HttpOnly = false;
            resp.Headers.AddCookies(new CookieHeaderValue[] { cookie,cookie1 });
            return resp;
        }

        //Snippet 2
        public void Snippet2()
        {
            CookieHeaderValue objCookieHeaderValue2 = new CookieHeaderValue("CookieName2", "CookieVal2")
            {
                Path = "/",
            };
            objCookieHeaderValue2.Secure = true;
            objCookieHeaderValue2.HttpOnly = false;
        }

        //Snippet 3
        public void Snippet3()
        {
            CookieHeaderValue objCookieHeaderValue3 = new CookieHeaderValue("CookieName3", "CookieVal3")
            {
                Path = "/",
                HttpOnly = true,
            };
            objCookieHeaderValue3.Secure = true;
        }

        //Snippet 4
        public void Snippet4()
        {
            var objCookieHeaderValue4 = new CookieHeaderValue("CookieName4", "CookieVal4")
            {
                Path = "/",
                HttpOnly = true,
            };
            objCookieHeaderValue4.Secure = false;
        }
        //Snippet 5
        public void Snippet5()
        {
            var objCookieHeaderValue5 = new CookieHeaderValue("CookieName5", "CookieVal5");
            objCookieHeaderValue5.Secure = true;
            objCookieHeaderValue5.HttpOnly = false;
        }

        //Snippet 6
        public void Snippet6()
        {
            CookieHeaderValue objCookieHeaderValue6 = new CookieHeaderValue("CookieName6", "CookieVal6");
            objCookieHeaderValue6.Secure = false;
            objCookieHeaderValue6.HttpOnly = true;
        }

        //Snippet7
        public HttpResponse Snippet7(HttpResponse response)
        {
            foreach (string s in response.Cookies.AllKeys)
            {
                response.Cookies[s].Secure = true;
            }
        }

		//Snippet8
		public HttpResponse Snippet8(string secureCookieName, HttpResponse response)
        {
            foreach (string s in response.Cookies.AllKeys)
            {
                response.Cookies[s].Secure = true;
            }
        }

		//Snippet9 Response object from Web.UI.Page
		public void Snippet9()
        {
            foreach (string s in Response.Cookies.AllKeys)
            {
                Response.Cookies[s].Secure = true;
            }
        }
    }
}