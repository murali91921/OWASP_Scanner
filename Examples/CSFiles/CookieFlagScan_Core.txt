using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;

namespace CFSNSExample5
{
    public class Cookie_Core : Controller
    {
        public void CreateCookieOptions()
        {
            Microsoft.AspNetCore.Http.CookieOptions cookieOptions = new CookieOptions();
            cookieOptions.HttpOnly = false;
            cookieOptions.Secure = false;
            Response.Cookies.Append("first", "", cookieOptions);

            cookieOptions = new CookieOptions() { HttpOnly = false, Secure = false };
            Response.Cookies.Append("second", "", cookieOptions);

            Microsoft.Net.Http.Headers.SetCookieHeaderValue setCookieHeader = new Microsoft.Net.Http.Headers.SetCookieHeaderValue("obj");
            setCookieHeader.HttpOnly = false;
            setCookieHeader.Secure = false;
            setCookieHeader = new Microsoft.Net.Http.Headers.SetCookieHeaderValue("assign")
            {
                HttpOnly = false,
                Secure = false
            };
            HttpContext.Response.Headers.Add("SetCookie", setCookieHeader.ToString());
        }
    }
}