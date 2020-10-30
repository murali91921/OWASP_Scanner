using System;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;

namespace CFSNSExample3
{
    public class CFSClassExample3
    {
        public void TestMethod(string key, string value)
        {
            var responseCookies = new ResponseCookies();
            responseCookies.Append(key, value, GetCookieOptions());
        }
        public CookieOptions GetCookieOptions()
        {
            var cookieOptions = new CookieOptions();
            cookieOptions.Secure = false;
            cookieOptions.HttpOnly = true;
            return cookieOptions;
        }
    }
}