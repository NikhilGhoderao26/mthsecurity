using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Configuration;

namespace MTH.Security.Cors
{
    public class EnableCorsModule : IHttpModule
    {
        private string[] _origins = null;
        private string _methods = null;
        private HttpApplication _context = null;
        private bool _corsEnabled = false;

        public void Dispose()
        {
        }

        public void Init(HttpApplication context)
        {
            var domains = WebConfigurationManager.AppSettings["CorsAllowedDomains"];
            var methods = WebConfigurationManager.AppSettings["CorsAllowedMethods"];
            var corsEnabledStr = WebConfigurationManager.AppSettings["CorsEnabled"];
            if (!string.IsNullOrEmpty(corsEnabledStr))
            {
                var corsEnabledBool = false;
                if (bool.TryParse(corsEnabledStr, out corsEnabledBool))
                    _corsEnabled = corsEnabledBool;
            }

            if (string.IsNullOrEmpty(methods))
                methods = "GET, PUT, POST, DELETE, OPTIONS";

            _context = context;
            _origins = domains?.Split(',');
            for (int i = 0; i < _origins.Length; i++)
                _origins[i] = _origins[i].Trim();

            _methods = methods;
            context.BeginRequest += context_BeginRequest;
        }

        private void context_BeginRequest(object sender, EventArgs e)
        {
            /*
            if (_corsEnabled)
            {
                string origin = "NA";
                if (HttpContext.Current.Request.Headers.AllKeys.Contains("Origin"))
                    origin = HttpContext.Current.Request.Headers.GetValues("Origin").FirstOrDefault();
                else if (HttpContext.Current.Request.Headers.AllKeys.Contains("origin"))
                    origin = HttpContext.Current.Request.Headers.GetValues("origin").FirstOrDefault();
                else if (HttpContext.Current.Request.Headers.AllKeys.Contains("ORIGIN"))
                    origin = HttpContext.Current.Request.Headers.GetValues("ORIGIN").FirstOrDefault();

                HttpContext.Current.Response.AppendHeader("X-SP-CORS", origin);
            }
            else
            {
                HttpContext.Current.Response.AppendHeader("X-SP-CORS", "Disabled");
            }
            */

            if (_corsEnabled)
            {               
                string origin = "missing";
                if (HttpContext.Current.Request.Headers.AllKeys.Contains("Origin"))
                    origin = HttpContext.Current.Request.Headers.GetValues("Origin").FirstOrDefault();
                else if (HttpContext.Current.Request.Headers.AllKeys.Contains("origin"))
                    origin = HttpContext.Current.Request.Headers.GetValues("origin").FirstOrDefault();
                else if (HttpContext.Current.Request.Headers.AllKeys.Contains("ORIGIN"))
                    origin = HttpContext.Current.Request.Headers.GetValues("ORIGIN").FirstOrDefault();

                HttpContext.Current.Response.AppendHeader("X-SP-CORS-ENABLED", "true");
                if (_origins != null && _origins.Any() &&
                    (_origins.Contains(origin, StringComparer.InvariantCultureIgnoreCase) ||
                        _origins.Contains("*", StringComparer.InvariantCultureIgnoreCase)))
                {
                    HttpContext.Current.Response.AppendHeader("X-SP-CORS", origin);
                    HttpContext.Current.Response.AppendHeader("Access-Control-Allow-Origin", origin);
                    HttpContext.Current.Response.AppendHeader("Access-Control-Allow-Methods", _methods);
                }
                else
                {
                    HttpContext.Current.Response.AppendHeader("X-SP-CORS", origin);
                    HttpContext.Current.Response.AppendHeader("Access-Control-Allow-Methods", _methods);
                }
            }
            else
            {
                string origin = string.Empty;
                if (HttpContext.Current.Request.Headers.AllKeys.Contains("Origin"))
                    origin = HttpContext.Current.Request.Headers.GetValues("Origin").FirstOrDefault();
                else if (HttpContext.Current.Request.Headers.AllKeys.Contains("origin"))
                    origin = HttpContext.Current.Request.Headers.GetValues("origin").FirstOrDefault();
                else if (HttpContext.Current.Request.Headers.AllKeys.Contains("ORIGIN"))
                    origin = HttpContext.Current.Request.Headers.GetValues("ORIGIN").FirstOrDefault();

                HttpContext.Current.Response.AppendHeader("X-SP-CORS-ENABLED", "false");
                HttpContext.Current.Response.AppendHeader("X-SP-CORS", origin);
                HttpContext.Current.Response.AppendHeader("Access-Control-Allow-Origin", "*");
                HttpContext.Current.Response.AppendHeader("Access-Control-Allow-Methods", _methods);
            }
        }
    }
}
