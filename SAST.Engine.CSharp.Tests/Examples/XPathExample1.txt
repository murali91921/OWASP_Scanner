using System;
using System.Runtime;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

namespace WebApplicationDotNetCore.Controllers
{
    public class XPathInjectionCompliant
    {
        public XmlDocument doc { get; set; }

        public void Authenticate(string user, string pass)
        {
            // Restrict the username and password to letters only
            //if (!Regex.IsMatch(user, "^[a-zA-Z]+$") || !Regex.IsMatch(pass, "^[a-zA-Z]+$"))
            //{
            //    return ;
            //}

            System.String expression = "/users/user[@name='" + user + "' and @pass='" + pass + "']"; // Compliant
            XmlNode node = doc.SelectSingleNode(expression);
            XPathNavigator nav = doc.CreateNavigator();
            XElement element = System.Xml.XPath.Extensions.XPathSelectElement(null, expression);

            Console.WriteLine(doc.SelectNodes(expression));
            Console.WriteLine(doc.SelectNodes(expression, null));
            Console.WriteLine(doc.SelectSingleNode(expression));
            Console.WriteLine(doc.SelectSingleNode(expression, null));
            Console.WriteLine(node.SelectNodes(expression));;
            Console.WriteLine(node.SelectNodes(expression, null));
            Console.WriteLine(node.SelectSingleNode(expression));
            Console.WriteLine(node.SelectSingleNode(expression, null));
            Console.WriteLine(nav.SelectSingleNode(expression));
            Console.WriteLine(nav.SelectSingleNode(expression, null));
            Console.WriteLine(nav.SelectSingleNode(nav.Compile(expression)));
            Console.WriteLine(nav.Select(expression));
            Console.WriteLine(nav.Select(expression, null));
            Console.WriteLine(nav.Select(nav.Compile(expression)));
            Console.WriteLine(nav.Compile(expression));
            Console.WriteLine(nav.Evaluate(expression));
            Console.WriteLine(nav.Evaluate(expression, null));
            Console.WriteLine(nav.Evaluate(nav.Compile(expression)));
            Console.WriteLine(nav.Evaluate(nav.Compile(expression), null));
            Console.WriteLine(XPathExpression.Compile(expression));
            Console.WriteLine(XPathExpression.Compile(expression, null));
            Console.WriteLine(element.XPathSelectElement(expression));
            Console.WriteLine(element.XPathSelectElement(expression, null));
            Console.WriteLine(element.XPathSelectElements(expression));
            Console.WriteLine(element.XPathSelectElements(expression, null));
            Console.WriteLine(element.XPathEvaluate(expression));
            Console.WriteLine(element.XPathEvaluate(expression, null));
            Console.WriteLine(System.Xml.XPath.Extensions.XPathSelectElement(element, expression));
            Console.WriteLine(System.Xml.XPath.Extensions.XPathSelectElement(element, expression, null));
            Console.WriteLine(System.Xml.XPath.Extensions.XPathSelectElements(element, expression));
            Console.WriteLine(System.Xml.XPath.Extensions.XPathSelectElements(element, expression, null));
            Console.WriteLine(System.Xml.XPath.Extensions.XPathEvaluate(element, expression));
            Console.WriteLine(System.Xml.XPath.Extensions.XPathEvaluate(element, expression, null));
        }
    }
}