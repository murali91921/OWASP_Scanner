using System;
using System.Xml;
using System.Xml.XPath;

namespace VulnerableApp
{
    public class XxeExample1
    {
        public static void Unsafe1()
        {
            // .NET Framework 4.5.2+
            XmlDocument parser = new XmlDocument { XmlResolver = null };
            _ = new XmlDocument { XmlResolver = new XmlUrlResolver() };
            parser.XmlResolver = new XmlUrlResolver(); 
            parser.LoadXml("xxe.xml");
        }
        public static void Unsafe2()
        {
            // .NET Framework 4.5.2+
            XmlTextReader reader = new XmlTextReader("xxe.xml");
            reader.DtdProcessing = DtdProcessing.Parse;
            reader.XmlResolver = new XmlUrlResolver();
            while (reader.Read())
                Console.WriteLine(reader.AttributeCount);
        }

        public static void Unsafe3()
        {
            //.NET Framework 4.5.2 +
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.ProhibitDtd = false;
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.XmlResolver = new XmlUrlResolver();
            XmlReader reader = XmlReader.Create("xxe.xml", settings);
            while (reader.Read())
            {
                Console.WriteLine(reader.AttributeCount);
            }
        }
        public static void Unsafe4()
        {
            // prior to .NET 4.5.2
            XPathDocument doc = new XPathDocument("xxe.xml");
            XPathNavigator nav = doc.CreateNavigator();
            string xml = nav.InnerXml.ToString();
        }
        public static void Unsafe5()
        {
            XmlTextReader reader = new XmlTextReader("xxe.xml");
            reader.XmlResolver = new XmlUrlResolver();
            while (reader.Read())
                Console.WriteLine(reader.AttributeCount);
        }
        public static void Safe1()
        {
            // .NET Framework 4.5.2+
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.DtdProcessing = DtdProcessing.Ignore;
            settings.XmlResolver = null;
            XmlReader reader = XmlReader.Create("xxe.xml", settings);
            while (reader.Read())
            {
                Console.WriteLine(reader.AttributeCount);
            }
        }
        public static void Safe2()
        {
            XmlDocument parser = new XmlDocument();
            parser.XmlResolver = null;
            parser.LoadXml("xxe.xml");
        }
        public static void Safe3()
        {
            XmlDocument parser = new XmlDocument();
            parser.LoadXml("xxe.xml");

        }
        public static void Safe4()
        {
            XmlTextReader reader = new XmlTextReader("xxe.xml");
            while (reader.Read())
                Console.WriteLine(reader.AttributeCount);
        }
        public static void Safe5()
        {
            // prior to .NET 4.5.2
            XmlReader reader = XmlReader.Create("xxe.xml");
            XPathDocument doc = new XPathDocument(reader);
        }
    }
}