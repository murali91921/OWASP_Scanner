using System;
using System.Xml;
using System.Xml.XPath;
using Dtd = System.Xml.DtdProcessing;

namespace VulnerableApp
{
    public class XxeExample2
    {
        static void SafeReader1()
        {
            XmlReader myReader = XmlReader.Create("xxe.xml");
            XmlReader myReader1 = XmlReader.Create(inputUri: "xxe.xml");
            while (myReader.Read())
                Console.WriteLine(myReader.Value);
        }
        static void UnsafeReader1()
        {
            XmlReaderSettings rs = new XmlReaderSettings();
            rs.ProhibitDtd = false;
            XmlReader myReader = XmlReader.Create("xxe.xml", rs);
            while (myReader.Read())
                Console.WriteLine(myReader.Value);
        }
        static void UnsafeReader1_0()
        {
            XmlReaderSettings rs = new XmlReaderSettings();
            rs.ProhibitDtd = true;
            XmlReader myReader = XmlReader.Create("xxe.xml", rs);
            while (myReader.Read())
                Console.WriteLine(myReader.Value);
        }
        static void SafeReader1_1()
        {
            XmlReader myReader = XmlReader.Create("xxe.xml", null);
            while (myReader.Read())
                Console.WriteLine(myReader.Value);
        }
        static void UnsafeReader1_2()
        {
            XmlReaderSettings rs = new XmlReaderSettings();
            XmlReader myReader = XmlReader.Create("xxe.xml", new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, ProhibitDtd = false, XmlResolver = null });
            while (myReader.Read())
                Console.WriteLine(myReader.Value);
        }
        static void SafeReader2()
        {
            XmlReaderSettings rs = new XmlReaderSettings();
            rs.DtdProcessing = DtdProcessing.Ignore;
            XmlReader myReader = XmlReader.Create("xxe.xml", rs);
            while (myReader.Read())
                Console.WriteLine(myReader.Value);
        }
        static void UnsafeReader2()
        {
            XmlReaderSettings rs = new XmlReaderSettings();
            rs.DtdProcessing = DtdProcessing.Parse;
            XmlReader myReader = XmlReader.Create("xxe.xml", rs);
            while (myReader.Read())
                Console.WriteLine(myReader.Value);
        }
        static void UnsafeTextReader3()
        {
            XmlTextReader myReader = new XmlTextReader("xxe.xml");
            while (myReader.Read())
                Console.WriteLine(myReader.Value);
        }
        static void SafeTextReader3()
        {
            XmlTextReader myReader = new XmlTextReader("xxe.xml");
            myReader.ProhibitDtd = true;
            while (myReader.Read())
                Console.WriteLine(myReader.Name);
        }
        static void SafeTextReader4()
        {
            XmlTextReader myReader = new XmlTextReader("xxe.xml");
            myReader.DtdProcessing = DtdProcessing.Prohibit;
            while (myReader.Read())
                Console.WriteLine(myReader.Name);
        }
    }
}