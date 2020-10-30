using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Serialization;

namespace XmlSerializerTest
{
    public class XmlSerializerTestCase
    {
		XmlSerializer serializer = null;
        public void unsecuredeserialization(string typeName)
        {
            Program obj = null;
            Type t = Type.GetType(typeName);
            serializer = new XmlSerializer(t); // Noncompliant
            serializer = new XmlSerializer(GetType()); // Compliant
            FileStream fs = new FileStream("C:\\File.txt", FileMode.Open);
            obj = (Program)serializer.Deserialize(fs);
        }
        public void securedeserialization()
        {
            Program obj = null;
            serializer = new XmlSerializer(typeof(Program)); // Compliant
            serializer = new XmlSerializer(GetType()); // Compliant
            FileStream fs = new FileStream("C:\\File.txt", FileMode.Open);
            obj = (Program)serializer.Deserialize(fs);
        }
    }
}