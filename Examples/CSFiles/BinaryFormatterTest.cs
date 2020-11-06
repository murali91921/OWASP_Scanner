using Newtonsoft.Json;
using System.Web.Script.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Messaging;
using System.Runtime.Serialization.Formatters.Soap;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Xml;
using System.Xml.Serialization;
using System;
using System.Reflection;

namespace VulnerableApp
{
    public class BinaryFormatterTest
    {
        static void Method()
        {
            // Unsafe 4
            Stream stream = new MemoryStream();
            BinaryFormatter binary1 = new BinaryFormatter() { Binder = new CustomBinder() };
            BinaryFormatter binary2 = new BinaryFormatter() { Binder = null };
            BinaryFormatter binary3 = new BinaryFormatter();
            BinaryFormatter binary4 = new BinaryFormatter();
			binary4.Binder = new CustomBinder();
            binary1.Deserialize(stream);
            binary2.Deserialize(stream);//NonComplaint
            binary3.Deserialize(stream);//NonComplaint
            binary4.Deserialize(stream);
            binary4.Deserialize(stream);
            binary4.UnsafeDeserialize(stream, null);
            binary4.UnsafeDeserializeMethodResponse(stream, null, null);
            binary4.DeserializeMethodResponse(stream, null, null);
        }
    }
    sealed class CustomBinder : SerializationBinder
    {
        public override Type BindToType(string assemblyName, string typeName)
        {
            if (!(typeName == "type1" || typeName == "type2" || typeName == "type3"))
            {
                throw new SerializationException("Only type1, type2 and type3 are allowed"); // Compliant
            }
            return Assembly.Load(assemblyName).GetType(typeName);
        }
    }
	
    public class NetDataContractSerializerTest
    {
        static void Method()
        {
            // Unsafe 4
            Stream stream = new MemoryStream();
            NetDataContractSerializer netDataContractSerializer1 = new NetDataContractSerializer(){ Binder = new CustomBinder() };
            NetDataContractSerializer netDataContractSerializer2 = new NetDataContractSerializer(){ Binder = null };
            NetDataContractSerializer netDataContractSerializer3 = new NetDataContractSerializer();
            NetDataContractSerializer netDataContractSerializer4 = new NetDataContractSerializer();
			netDataContractSerializer4.Binder = new CustomBinder();			
            netDataContractSerializer1.Deserialize(new MemoryStream());
            netDataContractSerializer2.Deserialize(new MemoryStream());
            netDataContractSerializer3.Deserialize(new MemoryStream());
			netDataContractSerializer3.Binder = new CustomBinder();			
            netDataContractSerializer3.Deserialize(new MemoryStream());
            netDataContractSerializer4.Deserialize(new MemoryStream());
            netDataContractSerializer1.ReadObject(new MemoryStream());
        }
    }
    public class NetDataContractSerializerTest
    {
        static void Method()
        {
            // Unsafe 4
            Stream stream = new MemoryStream();
            SoapFormatter soapFormatter1 = new SoapFormatter(){ Binder = new CustomBinder() };
            SoapFormatter soapFormatter2 = new SoapFormatter(){ Binder = null };
            SoapFormatter soapFormatter3 = new SoapFormatter();
            SoapFormatter soapFormatter4 = new SoapFormatter();
			soapFormatter4.Binder = new CustomBinder();			
            soapFormatter1.Deserialize(new MemoryStream());
            soapFormatter2.Deserialize(new MemoryStream());
            soapFormatter3.Deserialize(new MemoryStream());
            soapFormatter4.Deserialize(new MemoryStream());
        }
	}
	
    public class JavaScriptSerializerTest
    {
        static void Method()
        {
	        JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer = new JavaScriptSerializer(new SimpleTypeResolver());
            var resolver = new SimpleTypeResolver();
            serializer = new JavaScriptSerializer(null);
            serializer = new JavaScriptSerializer(resolver);
            // Unsafe 4
        }
	}
}