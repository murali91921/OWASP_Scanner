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

namespace VulnerableApp
{
    public class Model
    {
    // Unsafe 1
    [Newtonsoft.Json.JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, TypeNameHandling = InsecureDeserialize.typename)]
    public string SecureIdName { set; get; }
    [JsonProperty(TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All)]
    public string InsecureName { set; get; }
    }

    public class InsecureDeserialize
    {
        public const TypeNameHandling typename = TypeNameHandling.Objects;
        static void Method(string json, TypeNameHandling param)
        {
            //Unsafe 2
            var data = JsonConvert.DeserializeObject<Model>(json, new JsonSerializerSettings
            {
            TypeNameHandling = TypeNameHandling.Objects
            });
            var serializeSettings = new JsonSerializerSettings();
            serializeSettings.TypeNameHandling = TypeNameHandling.All;
            serializeSettings.TypeNameHandling = (TypeNameHandling)2;
            serializeSettings = new JsonSerializerSettings
            {
            TypeNameHandling = param
            };
            serializeSettings.TypeNameHandling = GetHandling("");

            // Unsafe 5
            BinaryMessageFormatter binaryMessage = new System.Messaging.BinaryMessageFormatter();
            binaryMessage.Read(new Message());


            // Unsafe 7
            System.Web.UI.ObjectStateFormatter formatter = new System.Web.UI.ObjectStateFormatter();
            formatter.Deserialize("");
            formatter.Deserialize(new MemoryStream());

            // Unsafe 8
            XmlObjectSerializer xmlObjectSerializer = null;
            xmlObjectSerializer.ReadObject(new MemoryStream());

            // Unsafe 11
            DataContractJsonSerializer dataContractJsonSerializer = new DataContractJsonSerializer(typeof(InsecureDeserialize));
            dataContractJsonSerializer.ReadObject(new MemoryStream());
            dataContractJsonSerializer.ReadObject(XmlDictionaryReader.Create(""));
            dataContractJsonSerializer.ReadObject(XmlDictionaryReader.Create(""), false);
            dataContractJsonSerializer.ReadObject(XmlReader.Create(""));
            dataContractJsonSerializer.ReadObject(XmlReader.Create(""), false);

            // Unsafe 12
            XmlSerializer xmlSerializer = new XmlSerializer(typeof(InsecureDeserialize));
            xmlSerializer.Deserialize(new MemoryStream());
            xmlSerializer.Deserialize(TextReader.Null);
            xmlSerializer.Deserialize(XmlReader.Create(""));
            xmlSerializer.Deserialize(XmlReader.Create(""), "\"");
            xmlSerializer.Deserialize(XmlReader.Create(""), new System.Xml.Serialization.XmlDeserializationEvents());
            xmlSerializer.Deserialize(XmlReader.Create(""), "\"", new System.Xml.Serialization.XmlDeserializationEvents());

            // Unsafe 13
            System.Messaging.XmlMessageFormatter xmlMessageFormatter = new XmlMessageFormatter();
            xmlMessageFormatter.Read(new System.Messaging.Message());

            // Unsafe 14
            System.Resources.ResourceReader resourceReader = new System.Resources.ResourceReader("");
            resourceReader = new System.Resources.ResourceReader(new MemoryStream());

            // Unsafe 15
            fastJSON.JSON.ToObject("");

            // Unsafe 16
            ServiceStack.Text.JsonSerializer.DeserializeFromString("", typeof(InsecureDeserialize));
            ServiceStack.Text.JsonSerializer.DeserializeFromReader(TextReader.Null, typeof(InsecureDeserialize));
            ServiceStack.Text.JsonSerializer.DeserializeFromStream(typeof(InsecureDeserialize), new MemoryStream());

            ServiceStack.Text.TypeSerializer.DeserializeFromString("", typeof(InsecureDeserialize));
            ServiceStack.Text.TypeSerializer.DeserializeFromReader(TextReader.Null, typeof(InsecureDeserialize));
            ServiceStack.Text.TypeSerializer.DeserializeFromStream(typeof(InsecureDeserialize), new MemoryStream());

            ServiceStack.Text.CsvSerializer.DeserializeFromString(typeof(InsecureDeserialize), "");
            ServiceStack.Text.CsvSerializer.DeserializeFromReader<InsecureDeserialize>(TextReader.Null);
            ServiceStack.Text.CsvSerializer.DeserializeFromStream(typeof(InsecureDeserialize), new MemoryStream());

            ServiceStack.Text.XmlSerializer.DeserializeFromString("", typeof(InsecureDeserialize));
            ServiceStack.Text.XmlSerializer.DeserializeFromReader<InsecureDeserialize>(TextReader.Null);
            ServiceStack.Text.XmlSerializer.DeserializeFromStream(typeof(InsecureDeserialize), new MemoryStream());
        }
        static TypeNameHandling GetHandling(string param)
        {
            return TypeNameHandling.None;
        }
    }
}