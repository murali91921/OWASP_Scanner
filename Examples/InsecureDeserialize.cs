using Newtonsoft.Json;
using System.Web.Script.Serialization;

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
            // //Unsafe 2
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


            // //Unsafe 3
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer = new JavaScriptSerializer(new SimpleTypeResolver());
            var resolver = new SimpleTypeResolver();
            serializer = new JavaScriptSerializer(null);
            serializer = new JavaScriptSerializer(resolver);

            //Unsafe 4
            Stream stream = new MemoryStream();
            BinaryFormatter binary = new BinaryFormatter();
            binary.Deserialize(stream);
            binary.UnsafeDeserialize(stream, null);
            binary.UnsafeDeserializeMethodResponse(stream, null, null);
            binary.DeserializeMethodResponse(stream, null, null);
        }
        static TypeNameHandling GetHandling(string param)
        {
            return TypeNameHandling.None;
        }
    }
}