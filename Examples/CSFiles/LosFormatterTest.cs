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
using System.Web.UI;

namespace VulnerableApp
{
    public class InsecureDeserialize
    {
		bool false_bool = false;
        public void Method(string json, TypeNameHandling param)
        {
            // Unsafe 13
            System.Web.UI.LosFormatter losFormatter;
			losFormatter = new LosFormatter(); // Noncompliant (S5773) {{Serialized data signature (MAC) should be verified.}}
            losFormatter = new LosFormatter(false, ""); // Noncompliant (S5773) {{Serialized data signature (MAC) should be verified.}}
            losFormatter = new LosFormatter(false, new byte[0]); // Noncompliant (S5773) {{Serialized data signature (MAC) should be verified.}}
			losFormatter = new LosFormatter(false_bool, new byte[0]); // Noncompliant (S5773) {{Serialized data signature (MAC) should be verified.}}
            losFormatter = new LosFormatter(true, ""); // Compliant - MAC filtering is enabled
            losFormatter = new LosFormatter(true, new byte[0]); // Compliant - MAC filtering is enabled

            losFormatter.Deserialize(new MemoryStream());
            losFormatter.Deserialize(TextReader.Null);
            losFormatter.Deserialize("");
		}
    }
}