using System.Text.RegularExpressions;

namespace AspxParser
{
    partial class Parser
    {
        private void ProcessServerInclude(Match match)
        {
            var location = CreateLocation(match);
            var pathType = match.Groups["pathtype"].Value;
            var fileName = match.Groups["filename"].Value;
            if ("file".EqualsNoCase(pathType))
            {
                eventListener.OnInclude(location, IncludePathType.Absolute, fileName);
            }
            else if ("virtual".EqualsNoCase(pathType))
            {
                eventListener.OnInclude(location, IncludePathType.Virtual, fileName);
            }
            else
            {
                eventListener.OnError(location, "Invlid server include path type.");
            }
        }
    }
}
