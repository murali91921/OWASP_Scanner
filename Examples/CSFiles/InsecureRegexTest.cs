namespace RegExpInjectionNS
{
    using System.Text.RegularExpressions;
    using static System.Text.RegularExpressions.Regex;
	
    public class RegExpInjection_unsafe
    {
        public bool Validate(string pattern, string input)
        {
            bool match = IsMatch(input, pattern); // Noncompliant
            return match;
        }
        public bool Validate_object(string pattern, string input)
        {
            Regex regex = new Regex(pattern);
            bool match = regex.IsMatch(input); // Noncompliant
            return match;
        }
    }
    public class RegExpInjection_safe
    {
        public bool Validate(string pattern, string input)
        {
            bool match = Regex.IsMatch(input, Regex.Escape(pattern)); // Compliant
            return match;
        }
        public bool Validate_object(string pattern, string input)
        {
            Regex regex = new Regex(Regex.Escape(pattern));
            bool match = regex.IsMatch(input); // Noncompliant
            return match;
        }
    }
}