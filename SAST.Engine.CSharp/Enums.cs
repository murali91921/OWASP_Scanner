using System.Runtime.Serialization;

namespace SAST.Engine.CSharp.Enums
{
    /// <summary>
    /// TODO: Replace this with SAST.Core once integrate
    /// </summary>
    public enum ScannerType
    {
        None = 0,
        Invalid = -1,
        HardcodePassword = 1,
        InsecureCookie = 2,
        OpenRedirect = 3,
        EmptyTry = 4,
        EmptyCatch = 5,
        WeakPasswordConfig = 6,
        WeakHashingConfig = 7,
        Csrf = 8,
        Ldap = 9,
        InsecureRandom = 10,
        SqlInjection = 11,
        XPath = 12,
        XSS = 13,
        XXE = 14
    }
    public enum ScannerSubType
    {
        None = 0,
        StoredXSS = 1,
        ReflectedXSS = 2,
        DomXSS = 3,
    }
    public enum Severity
    {
        Critical = 1,
        High = 2,
        Medium = 3,
        Low = 4,
        Information = 0,
    }

}