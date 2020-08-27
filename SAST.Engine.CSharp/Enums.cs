namespace SAST.Engine.CSharp.Enums
{
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
        XXE = 14,
        FormsAuthentication = 15,
        MachineKeyClearText = 16,
        WeakSymmetricAlgorithm = 17,
        WeakCipherMode = 18
    }
    public enum ScannerSubType
    {
        None = 0,
        StoredXSS = 1,
        ReflectedXSS = 2,
        DomXSS = 3,
        FAWeakCookie = 4
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