namespace SAST.Engine.CSharp.Enums
{
    /// <summary>
    /// TODO: Replace this with SAST.Core once integrate
    /// </summary>
    public enum ScannerType
    {
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
        None = 0,
        Invalid = -1
    }
}