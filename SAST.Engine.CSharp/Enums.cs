namespace SAST.Engine.CSharp.Enums
{
    /// <summary>
    /// Scanner Type Enum
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
        LdapInjection = 9,
        InsecureRandom = 10,
        SqlInjection = 11,
        XPath = 12,
        XSS = 13,
        XXE = 14,
        FormsAuthentication = 15,
        MachineKeyClearText = 16,
        WeakSymmetricAlgorithm = 17,
        WeakCipherModePadding = 18,
        InsecureDeserialization = 19,
        CommandInjection = 20,
        FilePathInjection = 21,
        CertificateValidation = 22,
        JWTValidation = 23,
        HTTPHeaderChecking = 24,
        EventValidation = 25,
        ViewStateMac = 26,
        PasswordLockout = 27,
        Authorize = 28,
        CorsAllowAnyOrigin = 29,
        WeakCryptoKeyLength = 30,
        SerializationType = 31,
        LdapSecureConnection = 32,
        RegexInjection = 33,
        HttpRequestValidation = 34,
        SerializationConstructor = 35,
        HardcodedIpAddress = 36,
        ExportInterface = 37,
        ThreadSuspendResume = 38,
        SafeHandle = 39,
        RecursiveTypeInheritance = 40,
        IDisposableImplement = 41,
        DisposableMember= 42,
    }

    /// <summary>
    /// Scanner Sub Type Enum
    /// </summary>
    public enum ScannerSubType
    {
        None = 0,
        StoredXSS = 1,
        ReflectedXSS = 2,
        DomXSS = 3,
        FAWeakCookie = 4,
        FAInsecureCookie = 5,
        FACookielessMode = 6,
        FACrossAppRedirect = 7,
        SecureFlag = 8,
        HttpOnlyFlag = 9
    }

    /// <summary>
    /// Severity Levels
    /// </summary>
    public enum Severity
    {
        Critical = 1,
        High = 2,
        Medium = 3,
        Low = 4,
        Information = 0,
    }
}