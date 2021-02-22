using System.Runtime.Serialization;

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
        MissingHttpOnlyCookie = 2,
        MissingSecureCookie = 3,
        OpenRedirect = 4,
        EmptyTry = 5,
        EmptyCatch = 6,
        WeakPasswordConfig = 7,
        WeakHashingConfig = 8,
        Csrf = 9,
        LdapInjection = 10,
        InsecureRandom = 11,
        SqlInjection = 12,
        XPath = 13,
        ReflectedXSS = 14,
        StoredXSS = 15,
        XXE = 16,
        WeakSymmetricAlgorithm = 17,
        MissingRequireSSLFormsAuthentication = 101,
        MissingCookielessFormsAuthentication = 102,
        MissingCrossAppRedirectsFormsAuthentication = 103,
        MissingCookieProtectionFormsAuthentication = 104,
        HTTPHeaderChecking = 105,
        MachineKeyClearText = 106,
        EventValidation = 107,
        ViewStateMac = 108,
        WeakCipherModePadding = 18,
        InsecureDeserialization = 19,
        CommandInjection = 20,
        FilePathInjection = 21,
        CertificateValidation = 22,
        JWTValidation = 23,
        PasswordLockout = 24,
        Authorize = 25,
        CorsAllowAnyOrigin = 26,
        WeakCryptoKeyLength = 27,
        SerializationType = 28,
        LdapSecureConnection = 29,        
        RegexInjection = 30,
        SerializationConstructor = 31,
        HardcodedIpAddress = 32,
        ExportInterface = 33,
        SerializationEventImplement = 34,
        CollectionSizeOrArrayLength = 35,
        UselessException = 36,
        OverwriteCollectionElement = 37,
        ConstructorArgumentValue = 38,
        ThreadSuspendResume = 39,
        SafeHandle = 40,
        RecursiveTypeInheritance = 41,
        SqlKeywordDelimit = 42,
        DestructorThrow = 43,
        NonAsyncTaskNull = 44,
        BeginEndInvoke = 45,
        SharedInstance = 46,
        PropertyAccessor = 47,
        RightShiftNotNumber = 48,
        SharedObjectLock = 49,
        PartCreationPolicyNonExport = 50,
        EnableDebugMode = 51,
        HeaderInjection = 52,
    }

    /// <summary>
    /// Scanner Sub Type Enum
    /// </summary>
    //public enum ScannerSubType
    //{
    //    None = 0,
    //    [EnumMember(Value = "Stored XSS")]
    //    StoredXSS = 1,
    //    ReflectedXSS = 2,
    //    DomXSS = 3,
    //    FAWeakCookie = 4,
    //    FAInsecureCookie = 5,
    //    FACookielessMode = 6,
    //    FACrossAppRedirect = 7,
    //    SecureFlag = 8,
    //    HttpOnlyFlag = 9
    //}

    /// <summary>
    /// Severity Levels
    /// </summary>
    public enum Severity
    {
        [EnumMember(Value = "Critical")]
        Critical = 1,

        [EnumMember(Value = "High")]
        High = 2,

        [EnumMember(Value = "Medium")]
        Medium = 3,

        [EnumMember(Value = "Low")]
        Low = 4,

        [EnumMember(Value = "Information")]
        Information = 0,
    }
}