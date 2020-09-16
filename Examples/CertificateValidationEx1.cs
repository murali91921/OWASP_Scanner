
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Tests.Diagnostics
{
    class CertificateValidationChecks
    {

        void FalseNegatives()
        {
            CreateRQ().ServerCertificateValidationCallback += FalseNegativeValidatorWithProperty;
            CreateRQ().ServerCertificateValidationCallback += DelegateProperty;
             CreateRQ().ServerCertificateValidationCallback += new CertificateValidationChecks() + 42;
            CreateRQ().ServerCertificateValidationCallback += FalseNegativeException;
        }

        void DirectAddHandlers()
        {
            
            CreateRQ().ServerCertificateValidationCallback += (sender, certificate, chain, SslPolicyErrors) => true;

            CreateRQ().ServerCertificateValidationCallback += (sender, certificate, chain, SslPolicyErrors) => (((true)));    
            CreateRQ().ServerCertificateValidationCallback += (sender, certificate, chain, SslPolicyErrors) => false;
            CreateRQ().ServerCertificateValidationCallback += (sender, certificate, chain, SslPolicyErrors) => certificate.Subject == "Test";

                  
            CreateRQ().ServerCertificateValidationCallback += (sender, certificate, chain, SslPolicyErrors) => { return true; };    
            CreateRQ().ServerCertificateValidationCallback += (sender, certificate, chain, SslPolicyErrors) =>                      
            {
               return true;    
            };
            CreateRQ().ServerCertificateValidationCallback += (sender, certificate, chain, SslPolicyErrors) =>
            {
                return false;
            };

            var rq = CreateRQ();
            rq.ServerCertificateValidationCallback += InvalidValidation;

            CreateRQ().ServerCertificateValidationCallback += InvalidValidation;

            CreateRQ().ServerCertificateValidationCallback = InvalidValidation;
            CreateRQ().ServerCertificateValidationCallback = (sender, certificate, chain, SslPolicyErrors) => { return true; };
        }

        void MultipleHandlers()
        {
            ServicePointManager.ServerCertificateValidationCallback += CompliantValidation;
            ServicePointManager.ServerCertificateValidationCallback += CompliantValidationPositiveA;
            ServicePointManager.ServerCertificateValidationCallback += InvalidValidation;           
            ServicePointManager.ServerCertificateValidationCallback += CompliantValidationPositiveB;
            ServicePointManager.ServerCertificateValidationCallback += CompliantValidationNegative;
            ServicePointManager.ServerCertificateValidationCallback += AdvInvalidTry;               
            ServicePointManager.ServerCertificateValidationCallback += AdvInvalidWithTryObstacles;  
            ServicePointManager.ServerCertificateValidationCallback += AdvCompliantWithTryObstacles;
            ServicePointManager.ServerCertificateValidationCallback += AdvInvalidWithObstacles;     
            ServicePointManager.ServerCertificateValidationCallback += AdvCompliantWithObstacles;
            ServicePointManager.ServerCertificateValidationCallback += AdvCompliantWithException;
            ServicePointManager.ServerCertificateValidationCallback += AdvCompliantWithExceptionAndRethrow;
        }

        void GenericHandlerSignature()
        {
            var httpHandler = new System.Net.Http.HttpClientHandler();
            httpHandler.ServerCertificateCustomValidationCallback += InvalidValidation;

            var ShouldNotTrigger = new NonrelatedSignatureType();
            ShouldNotTrigger.Callback += (sender, chain, certificate, SslPolicyErrors) => true;
            ShouldNotTrigger.Callback += (sender, chain, certificate, SslPolicyErrors) => false;
        }

        void DelegateReturnedByFunction()
        {
            CreateRQ().ServerCertificateValidationCallback += FindInvalid(false);
            CreateRQ().ServerCertificateValidationCallback += FindInvalid();
            CreateRQ().ServerCertificateValidationCallback += FindLambdaValidator();
            CreateRQ().ServerCertificateValidationCallback += FindCompliant(true);
            CreateRQ().ServerCertificateValidationCallback += FindCompliantRecursive(3);
            CreateRQ().ServerCertificateValidationCallback += FindInvalidRecursive(3);
        }

        void ConstructorArguments()
        {
            var optA = new OptionalConstructorArguments(this, cb: InvalidValidation);
            var optB = new OptionalConstructorArguments(this, cb: CompliantValidation);
            using (var ms = new System.IO.MemoryStream())
            {
                using (var ssl = new System.Net.Security.SslStream(ms, true, (sender, chain, certificate, SslPolicyErrors) => true))
                {
                }
                using (var ssl = new System.Net.Security.SslStream(ms, true, InvalidValidation))
                {
                }
                using (var ssl = new System.Net.Security.SslStream(ms, true, CompliantValidation))
                {
                }
            }
        }

        #region Helpers
        
        void InitAsArgument(RemoteCertificateValidationCallback Callback)
        {
            var cb = Callback;                                           
            CreateRQ().ServerCertificateValidationCallback += Callback;  
            CreateRQ().ServerCertificateValidationCallback += cb;        
        }

        void InitAsOptionalArgument(RemoteCertificateValidationCallback Callback = null)
        {
            CreateRQ().ServerCertificateValidationCallback += Callback;  
        }

        void InitAsArgumentRecursive(RemoteCertificateValidationCallback Callback, int cnt)
        {
            if (cnt == 0)
                CreateRQ().ServerCertificateValidationCallback += Callback;     
            else
                InitAsArgumentRecursive(Callback, cnt - 1);
        }
        
        void InitAsArgumentRecursiveNoInvocation(RemoteCertificateValidationCallback Callback, int cnt)
        {
            if (cnt == 0)
            {
                CreateRQ().ServerCertificateValidationCallback += Callback;     
            }
            else
            {
                InitAsArgumentRecursiveNoInvocation(Callback, cnt - 1);
            }
        }
        
        static HttpWebRequest CreateRQ()
        {
            return (HttpWebRequest)System.Net.HttpWebRequest.Create("http://localhost");
        }

        bool IsValid(X509Certificate crt)
        {
            return crt.Subject == "Test";
        }

        void Log(X509Certificate crt)
        {
            //Pretend to do some logging
        }

        #endregion

        #region Basic Validators

        static bool InvalidValidation(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        bool InvalidValidationAsArgument(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        static bool CompliantValidation(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return false;
        }

        bool CompliantValidationPositiveA(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (certificate.Subject == "Test")
            {
                return true;
            }
            else
            {
                return false; 
            }
        }

        bool CompliantValidationPositiveB(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return certificate.Subject == "Test";
        }
        
        bool CompliantValidationNegative(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (certificate.Subject != "Test")
            {
                return false;
            }
            else if (DateTime.Parse(certificate.GetExpirationDateString()) < DateTime.Now)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        #endregion

        #region Advanced Validators

        bool AdvInvalidTry(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            try
            {
                System.Diagnostics.Trace.WriteLine(certificate.Subject);
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine(ex.Message);
                return true;
            }
        }
        
        bool AdvInvalidWithTryObstacles(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            try
            {
                Console.WriteLine("Log something");
                System.Diagnostics.Trace.WriteLine("Log something");
                Log(certificate);

                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine(ex.Message);
            }
            return true;
        }

        bool AdvCompliantWithTryObstacles(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            try
            {
                Console.WriteLine("Log something");
                System.Diagnostics.Trace.WriteLine("Log something");
                Log(certificate);
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Trace.WriteLine(ex.Message);
            }
            return false;
        }

        bool AdvInvalidWithObstacles(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine("Log something");
            System.Diagnostics.Trace.WriteLine("Log something");
            Log(certificate);

            return true;
        }
        
        bool AdvCompliantWithObstacles(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine("Log something");
            System.Diagnostics.Trace.WriteLine("Log something");
            Log(certificate);
            return IsValid(certificate);
        }

        bool AdvCompliantWithException(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            if (certificate.Subject != "test")
            {
                throw new InvalidOperationException("You shall not pass!");
            }
            return true;
        }

        bool AdvCompliantWithExceptionAndRethrow(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            try
            {
                if (certificate.Subject != "test")
                {
                    throw new InvalidOperationException("You shall not pass!");
                }
                return true;
            }
            catch
            {
                throw;
            }
            return true;
        }
                
        #endregion

        #region Find Validators

        static RemoteCertificateValidationCallback FindInvalid()
        {
            return InvalidValidation;
        }

        static RemoteCertificateValidationCallback FindLambdaValidator()
        {
            return (sender, certificate, chain, SslPolicyErrors) => true;
        }

        static RemoteCertificateValidationCallback FindInvalid(bool useDelegate)
        {
            if (useDelegate)
            {
                return InvalidValidation;                                  
            }
            else
            {
                return (sender, certificate, chain, SslPolicyErrors) => true; 
            }
        }
        
        static RemoteCertificateValidationCallback FindCompliant(bool Compliant)
        {
            if (Compliant)
            {
                return null;
            }
            else
            {
                return (sender, certificate, chain, SslPolicyErrors) => true;
            }
        }

        static RemoteCertificateValidationCallback FindCompliantRecursive(int Index)
        {
            if (Index <= 0)
            {
                return CompliantValidation;
            }
            else
            {
                return FindCompliantRecursive(Index - 1);
            }
        }

        static RemoteCertificateValidationCallback FindInvalidRecursive(int Index)
        {
            if (Index <= 0)
            {
                return InvalidValidation;
            }
            else
            {
                return FindInvalidRecursive(Index - 1);
            }
        }

        #endregion
        
        #region False negatives

        static RemoteCertificateValidationCallback DelegateProperty
        {
            get
            {
                return (sender, certificate, chain, SslPolicyErrors) => true;
            }
        }

        static bool FalseNegativeValidatorWithProperty(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return TrueProperty;
        }

        static bool TrueProperty
        {
            get
            {
                return true;
            }
        }

        public static RemoteCertificateValidationCallback operator +(CertificateValidationChecks instance, int number)
        {
            return (sender, certificate, chain, SslPolicyErrors) => true;
        }

        bool FalseNegativeException(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            try
            {
                if (certificate.Subject != "test")
                {
                    throw new InvalidOperationException("You shall not pass! But you will anyway.");
                }
                return true;
            }
            catch
            {
            }
            return true;
        }

        #endregion

        #region Nested classes

        class RelatedSignatureType
        {

            public Func<NonrelatedSignatureType, X509Certificate2, X509Chain, SslPolicyErrors, Boolean> Callback { get; set; }

        }

        class NonrelatedSignatureType
        {
            public Func<NonrelatedSignatureType, X509Chain, X509Certificate2, SslPolicyErrors, Boolean> Callback { get; set; }

        }

        class OptionalConstructorArguments
        {

            public OptionalConstructorArguments(object owner, int a = 0, int b = 0, RemoteCertificateValidationCallback cb = null)
            {

            }

        }

        class InnerAssignmentClass
        {

            public void InitAsArgument(RemoteCertificateValidationCallback callback)
            {
                CertificateValidationChecks.CreateRQ().ServerCertificateValidationCallback += callback;
            }
        }

        class NeighbourAssignmentClass
        {
            public void Init(RemoteCertificateValidationCallback callback)
            {
                //Assignment from sibling class in nested tree
                new InnerAssignmentClass().InitAsArgument((sender, certificate, chain, SslPolicyErrors) => true);
            }
        }

        #endregion

    }
}