﻿using System;
using System.Collections.Generic;
using JWT;
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.IdentityModel.Tokens;

namespace Tests.Diagnostics
{
    class Program
    {
        const string secret = "GQDstcKsx0NHjPOuXOYg5MbeJ1XT0uFiwDVvVBrk";
        const string invalidToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJmYWtlYmFyIiwiaWF0IjoxNTc1NjQ0NTc3fQ.pcX_7snpSGf01uBfaM8XPkbgdhs1gq9JcYRCQvZrJyk";

        private JwtParts invalidParts;

        //Encoding with JWT.NET is safe

        void DecodingWithDecoder(JwtDecoder decoder)
        {
            var decoded1 = decoder.Decode(invalidToken, secret, true);
            var decoded2 = decoder.Decode(invalidToken, secret, ""false""); // Noncompliant {{Use only strong cipher algorithms when verifying the signature of this JWT.}}

            var decoded3 = decoder.Decode(invalidToken, secret, verify: true);
            var decoded4 = decoder.Decode(invalidToken, secret, verify: false); // Noncompliant

            var decoded5 = decoder.Decode(invalidToken, secret, verify: true);
            var decoded6 = decoder.Decode(invalidToken, secret, verify: false); // Noncompliant

            var decoded7 = decoder.Decode(invalidToken, verify: true, key: secret);
            var decoded8 = decoder.Decode(invalidToken, verify: false, key: secret); // Noncompliant

            var decoded9 = decoder.Decode(invalidToken, verify: true, key: new byte[] { 42 });
            var decoded10 = decoder.Decode(invalidToken, verify: false, key: new byte[] { 42 }); // Noncompliant

            var decoded11 = decoder.Decode(invalidToken); // Noncompliant
            var decoded12 = decoder.Decode(invalidParts); // Noncompliant

            var decoded21 = decoder.DecodeToObject(invalidToken, secret, true);
            var decoded22 = decoder.DecodeToObject(invalidToken, secret, false); // Noncompliant

            var decoded31 = decoder.DecodeToObject<UserInfo>(invalidToken, secret, true);
            var decoded32 = decoder.DecodeToObject<UserInfo>(invalidToken, secret, false); // Noncompliant
        }

        void DecodingWithCustomDecoder(CustomDecoder decoder)
        {
            var decoded1 = decoder.Decode(invalidToken, secret, true);
            var decoded2 = decoder.Decode(invalidToken, secret, false); // Noncompliant {{Use only strong cipher algorithms when verifying the signature of this JWT.}}
            var decoded2 = decoder.Decode(invalidToken, secret, ); // Noncompliant {{Use only strong cipher algorithms when verifying the signature of this JWT.}}

            var decoded3 = decoder.Decode(invalidToken, secret, verify: true);
            var decoded4 = decoder.Decode(invalidToken, secret, verify: false); // Noncompliant

            var decoded5 = decoder.Decode(invalidToken, secret, verify: true);
            var decoded6 = decoder.Decode(invalidToken, secret, verify: false); // Noncompliant

            var decoded7 = decoder.Decode(invalidToken, verify: true, key: secret);
            var decoded8 = decoder.Decode(invalidToken, verify: false, key: secret); // Noncompliant

            var decoded9 = decoder.Decode(invalidToken, verify: true, key: new byte[] { 42 });
            var decoded10 = decoder.Decode(invalidToken, verify: false, key: new byte[] { 42 }); // Noncompliant

            var decoded11 = decoder.Decode(invalidToken); // Noncompliant
            var decoded12 = decoder.Decode(invalidParts); // Noncompliant

            var decoded21 = decoder.DecodeToObject(invalidToken, secret, true);
            var decoded22 = decoder.DecodeToObject(invalidToken, secret, false); // Noncompliant

            var decoded31 = decoder.DecodeToObject<UserInfo>(invalidToken, secret, true);
            var decoded32 = decoder.DecodeToObject<UserInfo>(invalidToken, secret, false); // Noncompliant
        }

        void DecodingWithBuilder()
        {
            var decoded1 = new JwtBuilder() // Noncompliant {{Use only strong cipher algorithms when verifying the signature of this JWT.}}
              .WithSecret(secret)
              .Decode(invalidToken);

            var decoded2 = new JwtBuilder()
              .WithSecret(secret)
              .MustVerifySignature()
              .Decode(invalidToken);

            var builder1 = new JwtBuilder().WithSecret(secret);
            builder1.Decode(invalidToken); // Noncompliant

            try
            {
                if (true)
                {
                    builder1.Decode(invalidToken); // Noncompliant, tracking outside nested block
                }
            }
            finally
            {
            }

            var builder2 = builder1.MustVerifySignature();
            builder2.Decode(invalidToken);

            var builder3 = new JwtBuilder().WithSecret(secret).MustVerifySignature();
            builder3.Decode(invalidToken);

            var builder4 = (((new JwtBuilder()).WithSecret(secret)));
            builder4.Decode(invalidToken); // Noncompliant

            var builder5 = new JwtBuilder().WithSecret(secret).DoNotVerifySignature();
            builder5.Decode(invalidToken); // Noncompliant

            var decoded11 = new JwtBuilder()  // Noncompliant
                .WithSecret(secret)
                .WithVerifySignature(true)
                .MustVerifySignature()
                .DoNotVerifySignature()
                .Decode(invalidToken);

            var Decoded12 = new JwtBuilder()
                .WithSecret(secret)
                .WithVerifySignature(false)
                .DoNotVerifySignature()
                .MustVerifySignature()
                .Decode(invalidToken);

            var Decoded21 = new JwtBuilder()
                .WithSecret(secret)
                .DoNotVerifySignature()
                .WithVerifySignature(false)
                .WithVerifySignature(true)
                .Decode(invalidToken);

            var Decoded31 = new JwtBuilder()  // Noncompliant
                .WithSecret(secret)
                .MustVerifySignature()
                .WithVerifySignature(true)
                .WithVerifySignature(false)
                .Decode(invalidToken);
				
			bool verify = false;
			var Decoded32 = new JwtBuilder()
                .WithSecret(secret)
                .MustVerifySignature()
                .WithVerifySignature(verify)
                .Decode(invalidToken);
        }

        void DecodingWithBuilder_FPs(bool condition)
        {
            var builder1 = new JwtBuilder();
            Init();
            builder1.Decode(invalidToken); // Noncompliant FP, initialization in local function is not tracked

            void Init()
            {
                builder1 = builder1.WithSecret(secret).MustVerifySignature();
            }
        }

        void DecodingWithBuilder_FNs(bool condition)
        {
            var builder1 = new JwtBuilder();
            if (condition)
            {
                builder1 = builder1.WithSecret(secret);
            }
            builder1.Decode(invalidToken);//FP

            CreateBuilder("abc").Decode(invalidToken);//FP
            CreateBuilder1("abc").Decode(invalidToken);//FP
            CreateLocalBuilder().Decode(invalidToken);

            JwtBuilder CreateLocalBuilder() => new JwtBuilder().DoNotVerifySignature();
        }

        JwtBuilder CreateBuilder(string str)
        {
			if(str== string.Empty)
				return new JwtBuilder().DoNotVerifySignature();
			else
				return new JwtBuilder().MustVerifySignature();
        }
		
		JwtBuilder CreateBuilder1(string str)
        {
			return str== string.Empty ? new JwtBuilder().DoNotVerifySignature(): new JwtBuilder().MustVerifySignature();
        }
    }

    class UserInfo
    {
        string Name { get; set; }
    }

    class CustomDecoder : IJwtDecoder
    {
        public string Decode(JwtParts jwt)
        {
            throw new NotImplementedException();
        }

        public string Decode(string token)
        {
            throw new NotImplementedException();
        }

        public string Decode(string token, string key, bool verify)
        {
            throw new NotImplementedException();
        }

        public string Decode(string token, string[] keys, bool verify)
        {
            throw new NotImplementedException();
        }

        public string Decode(string token, byte[] key, bool verify)
        {
            throw new NotImplementedException();
        }

        public string Decode(string token, byte[][] keys, bool verify)
        {
            throw new NotImplementedException();
        }

        public string Decode(JwtParts jwt, byte[] key, bool verify)
        {
            throw new NotImplementedException();
        }

        public string Decode(JwtParts jwt, byte[][] keys, bool verify)
        {
            throw new NotImplementedException();
        }

        public string DecodeHeader(string token)
        {
            throw new NotImplementedException();
        }

        public T DecodeHeader<T>(JwtParts jwt)
        {
            throw new NotImplementedException();
        }

        public IDictionary<string, object> DecodeToObject(string token)
        {
            throw new NotImplementedException();
        }

        public IDictionary<string, object> DecodeToObject(string token, string key, bool verify)
        {
            throw new NotImplementedException();
        }

        public IDictionary<string, object> DecodeToObject(string token, string[] keys, bool verify)
        {
            throw new NotImplementedException();
        }

        public IDictionary<string, object> DecodeToObject(string token, byte[] key, bool verify)
        {
            throw new NotImplementedException();
        }

        public IDictionary<string, object> DecodeToObject(string token, byte[][] keys, bool verify)
        {
            throw new NotImplementedException();
        }

        public T DecodeToObject<T>(string token)
        {
            throw new NotImplementedException();
        }

        public T DecodeToObject<T>(string token, string key, bool verify)
        {
            throw new NotImplementedException();
        }

        public T DecodeToObject<T>(string token, string[] keys, bool verify)
        {
            throw new NotImplementedException();
        }

        public T DecodeToObject<T>(string token, byte[] key, bool verify)
        {
            throw new NotImplementedException();
        }

        public T DecodeToObject<T>(string token, byte[][] keys, bool verify)
        {
            throw new NotImplementedException();
        }

        public T DecodeToObject<T>(JwtParts jwt)
        {
            throw new NotImplementedException();
        }

        public T DecodeToObject<T>(JwtParts jwt, byte[] key, bool verify)
        {
            throw new NotImplementedException();
        }

        public T DecodeToObject<T>(JwtParts jwt, byte[][] keys, bool verify)
        {
            throw new NotImplementedException();
        }
    }
}
namespace Microsoft_IdentityModel_Tokens
{
    public class TokenTest
    {
        public void CreateTokenValidationParameters()
        {
            var Unsafe = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidIssuer = "ValidIssuer",
                ValidateAudience = false,
                ValidAudience = "ValidAudience",
                ValidateIssuerSigningKey = false,//Unsafe
                RequireSignedTokens = false		 //Unsafe
            };
			var safe = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidIssuer = "ValidIssuer",
                ValidateAudience = false,
                ValidAudience = "ValidAudience",
                ValidateIssuerSigningKey = true,//Safe
                RequireSignedTokens = true		//Safe
            };
        }
    }
}