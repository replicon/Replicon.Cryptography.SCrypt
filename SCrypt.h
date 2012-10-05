#pragma once

#include "crypto_scrypt.h"

using namespace System;
using namespace System::Text;

namespace SCrypt
{
    public ref class SCrypt
    {
    public:

        static String^ GenerateSalt()
        {
            return GenerateSalt(8, 16384, 8, 1);
        }

        static String^ GenerateSalt(UInt32 saltLengthBytes, UInt64 N, UInt32 r, UInt32 p)
        {
            array<Byte>^ salt = gcnew array<Byte>(saltLengthBytes);
            System::Security::Cryptography::RandomNumberGenerator::Create()->GetBytes(salt);

            StringBuilder^ builder = gcnew StringBuilder();
            builder->Append("$scrypt$");
            builder->Append(N);
            builder->Append("$");
            builder->Append(r);
            builder->Append("$");
            builder->Append(p);
            builder->Append("$");
            builder->Append(Convert::ToBase64String(salt));
            return builder->ToString();
        }

        static array<Byte>^ DerivePassword(array<Byte>^ password, array<Byte>^ salt, UInt64 N, UInt32 r, UInt32 p, UInt32 derivedPasswordLengthBytes)
        {
            pin_ptr<Byte> password_ptr = &password[0];
            pin_ptr<Byte> salt_ptr = &salt[0];

            array<Byte>^ derived_password = gcnew array<Byte>(derivedPasswordLengthBytes);
            pin_ptr<Byte> derived_password_ptr = &derived_password[0];

            crypto_scrypt(
                password_ptr, password->Length,
                salt_ptr, salt->Length,
                N, r, p,
                derived_password_ptr, derived_password->Length);

            return derived_password;
        }
    };
}
