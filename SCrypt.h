#pragma once

#include "crypto_scrypt.h"

namespace SCrypt
{
    public ref class SCrypt
    {
    public:
        static array<System::Byte>^ DerivePassword(array<System::Byte>^ password, array<System::Byte>^ salt, System::UInt64 N, System::UInt32 r, System::UInt32 p, System::UInt32 derivedPasswordLength)
        {
            pin_ptr<System::Byte> password_ptr = &password[0];
            pin_ptr<System::Byte> salt_ptr = &salt[0];

            array<System::Byte>^ derived_password = gcnew array<System::Byte>(derivedPasswordLength);
            pin_ptr<System::Byte> derived_password_ptr = &derived_password[0];

            crypto_scrypt(
                password_ptr, password->Length,
                salt_ptr, salt->Length,
                N, r, p,
                derived_password_ptr, derived_password->Length);

            return derived_password;
        }
    };
}