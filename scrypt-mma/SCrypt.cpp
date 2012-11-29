#include "SCrypt.h"
#include "SaltParseException.h"
#include "crypto_scrypt.h"

using namespace System;
using namespace System::Text;

namespace SCryptMMA
{
    String^ SCrypt::GenerateSalt()
    {
        return GenerateSalt(16, 16384, 8, 1, 32);
    }

    String^ SCrypt::GenerateSalt(UInt32 saltLengthBytes, UInt64 N, UInt32 r, UInt32 p, UInt32 hashLengthBytes)
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
        builder->Append(hashLengthBytes);
        builder->Append("$");
        builder->Append(Convert::ToBase64String(salt));
        builder->Append("$");
        return builder->ToString();
    }

    String^ SCrypt::HashPassword(String^ password)
    {
        return HashPassword(password, GenerateSalt());
    }

    String^ SCrypt::HashPassword(String^ password, String^ salt)
    {
        array<String^>^ saltComponents = salt->Split('$');
        if (saltComponents->Length != 8)
            throw gcnew SaltParseException("Expected 8 dollar-sign ($) delimited salt components");
        else if (saltComponents[0] != "" || saltComponents[1] != "scrypt")
            throw gcnew SaltParseException("Expected $scrypt$");

        UInt64 N;
        UInt32 r;
        UInt32 p;
        UInt32 hashLengthBytes;

        if (!UInt64::TryParse(saltComponents[2], N))
            throw gcnew SaltParseException("Failed to parse N parameter");
        else if (!UInt32::TryParse(saltComponents[3], r))
            throw gcnew SaltParseException("Failed to parse r parameter");
        else if (!UInt32::TryParse(saltComponents[4], p))
            throw gcnew SaltParseException("Failed to parse p parameter");
        else if (!UInt32::TryParse(saltComponents[5], hashLengthBytes))
            throw gcnew SaltParseException("Failed to parse hashLengthBytes parameter");

        array<Byte>^ salt_data = Convert::FromBase64String(saltComponents[6]);
        array<Byte>^ password_data = System::Text::Encoding::UTF8->GetBytes(password);
        array<Byte>^ hash_data = DeriveKey(password_data, salt_data, N, r, p, hashLengthBytes);

        return salt->Substring(0, salt->LastIndexOf('$') + 1) + Convert::ToBase64String(hash_data);
    }

    bool SCrypt::Verify(String^ password, String^ hash)
    {
        return hash == HashPassword(password, hash);
    }

    array<Byte>^ SCrypt::DeriveKey(array<Byte>^ password, array<Byte>^ salt, UInt64 N, UInt32 r, UInt32 p, UInt32 derivedKeyLengthBytes)
    {
        // Known issue: N=1 causes crash in crypto_scrypt.  At least we can provide a directed error message for this
        // case until it's fixed.
        if (N == 1)
            throw gcnew Exception("scrypt-mma crashes when using N=1, try using a different value or dig into the code and help fix this crash and remove this error");

        pin_ptr<uint8_t> password_ptr = &password[0];
        pin_ptr<uint8_t> salt_ptr = &salt[0];

        array<Byte>^ derived_key = gcnew array<Byte>(derivedKeyLengthBytes);
        pin_ptr<uint8_t> derived_key_ptr = &derived_key[0];

        int crypto_error = crypto_scrypt(
            password_ptr, password->Length,
            salt_ptr, salt->Length,
            N, r, p,
            derived_key_ptr, derived_key->Length);

        if (crypto_error != 0)
            throw gcnew System::InvalidOperationException("crypto_scrypt internal error");

        return derived_key;
    }
}
