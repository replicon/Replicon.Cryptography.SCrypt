#include "SCrypt.h"
#include "crypto_scrypt.h"

using namespace System;
using namespace System::Text;

namespace Replicon
{
    namespace Cryptography
    {
        namespace SCrypt
        {
            namespace MMA
            {
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
                        throw gcnew InvalidOperationException("crypto_scrypt internal error");

                    return derived_key;
                }
            }
        }
    }
}
