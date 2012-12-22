#pragma once

using namespace System;

namespace Replicon
{
    namespace Cryptography
    {
        namespace SCrypt
        {
            namespace MMA
            {
                public ref class SCrypt sealed : public Replicon::Cryptography::SCrypt::IKeyDerivationFunction
                {
                public:
                    SCrypt();
                    virtual array<Byte>^ DeriveKey(array<Byte>^ password, array<Byte>^ salt, UInt64 N, UInt32 r, UInt32 p, UInt32 derivedKeyLengthBytes);
                };
            }
        }
    }
}

