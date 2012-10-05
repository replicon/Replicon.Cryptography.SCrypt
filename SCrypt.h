#pragma once

using namespace System;

namespace SCrypt
{
    public ref class SCrypt
    {
    public:
        static String^ GenerateSalt();
        static String^ GenerateSalt(UInt32 saltLengthBytes, UInt64 N, UInt32 r, UInt32 p);

        static array<Byte>^ DerivePassword(array<Byte>^ password, array<Byte>^ salt, UInt64 N, UInt32 r, UInt32 p, UInt32 derivedPasswordLengthBytes);
    };
}
