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
                public ref class SaltParseException : public Exception
                {
                internal:
                    SaltParseException(String^);
                };
            }
        }
    }
}
