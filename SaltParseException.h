#pragma once

using namespace System;

namespace SCrypt
{
    public ref class SaltParseException : public Exception
    {
    internal:
        SaltParseException(String^);
    };
}

