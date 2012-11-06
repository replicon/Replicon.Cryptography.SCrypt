#pragma once

using namespace System;

namespace SCryptMMA
{
    public ref class SaltParseException : public Exception
    {
    internal:
        SaltParseException(String^);
    };
}

