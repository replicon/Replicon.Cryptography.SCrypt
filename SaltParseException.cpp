#include "SaltParseException.h"

namespace SCrypt
{
    SaltParseException::SaltParseException(String^ message)
        : Exception(message)
    {
    }
}