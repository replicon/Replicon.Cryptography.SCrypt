#include "SaltParseException.h"

namespace SCryptMMA
{
    SaltParseException::SaltParseException(String^ message)
        : Exception(message)
    {
    }
}