#include "SaltParseException.h"

namespace Replicon
{
    namespace Cryptography
    {
        namespace SCrypt
        {
            namespace MMA
            {
                SaltParseException::SaltParseException(String^ message)
                    : Exception(message)
                {
                }
            }
        }
    }
}
