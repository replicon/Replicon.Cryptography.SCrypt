using System;

namespace Replicon.Cryptography.SCrypt
{
    /// <summary>
    /// Exception thrown when a SCrypt salt string is unparsable.
    /// </summary>
    [Serializable]
    public class SaltParseException : Exception
    {
        internal SaltParseException(string message)
            : base(message)
        {
        }
    }
}
