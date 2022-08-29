using Bryllite.Cryptography.Scrypt;

namespace Replicon.Cryptography.SCrypt
{
    class KeyDerivationFunction : IKeyDerivationFunction
    {
        public byte[] DeriveKey(byte[] password, byte[] salt, ulong N, uint r, uint p, uint derivedKeyLengthBytes)
        {
            return Scrypt.CryptoScrypt(password, salt, (int)N, (int)r, (int)p, (int)derivedKeyLengthBytes);
        }
    }
}
