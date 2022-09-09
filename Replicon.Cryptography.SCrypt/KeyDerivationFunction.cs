
namespace Replicon.Cryptography.SCrypt
{
    class KeyDerivationFunction : IKeyDerivationFunction
    {
        public byte[] DeriveKey(byte[] password, byte[] salt, ulong N, uint r, uint p, uint derivedKeyLengthBytes)
        {
          // FIXME: Use https://www.nuget.org/packages/Scrypt.NET/ once PR #11 is released in https://github.com/viniciuschiele/Scrypt
          return ScryptEncoder.CryptoScrypt(password, salt, (int)N, (int)r, (int)p, (int)derivedKeyLengthBytes);
        }
    }
}
