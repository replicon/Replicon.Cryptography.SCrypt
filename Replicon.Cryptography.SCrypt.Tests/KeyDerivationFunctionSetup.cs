using NUnit.Framework;
using Replicon.Cryptography.SCrypt.Tests;

namespace Replicon.Cryptography.SCrypt.Tests
{
    [TestFixture]
    public class KeyDerivationFunctionSetup: KeyDerivationFunctionTests
    {
        protected override IKeyDerivationFunction Create()
        {
            return Factory.CreateKeyDerivationFunction();
        }
    }
}
