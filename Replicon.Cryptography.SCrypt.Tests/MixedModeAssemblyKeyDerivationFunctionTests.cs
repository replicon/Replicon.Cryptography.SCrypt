using NUnit.Framework;

namespace Replicon.Cryptography.SCrypt.Tests
{
    [TestFixture]
    public class MixedModeAssemblyKeyDerivationFunctionTests : KeyDerivationFunctionTests
    {
        protected override IKeyDerivationFunction Create()
        {
            return Factory.CreateNativeKeyDerivationFunction();
        }
    }
}
