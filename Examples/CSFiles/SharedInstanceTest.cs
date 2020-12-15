using System.ComponentModel.Composition;

namespace Tests.Diagnostics
{
    [PartCreationPolicy(CreationPolicy.Shared)]
    class SharedClass { }

    [System.ComponentModel.Composition.PartCreationPolicy(CreationPolicy.NonShared)]
    class NonSharedClass { }

    [PartCreationPolicy(CreationPolicy.Any)]
    class AnyClass { }

    [PartCreationPolicy(Foo)] // Error [CS0103] - Foo doesn't exist
    class InvalidAttrParameter { }

    [PartCreationPolicy()] // Error [CS7036]
    class NoAttrParameter { }

    class NoAttr { }

    class Program
    {
        public void Bar()
        {
            new SharedClass();//NonCompliant
            new NonSharedClass();
            new AnyClass();
            new InvalidAttrParameter();
            new NoAttrParameter();
            new NoAttr();
        }
    }
}
