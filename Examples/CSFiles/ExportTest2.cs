using System;
using System.ComponentModel.Composition;

namespace Classes
{
    [Export(typeof(IDisposable))]
    partial class Exported
    {
    }

    [Export(typeof(IDisposable))] // Noncompliant
    partial class NotExported
    {
    }
}


namespace Classes
{
    partial class Exported : IDisposable
    {
        public void Dispose() { }
    }

    partial class NotExported
    {
    }
}