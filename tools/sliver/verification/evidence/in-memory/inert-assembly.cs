// Lab-authored inert .NET assembly for bounded Sliver execute-assembly testing.
// It performs no networking, file/registry I/O, process creation, persistence,
// collection, or system modification; it only writes a fixed string to stdout.

using System;

public static class SliverInMemoryMarker
{
    public static int Main(string[] args)
    {
        Console.WriteLine("SLIVER_IN_MEMORY_INERT_MARKER");
        return 0;
    }
}
