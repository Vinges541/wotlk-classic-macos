// Mutex ownership is thread-affine. Keep acquire/release on the synchronous
// entry thread while async login/process work runs to completion.
static class SingleInstance
{
    public static int Run(string name, Func<Task<int>> action)
    {
        using var mutex = new Mutex(false, name);
        bool acquired;
        try { acquired = mutex.WaitOne(0); }
        catch (AbandonedMutexException) { acquired = true; }
        if (!acquired) throw new InvalidOperationException("Another launcher is running.");
        try { return action().GetAwaiter().GetResult(); }
        finally { mutex.ReleaseMutex(); }
    }

    public static void SelfTest()
    {
        string name = "WotLKClassicHermesLockTest-" + Guid.NewGuid();
        int owner = Environment.CurrentManagedThreadId;
        int result = Run(name, async () =>
        {
            await Task.Yield();
            if (Environment.CurrentManagedThreadId == owner)
                throw new InvalidOperationException("Test did not switch threads.");
            using var contender = new Mutex(false, name);
            if (contender.WaitOne(0))
            {
                contender.ReleaseMutex();
                throw new InvalidOperationException("Concurrent launcher was not excluded.");
            }
            return 7;
        });
        if (result != 7) throw new InvalidOperationException("Exit code was not preserved.");
        try
        {
            Run(name, async () =>
            {
                await Task.Yield();
                throw new FormatException("Synthetic async failure");
            });
            throw new InvalidOperationException("Async failure was lost.");
        }
        catch (FormatException) { }
        // Reacquisition from a different thread proves both paths released the
        // mutex rather than relying on recursive acquisition by the same owner.
        if (Task.Run(() => Run(name, () => Task.FromResult(9))).GetAwaiter().GetResult() != 9)
            throw new InvalidOperationException("Lock was not released.");
    }
}
