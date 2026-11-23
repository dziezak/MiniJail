using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace MiniJail;

public enum Verdict { Ok, RuntimeError, SecurityViolation, TimeLimit, OutputLimit }

public sealed record JailOptions(
    string Program,
    string[] Args,
    string? StdinFile = null,
    int CpuSeconds = 2,
    int WallMs = 5000,
    long MemoryMb = 256,
    long OutputKb = 1024,
    bool Trace = false,
    IReadOnlyCollection<string>? AllowRead = null
);

public sealed record JailResult(
    Verdict Verdict, string Detail, int ExitCode, int Signal,
    double CpuSeconds, double WallSeconds, long MaxRssKb, long Syscalls,
    string Stdout, string Stderr
);

public static unsafe class Jail
{
    sealed class State { public volatile bool TimedOut; }

    public static JailResult Run(JailOptions o)
    {
        var tmp = Directory.CreateTempSubdirectory("minijail-");
        string outPath = Path.Combine(tmp.FullName, "stdout"), errPath = Path.Combine(tmp.FullName, "stderr");

        var allocated = new List<nint>();
        nint Alloc(nuint size, bool zero = true)
        {
            nint p = (nint)(zero ? NativeMemory.AllocZeroed(size) : NativeMemory.Alloc(size));
            allocated.Add(p);
            return p;
        }
        nint CStr(string s)
        {
            nint p = Marshal.StringToHGlobalAnsi(s);
            allocated.Add(p);
            return p;
        }

        int inFd = -1, outFd = -1, errFd = -1;
        try
        {
            inFd = OpenFd(o.StdinFile ?? "/dev/null", Native.O_RDONLY, 0);
            outFd = OpenFd(outPath, Native.O_WRONLY | Native.O_CREAT | Native.O_TRUNC, 0x180);
            errFd = OpenFd(errPath, Native.O_WRONLY | Native.O_CREAT | Native.O_TRUNC, 0x180);

            nint path = CStr(o.Program);
            nint* argv = (nint*)Alloc((nuint)((o.Args.Length + 2) * sizeof(nint)));
            argv[0] = path;
            for (int i = 0; i < o.Args.Length; i++) argv[i + 1] = CStr(o.Args[i]);
            nint* envp = (nint*)Alloc((nuint)sizeof(nint));

            const int maxLimits = 5;
            Limit* limits = (Limit*)Alloc((nuint)(sizeof(Limit) * maxLimits));
            int nLimits = 0;
            limits[nLimits++] = new Limit { Resource = Native.RLIMIT_CPU, Cur = (ulong)o.CpuSeconds, Max = (ulong)o.CpuSeconds + 1 };
            limits[nLimits++] = new Limit { Resource = Native.RLIMIT_AS, Cur = (ulong)o.MemoryMb << 20, Max = (ulong)o.MemoryMb << 20 };
            limits[nLimits++] = new Limit { Resource = Native.RLIMIT_FSIZE, Cur = (ulong)o.OutputKb << 10, Max = (ulong)o.OutputKb << 10 };
            limits[nLimits++] = new Limit { Resource = Native.RLIMIT_CORE, Cur = 0, Max = 0 };
            limits[nLimits++] = new Limit { Resource = Native.RLIMIT_NOFILE, Cur = 16, Max = 16 };

            byte* rusage = (byte*)Alloc(256);
            var policy = new Policy(o.AllowRead);
            var state = new State();

            Marshal.PrelinkAll(typeof(Native)); // powiazanie wszystkich libc z góry
            // wymuszam kompilację JIT metody ChildAfterFork
            RuntimeHelpers.PrepareMethod(typeof(Jail).GetMethod(nameof(ChildAfterFork), BindingFlags.NonPublic | BindingFlags.Static)!.MethodHandle); 
            GC.TryStartNoGCRegion(8 * 1024 * 1024); // basiclly no GC

            var wall = Stopwatch.StartNew();
            int pid = Native.fork();
            if (pid == 0)
            {
                ChildAfterFork(inFd, outFd, errFd, limits, nLimits, path, argv, envp);
                Native._exit(127);
            }

            try
            {
                GC.EndNoGCRegion();
            }
            catch (InvalidOperationException)
            {
               //nice  
            }
            
            if (pid < 0) // cos sie popsulo
            {
                throw new InvalidOperationException("fork() nie powiódł się");
            }

            Native.close(inFd); 
            Native.close(outFd); 
            Native.close(errFd);
            inFd = outFd = errFd = -1;

            using var timer = new Timer(_ => { state.TimedOut = true; Native.kill(pid, Native.SIGKILL); },
                                        null, o.WallMs, Timeout.Infinite);

            long syscalls = 0;
            int status;
            WaitChild(pid, &status, rusage);
            if (!Native.WIFSTOPPED(status))
            {
                string why = Native.WIFEXITED(status)
                    ? $"dziecko zakończyło się przed exec, kod {Native.WEXITSTATUS(status)} (120-122 = błąd przygotowania, 127 = execve nie powiodło się)"
                    : $"dziecko zginęło przed exec, sygnał {Native.WTERMSIG(status)}";
                return Finish(Verdict.RuntimeError, why, -1, 0);
            }

            Native.ptrace(Native.PTRACE_SETOPTIONS, pid, 0, (nint)(Native.PTRACE_O_TRACESYSGOOD | Native.PTRACE_O_EXITKILL));

            string? violation = null;
            int exitCode = 0, termSig = 0;
            byte* info = stackalloc byte[128];

            Native.ptrace(Native.PTRACE_SYSCALL, pid, 0, 0);
            while (true)
            {
                WaitChild(pid, &status, rusage);

                if (Native.WIFEXITED(status))
                {
                    exitCode = Native.WEXITSTATUS(status); 
                    break;
                }

                if (Native.WIFSIGNALED(status))
                {
                    termSig = Native.WTERMSIG(status); 
                    break;
                }

                int sig = Native.WSTOPSIG(status);
                int inject = 0;

                if (sig == (Native.SIGTRAP | 0x80))
                {
                    Native.ptrace(Native.PTRACE_GET_SYSCALL_INFO, pid, 128, (nint)info);
                    if (info[0] == 1 && violation is null)
                    {
                        syscalls++;
                        uint arch = *(uint*)(info + 4);
                        ulong nr = *(ulong*)(info + 24); // number syscalla
                        var args = new ReadOnlySpan<ulong>(info + 32, 6);

                        string? reason = policy.Check(pid, arch, nr, args);
                        if (o.Trace)
                        {
                            Console.Error.WriteLine($"  [syscall] {Policy.NameOf(nr),-16}({args[0]:x}, {args[1]:x}, {args[2]:x})  {(reason is null ? "ALLOW" : "DENY: " + reason)}");
                        }

                        if (reason is not null)
                        {
                            violation = reason;
                            Native.kill(pid, Native.SIGKILL);
                            continue;
                        }
                    }
                }
                else
                {
                    inject = sig;
                }
                Native.ptrace(Native.PTRACE_SYSCALL, pid, 0, inject);
            }
            wall.Stop();

            if (violation is not null) return Finish(Verdict.SecurityViolation, violation, exitCode, termSig);
            if (state.TimedOut) return Finish(Verdict.TimeLimit, $"przekroczono limit czasu ściennego ({o.WallMs} ms)", exitCode, termSig);
            if (termSig == Native.SIGXCPU || termSig == Native.SIGKILL) return Finish(Verdict.TimeLimit, $"przekroczono limit czasu CPU ({o.CpuSeconds} s)", exitCode, termSig);
            if (termSig == Native.SIGXFSZ) return Finish(Verdict.OutputLimit, $"przekroczono limit wyjścia ({o.OutputKb} KB)", exitCode, termSig);
            if (termSig != 0) return Finish(Verdict.RuntimeError, $"program zabity sygnałem {termSig}" + (termSig == Native.SIGSEGV ? " (SIGSEGV — błąd pamięci)" : ""), exitCode, termSig);
            if (exitCode != 0) return Finish(Verdict.RuntimeError, $"kod wyjścia {exitCode}", exitCode, termSig);
            return Finish(Verdict.Ok, "", 0, 0);

            JailResult Finish(Verdict v, string detail, int code, int sigNo)
            {
                double Sec(int off) => *(long*)(rusage + off) + *(long*)(rusage + off + 8) / 1e6;
                return new JailResult(v, detail, code, sigNo, Sec(0) + Sec(16), wall.Elapsed.TotalSeconds,
                                      *(long*)(rusage + 32), syscalls,
                                      ReadHead(outPath), ReadHead(errPath));
            }
        }
        finally
        {
            foreach (int fd in new[] { inFd, outFd, errFd })
            {
                if (fd >= 0)
                {
                    Native.close(fd);
                }
            }
            foreach (var p in allocated)
            {
                NativeMemory.Free((void*)p);
            }

            try
            {
                tmp.Delete(recursive: true);
            }
            catch
            {
               //nope 
            }
        }
    }

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.AggressiveOptimization)]
    static void ChildAfterFork(int inFd, int outFd, int errFd, Limit* limits, int nLimits, nint path, nint* argv, nint* envp)
    {
        //podepnij standardowe strumenie do otawrtych plikow Runtime rodzica
        if (Native.dup2(inFd, 0) < 0 || Native.dup2(outFd, 1) < 0 || Native.dup2(errFd, 2) < 0)
        {
            Native._exit(120);
        }
        Native.close_range(3, uint.MaxValue, 0);

        for (int i = 0; i < nLimits; i++)
        {
            //limit samego siebie na czas CPU
            if (Native.setrlimit(limits[i].Resource, &limits[i].Cur) != 0)
            {
                Native._exit(121);
            }
        }

        //zgłaszam do jądra mojego rodzica
        if (Native.ptrace(Native.PTRACE_TRACEME, 0, 0, 0) != 0)
        {
            Native._exit(122);
        }

        // nadpisz cały process .Net kodem binarnego programu który dostałeś 
        Native.execve(path, argv, envp);
        Native._exit(127);
    }

    static int WaitChild(int pid, int* status, byte* rusage)
    {
        while (true)
        {
            int r = Native.wait4(pid, status, Native.__WALL, rusage);
            if (r >= 0) return r;
            int errno = Marshal.GetLastSystemError();
            if (errno != 4 /* EINTR */)
            {
                throw new InvalidOperationException($"wait4 errno={errno}");
            }
        }
    }

    static int OpenFd(string file, int flags, int mode)
    {
        nint p = Marshal.StringToHGlobalAnsi(file);
        try
        {
            int fd = Native.open(p, flags, mode);
            if (fd < 0)
            {
                throw new IOException($"open({file}) nie powiodło się, errno={Marshal.GetLastSystemError()}");
            }

            return fd;
        }
        finally
        {
            Marshal.FreeHGlobal(p);
        }
    }

    static string ReadHead(string file)
    {
        using var fs = File.OpenRead(file);
        var buf = new byte[2048];
        int n = fs.Read(buf, 0, buf.Length);
        var s = System.Text.Encoding.UTF8.GetString(buf, 0, n);
        return fs.Length > n ? s + $"\n… (ucięto, razem {fs.Length} B)" : s;
    }
}