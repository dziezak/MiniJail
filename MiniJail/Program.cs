using System.Runtime.InteropServices;
using MiniJail;

static int Usage()
{
    Console.Error.WriteLine("Użycie: minijail [--stdin F] [--cpu S] [--wall MS] [--mem MB] [--out KB] [--allow-read P]... [--trace] -- <program> [args...]");
    return 10;
}

if (!OperatingSystem.IsLinux() ||
    RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
{
    Console.Error.WriteLine("MiniJail działa tylko na Linux x86_64 lub ARM64.");
    return 10;
}

string? stdin = null; int cpu = 2, wall = 5000; long mem = 256, outKb = 1024; bool trace = false;
var allow = new List<string>();
int idx = 0;
for (; idx < args.Length && args[idx] != "--"; idx++)
{
    string Next() => idx + 1 < args.Length ? args[++idx] : throw new ArgumentException($"brak wartości dla {args[idx]}");
    try
    {
        switch (args[idx])
        {
            case "--stdin": stdin = Next(); break;
            case "--cpu": cpu = int.Parse(Next()); break;
            case "--wall": wall = int.Parse(Next()); break;
            case "--mem": mem = long.Parse(Next()); break;
            case "--out": outKb = long.Parse(Next()); break;
            case "--allow-read": allow.Add(Next()); break;
            case "--trace": trace = true; break;
            default: return Usage();
        }
    }
    catch (Exception e) when (e is ArgumentException or FormatException)
    {
        Console.Error.WriteLine(e.Message);
        return Usage();
    }
}
if (idx >= args.Length - 1) return Usage();

string program = Path.GetFullPath(args[idx + 1]);
if (!File.Exists(program))
{
    Console.Error.WriteLine($"Nie ma pliku: {program}");
    return 10;
}

var result = Jail.Run(new JailOptions(program, args[(idx + 2)..], stdin, cpu, wall, mem, outKb, trace, allow));

Console.WriteLine($"verdict : {result.Verdict}{(result.Detail == "" ? "" : " — " + result.Detail)}");
Console.WriteLine($"exit    : {(result.Signal != 0 ? $"sygnał {result.Signal}" : $"kod {result.ExitCode}")}");
Console.WriteLine($"cpu     : {result.CpuSeconds:F3} s   wall: {result.WallSeconds:F3} s   maxrss: {result.MaxRssKb} KB   syscalli: {result.Syscalls}");
if (result.Stdout.Length > 0) Console.WriteLine($"stdout  :\n{Indent(result.Stdout)}");
if (result.Stderr.Length > 0) Console.WriteLine($"stderr  :\n{Indent(result.Stderr)}");

return result.Verdict switch
{
    Verdict.Ok => 0,
    Verdict.RuntimeError => 1,
    Verdict.SecurityViolation => 2,
    Verdict.TimeLimit => 3,
    Verdict.OutputLimit => 4,
    _ => 10,
};

static string Indent(string s) => "    " + s.TrimEnd().Replace("\n", "\n    ");