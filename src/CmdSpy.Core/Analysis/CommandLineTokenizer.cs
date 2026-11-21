using System.Collections.Generic;
using System.Text;

namespace CmdSpy.Core.Analysis;

/// <summary>A command-line argument plus where it sits in the original text.</summary>
public readonly record struct CommandToken(string Value, int Start, int End);

/// <summary>
/// Splits a Windows command line exactly the way programs receive it
/// (CommandLineToArgvW / the MSVC runtime rules), remembering each argument's
/// position so the raw text after a switch such as <c>/c</c> can be recovered.
/// </summary>
public static class CommandLineTokenizer
{
    public static List<CommandToken> Tokenize(string? commandLine)
    {
        var tokens = new List<CommandToken>();
        if (string.IsNullOrEmpty(commandLine)) return tokens;

        var s = commandLine;
        int i = 0, n = s.Length;
        bool first = true;

        while (i < n)
        {
            while (i < n && IsSpace(s[i])) i++;
            if (i >= n) break;

            int start = i;
            var sb = new StringBuilder();

            if (first)
            {
                // The program name: quoted up to the next quote, otherwise up to
                // whitespace. Backslashes are never escapes here.
                if (s[i] == '"')
                {
                    i++;
                    while (i < n && s[i] != '"') sb.Append(s[i++]);
                    if (i < n) i++;
                }
                while (i < n && !IsSpace(s[i])) sb.Append(s[i++]);
                tokens.Add(new CommandToken(sb.ToString(), start, i));
                first = false;
                continue;
            }

            bool inQuotes = false;
            while (i < n)
            {
                char c = s[i];
                if (c == '\\')
                {
                    int count = 0;
                    while (i < n && s[i] == '\\') { count++; i++; }
                    if (i < n && s[i] == '"')
                    {
                        sb.Append('\\', count / 2);
                        if (count % 2 == 1) { sb.Append('"'); i++; }
                    }
                    else
                    {
                        sb.Append('\\', count);
                    }
                    continue;
                }
                if (c == '"')
                {
                    if (inQuotes && i + 1 < n && s[i + 1] == '"')
                    {
                        sb.Append('"');
                        i += 2;
                        continue;
                    }
                    inQuotes = !inQuotes;
                    i++;
                    continue;
                }
                if (!inQuotes && IsSpace(c)) break;
                sb.Append(c);
                i++;
            }
            tokens.Add(new CommandToken(sb.ToString(), start, i));
        }
        return tokens;
    }

    /// <summary>The untouched text that follows token <paramref name="index"/>.</summary>
    public static string RawAfter(string commandLine, IReadOnlyList<CommandToken> tokens, int index)
    {
        if (index < 0 || index >= tokens.Count) return "";
        var end = tokens[index].End;
        return end >= commandLine.Length ? "" : commandLine[end..].TrimStart(' ', '\t');
    }

    /// <summary>File name of a program token: <c>"C:\Windows\System32\cmd.exe"</c> → <c>cmd.exe</c>.</summary>
    public static string FileNameOf(string programToken)
    {
        var t = programToken.Trim().Trim('"');
        var slash = t.LastIndexOfAny(new[] { '\\', '/' });
        return slash >= 0 ? t[(slash + 1)..] : t;
    }

    private static bool IsSpace(char c) => c == ' ' || c == '\t';
}
