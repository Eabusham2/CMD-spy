using System.Collections.Generic;
using System.Text;

namespace CmdSpy.Core.Analysis;

/// <summary>Splits a command string into the individual commands it runs.</summary>
public static class StatementSplitter
{
    /// <summary>cmd.exe: splits on &amp;, &amp;&amp;, ||, | outside quotes; ^ escapes the next character.</summary>
    public static List<string> SplitCmd(string text)
    {
        var parts = new List<string>();
        var sb = new StringBuilder();
        bool inQuotes = false;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '^' && !inQuotes && i + 1 < text.Length)
            {
                sb.Append(text[i + 1]);
                i++;
                continue;
            }
            if (c == '"') inQuotes = !inQuotes;
            if (!inQuotes && (c == '&' || c == '|'))
            {
                Flush(parts, sb);
                if (i + 1 < text.Length && text[i + 1] == c) i++;   // && or ||
                continue;
            }
            sb.Append(c);
        }
        Flush(parts, sb);
        return parts;
    }

    /// <summary>PowerShell: splits statements on ; and newlines outside quotes, braces and parentheses.</summary>
    public static List<string> SplitPowerShell(string text) => Split(text, pipeline: false);

    /// <summary>PowerShell: splits one statement into its pipeline elements.</summary>
    public static List<string> SplitPipeline(string statement) => Split(statement, pipeline: true);

    private static List<string> Split(string text, bool pipeline)
    {
        var parts = new List<string>();
        var sb = new StringBuilder();
        char quote = '\0';
        int depth = 0;
        for (int i = 0; i < text.Length; i++)
        {
            char c = text[i];
            if (c == '`' && i + 1 < text.Length)
            {
                sb.Append(c).Append(text[i + 1]);
                i++;
                continue;
            }
            if (quote != '\0')
            {
                if (c == quote) quote = '\0';
                sb.Append(c);
                continue;
            }
            switch (c)
            {
                case '\'':
                case '"':
                    quote = c;
                    sb.Append(c);
                    continue;
                case '{':
                case '(':
                    depth++;
                    sb.Append(c);
                    continue;
                case '}':
                case ')':
                    if (depth > 0) depth--;
                    sb.Append(c);
                    continue;
            }
            if (depth == 0)
            {
                bool split = pipeline
                    ? c == '|' && !(i + 1 < text.Length && text[i + 1] == '|')
                    : c == ';' || c == '\n' || c == '\r';
                if (split)
                {
                    Flush(parts, sb);
                    continue;
                }
            }
            sb.Append(c);
        }
        Flush(parts, sb);
        return parts;
    }

    private static void Flush(List<string> parts, StringBuilder sb)
    {
        var s = sb.ToString().Trim();
        if (s.Length > 0) parts.Add(s);
        sb.Clear();
    }
}
