using System.Text.Json;

namespace IPV6Shutdown
{
    /// <summary>
    /// Estado original da máquina gravado antes da primeira alteração, para a reversão ser fiel.
    /// Serialização manual (sem reflexão) por causa do Native AOT.
    /// </summary>
    internal sealed class OriginalState
    {
        /// <summary>false quando a máquina já tinha sido alterada por uma versão antiga (sem snapshot).</summary>
        public bool OriginalKnown { get; set; } = true;
        public string Mode { get; set; } = "standard";
        public List<string> DisabledBindings { get; set; } = [];
        public string? IpHelperStartType { get; set; }
        public bool IpHelperWasRunning { get; set; }
        public bool DisabledComponentsPresent { get; set; }
        public int DisabledComponentsValue { get; set; }
        public Dictionary<string, string> Tunnels { get; set; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> CustomProtect { get; set; } = [];
        public DateTime? RegistryWrittenUtc { get; set; }

        internal static string DefaultPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "IPV6Shutdown", "state.json");

        internal string ToJson()
        {
            using var stream = new MemoryStream();
            using (var w = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            {
                w.WriteStartObject();
                w.WriteBoolean("originalKnown", OriginalKnown);
                w.WriteString("mode", Mode);
                WriteArray(w, "disabledBindings", DisabledBindings);
                if (IpHelperStartType is null) w.WriteNull("ipHelperStartType");
                else w.WriteString("ipHelperStartType", IpHelperStartType);
                w.WriteBoolean("ipHelperWasRunning", IpHelperWasRunning);
                w.WriteBoolean("disabledComponentsPresent", DisabledComponentsPresent);
                w.WriteNumber("disabledComponentsValue", DisabledComponentsValue);
                w.WriteStartObject("tunnels");
                foreach ((string key, string value) in Tunnels)
                    w.WriteString(key, value);
                w.WriteEndObject();
                WriteArray(w, "customProtect", CustomProtect);
                if (RegistryWrittenUtc is null) w.WriteNull("registryWrittenUtc");
                else w.WriteString("registryWrittenUtc", RegistryWrittenUtc.Value.ToString("O"));
                w.WriteEndObject();
            }
            return System.Text.Encoding.UTF8.GetString(stream.ToArray());
        }

        internal static OriginalState? FromJson(string json)
        {
            try
            {
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement r = doc.RootElement;
                if (r.ValueKind != JsonValueKind.Object)
                    return null;

                var s = new OriginalState();
                if (r.TryGetProperty("originalKnown", out JsonElement ok) && ok.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    s.OriginalKnown = ok.GetBoolean();
                if (r.TryGetProperty("mode", out JsonElement mode) && mode.ValueKind == JsonValueKind.String)
                    s.Mode = mode.GetString() ?? "standard";
                s.DisabledBindings = ReadArray(r, "disabledBindings");
                s.CustomProtect = ReadArray(r, "customProtect");
                if (r.TryGetProperty("ipHelperStartType", out JsonElement st) && st.ValueKind == JsonValueKind.String)
                    s.IpHelperStartType = st.GetString();
                if (r.TryGetProperty("ipHelperWasRunning", out JsonElement run) && run.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    s.IpHelperWasRunning = run.GetBoolean();
                if (r.TryGetProperty("disabledComponentsPresent", out JsonElement dcp) && dcp.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    s.DisabledComponentsPresent = dcp.GetBoolean();
                if (r.TryGetProperty("disabledComponentsValue", out JsonElement dcv) && dcv.TryGetInt32(out int v))
                    s.DisabledComponentsValue = v;
                if (r.TryGetProperty("tunnels", out JsonElement tunnels) && tunnels.ValueKind == JsonValueKind.Object)
                {
                    foreach (JsonProperty p in tunnels.EnumerateObject())
                    {
                        if (p.Value.ValueKind == JsonValueKind.String && p.Value.GetString() is { } value)
                            s.Tunnels[p.Name] = value;
                    }
                }
                if (r.TryGetProperty("registryWrittenUtc", out JsonElement rw) && rw.ValueKind == JsonValueKind.String
                    && DateTime.TryParse(rw.GetString(), null, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime when))
                    s.RegistryWrittenUtc = when.ToUniversalTime();
                return s;
            }
            catch (JsonException)
            {
                return null;
            }
        }

        internal static OriginalState? Load(string? path = null)
        {
            path ??= DefaultPath;
            try
            {
                return File.Exists(path) ? FromJson(File.ReadAllText(path)) : null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return null;
            }
        }

        internal void Save(string? path = null)
        {
            path ??= DefaultPath;
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, ToJson());
            File.Move(tmp, path, overwrite: true);
        }

        internal static void Delete(string? path = null)
        {
            path ??= DefaultPath;
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
                string? dir = Path.GetDirectoryName(path);
                if (dir is not null && Directory.Exists(dir) && !Directory.EnumerateFileSystemEntries(dir).Any())
                    Directory.Delete(dir);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }

        private static void WriteArray(Utf8JsonWriter w, string name, IEnumerable<string> items)
        {
            w.WriteStartArray(name);
            foreach (string item in items)
                w.WriteStringValue(item);
            w.WriteEndArray();
        }

        private static List<string> ReadArray(JsonElement root, string name)
        {
            var list = new List<string>();
            if (root.TryGetProperty(name, out JsonElement el) && el.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in el.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String && item.GetString() is { Length: > 0 } s)
                        list.Add(s);
                }
            }
            return list;
        }
    }
}
