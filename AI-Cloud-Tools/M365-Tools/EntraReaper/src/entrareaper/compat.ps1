# AADInternals macOS/.NET Core Compatibility Layer
# Provides shims for System.Web and System.Web.Extensions (Windows-only assemblies)
#
# Problems on macOS:
#   1. System.Web.Extensions.dll missing → JavaScriptSerializer unavailable
#   2. System.Web.dll missing → HttpUtility (UrlEncode, HtmlEncode) unavailable
#
# Solution: Define polyfill C# classes in the same namespaces that AADInternals expects.

$ErrorActionPreference = 'SilentlyContinue'

# Only apply polyfills if running on non-Windows (macOS/Linux)
if (-not $IsWindows) {

    # Check if types already exist (avoid re-adding)
    $httpUtilityExists = $null -ne ([System.Management.Automation.PSTypeName]'System.Web.HttpUtility').Type
    $jsSerializerExists = $null -ne ([System.Management.Automation.PSTypeName]'System.Web.Script.Serialization.JavaScriptSerializer').Type

    if (-not $httpUtilityExists) {
        # Polyfill: System.Web.HttpUtility
        # Maps to System.Net.WebUtility and System.Uri (both available in .NET Core)
        Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Net;

namespace System.Web
{
    public static class HttpUtility
    {
        public static string UrlEncode(string value)
        {
            if (value == null) return null;
            return Uri.EscapeDataString(value);
        }

        public static string UrlDecode(string value)
        {
            if (value == null) return null;
            return Uri.UnescapeDataString(value);
        }

        public static string HtmlEncode(string value)
        {
            if (value == null) return null;
            return WebUtility.HtmlEncode(value);
        }

        public static string HtmlDecode(string value)
        {
            if (value == null) return null;
            return WebUtility.HtmlDecode(value);
        }
    }
}
"@
    }

    if (-not $jsSerializerExists) {
        # Polyfill: System.Web.Script.Serialization.JavaScriptSerializer
        # Maps to System.Text.Json (built into .NET Core 3.0+)
        Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Text.Json;

namespace System.Web.Script.Serialization
{
    public class JavaScriptSerializer
    {
        public int MaxJsonLength { get; set; } = 67108864; // 64MB default

        public object DeserializeObject(string input)
        {
            if (string.IsNullOrEmpty(input)) return null;

            try
            {
                using var doc = JsonDocument.Parse(input);
                return ConvertElement(doc.RootElement);
            }
            catch (JsonException)
            {
                return input;
            }
        }

        public T Deserialize<T>(string input)
        {
            return JsonSerializer.Deserialize<T>(input);
        }

        public string Serialize(object obj)
        {
            var options = new JsonSerializerOptions { WriteIndented = false };
            return JsonSerializer.Serialize(obj, options);
        }

        private static object ConvertElement(JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    var dict = new Dictionary<string, object>();
                    foreach (var prop in element.EnumerateObject())
                    {
                        dict[prop.Name] = ConvertElement(prop.Value);
                    }
                    return dict;

                case JsonValueKind.Array:
                    var list = new List<object>();
                    foreach (var item in element.EnumerateArray())
                    {
                        list.Add(ConvertElement(item));
                    }
                    return list.ToArray();

                case JsonValueKind.String:
                    return element.GetString();

                case JsonValueKind.Number:
                    if (element.TryGetInt64(out long l)) return l;
                    return element.GetDouble();

                case JsonValueKind.True:
                    return true;

                case JsonValueKind.False:
                    return false;

                case JsonValueKind.Null:
                case JsonValueKind.Undefined:
                default:
                    return null;
            }
        }
    }
}
"@
    }
}
