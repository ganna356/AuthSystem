using System.Text.Json;

namespace AuthSystem.Services
{
    public class MessageService
    {
        private readonly Dictionary<string, string> _messages;

        public MessageService(string language)
        {
            var filePath = $"Resources/messages.{language}.json";
            _messages = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(filePath));
        }

        public string Get(string key)
        {
            return _messages.ContainsKey(key) ? _messages[key] : key;
        }
    }
}
