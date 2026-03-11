using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;
using AzureHookReceiver_Dojo.Model;
using Microsoft.AspNetCore.Mvc;

namespace AzureHookReceiver_Dojo.Controllers;

[ApiController]
[Route("[controller]")]
public class ApiController(IHttpClientFactory httpClientFactory, IConfiguration configuration) : ControllerBase
{
    private const string _urlSection = "App:Dojo:ApiUrl";
    private const string _tokenSection = "App:Dojo:Authorization";

    private readonly string _wiType = "Vulnerability";
    private readonly char _deduplicationSeparator = ';';

    [HttpPost]
    public async Task<bool> ProcessStatus()
    {
        using var client = httpClientFactory.CreateClient();
        var data = await Request.ReadFromJsonAsync<WorkItemData>();
        var workItemFields = data?.resource?.revision?.fields;

        var active = "false";
        var under_review = "false";
        var verified = "false";
        var is_mitigated = "false";
        var false_p = "false";
        var out_of_scope = "false";

        if (workItemFields?.TryGetValue("System.WorkItemType", out var rawType) == true && rawType is JsonElement jsonRawType && jsonRawType.GetString() == _wiType
        && workItemFields?.TryGetValue("System.State", out var rawState) == true && rawState is JsonElement jsonRawState)
        {
            switch(jsonRawState.GetString()?.ToUpper())
            {
                case ("NEW"): { active = "true"; break; }
                case ("ACTIVE"): { under_review = "true"; active = "true"; break; }
                case ("RESOLVED"): { verified = "true"; active = "true"; break; }
                case ("CLOSED"): { is_mitigated = "true"; break; }
                case ("FALSE POSITIVE"): { false_p = "true"; break; }
                case ("IGNORED"): { out_of_scope = "true"; break; }
                default: throw new NotSupportedException("Not supported State field");
            }
        }
        else
        {
            return false;
        }

        var jsonContent = $"{{" +
            $"\"active\":{active}," +
            $"\"under_review\":{under_review}," +
            $"\"verified\":{verified}," +
            $"\"is_mitigated\":{is_mitigated}," +
            $"\"false_p\":{false_p}," +
            $"\"out_of_scope\":{out_of_scope}" +
        $"}}";

        string[] items = [];
        if (workItemFields?.TryGetValue("Custom.Deduplication", out var rawDeduplication) == true && rawDeduplication is JsonElement jsonDeduplication)
        {
            var rawStr = jsonDeduplication.GetString();
            var plainText = Regex.Replace(rawStr!, "<[^>]+?>", " ");
            if (string.IsNullOrEmpty(plainText))
                throw new NotSupportedException("No deduplication codes");
            items = HttpUtility.HtmlDecode(plainText).Split(_deduplicationSeparator).Select(x=>x.Trim()).ToArray();
        }
        var url = configuration.GetSection(_urlSection).Value;
        var token = configuration.GetSection(_tokenSection).Value;
        foreach (var item in items)
        {
            var req = new HttpRequestMessage()
            {
                Method = HttpMethod.Patch,
                RequestUri = new Uri($"{url}v2/findings/{item}/"),
                Content = new StringContent(jsonContent, Encoding.UTF8, "application/json")
            };
            req.Headers.Add("Authorization", token);
            var response = await client.SendAsync(req);
            response.EnsureSuccessStatusCode();
        }
        return true;
    }
}
