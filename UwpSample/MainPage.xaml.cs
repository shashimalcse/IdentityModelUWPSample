using IdentityModel.OidcClient;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using Windows.Data.Json;
using Windows.Security.Authentication.Web;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Documents;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace UwpSample
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        HttpClient _client;
        String _mgt_token;
        String _user_token;
        IDictionary<string, string> groups;
        IDictionary<string, string> users;
        String _userId;
        String _name;


        public MainPage()
        {
            this.InitializeComponent();
        }

        private async void LoginSysBrowseButton_Click(object sender, RoutedEventArgs e)
        {
            var options = new OidcClientOptions
            {
                Authority = "https://api.asgardeo.io/t/shashi/oauth2/token",
                ClientId = "9EtfJ4xzAhZxO9nBixCOH_Q8tVca",
                RedirectUri = "io.identityserver.demo.uwp://callback",
                Scope = "openid profile internal_login",
                ResponseMode = OidcClientOptions.AuthorizeResponseMode.Redirect,
                Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode,
                Browser = new SystemBrowser()
            };


            // generate start URL, state, nonce, code challenge
            options.Policy.Discovery.ValidateEndpoints = false;
            options.Policy.Discovery.ValidateIssuerName = false;
            var client = new OidcClient(options);
            var result = await client.LoginAsync(new LoginRequest());


            if (!string.IsNullOrEmpty(result.Error))
            {
                ResultTextBox.Text = result.Error;
                return;
            }

            var sb = new StringBuilder(128);


            foreach (var claim in result.User.Claims)
            {
                sb.AppendLine($"{claim.Type}: {claim.Value}");
            }

            sb.AppendLine($"refresh token: {result.RefreshToken}");
            sb.AppendLine($"access token: {result.AccessToken}");

            _user_token = result.AccessToken;

            ResultTextBox.Text = sb.ToString();

            _client = new HttpClient(result.RefreshTokenHandler);
            _client.BaseAddress = new Uri("https://demo.identityserver.io/");
        }

        private async void LoginWabButton_Click(object sender, RoutedEventArgs e)
        {

            var options = new OidcClientOptions
            {
                Authority = "https://api.asgardeo.io/t/shashi/oauth2/token",
                ClientId = "9EtfJ4xzAhZxO9nBixCOH_Q8tVca",
                RedirectUri = "io.identityserver.demo.uwp://callback",
                Scope = "openid",
                ResponseMode = OidcClientOptions.AuthorizeResponseMode.Redirect,
                Flow = OidcClientOptions.AuthenticationFlow.AuthorizationCode,
                Browser = new WabBrowser(enableWindowsAuthentication: false)
            };

            // generate start URL, state, nonce, code challenge
            options.Policy.Discovery.ValidateEndpoints = false;
            options.Policy.Discovery.ValidateIssuerName = false;
            var client = new OidcClient(options);
            var result = await client.LoginAsync(new LoginRequest());

            if (!string.IsNullOrEmpty(result.Error))
            {
                ResultTextBox.Text = result.Error;
                return;
            }

            var sb = new StringBuilder(128);

            foreach (var claim in result.User.Claims)
            {
                sb.AppendLine($"{claim.Type}: {claim.Value}");
            }

            sb.AppendLine($"refresh token: {result.RefreshToken}");
            sb.AppendLine($"access token: {result.AccessToken}");
            
            ResultTextBox.Text = sb.ToString();

            _client = new HttpClient(result.RefreshTokenHandler);
            _client.BaseAddress = new Uri("https://demo.identityserver.io/");
        }

        private async void CallApiButton_Click(object sender, RoutedEventArgs e)
        {
            if (_client == null)
            {
                return;
            }

            var result = await _client.GetAsync("api/test");
            if (result.IsSuccessStatusCode)
            {
                var response = await result.Content.ReadAsStringAsync();
                ResultTextBox.Text = JArray.Parse(response).ToString();
            }
            else
            {
                ResultTextBox.Text = result.ReasonPhrase;
            }
        }

        private async void GetTokenButton_Click(object sender, RoutedEventArgs e)
        {
            var clientId = "VtanVLzeigsM9ttB5MxE2NseVM0a";
            var clientSecrect = "kk9sZqddhr4_WxRFpTWdaXZ3p_oa";
            using (HttpClient client = new HttpClient()) {
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes($"{clientId}:{clientSecrect}")));

                var content = new FormUrlEncodedContent(new[] {

                    new KeyValuePair<string, string>("grant_type", "client_credentials"),
                    new KeyValuePair<string, string>( "scope", "SYSTEM")
                });

                HttpResponseMessage response = await client.PostAsync("https://api.asgardeo.io/t/shashi/oauth2/token", content);
                string resBody = await response.Content.ReadAsStringAsync();
                ResultTextBox.Text = resBody;
                dynamic jsonObj = JsonConvert.DeserializeObject<dynamic>(resBody);
                _mgt_token = jsonObj.access_token;

            }
        }

        private async void CreateUserButton_Click(object sender, RoutedEventArgs e)
        {

            string url = "https://api.asgardeo.io/t/shashi/scim2/Users";

            string givenName = "Kim";
            string familyName = "Berry";
            string email = "nilagini8@gmail.com";
            string password = "aBcd!23";

            string json = $@"{{
                    ""schemas"": [],
                    ""name"": {{
                        ""givenName"": ""{givenName}"",
                        ""familyName"": ""{familyName}""
                    }},
                    ""userName"": ""DEFAULT/{email}"",
                    ""password"": ""{password}"",
                    ""emails"": [
                        {{
                            ""value"": ""{email}"",
                            ""primary"": true
                        }}
                    ],
                    ""urn:scim:wso2:schema"": {{
                        ""askPassword"": true
                    }}
                }}";

            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _mgt_token);
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/scim+json"));

                var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

                HttpResponseMessage response = await client.PostAsync(url, content);
                if (response.StatusCode == System.Net.HttpStatusCode.Created) {
                    string responseBody = await response.Content.ReadAsStringAsync();
                    dynamic jsonObj = JsonConvert.DeserializeObject<dynamic>(responseBody);
                    _userId = jsonObj.id;
                    _name = jsonObj.userName;

                }

            }
        }
        private async void GetGroupsButton_Click(object sender, RoutedEventArgs e)
        {

            
                using (HttpClient client = new HttpClient())
                {
                    client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _mgt_token);
                    client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/scim+json"));

                    HttpResponseMessage response = await client.GetAsync("https://api.asgardeo.io/t/shashi/scim2/Groups");
                    string responseBody = await response.Content.ReadAsStringAsync();
                    dynamic jsonObj = JsonConvert.DeserializeObject<dynamic>(responseBody);

                    dynamic resources = jsonObj.Resources;
                    var sb = new StringBuilder(128);
                    groups = new Dictionary<string, string>();

                    foreach (dynamic item in resources)
                    {
                        sb.AppendLine($"{item.id}: {item.displayName}");
                        string groupName = item.displayName;
                        string groupId = item.id;
                        groups.Add(groupName, groupId);
                    }

                    ResultTextBox.Text = sb.ToString();
                }
        }

        private async void AddUserToGroupButton_Click(object sender, RoutedEventArgs e)
        {

               string url = $"https://api.asgardeo.io/t/shashi/scim2/Groups/{groups["DEFAULT/Sales"]}";

               var patchRequest = new
                    {
                        schemas = new[] { "urn:ietf:params:scim:api:messages:2.0:PatchOp" },
                        Operations = new[]
                        {
                new
                {
                    op = "add",
                    value = new
                    {
                        members = new[]
                        {
                            new
                            {
                                display = _name,
                                value = _userId
                            }
                        }
                    }
                }
            }
            };

            string json = JsonConvert.SerializeObject(patchRequest);

            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/scim+json"));
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _mgt_token); // Replace with the actual access token

                var request = new HttpRequestMessage(new HttpMethod("PATCH"), url);
                request.Content = new StringContent(json, System.Text.Encoding.UTF8, "application/scim+json");
                try
                {
                    HttpResponseMessage response = await client.SendAsync(request);
                    string responseBody = await response.Content.ReadAsStringAsync();
                    ResultTextBox.Text = responseBody;
                }
                catch (HttpRequestException ex)
                {
                    // Failed
                }
            }
        }

        private async void GetUsersButton_Click(object sender, RoutedEventArgs e)
        {


            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _mgt_token);
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/scim+json"));

                HttpResponseMessage response = await client.GetAsync("https://api.asgardeo.io/t/shashi/scim2/Users");
                string responseBody = await response.Content.ReadAsStringAsync();
                dynamic jsonObj = JsonConvert.DeserializeObject<dynamic>(responseBody);

                dynamic resources = jsonObj.Resources;
                var sb = new StringBuilder(128);
                users = new Dictionary<string, string>();

                foreach (dynamic item in resources)
                {
                    sb.AppendLine($"{item.id}: {item.userName}");
                    string groupName = item.userName;
                    string groupId = item.id;
                    users.Add(groupName, groupId);
                }

                ResultTextBox.Text = sb.ToString();
            }

        }

        private async void UpdateMeButton_Click(object sender, RoutedEventArgs e)
        {

            string url = $"https://api.asgardeo.io/t/shashi/scim2/Me";



            string givenName = "Kim2";
            string familyName = "Berry2";

            string json = $@"{{
                    ""schemas"": [],
                    ""name"": {{
                        ""givenName"": ""{givenName}"",
                        ""familyName"": ""{familyName}""
                    }}
                }}";

            using (HttpClient client = new HttpClient())
            {
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/scim+json"));
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _user_token); // Replace with the actual access token

                var request = new HttpRequestMessage(new HttpMethod("PUT"), url);
                request.Content = new StringContent(json, System.Text.Encoding.UTF8, "application/scim+json");
                try
                {
                    HttpResponseMessage response = await client.SendAsync(request);
                    string responseBody = await response.Content.ReadAsStringAsync();
                    ResultTextBox.Text = responseBody;
                }
                catch (HttpRequestException ex)
                {
                    // Failed
                }
            }
        }

    }

}