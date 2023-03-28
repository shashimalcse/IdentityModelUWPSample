using IdentityModel.OidcClient;
using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Text;
using Windows.Security.Authentication.Web;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace UwpSample
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        HttpClient _client;

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
                Scope = "openid",
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
    }
}