//----------------------------------------------------------------------------------------------
//    Copyright 2014 Microsoft Corporation
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//----------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

// The following using statements were added for this sample.
using System.Collections.Concurrent;
using TodoListService.Models;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Globalization;
using System.Configuration;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Web;
using System.Net.Http.Headers;
using Newtonsoft.Json;
using System.Threading;
using TodoListService.DAL;
using System.Web.Http.Cors;
using System.Web.Script.Serialization;

namespace TodoListService.Controllers
{
   [Authorize]
   [EnableCors(origins: "*", headers: "*", methods: "*")]

    public class TodoListController : ApiController
    {
        ////
        //// The Client ID is used by the application to uniquely identify itself to Azure AD.
        //// The App Key is a credential used by the application to authenticate to Azure AD.
        //// The Tenant is the name of the Azure AD tenant in which this application is registered.
        //// The AAD Instance is the instance of Azure, for example public Azure or Azure China.
        //// The Authority is the sign-in URL of the tenant.
        ////
        //private static string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];
        //private static string tenant = ConfigurationManager.AppSettings["ida:Tenant"];
        //private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        //private static string appKey = ConfigurationManager.AppSettings["ida:AppKey"];

        ////
        //// To authenticate to the Graph API, the app needs to know the Grah API's App ID URI.
        //// To contact the Me endpoint on the Graph API we need the URL as well.
        ////
        //private static string graphResourceId = ConfigurationManager.AppSettings["ida:GraphResourceId"];
        //private static string graphUserUrl = ConfigurationManager.AppSettings["ida:GraphUserUrl"];
        //private const string TenantIdClaimType = "http://schemas.microsoft.com/identity/claims/tenantid";

        //
        // The Client ID is used by the application to uniquely identify itself to Azure AD.
        // The client secret is the credentials for the WebServer Client

        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];
        private static string clientSecret = ConfigurationManager.AppSettings["ida:ClientSecret"];
        private static string authority = ConfigurationManager.AppSettings["ida:Authority"];

        // Base address of the WebAPI
        private static string OBOWebAPIBase = ConfigurationManager.AppSettings["ida:OBOWebAPIBase"];

        //
        // To Do items list for all users.  Since the list is stored in memory, it will go away if the service is cycled.
        //
        private TodoListServiceContext db = new TodoListServiceContext();

        // Error Constants
        const String SERVICE_UNAVAILABLE = "temporarily_unavailable";

        // GET api/todolist
        public IEnumerable<TodoItem> Get()
        {
            //
            // The Scope claim tells you what permissions the client application has in the service.
            // In this case we look for a scope value of user_impersonation, or full access to the service as the user.
            var scopeClaim = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/scope");
            if (scopeClaim == null || !scopeClaim.Value.Contains("user_impersonation"))
            {
                throw new HttpResponseException(new HttpResponseMessage { StatusCode = HttpStatusCode.Unauthorized, ReasonPhrase = "The Scope claim does not contain 'user_impersonation' or scope claim not found" });
            }

            // A user's To Do list is keyed off of the Name claim, which contains an immutable, unique identifier for the user.
            Claim subject = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name);

            return from todo in db.TodoItems
                   where todo.Owner == subject.Value
                   select todo;
        }

        // POST api/todolist
        public async Task Post(TodoItem todo)
        {
            if (!ClaimsPrincipal.Current.FindFirst("https://schemas.microsoft.com/identity/claims/scope").Value.Contains("user_impersonation"))
            {
                throw new HttpResponseException(new HttpResponseMessage { StatusCode = HttpStatusCode.Unauthorized, ReasonPhrase = "The Scope claim does not contain 'user_impersonation' or scope claim not found" });
            }

            //
            // Call the WebAPIOBO On Behalf Of the user who called the To Do list web API.
            //
            string augmentedTitle = null;
            string custommessage = await CallGraphAPIOnBehalfOfUser();
            if (custommessage != null)
            {
                augmentedTitle = String.Format("{0}, Message: {1}", todo.Title, custommessage);
            }
            else
            {
                augmentedTitle = todo.Title;
            }

            if (null != todo && !string.IsNullOrWhiteSpace(todo.Title))
            {
                db.TodoItems.Add(new TodoItem { Title = augmentedTitle, Owner = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value });
                db.SaveChanges();
            }
        }

        public static async Task<string> CallGraphAPIOnBehalfOfUser()
        {
            string accessToken = null;
            AuthenticationResult result = null;
            AuthenticationContext authContext = null;
            HttpClient httpClient = new HttpClient();
            string custommessage = "";

            //
            // Use ADAL to get a token On Behalf Of the current user.  To do this we will need:
            //      The Resource ID of the service we want to call.
            //      The current user's access token, from the current request's authorization header.
            //      The credentials of this application.
            //      The username (UPN or email) of the user calling the API
            //
            ClientCredential clientCred = new ClientCredential(clientId, clientSecret);
            var bootstrapContext = ClaimsPrincipal.Current.Identities.First().BootstrapContext as System.IdentityModel.Tokens.BootstrapContext;
            string userName = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn) != null ? ClaimsPrincipal.Current.FindFirst(ClaimTypes.Upn).Value : ClaimsPrincipal.Current.FindFirst(ClaimTypes.Email).Value;
            string userAccessToken = bootstrapContext.Token;
            UserAssertion userAssertion = new UserAssertion(bootstrapContext.Token, "urn:ietf:params:oauth:grant-type:jwt-bearer", userName);

            string userId = ClaimsPrincipal.Current.FindFirst(ClaimTypes.Name).Value;
            authContext = new AuthenticationContext(authority, false);

            // In the case of a transient error, retry once after 1 second, then abandon.
            // Retrying is optional.  It may be better, for your application, to return an error immediately to the user and have the user initiate the retry.
            bool retry = false;
            int retryCount = 0;

            do
            {
                retry = false;
                try
                {
                    result = authContext.AcquireTokenAsync(OBOWebAPIBase, clientCred, userAssertion).Result;
                    accessToken = result.AccessToken;
                }
                catch (AdalException ex)
                {
                    if (ex.ErrorCode == "temporarily_unavailable")
                    {
                        // Transient error, OK to retry.
                        retry = true;
                        retryCount++;
                        Thread.Sleep(1000);
                    }
                }
            } while ((retry == true) && (retryCount < 1));

            if (accessToken == null)
            {
                // An unexpected error occurred.
                return (null);
            }

            // Once the token has been returned by ADAL, add it to the http authorization header, before making the call to access the To Do list service.
            httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.AccessToken);

            // Call the WebAPIOBO.
            HttpResponseMessage response = await httpClient.GetAsync(OBOWebAPIBase + "/api/WebAPIOBO");


            if (response.IsSuccessStatusCode)
            {
                // Read the response and databind to the GridView to display To Do items.
                string s = await response.Content.ReadAsStringAsync();
                JavaScriptSerializer serializer = new JavaScriptSerializer();
                custommessage = serializer.Deserialize<string>(s);
                return custommessage;
            }
            else
            {
                custommessage = "Unsuccessful OBO operation : " + response.ReasonPhrase;
            }
            // An unexpected error occurred calling the Graph API.  Return a null profile.
            return (null);
        }
    }
}
