using System;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using DotNetOpenAuth.Messaging;
using DotNetOpenAuth.OpenId;
using DotNetOpenAuth.OpenId.Extensions.SimpleRegistration;
using DotNetOpenAuth.OpenId.RelyingParty;
using StackExchange.DataExplorer.Helpers;
using StackExchange.DataExplorer.Models;
using System.Security.Cryptography;
using System.Text;
using System.Data;
using MySql.Data.MySqlClient;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using Dapper;

namespace StackExchange.DataExplorer.Controllers
{
    [HandleError]
    public class AccountController : StackOverflowController
    {
        private static readonly OpenIdRelyingParty openid = new OpenIdRelyingParty();


        [Route("account/logout")]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return Redirect("~/");
        }

        [Route("account/login", HttpVerbs.Get)]
        public ActionResult Login(string returnUrl)
        {
            return View("Login");
        }

        [Route("user/authenticate")]
        [ValidateInput(false)]
        public ActionResult Authenticate(string returnUrl)
        {
            MD5 md5Hash = MD5.Create();
            string pass = encryptPassword(Request.Form["password"]);
            string email = Request.Form["email"];
            string connstring = System.Configuration.ConfigurationManager.ConnectionStrings["ReaderConnection"].ConnectionString;

    //        string strConnection = ConfigurationSettings.AppSettings["ConnectionString"];
            MySqlConnection connection = new MySqlConnection(connstring);
    //        MySqlCommand command = connection.CreateCommand();
    //        MySqlDataReader reader;
    //        command.CommandText = "SELECT username FROM user WHERE email = '" + email + "' and password = '" + pass+"'";
            connection.Open();
    //        reader = command.ExecuteReader();
            var sql = "SELECT name FROM user WHERE email = '" + email + "' and password = '" + pass+"'";

            var id = connection.Query<String>(sql);
            if (id.Count() > 0)
            {
                string name = id.ElementAt(0);
                var normalizedClaim = Models.User.NormalizeOpenId(email);
                User user = Models.User.CreateUser(name, email, normalizedClaim);
                string Groups = user.IsAdmin ? "Admin" : "";

                var ticket = new FormsAuthenticationTicket(
                    1,
                    user.Id.ToString(),
                    DateTime.Now,
                    DateTime.Now.AddYears(2),
                    true,
                    Groups);

                string encryptedTicket = FormsAuthentication.Encrypt(ticket);

                var authenticationCookie = new HttpCookie(FormsAuthentication.FormsCookieName, encryptedTicket);
                authenticationCookie.Expires = ticket.Expiration;
                authenticationCookie.HttpOnly = true;
                Response.Cookies.Add(authenticationCookie);
            }
            return Redirect(returnUrl);
        }

        private String encryptPassword(String userPassword)
        {

            SHA1 sha1 = SHA1CryptoServiceProvider.Create();
            byte[] hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(userPassword));
            return Convert.ToBase64String(hash);
        }

        private bool IsVerifiedEmailProvider(string identifier)
        {
            identifier = identifier.ToLowerInvariant();

            if (identifier.Contains("@")) return false;

            if (identifier.StartsWith(@"http://google.com/accounts/o8/id")) return true;
            if (identifier.StartsWith(@"http://me.yahoo.com")) return true;
            if (identifier.Contains(@"//www.google.com/profiles/")) return true;
            if (identifier.StartsWith(@"http://stackauth.com/")) return true;
            if (identifier.StartsWith(@"http://openid.stackexchange.com/")) return true;
            return false;
        }
    }
}