<script runat="server">
Platform.Load("core", "1.1.1");

function oAuth() {
    var fn = {};

    fn.authenticate = function(env, pageURL){
        var oAuthUtils = _oAuthUtils();
        var redirectURI = pageURL;

        // Check for existing session cookie
        var sessionCookie = Platform.Request.GetCookieValue(env.client.oauth.cookieName);

        var qs = util.queryStringToJSON(pageURL);
        var logout = qs.logout === 1 ? oAuthUtils.logout() : null;
        var reload = qs.reload === 1 ? oAuthUtils.redirect() : null;
        var error = qs.error ? qs.error : null;
        var code = qs.code ? qs.code : null;


        // Check if session cookie exists or logout parameter
        // Logout intiates during BU context switching
        if (!sessionCookie) {

            if (!code) {
                
                Redirect('https://' + env.client.subdomain + '.auth.marketingcloudapis.com/v2/authorize?client_id=' + env.client.oauth.clientID + '&redirect_uri=' + redirectURI + '&response_type=code', false)

            } else {
                oAuthUtils.validateAuthenticationCode(env, code)
            }

        } else {

        }
    }

    return fn
}


function _oAuthUtils(){
    var fn = {};

    fn.logout = function(){
        var date = new Date();
        var exp = date.setDate(date.getDate() - 1);
        Platform.Response.SetCookie(env.client.oauth.cookieName, sessionCookie, exp, true);
    }


    fn.redirect = function(redirectURI){
        Redirect(redirectURI, false)
    }


    fn.validateAuthenticationCode = function(env, redirectURI, code){
        var payload = '';
        payload += 'grant_type=authorization_code&';
        payload += 'code=' + code + '&';
        payload += 'client_id=' + env.client.oauth.clientID + '&';
        payload += 'client_secret=' + env.client.oauth.clientSecret + '&';
        payload += 'redirect_uri=' + redirectURI;

        var req = new Script.Util.HttpRequest('https://' + env.client.subdomain + '.auth.marketingcloudapis.com/v2/token');
        req.emptyContentHandling = 0;
        req.retries = 2;
        req.continueOnError = true;
        req.contentType = 'application/x-www-form-urlencoded';
        req.method = 'POST';
        req.postData = payload;


        var resp = req.send();
        var resultStr = String(resp.content);
        var resultJSON = Platform.Function.ParseJSON(resultStr);

        var response = resultJSON["Response"][0];
        var accessToken = resultJSON.access_token;
    }
    
    return fn
}

/* 
// Check for logout query parameter to reinitiate OAuth 2 flow
var logout = Platform.Request.GetQueryStringParameter('logout');
var reload = Platform.Request.GetQueryStringParameter('reload');

// Check for code query paramter for OAuth 2 flow for validation
var code = Platform.Request.GetQueryStringParameter('code');

// Check for errors/unauthorized  
var unauthorized = Platform.Request.GetQueryStringParameter('error');


if (logout) {
    var exp = date.setDate(date.getDate() - 1);
    // Clear set cookie
    Platform.Response.SetCookie(env.client.oauth.cookieName, sessionCookie, exp, true);
}

if (reload) {
    Redirect(redirectURI, false)
}

if (unauthorized) {
    Redirect(config.nonAuthorizedRedirect, false)
}

// Check if session cookie exists or logout parameter
// Logout intiates during BU context switching
if (!sessionCookie) {

    if (!code) {
        
        Redirect('https://' + config.tennantBase + '.auth.marketingcloudapis.com/v2/authorize?client_id=' + config.secureClientId + '&redirect_uri=' + redirectURI + '&response_type=code', false)

    } else {
        var payload = '';
        payload += 'grant_type=authorization_code&';
        payload += 'code=' + code + '&';
        payload += 'client_id=' + config.secureClientId + '&';
        payload += 'redirect_uri=' + redirectURI;

        var req = new Script.Util.HttpRequest('https://' + config.tennantBase + '.auth.marketingcloudapis.com/v2/token');
        req.emptyContentHandling = 0;
        req.retries = 2;
        req.continueOnError = true;
        req.contentType = 'application/x-www-form-urlencoded';
        req.method = 'POST';
        req.postData = payload;


        var resp = req.send();
        var resultStr = String(resp.content);
        var resultJSON = Platform.Function.ParseJSON(resultStr);

        var response = resultJSON["Response"][0];
        var accessToken = resultJSON.access_token;

        if (!accessToken) {
            sessionDE.Rows.Add({
                sessionID: session,
                sessionData: Stringify(resultJSON)
            });
          
            Redirect(config.nonAuthorizedRedirect, false)

        } else {

            var date = new Date()
            var exp = date.setDate(date.getDate() + config.cookie.expDays);
            var session = Platform.Function.GUID();

            Platform.Response.SetCookie(config.cookie.cookieName, session, exp, true);

            if (config.logging.log) {
                var req = new Script.Util.HttpRequest('https://' + config.tennantBase + '.auth.marketingcloudapis.com/v2/userinfo');
                req.emptyContentHandling = 0;
                req.retries = 2;
                req.continueOnError = true;
                req.contentType = 'application/json';
                req.method = 'GET';
                req.setHeader("Authorization", "Bearer " + accessToken);
                var resp = req.send();
                var resultStr = String(resp.content);
                var userJSON = Platform.Function.ParseJSON(resultStr);

                var sessionData = {
                    id: session,
                    expires: exp,
                    businessUnit: {
                        mid: userJSON.organization.member_id
                    },
                    user: {
                        subscriberId: userJSON.user.sub,
                        emailAddress: userJSON.user.email
                    }
                }

                sessionDE.Rows.Add({
                    sessionID: session,
                    sessionData: Stringify(sessionData),
                    sessionExpireDate: exp
                });
            }
        }

    }
} else {

    var sessionFilter = {
        Property:"sessionID",
        SimpleOperator:"equals",
        Value: sessionCookie
    }

    var userData = sessionDE.Rows.Retrieve(sessionFilter);
} */
</script>