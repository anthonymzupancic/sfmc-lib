<script runat="server">
Platform.Load("core", "1.1.1");

function oAuth() {
    var fn = {};
  
    fn.authenticate = function(env, pageURL){
        var oAuthUtils = _oAuthUtils();
        var redirectURI = pageURL;

        // Check for existing session cookie
        var sessionCookie = Platform.Request.GetCookieValue(env.client.oauth.cookieName);
        var qs = pageURLSource.indexOf('?') > 0 ? util.queryStringToJSON(pageURLSource) :  null;
        util.deBug("qs", qs, null, 1)
      
        //var logout = qs.logout === 1 ? oAuthUtils.logout() : null;
        //var reload = qs.reload === 1 ? oAuthUtils.redirect() : null;
        //var error = qs.error ? qs.error : null;
        var code = qs && qs.code ? qs.code : null;
        
          
       // Check if session cookie exists or logout parameter
       // Logout intiates during BU context switching
        if (!sessionCookie) {
            util.deBug("No Session Cookie", null, null, 1)
            if (!code) {
              
                util.deBug("No Code", null, null, 1) 
                Redirect('https://' + env.client.subdomain + '.auth.marketingcloudapis.com/v2/authorize?client_id=' + env.client.oauth.clientID + '&redirect_uri=' + redirectURI + '&response_type=code', false)

            } else {
              
               var validToken = oAuthUtils.validateAuthenticationCode(env, redirectURI, code)
                util.deBug("Authentication Token", validToken, null, 1) 
              
               if(validToken){
                   var date = new Date();
                   var exp = date.setDate(date.getDate() + config.cookie.expDays);
                   var session = Platform.Function.GUID();

                  Platform.Response.SetCookie(env.client.oauth.cookieName, session, exp, true);
               }
              
               return
            }

        } else {

        }
        return
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
        return accessToken
    }
    
    return fn
}

</script>