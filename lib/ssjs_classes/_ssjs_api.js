<script runat="server">
  Platform.Load("core", "1.1.1");
  
  function api() {
    var fn = {}

    fn.auth = function (config) {
      if (!config) { return 'configuration required'; }
      if (!config.clientID) { return 'clientID required'; }
      if (!config.clientSecret) { return 'clientSecret required'; }
      if (!config.authBase) { return 'authBase required'; }
      if (!config.mid) { return 'account mid required'; }

      var authPayload = {
        account_id: config.mid,
        client_id: config.clientID,
        client_secret: config.clientSecret,
        grant_type: "client_credentials"
      }
       

      try {
        var req = new Script.Util.HttpRequest(config.authBase + "v2/token");
        req.emptyContentHandling = 0;
        req.retries = 2;
        req.continueOnError = true;
        req.contentType = "application/json"
        req.method = "POST";
        req.postData = Stringify(authPayload);

        var resp = req.send();
        var resultStr = String(resp.content);
        var resultJSON = Platform.Function.ParseJSON(resultStr);
        
        var response = resultJSON["Response"][0];
        var accessToken = resultJSON.access_token;
        var restBase = resultJSON.rest_instance_url;
        
        return {
          accessToken: accessToken,
          restBase: restBase
        };

      } catch (err) {
        Write(Stringify(err))
        
        return err
      }
    }


    fn.scriptUtil = function (config, apiConfig) {
      if (!config) { return 'configuration is reqired' }
      if (!config.url) { return 'configuration url is required' }
      if (!apiConfig.accessToken) { return 'unauthenticated' }

      try {
        var req = new Script.Util.HttpRequest(apiConfig.restBase + config.url);
        req.emptyContentHandling = 0;
        req.retries = 2;
        req.continueOnError = true;
        req.contentType = "application/json"
        req.method = config.method;
        req.setHeader("Authorization", "Bearer " + apiConfig.accessToken);
        
        if(config.payload){
          req.postData = config.payload;
        }

        var resp = req.send();
        var resultStr = String(resp.content);
        var resultJSON = Platform.Function.ParseJSON(resultStr);

        return resultJSON;
      } catch (err) {
        return err
      };
    }
    
    return fn
  }



</script>