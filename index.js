var express = require('express'),
  request = require('request'),
  jwt = require('jsonwebtoken'),
  app = express();

var uaaUrl = 'https://login.sticky-chanter.sapi.cf-app.com';

app.get('/v2/catalog', function(req, res) {
  var authHeader = req.get('Authorization');
  if (!authHeader)
  {
    res.status(401).send('No Authorization header');
    return;
  }
  var token = authHeader.split('Bearer ')[1];
  console.log(`Token: ${token}`);

  // Fetch the UAA Public Key that we need to verify the token
  request(uaaUrl + '/token_key', { strictSSL: false }, function(error, response, body) {
    if (error || !response) {
      res.status(500).send(`Failed to get UAA public key ${error}`);
      return;
    }
    var data = JSON.parse(response.body);
    console.log(response.body);
    var uaaPublicKey = data.value;

    // Let's check if the token is valid and decrypt it to check the scopes
    try {
      var { scope } = jwt.verify(token, uaaPublicKey);

      // We need servicebroker.admin to proceed
      if (scope.includes('servicebroker.admin')) {
        res.send('Token verified and contains correct scopes. Woohoo!');
        return;
      }
      else {
        res.status(401).send('Error: Missing servicebroker.admin scope');
        return;
      }
    }
    catch (e) {
      console.error('Invalid token');
      res.status(401).send('Invalid token');
      return;
    }
  });
});

app.listen(process.env.port || 3000, function() {
  console.log('Mine says sweet');
});

