let { RelyingParty } = require('openid');
let app = require('express')();

let relyingParty = new RelyingParty(
    'http://localhost:3000/login/verify', // Verification URL (yours)
    'http://localhost:3000/', // Realm (optional, specifies realm for OpenID authentication)
    false, // Use stateless verification
    false, // Strict mode
    []); // List of extensions to enable and include

app.get('/login/authenticate', async (request, response) => {
	let identifier = request.query.openid_identifier;

	// Resolve identifier, associate, and build authentication URL
	const authUrl = await relyingParty.authenticate(identifier, false).catch((error) => {
        response.status(500).json(error)
    })

    if (!authUrl) {
        response.status(500).send('Authentication failed');
    } else {
        response.status(302).redirect(authUrl);
    }
});

app.get('/login/verify', async (request, response) => {
	// Verify identity assertion
	const result = await relyingParty.verifyAssertion(new URL(request.protocol + '://' + request.get('host') + request.originalUrl)).catch((error) => {
        response.status(500).json(error);
    })

    if (result) {
        response.send(result.authenticated 
            ? 'Success :)' // TODO: redirect to something interesting!
            : 'Failure :('); // TODO: show some error message!
    }
});

app.listen(3000);