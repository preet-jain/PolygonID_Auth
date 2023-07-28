const express = require('express');
const { auth, resolver, loaders } = require('@iden3/js-iden3-auth')
const getRawBody = require('raw-body')
var dotenv = require('dotenv')
dotenv.config()
const app = express();
const ngrok = require('ngrok')
const port = process.env.PORT || 8080


app.get("/api/sign-in", (req, res) => {
    console.log('get Auth Request');
    GetAuthRequest(req, res);
});

app.post("/api/callback", (req, res) => {
    console.log('callback');
    Callback(req, res);
});

app.listen(port, async function () {
    try {
        await ngrok.authtoken(process.env.authtoken)
        const url = await ngrok.connect(port)
        console.log(url)
        process.env.url = url
        console.log(`Node.js server listening on ${port}`)
    } catch (error) {
        console.log("Error:", error)
    }

})

// Create a map to store the auth requests and their session IDs
const requestMap = new Map();

async function GetAuthRequest(req, res) {

    // Audience is verifier id
    const hostUrl = process.env.url;
    const sessionId = 1;
    const callbackURL = "/api/callback"
    const audience = "did:polygonid:polygon:main:2qDyy1kEo2AYcP3RT4XGea7BtxsY285szg6yP9SPrs"

    const uri = `${hostUrl}${callbackURL}?sessionId=${sessionId}`;

    // Generate request for basic authentication
    const request = auth.createAuthorizationRequest(
        'test flow',
        audience,
        uri,
    );

    request.id = '7f38a193-0918-4a48-9fac-36adfdb8b542';
    request.thid = '7f38a193-0918-4a48-9fac-36adfdb8b542';


    // Store auth request in map associated with session ID
    requestMap.set(`${sessionId}`, request);

    return res.status(200).set('Content-Type', 'application/json').send(request);
}

async function Callback(req, res) {

    // Get session ID from request
    const sessionId = req.query.sessionId;

    // get JWZ token params from the post request
    const raw = await getRawBody(req);
    const tokenStr = raw.toString().trim();

    const ethURL = process.env.ethURL;
    const contractAddress = "0x624ce98D2d27b20b8f8d521723Df8fC4db71D79D"
    const keyDIR = "./keys"

    const ethStateResolver = new resolver.EthStateResolver(
        ethURL,
        contractAddress,
    );

    const resolvers = {
        ['polygon:main']: ethStateResolver,
    };


    // fetch authRequest from sessionID
    const authRequest = requestMap.get(`${sessionId}`);

    // Locate the directory that contains circuit's verification keys
    const verificationKeyloader = new loaders.FSKeyLoader(keyDIR);

    // EXECUTE VERIFICATION
    const verifier = await auth.Verifier.newVerifier(
        verificationKeyloader,
        resolvers,
        {
            ipfsGatewayURL: "ipfs.io"
        },
    );


    try {
        const opts = {
            AcceptedStateTransitionDelay: 5 * 60 * 1000, // 5 minute
        };
        const authResponse = await verifier.fullVerify(tokenStr, authRequest, opts);
        console.log(authResponse.from)
    } catch (error) {
        return res.status(500).send(error);
    }
    return res.status(200).set('Content-Type', 'application/json').send("user with ID: " + authResponse.from + " Succesfully authenticated");
}

