/***********************************************************************************************************************
 * SAML2 SSO Proxy
 * This code supports SingleSignOn scenario 5.1.2 as described in:
 * https://www.oasis-open.org/committees/download.php/27819/sstc-saml-tech-overview-2.0-cd-02.pdf
 *
 * author: Jakub Zakrzewski
 * copyright: E2E Technologies Ltd.
 **********************************************************************************************************************/

var express = require('express')
    , passport = require('passport')
    , samlStrategy = require('passport-saml').Strategy
    , ensureLoggedIn = require('connect-ensure-login').ensureLoggedIn
    , httpProxy = require('http-proxy')
    , fs = require('fs')
    , path = require('path')
    , crypto = require('crypto')
    , winston = require('winston');

// read configuration
var configFile = process.env.CONFIG_FILE || path.join( __dirname, 'proxy.json');
var config = JSON.parse(fs.readFileSync( configFile));

var devEnv = !( process.env.NODE_ENV === 'prod' || process.env.NODE_ENV === 'production');

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.
//   For simplicity I serialize entire JSON structure here.
//   It's probable, that we won't need anything more sophisticated
passport.serializeUser(function(req, user, done) {
    done(null, JSON.stringify(user));
});

passport.deserializeUser(function(req, id, done) {
    done(null, JSON.parse(id));
});

// set up logger
var logger = new (winston.Logger)({
    transports: [
        new (require('winston-stderr'))({level: devEnv ? "debug" : "warn"})
    ]
});

// enable web server logging; pipe those log messages through winston
var loggerStream = {
    write: function(message, encoding){
        logger.debug(message.trim());
    }
};

var strategy = new samlStrategy(
    {
        entryPoint: config.saml.entryPoint,
        issuer: config.saml.issuer,
        protocol: config.saml.protocol,
        path: '/saml',
        cert: config.saml.cert,
        privateCert: config.saml.privateKeyFile ? fs.readFileSync(path.resolve( __dirname, config.certDir, config.saml.privateKeyFile), 'utf-8') : undefined
    },
    function(profile, done) {
        // simply accept everything - bridge will verify this
        logger.debug("Auth with: ", profile);
        return done(null, profile);
    }
);
passport.use(strategy);

var app = express();
app.use(express.logger({stream: loggerStream}));
app.use(express.favicon(path.join(__dirname, 'favicon.ico')));
app.use(express.cookieParser());
app.use(express.bodyParser());
app.use(express.methodOverride());
app.use(express.session({ secret: config.sessionSecret, cookie: { maxAge: config.sessionDuration }}));
app.use(passport.initialize());
app.use(passport.session());

app.all('/saml',
    passport.authenticate('saml', {
        samlFallback: 'login-request',
        successReturnToOrRedirect: config.indexPath || '/',
        failureRedirect: '/401',
        failureFlash: true
    }),
    function(req, res) {
        throw new Error("This callback should never be invoked");
    }
);

app.get('/401', function(req, res){
    res.status(401).send("Authentication failed");
});

var proxy = new httpProxy.RoutingProxy();
var signingKey = config.credentialsSigningKeyFile ? fs.readFileSync(path.resolve(__dirname, config.certDir, config.credentialsSigningKeyFile)).toString() : null;

config.routes.forEach(function(route){
    app.all( route.routedPrefix + '/*', ensureLoggedIn('/saml'), function(req, res) {
        var credentials = JSON.stringify({userData: req.user, timestamp: new Date()});
        req.headers[config.credentialsHeader] = encodeURIComponent(credentials);
        if( signingKey) {
            var signer = crypto.createSign("RSA-SHA1");
            signer.end( credentials);
            var signature = signer.sign( signingKey, 'base64');
            req.headers[config.signatureHeader] = encodeURIComponent(signature);
        }
        req.url = req.url.substring(route.routedPrefix.length); //strip route prefix from url
        logger.debug('Routing: ', req.url, ' to: ', JSON.stringify(route));
        proxy.proxyRequest(req, res, {
            host: route.destination,
            port: route.destinationPort
        });
    });
});

var port = process.env.PORT || config.port || 3000;

if( config.externalProtocol === 'http') {
    require('http').createServer(app).listen(port, function () {
        console.log("Server listening on port: " + port);
    });
} else if( config.externalProtocol === 'https') {
    require('https').createServer(
        {
            key: fs.readFileSync(path.resolve(__dirname, config.certDir, config.ssl.privateKeyFile)).toString(),
            cert: fs.readFileSync(path.resolve(__dirname, config.certDir, config.ssl.certificateFile)).toString()
        },
        app
    ).listen(port, function () {
        console.log("Secure server listening on port: " + port);
    });
} else {
    logger.error("Unknown protocol: ", config.externalProtocol);
}

