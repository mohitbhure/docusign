
const express = require('express');
const session = require('express-session');  // https://github.com/expressjs/session
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const MemoryStore = require('memorystore')(session); // https://github.com/roccomuso/memorystore
const path = require('path');
const passport = require('passport');
const DocusignStrategy = require('passport-docusign');
const fs = require('fs');
const tesseract = require("node-tesseract-ocr")

const dsConfig = require('./config.js').config;
const flash = require('express-flash');
const helmet = require('helmet');
const moment = require('moment');
const schedule = require('node-schedule');
const docusign = require('docusign-esign');
var pdf2img = require('pdf-img-convert');

const baseUriSuffix = '/restapi';
const tokenReplaceMinGet = 60;

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';
const max_session_min = 180;

const mongoose = require('mongoose');

mongoose.connect(dsConfig.dbUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});



const gracefulShutdown = function (msg, callback) {
    connection.close();
    console.log('Mongoose disconnected through ' + msg);
    callback();
};

process.once('SIGUSR2', function () {
    gracefulShutdown('nodemon restart', function () {
        process.kill(process.pid, 'SIGUSR2');
    });
});

process.on('SIGINT', function () {
    gracefulShutdown('app termination', function () {
        process.exit(0);
    });
});
const connection = mongoose.connection;

connection.on('open', function () {
    console.log('******* MongoDB connected *******');
});
connection.on('error', function (err) {
    console.log(
        'mongodb connection error'
    );
    console.log('error while connecting to database ', err);
});

const UserSchema = mongoose.Schema(
    {
        email: {
            type: String,
            required: true,
            lowercase: true
        },
        name: {
            type: String,
            required: true
        },
        accountName: {
            type: String,
            required: true
        },
        accountId: {
            type: String,
            required: true
        },
        expiresIn: {
            type: Number,
            required: true
        },
        tokenExpirationTimestamp: {
            type: Number,
            required: true
        },
        accessToken: {
            type: String,
            required: true
        },
        refreshToken: {
            type: String,
            required: true
        },
    },
    {
        timestamps: true,
        toJSON: {
            virtuals: true,
            getters: true,
        },
        toObject: {
            virtuals: true,
            getters: true,
        },
    }
);

const User = mongoose.model('User', UserSchema);

const DocumentSchema = mongoose.Schema(
    {
        documentId: {
            type: String,
            required: true
        },
        documentIdGuid: {
            type: String,
            required: true
        },
        documentPath: {
            type: String,
            required: true
        },
        parseStatus: {
            type: Number,
            default: 0
        },
        name: {
            type: String,
            required: true
        },
        userId: {
            type: mongoose.Types.ObjectId,
            ref: "User"
        },
        accountId: {
            type: String,
            required: true
        },
        envelopId: {
            type: String,
            required: true
        },
        parsedText: {
            type: String,
            default: ""
        }
    },
    {
        timestamps: true,
        toJSON: {
            virtuals: true,
            getters: true,
        },
        toObject: {
            virtuals: true,
            getters: true,
        },
    }
);

const Document = mongoose.model('Document', DocumentSchema);

let hostUrl = 'http://' + HOST + ':' + PORT;

const DSAuthCodeGrant = function _DSAuthCodeGrant(req) {

    this._debug_prefix = 'DSAuthCodeGrant';
    this._accessToken = req.user && req.user.accessToken;
    this._refreshToken = req.user && req.user.refreshToken;
    this._tokenExpiration = req.user && req.user.tokenExpirationTimestamp;
    this._debug = true;

}
DSAuthCodeGrant.prototype.Error_set_account = "Error_set_account";

DSAuthCodeGrant.prototype.Error_account_not_found = "Could not find account information for the user";


DSAuthCodeGrant.prototype.Error_invalid_grant = 'invalid_grant'; // message when bad client_id is provided


DSAuthCodeGrant.prototype.login = function (req, res, next) {
    // Reset
    this.internalLogout(req, res);
    req.session.authMethod = 'grand-auth';
    passport.authenticate('docusign')(req, res, next);
}

DSAuthCodeGrant.prototype.oauth_callback1 = (req, res, next) => {

    passport.authenticate('docusign', { failureRedirect: '/' })(req, res, next)
}

async function saveUserAccount(req, account) {
    let existingUser = await User.findOne({
        email: req.user.email
    });

    if (!existingUser) {
        existingUser = new User({
            email: req.user.email,
            name: req.user.name,
            accountId: account.account_id,
            accountName: account.account_name,
            refreshToken: req.user.refreshToken,
            accessToken: req.user.accessToken,
            expiresIn: req.user.expiresIn,
            tokenExpirationTimestamp: req.user.tokenExpirationTimestamp
        })
    } else {
        existingUser.name = req.user.name;
        existingUser.refreshToken = req.user.refreshToken;
        existingUser.expiresIn = req.user.expiresIn;
        existingUser.tokenExpirationTimestamp = req.user.tokenExpirationTimestamp;
    }

    await existingUser.save();

}

DSAuthCodeGrant.prototype.oauth_callback2 = async function _oauth_callback2(req, res, next) {
    this._accessToken = req.user.accessToken;
    console.log(`Received access_token: |${req.user.accessToken}|`);
    console.log(`Expires at ${req.user.tokenExpirationTimestamp.format("dddd, MMMM Do YYYY, h:mm:ss a")}`);

    let account = this.getDefaultAccountInfo(req);
    await saveUserAccount(req, account);
    res.redirect('/');
}


DSAuthCodeGrant.prototype.logout = function _logout(req, res) {
    let logoutCB = encodeURIComponent(res.locals.hostUrl + '/ds/logoutCallback')
        , oauthServer = dsConfig.dsOauthServer
        , client_id = dsConfig.dsClientId
        , logoutURL = `${oauthServer}/logout?client_id=${client_id}&redirect_uri=${logoutCB}&response_mode=logout_redirect`
        ;

    this.logoutCallback(req, res);
}

/**
 * Clears the user information including the tokens.
 * @function
 */
DSAuthCodeGrant.prototype.logoutCallback = function _logout(req, res) {
    req.logout(function (err) {
        if (err) {
            throw err;
        }
    });
    this.internalLogout(req, res);
    req.flash('info', 'You have logged out.');
    res.redirect('/');
}

DSAuthCodeGrant.prototype.internalLogout = function _internalLogout(req, res) {
    this._tokenExpiration = null;
    req.session.accountId = null;
    req.session.accountName = null;
    req.session.basePath = null;
}

DSAuthCodeGrant.prototype.getDefaultAccountInfo = function _getDefaultAccountInfo(req) {
    const targetAccountId = dsConfig.targetAccountId
        , accounts = req.user.accounts
        ;

    let account = null;
    if (targetAccountId) {
        account = accounts.find(a => a.account_id == targetAccountId);
        if (!account) {
            throw new Error(this.Error_account_not_found)
        }
    } else {
        account = accounts.find(a => a.is_default);
    }


    req.session.accountId = account.account_id;
    req.session.accountName = account.account_name;
    req.session.basePath = account.base_uri + baseUriSuffix;
    console.log(`Using account ${account.account_id}: ${account.account_name}`);
    return account;
}


DSAuthCodeGrant.prototype.checkToken = function _checkToken(bufferMin = tokenReplaceMinGet) {
    let noToken = !this._accessToken || !this._tokenExpiration
        , now = moment()
        , needToken = noToken || moment(this._tokenExpiration).subtract(
            bufferMin, 'm').isBefore(now)
        ;
    if (this._debug) {
        if (noToken) { this._debug_log('checkToken: Starting up--need a token') }
        if (needToken && !noToken) { this._debug_log('checkToken: Replacing old token') }
        if (!needToken) { this._debug_log('checkToken: Using current token') }
    }

    return (!needToken)
}

DSAuthCodeGrant.prototype.setEg = function _setEg(req, eg) {
    req.session.eg = eg
}


DSAuthCodeGrant.prototype._debug_log = function (m) {
    if (!this._debug) { return }
    console.log(this._debug_prefix + ': ' + m)
}


DSAuthCodeGrant.prototype._debug_log_obj = function (m, obj) {
    if (!this._debug) { return }
    console.log(this._debug_prefix + ': ' + m + "\n" + JSON.stringify(obj, null, 4))
}

let app = express()
    .use(helmet())
    .use(express.static(path.join(__dirname, 'public')))
    .use(cookieParser())
    .use(session({
        secret: dsConfig.sessionSecret,
        name: 'ds-launcher-session',
        cookie: { maxAge: max_session_min * 60000 },
        saveUninitialized: true,
        resave: true,
        store: new MemoryStore({
            checkPeriod: 86400000
        })
    }))
    .use(passport.initialize())
    .use(passport.session())
    .use(bodyParser.urlencoded({ extended: true }))
    .use(((req, res, next) => {
        res.locals.user = req.user;
        res.locals.session = req.session;
        res.locals.hostUrl = hostUrl;
        next()
    })) // Send user info to views
    .use(flash())
    .set('views', path.join(__dirname, 'views'))
    .set('view engine', 'ejs')

    .use((req, res, next) => {
        req.dsAuthCodeGrant = new DSAuthCodeGrant(req);
        req.dsAuth = req.dsAuthCodeGrant;
        next();
    })
    .get('/', function (req, res) {
        res.render('index');
    })
    .get('/ds/logout', (req, res) => {
        req.dsAuth.logout(req, res);
    })
    .post('/login', function (req, res, next) {
        req.dsAuth.login(req, res, next);
    })
    .get('/documents', async function (req, res) {
        let documents = await Document.find({})
        return res.json(documents);
    })
    .get('/ds/callback', [dsLoginCB1, dsLoginCB2])


function dsLoginCB1(req, res, next) { req.dsAuthCodeGrant.oauth_callback1(req, res, next) }
function dsLoginCB2(req, res, next) { req.dsAuthCodeGrant.oauth_callback2(req, res, next) }

app.listen(PORT)
console.log(`Listening on ${PORT}`);
console.log(`Ready! Open ${hostUrl}`);

passport.serializeUser(function (user, done) { done(null, user) });
passport.deserializeUser(function (obj, done) { done(null, obj) });

const SCOPES = ["signature"];
const ROOM_SCOPES = [
    "signature", "dtr.rooms.read", "dtr.rooms.write",
    "dtr.documents.read", "dtr.documents.write", "dtr.profile.read", "dtr.profile.write",
    "dtr.company.read", "dtr.company.write", "room_forms"
];
const CLICK_SCOPES = [
    "signature", "click.manage", "click.send"
];
const MONITOR_SCOPES = [
    "signature", "impersonation"
];
const ADMIN_SCOPES = [
    "organization_read", "group_read", "permission_read	",
    "user_read", "user_write", "account_read",
    "domain_read", "identity_provider_read", "signature",
    "user_data_redact"
];

const scope = [...ROOM_SCOPES, ...CLICK_SCOPES, ...MONITOR_SCOPES, ...ADMIN_SCOPES, ...SCOPES];


let docusignStrategy = new DocusignStrategy({
    production: dsConfig.production,
    clientID: dsConfig.dsClientId,
    scope: scope.join(" "),
    clientSecret: dsConfig.dsClientSecret,
    callbackURL: hostUrl + '/ds/callback',
    state: true
},
    function _processDsResult(accessToken, refreshToken, params, profile, done) {
        let user = profile;
        user.accessToken = accessToken;
        user.refreshToken = refreshToken;
        user.expiresIn = params.expires_in;
        user.tokenExpirationTimestamp = moment().add(user.expiresIn, 's'); // The dateTime when the access token will expire
        return done(null, user);
    }
);

passport.use(docusignStrategy);

schedule.scheduleJob('*/1 * * * *', async function () {

    let userCursor = User.find({}).cursor();
    let user = null;
    while (user = await userCursor.next()) {
        let dsApiClient = new docusign.ApiClient();
        dsApiClient.setBasePath(dsConfig.docusignApiUrl);
        dsApiClient.addDefaultHeader('Authorization', 'Bearer ' + user.accessToken);
        let envelopsApi = new docusign.EnvelopesApi(dsApiClient);

        const envelops = await envelopsApi.listStatusChanges(user.accountId, {
            folderTypes: "inbox",
            fromDate: moment().subtract(1, 'month').toDate()
        });

        if (envelops && envelops.envelopes) {

            for (let envelop of envelops.envelopes) {
                const documents = await envelopsApi.listDocuments(user.accountId, envelop.envelopeId);
                for (let document of documents.envelopeDocuments) {
                    if (document.documentId === 'certificate') {
                        continue;
                    }
                    let existingDocument = await Document.findOne({ documentIdGuid: document.documentIdGuid });

                    if (existingDocument) {
                        console.log(" ** document already exists *** ", document.pages);
                        continue;
                    }

                    let documentData = await envelopsApi.getDocument(user.accountId, envelop.envelopeId, document.documentId);
                    fs.writeFileSync(`./${document.documentIdGuid}.pdf`, documentData, { encoding: 'binary' });

                    const documentToSave = new Document({
                        documentId: document.documentId,
                        documentIdGuid: document.documentIdGuid,
                        name: document.name,
                        userId: user._id,
                        accountId: user.accountId,
                        envelopId: envelop.envelopeId,
                        documentPath: `${document.documentIdGuid}.pdf`,
                        parseStatus: 0
                    });

                    await documentToSave.save();
                    console.log(" *** document saved *** ");
                }
            }
        }
    }


});
schedule.scheduleJob('*/30 * * * * *', async function () {
    let documentCursor = Document.find({ parseStatus: 0 }).cursor();
    let document = null;
    while (document = await documentCursor.next()) {
        const documentPath = document.documentPath;

        if (!fs.existsSync('./images')) {
            fs.mkdirSync('./images');
        }

        const outputImages = await pdf2img.convert(`./${documentPath}`);

        let i = 1;
        let parsedText = '';
        for (let image of outputImages) {
            fs.writeFileSync(`./images/${document.documentIdGuid}.${i}.png`, image);
            const config = {
                lang: "eng",
                oem: 1,
                psm: 3,
            }

            const text = await tesseract
                .recognize(path.resolve(`./images/${document.documentIdGuid}.${i}.png`), config)
            parsedText = parsedText + " " + text;
            i++;
        }

        document.parsedText = parsedText;
        document.parseStatus = 1;
        document = await document.save();
        console.log(" converted ");
    }


});