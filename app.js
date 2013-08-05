
/**
 * Module dependencies.
 */

var express = require('express'),
    http = require('http'),
    path = require('path'),
    passport = require("passport"),
    LocalStrategy = require('passport-local').Strategy,
    mongoose = require('mongoose'),
    bcrypt = require('bcrypt'),
    nodemailer = require("nodemailer"),
    SALT_WORK_FACTOR = 10;

var db = mongoose.createConnection('mongodb://localhost/test');

db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function callback() {
    console.log('Connected to DB');
});


var app = express();

var userSchema = mongoose.Schema({
    displayName: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true},
    createdAt: { type: Date},
    updatedAt: { type: Date},
    access:{ type: Boolean},
    confirmed: {type: Boolean},
    confirmationToken: {type: String, required: true}
});

userSchema.pre('save', function(next) {
    var user = this;
    if(!user.isModified('password')) return next();

    bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
        if(err) return next(err);

        bcrypt.hash(user.password, salt, function(err, hash) {
            if(err) return next(err);
            user.password = hash;
            next();
        });
    });
});

userSchema.methods.comparePassword = function(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if(err) return cb(err);
        cb(null, isMatch);
    });
};

userSchema.methods.preSaveComparePassword = function(candidatePassword, cb) {
    if(candidatePassword !== this.password){
        return cb({error: true, info: "Password confirmation was unsuccessful"});
    }else{
        return cb(null)
    }
};

var User = db.model('testUsers', userSchema);
var user = new User({
        displayName: 'artem',
        password: 'secret',
        email: 'myzlio@gmail.com',
        createdAt: new Date(),
        updatedAt: new Date(),
        access: false,
        confirmed: false,
        confirmationToken: "arrtrrrtrtr"
});

passport.use(new LocalStrategy(function(username, password, done) {

    User.findOne({ email: username }, function(err, user) {
        console.log(user);
        if (err) { return done(err); }
        if (!user) { return done(null, false, { message: 'Unknown user ' + email }); }

        user.comparePassword(password, function(err, isMatch) {
            if (err) return done(err);
            if(isMatch) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Invalid password' });
            }
        });
    });
}));

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});


// create reusable transport method (opens pool of SMTP connections)
var smtpTransport = nodemailer.createTransport("SMTP",{
    host: "in.mailjet.com", // hostname
    secureConnection: false, // use SSL
    port: 587, // port for secure SMTP
    auth: {
        user: "7908658af6fbd99ec6ea40ee2387985e",
        pass: "d742abab0bbc5c2398c538da7b0185d4"
    }
});

// setup e-mail data with unicode symbols
var mailOptions = {
    from: "Vlad Tsepelev <vlad@toptechphoto.com>", // sender address
    to: "myzlio@gmail.com", // list of receivers
    subject: "Nodejs SMTP test", // Subject line
    text: "Hi, im just text", // plaintext body
    html: "Hi, <b>im html text</b>" // html body
}

// send mail with defined transport object


// all environments
app.set('port', 3002);
app.set('views', __dirname + '/views');
app.set('view engine', 'jade');
app.use(express.favicon());
app.use(express.logger('dev'));
app.use(express.bodyParser());
app.use(express.methodOverride());
app.use(express.cookieParser('your secret here'));
app.use(express.session({ secret: 'keyboard cat' }));
// Initialize Passport!  Also use passport.session() middleware, to support
// persistent login sessions (recommended).
app.use(passport.initialize());
app.use(passport.session());
app.use(app.router);
app.use(express.static(path.join(__dirname, 'public')));

// development only
if ('development' == app.get('env')) {
  app.use(express.errorHandler());
}

app.get('/', function(req, res){
    res.json({status: "ok"});
});

app.post('/signin', function(req, res, next) {
    passport.authenticate('local', function(err, user, info) {
        if (err) { return next(err) }
        if (!user) {
            req.session.messages =  [info.message];
            console.log(info.message);
            return res.json(false);
        }
        req.logIn(user, function(err) {
            if (err) { return next(err); }
            return res.json(user);
        });
    })(req, res, next);

});

app.post('/signout', function(req, res, next) {
    req.logout();
    return res.json({"action":"logout"});
});

app.post('/signup', function(req, res) {
    var params = req.body;

    var user = new User({
        displayName: params.displayName,
        password: params.password,
        email: params.email,
        createdAt: new Date(),
        updatedAt: new Date(),
        access: false,
        confirmed: false,
        confirmationToken: ""
    });
    require('crypto').randomBytes(48, function(ex, buf) {
        var token = buf.toString('hex');
        user.confirmationToken = token;
        user.preSaveComparePassword(params.passwordConfirmation, function(err) {
            if (err){
                return res.json(err);
            }else{
                user.save(function(err){
                    if(err){
                        return res.json(err);
                    }else{



                        mailOptions.html += "<a href = 'http://localhost:3002/userConfirmaion/" + user.confirmationToken + "' >Confirmation</a>";
                        console.log(mailOptions.html);
                        smtpTransport.sendMail(mailOptions, function(error, response){
                            if(error){
                                return res.json({"action":"email", info: "Message failed"});
                            }else{
                                return res.json(user);
                            }
                            // if you don't want to use this transport object anymore, uncomment following line
                            //smtpTransport.close(); // shut down the connection pool, no more messages
                        });
                    }
                });
            }

        });
    });
});

app.post('/signout', function(req, res, next) {
    req.logout();
    return res.json({"action":"logout"});
});

app.get('/userConfirmaion/:confirmation', function(req, res, next) {
    User.findOne({ confirmationToken: req.params.confirmation }, function(err, user) {
        if (err) { return res.json(err); }
        if (!user) { return res.json(null, false, { message: 'Unknown user ' + email }); }

        user.confirmed = true;
        user.save(function(err){
            if(err){
                return res.json(err);
            }else{
                return res.json(user);
            }
        });

        res.json(user);
    });
});

app.post('/resetPassword', function(req, res) {
    var params = req.body;
    var email = params.email;

    User.findOne({ email: email }, function(err, user) {
        if (err) { return res.json(err); }
        if (!user) { return res.json(null, false, { message: 'Unknown user ' + email }); }
        console.log(params.password);
        user.comparePassword(params.password, function(err, isMatch) {
            var enter = 0;
            if (err){
                return console.dir(err);
            }
            console.log(isMatch);
            if(isMatch) {
                console.log("match");
                user.password  = params.newPassword;
                user.save(function(err){
                    if(err){
                        return res.json(err);
                    }else{
                        console.log("try to save2");
                        user.save(function(err){
                            if(err){
                                return res.json(err);
                            }else{
                                return res.json(user);
                            }
                        });
                    }
                });
            } else {
                return res.json({ message: 'Invalid password' });
            }
        });



        res.json(user);
    });
});


http.createServer(app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});
