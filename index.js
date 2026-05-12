require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const bcrypt = require('bcrypt');
const Joi = require('joi');

const saltRounds = 12;
const app = express();
const port = 3000;

const expireTime = 1 * 60 * 60 * 1000; // 1 hour in milliseconds

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

// MongoDB
const MongoClient = require('mongodb').MongoClient;
const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`;
const database = new MongoClient(atlasURI);
const userCollection = database.db(mongodb_database).collection('users');

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

app.use((req, res, next) => {
    res.locals.authenticated = req.session.authenticated || false;
    res.locals.user_type = req.session.user_type || '';
    next();
});

function sessionValidation(req, res, next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect('/login');
    }
}

function adminAuthorization(req, res, next) {
    if (req.session.user_type === 'admin') {
        next();
    } else {
        res.status(403);
        res.render('403');
    }
}

app.get('/', (req, res) => {
    res.render('index', { name: req.session.name });
});

app.get('/signup', (req, res) => {
    res.render('signup', { errorMessage: null });
});

app.post('/signupSubmit', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    if (!name) {
        res.render('signup', { errorMessage: 'Name is required.' });
        return;
    }
    if (!email) {
        res.render('signup', { errorMessage: 'Email is required.' });
        return;
    }
    if (!password) {
        res.render('signup', { errorMessage: 'Password is required.' });
        return;
    }

    const schema = Joi.object({
        name: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().max(40).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render('signup', { errorMessage: validationResult.error.message });
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({
        name: name,
        email: email,
        password: hashedPassword,
        user_type: 'user'
    });

    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.name = name;
    req.session.user_type = 'user';
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
});

app.get('/login', (req, res) => {
    res.render('login', { errorMessage: null });
});

app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().email().max(40).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.render('login', { errorMessage: 'Invalid email/password combination.' });
        return;
    }

    const result = await userCollection.find({ email: email })
        .project({ name: 1, email: 1, password: 1, user_type: 1, _id: 1 })
        .toArray();

    if (result.length != 1) {
        console.log("user not found");
        res.render('login', { errorMessage: 'Invalid email/password combination.' });
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
        return;
    }
    else {
        console.log("incorrect password");
        res.render('login', { errorMessage: 'Invalid email/password combination.' });
        return;
    }
});

app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
    res.render('members', { name: req.session.name, images: images });
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const users = await userCollection.find()
        .project({ name: 1, email: 1, user_type: 1, _id: 1 })
        .toArray();

    res.render('admin', { users: users });
});

app.get('/admin/promote/:email', sessionValidation, adminAuthorization, async (req, res) => {
    var email = req.params.email;

    const schema = Joi.string().email().max(40).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/admin');
        return;
    }

    await userCollection.updateOne(
        { email: email },
        { $set: { user_type: 'admin' } }
    );
    res.redirect('/admin');
});

app.get('/admin/demote/:email', sessionValidation, adminAuthorization, async (req, res) => {
    var email = req.params.email;

    const schema = Joi.string().email().max(40).required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect('/admin');
        return;
    }

    await userCollection.updateOne(
        { email: email },
        { $set: { user_type: 'user' } }
    );
    res.redirect('/admin');
});

app.use(express.static(__dirname + "/public"));

app.use((req, res) => {
    res.status(404);
    res.render('404');
});

app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});