//Criando config para colocar ssl no servidor que vai usar https
const fs = require('fs');
const https = require('https');
const privateKey  = fs.readFileSync('./sslcert/selfsigned.key', 'utf8');
const certificate = fs.readFileSync('./sslcert/selfsigned.crt', 'utf8');
const credentials = {key: privateKey, cert: certificate};
const port = 3001;

//Criando config para o servidor que vai usar http
const http = require('http')
const portHttp = 3000

//inicia o express
const express = require('express');
const app = express();

//pega class que trata a cripto do programa
const cript = require("./cript");

//pega a class que cuida do banco de dados
const db = require("./db");

//
var cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const { randomUUID } = require('crypto');
var RateLimit = require('express-rate-limit');
var limiter = new RateLimit({
    windowMs: 15 * 60 * 1000,
    max: 50,
    delayMs: 0,
    message: "Too many accounts created from this IP, please try again after an hour"
});

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(limiter);

app.get('/users', async (req, res, next) => {
    if (req.cookies["auth"] !== "true") {
        return res.status(401).send();
    }
    console.log("Retornou todos usuarios!");
    var resp = await db.selectUsers()
    res.status(200).json(resp);
});

app.post('/register', async (req, res, next) => {

    try {
        if (!req.body.password.match("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{10,})")) {
            return res.status(422).json({ error: "A senha é muito fraca", message: "Deve conter ao menos 10 caracteres entre maiúsculas, minúsculas, numéricos e caracteres especiais" });
        }

        const users = await db.insertUser(req.body.username, cript.hash(req.body.password));

        if (users.affectedRows) {
            console.log(`Usuário ${req.body.username} registrado com sucesso!`);
            return res.status(201).send(`Usuário ${req.body.username} registrado com sucesso!`);
        }
    } catch (err) {
        return res.status(err.code).json(err);
    }
});

app.post('/login', async (req, res, next) => {

    const users = await db.selectUserByLogin(req.body.username);
    
    if(users.length && cript.validate(users[0].password, req.body.password)){ 
        console.log("Fez login e gerou token!");
        res.cookie("auth", "true");
        return res.status(200).send();
    }

    return res.status(401).send('Login inválido!');
});

app.post('/logout', function (req, res) {
    console.log("Fez logout e cancelou o token!");
    res.cookie("auth", "false").status(200).send('done');
});

//Iniciando servidor no https
var httpsServer = https.createServer(credentials, app);
httpsServer.listen(port, () => {
    console.log(`Example app listening https at https://localhost:${port}`)
})

//Iniciando servidor no http
var httpServer = http.createServer(app)
httpServer.listen(portHttp,() => {
    console.log(`Example app listening http at http://localhost:${portHttp}`)
})




