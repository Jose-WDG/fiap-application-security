const { randomUUID } = require('crypto');

async function connect(){
    if(global.connection && global.connection.state !== 'disconnected')
        return global.connection;

    const mysql = require("mysql2/promise");
    const connection = await mysql.createConnection({
        host: process.env.DB_HOST || 'localhost',
        port: 3306,
        user: 'root',
        password: '',
        database: 'lab5',
        multipleStatements: true
      } );
    console.log("Conectou no MySQL!");
    global.connection = connection;
    return connection;
}

async function selectUsers(){
    const conn = await connect();

    const query = `SELECT * FROM users LIMIT 1000;`;
    console.log(`Executando query: ${query}`);

    try{
        const [rows, fields] = await conn.execute(query);
        console.log(`Rows: ${JSON.stringify(rows)}`);
        return rows;
    }catch(err){
        console.err(err);
        throw {code: 500, message: 'Erro inesperado ao tentar buscar usuário'};
    }
}

async function selectUserByLogin(user, password){
    const conn = await connect();

    const query = "SELECT * FROM `users` WHERE `user` = ? AND `password` = ?";
    console.log(`Executando query: ${query}`);

    try{
        const [rows, fields] = await conn.execute(query, [user, password]);
        return rows;
    }catch(err){
        console.log(err);
        throw {code: 500, message: 'Erro inesperado ao tentar logar usuário'};
    }
}

async function selectUserByLogin(user){
    const conn = await connect();
    
    const query = "SELECT * FROM `users` WHERE `user` = ?;";
    console.log(`Executando query: ${query}`);
    
    const [rows, fields] = await connection.execute(query, [user]);

    return rows;
 }
 
async function insertUser(user, password){
    const conn = await connect();

    const query = "INSERT INTO users(id, user, password) VALUES (?, ?, ?);";
    console.log(`Executando query: ${query}`);

    try{
        const [rows, fields] = await conn.execute(query, [randomUUID(), user, password]);
        return rows;
    }catch(err){
        if(err.errno === 1062){
            throw {code: 500, message: 'Erro ao cadastrar usuário: Usuário já existe'};
        }else{
            console.err(err);
            throw {code: 500, message: 'Erro inesperado ao tentar cadastrar usuário'};
        }
    }
}

module.exports = {selectUserByLogin, selectUsers, insertUser}
