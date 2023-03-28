const express = require("express");
const cors = require("cors");
const { dbConnection } = require("../database/config");

class Server {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 3000;
        this.usuariosPath = "/api/usuarios";
        this.authPath = "/api/auth"
        // Conectar a base de datos
        this.conectarDb();
        // Middleware
        this.middlewares();
        // Rutas de la aplicacion
        this.routes();
    }
    async conectarDb(){
        await dbConnection();
    }
    middlewares() {
        // Directorio publico
        this.app.use(express.static("public"));
        // Parseo y lectura del body
        this.app.use(express.json());
        this.app.use(express.urlencoded({extended: true}));
        //CORS
        this.app.use(cors());
    }
    routes() {
        this.app.use(this.authPath,require("../routes/auth"));
        this.app.use(this.usuariosPath,require("../routes/user"));
    }
    listen() {
        this.app.listen(this.port, () => {
            console.log("Server running on port " + this.port);
        });
    }
}

module.exports = Server;
