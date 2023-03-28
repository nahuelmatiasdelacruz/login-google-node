const mongoose = require("mongoose");
const dbConnection = async () => {
    try{
        await mongoose.connect(process.env.MONGODB_CONN,{
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log("Base de datos CONECTADA!");
    }catch(err){
        console.log(err);
        throw new Error("Error de conexión a la base de datos");
    }
}

module.exports = {dbConnection}