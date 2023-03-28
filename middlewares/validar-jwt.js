const jwt = require('jsonwebtoken');
const Usuario = require("../models/usuario");

const validarJwt = async (req,res,next) => {
    const token = req.header("x-token");
    if(!token){
        return res.status(401).json({
            msg: "No hay token en la petición"
        })
    }
    try{
        const {uid} = jwt.verify(token,process.env.SECRETORPRIVATEKEY);
        const usuario = await Usuario.findById(uid);
        if(!usuario){
            return res.status(401).json({
                msg: "El usuario no existe en la db"
            });
        }
        if(!usuario.estado){
            return res.status(401).json({
                msg: "El usuario está deshabilitado"
            });
        }
        req.usuario = usuario;
        next();
    }catch(e){
        res.status(401).json({
            msg: "Token no valido"
        })
    }
}

module.exports = {validarJwt}