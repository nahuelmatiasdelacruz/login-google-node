const Usuario = require("../models/usuario");
const bcryptjs = require("bcryptjs");
const { generarJWT } = require("../helpers/generar-jwt");
const { googleVerify } = require("../helpers/google-verify");

const login = async (req,res) => {
    const{correo,password} = req.body;
    try{
        const usuario = await Usuario.findOne({correo});
        if(!usuario){
            return res.status(400).json({msg: "Usuario / contraseña no son correctos"});
        }
        if(!usuario.estado){
            return res.status(400).json({msg: "Usuario eliminado"});
        }
        const validPassword = bcryptjs.compareSync(password,usuario.password);
        if(!validPassword){
            return res.status(400).json({msg: "Contraseña incorrecta"});
        }
        const token = await generarJWT(usuario.id);

        res.json({
            msg: "Login OK",
            usuario,
            token
        })
    }catch(e){
        return res.status(500).json({msg: "Algo salio mal"});
    }
}

const googleSignIn = async (req,res)=>{
    const {id_token} = req.body;
    try{
        const {name,email,picture} = await googleVerify(id_token);
        let user = await Usuario.findOne({email});
        if(!user){
            const data = {
                nombre: name,
                correo: email,
                rol: "ADMIN_ROLE",
                password: "testing",
                img: picture,
                google: true
            }
            user = new Usuario(data);
            await user.save();
        }
        if(!user.estado){
            return res.status(401).json({
                success: false,
                message: "Usuario negado"
            });
        }
        const token = await generarJWT(user.id);
        res.json({
            user,
            token
        })
    }catch(e){
        console.log(e);
        res.status(400).json({
            success: false,
            msg: "El token no se verificó"
        })
    }
}

module.exports = {login,googleSignIn}