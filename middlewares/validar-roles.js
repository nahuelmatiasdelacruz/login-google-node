
const esAdminRole = async (req,res,next)=> {
    const {rol,nombre} = req.usuario;
    console.log(rol);
    if(rol!=="ADMIN_ROLE"){
        return res.status(401).json({
            msg: `El usuario ${nombre} no es administrador`
        });
    }
    next();
}
const tieneRol = (...roles)=>{
    return (req,res,next)=>{
        const {rol} = req.usuario;
        if(!roles.includes(rol)){
            return res.status(401).json({
                msg: `El servicio requiere uno de estos roles: ${roles}`
            })
        }

        next();
    }
}
module.exports = {esAdminRole,tieneRol};