const { Router } = require("express");
const { check } = require("express-validator");
const { usuariosGet, usuariosPut, usuariosPost, usuariosDelete } = require("../controllers/user");
const { isValidRole, existeEmail,existeUsuarioById} = require("../helpers/db-validators");
const {validarCampos,validarJwt,esAdminRole,tieneRol} = require("../middlewares");
const router = Router();

router.get("/", usuariosGet);
router.put("/:id",[
    check("id","No es un ID valido").isMongoId(),
    check("id").custom(existeUsuarioById),
    check("rol").custom(isValidRole),
    validarCampos
],usuariosPut);
router.post("/",[
    check("password","El password es obligatorio").isLength({min: 6}),
    check("correo","El correo no es valido").isEmail(),
    check("nombre","El nombre es obligatorio").not().isEmpty(),
    check("correo").custom(existeEmail),
    check("rol").custom(isValidRole),
    validarCampos
],usuariosPost);
router.delete("/:id",[
    validarJwt,
    //esAdminRole,
    tieneRol("ADMIN_ROLE","VENTAS_ROLE"),
    check("id","No es un ID valido").isMongoId(),
    check("id").custom(existeUsuarioById),
    validarCampos
], usuariosDelete);

module.exports = router;