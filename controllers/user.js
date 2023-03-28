const { response } = require("express");
const bcryptjs = require("bcryptjs");
const Usuario = require("../models/usuario");
const usuariosGet = async (req, res = response) => {
	const { limite = 0, desde = 0 } = req.query;
	const [total,usuarios] = await Promise.all([Usuario.find({ estado: true }).skip(desde).limit(limite), Usuario.countDocuments({ estado: true })]);
	res.json({
        total,
        usuarios
    });
};
const usuariosPut = async (req, res = response) => {
	const id = req.params.id;
	const { _id, password, google, correo, ...resto } = req.body;

	if (password) {
		const salt = bcryptjs.genSaltSync();
		resto.password = bcryptjs.hashSync(password, salt);
	}
	const usuario = await Usuario.findByIdAndUpdate(id, resto, { new: true });
	res.json(usuario);
};
const usuariosPost = async (req, res = response) => {
	const { nombre, correo, password, rol } = req.body;
	const usuario = new Usuario({ nombre, correo, password, rol });

	const salt = bcryptjs.genSaltSync();
	usuario.password = bcryptjs.hashSync(password, salt);

	await usuario.save();
	res.json({
		msg: "Post api - Controlador",
		usuario,
	});
};
const usuariosDelete = async (req, res = response) => {
	const {id} = req.params;
	const usuario = await Usuario.findByIdAndUpdate(id,{estado: false});
	res.json({usuario});
};
module.exports = {
	usuariosGet,
	usuariosDelete,
	usuariosPost,
	usuariosPut,
};
