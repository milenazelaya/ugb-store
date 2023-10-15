const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
require('dotenv').config();

// Conexión a MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/users', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Conectado a MongoDB'))
    .catch(err => console.error('Error al conectar a MongoDB', err));

// Definición del esquema y modelo para SuperUser
const superUserSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email:  { type: String, unique: true },
    password: String
});

const SuperUser = mongoose.model('SuperUser', superUserSchema);

async function createSuperAdmin() {
    console.log("Creando superadministrador...");

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(process.env.SUPER_USER_PASSWORD, salt);

    const superAdmin = new SuperUser({
        firstName: 'Super',
        lastName: 'Admin',
        email: process.env.SUPER_USER_EMAIL,
        password: hashedPassword
    });

    await superAdmin.save();
    console.log('Superadmin creado exitosamente!');
    mongoose.connection.close();
}

createSuperAdmin();
