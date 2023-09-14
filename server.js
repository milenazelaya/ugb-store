const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const path = require('path');


const app = express();

// Configuración de bodyParser y CORS
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join('C:', 'Escritorio', 'ugb store')));


// Conexión a MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/users', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Could not connect to MongoDB', err));

// Definición del esquema y modelo de estudiantes
const studentSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email:  { type: String, unique: true }, // Hacer el email único
    studentCode:{ type: String, unique: true }, // Hacer el código de estudiante único
    password: String
});

const Student = mongoose.model('Student', studentSchema);

// Ruta POST para registrar estudiantes
app.post('/register', async (req, res) => {
    console.log("Cuerpo de la solicitud:", req.body);

    if (!req.body.password) {
        console.error("Contraseña no proporcionada en la solicitud.");
        return res.status(400).json({ success: false, message: 'Contraseña no proporcionada.' });
    }

    try {
        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        const student = new Student({
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            studentCode: req.body.studentCode,
            password: hashedPassword
        });

        await student.save();
        res.json({ success: true, message: 'Registro exitoso.' });
        
    } catch (error) {
        if (error.code === 11000) {
            if (error.keyPattern.email) {
                return res.status(400).json({ success: false, message: 'El correo ya está registrado.' });

            }
            if (error.keyPattern.studentCode) {
                return res.status(400).json({ success: false, message: 'El código de estudiante ya está registrado.' });
            }
        }
        console.error("Error al registrar el estudiante:", error);
        res.status(500).json({ success: false, message: 'Error al registrar. Inténtalo de nuevo.' });
    }
});

app.post('/login', async (req, res) => {
    console.log("Datos recibidos:", req.body);
    try {
        const student = await Student.findOne({ email: req.body.email });

        if (!student) {
            console.log("Correo no encontrado en la base de datos.");
            return res.status(400).send("el usuario o la contraseña no coincide por favor verifique sus datos");
        }
        
        const validPassword = await bcrypt.compare(req.body.password, student.password);
                
        if (!validPassword) {
            console.log("Contraseña incorrecta.");
            return res.status(400).send("el usuario o la contraseña no coincide por favor verifique sus datos");
        }

        res.send('Inicio de sesión exitoso!');
    } catch (error) {
        console.error("Error al iniciar sesión:", error);
        res.status(500).send('Error al iniciar sesión. Inténtalo de nuevo.');
    }
});

// Iniciar el servidor en el puerto 3000
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);

});