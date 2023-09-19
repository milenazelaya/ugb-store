const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const path = require('path');
const nodemailer = require('nodemailer');
const session = require('express-session'); // Importa express-session aqui

// Cargar las variables de entorno
require('dotenv').config();

const app = express();

// Configuración de express-session aqui
app.use(session({
    secret: 'tuSecretoAqui',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, httpOnly: true, sameSite: 'lax' }
}));



// Configuración de bodyParser y CORS
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
//app.use(cors());
app.use(express.static(path.join('C:', 'Escritorio', 'ugb store')));

// Configuración de CORS
const corsOptions = {
    origin: 'http://127.0.0.1:5500', // Especifica el origen permitido AQUI
    credentials: true
};
app.use(cors(corsOptions));



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

const resetPasswordSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'Student'
    },
    resetPasswordToken: {
        type: String,
        required: true
    },
    expire: {
        type: Date,
        required: true
    }
});

const ResetPassword = mongoose.model('ResetPassword', resetPasswordSchema);

const crypto = require('crypto'); // para generar tokens

// Configuración de Nodemailer
let transporter = nodemailer.createTransport({
    host: 'smtp-mail.outlook.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER, // Usando la variable de entorno
        pass: process.env.EMAIL_PASS  // Usando la variable de entorno
    }
});



app.post('/request-password-reset', async (req, res) => {
    const email = req.body.email;
    const user = await Student.findOne({ email: email });

    if (!user) {
        return res.status(400).send('Correo no registrado.');
    }

    // Generar un token
    const token = crypto.randomBytes(20).toString('hex');

    // Almacenar el token en la base de datos con una fecha de vencimiento
    const resetPasswordRecord = new ResetPassword({
        userId: user._id,
        resetPasswordToken: token,
        expire: Date.now() + 3600000
    });

    await resetPasswordRecord.save();

    // Configurar opciones del correo
    let mailOptions = {
        from: 'nathy.zelaya5@gmail.com',
        to: email,
        subject: 'Restablecimiento de Contraseña',
        text: `Hola,

Has solicitado restablecer tu contraseña. Por favor, haz clic en el siguiente enlace para restablecerla:

http://localhost:3000/reset-password.html?token=${token}

Si no has solicitado este cambio, ignora este correo.

Saludos,
Tu equipo`
    };

    // Enviar el correo
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error al enviar el correo:', error);
            return res.status(500).send('Error al enviar el correo de restablecimiento.');
        } else {
            console.log('Correo enviado exitosamente:', info.response);
            res.send('Solicitud de recuperación enviada. Por favor, revisa tu correo.');
        }
    });
});



// Ruta POST para registrar estudiantes
app.post('/register', async (req, res) => {
    console.log("Cuerpo de la solicitud:", req.body);

    const emailPrefix = req.body.email.split('@')[0].toUpperCase();
    if (emailPrefix !== req.body.studentCode) {
        return res.status(400).json({ success: false, message: 'El correo y el código de estudiante deben coincidir.' });
    }


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
            return res.status(400).json({ message: "el usuario o la contraseña no coincide por favor verifique sus datos" });
        }
        
        const validPassword = await bcrypt.compare(req.body.password, student.password);
                
        if (!validPassword) {
            console.log("Contraseña incorrecta.");
            return res.status(400).json({ message: "el usuario o la contraseña no coincide por favor verifique sus datos" });
        }

        // Guardar el ID del usuario en la sesión
        req.session.userId = student._id;

        console.log("Inicio de Sesion");
        res.json({ success: true, message: 'Inicio de sesión exitoso!' });
    } catch (error) {
        console.error("Error al iniciar sesión:", error);
        res.status(500).json({ message: 'Error al iniciar sesión. Inténtalo de nuevo.' });
    }
});

app.post('/reset-password', async (req, res) => {
    const token = req.body.token;
    const newPassword = req.body.newPassword;

    const resetPasswordRecord = await ResetPassword.findOne({ resetPasswordToken: token });

    if (!resetPasswordRecord) {
        return res.status(400).json({ message: 'Token inválido o expirado.' });
    }
    
    if (Date.now() > resetPasswordRecord.expire) {
        return res.status(400).json({ message: 'Token expirado.' });
    }
    

    const user = await Student.findById(resetPasswordRecord.userId);
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    // Eliminar el token de recuperación ya que ya no es necesario
    await ResetPassword.findByIdAndDelete(resetPasswordRecord._id);
    res.json({ message: 'Contraseña actualizada con éxito.' });
});

//aqui
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) throw err;
        res.json({ success: true, message: 'Logged out successfully' });
    });
});


app.get('/algunaRuta', (req, res) => {
    if (req.session.userId) {
        // El usuario está autenticado. aqui
        // Puedes hacer algo específico para usuarios autenticados aquí.
    } else {
        // El usuario no está autenticado.
        // Puedes redirigir al usuario a la página de inicio de sesión o mostrar un mensaje de error.
    }
});

app.get('/current-user', async (req, res) => {
    if (!req.session.userId) {
        return res.status(401).send('No user is logged in.');
    }

    try {
        const student = await Student.findById(req.session.userId);
        if (!student) {
            return res.status(404).send('User not found.');
        }

        res.json({ 
            name: `${student.firstName} ${student.lastName}`,
            code: student.studentCode  // Agregar el código del estudiante a la respuesta
        });
    } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).send('Error fetching user.');
    }
});



// Iniciar el servidor en el puerto 3000
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);

});