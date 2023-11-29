const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const path = require('path');
const nodemailer = require('nodemailer');
const session = require('express-session'); // Importa express-session aqui
const express = require('express');
const app = express();
const multer = require('multer');


// Cargar las variables de entorno
require('dotenv').config();






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
app.use(express.static(path.join('C:', 'Users', 'Usuario', 'Desktop', 'ugb-store')));
app.use('/uploads', express.static('uploads'));








// Configuración de CORS
const corsOptions = {
    origin: 'http://127.0.0.1:5500',
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
    password: String,
    isAdmin: {
        type: Boolean,
        default: false
    }
});


const Student = mongoose.model('Student', studentSchema);

// Definición del esquema y modelo de docentes
const teacherSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, unique: true }, // Hacer el email único
    password: String
});

const Teacher = mongoose.model('Teacher', teacherSchema);




const superUserSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, unique: true },
    password: String
});

const SuperUser = mongoose.model('SuperUser', superUserSchema);




const productSchema = new mongoose.Schema({
    name: String,
    category: String,
    description: String,
    price: Number,
    offer: String,
    availability: String,
    imageUrl: String,
    stock: Number,
    popular: { // Agregado el campo popular
        type: Boolean,
        default: false
    }
});

const Product = mongoose.model('Product', productSchema);


const bannerSchema = new mongoose.Schema({
    imageUrl: String
    // Puedes agregar más campos si es necesario
});

const Banner = mongoose.model('Banner', bannerSchema);


// Definición del esquema y modelo para ResetPassword
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
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS  
    },
    tls: {
        rejectUnauthorized: false
    }
});




// Configuración de Multer con ruta absoluta
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, 'uploads/'))
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname)
    }
});
const upload = multer({ storage: storage });



app.post('/request-password-reset', async (req, res) => {
    const email = req.body.email;
    let user = await Student.findOne({ email: email });

    if (!user) {
        user = await Teacher.findOne({ email: email });
        if (!user) {
            return res.status(400).json({ message: 'Correo no registrado.' });
        }
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
        from: 'ugbstore.assistance@outlook.com',
        to: email,
        subject: 'Restablecimiento de Contraseña',
        text: `Hola,

Has solicitado restablecer tu contraseña. Por favor, haz clic en el siguiente enlace para restablecerla:

http://127.0.0.1:5500/reset-password.html?token=${token}

Si no has solicitado este cambio, ignora este correo.

Saludos,
Tu equipo`
    };

    // Enviar el correo
    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error al enviar el correo:', error);
            return res.status(500).json({ message: 'Error al enviar el correo de restablecimiento.' });
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

    let user = null;

    // Intenta encontrar al usuario en SuperUser
    const superUser = await SuperUser.findOne({ email: req.body.email });

    if (superUser) {
        console.log("SuperUser encontrado:", superUser);
        user = superUser;
    } else {
        // Si no es un superusuario, intenta encontrarlo en Student
        const student = await Student.findOne({ email: req.body.email });
        if (student) {
            console.log("Student encontrado:", student);
            user = student;
        } else {
            // Si no es un estudiante, intenta encontrarlo en Teacher
            const teacher = await Teacher.findOne({ email: req.body.email });
            if (teacher) {
                console.log("Teacher encontrado:", teacher);
                user = teacher;
            }
        }
    }

    if (!user) {
        console.log("Correo no encontrado en la base de datos.");
        return res.status(400).json({ message: "El usuario o la contraseña no coincide. Por favor, verifica tus datos." });
    }

    console.log("Contraseña ingresada:", req.body.password);
    console.log("Contraseña hasheada en la base de datos:", user.password);

    console.log("Comparando contraseñas...");
    const isMatch = await bcrypt.compare(req.body.password, user.password);
    console.log("Resultado de la comparación:", isMatch);

    if (!isMatch) {
        console.log("Contraseña incorrecta.");
        return res.status(400).json({ message: "El usuario o la contraseña no coincide. Por favor, verifica tus datos." });
    }

    // Guardar el ID del usuario en la sesión
    req.session.userId = user._id;

    console.log("Usuario guardado en la sesión:", req.session.userId);

    // Enviar respuesta con información sobre si el usuario es administrador o no
    res.json({ 
        success: true, 
        message: 'Inicio de sesión exitoso!',
        isAdmin: user instanceof SuperUser,  // Esto determinará si el usuario es un SuperUser o no
        isTeacher: user instanceof Teacher  // Esto determinará si el usuario es un docente
    });
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
    console.log("Ruta /logout accedida"); // Añade esta línea
req.session.destroy((err) => {
        if (err) {
            console.error("Error al destruir la sesión:", err);
            return res.status(500).json({ success: false, message: 'Error al cerrar sesión.' });
        }
        console.log("Sesión cerrada exitosamente.");
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
    console.log("Contenido de la sesión:", req.session);
    if (!req.session.userId) {
        return res.status(401).send('No user is logged in.');
    }

    try {
        let user = await Student.findById(req.session.userId);
        if (!user) {
            user = await SuperUser.findById(req.session.userId);
            if (!user) {
                user = await Teacher.findById(req.session.userId); // Buscar en la colección Teacher
                if (!user) {
                    return res.status(404).send('User not found.');
                }
            }
        }

        res.json({ 
            name: `${user.firstName} ${user.lastName}`,
            code: user.studentCode || (user instanceof Teacher ? "Teacher" : "Admin"),  // Si es un Teacher, mostrará "Teacher", si es un SuperUser mostrará "Admin"
            email: user.email  // Añadir el campo email aquí
        });
    } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).send('Error fetching user.');
    }
});


app.get('/products', async (req, res) => {
    console.log("Solicitud de lista de productos");
    try {
        let query = {};

        // Filtrar por categoría
        if (req.query.category && req.query.category !== 'All') {
            query.category = req.query.category;
        }

        // Filtrar por término de búsqueda (puedes ajustar esto según tus necesidades)
        if (req.query.search) {
            query.name = new RegExp(req.query.search, 'i'); // Buscar por nombre de producto que contenga el término de búsqueda (no sensible a mayúsculas/minúsculas)
        }

        const products = await Product.find(query);
        console.log("Productos recuperados de la base de datos:", products);
        res.json(products);
    } catch (error) {
        console.error("Error al obtener los productos:", error);
        res.status(500).send('Error al obtener los productos.');
    }
});




// Ruta para obtener todos los banners
app.get('/banners', async (req, res) => {
    console.log("Solicitud de lista de banners");
    try {
        const banners = await Banner.find();
        res.json(banners);
    } catch (error) {
        console.error("Error al obtener los banners:", error);
        res.status(500).send('Error al obtener los banners.');
    }
});





app.post('/upload-product', upload.single('productImage'), (req, res) => {
    console.log("Intento de subir producto con datos:", req.body);
    
   
    const isPopular = req.body.productPopular && req.body.productPopular.includes('on');

    const product = new Product({
        name: req.body.productName,
        imageUrl: '/uploads/' + req.file.filename,
        category: req.body.productCategory,
        description: req.body.productDescription,
        price: req.body.productPrice,
        offer: req.body.productOffer,
        availability: req.body.productAvailability,
        stock: req.body.productStock,  // Asegúrate de que el nombre del campo coincida con el nombre que envías desde el frontend
        popular: isPopular // Usar el valor ajustado
    });

    product.save().then(() => {
        res.json({ success: true, message: 'Producto subido con éxito' });
    }).catch(err => {
        res.json({ success: false, message: 'Error al subir el producto', error: err });
    });
});

app.delete('/products/:id', async (req, res) => {
    const productId = req.params.id;
   
    try {
        await Product.findByIdAndDelete(productId);
        res.status(200).json({ success: true, message: 'Producto eliminado con éxito.' });
        
    } catch (err) {
        console.error("Error al eliminar el producto:", err);
        res.status(500).json({ success: false, message: 'Error al eliminar el producto.' });
       
    }
});


// Ruta para actualizar un producto
app.put('/products/:id', async (req, res) => {
    const productId = req.params.id;
    const updatedProductData = req.body;

    try {
        const updatedProduct = await Product.findByIdAndUpdate(productId, updatedProductData, { new: true });
        if (!updatedProduct) {
            return res.status(404).json({ success: false, message: 'Producto no encontrado.' });
        }
        res.status(200).json({ success: true, message: 'Producto actualizado con éxito.', product: updatedProduct });
    } catch (err) {
        console.error("Error al actualizar el producto:", err);
        res.status(500).json({ success: false, message: 'Error al actualizar el producto.' });
    }
});



app.post('/upload-banner', upload.single('bannerImage'), async (req, res) => {
    console.log("Intento de subir banner con datos:", req.body);

    const banner = new Banner({
        imageUrl: '/uploads/' + req.file.filename
    });

    try {
        const savedBanner = await banner.save();
        res.json({ success: true, message: 'Banner subido con éxito', bannerId: savedBanner._id });
    } catch (err) {
        res.json({ success: false, message: 'Error al subir el banner', error: err });
    }
});

app.delete('/banners/:id', async (req, res) => {
    const bannerId = req.params.id;
   
    try {
        await Banner.findByIdAndDelete(bannerId);
        res.status(200).json({ success: true, message: 'Banner eliminado con éxito.' });
        
    } catch (err) {
        console.error("Error al eliminar el banner:", err);
        res.status(500).json({ success: false, message: 'Error al eliminar el banner.' });
       
    }
});

app.get('/banners', async (req, res) => {
    console.log("Accediendo a la ruta de banners...");
    try {
        const banners = await Banner.find();
        if (banners.length === 0) {
            console.log("No se encontraron banners en la base de datos.");
        } else {
            console.log("Banners recuperados de la base de datos:", banners);
        }
        res.json(banners);
    } catch (error) {
        console.error("Error al obtener los banners:", error);
        res.status(500).send('Error al obtener los banners.');
    }
});

// Ruta POST para registrar docentes
app.post('/registerTeacher', async (req, res) => {
    console.log("Cuerpo de la solicitud:", req.body);

    if (!req.body.password) {
        console.error("Contraseña no proporcionada en la solicitud.");
        return res.status(400).json({ success: false, message: 'Contraseña no proporcionada.' });
    }

    try {
        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        const teacher = new Teacher({
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            password: hashedPassword
        });

        await teacher.save();
        res.json({ success: true, message: 'Registro exitoso.' });
        
    } catch (error) {
        if (error.code === 11000) {
            if (error.keyPattern.email) {
                return res.status(400).json({ success: false, message: 'El correo ya está registrado.' });
            }
        }
        console.error("Error al registrar el docente:", error);
        res.status(500).json({ success: false, message: 'Error al registrar. Inténtalo de nuevo.' });
    }
});

app.get('/popular-products', async (req, res) => {
    try {
        const popularProducts = await Product.find({ popular: true });
        res.json(popularProducts);
    } catch (error) {
        console.error("Error al obtener los productos populares:", error);
        res.status(500).json({ message: 'Error al obtener los productos populares.' });
    }
});



app.get('/offer-products', async (req, res) => {
    try {
        const offerProducts = await Product.find({ offer: { $gt: "0" } });
        res.json(offerProducts);
    } catch (error) {
        console.error("Error al obtener los productos en oferta:", error);
        res.status(500).json({ message: 'Error al obtener los productos en oferta.' });
    }
});

app.get('/reservations', async (req, res) => {
    try {
        const reservations = await Reservation.find();
        res.json(reservations);
    } catch (error) {
        console.error("Error al obtener las reservas:", error);
        res.status(500).send('Error al obtener las reservas.');
    }
});

app.post('/reserve-product', async (req, res) => {
    console.log(req.body); // Esto mostrará todo el cuerpo de la solicitud
    const { name, email, productId, pickupTime } = req.body;

    if (!name || !email || !productId || !pickupTime) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
    }

    const reservation = new Reservation({
        name,
        email,
        product: productId,
        pickupTime: new Date(pickupTime)
    });

    try {
        await reservation.save();
        res.json({ success: true, message: 'Reserva realizada con éxito.' });
    } catch (error) {
        console.error("Error al guardar la reserva:", error);
        res.status(500).json({ message: 'Error al realizar la reserva.' });
    }
});

app.delete('/reservations/:id', async (req, res) => {
    const reservationId = req.params.id;
   
    try {
        await Reservation.findByIdAndDelete(reservationId);
        res.status(200).json({ success: true, message: 'Reserva eliminada con éxito.' });
    } catch (err) {
        console.error("Error al eliminar la reserva:", err);
        res.status(500).json({ success: false, message: 'Error al eliminar la reserva.' });
    }
});

const commentSchema = new mongoose.Schema({
    text: String,
    userName: String,  // Añade un campo para el nombre del usuario
    product: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Product'
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});


const Comment = mongoose.model('Comment', commentSchema);

app.post('/add-comment', async (req, res) => {
    const { productId, comment, userName } = req.body;
    
    
    try {
        // Buscar el producto por nombre
        const product = await Product.findOne({ name: productId });
        if (!product) {
            return res.status(400).json({ success: false, message: 'Producto no encontrado' });
        }

        // Crear un nuevo comentario usando el ObjectId del producto
        const newComment = new Comment({
            product: product._id,
            text: comment,
            userName: userName  // Aquí deberías obtener el nombre real del usuario
        });
        
        await newComment.save();
        res.json({ success: true, message: 'Comentario guardado con éxito' });
    } catch (error) {
        console.error('Error al guardar el comentario:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});


app.get('/get-comments', async (req, res) => {
    try {
        // Aquí, estamos usando populate para obtener el nombre del producto asociado al comentario.
        const comments = await Comment.find().populate('product', 'name');
        res.json(comments);
    } catch (error) {
        console.error('Error al obtener los comentarios:', error);
        res.status(500).json({ success: false, message: 'Error interno del servidor' });
    }
});



// Iniciar el servidor en el puerto 3000
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);

});