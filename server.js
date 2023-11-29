process.env.TZ = 'America/El_Salvador';
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
    stock: {
        type: Number,
        required: true,
        min: [0, 'El stock no puede ser negativo']
    },
    popular: { // Agregado el campo popular
        type: Boolean,
        default: false
    },
    isReserved: { // Campo nuevo para indicar si el producto está reservado
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



// Ruta POST para solicitar restablecimiento de contraseña
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

    // Intenta encontrar al usuario primero en SuperUser y luego en RegularUser
    let user = await SuperUser.findById(resetPasswordRecord.userId);
    if (!user) {
        user = await RegularUser.findById(resetPasswordRecord.userId);
    }

    if (!user) {
        return res.status(400).json({ message: 'Usuario no encontrado.' });
    }

    // Actualiza la contraseña del usuario
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    // Elimina el token de recuperación, ya que ya no es necesario
    await ResetPassword.findByIdAndDelete(resetPasswordRecord._id);

    res.json({ message: 'Contraseña actualizada con éxito.' });
});


// Ruta POST para registrar usuarios
app.post('/register', async (req, res) => {
    console.log("Cuerpo de la solicitud:", req.body);

    // Validación del formato del correo electrónico
    if (!/^[a-zA-Z0-9._%+-]+@ugb\.edu\.sv$/.test(req.body.email)) {
        return res.status(400).json({ success: false, message: 'El correo debe terminar con @ugb.edu.sv' });
    }

    if (!req.body.password) {
        console.error("Contraseña no proporcionada en la solicitud.");
        return res.status(400).json({ success: false, message: 'Contraseña no proporcionada.' });
    }

    try {
        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(req.body.password, salt);

        const user = new RegularUser({
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            password: hashedPassword
        });

        await user.save();
        res.json({ success: true, message: 'Registro exitoso.' });
        
    } catch (error) {
        if (error.code === 11000 && error.keyPattern.email) {
            return res.status(400).json({ success: false, message: 'El correo ya está registrado.' });
        }
        console.error("Error al registrar el usuario:", error);
        res.status(500).json({ success: false, message: 'Error al registrar. Inténtalo de nuevo.' });
    }
});

app.post('/login', async (req, res) => {
    console.log("Datos recibidos:", req.body);

    // Intentar encontrar al usuario en SuperUser
    let user = await SuperUser.findOne({ email: req.body.email });
    let isAdmin = false;

    // Si no se encuentra en SuperUser, buscar en RegularUser
    if (!user) {
        user = await RegularUser.findOne({ email: req.body.email });
    } else {
        isAdmin = true; // El usuario es un SuperUser, por lo tanto, es administrador
    }

    // Si no se encuentra el usuario en ninguna de las dos colecciones
    if (!user) {
        console.log("Correo no encontrado en la base de datos.");
        return res.status(400).json({ message: "El usuario o la contraseña no coincide. Por favor, verifica tus datos." });
    }

    // Comparar la contraseña ingresada con la almacenada en la base de datos
    const isMatch = await bcrypt.compare(req.body.password, user.password);
    if (!isMatch) {
        console.log("Contraseña incorrecta.");
        return res.status(400).json({ message: "El usuario o la contraseña no coincide. Por favor, verifica tus datos." });
    }

    // Guardar el ID del usuario en la sesión
    req.session.userId = user._id;

    // Enviar respuesta con la bandera isAdmin
    res.json({ 
        success: true, 
        message: 'Inicio de sesión exitoso!',
        isAdmin: isAdmin
    });
});




const regularUserSchema = new mongoose.Schema({
    firstName: String,
    lastName: String,
    email: { type: String, unique: true },
    password: String
    // Puedes agregar más campos aquí si es necesario
});


const RegularUser = mongoose.model('RegularUser', regularUserSchema);

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

    // Buscar usuario en RegularUser
    let user = await RegularUser.findById(resetPasswordRecord.userId);
    if (!user) {
        return res.status(400).json({ message: 'Usuario no encontrado.' });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();

    // Eliminar el token de recuperación ya que ya no es necesario
    await ResetPassword.findByIdAndDelete(resetPasswordRecord._id);
    res.json({ message: 'Contraseña actualizada con éxito.' });
});

app.post('/request-password-reset', async (req, res) => {
    const email = req.body.email;
    let user = await RegularUser.findOne({ email: email });

    if (!user) {
        return res.json({ message: 'Si tu correo está registrado, recibirás un enlace para restablecer tu contraseña.' });
    }

    // Generar un token
    const token = crypto.randomBytes(20).toString('hex');

    // Almacenar el token en la base de datos con una fecha de vencimiento
    const resetPasswordRecord = new ResetPassword({
        userId: user._id,
        resetPasswordToken: token,
        expire: Date.now() + 3600000 // 1 hora
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
            res.json({ message: 'Si tu correo está registrado, recibirás un enlace para restablecer tu contraseña.' });
        }
    });
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
        let user = await SuperUser.findById(req.session.userId);
        if (!user) {
            user = await RegularUser.findById(req.session.userId);
            if (!user) {
                return res.status(404).send('User not found.');
            }
        }

        res.json({ 
            name: `${user.firstName} ${user.lastName}`,
            email: user.email  // Añadir el campo email aquí
        });
    } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).send('Error fetching user.');
    }
});



app.get('/products', async (req, res) => {
    try {
        let query = {};
        if (req.query.category && req.query.category !== '') {
            query.category = req.query.category;
        }

        const products = await Product.find(query);
        res.json(products);
    } catch (error) {
        console.error("Error al obtener los productos:", error);
        res.status(500).send('Error al obtener los productos.');
    }
});


// Ruta para obtener un producto específico por su ID
app.get('/products/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        if (!product) {
            // Si no se encuentra el producto, enviar una respuesta 404
            return res.status(404).json({ message: 'Producto no encontrado' });
        }
        // Si se encuentra el producto, enviar una respuesta con el producto en formato JSON
        res.json(product);
    } catch (error) {
        // Si ocurre un error, enviar una respuesta de error
        res.status(500).json({ message: 'Error al buscar el producto', error: error.message });
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
app.put('/products/:id', upload.single('image'), async (req, res) => {
    const productId = req.params.id;
    let updatedProductData = req.body;

    if (req.file) {
        updatedProductData.imageUrl = '/uploads/' + req.file.filename;
    }

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

const moment = require('moment-timezone'); // Asegúrate de tener instalado este paquete

// Definición del esquema de reservas
const reservationSchema = new mongoose.Schema({
    name: String,
    email: String,
    product: String,
    productName: String,
    productImage: String,
    pickupTime: {
        type: Date,
        set: val => moment(val).tz("America/El_Salvador").toDate()
    },
    expirationTime: {
        type: Date,
        set: val => moment(val).tz("America/El_Salvador").toDate()
    },
    isPickedUp: {
        type: Boolean,
        default: false
    },
    hasExpired: {
        type: Boolean,
        default: false
    },
    reservationDate: {
        type: Date,
        default: Date.now // Esto guardará automáticamente la fecha actual cuando se cree la reserva
    }
});

const Reservation = mongoose.model('Reservation', reservationSchema);


// Establece la zona horaria predeterminada para todas las operaciones de fecha/hora
moment.tz.setDefault("America/El_Salvador");

// Ejemplo de cómo crear una fecha actual en la zona horaria de El Salvador
const now = moment.tz("America/El_Salvador");
console.log("Hora actual del servidor en El Salvador:", now.format('YYYY-MM-DD HH:mm:ss Z'));

app.get('/reservations/search', async (req, res) => {
    const searchTerm = req.query.term;
    try {
        const results = await Reservation.find({
            $or: [
                { email: new RegExp(searchTerm, 'i') },
                { name: new RegExp(searchTerm, 'i') }
            ]
        });
        res.json(results);
    } catch (error) {
        // Asegúrate de enviar una respuesta en formato JSON incluso en caso de error
        res.status(500).json({ message: 'Error al buscar reservaciones.', error: error.message });
    }
});


// Ruta para obtener los detalles de una reserva específica
app.get('/reservations/:reservationId', async (req, res) => {
    const reservationId = req.params.reservationId;
    try {
        const reservation = await Reservation.findById(reservationId);
        if (!reservation) {
            return res.status(404).send('Reserva no encontrada.');
        }

        // Convertir de UTC a hora local para mostrar al usuario
        const pickupTimeLocal = moment.utc(reservation.pickupTime).tz("America/El_Salvador").format();

        // Enviar la respuesta con la hora local
        res.json({
            ...reservation.toObject(), // Convertir el documento de Mongoose a un objeto JavaScript
            pickupTime: pickupTimeLocal, // Reemplaza el tiempo de recogida con la hora local
            // Asegúrate de que todos los demás campos necesarios se incluyan en la respuesta
        });

    } catch (error) {
        console.error("Error al obtener la reserva:", error);
        res.status(500).send('Error al obtener los detalles de la reserva.');
    }
});

// Función para validar la hora de recogida
function isValidPickupTime(pickupTime) {
    // Implementa tu lógica de validación aquí
    // Por ejemplo, verificar que la hora esté dentro del horario comercial
}

// Ruta POST para reservar producto
app.post('/reserve-product', async (req, res) => {
    const { name, email, pickupTime, productId, productName, productImage } = req.body;

    // Validar que todos los campos necesarios están presentes
    if (!name || !email || !productId || !pickupTime) {
        return res.status(400).json({ message: 'Todos los campos son obligatorios.' });
    }

    // Convertir la hora de recogida a UTC
    const pickupTimeUTC = moment.tz(pickupTime, "America/El_Salvador").utc().format();

    // Verificar si la hora de recogida es válida
    if (!isValidPickupTime(moment(pickupTimeUTC))) {
        return res.status(400).json({ message: 'Hora de recogida no válida.' });
    }

    try {
        // Buscar reservas existentes para el usuario
        const existingReservation = await Reservation.findOne({
            email: email,
            isPickedUp: false,
            expirationTime: { $gt: new Date() }
        });

        // Si ya hay una reserva pendiente, devolver error
        if (existingReservation) {
            return res.status(400).json({ success: false, message: 'Ya tienes una reserva pendiente.' });
        }

        // Verificar el stock del producto
        const product = await Product.findById(productId);
        if (!product) {
            return res.status(404).json({ success: false, message: 'Producto no encontrado.' });
        }

        if (product.stock <= 0) {
            return res.status(400).json({ success: false, message: 'No hay suficiente stock para realizar la reserva.' });
        }

        // Reducir el stock y guardar el producto
        product.stock -= 1;
        await product.save();

        // Crear la nueva reserva
        const reservation = new Reservation({
            name,
            email,
            product: productId,
            productName,
            pickupTime: new Date(pickupTimeUTC), // Guardar en UTC
            expirationTime: new Date(pickupTimeUTC), // Guardar en UTC
            productImage
        });

        // Guardar la reserva
        await reservation.save();

        // Devolver respuesta exitosa
        return res.json({
            success: true,
            message: 'Reserva realizada con éxito.',
            reservationId: reservation._id,
            serverTime: moment.utc().format(),
            pickupTime: moment(pickupTimeUTC).format(), // Formato local para mostrar
            expirationTime: moment(pickupTimeUTC).format() // Formato local para mostrar
        });

    } catch (error) {
        console.error("Error al realizar la reserva para", email, ":", error);
        return res.status(500).json({ message: 'Error al realizar la reserva.', error });
    }
});


function isValidPickupTime(time) {
    const hour = time.hour();
    const day = time.day(); // 0 es domingo, 6 es sábado

    // Verificar si es domingo
    if (day === 0) return false;

    // Verificar si está dentro del intervalo de almuerzo (12:00 PM - 1:00 PM)
    if (hour === 12) return false;

    // Verificar si está fuera del horario de atención (8:00 AM - 4:00 PM)
    if (hour < 8 || hour >= 16) return false;

    return true;
}

app.get('/current-server-time', (req, res) => {
    const serverTime = moment.tz("America/El_Salvador").format();
    res.json({ serverTime });
});



app.delete('/reservations/:id', async (req, res) => {
    const reservationId = req.params.id;

    try {
        // Encuentra la reserva y obtén la información del producto
        const reservation = await Reservation.findById(reservationId);
        if (!reservation) {
            return res.status(404).json({ message: 'Reserva no encontrada.' });
        }

        // Encuentra el producto asociado a la reserva y aumenta el stock
        const product = await Product.findById(reservation.product);
        if (product) {
            product.stock += 1;
            await product.save();
        }

        // Ahora elimina la reserva
        await Reservation.findByIdAndDelete(reservationId);
        
        res.status(200).json({ success: true, message: 'Reserva eliminada y stock actualizado con éxito.' });
    } catch (err) {
        console.error("Error al eliminar la reserva:", err);
        res.status(500).json({ success: false, message: 'Error al eliminar la reserva.' });
    }
});



const checkExpiredReservations = async () => {
    // Obtener la hora actual en la zona horaria de El Salvador y formatearla para mostrarla en los logs
    const now = moment.tz("America/El_Salvador");
    console.log("Verificando reservas expiradas. Hora actual en El Salvador:", now.format('YYYY-MM-DD HH:mm:ss Z'));

    try {
        // Utiliza 'now.toDate()' para obtener un objeto Date de JavaScript y compararlo en la consulta a MongoDB
        const expiredReservations = await Reservation.find({
            isPickedUp: false,
            expirationTime: { $lt: now.toDate() },
            hasExpired: false
        });

        console.log(`Reservas encontradas para verificar expiración: ${expiredReservations.length}`);

        for (const reservation of expiredReservations) {
            // Marcamos la reserva como expirada
            reservation.hasExpired = true;
            await reservation.save();
            console.log(`Reserva con ID: ${reservation._id} ha sido marcada como expirada`);
        }
    } catch (error) {
        console.error("Error al buscar reservas para marcar como expiradas:", error);
    }
};


app.get('/reservations', async (req, res) => {
    try {
        // Filtrar para no obtener las reservas que han sido marcadas como recogidas
        const reservations = await Reservation.find({ isPickedUp: false });
        // Convertir las fechas a ISO antes de enviar
        const modifiedReservations = reservations.map(reservation => {
            return {
                ...reservation.toObject(),
                reservationDate: reservation.reservationDate.toISOString(),
                pickupTime: reservation.pickupTime ? reservation.pickupTime.toISOString() : null, // Manejar casos donde pickupTime pueda ser nulo
            };
        });
        res.json(modifiedReservations);
    } catch (error) {
        console.error("Error al obtener las reservas:", error);
        res.status(500).send('Error al obtener las reservas.');
    }
});



const pickedUpReservationSchema = new mongoose.Schema({
    // Asume que las propiedades son las mismas que reservationSchema
    // Ajusta según sea necesario para tu caso de uso
    name: String,
    email: String,
    product: String,
    productName: String,
    productImage: String,
    pickupTime: Date,
    expirationTime: Date,
    isPickedUp: {
      type: Boolean,
      default: true // Cambiado a true porque esta colección es para reservas recogidas
    },
    hasExpired: {
      type: Boolean,
      default: false
    },
    reservationDate: {
      type: Date,
      default: Date.now
    }
  });
  
  const PickedUpReservation = mongoose.model('PickedUpReservation', pickedUpReservationSchema);
  
  module.exports = PickedUpReservation;

  app.patch('/reservations/pickup/:id', async (req, res) => {
    const reservationId = req.params.id;
   
    try {
        const reservation = await Reservation.findById(reservationId);
        if (!reservation) {
            return res.status(404).json({ success: false, message: 'Reserva no encontrada.' });
        }
        
        // Crear un nuevo documento en la colección de reservas recogidas
        const pickedUpReservation = new PickedUpReservation({
            // Asume que quieres copiar todas las propiedades
            ...reservation.toObject(),
            isPickedUp: true // Asegúrate de que esta propiedad sea true
        });
        await pickedUpReservation.save();

        // Eliminar la reserva original de la colección de reservas pendientes
        await Reservation.findByIdAndDelete(reservationId);

        // Actualizar el stock del producto si es necesario
        // ...

        res.status(200).json({ success: true, message: 'Reserva marcada como recogida y movida a la colección correspondiente.' });
    } catch (err) {
        console.error("Error al marcar la reserva como recogida:", err);
        res.status(500).json({ success: false, message: 'Error al marcar la reserva como recogida y moverla a la colección correspondiente.' });
    }
});




// Ruta para obtener los productos recogidos
app.get('/products/picked-up', async (req, res) => {
    try {
        // Encuentra todas las reservas donde isPickedUp es true en la colección correcta
        const pickedUpReservations = await PickedUpReservation.find({});

        // Envía la lista de productos recogidos incluyendo nombre y correo electrónico del cliente
        const pickedUpProducts = pickedUpReservations.map(reservation => {
            return {
                _id: reservation._id, // Asegúrate de enviar el ID al cliente
                customerName: reservation.name, // Incluye el nombre del cliente
                customerEmail: reservation.email, // Incluye el correo electrónico del cliente
                productName: reservation.productName,
                productImage: reservation.productImage,
                pickupTime: reservation.pickupTime.toISOString(),
                // ... cualquier otra información del producto que necesites
            };
        });

        res.json(pickedUpProducts);
    } catch (error) {
        console.error("Error al obtener los productos recogidos:", error);
        res.status(500).send('Error al obtener los productos recogidos.');
    }
});





const checkAndReleaseExpiredReservations = async () => {
    // Asegúrate de establecer la zona horaria de El Salvador
    const now = moment.tz("America/El_Salvador");

    console.log(`Verificando reservas expiradas. Hora actual en El Salvador: ${now.format('YYYY-MM-DD HH:mm:ss Z')}`);

    // Encuentra reservas que han expirado y aún no han sido marcadas como expiradas
    const expiredReservations = await Reservation.find({
        expirationTime: { $lt: now.toDate() }, // Compara usando la fecha actual en la zona horaria correcta
        hasExpired: false
    });

    console.log(`Reservas encontradas para verificar expiración: ${expiredReservations.length}`);

    for (const reservation of expiredReservations) {
        // Actualiza el stock del producto
        await Product.updateOne(
            { _id: reservation.product },
            { $inc: { stock: 1 } }
        );

        // Marca la reserva como expirada
        await Reservation.updateOne(
            { _id: reservation._id },
            { hasExpired: true }
        );

        // Opcional: Notifica al usuario que su reserva ha expirado
        // Esto puede implicar enviar un correo electrónico o alguna otra forma de notificación
        // Ejemplo: sendExpirationNotice(reservation.email);
    }
};


  // Ruta para eliminar una reserva recogida
app.delete('/picked-up-reservations/:id', async (req, res) => {
    const reservationId = req.params.id;

    try {
        // Intenta encontrar y eliminar la reserva recogida por ID
        const result = await PickedUpReservation.findByIdAndDelete(reservationId);

        if (result) {
            res.status(200).json({ message: 'Reserva recogida eliminada con éxito' });
        } else {
            // Si no se encuentra la reserva recogida, envía un error 404
            res.status(404).json({ message: 'Reserva recogida no encontrada' });
        }
    } catch (error) {
        // Maneja cualquier otro error (por ejemplo, error de base de datos)
        res.status(500).json({ message: 'Error al eliminar la reserva recogida', error: error });
    }
});

  




const cron = require('node-cron');
 
// Tarea que se ejecuta cada minuto
cron.schedule('* * * * *', () => {
  console.log('Verificando reservas expiradas cada minuto');
  checkExpiredReservations();
});


const commentSchema = new mongoose.Schema({
    text: String,
    userName: String,
    productImage: String,
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
    const { productId, comment, userName, productImage } = req.body;  // Añade productImage aquí
    
    try {
        // Buscar el producto por ID
        const product = await Product.findById(productId);
        if (!product) {
            return res.status(400).json({ success: false, message: 'Producto no encontrado' });
        }

        // Crear un nuevo comentario usando el ObjectId del producto
        const newComment = new Comment({
            product: product._id,
            text: comment,
            userName: userName,  // Aquí deberías obtener el nombre real del usuario
            productImage: productImage  // Guarda la URL de la imagen del producto aquí
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

app.get('/product-reservation-stats', async (req, res) => {
    try {
        // Obtiene todos los productos
        const allProducts = await Product.find().lean();

        // Realiza la agregación para obtener las estadísticas de reservas
        const reservationStats = await Reservation.aggregate([
            { $group: { _id: "$product", totalReservations: { $sum: 1 } } },
            { $sort: { totalReservations: 1 } }, // Orden ascendente por total de reservas
            { $lookup: {
                from: "products",
                localField: "_id",
                foreignField: "_id",
                as: "productInfo"
            } },
            { $unwind: { path: "$productInfo", preserveNullAndEmptyArrays: true } }
        ]);

        // Mapea todos los productos para incluir las estadísticas de reservas
        const productReservationStats = allProducts.map(product => {
            const reservationStat = reservationStats.find(stat => stat._id.toString() === product._id.toString());
            return {
                productName: product.name,
                totalReservations: reservationStat ? reservationStat.totalReservations : 0 // Usar 0 si no hay estadísticas de reservas
            };
        });

        // Ordena los productos por total de reservas de menor a mayor
        productReservationStats.sort((a, b) => a.totalReservations - b.totalReservations);

        res.json(productReservationStats);
    } catch (error) {
        console.error("Error al obtener estadísticas de reservas:", error);
        res.status(500).send('Error al obtener estadísticas de reservas.');
    }
});

app.get('/product-stock-stats', async (req, res) => {
    try {
        const products = await Product.find();

        const stockStats = products.map(product => {
            let stockStatus = 'Rojo'; // Por defecto, asume que no hay stock
            if (product.stock > 10) {
                stockStatus = 'Verde';
            } else if (product.stock >= 5 && product.stock <= 10) {
                stockStatus = 'Amarillo';
            }
            return {
                name: product.name,
                stock: product.stock,
                stockStatus: stockStatus
            };
        });

        res.json(stockStats);
    } catch (error) {
        console.error("Error al obtener estadísticas de stock:", error);
        res.status(500).send('Error al obtener estadísticas de stock.');
    }
});




// Iniciar el servidor en el puerto 3000
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);

});