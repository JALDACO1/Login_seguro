// ============================================================
//  SERVIDOR DE AUTENTICACIÓN SEGURA
//  Proyecto Universitario - Desarrollo de Software Seguro
//  Tecnologías: Node.js + Express + SHA-256 + Salting
// ============================================================

// ---- IMPORTACIONES ----
// Express: framework web para crear rutas y manejar peticiones HTTP
const express = require('express');

// crypto: módulo NATIVO de Node.js (no necesita instalación)
// Proporciona funciones criptográficas: hashing, generación de bytes aleatorios, etc.
const crypto = require('crypto');

// path: módulo nativo para manejar rutas de archivos de forma segura
// Evita problemas de rutas entre Windows (\) y Mac/Linux (/)
const path = require('path');

// ---- INICIALIZACIÓN ----
const app = express();
const PORT = 3000;

// ---- MIDDLEWARE ----
// Los middleware son funciones que procesan CADA petición ANTES de llegar a las rutas.
// Analogía: son como los guardias en la entrada de un edificio que revisan
// a cada persona antes de dejarla pasar.

// express.urlencoded(): Permite leer datos enviados desde formularios HTML
// El formato es: "username=juan&password=123" → { username: "juan", password: "123" }
// extended: false usa la librería 'querystring' (más simple y segura)
app.use(express.urlencoded({ extended: false }));

// express.json(): Permite leer datos enviados como JSON desde fetch/AJAX
// El formato es: {"username":"juan","password":"123"} → { username: "juan", password: "123" }
app.use(express.json());

// express.static(): Sirve archivos estáticos (HTML, CSS, JS, imágenes)
// Cualquier archivo dentro de la carpeta 'public' será accesible desde el navegador
// Ejemplo: public/login.html → http://localhost:3000/login.html
app.use(express.static(path.join(__dirname, 'public')));

// ============================================================
//  ALMACENAMIENTO EN MEMORIA
// ============================================================
// IMPORTANTE: Esto es solo para el proyecto universitario.
// En producción SIEMPRE usarías una base de datos (PostgreSQL, MongoDB, etc.)
//
// Estructura del objeto 'usuarios':
// {
//   "juan": {
//     sal: "a1b2c3d4...",        ← Sal única de 32 bytes (64 chars hex)
//     hash: "e5f6g7h8...",       ← Hash SHA-256 de (sal + contraseña)
//     creadoEn: "2024-01-15..."  ← Fecha de registro
//   }
// }
const usuarios = {};

// ============================================================
//  SISTEMA DE LIMITACIÓN DE INTENTOS FALLIDOS (Rate Limiting)
// ============================================================
// ¿Por qué? Sin esto, un atacante puede probar miles de contraseñas
// por segundo (ataque de fuerza bruta).
//
// Estructura:
// {
//   "juan": {
//     intentos: 3,
//     ultimoIntento: 1705123456789  ← timestamp en milisegundos
//   }
// }
const intentosFallidos = {};
const MAX_INTENTOS = 5;                    // Máximo 5 intentos antes de bloquear
const TIEMPO_BLOQUEO = 15 * 60 * 1000;    // 15 minutos en milisegundos

// ============================================================
//  FUNCIONES DE SEGURIDAD
// ============================================================

/**
 * GENERAR SAL ALEATORIA
 *
 * crypto.randomBytes(n) genera 'n' bytes aleatorios criptográficamente seguros.
 * Esto es diferente de Math.random(), que NO es seguro para criptografía.
 *
 * ¿Por qué 32 bytes? → Produce 64 caracteres hexadecimales.
 * Esto hace que cada sal sea prácticamente irrepetible.
 * La probabilidad de repetición es 1 entre 2^256 (más átomos que en el universo).
 *
 * .toString('hex') convierte los bytes binarios a texto legible hexadecimal.
 * Ejemplo: Buffer <a1 b2 c3> → "a1b2c3"
 */
function generarSal(longitud = 32) {
    return crypto.randomBytes(longitud).toString('hex');
}

/**
 * HASHEAR CONTRASEÑA CON SAL
 *
 * Proceso:
 * 1. Se concatena: sal + contraseña → "a1b2c3...miPassword123"
 * 2. Se aplica SHA-256 a esa concatenación
 * 3. Se devuelve el hash en formato hexadecimal (64 caracteres)
 *
 * ¿Por qué la sal va ANTES de la contraseña?
 * Por convención y porque evita ciertos ataques de extensión de longitud
 * (length extension attacks) en algoritmos de la familia SHA-2.
 *
 * crypto.createHash('sha256') → Crea un objeto hasher SHA-256
 * .update(datos)              → Le pasa los datos a hashear
 * .digest('hex')              → Calcula el hash y lo devuelve como hexadecimal
 */
function hashearPassword(password, sal) {
    return crypto
        .createHash('sha256')
        .update(sal + password)
        .digest('hex');
}

/**
 * COMPARACIÓN SEGURA DE HASHES (Timing-Safe)
 *
 * ERROR COMÚN: Comparar hashes con === o ==
 *   if (hashA === hashB)  ← ¡INSEGURO!
 *
 * ¿Por qué es inseguro?
 * El operador === compara carácter por carácter y PARA en cuanto encuentra
 * una diferencia. Un atacante puede medir cuánto TIEMPO tarda la comparación:
 *   - "aaaaaa" vs "baaaaa" → Falla en el 1er carácter (muy rápido)
 *   - "aaaaaa" vs "abaaaa" → Falla en el 2do carácter (un poco más lento)
 *
 * Midiendo estos tiempos (ataque de timing), el atacante puede adivinar
 * el hash carácter por carácter. Esto se llama "timing attack".
 *
 * crypto.timingSafeEqual() SIEMPRE tarda el MISMO tiempo, sin importar
 * en qué posición difieren los strings. Compara TODOS los bytes siempre.
 *
 * Requiere que ambos buffers tengan la MISMA longitud (por eso validamos primero).
 */
function compararHashSeguro(hashA, hashB) {
    // Si tienen diferente longitud, no son iguales
    // (esta verificación sí puede filtrar timing, pero la longitud del hash
    // SHA-256 es siempre 64 caracteres, así que no revela información útil)
    if (hashA.length !== hashB.length) {
        return false;
    }

    // Convertir strings hexadecimales a Buffers (arrays de bytes)
    const bufferA = Buffer.from(hashA, 'hex');
    const bufferB = Buffer.from(hashB, 'hex');

    // Comparación en tiempo constante
    return crypto.timingSafeEqual(bufferA, bufferB);
}

/**
 * SANITIZAR ENTRADA (Prevención básica de XSS)
 *
 * XSS (Cross-Site Scripting): Un atacante inyecta código malicioso
 * en los campos del formulario. Ejemplo:
 *   Username: <script>robarCookies()</script>
 *
 * Si el servidor muestra ese username sin sanitizar, el código
 * JavaScript se ejecutaría en el navegador de otros usuarios.
 *
 * Esta función reemplaza los caracteres peligrosos por sus
 * equivalentes HTML (entidades HTML) que se MUESTRAN como texto
 * pero NO se ejecutan como código.
 */
function sanitizarEntrada(texto) {
    if (typeof texto !== 'string') return '';
    return texto
        .replace(/&/g, '&amp;')     // & → &amp;  (debe ser el primero)
        .replace(/</g, '&lt;')      // < → &lt;   (evita abrir tags HTML)
        .replace(/>/g, '&gt;')      // > → &gt;   (evita cerrar tags HTML)
        .replace(/"/g, '&quot;')    // " → &quot;  (evita romper atributos)
        .replace(/'/g, '&#x27;');   // ' → &#x27; (evita romper atributos)
}

/**
 * REGISTRAR INTENTO FALLIDO
 *
 * Lleva el conteo de intentos fallidos por usuario.
 * Después de MAX_INTENTOS, la cuenta se bloquea temporalmente.
 */
function registrarIntentoFallido(usuario) {
    if (!intentosFallidos[usuario]) {
        intentosFallidos[usuario] = { intentos: 0, ultimoIntento: 0 };
    }
    intentosFallidos[usuario].intentos++;
    intentosFallidos[usuario].ultimoIntento = Date.now();

    console.log(`[SEGURIDAD] Intento fallido para "${usuario}". ` +
                `Total: ${intentosFallidos[usuario].intentos}/${MAX_INTENTOS}`);
}

/**
 * VERIFICAR SI LA CUENTA ESTÁ BLOQUEADA
 *
 * Retorna un objeto indicando si está bloqueada y cuántos minutos faltan.
 */
function verificarBloqueo(usuario) {
    const registro = intentosFallidos[usuario];

    if (!registro || registro.intentos < MAX_INTENTOS) {
        return { bloqueado: false };
    }

    const tiempoTranscurrido = Date.now() - registro.ultimoIntento;

    if (tiempoTranscurrido < TIEMPO_BLOQUEO) {
        const minutosRestantes = Math.ceil((TIEMPO_BLOQUEO - tiempoTranscurrido) / 60000);
        return { bloqueado: true, minutosRestantes };
    }

    // Ya pasó el tiempo de bloqueo, limpiar registro
    delete intentosFallidos[usuario];
    return { bloqueado: false };
}

// ============================================================
//  RUTAS DE LA API
// ============================================================

// ---- RUTA: REGISTRO DE USUARIO ----
// POST /api/registro
// Recibe: { username, password }
// Proceso: Valida → Genera sal → Hashea → Almacena
app.post('/api/registro', (req, res) => {
    const { username, password } = req.body;

    // --- VALIDACIÓN DE ENTRADAS ---
    // Nunca confíes en los datos del usuario. SIEMPRE valida en el servidor.
    // La validación del frontend se puede saltar fácilmente con DevTools.

    if (!username || !password) {
        return res.status(400).json({
            error: 'Todos los campos son obligatorios.'
        });
    }

    // Sanitizar el nombre de usuario (prevención XSS)
    const usuarioLimpio = sanitizarEntrada(username.trim());

    if (usuarioLimpio.length < 3) {
        return res.status(400).json({
            error: 'El nombre de usuario debe tener al menos 3 caracteres.'
        });
    }

    if (password.length < 8) {
        return res.status(400).json({
            error: 'La contraseña debe tener al menos 8 caracteres.'
        });
    }

    // Verificar que el usuario no exista
    if (usuarios[usuarioLimpio]) {
        // NOTA DE SEGURIDAD: En producción, algunos sistemas prefieren NO revelar
        // si un usuario existe. Pero para registro, es necesario informar al usuario.
        return res.status(409).json({
            error: 'Ese nombre de usuario ya está registrado.'
        });
    }

    // --- PROCESO DE HASHING CON SAL ---
    // Paso 1: Generar una sal ÚNICA para este usuario
    const sal = generarSal();

    // Paso 2: Concatenar sal + contraseña y aplicar SHA-256
    const hash = hashearPassword(password, sal);

    // Paso 3: Almacenar usuario con su sal y hash (NUNCA la contraseña en texto plano)
    usuarios[usuarioLimpio] = {
        sal: sal,
        hash: hash,
        rol: 'user',
        creadoEn: new Date().toISOString()
    };

    // --- LOGS DE DEPURACIÓN (solo para desarrollo) ---
    // En producción NUNCA imprimas hashes ni sales en los logs
    console.log('\n========================================');
    console.log(`[REGISTRO] Usuario: "${usuarioLimpio}"`);
    console.log(`[DEBUG] Sal generada:  ${sal}`);
    console.log(`[DEBUG] Hash generado: ${hash}`);
    console.log(`[DEBUG] Usuarios en memoria: ${Object.keys(usuarios).length}`);
    console.log('========================================\n');

    res.json({ mensaje: 'Usuario registrado exitosamente.' });
});

// ---- RUTA: INICIO DE SESIÓN ----
// POST /api/login
// Recibe: { username, password }
// Proceso: Valida → Verifica bloqueo → Busca usuario → Regenera hash → Compara
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            error: 'Todos los campos son obligatorios.'
        });
    }

    const usuarioLimpio = sanitizarEntrada(username.trim());

    // --- VERIFICAR BLOQUEO POR INTENTOS ---
    const bloqueo = verificarBloqueo(usuarioLimpio);
    if (bloqueo.bloqueado) {
        console.log(`[SEGURIDAD] Cuenta "${usuarioLimpio}" bloqueada. ` +
                    `Faltan ${bloqueo.minutosRestantes} minutos.`);
        return res.status(429).json({
            error: `Demasiados intentos. Cuenta bloqueada por ${bloqueo.minutosRestantes} minuto(s).`
        });
    }

    // --- MENSAJE DE ERROR GENÉRICO ---
    // IMPORTANTE: Usamos el MISMO mensaje si el usuario no existe O si la
    // contraseña es incorrecta. ¿Por qué?
    //
    // Si dijéramos "usuario no encontrado" vs "contraseña incorrecta",
    // un atacante sabría CUÁLES usuarios existen en el sistema.
    // Esto se llama "user enumeration" y es una vulnerabilidad real.
    const ERROR_GENERICO = 'Usuario o contraseña incorrectos.';

    // --- BUSCAR USUARIO ---
    const usuario = usuarios[usuarioLimpio];

    if (!usuario) {
        // El usuario no existe, pero mostramos el mismo mensaje genérico
        registrarIntentoFallido(usuarioLimpio);
        return res.status(401).json({ error: ERROR_GENERICO });
    }

    // --- PROCESO DE VERIFICACIÓN ---
    // Paso 1: Recuperar la sal almacenada de este usuario
    // Paso 2: Concatenar ESA sal + la contraseña que ingresó ahora
    // Paso 3: Generar un nuevo hash con esos datos
    // Paso 4: Comparar el hash nuevo con el hash almacenado
    //
    // Si son iguales → la contraseña es correcta
    // Si son diferentes → la contraseña es incorrecta
    const hashIntento = hashearPassword(password, usuario.sal);

    // --- COMPARACIÓN SEGURA (timing-safe) ---
    if (!compararHashSeguro(hashIntento, usuario.hash)) {
        registrarIntentoFallido(usuarioLimpio);
        console.log(`[LOGIN] Contraseña incorrecta para "${usuarioLimpio}"`);
        return res.status(401).json({ error: ERROR_GENERICO });
    }

    // --- LOGIN EXITOSO ---
    // Limpiar el registro de intentos fallidos
    delete intentosFallidos[usuarioLimpio];

    console.log('\n========================================');
    console.log(`[LOGIN] Usuario "${usuarioLimpio}" autenticado exitosamente`);
    console.log('========================================\n');

    res.json({
        mensaje: 'Inicio de sesión exitoso.',
        usuario: usuarioLimpio,
        rol: usuario.rol
    });
});

// ---- RUTA: LISTADO DE USUARIOS PARA EL ADMIN ----
// GET /api/admin/usuarios
// Devuelve todos los usuarios con su hash completo (para el dashboard de admin)
// En producción esta ruta requeriría autenticación de sesión real
app.get('/api/admin/usuarios', (req, res) => {
    const lista = Object.entries(usuarios).map(([nombre, datos]) => ({
        usuario: nombre,
        hash: datos.hash,
        rol: datos.rol,
        creadoEn: datos.creadoEn
    }));
    res.json(lista);
});

// ---- RUTA: VER USUARIOS REGISTRADOS (solo para depuración) ----
// GET /api/debug/usuarios
// ADVERTENCIA: Esta ruta NUNCA debe existir en producción
app.get('/api/debug/usuarios', (req, res) => {
    const resumen = {};
    for (const [nombre, datos] of Object.entries(usuarios)) {
        resumen[nombre] = {
            sal: datos.sal.substring(0, 10) + '...',   // Solo muestra los primeros 10 chars
            hash: datos.hash.substring(0, 10) + '...',
            creadoEn: datos.creadoEn
        };
    }
    res.json({
        totalUsuarios: Object.keys(usuarios).length,
        usuarios: resumen
    });
});

// ============================================================
//  INICIAR SERVIDOR
// ============================================================
app.listen(PORT, () => {
    // ---- CREAR USUARIO ADMIN POR DEFECTO ----
    // Se crea al iniciar el servidor para que siempre exista.
    // En producción, el admin se crearía en la base de datos durante el despliegue.
    const ADMIN_USER = 'admin';
    const ADMIN_PASS = 'Admin123!';
    const adminSal  = generarSal();
    const adminHash = hashearPassword(ADMIN_PASS, adminSal);
    usuarios[ADMIN_USER] = {
        sal:      adminSal,
        hash:     adminHash,
        rol:      'admin',
        creadoEn: new Date().toISOString()
    };

    console.log('\n====================================================');
    console.log('  SERVIDOR DE AUTENTICACIÓN SEGURA');
    console.log(`  Corriendo en: http://localhost:${PORT}`);
    console.log('  ');
    console.log('  Credenciales de administrador:');
    console.log(`    Usuario:    ${ADMIN_USER}`);
    console.log(`    Contraseña: ${ADMIN_PASS}`);
    console.log('  ');
    console.log('  Rutas disponibles:');
    console.log(`    GET  http://localhost:${PORT}/login.html           → Registro`);
    console.log(`    GET  http://localhost:${PORT}/iniciar-sesion.html  → Login`);
    console.log(`    GET  http://localhost:${PORT}/dashboard.html       → Dashboard usuario`);
    console.log(`    GET  http://localhost:${PORT}/admin-dashboard.html → Dashboard admin`);
    console.log(`    POST http://localhost:${PORT}/api/registro         → API Registro`);
    console.log(`    POST http://localhost:${PORT}/api/login            → API Login`);
    console.log(`    GET  http://localhost:${PORT}/api/admin/usuarios   → Lista usuarios`);
    console.log('====================================================\n');
});
