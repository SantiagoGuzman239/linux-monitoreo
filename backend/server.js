require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');
const rateLimit = require('express-rate-limit');
const bodyParser = require('body-parser');
const si = require('systeminformation');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs').promises;
const FileStore = require('session-file-store')(session);
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const USERS_FILE = path.join(__dirname, '..', 'data', 'users.json');
const SESSIONS_DIR = path.join(__dirname, '..', 'data', 'sessions');

// Asegurar que los directorios existen
const ensureDataDir = async () => {
    try {
        await fs.access(path.dirname(USERS_FILE));
    } catch {
        await fs.mkdir(path.dirname(USERS_FILE), { recursive: true });
    }
    try {
        await fs.access(SESSIONS_DIR);
    } catch {
        await fs.mkdir(SESSIONS_DIR, { recursive: true });
    }
};

// Middlewares
app.use(helmet({
    contentSecurityPolicy: false
}));
app.use(compression());
app.use(morgan('combined'));
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de sesiones
const sessionConfig = {
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: new FileStore({
        path: SESSIONS_DIR,
        ttl: 86400,
        retries: 0
    }),
    cookie: { 
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
};

app.use(session(sessionConfig));

// Rate limiting
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 1000
}));

// Funciones de usuario
async function loadUsers() {
    try {
        const data = await fs.readFile(USERS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (e) {
        return [];
    }
}

async function saveUsers(users) {
    await ensureDataDir();
    await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
}

async function createUser(username, password, email, fullName) {
    const users = await loadUsers();
    if (users.some(u => u.username === username.toLowerCase())) {
        throw new Error('Usuario ya existe');
    }
    if (users.some(u => u.email === email.toLowerCase())) {
        throw new Error('Email ya registrado');
    }
    
    const hashed = await bcrypt.hash(password, 12);
    const user = {
        id: uuidv4(),
        username: username.toLowerCase(),
        password: hashed,
        email: email.toLowerCase(),
        fullName,
        role: users.length === 0 ? 'admin' : 'user',
        createdAt: new Date().toISOString(),
        isActive: true
    };
    users.push(user);
    await saveUsers(users);
    return user;
}

async function authUser(username, password) {
    const users = await loadUsers();
    const user = users.find(u => u.username === username.toLowerCase() && u.isActive);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return null;
    }
    return user;
}

// Middleware de autenticación
const requireAuth = (req, res, next) => {
    if (req.session.user) {
        next();
    } else {
        res.status(401).json({ error: 'No autorizado' });
    }
};

// Rutas de autenticación
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, email, fullName } = req.body;
        
        if (!username || !password || !email || !fullName) {
            return res.status(400).json({ error: 'Todos los campos son requeridos' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
        }
        
        const user = await createUser(username, password, email, fullName);
        req.session.user = { 
            id: user.id, 
            username: user.username, 
            email: user.email, 
            role: user.role, 
            fullName: user.fullName 
        };
        
        res.json({ 
            success: true, 
            message: 'Usuario creado exitosamente', 
            user: req.session.user 
        });
    } catch (e) {
        res.status(400).json({ error: e.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }
        
        const user = await authUser(username, password);
        
        if (user) {
            req.session.user = { 
                id: user.id, 
                username: user.username, 
                email: user.email, 
                role: user.role, 
                fullName: user.fullName 
            };
            res.json({ 
                success: true, 
                message: 'Login exitoso', 
                user: req.session.user 
            });
        } else {
            res.status(401).json({ error: 'Credenciales inválidas' });
        }
    } catch (e) {
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

app.get('/api/auth/check', (req, res) => {
    res.json({ 
        authenticated: !!req.session.user, 
        user: req.session.user || null 
    });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Error al cerrar sesión' });
        }
        res.clearCookie('connect.sid');
        res.json({ success: true, message: 'Sesión cerrada' });
    });
});

// Ruta de métricas del sistema
app.get('/api/system/metrics', requireAuth, async (req, res) => {
    try {
        const [
            cpu, mem, load, fsSize, network, processes, temp,
            osInfo, time, users, networkInterfaces
        ] = await Promise.all([
            si.cpu(),
            si.mem(),
            si.currentLoad(),
            si.fsSize(),
            si.networkStats(),
            si.processes(),
            si.cpuTemperature().catch(() => ({ main: null })),
            si.osInfo(),
            si.time(),
            si.users(),
            si.networkInterfaces()
        ]);

        const metrics = {
            system: {
                hostname: os.hostname(),
                platform: osInfo.platform,
                distro: osInfo.distro,
                kernel: osInfo.kernel,
                arch: os.arch(),
                uptime: os.uptime(),
                time: time,
                os: osInfo
            },
            cpu: {
                usage: Math.round(load.currentLoad),
                cores: cpu.cores,
                speed: cpu.speed,
                brand: cpu.brand,
                manufacturer: cpu.manufacturer,
                temperature: temp.main,
                load1: load.avgLoad?.[0] || 0,
                load5: load.avgLoad?.[1] || 0,
                load15: load.avgLoad?.[2] || 0
            },
            memory: {
                total: mem.total,
                used: mem.used,
                free: mem.free,
                active: mem.active,
                available: mem.available,
                usage: Math.round((mem.used / mem.total) * 100),
                swapTotal: mem.swaptotal,
                swapUsed: mem.swapused,
                swapFree: mem.swapfree
            },
            disk: fsSize.map(d => ({
                fs: d.fs,
                type: d.type,
                size: d.size,
                used: d.used,
                available: d.available,
                usage: Math.round(d.use),
                mount: d.mount
            })),
            network: {
                interfaces: networkInterfaces.map(n => ({
                    iface: n.iface,
                    ip4: n.ip4,
                    ip6: n.ip6,
                    mac: n.mac,
                    internal: n.internal
                })),
                stats: network.map(n => ({
                    iface: n.iface,
                    rx_sec: n.rx_sec || 0,
                    tx_sec: n.tx_sec || 0,
                    rx_bytes: n.rx_bytes || 0,
                    tx_bytes: n.tx_bytes || 0,
                    operstate: n.operstate || 'unknown'
                }))
            },
            processes: {
                total: processes.all,
                running: processes.running,
                sleeping: processes.sleeping,
                list: processes.list
                    .sort((a, b) => (b.cpu || 0) - (a.cpu || 0))
                    .slice(0, 10)
                    .map(p => ({
                        pid: p.pid,
                        name: p.name,
                        cpu: p.cpu || 0,
                        memory: p.memory || 0,
                        state: p.state || 'unknown'
                    }))
            },
            users: users,
            timestamp: new Date().toISOString()
        };

        res.json(metrics);
    } catch (e) {
        console.error('Error getting metrics:', e);
        // Datos de respaldo si falla systeminformation
        const fallbackMetrics = {
            system: {
                hostname: os.hostname(),
                platform: process.platform,
                distro: 'Linux',
                kernel: os.release(),
                arch: os.arch(),
                uptime: os.uptime(),
                time: { current: new Date().toISOString() }
            },
            cpu: {
                usage: 0,
                cores: os.cpus().length,
                speed: os.cpus()[0]?.speed || 0,
                brand: 'Unknown',
                load1: os.loadavg()[0],
                load5: os.loadavg()[1],
                load15: os.loadavg()[2]
            },
            memory: {
                total: os.totalmem(),
                used: os.totalmem() - os.freemem(),
                free: os.freemem(),
                usage: Math.round(((os.totalmem() - os.freemem()) / os.totalmem()) * 100)
            },
            disk: [],
            network: { interfaces: [], stats: [] },
            processes: { total: 0, running: 0, sleeping: 0, list: [] },
            users: [],
            timestamp: new Date().toISOString()
        };
        res.json(fallbackMetrics);
    }
});

// Ruta de salud
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Ruta de información del sistema
app.get('/api/system/info', requireAuth, async (req, res) => {
    try {
        const osInfo = await si.osInfo();
        const cpu = await si.cpu();
        const mem = await si.mem();
        
        res.json({
            system: {
                hostname: os.hostname(),
                platform: osInfo.platform,
                distro: osInfo.distro,
                version: osInfo.release,
                kernel: osInfo.kernel,
                arch: os.arch(),
                uptime: os.uptime(),
                cpu: {
                    cores: cpu.cores,
                    model: cpu.brand,
                    speed: cpu.speed,
                    manufacturer: cpu.manufacturer
                },
                memory: {
                    total: (mem.total / 1024 / 1024 / 1024).toFixed(2) + ' GB',
                    free: (mem.free / 1024 / 1024 / 1024).toFixed(2) + ' GB'
                }
            }
        });
    } catch (e) {
        res.json({
            system: {
                hostname: os.hostname(),
                platform: process.platform,
                distro: 'Linux',
                kernel: os.release(),
                arch: os.arch(),
                uptime: os.uptime()
            }
        });
    }
});

// Rutas del frontend - CORREGIDAS
app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Ruta principal ahora apunta a index.html (antes login.html)
app.get('/', (req, res) => {
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});

// Ruta de login para compatibilidad
app.get('/login', (req, res) => {
    if (req.session.user) {
        res.redirect('/dashboard');
    } else {
        res.redirect('/');
    }
});

// Manejo de rutas no encontradas
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

// Inicialización del servidor
const server = app.listen(PORT, HOST, async () => {
    await ensureDataDir();
    console.log(`\n${'='.repeat(50)}`);
    console.log(`🚀 LinuxMon Pro Premium v5.0.0`);
    console.log(`🌐 Servidor: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
    console.log(`🔐 Entorno: ${process.env.NODE_ENV}`);
    console.log(`${'='.repeat(50)}\n`);
});

// Manejo graceful de shutdown
process.on('SIGINT', () => {
    console.log('\nApagando servidor...');
    server.close(() => {
        console.log('Servidor cerrado.');
        process.exit(0);
    });
});