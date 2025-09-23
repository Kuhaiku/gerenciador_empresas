// Importações
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');

const app = express();
const port = 3000;

// Configuração do EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Configurações do banco de dados (lendo do .env)
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT
};

// Conexão com o banco de dados
async function createDBConnection() {
    try {
        const connection = await mysql.createConnection(dbConfig);
        console.log('Conectado ao banco de dados MySQL.');
        return connection;
    } catch (error) {
        console.error('Erro ao conectar com o banco de dados:', error);
        throw error;
    }
}

// Configurações do servidor de e-mail (lendo do .env)
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: process.env.EMAIL_PORT == 465,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // 'true' em produção com HTTPS
}));

// Roteamento de arquivos estáticos (CSS, JS, imagens, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// Rotas para servir as páginas EJS
app.get('/', (req, res) => {
    const message = req.session.message;
    req.session.message = null; // Limpa a mensagem
    res.render('login', { message: message });
});
app.get('/register', (req, res) => {
    const message = req.session.message;
    req.session.message = null;
    res.render('register', { message: message });
});
app.get('/verify-email', (req, res) => {
    const message = req.session.message;
    req.session.message = null;
    res.render('verify_email', { message: message });
});
app.get('/dashboard', (req, res) => {
    if (req.session.loggedin) {
        const message = req.session.message || null; 
        req.session.message = null;
        res.render('dashboard', { message: message, email: req.session.email });
    } else {
        req.session.message = 'Você precisa estar logado para acessar o dashboard.';
        res.redirect('/');
    }
});
app.get('/forgot-password', (req, res) => {
    const message = req.session.message;
    req.session.message = null;
    res.render('forgot_password', { message: message });
});
app.get('/reset-password', (req, res) => {
    const message = req.session.message;
    req.session.message = null;
    res.render('reset_password', { message: message });
});


// Rotas de Autenticação (POST)

// Registro de usuário
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const connection = await createDBConnection();
    try {
        const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length > 0) {
            req.session.message = 'Este e-mail já está em uso.';
            return res.redirect('/register');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const verificationToken = await bcrypt.hash(code, 10);

        await connection.execute('INSERT INTO users (email, password, verification_code) VALUES (?, ?, ?)', [email, hashedPassword, verificationToken]);

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Código de Verificação de Conta',
            text: `Seu código de verificação é: ${code}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
                req.session.message = 'Erro ao enviar e-mail de verificação.';
                return res.redirect('/register');
            }
            req.session.message = 'Registro realizado com sucesso. Verifique seu e-mail para o código de verificação.';
            res.redirect('/verify-email');
        });
    } catch (error) {
        console.error(error);
        req.session.message = 'Erro no servidor.';
        res.redirect('/register');
    } finally {
        connection.end();
    }
});

// Verificação de e-mail (etapa adicional)
app.post('/verify-email', async (req, res) => {
    const { email, code } = req.body;
    const connection = await createDBConnection();
    try {
        const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            req.session.message = 'E-mail não encontrado.';
            return res.redirect('/verify-email');
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(code, user.verification_code);

        if (isMatch) {
            await connection.execute('UPDATE users SET verified = 1, verification_code = NULL WHERE email = ?', [email]);
            req.session.message = 'E-mail verificado com sucesso. Você já pode fazer login.';
            res.redirect('/');
        } else {
            req.session.message = 'Código de verificação inválido.';
            res.redirect('/verify-email');
        }
    } catch (error) {
        console.error(error);
        req.session.message = 'Erro no servidor.';
        res.redirect('/verify-email');
    } finally {
        connection.end();
    }
});

// Login do usuário
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const connection = await createDBConnection();
    try {
        const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            req.session.message = 'E-mail ou senha incorretos.';
            return res.redirect('/');
        }

        const user = rows[0];
        if (!user.verified) {
            req.session.message = 'Sua conta ainda não foi verificada. Por favor, verifique seu e-mail.';
            return res.redirect('/');
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            req.session.loggedin = true;
            req.session.email = email;
            req.session.message = 'Bem-vindo(a)!';
            res.redirect('/dashboard');
        } else {
            req.session.message = 'E-mail ou senha incorretos.';
            res.redirect('/');
        }
    } catch (error) {
        console.error(error);
        req.session.message = 'Erro no servidor.';
        res.redirect('/');
    } finally {
        connection.end();
    }
});

// Esqueci a senha
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const connection = await createDBConnection();
    try {
        const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            req.session.message = 'E-mail não encontrado.';
            return res.redirect('/forgot-password');
        }

        const user = rows[0];
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const resetToken = await bcrypt.hash(code, 10);

        await connection.execute('UPDATE users SET reset_token = ? WHERE id = ?', [resetToken, user.id]);

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Código de Recuperação de Senha',
            text: `Seu código para redefinir a senha é: ${code}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
                req.session.message = 'Erro ao enviar e-mail de recuperação.';
                return res.redirect('/forgot-password');
            }
            req.session.message = 'Código de recuperação enviado para seu e-mail.';
            res.redirect('/reset-password');
        });
    } catch (error) {
        console.error(error);
        req.session.message = 'Erro no servidor.';
        res.redirect('/forgot-password');
    } finally {
        connection.end();
    }
});

// Redefinir senha com código
app.post('/reset-password', async (req, res) => {
    const { email, code, newPassword } = req.body;
    const connection = await createDBConnection();
    try {
        const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            req.session.message = 'E-mail não encontrado.';
            return res.redirect('/reset-password');
        }

        const user = rows[0];
        const isMatch = await bcrypt.compare(code, user.reset_token);

        if (isMatch) {
            const newHashedPassword = await bcrypt.hash(newPassword, 10);
            await connection.execute('UPDATE users SET password = ?, reset_token = NULL WHERE id = ?', [newHashedPassword, user.id]);
            req.session.message = 'Senha redefinida com sucesso.';
            res.redirect('/');
        } else {
            req.session.message = 'Código de recuperação inválido.';
            res.redirect('/reset-password');
        }
    } catch (error) {
        console.error(error);
        req.session.message = 'Erro no servidor.';
        res.redirect('/reset-password');
    } finally {
        connection.end();
    }
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error(err);
        }
        res.redirect('/');
    });
});

// Iniciar o servidor
app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});