// Importações
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const MercadoPago = require('mercadopago'); // A classe é importada com letra maiúscula

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

// Configuração do Mercado Pago (Sintaxe correta para a versão mais recente)
const mercadopago = new MercadoPago(process.env.MERCADOPAGO_ACCESS_TOKEN);

// Middlewares
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,
        maxAge: 3600000
    }
}));

// Roteamento de arquivos estáticos (CSS, JS, imagens, etc.)
app.use(express.static(path.join(__dirname, 'public')));

// Rotas para servir as páginas EJS
app.get('/', (req, res) => {
    const message = req.session.message;
    req.session.message = null;
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
app.get('/dashboard', async (req, res) => {
    if (req.session.loggedin) {
        const connection = await createDBConnection();
        const [rows] = await connection.execute('SELECT subscription_status FROM users WHERE email = ?', [req.session.email]);
        const subscriptionStatus = rows[0] ? rows[0].subscription_status : 'inactive';
        connection.end();

        const message = req.session.message || null;
        req.session.message = null;
        res.render('dashboard', { message: message, email: req.session.email, subscriptionStatus: subscriptionStatus });
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
app.get('/subscription', (req, res) => {
    if (!req.session.loggedin) {
        req.session.message = 'Você precisa estar logado para assinar o serviço.';
        return res.redirect('/');
    }
    const message = req.session.message || null;
    req.session.message = null;
    res.render('subscription', { message: message });
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
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

        await connection.execute('INSERT INTO users (email, password, verification_code, verification_expires_at) VALUES (?, ?, ?, ?)', [email, hashedPassword, verificationToken, expiresAt]);

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Código de Verificação de Conta',
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4; text-align: center;">
                    <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background-color: #fff;">
                        <h2 style="color: #333;">Verificação de Conta</h2>
                        <p style="color: #555; font-size: 16px;">
                            Olá, <br>
                            Obrigado por se registrar! Use o código abaixo para verificar sua conta.
                        </p>
                        <div style="background-color: #007bff; color: #fff; padding: 15px; border-radius: 5px; margin-top: 20px; font-size: 24px; font-weight: bold;">
                            ${code}
                        </div>
                        <p style="color: #888; font-size: 14px; margin-top: 20px;">
                            Este código é válido por 24 horas.
                        </p>
                    </div>
                </div>
            `
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

// Verificação de e-mail
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
        if (new Date() > user.verification_expires_at) {
            req.session.message = 'Código de verificação expirado. Por favor, registre-se novamente.';
            return res.redirect('/register');
        }
        const isMatch = await bcrypt.compare(code, user.verification_code);

        if (isMatch) {
            await connection.execute('UPDATE users SET verified = 1, verification_code = NULL, verification_expires_at = NULL WHERE email = ?', [email]);
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

            if (req.body.rememberMe) {
                req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;
            } else {
                req.session.cookie.maxAge = 3600000;
            }

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
        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

        await connection.execute('UPDATE users SET reset_token = ?, reset_expires_at = ? WHERE id = ?', [resetToken, expiresAt, user.id]);

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Código de Recuperação de Senha',
            html: `
                <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f4; text-align: center;">
                    <div style="max-width: 600px; margin: auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px; background-color: #fff;">
                        <h2 style="color: #333;">Recuperação de Senha</h2>
                        <p style="color: #555; font-size: 16px;">
                            Olá, <br>
                            Você solicitou a recuperação de sua senha. Use o código abaixo para redefini-la.
                        </p>
                        <div style="background-color: #dc3545; color: #fff; padding: 15px; border-radius: 5px; margin-top: 20px; font-size: 24px; font-weight: bold;">
                            ${code}
                        </div>
                        <p style="color: #888; font-size: 14px; margin-top: 20px;">
                            Este código é válido por 24 horas.
                        </p>
                    </div>
                </div>
            `
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
        if (new Date() > user.reset_expires_at) {
            req.session.message = 'Código de redefinição de senha expirado. Por favor, solicite um novo código.';
            return res.redirect('/forgot-password');
        }
        const isMatch = await bcrypt.compare(code, user.reset_token);

        if (isMatch) {
            const newHashedPassword = await bcrypt.hash(newPassword, 10);
            await connection.execute('UPDATE users SET password = ?, reset_token = NULL, reset_expires_at = NULL WHERE id = ?', [newHashedPassword, user.id]);
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


// Rotas de Assinatura (Mercado Pago)

app.post('/create-subscription', async (req, res) => {
    if (!req.session.loggedin) {
        req.session.message = 'Você precisa estar logado para assinar.';
        return res.redirect('/');
    }
    const connection = await createDBConnection();

    try {
        const [rows] = await connection.execute('SELECT * FROM users WHERE email = ?', [req.session.email]);
        if (rows.length === 0) {
             req.session.message = 'Usuário não encontrado.';
             return res.redirect('/dashboard');
        }
        const user = rows[0];
        if (user.subscription_status === 'active' || user.subscription_status === 'pending') {
             req.session.message = 'Você já tem uma assinatura ativa ou pendente.';
             return res.redirect('/dashboard');
        }

        const userEmail = req.session.email;
        const subscriptionData = {
            reason: 'Assinatura Mensal - Gerenciador de Empresas',
            auto_recurring: {
                frequency: 1,
                frequency_type: 'months',
                transaction_amount: 60,
                currency_id: 'BRL'
            },
            payer_email: userEmail,
            back_url: `http://localhost:3000/subscription/success`,
            status: 'authorized'
        };

        const subscription = await mercadopago.preapproval.create(subscriptionData);

        await connection.execute('UPDATE users SET subscription_status = ?, mp_preapproval_id = ? WHERE email = ?', ['pending', subscription.body.id, userEmail]);
        req.session.message = 'Você será redirecionado para o Mercado Pago para finalizar a sua assinatura.';

        res.redirect(subscription.body.init_point);

    } catch (error) {
        console.error('Erro ao criar a assinatura:', error);
        req.session.message = 'Erro ao criar a sua assinatura.';
        res.redirect('/subscription');
    } finally {
        connection.end();
    }
});

app.get('/subscription/success', async (req, res) => {
    const preapprovalId = req.query.preapproval_id;
    const connection = await createDBConnection();

    try {
        if (!preapprovalId) {
             req.session.message = 'Erro: ID de assinatura não encontrado.';
             return res.redirect('/dashboard');
        }

        const subscription = await mercadopago.preapproval.get(preapprovalId);

        if (subscription.body.status === 'authorized') {
            await connection.execute('UPDATE users SET subscription_status = ?, mp_preapproval_id = ? WHERE email = ?', ['active', preapprovalId, req.session.email]);
            req.session.message = 'Assinatura ativada com sucesso! Você já pode usar o serviço.';
        } else {
            req.session.message = 'Houve um problema com a sua assinatura. Por favor, tente novamente.';
        }

    } catch (error) {
        console.error('Erro ao verificar a assinatura:', error);
        req.session.message = 'Erro ao verificar a sua assinatura.';
    } finally {
        connection.end();
    }
    res.redirect('/dashboard');
});

// Iniciar o servidor
app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});