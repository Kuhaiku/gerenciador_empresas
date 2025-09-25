// Importações
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');

// Mercado Pago (SDK v2)
const { MercadoPagoConfig, PreApproval } = require('mercadopago');
const mpClient = new MercadoPagoConfig({ accessToken: process.env.MERCADOPAGO_ACCESS_TOKEN });
const preapproval = new PreApproval(mpClient);

const app = express();
const port = 3000;

// Configuração do EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Configurações do banco de dados
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

// Configuração do servidor de e-mail
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
  cookie: { secure: false, maxAge: 3600000 }
}));

// Arquivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// ---------------- ROTAS PÁGINAS ----------------
app.get('/', (req, res) => {
  const message = req.session.message;
  req.session.message = null;
  res.render('login', { message });
});

app.get('/register', (req, res) => {
  const message = req.session.message;
  req.session.message = null;
  res.render('register', { message });
});

app.get('/verify-email', (req, res) => {
  const message = req.session.message;
  req.session.message = null;
  res.render('verify_email', { message });
});

app.get('/dashboard', async (req, res) => {
  if (req.session.loggedin) {
    const connection = await createDBConnection();
    const [rows] = await connection.execute(
      'SELECT subscription_status FROM users WHERE email = ?', 
      [req.session.email]
    );
    const subscriptionStatus = rows[0] ? rows[0].subscription_status : 'inactive';
    connection.end();

    const message = req.session.message || null;
    req.session.message = null;
    res.render('dashboard', { message, email: req.session.email, subscriptionStatus });
  } else {
    req.session.message = 'Você precisa estar logado para acessar o dashboard.';
    res.redirect('/');
  }
});

app.get('/forgot-password', (req, res) => {
  const message = req.session.message;
  req.session.message = null;
  res.render('forgot_password', { message });
});

app.get('/reset-password', (req, res) => {
  const message = req.session.message;
  req.session.message = null;
  res.render('reset_password', { message });
});

app.get('/subscription', (req, res) => {
  if (!req.session.loggedin) {
    req.session.message = 'Você precisa estar logado para assinar o serviço.';
    return res.redirect('/');
  }
  const message = req.session.message || null;
  req.session.message = null;
  res.render('subscription', { message });
});

// ---------------- ROTAS DE AUTENTICAÇÃO ----------------

// Registro
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

    await connection.execute(
      'INSERT INTO users (email, password, verification_code, verification_expires_at) VALUES (?, ?, ?, ?)',
      [email, hashedPassword, verificationToken, expiresAt]
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Código de Verificação de Conta',
      html: `<h2>Seu código de verificação</h2><p>${code}</p>`
    };

    transporter.sendMail(mailOptions, (error) => {
      if (error) {
        console.log(error);
        req.session.message = 'Erro ao enviar e-mail.';
        return res.redirect('/register');
      }
      req.session.message = 'Verifique seu e-mail para ativar sua conta.';
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
      req.session.message = 'Código expirado. Registre-se novamente.';
      return res.redirect('/register');
    }
    const isMatch = await bcrypt.compare(code, user.verification_code);

    if (isMatch) {
      await connection.execute(
        'UPDATE users SET verified = 1, verification_code = NULL, verification_expires_at = NULL WHERE email = ?',
        [email]
      );
      req.session.message = 'E-mail verificado. Faça login.';
      res.redirect('/');
    } else {
      req.session.message = 'Código inválido.';
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

// Login
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
      req.session.message = 'Conta não verificada.';
      return res.redirect('/');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      req.session.loggedin = true;
      req.session.email = email;
      req.session.message = 'Bem-vindo!';
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

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error(err);
    res.redirect('/');
  });
});

// ---------------- MERCADO PAGO (ASSINATURA) ----------------

// Criar assinatura
app.post('/create-subscription', async (req, res) => {
  if (!req.session.loggedin) {
    req.session.message = 'Faça login para assinar.';
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
      req.session.message = 'Você já tem assinatura ativa ou pendente.';
      return res.redirect('/dashboard');
    }

    const subscription = await preapproval.create({
      body: {
        reason: 'Assinatura Mensal - Gerenciador de Empresas',
        auto_recurring: {
          frequency: 1,
          frequency_type: 'months',
          transaction_amount: 60,
          currency_id: 'BRL',
        },
        payer_email: req.session.email,
        back_url: `http://localhost:3000/subscription/success`,
        status: 'authorized',
      }
    });

    await connection.execute(
      'UPDATE users SET subscription_status = ?, mp_preapproval_id = ? WHERE email = ?',
      ['pending', subscription.id, req.session.email]
    );
    req.session.message = 'Redirecionando para Mercado Pago...';
    res.redirect(subscription.init_point);

  } catch (error) {
    console.error('Erro ao criar assinatura:', error);
    req.session.message = 'Erro ao criar assinatura.';
    res.redirect('/subscription');
  } finally {
    connection.end();
  }
});

// Callback de sucesso
app.get('/subscription/success', async (req, res) => {
  const preapprovalId = req.query.preapproval_id;
  const connection = await createDBConnection();

  try {
    if (!preapprovalId) {
      req.session.message = 'ID de assinatura não encontrado.';
      return res.redirect('/dashboard');
    }

    const subscription = await preapproval.get({ id: preapprovalId });

    if (subscription.status === 'authorized') {
      await connection.execute(
        'UPDATE users SET subscription_status = ?, mp_preapproval_id = ? WHERE email = ?',
        ['active', preapprovalId, req.session.email]
      );
      req.session.message = 'Assinatura ativada com sucesso!';
    } else {
      req.session.message = 'Problema com sua assinatura. Tente novamente.';
    }

  } catch (error) {
    console.error('Erro ao verificar assinatura:', error);
    req.session.message = 'Erro ao verificar assinatura.';
  } finally {
    connection.end();
  }
  res.redirect('/dashboard');
});

// ---------------- INICIAR SERVIDOR ----------------
app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
