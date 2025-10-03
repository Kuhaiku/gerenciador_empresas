// ---------------- IMPORTAÇÕES ----------------
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs'); // CORREÇÃO: Usando bcryptjs, que está instalado
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const session = require('express-session');
const path = require('path');
const stripe = require('stripe');

// ---------------- CONFIGURAÇÕES ----------------
const app = express();
const port = 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  port: process.env.DB_PORT
};

// Função de conexão simplificada
async function createDBConnection() {
  try {
    const connection = await mysql.createConnection(dbConfig);
    return connection;
  } catch (error) {
    console.error('Erro ao conectar MySQL:', error);
    throw error;
  }
}

// Helper para obter o ID do usuário logado a partir do e-mail da sessão
async function getUserIdByEmail(email, connection) {
  const [rows] = await connection.execute(
    'SELECT id FROM users WHERE email = ?',
    [email]
  );
  return rows.length > 0 ? rows[0].id : null; 
}


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
  secret: process.env.SESSION_SECRET || 'seu_segredo_super_seguro',
  resave: false,
  saveUninitialized: true,
  // Para produção em Easypanel (HTTPS), mude para secure: true
  cookie: { secure: false, maxAge: 3600000 } 
}));
app.use(express.static(path.join(__dirname, 'public')));

// ---------------- STRIPE ----------------
// OBS: Removido o cliente Stripe caso não esteja em uso no momento
// const stripeClient = stripe(process.env.STRIPE_SECRET_KEY);
// const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID;

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
    req.session.message = 'Faça login para assinar.';
    return res.redirect('/');
  }
  const message = req.session.message || null;
  req.session.message = null;
  res.render('subscription', { message });
});

// ---------------- ROTA DASHBOARD (ATUALIZADA COM EMPRESAS) ----------------

app.get('/dashboard', async (req, res) => {
    if (!req.session.loggedin) {
      req.session.message = 'Faça login para acessar o dashboard.';
      return res.redirect('/');
    }
  
    const userEmail = req.session.email;
    const connection = await createDBConnection();
  
    try {
      // 1. Obter status de assinatura e ID do usuário
      const [userRows] = await connection.execute(
        'SELECT id, subscription_status FROM users WHERE email = ?',
        [userEmail]
      );
      
      if (userRows.length === 0) {
          req.session.message = 'Usuário não encontrado.';
          return res.redirect('/logout');
      }
      
      const user = userRows[0];
      const subscriptionStatus = user.subscription_status || 'inactive';
      
      let companies = [];
      
      if (subscriptionStatus === 'active') {
          // 2. Obter lista de empresas ativas para o usuário (Multi-Tenant)
          const [companyRows] = await connection.execute(
              'SELECT id, name, cnpj FROM companies WHERE user_id = ? ORDER BY name ASC',
              [user.id]
          );
          companies = companyRows;
      }
  
      const message = req.session.message || null;
      req.session.message = null;
      
      // Passa a lista de empresas para a view
      res.render('dashboard', { 
          message, 
          email: userEmail, 
          subscriptionStatus, 
          companies // Novo dado para o grid de empresas
      });
      
    } catch (error) {
      console.error('Erro ao carregar dashboard:', error);
      req.session.message = 'Erro no servidor ao carregar o dashboard.';
      res.redirect('/');
    } finally {
      connection.end();
    }
});

// ---------------- ROTAS EMPRESA (NOVO) ----------------

// Rota para o formulário de Cadastro de Empresa (Crítica)
app.get('/company/register', (req, res) => {
  if (!req.session.loggedin) {
      req.session.message = 'Faça login para acessar esta funcionalidade.';
      return res.redirect('/');
  }
  const message = req.session.message;
  req.session.message = null;
  res.render('company_register', { message }); 
});

// Rota para o perfil da empresa (Crítica)
app.get('/company/:id', async (req, res) => {
  if (!req.session.loggedin) {
      req.session.message = 'Faça login para acessar esta funcionalidade.';
      return res.redirect('/');
  }
  
  const companyId = req.params.id;
  const userEmail = req.session.email;
  const connection = await createDBConnection();

  try {
      const userId = await getUserIdByEmail(userEmail, connection);
      if (!userId) {
          req.session.message = 'Usuário não encontrado.';
          return res.redirect('/dashboard');
      }

      // Busca a empresa e verifica se pertence ao usuário (Multi-Tenant)
      const [companyRows] = await connection.execute(
          'SELECT * FROM companies WHERE id = ? AND user_id = ?',
          [companyId, userId]
      );

      if (companyRows.length === 0) {
          req.session.message = 'Empresa não encontrada ou você não tem permissão para acessá-la.';
          return res.redirect('/dashboard');
      }

      const company = companyRows[0];
      
      // Futuramente: Lógica para buscar Documentos, Débitos e Observações desta empresa
      
      const message = req.session.message || null;
      req.session.message = null;
      
      res.render('company_profile', { message, company }); 

  } catch (error) {
      console.error('Erro ao buscar perfil da empresa:', error);
      req.session.message = 'Erro no servidor ao carregar a empresa.';
      res.redirect('/dashboard');
  } finally {
      connection.end();
  }
});


// ---------------- AUTENTICAÇÃO (POST) ----------------

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

    // Ajuste: A tabela users deve ter 'verification_code' e 'verification_expires_at'
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

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.log(err);
        req.session.message = 'Erro ao enviar e-mail.';
        return res.redirect('/register');
      }
      req.session.message = 'Verifique seu e-mail para ativar a conta.';
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
    // Ajuste: O campo de verificação deve ser 'verified' ou 'is_verified'
    if (!user.verified && !user.is_verified) { 
      req.session.message = 'Conta não verificada.';
      return res.redirect('/');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      req.session.loggedin = true;
      req.session.email = email;
      // Garante que o status da assinatura vá para a sessão
      req.session.subscriptionStatus = user.subscription_status || 'inactive'; 
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

// Recuperação de Senha - Enviar Código
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
    if (!user.verified && !user.is_verified) {
      req.session.message = 'Conta não verificada. Por favor, verifique seu e-mail primeiro.';
      return res.redirect('/forgot-password');
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const resetToken = await bcrypt.hash(code, 10);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hora de validade

    await connection.execute(
      'UPDATE users SET reset_token = ?, reset_expires_at = ? WHERE email = ?',
      [resetToken, expiresAt, email]
    );

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Código de Recuperação de Senha',
      html: `<h2>Seu código de recuperação</h2><p>${code}</p><p>Este código é válido por 1 hora.</p>`
    };

    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        console.error(err);
        req.session.message = 'Erro ao enviar e-mail com código de recuperação.';
        return res.redirect('/forgot-password');
      }
      req.session.message = 'Código de recuperação enviado para o seu e-mail.';
      res.redirect('/reset-password');
    });

  } catch (error) {
    console.error(error);
    req.session.message = 'Erro no servidor ao solicitar recuperação.';
    res.redirect('/forgot-password');
  } finally {
    connection.end();
  }
});

// Redefinir Senha
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
    
    if (!user.reset_token || new Date() > user.reset_expires_at) {
      req.session.message = 'Código inválido ou expirado. Tente solicitar um novo código.';
      return res.redirect('/forgot-password');
    }

    const isMatch = await bcrypt.compare(code, user.reset_token);
    
    if (isMatch) {
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      
      await connection.execute(
        'UPDATE users SET password = ?, reset_token = NULL, reset_expires_at = NULL WHERE email = ?',
        [hashedPassword, email]
      );
      
      req.session.message = 'Senha redefinida com sucesso! Faça login.';
      res.redirect('/');
    } else {
      req.session.message = 'Código inválido.';
      res.redirect('/reset-password');
    }

  } catch (error) {
    console.error(error);
    req.session.message = 'Erro no servidor ao redefinir senha.';
    res.redirect('/reset-password');
  } finally {
    connection.end();
  }
});

// ---------------- LÓGICA DE CADASTRO DE EMPRESA (POST) ----------------

app.post('/company/register', async (req, res) => {
  if (!req.session.loggedin || !req.session.email) {
      req.session.message = 'Sessão expirada. Faça login novamente.';
      return res.redirect('/');
  }

  const { name, cnpj, address, phone } = req.body;
  const userEmail = req.session.email;
  const connection = await createDBConnection();

  try {
      const userId = await getUserIdByEmail(userEmail, connection);
      if (!userId) {
          req.session.message = 'Erro de usuário. Tente novamente.';
          return res.redirect('/company/register');
      }
      
      // Checa se o CNPJ já está cadastrado globalmente
      const [existing] = await connection.execute(
          'SELECT id FROM companies WHERE cnpj = ?',
          [cnpj]
      );

      if (existing.length > 0) {
          req.session.message = 'CNPJ já cadastrado no sistema.';
          return res.redirect('/company/register');
      }

      // Inserir a nova empresa
      const [result] = await connection.execute(
          'INSERT INTO companies (user_id, name, cnpj, address, phone) VALUES (?, ?, ?, ?, ?)',
          [userId, name, cnpj, address, phone]
      );

      const newCompanyId = result.insertId;

      req.session.message = `Empresa ${name} cadastrada com sucesso!`;
      res.redirect(`/company/${newCompanyId}`); // Redireciona para o Perfil da Empresa
      
  } catch (error) {
      console.error('Erro ao cadastrar empresa:', error);
      req.session.message = 'Erro no servidor ao cadastrar empresa.';
      res.redirect('/company/register');
  } finally {
      connection.end();
  }
});

// ---------------- STRIPE / ASSINATURA (Não alteradas, mantendo o original) ----------------

// Simulação de Assinatura (para testes, pois a lógica completa do Stripe depende de variáveis .env)
app.post('/create-subscription', async (req, res) => {
  if (!req.session.loggedin || !req.session.email) {
    req.session.message = 'Faça login para assinar.';
    return res.redirect('/');
  }

  const userEmail = req.session.email;
  const connection = await createDBConnection();

  try {
    // Simulação: Ativa a assinatura no DB
    await connection.execute(
      'UPDATE users SET subscription_status = ? WHERE email = ?',
      ['active', userEmail]
    );
    req.session.subscriptionStatus = 'active';

    req.session.message = 'Assinatura ativada (Simulada) com sucesso! Você foi redirecionado para o Dashboard.';
    res.redirect('/dashboard');
    
  } catch (err) {
    console.error('Erro ao simular Assinatura:', err);
    req.session.message = 'Erro ao processar assinatura.';
    res.redirect('/subscription');
  } finally {
    connection.end();
  }
});

// ---------------- INICIAR SERVIDOR ----------------
app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});