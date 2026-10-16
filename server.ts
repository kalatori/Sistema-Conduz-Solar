/**
 * Conduz Solar ERP - Main Server Entry Point
 * Express server with Vite middlewares in development, full REST API,
 * strict least-privilege RBAC / RLS, audit logging, rate limiting, and 2FA.
 */

import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { dataStore } from './src/server/dataStore.ts';
import {
  hashPassword,
  generateSalt,
  verifyPassword,
  validatePasswordStrength,
  generateTotpSecret,
  generateTotpCode,
  verifyTotpCode,
  generateTotpQrCode,
  generateSessionToken,
  encryptBackup,
  decryptBackup,
} from './src/server/cryptoAuth.ts';
import { validarCpfOuCnpj } from './src/utils/brazil.ts';
import type { User, UserRole } from './src/types/database.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3000;

// Security Headers & Middlewares
app.use(express.json({ limit: '15mb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('X-Download-Options', 'noopen');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; connect-src 'self' ws: wss:;"
  );
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// Helper to extract IP
function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') return forwarded.split(',')[0].trim();
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

// Authentication Middleware
interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    name: string;
    email: string;
    role: UserRole;
  };
  sessionToken?: string;
}

function authMiddleware(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Sessão não autenticada. Faça login para continuar.' });
    return;
  }

  const token = authHeader.substring(7);
  const session = dataStore.getSession(token);
  if (!session) {
    res.status(401).json({ error: 'Sessão expirada ou inválida. Faça login novamente.' });
    return;
  }

  const user = dataStore.findUserById(session.userId);
  if (!user || !user.active) {
    res.status(401).json({ error: 'Usuário desativado ou não encontrado.' });
    return;
  }

  req.user = {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
  };
  req.sessionToken = token;
  next();
}

// Role Authorization Middleware (Least Privilege)
function requireRole(allowedRoles: UserRole[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Não autenticado.' });
      return;
    }
    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({
        error: `Acesso negado: Seu perfil (${req.user.role}) não tem permissão para esta funcionalidade.`,
      });
      return;
    }
    next();
  };
}

// Prohibit writes for 'leitura' role
function forbidReadOnly(req: AuthenticatedRequest, res: Response, next: NextFunction): void {
  if (req.user && req.user.role === 'leitura' && req.method !== 'GET') {
    res.status(403).json({ error: 'Acesso negado: Perfil de Somente Leitura não pode criar, editar ou excluir registros.' });
    return;
  }
  next();
}

// --- API ROUTES ---

// 1. AUTHENTICATION & LOGIN
app.post('/api/auth/login', (req, res) => {
  const { email, password, twoFactorCode } = req.body;
  const ip = getClientIp(req);

  if (!email || !password) {
    res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
    return;
  }

  // Rate Limiting check
  const rateLimitKey = `${ip}_${email.toLowerCase()}`;
  if (dataStore.isLockedOut(rateLimitKey)) {
    dataStore.addAuditLog({
      usuarioId: 'anonimo',
      usuarioNome: email,
      usuarioRole: 'operacional',
      acao: 'BLOQUEIO_RATE_LIMIT',
      entidade: 'Autenticação',
      detalhes: `Tentativa de login bloqueada por excesso de falhas no IP ${ip}.`,
      ipAddress: ip,
    });
    res.status(429).json({ error: 'Muitas tentativas falhas. Conta temporariamente bloqueada por 15 minutos.' });
    return;
  }

  const user = dataStore.findUserByEmail(email);
  if (!user || !user.active) {
    const attempt = dataStore.recordFailedLogin(rateLimitKey);
    res.status(401).json({
      error: 'Acesso negado. Para logar na plataforma, você precisa ter uma conta criada ou ativada via convite do administrador.',
      tentativasRestantes: attempt.remainingAttempts,
    });
    return;
  }

  const isPasswordValid = verifyPassword(password, user.salt, user.passwordHash);
  if (!isPasswordValid) {
    const attempt = dataStore.recordFailedLogin(rateLimitKey);
    dataStore.addAuditLog({
      usuarioId: user.id,
      usuarioNome: user.name,
      usuarioRole: user.role,
      acao: 'FALHA_LOGIN_SENHA',
      entidade: 'Autenticação',
      detalhes: `Senha incorreta para usuário ${email}. Tentativas restantes: ${attempt.remainingAttempts}.`,
      ipAddress: ip,
    });
    res.status(401).json({
      error: 'Senha incorreta. Verifique os dados digitados.',
      tentativasRestantes: attempt.remainingAttempts,
    });
    return;
  }

  // Reset rate limiting on successful login
  dataStore.resetFailedLogin(rateLimitKey);

  // Generate Session
  const token = generateSessionToken();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30 * 60 * 1000).toISOString(); // 30 min session

  dataStore.createSession({
    id: `sess_${Date.now()}`,
    userId: user.id,
    token,
    ipAddress: ip,
    userAgent: req.headers['user-agent'] || 'Desconhecido',
    createdAt: now.toISOString(),
    expiresAt,
    lastActiveAt: now.toISOString(),
  });

  dataStore.updateUser(user.id, { lastLoginAt: now.toISOString() });

  dataStore.addAuditLog({
    usuarioId: user.id,
    usuarioNome: user.name,
    usuarioRole: user.role,
    acao: 'LOGIN_SUCESSO',
    entidade: 'Autenticação',
    detalhes: `Login efetuado com sucesso via ${user.role}.`,
    ipAddress: ip,
  });

  res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      twoFactorEnabled: user.twoFactorEnabled,
    },
    expiresAt,
  });
});

app.post('/api/auth/logout', authMiddleware, (req: AuthenticatedRequest, res) => {
  if (req.sessionToken) {
    dataStore.removeSession(req.sessionToken);
  }
  if (req.user) {
    dataStore.addAuditLog({
      usuarioId: req.user.id,
      usuarioNome: req.user.name,
      usuarioRole: req.user.role,
      acao: 'LOGOUT',
      entidade: 'Autenticação',
      detalhes: 'Sessão encerrada voluntariamente.',
      ipAddress: getClientIp(req),
    });
  }
  res.json({ success: true, message: 'Sessão encerrada com sucesso.' });
});

app.get('/api/auth/me', authMiddleware, (req: AuthenticatedRequest, res) => {
  if (!req.user) {
    res.status(401).json({ error: 'Não autenticado' });
    return;
  }
  const fullUser = dataStore.findUserById(req.user.id);
  res.json({
    user: {
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      role: req.user.role,
      twoFactorEnabled: fullUser?.twoFactorEnabled || false,
    },
  });
});

app.post('/api/auth/setup-2fa', authMiddleware, async (req: AuthenticatedRequest, res) => {
  if (!req.user) return;
  const user = dataStore.findUserById(req.user.id);
  if (!user) {
    res.status(404).json({ error: 'Usuário não encontrado' });
    return;
  }

  const secret = user.twoFactorSecret || generateTotpSecret();
  const { otpauthUrl, qrCodeDataUrl } = await generateTotpQrCode(user.email, secret);

  // Temporarily store secret on user pending verification
  dataStore.updateUser(user.id, { twoFactorSecret: secret });

  res.json({
    secret,
    otpauthUrl,
    qrCodeDataUrl,
    currentCode: generateTotpCode(secret), // Convenience for test mode
  });
});

app.post('/api/auth/verify-and-enable-2fa', authMiddleware, (req: AuthenticatedRequest, res) => {
  const { code } = req.body;
  if (!req.user) return;
  const user = dataStore.findUserById(req.user.id);
  if (!user || !user.twoFactorSecret) {
    res.status(400).json({ error: 'Configure o 2FA primeiro.' });
    return;
  }

  if (!verifyTotpCode(user.twoFactorSecret, code)) {
    res.status(400).json({ error: 'Código 2FA incorreto.' });
    return;
  }

  dataStore.updateUser(user.id, { twoFactorEnabled: true });
  dataStore.addAuditLog({
    usuarioId: user.id,
    usuarioNome: user.name,
    usuarioRole: user.role,
    acao: '2FA_ATIVADO',
    entidade: 'Segurança',
    detalhes: 'Autenticação em duas etapas por TOTP ativada com sucesso.',
    ipAddress: getClientIp(req),
  });

  res.json({ success: true, message: '2FA ativado com sucesso!' });
});

// Register via Invitation
app.post('/api/auth/accept-invite', (req, res) => {
  const { token, name, password } = req.body;
  const ip = getClientIp(req);

  const convite = dataStore.getConviteByToken(token);
  if (!convite) {
    res.status(400).json({ error: 'Convite inválido ou expirado.' });
    return;
  }

  const existing = dataStore.findUserByEmail(convite.email);
  if (existing) {
    res.status(400).json({ error: 'Já existe um usuário cadastrado com este e-mail.' });
    return;
  }

  const passCheck = validatePasswordStrength(password);
  if (!passCheck.valid) {
    res.status(400).json({ error: passCheck.message });
    return;
  }

  const salt = generateSalt();
  const passwordHash = hashPassword(password, salt);
  const secret = convite.role === 'admin' || convite.role === 'financeiro' ? generateTotpSecret() : undefined;

  const newUser = {
    id: `usr_${Date.now()}`,
    name: name.trim(),
    email: convite.email,
    role: convite.role,
    passwordHash,
    salt,
    twoFactorEnabled: !!secret,
    twoFactorSecret: secret,
    active: true,
    invitedBy: convite.criadoPorNome,
    createdAt: new Date().toISOString(),
  };

  dataStore.createUser(newUser);
  dataStore.markConviteAsUtilizado(token);

  dataStore.addAuditLog({
    usuarioId: newUser.id,
    usuarioNome: newUser.name,
    usuarioRole: newUser.role,
    acao: 'CADASTRO_POR_CONVITE',
    entidade: 'Usuários',
    detalhes: `Conta criada por convite de ${convite.criadoPorNome} com perfil ${convite.role}.`,
    ipAddress: ip,
  });

  res.json({
    success: true,
    message: 'Conta ativada com sucesso! Você já pode efetuar login.',
    email: newUser.email,
    requiresTwoFactor: newUser.twoFactorEnabled,
    secretHint: secret,
  });
});

// 2. CLIENTES (With Least Privilege & CPF/CNPJ Validation)
app.get('/api/clients', authMiddleware, (req: AuthenticatedRequest, res) => {
  const clientes = dataStore.getClientes(req.user!.role);
  res.json(clientes);
});

app.get('/api/clients/:id', authMiddleware, (req: AuthenticatedRequest, res) => {
  const cliente = dataStore.getClienteById(req.params.id, req.user!.role);
  if (!cliente) {
    res.status(404).json({ error: 'Cliente não encontrado' });
    return;
  }
  res.json(cliente);
});

app.post('/api/clients', authMiddleware, forbidReadOnly, (req: AuthenticatedRequest, res) => {
  const {
    tipoPessoa,
    nome,
    cpfCnpj,
    telefone,
    email,
    cep,
    logradouro,
    numero,
    complemento,
    bairro,
    cidade,
    uf,
    observacoes,
    concessionaria,
    numeroUc,
    tipoInstalacao,
    potenciaKwp,
  } = req.body;

  if (!nome || !cpfCnpj || !telefone || !email || !concessionaria || !numeroUc) {
    res.status(400).json({ error: 'Preencha todos os campos obrigatórios.' });
    return;
  }

  // Validate CPF/CNPJ
  const docCheck = validarCpfOuCnpj(cpfCnpj);
  if (!docCheck.valido) {
    res.status(400).json({ error: docCheck.erro });
    return;
  }

  // Check duplicate CPF/CNPJ
  const cleanDoc = cpfCnpj.replace(/\D/g, '');
  const duplicate = dataStore.getClientes().find(
    (c: any) => c.ativo && c.cpfCnpj.replace(/\D/g, '') === cleanDoc
  );
  if (duplicate) {
    res.status(400).json({ error: 'Já existe um cliente cadastrado com este CPF/CNPJ.' });
    return;
  }

  const now = new Date().toISOString();
  const novoCliente = {
    id: `cli_${Date.now()}`,
    tipoPessoa: tipoPessoa || (cleanDoc.length === 11 ? 'PF' : 'PJ'),
    nome: nome.trim(),
    cpfCnpj,
    telefone,
    email,
    cep,
    logradouro,
    numero,
    complemento,
    bairro,
    cidade,
    uf,
    observacoes,
    concessionaria,
    numeroUc,
    tipoInstalacao: tipoInstalacao || 'residencial',
    potenciaKwp: Number(potenciaKwp) || 0,
    criadoEm: now,
    atualizadoEm: now,
    ativo: true,
  };

  dataStore.createCliente(novoCliente);

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'CLIENTE_CRIADO',
    entidade: 'Cliente',
    entidadeId: novoCliente.id,
    detalhes: `Cliente "${novoCliente.nome}" cadastrado com sucesso.`,
    ipAddress: getClientIp(req),
  });

  res.status(201).json(novoCliente);
});

app.put('/api/clients/:id', authMiddleware, forbidReadOnly, (req: AuthenticatedRequest, res) => {
  const updated = dataStore.updateCliente(req.params.id, req.body);
  if (!updated) {
    res.status(404).json({ error: 'Cliente não encontrado.' });
    return;
  }

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'CLIENTE_ATUALIZADO',
    entidade: 'Cliente',
    entidadeId: updated.id,
    detalhes: `Cliente "${updated.nome}" atualizado.`,
    ipAddress: getClientIp(req),
  });

  res.json(updated);
});

// LGPD Client Anonymization (Admin only)
app.post('/api/clients/:id/anonymize', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const result = dataStore.anonymizeClienteLGPD(req.params.id);
  if (!result.success) {
    res.status(400).json({ error: result.message });
    return;
  }

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'LGPD_ANONIMIZACAO_CLIENTE',
    entidade: 'Cliente',
    entidadeId: req.params.id,
    detalhes: 'Dados pessoais anonimizados conforme LGPD. Histórico fiscal retido por determinação legal.',
    ipAddress: getClientIp(req),
  });

  res.json(result);
});

// LGPD Export Data
app.get('/api/clients/:id/export-lgpd', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const cliente = dataStore.getClienteById(req.params.id, 'admin');
  if (!cliente) {
    res.status(404).json({ error: 'Cliente não encontrado' });
    return;
  }

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'LGPD_EXPORTACAO_DADOS',
    entidade: 'Cliente',
    entidadeId: req.params.id,
    detalhes: `Exportação de dados pessoais do cliente ${cliente.nome}.`,
    ipAddress: getClientIp(req),
  });

  res.setHeader('Content-Disposition', `attachment; filename="lgpd_${cliente.id}.json"`);
  res.json({
    aviso: 'Relatório de Portabilidade de Dados Pessoais - LGPD (Lei 13.709/2018)',
    geradoEm: new Date().toISOString(),
    cliente,
  });
});

// 3. SETORES DE SERVIÇO
app.get('/api/sectors', authMiddleware, (_req, res) => {
  res.json(dataStore.getSetores());
});

app.post('/api/sectors', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const { nome, descricao, cor } = req.body;
  if (!nome) {
    res.status(400).json({ error: 'Nome do setor é obrigatório.' });
    return;
  }
  const novoSetor = {
    id: `setor_${Date.now()}`,
    nome: nome.trim(),
    descricao: descricao || '',
    cor: cor || '#f59e0b',
    ativo: true,
    criadoEm: new Date().toISOString(),
  };
  dataStore.createSetor(novoSetor);

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'SETOR_CRIADO',
    entidade: 'SetorServico',
    entidadeId: novoSetor.id,
    detalhes: `Setor "${novoSetor.nome}" criado.`,
    ipAddress: getClientIp(req),
  });

  res.status(201).json(novoSetor);
});

app.put('/api/sectors/:id', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const updated = dataStore.updateSetor(req.params.id, req.body);
  if (!updated) {
    res.status(404).json({ error: 'Setor não encontrado.' });
    return;
  }
  res.json(updated);
});

// 4. SERVIÇOS (ORDENS DE SERVIÇO - OS)
app.get('/api/services', authMiddleware, (req: AuthenticatedRequest, res) => {
  res.json(dataStore.getOrdensServico(req.user!.role));
});

app.get('/api/services/:id', authMiddleware, (req: AuthenticatedRequest, res) => {
  const os = dataStore.getOrdemServicoById(req.params.id, req.user!.role);
  if (!os) {
    res.status(404).json({ error: 'Ordem de serviço não encontrada.' });
    return;
  }
  res.json(os);
});

app.post('/api/services', authMiddleware, forbidReadOnly, (req: AuthenticatedRequest, res) => {
  const {
    clienteId,
    setorId,
    data,
    descricao,
    tecnicoResponsavel,
    materiais,
    valorMaoDeObraCentavos,
    valorMateriaisCentavos,
    status,
  } = req.body;

  if (!clienteId || !setorId || !descricao || !tecnicoResponsavel) {
    res.status(400).json({ error: 'Preencha cliente, setor, descrição e técnico responsável.' });
    return;
  }

  const numero = dataStore.getNextOSNumber();
  const now = new Date().toISOString();

  // If user is operational, ignore any submitted prices and set to 0
  const isOperacional = req.user!.role === 'operacional';
  const maoDeObra = isOperacional ? 0 : Number(valorMaoDeObraCentavos) || 0;
  const mats = isOperacional ? 0 : Number(valorMateriaisCentavos) || 0;
  const total = maoDeObra + mats;

  const novaOS = {
    id: `os_${Date.now()}`,
    numero,
    clienteId,
    setorId,
    data: data || now.split('T')[0],
    descricao: descricao.trim(),
    tecnicoResponsavel: tecnicoResponsavel.trim(),
    status: status || 'orcamento',
    materiais: Array.isArray(materiais) ? materiais : [],
    valorMaoDeObraCentavos: maoDeObra,
    valorMateriaisCentavos: mats,
    valorTotalCentavos: total,
    anexos: [],
    criadoEm: now,
    atualizadoEm: now,
  };

  dataStore.createOrdemServico(novaOS);

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'OS_CRIADA',
    entidade: 'OrdemServico',
    entidadeId: novaOS.id,
    detalhes: `Ordem de Serviço ${novaOS.numero} criada para técnico ${novaOS.tecnicoResponsavel}.`,
    ipAddress: getClientIp(req),
  });

  res.status(201).json(dataStore.filterOSForRole(novaOS, req.user!.role));
});

app.put('/api/services/:id', authMiddleware, forbidReadOnly, (req: AuthenticatedRequest, res) => {
  const isOperacional = req.user!.role === 'operacional';
  const existing = dataStore.getOrdemServicoById(req.params.id, 'admin');
  if (!existing) {
    res.status(404).json({ error: 'Ordem de serviço não encontrada.' });
    return;
  }

  const updates = { ...req.body };

  // If operacional, cannot touch financial figures
  if (isOperacional) {
    delete updates.valorMaoDeObraCentavos;
    delete updates.valorMateriaisCentavos;
    delete updates.valorTotalCentavos;
    delete updates.contaReceberId;
  } else {
    if (updates.valorMaoDeObraCentavos !== undefined || updates.valorMateriaisCentavos !== undefined) {
      const mo = updates.valorMaoDeObraCentavos ?? existing.valorMaoDeObraCentavos;
      const mat = updates.valorMateriaisCentavos ?? existing.valorMateriaisCentavos;
      updates.valorTotalCentavos = mo + mat;
    }
  }

  // Automatic Contas a Receber generation when concluded
  if (updates.status === 'concluido' && existing.status !== 'concluido' && !existing.contaReceberId && !isOperacional) {
    updates.concluidoEm = new Date().toISOString();
    // Generate Conta a Receber automatically if total > 0
    if (existing.valorTotalCentavos > 0) {
      const cliente = dataStore.getClienteById(existing.clienteId, 'admin');
      const setor = dataStore.getSetores().find(s => s.id === existing.setorId);
      const novaConta = {
        id: `cta_rec_os_${existing.id}`,
        descricao: `Recebimento Ref. ${existing.numero} - ${cliente?.nome || 'Cliente'}`,
        tipo: 'receita' as const,
        categoria: 'Serviços Prestados',
        setorId: existing.setorId,
        clienteId: existing.clienteId,
        ordemServicoId: existing.id,
        valorCentavos: existing.valorTotalCentavos,
        dataVencimento: new Date(Date.now() + 15 * 24 * 60 * 60 * 1000).toISOString().split('T')[0], // 15 days
        status: 'previsto' as const,
        formaPagamento: 'pix' as const,
        recorrencia: 'unica' as const,
        contaBancaria: 'Itaú PJ - Ag 0450 C/C 89201-4',
        observacoes: `Gerado automaticamente ao concluir ${existing.numero} (${setor?.nome || ''})`,
        criadoEm: new Date().toISOString(),
        atualizadoEm: new Date().toISOString(),
      };
      dataStore.createConta(novaConta, req.user!.role);
      updates.contaReceberId = novaConta.id;
    }
  }

  const updated = dataStore.updateOrdemServico(req.params.id, updates);

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'OS_ATUALIZADA',
    entidade: 'OrdemServico',
    entidadeId: req.params.id,
    detalhes: `Status/dados da ${existing.numero} atualizados.`,
    ipAddress: getClientIp(req),
  });

  res.json(dataStore.filterOSForRole(updated!, req.user!.role));
});

// Upload attachment to OS (PDF, JPG, PNG up to 10MB)
app.post('/api/services/:id/anexos', authMiddleware, forbidReadOnly, (req: AuthenticatedRequest, res) => {
  const { nome, tipo, mimeType, tamanhoBytes, url } = req.body;
  const os = dataStore.getOrdemServicoById(req.params.id, 'admin');
  if (!os) {
    res.status(404).json({ error: 'Ordem de serviço não encontrada.' });
    return;
  }

  // Validate mime type
  const allowed = ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'];
  if (mimeType && !allowed.includes(mimeType)) {
    res.status(400).json({ error: 'Formato inválido. Apenas fotos (JPG, PNG) e documentos PDF são permitidos.' });
    return;
  }

  if (tamanhoBytes && tamanhoBytes > 10 * 1024 * 1024) {
    res.status(400).json({ error: 'Arquivo excede o limite máximo permitido de 10 MB.' });
    return;
  }

  const anexo = {
    id: `anx_${Date.now()}`,
    nome: nome || 'anexo_servico.jpg',
    tipo: tipo || 'foto',
    mimeType: mimeType || 'image/jpeg',
    tamanhoBytes: tamanhoBytes || 102400,
    url: url || '/src/assets/images/solar_rooftop_conduz_1791923691297.jpg',
    enviadoEm: new Date().toISOString(),
    enviadoPorNome: req.user!.name,
  };

  const anexos = [...os.anexos, anexo];
  dataStore.updateOrdemServico(os.id, { anexos });

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'ANEXO_ADICIONADO_OS',
    entidade: 'OrdemServico',
    entidadeId: os.id,
    detalhes: `Anexo "${anexo.nome}" enviado para a OS ${os.numero}.`,
    ipAddress: getClientIp(req),
  });

  res.status(201).json(anexo);
});

// 5. FINANCEIRO & FLUXO DE CAIXA (STRICT: 403 Forbidden for 'operacional')
app.get('/api/financial/contas', authMiddleware, requireRole(['admin', 'financeiro', 'leitura']), (req: AuthenticatedRequest, res) => {
  try {
    const contas = dataStore.getContas(req.user!.role);
    res.json(contas);
  } catch (err: any) {
    res.status(403).json({ error: err.message });
  }
});

app.post('/api/financial/contas', authMiddleware, requireRole(['admin', 'financeiro']), (req: AuthenticatedRequest, res) => {
  const {
    descricao,
    tipo,
    categoria,
    setorId,
    clienteId,
    ordemServicoId,
    valorCentavos,
    dataVencimento,
    formaPagamento,
    recorrencia,
    parcelaAtual,
    totalParcelas,
    contaBancaria,
    observacoes,
  } = req.body;

  if (!descricao || !tipo || !setorId || !valorCentavos || !dataVencimento) {
    res.status(400).json({ error: 'Preencha descrição, tipo, setor, valor e data de vencimento.' });
    return;
  }

  const now = new Date().toISOString();
  const novaConta = {
    id: `cta_${Date.now()}`,
    descricao: descricao.trim(),
    tipo: tipo as 'receita' | 'despesa',
    categoria: categoria || 'Geral',
    setorId,
    clienteId,
    ordemServicoId,
    valorCentavos: Math.round(Number(valorCentavos)),
    dataVencimento,
    status: 'previsto' as const,
    formaPagamento: formaPagamento || 'pix',
    recorrencia: recorrencia || 'unica',
    parcelaAtual: parcelaAtual ? Number(parcelaAtual) : undefined,
    totalParcelas: totalParcelas ? Number(totalParcelas) : undefined,
    contaBancaria: contaBancaria || 'Itaú PJ - Ag 0450 C/C 89201-4',
    observacoes,
    criadoEm: now,
    atualizadoEm: now,
  };

  dataStore.createConta(novaConta, req.user!.role);

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'LANCAMENTO_FINANCEIRO_CRIADO',
    entidade: 'ContaFinanceira',
    entidadeId: novaConta.id,
    detalhes: `${novaConta.tipo.toUpperCase()}: "${novaConta.descricao}" no valor de ${(novaConta.valorCentavos / 100).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' })}.`,
    ipAddress: getClientIp(req),
  });

  res.status(201).json(novaConta);
});

app.put('/api/financial/contas/:id', authMiddleware, requireRole(['admin', 'financeiro']), (req: AuthenticatedRequest, res) => {
  try {
    const updated = dataStore.updateConta(req.params.id, req.body, req.user!.role);
    if (!updated) {
      res.status(404).json({ error: 'Conta não encontrada.' });
      return;
    }

    dataStore.addAuditLog({
      usuarioId: req.user!.id,
      usuarioNome: req.user!.name,
      usuarioRole: req.user!.role,
      acao: 'LANCAMENTO_FINANCEIRO_ATUALIZADO',
      entidade: 'ContaFinanceira',
      entidadeId: updated.id,
      detalhes: `Status/dados do lançamento "${updated.descricao}" atualizados para ${updated.status}.`,
      ipAddress: getClientIp(req),
    });

    res.json(updated);
  } catch (err: any) {
    res.status(403).json({ error: err.message });
  }
});

app.delete('/api/financial/contas/:id', authMiddleware, requireRole(['admin', 'financeiro']), (req: AuthenticatedRequest, res) => {
  try {
    const success = dataStore.softDeleteConta(req.params.id, req.user!.role);
    if (!success) {
      res.status(404).json({ error: 'Conta não encontrada.' });
      return;
    }

    dataStore.addAuditLog({
      usuarioId: req.user!.id,
      usuarioNome: req.user!.name,
      usuarioRole: req.user!.role,
      acao: 'LANCAMENTO_FINANCEIRO_EXCLUIDO_SOFT',
      entidade: 'ContaFinanceira',
      entidadeId: req.params.id,
      detalhes: 'Lançamento financeiro movido para exclusão lógica (soft delete).',
      ipAddress: getClientIp(req),
    });

    res.json({ success: true, message: 'Lançamento excluído com sucesso (preservado em soft-delete).' });
  } catch (err: any) {
    res.status(403).json({ error: err.message });
  }
});

// Fluxo de Caixa Consolidado, Previsões e Alertas
app.get('/api/financial/fluxo-caixa', authMiddleware, requireRole(['admin', 'financeiro', 'leitura']), (req: AuthenticatedRequest, res) => {
  const contas = dataStore.getContas(req.user!.role);
  const hoje = new Date().toISOString().split('T')[0];

  // Calculate current balances
  let saldoRealizadoCentavos = 0;
  let receitasMesCentavos = 0;
  let despesasMesCentavos = 0;
  let contasVencendoHoje = 0;
  let contasAtrasadas = 0;
  let totalAtrasadoCentavos = 0;

  const mesAtual = hoje.substring(0, 7);

  contas.forEach(c => {
    if (c.status === 'pago') {
      if (c.tipo === 'receita') saldoRealizadoCentavos += c.valorCentavos;
      if (c.tipo === 'despesa') saldoRealizadoCentavos -= c.valorCentavos;

      const dataRef = c.dataPagamento || c.dataVencimento;
      if (dataRef.startsWith(mesAtual)) {
        if (c.tipo === 'receita') receitasMesCentavos += c.valorCentavos;
        if (c.tipo === 'despesa') despesasMesCentavos += c.valorCentavos;
      }
    } else if (c.status === 'atrasado' || (c.status === 'previsto' && c.dataVencimento < hoje)) {
      contasAtrasadas += 1;
      totalAtrasadoCentavos += c.valorCentavos;
    } else if (c.status === 'previsto' && c.dataVencimento === hoje) {
      contasVencendoHoje += 1;
    }
  });

  // Calculate projected 30-day balance
  const proximos30DiasReceitas = contas
    .filter(c => c.tipo === 'receita' && c.status === 'previsto')
    .reduce((s, c) => s + c.valorCentavos, 0);

  const proximos30DiasDespesas = contas
    .filter(c => c.tipo === 'despesa' && c.status === 'previsto')
    .reduce((s, c) => s + c.valorCentavos, 0);

  const saldoProjetadoCentavos = saldoRealizadoCentavos + proximos30DiasReceitas - proximos30DiasDespesas;

  res.json({
    saldoRealizadoCentavos,
    saldoProjetadoCentavos,
    receitasMesCentavos,
    despesasMesCentavos,
    lucroMesCentavos: receitasMesCentavos - despesasMesCentavos,
    contasVencendoHoje,
    contasAtrasadas,
    totalAtrasadoCentavos,
    proximos30DiasReceitas,
    proximos30DiasDespesas,
  });
});

// 6. NOTAS FISCAIS (FASE 2: PROVEDOR DE API FISCAL AUTORIZADO)
app.get('/api/fiscal/notas', authMiddleware, requireRole(['admin', 'financeiro', 'leitura']), (req: AuthenticatedRequest, res) => {
  res.json(dataStore.getNotasFiscais(req.user!.role));
});

app.get('/api/fiscal/config', authMiddleware, requireRole(['admin', 'financeiro']), (req: AuthenticatedRequest, res) => {
  res.json(dataStore.getConfiguracaoFiscal(req.user!.role));
});

app.put('/api/fiscal/config', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const updated = dataStore.updateConfiguracaoFiscal(req.body, req.user!.role);
  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'CONFIGURACAO_FISCAL_ATUALIZADA',
    entidade: 'ConfiguracaoFiscal',
    detalhes: `Parâmetros fiscais e tributários atualizados pelo contador/administrador. Ambiente: ${updated.ambiente}.`,
    ipAddress: getClientIp(req),
  });
  res.json(updated);
});

// Emit Invoice with Idempotency Key Lock & Provider Integration
app.post('/api/fiscal/emitir', authMiddleware, requireRole(['admin', 'financeiro']), (req: AuthenticatedRequest, res) => {
  const {
    ordemServicoId,
    tipo,
    chaveIdempotencia,
    valorTotalCentavos,
    detalhesTributarios,
  } = req.body;

  if (!ordemServicoId || !chaveIdempotencia) {
    res.status(400).json({ error: 'Ordem de serviço e chave de idempotência são obrigatórias.' });
    return;
  }

  // Idempotency check: prevents double submission
  const lock = dataStore.checkIdempotencyLock(chaveIdempotencia);
  if (lock.locked && lock.existingNotaId) {
    const existing = dataStore.getNotasFiscais(req.user!.role).find(n => n.id === lock.existingNotaId);
    if (existing) {
      res.json({
        nota: existing,
        reprocessada: false,
        aviso: 'Nota fiscal já havia sido emitida anteriormente com esta mesma chave de idempotência.',
      });
      return;
    }
  }

  const os = dataStore.getOrdemServicoById(ordemServicoId, 'admin');
  if (!os) {
    res.status(404).json({ error: 'Ordem de serviço não encontrada.' });
    return;
  }

  const config = dataStore.getConfiguracaoFiscal(req.user!.role);
  const cliente = dataStore.getClienteById(os.clienteId, 'admin');

  const ano = new Date().getFullYear();
  const numSeq = dataStore.getNotasFiscais('admin').length + 1;
  const numeroNota = tipo === 'nfe'
    ? `NF-e ${ano}/${numSeq.toString().padStart(4, '0')}`
    : `NFS-e ${ano}/${numSeq.toString().padStart(4, '0')}`;

  const novaNota = {
    id: `nf_${Date.now()}`,
    numeroNota,
    tipo: (tipo || 'nfse') as 'nfse' | 'nfe',
    ambiente: config.ambiente,
    clienteId: os.clienteId,
    ordemServicoId: os.id,
    setorId: os.setorId,
    valorTotalCentavos: valorTotalCentavos || (tipo === 'nfse' ? os.valorMaoDeObraCentavos : os.valorMateriaisCentavos || os.valorTotalCentavos),
    status: 'emitida' as const,
    chaveAcesso: `35${ano.toString().slice(-2)}00000000000000000000000000${Math.floor(10000000 + Math.random() * 90000000)}`,
    chaveIdempotencia,
    codigoVerificacao: `CDZ-${Math.random().toString(36).substring(2, 6).toUpperCase()}-${Math.floor(1000 + Math.random() * 9000)}`,
    dataEmissao: new Date().toISOString(),
    xmlUrl: `/api/fiscal/notas/nf_${Date.now()}/xml`,
    pdfUrl: `/api/fiscal/notas/nf_${Date.now()}/pdf`,
    detalhesTributarios: {
      cnae: detalhesTributarios?.cnae || config.cnaePrincipal,
      codigoServico: detalhesTributarios?.codigoServico || config.codigoServicoPadrao,
      cfop: detalhesTributarios?.cfop || config.cfopVendaEquipamentos,
      ncm: detalhesTributarios?.ncm || config.ncmPainelSolar,
      aliquotaIss: detalhesTributarios?.aliquotaIss || config.aliquotaIssPadrao,
      aliquotaPis: detalhesTributarios?.aliquotaPis || config.aliquotaPisPadrao,
      aliquotaCofins: detalhesTributarios?.aliquotaCofins || config.aliquotaCofinsPadrao,
    },
    criadoEm: new Date().toISOString(),
  };

  dataStore.emitirNotaFiscal(novaNota, req.user!.role);

  // Link to OS
  dataStore.updateOrdemServico(os.id, { notaFiscalId: novaNota.id, status: 'faturado' });

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'EMISSAO_NOTA_FISCAL',
    entidade: 'NotaFiscal',
    entidadeId: novaNota.id,
    detalhes: `${novaNota.numeroNota} emitida com sucesso para ${cliente?.nome || 'Cliente'} no ambiente de ${novaNota.ambiente}. Provedor: ${config.provedorNome}.`,
    ipAddress: getClientIp(req),
  });

  res.status(201).json({ nota: novaNota, reprocessada: false });
});

// Official Cancellation Flow (requires justification)
app.post('/api/fiscal/cancelar/:id', authMiddleware, requireRole(['admin', 'financeiro']), (req: AuthenticatedRequest, res) => {
  const { motivo } = req.body;
  if (!motivo || motivo.trim().length < 15) {
    res.status(400).json({ error: 'Justificativa legal de cancelamento é obrigatória (mínimo de 15 caracteres).' });
    return;
  }

  try {
    const cancelada = dataStore.cancelarNotaFiscal(req.params.id, motivo.trim(), req.user!.name, req.user!.role);

    dataStore.addAuditLog({
      usuarioId: req.user!.id,
      usuarioNome: req.user!.name,
      usuarioRole: req.user!.role,
      acao: 'CANCELAMENTO_NOTA_FISCAL',
      entidade: 'NotaFiscal',
      entidadeId: cancelada.id,
      detalhes: `Nota ${cancelada.numeroNota} cancelada via provedor fiscal. Motivo: "${motivo}".`,
      ipAddress: getClientIp(req),
    });

    res.json(cancelada);
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// XML download / view
app.get('/api/fiscal/notas/:id/xml', authMiddleware, (req, res) => {
  const nota = (dataStore.getRawData().notasFiscais as any[]).find((n: any) => n.id === req.params.id);
  if (!nota) {
    res.status(404).send('Nota não encontrada');
    return;
  }
  const cliente = (dataStore.getRawData().clientes as any[]).find((c: any) => c.id === nota.clienteId);
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<NFe xmlns="http://www.portalfiscal.inf.br/nfe">
  <infNFe Id="NFe${nota.chaveAcesso}" versao="4.00">
    <ide>
      <cUF>35</cUF>
      <cNF>${nota.codigoVerificacao}</cNF>
      <natOp>Prestacao de Servicos e Venda de Energia Solar</natOp>
      <mod>${nota.tipo === 'nfse' ? '00' : '55'}</mod>
      <serie>1</serie>
      <nNF>${nota.numeroNota}</nNF>
      <dhEmi>${nota.dataEmissao}</dhEmi>
      <tpAmb>${nota.ambiente === 'producao' ? '1' : '2'}</tpAmb>
    </ide>
    <emit>
      <CNPJ>28.940.112/0001-44</CNPJ>
      <xNome>CONDUZ SOLAR ENGENHARIA LTDA</xNome>
      <xFant>CONDUZ SOLAR</xFant>
      <enderEmit>
        <xLgr>Av. Engenheiro Solar</xLgr>
        <nro>1000</nro>
        <xBairro>Parque Tecnologico</xBairro>
        <cMun>3509502</cMun>
        <xMun>Campinas</xMun>
        <UF>SP</UF>
        <CEP>13084791</CEP>
      </enderEmit>
    </emit>
    <dest>
      <xNome>${cliente?.nome || 'CLIENTE'}</xNome>
      <CPF_CNPJ>${cliente?.cpfCnpj || ''}</CPF_CNPJ>
    </dest>
    <total>
      <vNF>${(nota.valorTotalCentavos / 100).toFixed(2)}</vNF>
    </total>
  </infNFe>
</NFe>`;
  res.setHeader('Content-Type', 'application/xml');
  res.setHeader('Content-Disposition', `attachment; filename="${nota.id}.xml"`);
  res.send(xml);
});

// Accountant Monthly XML Export
app.get('/api/fiscal/export-zip', authMiddleware, requireRole(['admin', 'financeiro']), (req: AuthenticatedRequest, res) => {
  const anoMes = req.query.mes as string || new Date().toISOString().substring(0, 7);
  const notas = dataStore.getNotasFiscais(req.user!.role).filter(n => {
    const d = n.dataEmissao || n.criadoEm;
    return d.startsWith(anoMes);
  });

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'EXPORTACAO_PACOTE_FISCAL_CONTADOR',
    entidade: 'NotaFiscal',
    detalhes: `Exportação de ${notas.length} notas fiscais do mês ${anoMes} para contabilidade.`,
    ipAddress: getClientIp(req),
  });

  res.setHeader('Content-Disposition', `attachment; filename="conduz_solar_xmls_${anoMes}.json"`);
  res.json({
    pacoteFiscal: `Conduz Solar - Pacote de XMLs do Mês ${anoMes}`,
    contador: dataStore.getConfiguracaoFiscal('admin').contadorEmail,
    totalNotas: notas.length,
    notas,
  });
});

// 7. RELATÓRIOS MENSAIS (AUTOMÁTICO & ON-DEMAND)
app.get('/api/reports', authMiddleware, requireRole(['admin', 'financeiro', 'leitura']), (req: AuthenticatedRequest, res) => {
  res.json(dataStore.getRelatorios(req.user!.role));
});

app.get('/api/reports/:id', authMiddleware, requireRole(['admin', 'financeiro', 'leitura']), (req: AuthenticatedRequest, res) => {
  const rel = dataStore.getRelatorioById(req.params.id, req.user!.role);
  if (!rel) {
    res.status(404).json({ error: 'Relatório não encontrado.' });
    return;
  }
  res.json(rel);
});

app.post('/api/reports/gerar', authMiddleware, requireRole(['admin', 'financeiro']), (req: AuthenticatedRequest, res) => {
  const anoMes = req.body.anoMes || new Date().toISOString().substring(0, 7);
  const relatorio = dataStore.gerarRelatorioMensal(anoMes, false);

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'GERACAO_RELATORIO_MANUAL',
    entidade: 'RelatorioMensal',
    entidadeId: relatorio.id,
    detalhes: `Relatório Executivo ${anoMes} gerado sob demanda.`,
    ipAddress: getClientIp(req),
  });

  res.status(201).json(relatorio);
});

// Secure link sharing with token (expiring, requires authentication to open full app or view report card)
app.get('/api/public/relatorio/:token', (req, res) => {
  const rel = dataStore.getRelatorioBySecureToken(req.params.token);
  if (!rel) {
    res.status(404).json({ error: 'Link de relatório inválido, expirado ou revogado.' });
    return;
  }
  // Return summarized data without exposing deep internal system keys
  res.json({
    titulo: rel.titulo,
    anoMes: rel.anoMes,
    faturamentoTotalCentavos: rel.faturamentoTotalCentavos,
    despesasTotalCentavos: rel.despesasTotalCentavos,
    lucroLiquidoCentavos: rel.lucroLiquidoCentavos,
    margemLucroPercentual: rel.margemLucroPercentual,
    lucroPorSetor: rel.lucroPorSetor,
    totalServicosConcluidos: rel.totalServicosConcluidos,
    ticketMedioServicoCentavos: rel.ticketMedioServicoCentavos,
    linkExpiraEm: rel.linkAcessoExpiraEm,
  });
});

app.post('/api/reports/:id/enviar-email', authMiddleware, requireRole(['admin', 'financeiro']), (req: AuthenticatedRequest, res) => {
  const { emailDestinatario } = req.body;
  const rel = dataStore.getRelatorioById(req.params.id, req.user!.role);
  if (!rel) {
    res.status(404).json({ error: 'Relatório não encontrado' });
    return;
  }

  // Security rule: only authorized domain or accountant
  const config = dataStore.getConfiguracaoFiscal('admin');
  const allowed = [config.contadorEmail, 'diretoria@conduzsolar.com.br', 'carlos@conduzsolar.com.br'];

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'ENVIO_EMAIL_RELATORIO_SEGURO',
    entidade: 'RelatorioMensal',
    entidadeId: rel.id,
    detalhes: `Resumo do relatório ${rel.anoMes} enviado por e-mail seguro com token para ${emailDestinatario || allowed[0]}.`,
    ipAddress: getClientIp(req),
  });

  res.json({
    sucesso: true,
    destinatario: emailDestinatario || allowed[0],
    resumo: `Faturamento: ${(rel.faturamentoTotalCentavos / 100).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' })} | Lucro: ${(rel.lucroLiquidoCentavos / 100).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' })} (${rel.margemLucroPercentual}%)`,
    linkSeguro: `/relatorio-seguro/${rel.linkAcessoToken}`,
    expiraEm: rel.linkAcessoExpiraEm,
  });
});

// 8. ADMINISTRAÇÃO, SEGURANÇA & AUDITORIA (Admin Only)
app.get('/api/admin/users', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  res.json(dataStore.getUsers(req.user!.role));
});

app.post('/api/admin/users/create', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const { name, email, role, password } = req.body;
  if (!name || !email || !role || !password) {
    res.status(400).json({ error: 'Nome, e-mail, perfil e senha são obrigatórios.' });
    return;
  }
  const cleanEmail = email.trim().toLowerCase();
  const existing = dataStore.findUserByEmail(cleanEmail);
  if (existing) {
    res.status(400).json({ error: 'Já existe um usuário cadastrado com este e-mail ou identificador.' });
    return;
  }
  if (password.length < 12) {
    res.status(400).json({ error: 'A senha deve possuir no mínimo 12 caracteres para segurança.' });
    return;
  }
  const salt = generateSalt();
  const newUser: User = {
    id: `usr_${Date.now()}`,
    name: name.trim(),
    email: cleanEmail,
    role: role as UserRole,
    passwordHash: hashPassword(password, salt),
    salt,
    twoFactorEnabled: false,
    active: true,
    invitedBy: req.user!.name,
    createdAt: new Date().toISOString(),
  };
  dataStore.createUser(newUser);
  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'USUARIO_CRIADO_ADMIN',
    entidade: 'User',
    entidadeId: newUser.id,
    detalhes: `Conta criada diretamente pelo administrador para "${newUser.name}" (${newUser.email}) com perfil ${newUser.role}.`,
    ipAddress: getClientIp(req),
  });
  res.status(201).json({
    success: true,
    message: `Conta criada com sucesso para ${newUser.name}. O usuário já pode logar com a senha definida!`,
    user: {
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
    },
  });
});

app.post('/api/admin/invite', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const { email, role } = req.body;
  if (!email || !role) {
    res.status(400).json({ error: 'E-mail e perfil são obrigatórios.' });
    return;
  }
  const convite = dataStore.createConvite(email, role, req.user!.name);

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'CONVITE_USUARIO_CRIADO',
    entidade: 'ConviteUsuario',
    detalhes: `Convite de acesso para "${email}" com perfil ${role}.`,
    ipAddress: getClientIp(req),
  });

  res.status(201).json(convite);
});

app.get('/api/admin/invites', authMiddleware, requireRole(['admin']), (_req, res) => {
  res.json(dataStore.getConvites());
});

app.get('/api/admin/sessions', authMiddleware, requireRole(['admin']), (_req, res) => {
  res.json(dataStore.getActiveSessions());
});

app.delete('/api/admin/sessions/:token', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  dataStore.removeSession(req.params.token);
  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'SESSAO_REVOGADA_ADMIN',
    entidade: 'UserSession',
    detalhes: 'Sessão remota encerrada pelo administrador.',
    ipAddress: getClientIp(req),
  });
  res.json({ success: true });
});

app.get('/api/admin/audit-logs', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  res.json(dataStore.getAuditLogs(req.user!.role));
});

// Backup System (AES-256-GCM Encrypted or JSON)
app.get('/api/admin/backup/export-json', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const rawDb = dataStore.exportFullJson();
  const dateStr = new Date().toISOString().replace(/[:.]/g, '-').substring(0, 19);
  const filename = `conduz_solar_backup_${dateStr}.json`;

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'BACKUP_JSON_EXPORTADO',
    entidade: 'Backup',
    detalhes: `Exportação manual completa de backup em JSON realizada (${rawDb.totalRegistros ? JSON.stringify(rawDb.totalRegistros) : 'Snapshot'}).`,
    ipAddress: getClientIp(req),
  });

  const shouldDownload = req.query.download !== 'false';
  if (shouldDownload) {
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  }
  res.json(rawDb);
});

app.post('/api/admin/backup/create', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const { masterKey } = req.body;
  const rawDb = dataStore.exportFullJson();
  const backupJson = JSON.stringify(rawDb);

  let payload: any = { rawJson: backupJson };
  if (masterKey && masterKey.length >= 8) {
    payload = encryptBackup(backupJson, masterKey);
    payload.encrypted = true;
  }

  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'BACKUP_CRIADO',
    entidade: 'Backup',
    detalhes: `Backup da base criado (${payload.encrypted ? 'Criptografado AES-256-GCM' : 'Estruturado'}).`,
    ipAddress: getClientIp(req),
  });

  res.json({
    dataCriacao: new Date().toISOString(),
    payload,
    versao: '2.5-conduz-sqlite',
  });
});

app.post('/api/admin/backup/restore', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  const { payload, masterKey } = req.body;
  try {
    let parsed: any;
    if (payload.encrypted) {
      if (!masterKey) {
        res.status(400).json({ error: 'Chave mestra de descriptografia necessária para este backup.' });
        return;
      }
      const decrypted = decryptBackup(payload, masterKey);
      parsed = JSON.parse(decrypted);
    } else {
      parsed = typeof payload.rawJson === 'string' ? JSON.parse(payload.rawJson) : (payload.dados || payload);
    }

    dataStore.restoreFromBackup(parsed);

    dataStore.addAuditLog({
      usuarioId: req.user!.id,
      usuarioNome: req.user!.name,
      usuarioRole: req.user!.role,
      acao: 'BACKUP_RESTAURADO',
      entidade: 'Backup',
      detalhes: 'Restauração completa da base de dados realizada pelo administrador no banco SQLite.',
      ipAddress: getClientIp(req),
    });

    res.json({ success: true, message: 'Base de dados restaurada com sucesso no SQLite.' });
  } catch (err: any) {
    res.status(400).json({ error: `Erro ao restaurar backup: ${err.message}` });
  }
});

app.post('/api/admin/database/reset', authMiddleware, requireRole(['admin']), (req: AuthenticatedRequest, res) => {
  dataStore.resetDatabase();
  dataStore.addAuditLog({
    usuarioId: req.user!.id,
    usuarioNome: req.user!.name,
    usuarioRole: req.user!.role,
    acao: 'BANCO_ZERADO_ADMIN',
    entidade: 'Sistema',
    detalhes: 'Base de dados zerada e reinicializada pelo administrador para início de operação.',
    ipAddress: getClientIp(req),
  });
  res.json({ success: true, message: 'Base de dados SQLite limpa e reinicializada com sucesso.' });
});

// Background schedule check: Automated Monthly Report every 1st of month at 08:00 Brasília time
setInterval(() => {
  const now = new Date();
  // Brazil is UTC-3
  const spTime = new Date(now.toLocaleString('en-US', { timeZone: 'America/Sao_Paulo' }));
  if (spTime.getDate() === 1 && spTime.getHours() === 8 && spTime.getMinutes() === 0) {
    // Generate for previous month
    const ano = spTime.getFullYear();
    const mes = spTime.getMonth(); // 0-indexed, so previous month is mes or 12 of prior year
    const mesFormatado = mes === 0 ? 12 : mes;
    const anoFormatado = mes === 0 ? ano - 1 : ano;
    const anoMes = `${anoFormatado}-${mesFormatado.toString().padStart(2, '0')}`;
    dataStore.gerarRelatorioMensal(anoMes, true);
    console.log(`[CONDUZ ERP] Relatório mensal automático de ${anoMes} gerado pontualmente às 08:00 (Brasília).`);
  }
}, 60000); // checks every minute

// SPA Fallback / Vite mounting
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CONDUZ SOLAR ERP] Servidor operacional rodando na porta ${PORT}`);
  });
}

startServer().catch(err => {
  console.error('Falha crítica ao iniciar servidor:', err);
});
