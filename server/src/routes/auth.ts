import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../db/prisma';
import { comparePassword, signJwtToken, authenticateToken } from '../middleware/auth';
import { logAudit } from '../services/auditLogger';

const router = Router();

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

router.post('/login', async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      await logAudit('LOGIN_FAILED', 'User', undefined, { email, reason: 'User not found' }, undefined, email, req.ip);
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const isValid = await comparePassword(password, user.passwordHash);
    if (!isValid) {
      await logAudit('LOGIN_FAILED', 'User', user.id, { email, reason: 'Invalid password' }, user.id, email, req.ip);
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const token = signJwtToken({
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role as 'ADMIN' | 'ANALYST',
    });

    await logAudit('LOGIN_SUCCESS', 'User', user.id, { email }, user.id, email, req.ip);

    // Set HTTP-only secure cookie
    res.cookie('sentinel_token', token, {
      httpOnly: true,
      secure: false, // development mode
      sameSite: 'lax',
      maxAge: 24 * 3600 * 1000,
    });

    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
    });
  } catch (err: any) {
    res.status(400).json({ error: 'Bad Request', details: err.message });
  }
});

router.get('/me', authenticateToken, (req: Request, res: Response) => {
  res.json({ user: req.user });
});

router.post('/logout', (req: Request, res: Response) => {
  res.clearCookie('sentinel_token');
  res.json({ success: true, message: 'Logged out successfully' });
});

export default router;
