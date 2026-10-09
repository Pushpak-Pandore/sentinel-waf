import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { prisma } from '../db/prisma';
import { authenticateToken, requireRole } from '../middleware/auth';
import { logAudit } from '../services/auditLogger';

const router = Router();

const updateSettingSchema = z.object({
  key: z.string().min(1),
  value: z.string().min(1),
});

router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const settings = await prisma.systemSetting.findMany();
    const map: Record<string, string> = {};
    for (const s of settings) {
      map[s.key] = s.value;
    }
    res.json({
      settings: map,
      raw: settings,
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

router.post('/', authenticateToken, requireRole('ADMIN'), async (req: Request, res: Response): Promise<void> => {
  try {
    const { key, value } = updateSettingSchema.parse(req.body);

    if (key === 'WAF_MODE' && !['PREVENTION', 'DETECTION', 'DISABLED'].includes(value)) {
      res.status(400).json({ error: 'Invalid WAF Mode value. Must be PREVENTION, DETECTION, or DISABLED.' });
      return;
    }

    const setting = await prisma.systemSetting.upsert({
      where: { key },
      update: { value },
      create: { key, value, description: `System configuration parameter for ${key}` },
    });

    await logAudit(key === 'WAF_MODE' ? 'MODE_CHANGE' : 'SETTING_UPDATE', 'SystemSetting', setting.id, { key, value }, req.user?.userId, req.user?.email, req.ip);

    res.json(setting);
  } catch (err: any) {
    res.status(400).json({ error: 'Failed to update setting', details: err.message });
  }
});

// Export complete WAF configuration bundle
router.get('/export-config', authenticateToken, async (req: Request, res: Response) => {
  try {
    const { exportWafConfiguration } = await import('../services/configExporter.js');
    const bundle = await exportWafConfiguration();
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename=sentinel-waf-config-backup.json');
    res.json(bundle);
  } catch (err: any) {
    res.status(500).json({ error: 'Configuration export failed' });
  }
});

export default router;
