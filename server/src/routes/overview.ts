import { Router, Request, Response } from 'express';
import { authenticateToken } from '../middleware/auth';
import { getOverviewStats } from '../services/statsService';

const router = Router();

router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const timeframe = parseInt((req.query.timeframe as string) || '86400000', 10);
    const stats = await getOverviewStats(timeframe);
    res.json(stats);
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch overview stats', details: err.message });
  }
});

export default router;
