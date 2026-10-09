import { Router, Request, Response } from 'express';
import { authenticateToken } from '../middleware/auth';
import { getTimeSeriesAnalytics, getOverviewStats } from '../services/statsService';
import { prisma } from '../db/prisma';
import { lookupGeoIp } from '../engine/geoip';
import { generateExecutivePdfReport } from '../services/pdfReportGenerator';

const router = Router();

router.get('/', authenticateToken, async (req: Request, res: Response) => {
  try {
    const timeRangeMs = parseInt((req.query.timeframe as string) || '86400000', 10);
    const [stats, timeSeries] = await Promise.all([
      getOverviewStats(timeRangeMs),
      getTimeSeriesAnalytics(timeRangeMs),
    ]);

    res.json({
      summary: stats,
      timeSeries,
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch analytics', details: err.message });
  }
});

/**
 * GET /api/v1/analytics/geo-threats
 * Returns country-level attack event metrics for the World Threat Map
 */
router.get('/geo-threats', authenticateToken, async (req: Request, res: Response) => {
  try {
    const timeframe = (req.query.period as string) || '24h';
    let since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    if (timeframe === '7d') since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    else if (timeframe === '30d') since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    else if (timeframe === 'all') since = new Date(0);

    const events = await prisma.securityEvent.findMany({
      where: { timestamp: { gte: since } },
      select: {
        countryCode: true,
        countryName: true,
        clientIp: true,
        decision: true,
        severity: true,
      },
    });

    const countryMap: Record<string, { countryCode: string; countryName: string; totalEvents: number; blockedCount: number; allowedCount: number; lat: number; lng: number }> = {};

    for (const ev of events) {
      let code = ev.countryCode || 'UNKNOWN';
      let name = ev.countryName || 'Unknown Country';

      // If missing in DB record, attempt real-time lookup
      if (code === 'UNKNOWN' || !code) {
        const geo = lookupGeoIp(ev.clientIp);
        code = geo.countryCode;
        name = geo.countryName;
      }

      if (!countryMap[code]) {
        const geoInfo = lookupGeoIp(ev.clientIp);
        countryMap[code] = {
          countryCode: code,
          countryName: name,
          totalEvents: 0,
          blockedCount: 0,
          allowedCount: 0,
          lat: geoInfo.latitude || 0,
          lng: geoInfo.longitude || 0,
        };
      }

      countryMap[code].totalEvents += 1;
      if (ev.decision === 'BLOCK') countryMap[code].blockedCount += 1;
      else countryMap[code].allowedCount += 1;
    }

    const result = Object.values(countryMap).sort((a, b) => b.totalEvents - a.totalEvents);

    res.json({
      period: timeframe,
      totalEventsAnalyzed: events.length,
      countries: result,
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch geographic threat analytics', details: err.message });
  }
});

/**
 * GET /api/v1/analytics/ml-shadow
 * Returns Machine Learning Anomaly Detection Shadow Mode evaluation stats
 */
router.get('/ml-shadow', authenticateToken, async (req: Request, res: Response) => {
  try {
    const timeframe = (req.query.period as string) || '24h';
    let since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    if (timeframe === '7d') since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const events = await prisma.securityEvent.findMany({
      where: { timestamp: { gte: since } },
      select: {
        id: true,
        correlationId: true,
        path: true,
        method: true,
        decision: true,
        mlAnomalyScore: true,
        mlPrediction: true,
        mlFeatureMeta: true,
        timestamp: true,
      },
    });

    const totalEvaluated = events.length;
    let anomaliesCount = 0;
    let sumScore = 0;
    let agreements = 0;

    for (const ev of events) {
      const score = ev.mlAnomalyScore || 0;
      sumScore += score;
      if (ev.mlPrediction === 'ANOMALY' || score >= 0.6) {
        anomaliesCount += 1;
      }

      // Check agreement: if ML anomaly and WAF blocked, or ML normal and WAF allowed
      const isMlAnomaly = ev.mlPrediction === 'ANOMALY' || score >= 0.6;
      const isWafBlocked = ev.decision === 'BLOCK' || ev.decision === 'RATE_LIMIT';
      if ((isMlAnomaly && isWafBlocked) || (!isMlAnomaly && !isWafBlocked)) {
        agreements += 1;
      }
    }

    const avgScore = totalEvaluated > 0 ? parseFloat((sumScore / totalEvaluated).toFixed(3)) : 0;
    const agreementRate = totalEvaluated > 0 ? parseFloat(((agreements / totalEvaluated) * 100).toFixed(1)) : 100;

    res.json({
      period: timeframe,
      mode: 'SHADOW_NON_BLOCKING',
      totalEvaluated,
      anomaliesCount,
      normalCount: totalEvaluated - anomaliesCount,
      avgAnomalyScore: avgScore,
      wafAgreementPercentage: agreementRate,
      recentAnomalies: events
        .filter((e) => (e.mlAnomalyScore || 0) >= 0.5)
        .slice(0, 10),
    });
  } catch (err: any) {
    res.status(500).json({ error: 'Failed to fetch ML shadow analytics', details: err.message });
  }
});

/**
 * GET /api/v1/analytics/report/pdf
 * Generates and downloads the Executive Security Audit PDF report
 */
router.get('/report/pdf', authenticateToken, async (req: Request, res: Response) => {
  try {
    const period = (req.query.period as string) || '24h';
    const appId = req.query.appId as string;
    const userEmail = (req as any).user?.email || 'Sentinel Admin';

    const pdfBuffer = await generateExecutivePdfReport({
      period,
      appId,
      userEmail,
    });

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `Sentinel_WAF_Executive_Security_Report_${timestamp}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdfBuffer.length);
    res.status(200).send(pdfBuffer);
  } catch (err: any) {
    console.error('[PDF Report Export Error]:', err);
    res.status(500).json({ error: 'Failed to generate PDF report', details: err.message });
  }
});

export default router;
