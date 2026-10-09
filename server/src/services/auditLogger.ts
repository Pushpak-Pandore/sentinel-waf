import { prisma } from '../db/prisma';

export async function logAudit(
  action: string,
  entity: string,
  entityId?: string,
  details?: any,
  userId?: string,
  userEmail?: string,
  ipAddress?: string
): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        action,
        entity,
        entityId: entityId || null,
        details: details ? JSON.stringify(details) : null,
        userId: userId || null,
        userEmail: userEmail || null,
        ipAddress: ipAddress || null,
      },
    });
  } catch (err) {
    console.error('[AuditLogger] Failed to write audit log:', err);
  }
}
