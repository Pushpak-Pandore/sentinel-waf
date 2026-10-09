import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

export const prisma = new PrismaClient();

export async function checkDbConnection(): Promise<boolean> {
  try {
    await prisma.$queryRaw`SELECT 1`;

    // Auto-seed default users and settings if database is newly created/empty
    const userCount = await prisma.user.count();
    if (userCount === 0) {
      console.log('[DB Auto-Seed] Database is empty. Seeding default admin & analyst accounts...');
      const adminPasswordHash = await bcrypt.hash('AdminPass123!', 10);
      const analystPasswordHash = await bcrypt.hash('AnalystPass123!', 10);

      await prisma.user.create({
        data: {
          email: 'admin@sentinel.local',
          name: 'Security Administrator',
          passwordHash: adminPasswordHash,
          role: 'ADMIN',
        },
      });

      await prisma.user.create({
        data: {
          email: 'analyst@sentinel.local',
          name: 'Security Analyst',
          passwordHash: analystPasswordHash,
          role: 'ANALYST',
        },
      });

      await prisma.systemSetting.create({
        data: { key: 'WAF_MODE', value: 'PREVENTION', description: 'Global WAF Operating Mode' },
      });

      await prisma.systemSetting.create({
        data: { key: 'DEFAULT_SECURITY_HEADERS', value: 'true', description: 'Inject Security Headers' },
      });

      console.log('[DB Auto-Seed] Admin & Analyst accounts created successfully!');
    }

    return true;
  } catch (error) {
    console.error('Database connection failed:', error);
    return false;
  }
}
