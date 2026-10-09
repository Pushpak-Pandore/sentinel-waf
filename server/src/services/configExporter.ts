import { prisma } from '../db/prisma';

export async function exportWafConfiguration() {
  const [rules, ipRules, ratePolicies, apps, virtualPatches, exceptions, settings] = await Promise.all([
    prisma.wafRule.findMany(),
    prisma.ipAccessRule.findMany(),
    prisma.rateLimitPolicy.findMany(),
    prisma.protectedApp.findMany(),
    prisma.virtualPatch.findMany(),
    prisma.wafException.findMany(),
    prisma.systemSetting.findMany(),
  ]);

  return {
    version: '2.0.0',
    exportedAt: new Date().toISOString(),
    configuration: {
      rules,
      ipRules,
      ratePolicies,
      apps,
      virtualPatches,
      exceptions,
      settings,
    },
  };
}
