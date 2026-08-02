export function createIncident({ attackType, page, fraudRisk, modifiedFields = [], detectedRules = [], actionTaken, originalTransaction, modifiedTransaction }) {
  return { id: crypto.randomUUID(), timestamp: new Date().toISOString(), attackType, page, fraudRisk, modifiedFields, detectedRules, actionTaken, originalTransaction, modifiedTransaction };
}
