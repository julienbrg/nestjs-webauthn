export interface OriginConfig {
  origin: string;
  addedAt: Date;
}

export interface OriginStorageData {
  origins: OriginConfig[];
}
