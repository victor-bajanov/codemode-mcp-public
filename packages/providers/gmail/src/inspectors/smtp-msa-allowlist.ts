/**
 * Host allowlist for the SMTP MSA sub-object on
 * users.settings.sendAs.create. Empty by default — any smtpMsa block is
 * denied. Operators who need MSA routing add an explicit host as a
 * reviewable code change.
 */
export const SMTP_MSA_HOST_ALLOWLIST: readonly string[] = [] as const;
