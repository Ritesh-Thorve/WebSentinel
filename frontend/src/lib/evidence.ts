/** Defense in depth only: live services must redact secrets before returning data. */
export function redactEvidence(input: string): string {
  return input
    .replace(/^(\s*(?:set-cookie|cookie|authorization|proxy-authorization|x-api-key|x-auth-token|api-key)\s*:\s*).+$/gim, '$1[REDACTED]')
    .replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+/gi, '$1 [REDACTED]')
    .replace(/([?&](?:access_token|refresh_token|id_token|token|api_?key|secret|password|passwd|credential|session(?:_?id)?|code)=)[^&#\s]*/gi, '$1[REDACTED]')
    .replace(/((?:["']?)(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|client[_-]?secret|secret|password|passwd|authorization|cookie|session[_-]?id)(?:["']?)\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&}\r\n]+)/gi, '$1[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED]')
    .replace(/-----BEGIN (?:[A-Z ]*PRIVATE KEY)-----[\s\S]*?-----END (?:[A-Z ]*PRIVATE KEY)-----/g, '[REDACTED PRIVATE KEY]')
    .replace(/(https?:\/\/)[^\s/@:]+:[^\s/@]+@/gi, '$1[REDACTED]@');
}
export const limitationsNotice = 'Automated scans have limitations. A missing header, reflected marker, or HTTP 200 response alone does not establish an exploitable vulnerability. Findings require contextual review; an automated scan does not prove an application is secure.';