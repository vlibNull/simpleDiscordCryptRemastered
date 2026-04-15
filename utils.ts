/**
 * SimpleDiscordCrypt - Utilities
 */

export function cl(...names: (string | false | null | undefined)[]): string {
    return names.filter(Boolean).map(n => `sdc-${n}`).join(" ");
}

/** Extract the plaintext of a rendered message element */
export function getMessageText(el: HTMLElement): string {
    return el.textContent ?? "";
}

/** Send a Discord message without triggering our outbound hook */
export const SDC_NOENC_PREFIX = "\x00SDC_NOENC\x00";

export function stripSdcPrefix(content: string): string {
    return content.startsWith(SDC_NOENC_PREFIX) ? content.slice(SDC_NOENC_PREFIX.length) : content;
}

/** True if content starts with ENC/NOENC user-level prefix */
export function hasEncPrefix(content: string): boolean | null {
    if (/^:?ENC:?\s/i.test(content)) return true;
    if (/^:?NOENC:?\s/i.test(content)) return false;
    return null;
}

export function stripEncPrefix(content: string): string {
    return content.replace(/^:?(?:EN|NOEN)C:?\s+/i, "");
}

/** Shallow debounce */
export function debounce<T extends (...args: any[]) => any>(fn: T, ms: number): T {
    let t: ReturnType<typeof setTimeout>;
    return ((...args: any[]) => {
        clearTimeout(t);
        t = setTimeout(() => fn(...args), ms);
    }) as T;
}
