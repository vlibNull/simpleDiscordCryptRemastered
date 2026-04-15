/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/**
 * SimpleDiscordCrypt - Main Plugin Entry Point
 *
 * Full Vencord/Equicord re-implementation of An0's SimpleDiscordCrypt.
 */

import {
    addMessagePreSendListener,
    type MessageObject,
    type MessageSendListener,
    removeMessagePreSendListener,
} from "@api/MessageEvents";
import { definePluginSettings } from "@api/Settings";
import { Logger } from "@utils/Logger";
import definePlugin, { OptionType } from "@utils/types";
import {
    ChannelStore,
    ContextMenuApi,
    Menu,
    React,
    Text,
    Flux,
} from "@webpack/common";
import { findByProps } from "@webpack";

const logger = new Logger("SimpleDiscordCrypt");

// ─────────────────────────────────────────────────────────────────────────────
// DATABASE & COMPONENTS
// ─────────────────────────────────────────────────────────────────────────────
import {
    getActiveKeyIdForChannel,
    getAesKeyForId,
    initializeDatabase,
    isEncryptionEnabled,
    isUnlocked,
    touchChannel,
    listKeys,
    getKey,
    regenerateMasterSeed,
} from "./database";
import {
    getLockMenuItems,
    KeySelector,
    LockButton,
    openPasswordModal,
    openStartupModal,
} from "./components";
import {
    decryptMessage,
    encryptMessage,
    isBrailleMessage,
} from "./crypto";
import pluginStyle from "./style.css?managed";
import {
    hasEncPrefix,
    SDC_NOENC_PREFIX,
    stripEncPrefix,
} from "./utils";

// ─────────────────────────────────────────────────────────────────────────────
// PROTOCOL CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

const SDC_PREFIX = "⢢⠹⣑⡏⣃⢩⠡⡟⢭⠨⠮⠋⣇⡙⡉⡷";
const SDC_SUFFIX = " `𝘚𝘪𝘮𝘱𝘭𝘦𝘋𝘪𝘴𝘤𝘰𝘳𝘥𝘊𝘳𝘺𝘱𝘵`";

// ─────────────────────────────────────────────────────────────────────────────
// DATA INTERCEPTION & CACHE
// ─────────────────────────────────────────────────────────────────────────────

interface DecryptedMessage {
    plaintext: string;
    success: boolean;
    timestamp: number;
}

const decryptCache = new Map<string, DecryptedMessage>();

// Webpack Modules (Resolved at runtime)
let MessageStore: any;
let FluxDispatcher: any;

async function tryDecrypt(messageId: string, content: string, channelId: string): Promise<DecryptedMessage | null> {
    const cached = decryptCache.get(messageId);
    if (cached) return cached;

    if (!content.startsWith(SDC_PREFIX) || !content.endsWith(SDC_SUFFIX)) return null;
    
    if (!isUnlocked()) {
        return { plaintext: "[Locked - Unlock SDC to decrypt]", success: false, timestamp: Date.now() };
    }

    const rawBraille = content.slice(SDC_PREFIX.length, -SDC_SUFFIX.length);
    
    // Validate braille format
    if (!isBrailleMessage(rawBraille)) {
        const failure: DecryptedMessage = { 
            plaintext: "Invalid message format", 
            success: false, 
            timestamp: Date.now() 
        };
        decryptCache.set(messageId, failure);
        return failure;
    }
    
    const keysToTry = listKeys(true);
    const keyId = getActiveKeyIdForChannel(channelId);
    
    const activeKey = keyId ? getKey(keyId) : null;
    const sortedKeys = activeKey 
        ? [activeKey, ...keysToTry.filter(k => k.id !== activeKey.id)]
        : keysToTry;

    for (const key of sortedKeys) {
        const aesKey = await getAesKeyForId(key.id, channelId);
        if (!aesKey) continue;

        try {
            const plaintext = await decryptMessage(rawBraille, aesKey);
            if (plaintext !== null && plaintext.length > 0) {
                const result: DecryptedMessage = {
                    plaintext,
                    success: true,
                    timestamp: Date.now(),
                };
                decryptCache.set(messageId, result);
                logger.debug(`✓ Decrypted with key: ${key.name}`);
                return result;
            }
        } catch (err) {
            logger.debug(`Failed with key ${key.name}:`, err);
            continue;
        }
    }

    const failure: DecryptedMessage = { 
        plaintext: `Wrong key (tried ${sortedKeys.length} key${sortedKeys.length !== 1 ? 's' : ''})`, 
        success: false, 
        timestamp: Date.now() 
    };
    decryptCache.set(messageId, failure);
    return failure;
}

function reprocessAllMessages() {
    if (!isUnlocked() || !MessageStore) return;
    
    const channelId = (ChannelStore as any).getChannelId?.() || window.location.pathname.match(/\/channels\/[^/]+\/(\d+)/)?.[1];
    if (!channelId) return;

    const messages = MessageStore.getMessages(channelId);
    if (!messages) return;

    let msgArray = [];
    try {
        if (typeof messages.toArray === "function") msgArray = messages.toArray();
        else if (messages._array) msgArray = messages._array;
        else if (typeof messages.values === "function") msgArray = Array.from(messages.values());
        else msgArray = Object.values(messages);
    } catch (e) {
        return;
    }
    
    for (const m of msgArray) {
        if (!m) continue;
        const hasProtocol = m.content && m.content.startsWith(SDC_PREFIX) && m.content.endsWith(SDC_SUFFIX);
        const hasEncAttachments = m.attachments?.some((a: any) => a.filename.endsWith(".enc") && !a._decrypted);
        
        if ((hasProtocol && !m.content.startsWith("🔐 ") && !m.content.startsWith("🔒 ")) || hasEncAttachments) {
            processIncomingMessage(m);
            if (m.attachments?.length > 0) decryptAttachments(m);
        }
    }
}

function processIncomingMessage(message: any) {
    if (!message || typeof message.content !== "string") return;
    if (!message.content.startsWith(SDC_PREFIX) || !message.content.endsWith(SDC_SUFFIX)) return;
    
    if (!isUnlocked()) {
        // Mark as encrypted but locked
        if (!message.content.startsWith("🔒 ")) {
            message.content = "🔒 [Locked - Unlock SDC to decrypt]";
        }
        return;
    }
    
    if (message.content.startsWith("🔐 ") || message.content.startsWith("🔒 ")) return; // Already processed

    const channelId = message.channel_id || message.channelId;
    if (!channelId) return;

    const cached = decryptCache.get(message.id);
    if (cached?.success) {
        message.content = `🔐 ${cached.plaintext}`;
        return;
    }

    // Show decrypting placeholder
    const originalContent = message.content;
    message.content = "🔐 [Decrypting...]";

    tryDecrypt(message.id, originalContent, channelId).then(dec => {
        if (dec?.success && dec.plaintext) {
            const finalPlain = `🔐 ${dec.plaintext}`;
            message.content = finalPlain;
            
            if (MessageStore && FluxDispatcher) {
                const msgInStore = MessageStore.getMessage(channelId, message.id);
                if (msgInStore) {
                    msgInStore.content = finalPlain;
                    FluxDispatcher.dispatch({ type: "MESSAGE_UPDATE", message: msgInStore, _sdc: true });
                }
            }
        } else {
            // Decryption failed
            message.content = `🔐 ❌ [${dec?.plaintext || "Decryption failed"}]`;
            
            if (MessageStore && FluxDispatcher) {
                const msgInStore = MessageStore.getMessage(channelId, message.id);
                if (msgInStore) {
                    msgInStore.content = message.content;
                    FluxDispatcher.dispatch({ type: "MESSAGE_UPDATE", message: msgInStore, _sdc: true });
                }
            }
        }
    }).catch(err => {
        logger.error("Decryption error:", err);
        message.content = "🔐 ⚠️ [Error during decryption]";
    });
}

async function decryptAttachments(message: any) {
    if (!isUnlocked() || !message.attachments) return;

    const channelId = message.channel_id || message.channelId;
    const keyId = getActiveKeyIdForChannel(channelId);
    if (!keyId) return;
    const aesKey = await getAesKeyForId(keyId, channelId);
    if (!aesKey) return;

    for (const attachment of message.attachments) {
        if (attachment.filename.startsWith(SDC_PREFIX) && attachment.filename.endsWith(".enc") && !attachment._decrypted) {
            try {
                const metaBraille = attachment.filename.slice(0, -4); 
                const metaJson = await decryptMessage(metaBraille, aesKey);
                if (!metaJson) continue;
                const meta = JSON.parse(metaJson);

                const res = await fetch(attachment.url);
                const contentBraille = await res.text();
                if (!contentBraille.startsWith(SDC_PREFIX)) continue;
                const rawBraille = contentBraille.slice(SDC_PREFIX.length, -SDC_SUFFIX.length);
                
                const decryptedBytes = await decryptMessage(rawBraille, aesKey, true);
                if (decryptedBytes) {
                    const blob = new Blob([decryptedBytes], { type: meta.type });
                    attachment.url = URL.createObjectURL(blob);
                    attachment.filename = meta.name;
                    attachment.content_type = meta.type;
                    attachment._decrypted = true;
                    
                    if (FluxDispatcher) {
                        FluxDispatcher.dispatch({ type: "MESSAGE_UPDATE", message: message, _sdc: true });
                    }
                }
            } catch (e) {
                logger.error("Attachment decryption failed", e);
            }
        }
    }
}

function sdcFluxInterceptor(action: any) {
    if (action._sdc) return;

    switch (action.type) {
        case "MESSAGE_CREATE":
            if (action.message) {
                Promise.resolve().then(() => {
            processIncomingMessage(action.message);
                    if (action.message.attachments?.length > 0) {
                        decryptAttachments(action.message);
                    }
                });
            }
            break;
            
        case "MESSAGE_UPDATE":
            if (action.message) {
                if (action.message.content?.startsWith(SDC_PREFIX)) {
                decryptCache.delete(action.message.id);
            }
                Promise.resolve().then(() => {
            processIncomingMessage(action.message);
                    if (action.message.attachments?.length > 0) {
                        decryptAttachments(action.message);
                    }
                });
            }
            break;
            
        case "LOAD_MESSAGES_SUCCESS":
            if (Array.isArray(action.messages)) {
                Promise.resolve().then(() => {
                for (const m of action.messages) {
                    processIncomingMessage(m);
                        if (m.attachments?.length > 0) {
                            decryptAttachments(m);
                        }
                }
                });
            }
            break;
            
        case "CHANNEL_SELECT":
        case "GUILD_SELECT":
            setTimeout(() => {
                reprocessAllMessages();
            }, 150);
            break;
    }
}

async function encryptFile(file: File, aesKey: Uint8Array): Promise<File> {
    const buffer = await file.arrayBuffer();
    const contentBraille = await encryptMessage(new Uint8Array(buffer), aesKey);
    const finalContent = SDC_PREFIX + contentBraille + SDC_SUFFIX;

    const metadata = JSON.stringify({ name: file.name, type: file.type });
    const metaBraille = await encryptMessage(metadata, aesKey);
    const finalFilename = metaBraille + ".enc";

    return new File([finalContent], finalFilename, { type: "application/octet-stream" });
}

// ─────────────────────────────────────────────────────────────────────────────
// UI CONTROLS
// ─────────────────────────────────────────────────────────────────────────────

function SdcHeaderBarControls() {
    const [channelId, setChannelId] = React.useState("");
    const [, forceUpdate] = React.useReducer(x => x + 1, 0);

    React.useEffect(() => {
        const interval = setInterval(() => {
            const current = (ChannelStore as any).getChannelId?.() || window.location.pathname.match(/\/channels\/[^/]+\/(\d+)/)?.[1];
            if (current && current !== channelId) {
                setChannelId(current);
                forceUpdate();
            }
        }, 500);
        return () => clearInterval(interval);
    }, [channelId]);

    if (!channelId || !isUnlocked()) return null;

    const channel = ChannelStore.getChannel(channelId);
    if (!channel) return null;

    const enabled = isEncryptionEnabled(channelId);
    const activeKeyId = getActiveKeyIdForChannel(channelId);
    const activeKey = activeKeyId ? getKey(activeKeyId) : null;

    const handleContextMenu = (e: React.MouseEvent) => {
        e.preventDefault();
        e.stopPropagation();
        const items = getLockMenuItems(channelId, channel.type === 1);
        ContextMenuApi.openContextMenu(e, () => (
            <Menu.Menu navId="sdc-lock-menu" onClose={ContextMenuApi.closeContextMenu}>
                {items.map(item => (
                    <Menu.MenuItem key={item.label} id={item.label} label={item.label} action={item.action} color={item.danger ? "danger" : "default"} />
                ))}
            </Menu.Menu>
        ));
    };

    return (
        <div className="sdc-header-controls" style={{ display: "inline-flex", alignItems: "center", gap: "8px" }}>
            <LockButton channelId={channelId} onToggle={() => forceUpdate()} onContextMenu={handleContextMenu} />
            <KeySelector channelId={channelId} onUpdate={() => forceUpdate()} />
            {enabled && !activeKey && (
                <span style={{ color: "var(--status-warning)", fontSize: "11px", fontWeight: 500 }}>
                    ⚠️ No key
                </span>
            )}
        </div>
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// SETTINGS
// ─────────────────────────────────────────────────────────────────────────────

const settings = definePluginSettings({
    autoKX: { type: OptionType.BOOLEAN, description: "Automatically initiate key exchange", default: true, restartNeeded: false },
    showDecryptedBadge: { type: OptionType.BOOLEAN, description: "Show 🔐 indicator", default: true, restartNeeded: false },
    notifyOnEncryptedPing: { type: OptionType.BOOLEAN, description: "Notify on encrypted ping", default: true, restartNeeded: false },
    regenerateSeed: {
        type: OptionType.BUTTON,
        description: "Regenerate Personal Identity (Master Seed)",
        onClick: () => {
            if (confirm("Are you sure? This makes old messages unreadable!")) {
                regenerateMasterSeed().then(() => alert("Regenerated."));
            }
        }
    }
});

const preSendListener: MessageSendListener = async (channelId, messageObj) => {
    if (typeof messageObj.content === "string" && messageObj.content.startsWith(SDC_NOENC_PREFIX)) {
        messageObj.content = messageObj.content.slice(SDC_NOENC_PREFIX.length);
        return;
    }
    if (!isUnlocked()) return;
    const content = messageObj.content ?? "";
    const explicit = hasEncPrefix(content);
    const plain = explicit ? stripEncPrefix(content) : content;
    const shouldEncrypt = explicit === true ? true : explicit === false ? false : isEncryptionEnabled(channelId);
    if (!shouldEncrypt) return;

    const keyId = getActiveKeyIdForChannel(channelId);
    const aesKey = keyId ? await getAesKeyForId(keyId, channelId) : null;
    if (!aesKey) return;

    try {
        if (plain.trim() === "") {
            messageObj.content = SDC_PREFIX + SDC_SUFFIX;
        } else {
            const encrypted = await encryptMessage(plain, aesKey);
            messageObj.content = SDC_PREFIX + encrypted + SDC_SUFFIX;
            if (messageObj.id) {
                decryptCache.set(messageObj.id, { plaintext: plain, success: true, timestamp: Date.now() });
            }
        }
        await touchChannel(channelId);
    } catch (e) { logger.error("Encryption failed", e); }
};

export default definePlugin({
    name: "SimpleDiscordCrypt",
    description: "E2E encryption plugin",
    authors: [{ name: "SDC Re-impl", id: 0n }],
    managedStyle: pluginStyle,
    settings,

    patches: [
        {
            find: "toolbar:function",
            replacement: {
                match: /(toolbar:function.+?children:\[)/,
                replace: "$1window.SdcToolbarControls?.(),"
            }
        },
    ],

    async start() {
        // IMPROVED WEBPACK RESOLUTION WITH RETRY
        const resolveModules = async () => {
            let attempts = 0;
            const maxAttempts = 10;
            
            while (attempts < maxAttempts) {
                try {
                    if (!MessageStore) {
                        MessageStore = findByProps("getMessage", "getMessages");
                        logger.info("✓ MessageStore resolved");
                    }
                    if (!FluxDispatcher) {
                        FluxDispatcher = findByProps("dispatch", "subscribe") || (Flux as any).Dispatcher;
                        logger.info("✓ FluxDispatcher resolved");
                    }
                    
                    if (MessageStore && FluxDispatcher) {
                        break;
                    }
                } catch (e) {
                    logger.warn(`Module resolution attempt ${attempts + 1}/${maxAttempts}`);
                }
                
                attempts++;
                await new Promise(resolve => setTimeout(resolve, Math.min(100 * Math.pow(2, attempts), 2000)));
            }
            
            if (!MessageStore || !FluxDispatcher) {
                logger.error("❌ Failed to resolve required modules");
            }
        };

        await resolveModules();
        
        if (FluxDispatcher) {
            FluxDispatcher.addInterceptor(sdcFluxInterceptor);
            logger.info("✓ Flux interceptor added");
        }

        // FILE UPLOAD HOOK
        try {
            const UploadModule = findByProps("instantBatchUpload", "upload");
            if (UploadModule && UploadModule.instantBatchUpload) {
                (this as any)._originalInstantBatchUpload = UploadModule.instantBatchUpload;
                
                UploadModule.instantBatchUpload = async (channelId: string, files: File[], ...args: any[]) => {
                    if (!isUnlocked() || !isEncryptionEnabled(channelId)) {
                        return (this as any)._originalInstantBatchUpload.call(UploadModule, channelId, files, ...args);
                    }
                    
                    const keyId = getActiveKeyIdForChannel(channelId);
                    if (!keyId) {
                        logger.warn("No key selected for channel", channelId);
                        return (this as any)._originalInstantBatchUpload.call(UploadModule, channelId, files, ...args);
                    }
                    
                    const aesKey = await getAesKeyForId(keyId, channelId);
                    if (!aesKey) {
                        logger.error("Failed to get AES key for file encryption");
                        return (this as any)._originalInstantBatchUpload.call(UploadModule, channelId, files, ...args);
                    }
                    
                    logger.info(`🔐 Encrypting ${files.length} file(s)`);
                    const encryptedFiles = await Promise.all(
                        files.map(f => encryptFile(f, aesKey))
                    );
                    
                    return (this as any)._originalInstantBatchUpload.call(UploadModule, channelId, encryptedFiles, ...args);
                };
                
                logger.info("✓ File upload hook installed");
            } else {
                logger.warn("⚠️ Upload module not found - file encryption disabled");
            }
        } catch (e) {
            logger.error("❌ Failed to hook file uploads:", e);
        }

        (window as any).SdcToolbarControls = SdcHeaderBarControls;
        (window as any).SdcProcessMsg = processIncomingMessage;
        (window as any).SdcReprocessAll = reprocessAllMessages;
        (window as any).SdcUnlocked = isUnlocked;
        (window as any).SdcEncryptEnabled = isEncryptionEnabled;
        (window as any).SdcActiveKey = getActiveKeyIdForChannel;
        (window as any).SdcGetAesKey = getAesKeyForId;
        (window as any).SdcEncryptFile = encryptFile;

        // Debug tools
        (window as any).SdcDebug = {
            cache: () => decryptCache,
            clearCache: () => decryptCache.clear(),
            reprocess: () => reprocessAllMessages(),
            testEncrypt: async (text: string) => {
                const ch = (ChannelStore as any).getChannelId();
                const keyId = getActiveKeyIdForChannel(ch);
                const aesKey = keyId ? await getAesKeyForId(keyId, ch) : null;
                if (!aesKey) return "No key";
                return await encryptMessage(text, aesKey);
            }
        };

        addMessagePreSendListener(preSendListener);

        setTimeout(() => {
            openStartupModal(() => {
                logger.info("✅ SDC Ready");
                reprocessAllMessages();
            });
        }, 1000);

        (this as any)._sdcInterval = setInterval(reprocessAllMessages, 2000);
    },

    stop() {
        if ((this as any)._sdcInterval) clearInterval((this as any)._sdcInterval);
        if (FluxDispatcher) FluxDispatcher.removeInterceptor(sdcFluxInterceptor);
        
        try {
            const Uploader = findByProps("instantBatchUpload");
            if (Uploader && (this as any)._originalInstantBatchUpload) {
                Uploader.instantBatchUpload = (this as any)._originalInstantBatchUpload;
            }
        } catch (e) {}

        delete (window as any).SdcToolbarControls;
        delete (window as any).SdcDebug;
        removeMessagePreSendListener(preSendListener);
    },
});