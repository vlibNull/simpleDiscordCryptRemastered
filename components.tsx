/**
 * SimpleDiscordCrypt - UI Components
 * Lock icon toolbar button, key selector dropdown, key manager modal,
 * database import/export modal, and key visualizer.
 * 
**/

import { React, useState, useEffect, useCallback, useRef } from "@webpack/common";
import { Flex } from "@components/Flex";
import { Forms } from "@webpack/common";
import { Button, Text, TextInput, Select, Tooltip, Switch } from "@webpack/common";
import { Modals, openModal } from "@utils/modal";
import { sendMessage } from "@utils/discord";
import { cl } from "./utils";
import {
    listKeys, getKey, updateKey, deleteKey, addGroupKey,
    getDatabase, getChannel, setChannelKey, setChannelEncryption,
    getActiveKeyIdForChannel, isEncryptionEnabled,
    exportDatabaseJson, importDatabaseJson,
    startKX, getPublicKeyBytes, rotateKey as dbRotateKey,
    clearChannels, clearKeys, setPingPattern, getPingPattern,
    isUnlocked, initializeDatabase, lock, hasStoredDatabase,
} from "./database";
import { buildKxInitMessage, keyFingerprint, uint8ToBase64, base64ToUint8 } from "./crypto";
import { SDC_NOENC_PREFIX } from "./utils";
import type { StoredKey } from "./database";

// ─── Lock/Unlock toggle button ────────────────────────────────────────────────

interface LockButtonProps {
    channelId: string;
    onToggle: (enabled: boolean) => void;
    onContextMenu: (e: React.MouseEvent) => void;
}

export function LockButton({ channelId, onToggle, onContextMenu }: LockButtonProps) {
    const enabled = isEncryptionEnabled(channelId);

    const toggle = useCallback(() => {
        const next = !enabled;
        setChannelEncryption(channelId, next);
        onToggle(next);
    }, [channelId, enabled, onToggle]);

    return (
        <Tooltip text={enabled ? "Encryption ON (right-click for menu)" : "Encryption OFF (click to enable)"}>
            {(tooltipProps: any) => (
                <button
                    {...tooltipProps}
                    className={cl("lock-btn", enabled ? "lock-active" : "lock-inactive")}
                    onClick={toggle}
                    onContextMenu={onContextMenu}
                    aria-label="Toggle encryption"
                    style={{
                        background: "none", border: "none", cursor: "pointer",
                        fontSize: "20px", padding: "0 4px", opacity: enabled ? 1 : 0.5,
                        transition: "opacity 0.15s",
                    }}
                >
                    {enabled ? "🔐" : "🔓"}
                </button>
            )}
        </Tooltip>
    );
}

// ─── Key selector dropdown (FIXED) ─────────────────────────────────────────────

interface KeySelectorProps {
    channelId: string;
    onUpdate?: () => void;
}

export function KeySelector({ channelId, onUpdate }: KeySelectorProps) {
    const [activeId, setActiveId] = useState(() => getActiveKeyIdForChannel(channelId) ?? "");
    const [keys, setKeys] = useState(() => listKeys(false).filter(k => !k.hidden));
    const [, forceUpdate] = React.useReducer(x => x + 1, 0);

    // Refresh when channel changes
    useEffect(() => {
        const newActiveId = getActiveKeyIdForChannel(channelId) ?? "";
        setActiveId(newActiveId);
        setKeys(listKeys(false).filter(k => !k.hidden));
    }, [channelId]);    

    // Poll for key list changes (key manager operations)
    useEffect(() => {
        const interval = setInterval(() => {
            const currentKeys = listKeys(false).filter(k => !k.hidden);
            const currentActiveId = getActiveKeyIdForChannel(channelId) ?? "";
            
            // Check if keys changed (by comparing IDs)
            const currentIds = currentKeys.map(k => k.id).sort().join(',');
            const storedIds = keys.map(k => k.id).sort().join(',');
            
            if (currentIds !== storedIds) {
                setKeys(currentKeys);
                forceUpdate();
            }
            
            // Check if active key changed
            if (currentActiveId !== activeId) {
                setActiveId(currentActiveId);
                forceUpdate();
            }
        }, 500);
        
        return () => clearInterval(interval);
    }, [channelId, activeId, keys]);

    if (!isUnlocked() || !isEncryptionEnabled(channelId)) {
        return null;
    }

    const options = [
        { label: "— No key selected —", value: "" },
        ...keys.map(k => ({
            label: `[${k.type}] ${k.name}`,
            value: k.id,
        })),
    ];

    // Validate activeId still exists in keys
    const safeActiveId = options.some(o => o.value === activeId) ? activeId : "";
    
    // If activeId became invalid, update database
    if (activeId && !safeActiveId) {
        setChannelKey(channelId, null).then(() => {
            setActiveId("");
            if (onUpdate) onUpdate();
        });
    }

    const handleChange = useCallback((value: string) => {
        setActiveId(value);
        setChannelKey(channelId, value || null);
        forceUpdate();
        if (onUpdate) onUpdate();
    }, [channelId, onUpdate]);

    return (
        <div className={cl("key-selector-wrap")}>
            <Select
                options={options}
                select={handleChange}
                isSelected={v => v === safeActiveId}
                serialize={v => v}
                popoutPosition="bottom"
                style={{ minWidth: "140px", maxWidth: "140px", fontSize: "12px" }}
            />
        </div>
    );
}

// ─── Context menu (right-click on lock) ──────────────────────────────────────

export interface LockContextItem {
    label: string;
    action: () => void;
    danger?: boolean;
}

export function getLockMenuItems(channelId: string, isDM: boolean): LockContextItem[] {
    return [
        {
            label: "Key Manager",
            action: () => openKeyManagerModal(),
        },
        ...(isDM ? [{
            label: "Start Key Exchange",
            action: () => openKXModal(channelId),
        }] : [{
            label: "Generate Group Key",
            action: () => openGroupKeyModal(channelId),
        }]),
        {
            label: "Share Keys",
            action: () => openShareKeysModal(channelId),
        },
        {
            label: "Key Visualizer",
            action: () => openKeyVisualizerModal(channelId),
        },
        {
            label: "Import Database",
            action: () => openImportModal(),
        },
        {
            label: "Export Database",
            action: () => openExportModal(),
        },
    ];
}

// ─── Key Manager Modal ────────────────────────────────────────────────────────

function KeyManagerModal({ modalProps }: { modalProps: any }) {
    const [keys, setKeys] = useState<StoredKey[]>(() => listKeys(true));
    const [editId, setEditId] = useState<string | null>(null);
    const [editName, setEditName] = useState("");

    const refresh = () => setKeys(listKeys(true));

    const startEdit = (key: StoredKey) => {
        setEditId(key.id);
        setEditName(key.name ?? "");
    };

    const saveEdit = async () => {
        if (!editId) return;
        await updateKey(editId, { name: editName || "Unnamed Key", descriptor: editName || "Unnamed Key" });
        setEditId(null);
        refresh();
    };

    const toggleHide = async (key: StoredKey) => {
        await updateKey(key.id, { hidden: !key.hidden });
        refresh();
    };

    const del = async (key: StoredKey) => {
        if (!confirm(`Delete key "${key.name}"? This cannot be undone.`)) return;
        await deleteKey(key.id);
        refresh();
    };

    const fingerprint = async (key: StoredKey) => {
        const raw = key.rawKeyB64 ?? key.sharedKeyB64;
        if (!raw) {
            alert("No key material available for fingerprint");
            return;
        }
        const fp = await keyFingerprint(base64ToUint8(raw));
        alert("Key fingerprint:\n" + fp);
    };

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">🗝️ Key Manager</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "12px" }}>
                    {keys.length === 0 && <Text>No keys in database.</Text>}
                    {keys.map(key => (
                        <div key={key.id} style={{
                            border: "1px solid var(--background-modifier-accent)",
                            borderRadius: "4px",
                            padding: "12px",
                            background: key.hidden ? "var(--background-secondary-alt)" : "var(--background-secondary)",
                        }}>
                            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                            {editId === key.id ? (
                                <>
                                    <TextInput
                                        value={editName}
                                            onChange={setEditName} 
                                            style={{ flex: 1, marginRight: "8px" }}
                                            autoFocus
                                    />
                                    <Button size={Button.Sizes.SMALL} onClick={saveEdit}>Save</Button>
                                </>
                            ) : (
                                <>
                                        <div>
                                            <Text variant="text-md/semibold">{key.name}</Text>
                                            <Text variant="text-xs/normal" style={{ color: "var(--text-muted)" }}>
                                                {key.type} • {new Date(key.lastseen).toLocaleDateString()}
                                            </Text>
                                        </div>
                                        <div style={{ display: "flex", gap: "4px" }}>
                                    <Button size={Button.Sizes.SMALL} onClick={() => startEdit(key)}>Rename</Button>
                                    <Button size={Button.Sizes.SMALL} onClick={() => toggleHide(key)}>
                                        {key.hidden ? "Unhide" : "Hide"}
                                    </Button>
                                    <Button size={Button.Sizes.SMALL} onClick={() => fingerprint(key)}>🔍</Button>
                                    {key.type !== "PERSONAL" && (
                                                <Button 
                                                    size={Button.Sizes.SMALL} 
                                                    color={Button.Colors.RED}
                                                    onClick={() => del(key)}
                                                >
                                                    Delete
                                                </Button>
                                    )}
                                        </div>
                                </>
                            )}
                        </div>
                        </div>
                    ))}
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <Button look={Button.Looks.LINK} onClick={modalProps.onClose}>Close</Button>
            </Modals.ModalFooter>
        </Modals.ModalRoot>
    );
}

export const openKeyManagerModal = () =>
    openModal(props => <KeyManagerModal modalProps={props} />);

// ─── Key Exchange Modal ───────────────────────────────────────────────────────

function KXModal({ modalProps, channelId }: { modalProps: any; channelId: string }) {
    const [status, setStatus] = useState("");

    const initiate = async () => {
        try {
            const { keyId, pubKeyB64 } = await startKX(channelId);
            const msg = buildKxInitMessage(base64ToUint8(pubKeyB64));
            await sendMessage(channelId, { content: SDC_NOENC_PREFIX + msg });
            setStatus("✅ Key exchange initiated. Waiting for response...");
        } catch (e: any) {
            setStatus("❌ Failed: " + e.message);
        }
    };

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">Key Exchange</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px" }}>
                    <Text>This will send a key exchange request to the channel.</Text>
                    {status && <Text style={{ marginTop: "8px", color: status.startsWith("✅") ? "#3ba55c" : "#ed4245" }}>{status}</Text>}
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <Button onClick={initiate}>Initiate Key Exchange</Button>
                <Button look={Button.Looks.LINK} onClick={modalProps.onClose}>Close</Button>
            </Modals.ModalFooter>
        </Modals.ModalRoot>
    );
}

export const openKXModal = (channelId: string) =>
    openModal(props => <KXModal modalProps={props} channelId={channelId} />);

// ─── Group Key Modal ──────────────────────────────────────────────────────────

function GroupKeyModal({ modalProps, channelId }: { modalProps: any; channelId: string }) {
    const [name, setName] = useState("");
    const [status, setStatus] = useState("");

    const generate = async () => {
        if (!name.trim()) {
            setStatus("❌ Please enter a key name");
            return;
        }
        
        try {
            const key = await addGroupKey(name.trim());
            await setChannelKey(channelId, key.id);
            setStatus("✅ Group key created and activated");
            setTimeout(() => modalProps.onClose(), 1500);
        } catch (e: any) {
            setStatus("❌ Failed: " + e.message);
        }
    };

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">Generate Group Key</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "12px" }}>
                    <Text>Create a new symmetric key for this group channel.</Text>
                    <TextInput 
                        value={name} 
                        onChange={setName} 
                        placeholder="Key name (e.g., 'Gaming Group')"
                    />
                    {status && <Text style={{ color: status.startsWith("✅") ? "#3ba55c" : "#ed4245" }}>{status}</Text>}
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <Button onClick={generate}>Generate</Button>
                <Button look={Button.Looks.LINK} onClick={modalProps.onClose}>Cancel</Button>
            </Modals.ModalFooter>
        </Modals.ModalRoot>
    );
}

export function openIncomingKXApprovalModal(senderName: string): Promise<boolean> {
    return new Promise(resolve => {
        openModal(modalProps => (
            <IncomingKXModal
                modalProps={modalProps}
                senderName={senderName}
                onDecision={resolve}
            />
        ));
    });
}

// ─── Share Keys Modal ─────────────────────────────────────────────────────────

function ShareKeysModal({ modalProps, channelId }: { modalProps: any; channelId: string }) {
    const [selectedKeys, setSelectedKeys] = useState<string[]>([]);
    const keys = listKeys(false).filter(k => k.type === "GROUP");

    const share = async () => {
        if (selectedKeys.length === 0) {
            alert("Select at least one key to share");
            return;
        }
        
        const keysToShare = selectedKeys.map(id => getKey(id)).filter(Boolean);
        const payload = JSON.stringify({
            keys: keysToShare.map(k => ({
                id: k!.id,
                name: k!.name,
                type: k!.type,
                rawKeyB64: k!.rawKeyB64,
            }))
        });
        
        await sendMessage(channelId, { content: SDC_NOENC_PREFIX + `:SHARE_KEYS:${payload}` });
        alert("Keys shared!");
        modalProps.onClose();
    };

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">Share Keys</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "12px" }}>
                    <Text>Select group keys to share with this channel:</Text>
                    {keys.length === 0 ? (
                        <Text style={{ color: "var(--text-muted)" }}>No group keys available</Text>
                    ) : (
                        keys.map(k => (
                            <div key={k.id} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                            <input
                                type="checkbox"
                                    checked={selectedKeys.includes(k.id)}
                                    onChange={e => {
                                        if (e.target.checked) {
                                            setSelectedKeys([...selectedKeys, k.id]);
                                        } else {
                                            setSelectedKeys(selectedKeys.filter(id => id !== k.id));
                                        }
                                    }}
                            />
                                <Text>{k.name}</Text>
                        </div>
                        ))
                    )}
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <Button onClick={share} disabled={selectedKeys.length === 0}>Share</Button>
                <Button look={Button.Looks.LINK} onClick={modalProps.onClose}>Cancel</Button>
            </Modals.ModalFooter>
        </Modals.ModalRoot>
    );
}

export const openShareKeysModal = (channelId: string) =>
    openModal(props => <ShareKeysModal modalProps={props} channelId={channelId} />);

// ─── Key Visualizer Modal ─────────────────────────────────────────────────────

function KeyVisualizerModal({ modalProps, channelId }: { modalProps: any; channelId: string }) {
    const activeKeyId = getActiveKeyIdForChannel(channelId);
    const key = activeKeyId ? getKey(activeKeyId) : null;

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">🔍 Key Visualizer</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px" }}>
                    {!key ? (
                        <Text>No key selected for this channel</Text>
                    ) : (
                        <div>
                            <Text variant="text-md/semibold">{key.name}</Text>
                            <Text variant="text-sm/normal" style={{ color: "var(--text-muted)", marginTop: "4px" }}>
                                Type: {key.type}<br />
                                Created: {new Date(key.registered).toLocaleString()}<br />
                                Last used: {new Date(key.lastseen).toLocaleString()}
                    </Text>
                            {key.rawKeyB64 && (
                                <div style={{ marginTop: "12px" }}>
                                    <Text variant="text-sm/semibold">Key Material (Base64):</Text>
                                    <code style={{ 
                                        display: "block", 
                                        background: "var(--background-tertiary)", 
                                        padding: "8px", 
                                        borderRadius: "4px",
                                        fontSize: "10px",
                                        wordBreak: "break-all",
                                        marginTop: "4px"
                                    }}>
                                        {key.rawKeyB64}
                                    </code>
                                </div>
                            )}
                    </div>
                    )}
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <Button look={Button.Looks.LINK} onClick={modalProps.onClose}>Close</Button>
            </Modals.ModalFooter>
        </Modals.ModalRoot>
    );
}

export const openKeyVisualizerModal = (channelId: string) =>
    openModal(props => <KeyVisualizerModal modalProps={props} channelId={channelId} />);

// ─── Export Modal ─────────────────────────────────────────────────────────────

function ExportModal({ modalProps }: { modalProps: any }) {
    const json = exportDatabaseJson();

    const copy = () => {
        navigator.clipboard.writeText(json);
        alert("Database copied to clipboard!");
    };

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">Export Database</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px" }}>
                    <Text style={{ marginBottom: "8px" }}>Copy this JSON to backup your database:</Text>
                    <textarea
                        readOnly
                        value={json}
                        style={{
                            width: "100%", height: "200px", fontFamily: "monospace", fontSize: "12px",
                            background: "var(--background-secondary)", border: "1px solid var(--background-modifier-accent)",
                            borderRadius: "4px", padding: "8px", color: "var(--text-normal)",
                        }}
                    />
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <Button onClick={copy}>Copy to Clipboard</Button>
                <Button look={Button.Looks.LINK} onClick={modalProps.onClose}>Close</Button>
            </Modals.ModalFooter>
        </Modals.ModalRoot>
    );
}

export const openExportModal = () =>
    openModal(props => <ExportModal modalProps={props} />);

// ─── Import Modal ─────────────────────────────────────────────────────────────

function ImportModal({ modalProps }: { modalProps: any }) {
    const [json, setJson] = useState("");
    const [asSecondary, setAsSecondary] = useState(false);
    const [status, setStatus] = useState("");

    const doImport = async () => {
        try {
            await importDatabaseJson(json, asSecondary);
            setStatus("✅ Database imported successfully");
            setTimeout(() => modalProps.onClose(), 1500);
        } catch (e: any) {
            setStatus("❌ Import failed: " + e.message);
        }
    };

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">Import Database</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "12px" }}>
                    <Text>Paste the contents of your exported database JSON below:</Text>
                    <textarea
                        value={json}
                        onChange={e => setJson((e.target as HTMLTextAreaElement).value)}
                        style={{
                            width: "100%", height: "150px", fontFamily: "monospace", fontSize: "12px",
                            background: "var(--background-secondary)", border: "1px solid var(--background-modifier-accent)",
                            borderRadius: "4px", padding: "8px", color: "var(--text-normal)",
                        }}
                        placeholder='{"version":3,...}'
                    />
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <input type="checkbox" checked={asSecondary} onChange={e => setAsSecondary((e.target as HTMLInputElement).checked)} id="secondary-chk" />
                        <label htmlFor="secondary-chk">
                            <Text>Import as secondary (won't replace identity keys)</Text>
                        </label>
                    </div>
                    {status && <Text style={{ color: status.startsWith("✅") ? "#3ba55c" : "#ed4245" }}>{status}</Text>}
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <Button onClick={doImport} disabled={!json.trim()}>Import</Button>
                <Button look={Button.Looks.LINK} onClick={modalProps.onClose}>Close</Button>
            </Modals.ModalFooter>
        </Modals.ModalRoot>
    );
}

export const openImportModal = () =>
    openModal(props => <ImportModal modalProps={props} />);

// ─── Password/Unlock modal ────────────────────────────────────────────────────

export function openPasswordModal(onUnlock: (password: string) => void): void {
    openModal(props => <PasswordModal modalProps={props} onUnlock={onUnlock} />);
}

function PasswordModal({ modalProps, onUnlock }: { modalProps: any; onUnlock: (pw: string) => void }) {
    const [pw, setPw] = useState("");
    const [error, setError] = useState("");

    const submit = async () => {
        const ok = await initializeDatabase(pw);
        if (ok) { onUnlock(pw); modalProps.onClose(); }
        else setError("Incorrect password or database corrupted.");
    };

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">🔐 Unlock SimpleDiscordCrypt</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px" }}>
                    <Text style={{ marginBottom: "8px" }}>Enter your database password:</Text>
                    <TextInput
                        type="password"
                        value={pw}
                        onChange={setPw}
                        placeholder="Password"
                        onKeyDown={(e: React.KeyboardEvent) => e.key === "Enter" && submit()}
                    />
                    {error && <Text style={{ color: "#ed4245", marginTop: "8px" }}>{error}</Text>}
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <Button onClick={submit}>Unlock</Button>
            </Modals.ModalFooter>
        </Modals.ModalRoot>
    );
}

// ─── Startup Modal (Initial Setup) ─────────────────────────────────────────────

function StartupModal({ modalProps, onFinish }: { modalProps: any; onFinish: () => void }) {
    const [view, setView] = useState<"choose" | "create" | "import" | "unlock">("choose");
    const [pw, setPw] = useState("");
    const [error, setError] = useState("");
    const [json, setJson] = useState("");

    useEffect(() => {
        hasStoredDatabase().then(exists => {
            if (exists) setView("unlock");
        });
    }, []);

    const doCreate = async () => {
        const ok = await initializeDatabase(pw || undefined);
        if (ok) { onFinish(); modalProps.onClose(); }
        else setError("Creation failed.");
    };

    const doImport = async () => {
        try {
            await importDatabaseJson(json, false);
            onFinish();
            modalProps.onClose();
        } catch (e: any) {
            setError("Import failed: " + e.message);
        }
    };

    const doUnlock = async () => {
        const ok = await initializeDatabase(pw);
        if (ok) { onFinish(); modalProps.onClose(); }
        else setError("Incorrect password.");
    };

    if (view === "choose") {
        return (
            <Modals.ModalRoot {...modalProps}>
                <Modals.ModalHeader><Text variant="heading-lg/semibold">SimpleDiscordCrypt Setup</Text></Modals.ModalHeader>
                <Modals.ModalContent>
                    <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "12px" }}>
                        <Text>Welcome to SDC Remastered. Choose an option to get started:</Text>
                        <Button onClick={() => setView("create")}>Create New Database</Button>
                        <Button onClick={() => setView("import")}>Import Existing Database</Button>
                    </div>
                </Modals.ModalContent>
            </Modals.ModalRoot>
        );
    }

    if (view === "create") {
        return (
            <Modals.ModalRoot {...modalProps}>
                <Modals.ModalHeader><Text variant="heading-lg/semibold">Create Database</Text></Modals.ModalHeader>
                <Modals.ModalContent>
                    <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "12px" }}>
                        <Text>Set a password for your new database (optional):</Text>
                        <TextInput type="password" value={pw} onChange={setPw} placeholder="Password (leave blank for none)" />
                        {error && <Text style={{ color: "#ed4245" }}>{error}</Text>}
                        <Button onClick={doCreate}>Create & Start</Button>
                        <Button look={Button.Looks.LINK} onClick={() => setView("choose")}>Back</Button>
                    </div>
                </Modals.ModalContent>
            </Modals.ModalRoot>
        );
    }

    if (view === "import") {
        return (
            <Modals.ModalRoot {...modalProps}>
                <Modals.ModalHeader><Text variant="heading-lg/semibold">Import Database</Text></Modals.ModalHeader>
                <Modals.ModalContent>
                    <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "12px" }}>
                        <Text>Paste your database JSON:</Text>
                        <textarea
                            value={json}
                            onChange={e => setJson((e.target as HTMLTextAreaElement).value)}
                            style={{
                                width: "100%", height: "150px", fontFamily: "monospace", fontSize: "12px",
                                background: "var(--background-secondary)", border: "1px solid var(--background-modifier-accent)",
                                borderRadius: "4px", padding: "8px", color: "var(--text-normal)",
                            }}
                        />
                        {error && <Text style={{ color: "#ed4245" }}>{error}</Text>}
                        <Button onClick={doImport} disabled={!json.trim()}>Import & Start</Button>
                        <Button look={Button.Looks.LINK} onClick={() => setView("choose")}>Back</Button>
                    </div>
                </Modals.ModalContent>
            </Modals.ModalRoot>
        );
    }

    if (view === "unlock") {
        return (
            <Modals.ModalRoot {...modalProps}>
                <Modals.ModalHeader><Text variant="heading-lg/semibold">Unlock Database</Text></Modals.ModalHeader>
                <Modals.ModalContent>
                    <div style={{ padding: "16px", display: "flex", flexDirection: "column", gap: "12px" }}>
                        <Text>Enter your database password:</Text>
                        <TextInput type="password" value={pw} onChange={setPw} placeholder="Password" onKeyDown={(e: React.KeyboardEvent) => e.key === "Enter" && doUnlock()} />
                        {error && <Text style={{ color: "#ed4245" }}>{error}</Text>}
                        <Button onClick={doUnlock}>Unlock</Button>
                    </div>
                </Modals.ModalContent>
            </Modals.ModalRoot>
        );
    }

    return null;
}

export const openStartupModal = (onFinish: () => void) =>
    openModal(props => <StartupModal modalProps={props} onFinish={onFinish} />);
