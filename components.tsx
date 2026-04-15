/**
 * SimpleDiscordCrypt - UI Components
 * Lock icon toolbar button, key selector dropdown, key manager modal,
 * database import/export modal, and key visualizer.
 */

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

// ─── Key selector dropdown ─────────────────────────────────────────────────────

interface KeySelectorProps {
    channelId: string;
}

export function KeySelector({ channelId }: KeySelectorProps) {
    const [activeId, setActiveId] = useState(() => getActiveKeyIdForChannel(channelId) ?? "");

    useEffect(() => {
        setActiveId(getActiveKeyIdForChannel(channelId) ?? "");
    }, [channelId]);    

    if (!isUnlocked() || !isEncryptionEnabled(channelId)) {
        return null;
    }
    const keys = listKeys(false).filter(k => !k.hidden);

    const options = [
        { label: "— No key selected —", value: "" },
        ...keys.map(k => ({
            label: `[${k.type}] ${k.name}`,
            value: k.id,
        })),
    ];

    const safeActiveId = options.some(o => o.value === activeId) ? activeId : "";
    const handleChange = useCallback((value: string) => {
        setActiveId(value);
        setChannelKey(channelId, value || null);
    }, [channelId]);

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
        await deleteKey(key.id);
        refresh();
    };

    const fingerprint = async (key: StoredKey) => {
        const raw = key.rawKeyB64 ?? key.sharedKeyB64;
        if (!raw) return;
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
                            borderRadius: "8px", padding: "10px",
                            display: "flex", alignItems: "center", gap: "8px",
                            flexWrap: "wrap",
                        }}>
                            <span style={{
                                background: key.type === "DM" ? "#5865f2" : key.type === "GROUP" ? "#3ba55c" : "#747f8d",
                                color: "white", borderRadius: "4px", padding: "2px 6px", fontSize: "11px",
                            }}>{key.type ?? "KEY"}</span>
                            {editId === key.id ? (
                                <>
                                    <TextInput
                                        value={editName}
                                        onChange={(v: string) => setEditName(v)}
                                        style={{ flex: 1 }}
                                    />
                                    <Button size={Button.Sizes.SMALL} onClick={saveEdit}>Save</Button>
                                    <Button size={Button.Sizes.SMALL} look={Button.Looks.LINK} onClick={() => setEditId(null)}>Cancel</Button>
                                </>
                            ) : (
                                <>
                                    <Text style={{ flex: 1 }}>{key.name || "Unnamed Key"}</Text>
                                    {key.hidden && <span style={{ fontSize: "11px", opacity: 0.6 }}>[hidden]</span>}
                                    <Button size={Button.Sizes.SMALL} onClick={() => startEdit(key)}>Rename</Button>
                                    <Button size={Button.Sizes.SMALL} onClick={() => toggleHide(key)}>
                                        {key.hidden ? "Unhide" : "Hide"}
                                    </Button>
                                    <Button size={Button.Sizes.SMALL} onClick={() => fingerprint(key)}>🔍</Button>
                                    {key.type !== "PERSONAL" && (
                                        <Button size={Button.Sizes.SMALL} color={Button.Colors.RED} onClick={() => del(key)}>Delete</Button>
                                    )}
                                </>
                            )}
                        </div>
                    ))}
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <Button onClick={() => openGroupKeyModal(null)}>+ New Group Key</Button>
                <Button look={Button.Looks.LINK} onClick={modalProps.onClose}>Close</Button>
            </Modals.ModalFooter>
        </Modals.ModalRoot>
    );
}

export const openKeyManagerModal = () =>
    openModal(props => <KeyManagerModal modalProps={props} />);

// ─── Group Key Generation Modal ───────────────────────────────────────────────

function GroupKeyModal({ modalProps, channelId }: { modalProps: any; channelId: string | null }) {
    const [name, setName] = useState("");
    const [done, setDone] = useState<string | null>(null);

    const generate = async () => {
        if (!name.trim()) return;
        const key = await addGroupKey(name.trim());
        if (channelId) await setChannelKey(channelId, key.id);
        setDone(key.id);
    };

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">Generate Group Key</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px" }}>
                    {done ? (
                        <Text>✅ Group key "{name}" created and set for this channel!</Text>
                    ) : (
                        <>
                            <Text style={{ marginBottom: "8px" }}>
                                Enter a recognizable name for the new group key.
                                Share it via the Key Manager after creation.
                            </Text>
                            <TextInput
                                placeholder="Group key name (e.g. #general-2024)"
                                value={name}
                                onChange={setName}
                            />
                        </>
                    )}
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                {!done && <Button onClick={generate} disabled={!name.trim()}>Generate</Button>}
                <Button look={Button.Looks.LINK} onClick={modalProps.onClose}>Close</Button>
            </Modals.ModalFooter>
        </Modals.ModalRoot>
    );
}

export const openGroupKeyModal = (channelId: string | null) =>
    openModal(props => <GroupKeyModal modalProps={props} channelId={channelId} />);

// ─── Key Exchange Modal ───────────────────────────────────────────────────────

function KXModal({ modalProps, channelId }: { modalProps: any; channelId: string }) {
    const [status, setStatus] = useState("idle");

    const start = async () => {
        setStatus("starting");
        const { pubKeyB64 } = await startKX(channelId);
        await sendMessage(channelId, { content: SDC_NOENC_PREFIX + buildKxInitMessage(base64ToUint8(pubKeyB64)) });
        setStatus(`Sent. Waiting for response...\n\nYour pub key (base64):\n${pubKeyB64.slice(0, 40)}...`);
    };

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">Start Key Exchange</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px" }}>
                    <Text style={{ marginBottom: "8px" }}>
                        This will send an ECDH P-521 key exchange initiation message in this DM.
                        Both parties must have SDC installed for this to work automatically.
                    </Text>
                    {status !== "idle" && (
                        <pre style={{ background: "var(--background-secondary)", padding: "8px", borderRadius: "4px", fontSize: "12px", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                            {status}
                        </pre>
                    )}
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <Button onClick={start} disabled={status !== "idle"}>Start Key Exchange</Button>
                <Button look={Button.Looks.LINK} onClick={modalProps.onClose}>Close</Button>
            </Modals.ModalFooter>
        </Modals.ModalRoot>
    );
}

export const openKXModal = (channelId: string) =>
    openModal(props => <KXModal modalProps={props} channelId={channelId} />);

function IncomingKXModal({
    modalProps,
    senderName,
    onDecision,
}: {
    modalProps: any;
    senderName: string;
    onDecision: (accepted: boolean) => void;
}) {
    const resolvedRef = useRef(false);

    useEffect(() => {
        return () => {
            if (!resolvedRef.current) onDecision(false);
        };
    }, [onDecision]);

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">Allow Key Exchange</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px" }}>
                    <Text>
                        Allow key exchange for <code>DM key with {senderName}</code> from <code>{senderName}</code>?
                    </Text>
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <Button
                    onClick={() => {
                        resolvedRef.current = true;
                        onDecision(true);
                        modalProps.onClose();
                    }}
                >
                    Allow
                </Button>
                <Button
                    look={Button.Looks.LINK}
                    onClick={() => {
                        resolvedRef.current = true;
                        onDecision(false);
                        modalProps.onClose();
                    }}
                >
                    Deny
                </Button>
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
    const keys = listKeys(false).filter(k => !k.hidden && k.type === "GROUP");
    const [selectedIds, setSelectedIds] = useState<string[]>([]);

    const toggle = (id: string) =>
        setSelectedIds(prev => prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]);

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">Share Keys</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px" }}>
                    <Text style={{ marginBottom: "8px" }}>
                        Select group keys to share. They will be sent encrypted to the other party
                        using the established DM key for this channel.
                    </Text>
                    {keys.map(key => (
                        <div key={key.id} style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                            <input
                                type="checkbox"
                                checked={selectedIds.includes(key.id)}
                                onChange={() => toggle(key.id)}
                            />
                            <Text>{key.name}</Text>
                        </div>
                    ))}
                    {keys.length === 0 && <Text>No shareable group keys found.</Text>}
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <Button
                    disabled={selectedIds.length === 0}
                    onClick={() => {
                        // Actual share logic is handled in index.ts via message dispatch
                        const ev = new CustomEvent("sdc:share-keys", { detail: { channelId, keyIds: selectedIds } });
                        document.dispatchEvent(ev);
                        modalProps.onClose();
                    }}
                >
                    Share Selected
                </Button>
                <Button look={Button.Looks.LINK} onClick={modalProps.onClose}>Cancel</Button>
            </Modals.ModalFooter>
        </Modals.ModalRoot>
    );
}

export const openShareKeysModal = (channelId: string) =>
    openModal(props => <ShareKeysModal modalProps={props} channelId={channelId} />);

// ─── Key Visualizer Modal ─────────────────────────────────────────────────────

function KeyVisualizerModal({ modalProps, channelId }: { modalProps: any; channelId: string }) {
    const [fp, setFp] = useState("Computing...");
    const activeKeyId = getActiveKeyIdForChannel(channelId);

    useEffect(() => {
        (async () => {
            if (!activeKeyId) { setFp("No key selected"); return; }
            const key = getKey(activeKeyId);
            if (!key) { setFp("Key not found"); return; }
            const raw = key.rawKeyB64 ?? key.sharedKeyB64;
            if (!raw) { setFp("No key data"); return; }
            setFp(await keyFingerprint(base64ToUint8(raw)));
        })();
    }, [activeKeyId]);

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">Key Visualizer</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "24px", textAlign: "center" }}>
                    <Text style={{ marginBottom: "8px" }}>
                        Compare this fingerprint with the other party out-of-band to confirm you share the same key:
                    </Text>
                    <div style={{ fontSize: "36px", letterSpacing: "4px", padding: "16px", background: "var(--background-secondary)", borderRadius: "8px" }}>
                        {fp}
                    </div>
                    <Text style={{ marginTop: "8px", opacity: 0.7, fontSize: "12px" }}>
                        Active key: {activeKeyId ? (getKey(activeKeyId)?.name ?? activeKeyId) : "None"}
                    </Text>
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
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);

    return (
        <Modals.ModalRoot {...modalProps}>
            <Modals.ModalHeader>
                <Text variant="heading-lg/semibold">Export Database</Text>
            </Modals.ModalHeader>
            <Modals.ModalContent>
                <div style={{ padding: "16px" }}>
                    <Text>Your database contains all keys and channel settings.</Text>
                    <Text style={{ marginTop: "8px" }}>Keep this file safe — it contains private key material.</Text>
                </div>
            </Modals.ModalContent>
            <Modals.ModalFooter>
                <a href={url} download="SimpleDiscordCrypt.json" style={{ textDecoration: "none" }}>
                    <Button>Download JSON</Button>
                </a>
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
        if (!json.trim()) return;
        try {
            await importDatabaseJson(json, asSecondary);
            setStatus("✅ Import successful! Reload Discord to apply.");
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
                    <Text>Paste the contents of your exported database JSON below, or drag a file.</Text>
                    <textarea
                        value={json}
                        onChange={e => setJson((e.target as HTMLTextAreaElement).value)}
                        style={{
                            width: "100%", height: "150px", fontFamily: "monospace", fontSize: "12px",
                            background: "var(--background-secondary)", border: "1px solid var(--background-modifier-accent)",
                            borderRadius: "4px", padding: "8px", color: "var(--text-normal)",
                        }}
                        placeholder='{"version":2,...}'
                    />
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                        <input type="checkbox" checked={asSecondary} onChange={e => setAsSecondary((e.target as HTMLInputElement).checked)} id="secondary-chk" />
                        <label htmlFor="secondary-chk">
                            <Text>Import as secondary (won't replace identity keys, ignores future key exchanges)</Text>
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
