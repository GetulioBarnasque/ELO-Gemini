import React, { useState, useEffect, useRef, useImperativeHandle, forwardRef } from 'react';
import ReactDOM from 'react-dom/client';
import { GoogleGenAI } from "@google/genai";
import ReactMarkdown from 'react-markdown';

declare global {
    interface Window {
        process: {
            env: {
                API_KEY: string;
            };
        };
    }
}

// --- TYPES ---
type Sender = 'user' | 'bot';

interface Message {
  id: string;
  sender: Sender;
  text: string;
  image?: string; 
  isStreaming?: boolean;
  isError?: boolean;
}

interface Conversation {
  id: string;
  name: string;
  messages: Message[];
}

type Role = 'FREE' | 'PRO' | 'PREMIUM' | 'ADMIN';

interface User {
  id:string;
  email: string;
  passwordHash: string; // This is actually the KEK salt + encrypted DEK
  role: Role;
  conversations: string; // Encrypted conversations JSON
}

// --- ICONS ---

const BotIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
  <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 8V4H8" /><rect width="16" height="12" x="4" y="8" rx="2" /><path d="M2 14h2" /><path d="M20 14h2" /><path d="M15 13v2" /><path d="M9 13v2" />
  </svg>
);

const UserIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
  <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" />
  </svg>
);

const SendIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
  <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="m22 2-7 20-4-9-9-4Z" /><path d="M22 2 11 13" />
  </svg>
);

const PlusIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
  <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M5 12h14" /><path d="M12 5v14" />
  </svg>
);

const PaperclipIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
  <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.59a2 2 0 0 1-2.83-2.83l8.49-8.48" />
  </svg>
);

const AdminIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 0 2l-.15.08a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.38a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1 0 2l.15-.08a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" /><circle cx="12" cy="12" r="3" />
    </svg>
);

const LogoutIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><polyline points="16 17 21 12 16 7" /><line x1="21" x2="9" y1="12" y2="12" />
    </svg>
);

const KeyIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="7.5" cy="15.5" r="5.5" /><path d="m21 2-9.6 9.6" /><path d="m15.5 7.5 3 3L22 7l-3-3" />
    </svg>
);

const EloIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-1-13h2v6h-2zm0 8h2v2h-2z" />
    </svg>
);

const ChevronDoubleLeftIcon: React.FC<{ className?: string }> = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M18.75 19.5l-7.5-7.5 7.5-7.5m-6 15L5.25 12l7.5-7.5" />
    </svg>
);

const ArrowLeftIcon: React.FC<{ className?: string }> = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M10.5 19.5L3 12m0 0l7.5-7.5M3 12h18" />
    </svg>
);

const UploadIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line x1="12" x2="12" y1="3" y2="15" />
    </svg>
);

const DownloadIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" x2="12" y1="15" y2="3" />
    </svg>
);

const MenuIcon: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
    <svg {...props} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
        <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
    </svg>
);


// --- TOAST NOTIFICATION ---
const Toast: React.FC<{ message: string; type: 'success' | 'error' | 'info'; onClose: () => void; }> = ({ message, type, onClose }) => {
    const [visible, setVisible] = useState(false);

    useEffect(() => {
        if (message) {
            setVisible(true);
            const timer = setTimeout(() => {
                setVisible(false);
                setTimeout(onClose, 300); // Allow fade out animation
            }, 5000);
            return () => clearTimeout(timer);
        }
    }, [message, onClose]);

    const baseStyle = "fixed top-5 right-5 p-4 rounded-lg shadow-lg text-white max-w-sm z-50 transition-opacity duration-300";
    const typeStyles = {
        success: "bg-green-500",
        error: "bg-red-500",
        info: "bg-blue-500"
    };

    return (
        <div className={`${baseStyle} ${typeStyles[type] || typeStyles.info} ${visible ? 'opacity-100' : 'opacity-0'}`}>
            {message}
        </div>
    );
};

// --- SERVICE CLASS ---
// This service simulates a backend and handles all data, logic, and cryptography.
class FirebaseService {
    private ai: GoogleGenAI | null = null;
    private users: User[] = [];
    private sessionKey: CryptoKey | null = null; // KEK
    private dataKey: CryptoKey | null = null; // DEK
    private readonly MASTER_KEY = 'BETA_ELO_2024!';
    private readonly ADMIN_KEY = 'Admin123!';
    private readonly PRO_KEY = 'PRO_ELO_2024!';
    private readonly PREMIUM_KEY = 'PREMIUM_ELO_2024!';
    private readonly USAGE_LIMIT = 25;
    private readonly ENCRYPTED_CONFIGS_KEY = 'elo_encrypted_configs';
    private readonly DEFAULT_WELCOME_MESSAGE = "Bem-vindo ao Beta do Protocolo ELO! Como usuário {role}, você tem acesso ilimitado. Encontrou um problema? Use o link 'Reportar um Bug' na barra lateral. Agradecemos seu feedback!";

    // In-memory cache for decrypted configs
    private systemInstructions: Record<Role, string> | null = null;
    private knowledgeBases: Record<Role, string> | null = null;
    private welcomeMessage: string | null = null;

    constructor() {
        // Always initialize user data first for login functionality
        this.initializeDefaultData();

        try {
            const apiKey = window.process?.env?.API_KEY;
            if (!apiKey || apiKey === "YOUR_API_KEY") {
                console.error("API_KEY not found or is a placeholder in config.js. Chat functionality will be disabled.");
                this.ai = null;
                return;
            }
            this.ai = new GoogleGenAI({ apiKey: apiKey });
        } catch (error) {
            console.error("Failed to initialize GoogleGenAI:", error);
            this.ai = null;
        }
    }

    private initializeDefaultData() {
        const storedUsers = localStorage.getItem('elo_users');
        if (storedUsers) {
            this.users = JSON.parse(storedUsers);
        }
    }

    // --- Crypto Methods ---
    private strToArrBuf(str: string): Uint8Array { return new TextEncoder().encode(str); }
    private arrBufToStr(buf: ArrayBuffer): string { return new TextDecoder().decode(new Uint8Array(buf)); }
    private bufToBase64(buf: ArrayBuffer): string { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
    private base64ToBuf(b64: string): ArrayBuffer {
        const byteString = atob(b64);
        const bytes = new Uint8Array(byteString.length);
        for (let i = 0; i < byteString.length; i++) {
            bytes[i] = byteString.charCodeAt(i);
        }
        return bytes.buffer;
    }
    private async deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
        const baseKey = await window.crypto.subtle.importKey(
            'raw', this.strToArrBuf(password), { name: 'PBKDF2' }, false, ['deriveKey']
        );
        return window.crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
            baseKey, { name: 'AES-GCM', length: 256 }, true, ['wrapKey', 'unwrapKey']
        );
    }
    private async encryptData(data: string, key: CryptoKey): Promise<string> {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedData = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv }, key, this.strToArrBuf(data)
        );
        return `${this.bufToBase64(iv.buffer)}:${this.bufToBase64(encryptedData)}`;
    }
    private async decryptData(encryptedString: string, key: CryptoKey): Promise<string> {
        try {
            const [ivB64, encryptedDataB64] = encryptedString.split(':');
            const iv = this.base64ToBuf(ivB64);
            const encryptedData = this.base64ToBuf(encryptedDataB64);
            const decryptedData = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv }, key, encryptedData
            );
            return this.arrBufToStr(decryptedData);
        } catch (e) {
            console.error("Decryption failed:", e);
            throw new Error("Invalid key or corrupted data.");
        }
    }

    // --- User & Auth Methods ---
    async loginWithMasterKey(key: string): Promise<User | null> {
        let email: string;
        let password: string;
        let role: Role;

        if (key === this.MASTER_KEY) {
            email = 'elo@protocoloelo.com';
            password = 'BetaUserPassword123!'; // Dummy password for KEK derivation
            role = 'FREE';
        } else if (key === this.PRO_KEY) {
            email = 'pro@protocoloelo.com';
            password = 'ProUserPassword456!';
            role = 'PRO';
        } else if (key === this.PREMIUM_KEY) {
            email = 'premium@protocoloelo.com';
            password = 'PremiumUserPassword789!';
            role = 'PREMIUM';
        } else if (key === this.ADMIN_KEY) {
            email = 'admin@protocoloelo.com';
            password = this.ADMIN_KEY;
            role = 'ADMIN';
        } else {
            return null;
        }

        let user = this.users.find(u => u.email === email);
        if (!user) { // First time login for this user
            user = await this.createDefaultUser(email, password, role);
        }

        const [saltB64, encryptedDekB64] = user.passwordHash.split(':');
        const salt = this.base64ToBuf(saltB64);
        const kek = await this.deriveKey(password, new Uint8Array(salt));
        
        this.sessionKey = kek; // Store KEK
        
        const dek = await window.crypto.subtle.unwrapKey(
            'raw', this.base64ToBuf(encryptedDekB64), kek,
            { name: 'AES-GCM', iv: new Uint8Array(12) }, // IV is not used for unwrap, but required
            { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );

        this.dataKey = dek; // Store DEK
        
        await this._loadAndDecryptConfigs();

        return user;
    }

    private async createDefaultUser(email: string, password: string, role: Role): Promise<User> {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const kek = await this.deriveKey(password, salt);
        const dek = await window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );

        const wrappedDek = await window.crypto.subtle.wrapKey(
            'raw', dek, kek, { name: 'AES-GCM', iv: new Uint8Array(12) }
        );

        const welcomeTemplate = this.getWelcomeMessage();
        const welcomeMessageText = welcomeTemplate.replace('{role}', role);

        const defaultConversations: Conversation[] = [{ id: `conv-${Date.now()}`, name: "Nova Conversa", messages: [
            { id: 'welcome', sender: 'bot', text: welcomeMessageText}
        ] }];

        const encryptedConversations = await this.encryptData(JSON.stringify(defaultConversations), dek);
        
        const newUser: User = {
            id: `user-${Date.now()}`,
            email,
            passwordHash: `${this.bufToBase64(salt.buffer)}:${this.bufToBase64(wrappedDek)}`,
            role: role,
            conversations: encryptedConversations,
        };

        this.users.push(newUser);
        this.saveUsers();
        return newUser;
    }

    logout() {
        this.sessionKey = null;
        this.dataKey = null;
        this.systemInstructions = null;
        this.knowledgeBases = null;
        this.welcomeMessage = null;
    }

    private saveUsers() {
        localStorage.setItem('elo_users', JSON.stringify(this.users));
    }

    // --- Data Methods ---
    async getDecryptedConversations(user: User): Promise<Conversation[]> {
        if (!this.dataKey) throw new Error("Not logged in.");
        if (!user.conversations) return [];
        const decryptedJson = await this.decryptData(user.conversations, this.dataKey);
        return JSON.parse(decryptedJson);
    }
    
    async saveEncryptedConversations(user: User, conversations: Conversation[]) {
        if (!this.dataKey) throw new Error("Not logged in.");
        const encryptedJson = await this.encryptData(JSON.stringify(conversations), this.dataKey);
        const userIndex = this.users.findIndex(u => u.id === user.id);
        if (userIndex > -1) {
            this.users[userIndex].conversations = encryptedJson;
            this.saveUsers();
        }
    }
    
    // --- Usage Limit ---
    checkUsageLimit(user: User): { allowed: boolean; remaining: number; limit: number } {
        if (user.role === 'ADMIN' || user.role === 'PRO' || user.role === 'PREMIUM') return { allowed: true, remaining: Infinity, limit: Infinity };
        
        const today = new Date().toISOString().split('T')[0];
        const usageDataStr = localStorage.getItem(`elo_usage_${user.id}`);
        let usageData = usageDataStr ? JSON.parse(usageDataStr) : { date: today, count: 0 };
        
        if (usageData.date !== today) {
            usageData = { date: today, count: 0 };
        }
        
        return {
            allowed: usageData.count < this.USAGE_LIMIT,
            remaining: this.USAGE_LIMIT - usageData.count,
            limit: this.USAGE_LIMIT,
        };
    }

    recordUsage(user: User) {
        if (user.role === 'ADMIN' || user.role === 'PRO' || user.role === 'PREMIUM') return;
        const today = new Date().toISOString().split('T')[0];
        const usageDataStr = localStorage.getItem(`elo_usage_${user.id}`);
        let usageData = usageDataStr ? JSON.parse(usageDataStr) : { date: today, count: 0 };

        if (usageData.date !== today) {
            usageData = { date: today, count: 1 };
        } else {
            usageData.count += 1;
        }
        localStorage.setItem(`elo_usage_${user.id}`, JSON.stringify(usageData));
    }
    
    // --- RAG and System Prompts (ENCRYPTED) ---
    private async _loadAndDecryptConfigs() {
        if (!this.dataKey) return;

        const defaults = { instructions: { FREE: '', PRO: '', PREMIUM: '', ADMIN: '' }, bases: { FREE: '', PRO: '', PREMIUM: '', ADMIN: '' }, welcomeMessage: this.DEFAULT_WELCOME_MESSAGE };

        try {
            const encryptedConfigs = localStorage.getItem(this.ENCRYPTED_CONFIGS_KEY);
            if (encryptedConfigs) {
                const decrypted = await this.decryptData(encryptedConfigs, this.dataKey);
                const configs = JSON.parse(decrypted);
                this.systemInstructions = { ...defaults.instructions, ...configs.instructions };
                this.knowledgeBases = { ...defaults.bases, ...configs.bases };
                this.welcomeMessage = configs.welcomeMessage || defaults.welcomeMessage;
            } else {
                this.systemInstructions = defaults.instructions;
                this.knowledgeBases = defaults.bases;
                this.welcomeMessage = defaults.welcomeMessage;
            }
        } catch (e) {
            console.error("Failed to load/decrypt configs:", e);
            this.systemInstructions = defaults.instructions;
            this.knowledgeBases = defaults.bases;
            this.welcomeMessage = defaults.welcomeMessage;
        }
    }

    private async _saveEncryptedConfigs() {
        if (!this.dataKey) throw new Error("Authentication required to save settings.");
        const configs = {
            instructions: this.systemInstructions,
            bases: this.knowledgeBases,
            welcomeMessage: this.welcomeMessage
        };
        const jsonString = JSON.stringify(configs);
        const encryptedData = await this.encryptData(jsonString, this.dataKey);
        localStorage.setItem(this.ENCRYPTED_CONFIGS_KEY, encryptedData);
    }

    private getRoleSystemInstruction(role: Role): string {
        return this.systemInstructions?.[role] || "Você é um assistente prestativo.";
    }
    
    private getKnowledgeBase(role: Role): string {
        const bases = this.knowledgeBases;
        if (!bases) return '';

        let knowledge = '';
        if (role === 'ADMIN') {
            knowledge += (bases['ADMIN'] || '') + '\n' + (bases['PREMIUM'] || '') + '\n' + (bases['PRO'] || '') + '\n' + (bases['FREE'] || '');
        } else if (role === 'PREMIUM') {
            knowledge += (bases['PREMIUM'] || '') + '\n' + (bases['PRO'] || '') + '\n' + (bases['FREE'] || '');
        } else if (role === 'PRO') {
            knowledge += (bases['PRO'] || '') + '\n' + (bases['FREE'] || '');
        } else { // FREE
            knowledge += bases['FREE'] || '';
        }
        return knowledge.trim();
    }
    
    getSystemInstructions(): Record<Role, string> {
        return this.systemInstructions || { FREE: '', PRO: '', PREMIUM: '', ADMIN: '' };
    }

    getKnowledgeBases(): Record<Role, string> {
        return this.knowledgeBases || { FREE: '', PRO: '', PREMIUM: '', ADMIN: '' };
    }

    getWelcomeMessage(): string {
        return this.welcomeMessage || this.DEFAULT_WELCOME_MESSAGE;
    }
    
    async saveAdminConfigs(configs: {
        instructions: Record<Role, string>;
        bases: Record<Role, string>;
        welcomeMessage: string;
    }) {
        this.systemInstructions = configs.instructions;
        this.knowledgeBases = configs.bases;
        this.welcomeMessage = configs.welcomeMessage;
        await this._saveEncryptedConfigs();
    }
    
    async exportEncryptedConfigs(): Promise<string> {
        if (!this.dataKey) throw new Error("Authentication required to export settings.");
        const configs = {
            instructions: this.systemInstructions,
            bases: this.knowledgeBases,
            welcomeMessage: this.welcomeMessage
        };
        const jsonString = JSON.stringify(configs);
        return this.encryptData(jsonString, this.dataKey);
    }

    async importEncryptedConfigs(encryptedData: string): Promise<void> {
        if (!this.dataKey) throw new Error("Authentication required to import settings.");
        const decryptedJson = await this.decryptData(encryptedData, this.dataKey);
        const configs = JSON.parse(decryptedJson);

        if (configs.instructions && configs.bases) {
            this.systemInstructions = configs.instructions;
            this.knowledgeBases = configs.bases;
            this.welcomeMessage = configs.welcomeMessage || this.DEFAULT_WELCOME_MESSAGE;
            await this._saveEncryptedConfigs();
        } else {
            throw new Error("Invalid configuration file format.");
        }
    }

    // --- Gemini API Call ---
    async sendMessageStream(
        history: Message[],
        newMessage: string,
        image: string | undefined,
        role: Role,
        onChunk: (chunk: string) => void,
        onError: (error: string) => void
    ) {
        if (!this.ai) {
            onError("A funcionalidade de IA está desativada. Verifique se a chave de API está configurada corretamente no arquivo config.js e não é um placeholder.");
            return;
        }

        try {
            const systemInstruction = this.getRoleSystemInstruction(role);
            const knowledgeBase = this.getKnowledgeBase(role);
            
            let augmentedPrompt = newMessage;
            if (knowledgeBase) {
                augmentedPrompt = `Com base no seguinte CONTEXTO, responda à PERGUNTA do usuário. Se o contexto não for relevante, ignore-o.\n\n### CONTEXTO ###\n${knowledgeBase}\n\n### PERGUNTA ###\n${newMessage}`;
            }

            const conversationHistory = history.map(msg => ({
                role: msg.sender === 'user' ? 'user' : 'model',
                parts: [{ text: msg.text }] // Note: This simplistic mapping ignores images in history.
            }));

            const userParts: any[] = [{ text: augmentedPrompt }];
            if (image) {
                userParts.unshift({
                    inlineData: {
                        mimeType: 'image/jpeg', // Assuming jpeg for simplicity
                        data: image,
                    },
                });
            }

            const contents = [...conversationHistory, { role: 'user', parts: userParts }];

            const result = await this.ai.models.generateContentStream({
                model: 'gemini-2.5-flash',
                contents: contents,
                config: {
                    systemInstruction: systemInstruction,
                }
            });
            
            for await (const chunk of result) {
                if (chunk && chunk.text) {
                    onChunk(chunk.text);
                }
            }
        } catch (e) {
            console.error(e);
            let errorMessage = "Ocorreu um erro ao se comunicar com a IA.";
            if (e instanceof Error) {
                if (e.message.includes('API key not valid')) {
                    errorMessage = "Erro de API: A chave fornecida não é válida.";
                } else if (e.message.toLowerCase().includes('quota')) {
                    errorMessage = "Você atingiu o limite de uso da API. Tente novamente mais tarde.";
                }
            }
            onError(errorMessage);
        }
    }
}
const firebaseService = new FirebaseService();

// --- UI COMPONENTS (with full logic) ---

const Login: React.FC<{ onLoginSuccess: (user: User) => void; showToast: (message: string, type: 'success' | 'error') => void; }> = ({ onLoginSuccess, showToast }) => {
    const [key, setKey] = useState('');
    const [isLoading, setIsLoading] = useState(false);

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsLoading(true);
        try {
            const user = await firebaseService.loginWithMasterKey(key);
            if (user) {
                showToast("Login bem-sucedido!", "success");
                onLoginSuccess(user);
            } else {
                showToast("Chave de acesso inválida.", "error");
            }
        } catch (error) {
            console.error("Login failed", error);
            showToast("Falha no login. Verifique o console para mais detalhes.", "error");
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="flex items-center justify-center h-screen bg-gray-900">
            <div className="w-full max-w-md p-8 space-y-8 bg-gray-800 rounded-lg shadow-lg">
                <div className="text-center">
                    <EloIcon className="w-20 h-20 mx-auto text-indigo-500" />
                    <h2 className="mt-6 text-3xl font-extrabold text-white">
                        Protocolo ELO Beta
                    </h2>
                    <p className="mt-2 text-sm text-gray-400">
                        Insira a chave de acesso para começar
                    </p>
                </div>
                <form className="mt-8 space-y-6" onSubmit={handleLogin}>
                    <div className="relative">
                        <KeyIcon className="absolute w-5 h-5 text-gray-400 top-3.5 left-4" />
                        <input
                            id="master-key"
                            name="master-key"
                            type="password"
                            autoComplete="current-password"
                            required
                            className="w-full py-3 pl-12 pr-4 text-white bg-gray-700 border border-gray-600 rounded-md focus:ring-indigo-500 focus:border-indigo-500"
                            placeholder="Chave de Acesso Beta"
                            value={key}
                            onChange={(e) => setKey(e.target.value)}
                        />
                    </div>

                    <div>
                        <button
                            type="submit"
                            disabled={isLoading}
                            className="relative flex justify-center w-full px-4 py-3 text-sm font-medium text-white bg-indigo-600 border border-transparent rounded-md group hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:bg-indigo-400 disabled:cursor-not-allowed"
                        >
                            {isLoading ? 'Autenticando...' : 'Entrar'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

const AdminPanel: React.FC<{ onClose: () => void; showToast: (message: string, type: 'success' | 'error' | 'info') => void; }> = ({ onClose, showToast }) => {
    const ROLES: Role[] = ['FREE', 'PRO', 'PREMIUM', 'ADMIN'];
    const [activeTab, setActiveTab] = useState<'instructions' | 'knowledge'>('instructions');
    const [instructions, setInstructions] = useState<Record<Role, string>>({ FREE: '', PRO: '', PREMIUM: '', ADMIN: '' });
    const [knowledgeBases, setKnowledgeBases] = useState<Record<Role, string>>({ FREE: '', PRO: '', PREMIUM: '', ADMIN: '' });
    const [welcomeMessage, setWelcomeMessage] = useState('');
    const [isLoading, setIsLoading] = useState(true);
    const ragFileInputRef = useRef<HTMLInputElement>(null);
    const importFileInputRef = useRef<HTMLInputElement>(null);
    const [uploadTargetRole, setUploadTargetRole] = useState<Role | null>(null);

    useEffect(() => {
        setInstructions(firebaseService.getSystemInstructions());
        setKnowledgeBases(firebaseService.getKnowledgeBases());
        setWelcomeMessage(firebaseService.getWelcomeMessage());
        setIsLoading(false);
    }, []);

    const handleSave = async () => {
        try {
            await firebaseService.saveAdminConfigs({
                instructions,
                bases: knowledgeBases,
                welcomeMessage
            });
            showToast("Configurações salvas com sucesso!", "success");
        } catch (error) {
            console.error(error);
            showToast("Erro ao salvar configurações.", "error");
        }
    };

    const handleInstructionChange = (role: Role, value: string) => {
        setInstructions(prev => ({ ...prev, [role]: value }));
    };

    const handleKnowledgeChange = (role: Role, value: string) => {
        setKnowledgeBases(prev => ({ ...prev, [role]: value }));
    };

    const handleUploadClick = (role: Role) => {
        setUploadTargetRole(role);
        ragFileInputRef.current?.click();
    };

    const handleRagFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        if (!uploadTargetRole) return;
        const file = event.target.files?.[0];
        if (file) {
            if (file.type === "text/plain") {
                const reader = new FileReader();
                reader.onload = (e) => {
                    const content = e.target?.result as string;
                    setKnowledgeBases(prev => ({
                        ...prev,
                        [uploadTargetRole]: (prev[uploadTargetRole] ? prev[uploadTargetRole] + '\n\n' : '') + content
                    }));
                    showToast(`Conteúdo de ${file.name} adicionado para ${uploadTargetRole}.`, 'success');
                };
                reader.onerror = () => {
                    showToast("Erro ao ler o arquivo.", "error");
                };
                reader.readAsText(file);
            } else {
                showToast("Por favor, selecione um arquivo de texto (.txt).", "error");
            }
        }
        if (event.target) { event.target.value = ''; }
        setUploadTargetRole(null);
    };

    const handleExport = async () => {
        try {
            const encryptedData = await firebaseService.exportEncryptedConfigs();
            const blob = new Blob([encryptedData], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'elo_config_encrypted.json';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast("Configurações exportadas com sucesso!", "success");
        } catch (error) {
            console.error("Export failed", error);
            showToast("Falha ao exportar configurações.", "error");
        }
    };

    const handleImportClick = () => {
        importFileInputRef.current?.click();
    };

    const handleImportFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = async (e) => {
                try {
                    const content = e.target?.result as string;
                    await firebaseService.importEncryptedConfigs(content);
                    setInstructions(firebaseService.getSystemInstructions());
                    setKnowledgeBases(firebaseService.getKnowledgeBases());
                    setWelcomeMessage(firebaseService.getWelcomeMessage());
                    showToast("Configurações importadas com sucesso!", "success");
                } catch (err) {
                    console.error("Import failed", err);
                    let message = "Falha ao importar configurações.";
                    if (err instanceof Error && err.message.includes("Invalid key")) {
                        message = "Falha na importação: O arquivo pode ser de outro usuário ou a chave está incorreta.";
                    } else if (err instanceof Error && err.message.includes("format")) {
                        message = "Falha na importação: Formato de arquivo inválido.";
                    }
                    showToast(message, "error");
                }
            };
            reader.onerror = () => { showToast("Erro ao ler o arquivo de importação.", "error"); };
            reader.readAsText(file);
        }
        if (event.target) { event.target.value = ''; }
    };
    
    if (isLoading) {
        return <div className="p-4">Carregando configurações...</div>;
    }

    const currentData = activeTab === 'instructions' ? instructions : knowledgeBases;
    const currentHandler = activeTab === 'instructions' ? handleInstructionChange : handleKnowledgeChange;

    return (
        <div className="p-4 h-full flex flex-col text-sm">
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-bold">Painel de Admin</h2>
                <button onClick={onClose} className="flex items-center gap-2 text-sm p-2 rounded-md hover:bg-gray-700">
                    <ArrowLeftIcon className="w-4 h-4" />
                    Voltar
                </button>
            </div>

            <div className="flex-grow overflow-y-auto pr-2">
                <div className="mb-4 pb-4 border-b border-gray-700">
                     <label className="block font-semibold text-gray-300 mb-1">Mensagem de Boas-Vindas</label>
                     <textarea
                        value={welcomeMessage}
                        onChange={(e) => setWelcomeMessage(e.target.value)}
                        className="w-full h-24 p-2 bg-gray-900 rounded-md border border-gray-600 focus:ring-indigo-500 focus:border-indigo-500"
                        placeholder="Mensagem para novos usuários..."
                    />
                    <p className="text-xs text-gray-500 mt-1">
                        Use <code className="bg-gray-700 p-0.5 rounded">{'{role}'}</code> para inserir o nível do usuário (ex: FREE, PRO).
                    </p>
                </div>
                
                <div className="flex border-b border-gray-700 mb-4">
                    <button onClick={() => setActiveTab('instructions')} className={`px-4 py-2 ${activeTab === 'instructions' ? 'border-b-2 border-indigo-500 text-white' : 'text-gray-400'}`}>
                        Instruções de Sistema
                    </button>
                    <button onClick={() => setActiveTab('knowledge')} className={`px-4 py-2 ${activeTab === 'knowledge' ? 'border-b-2 border-indigo-500 text-white' : 'text-gray-400'}`}>
                        Base de Conhecimento (RAG)
                    </button>
                </div>

                <input type="file" ref={ragFileInputRef} className="hidden" accept=".txt" onChange={handleRagFileChange} />
                <input type="file" ref={importFileInputRef} className="hidden" accept=".json" onChange={handleImportFileChange} />

                <div className="space-y-4">
                    {ROLES.map(role => (
                        <div key={role}>
                             <div className="flex justify-between items-center mb-1">
                                 <label className="block font-semibold text-gray-300">{role}</label>
                                 {activeTab === 'knowledge' && (
                                     <button
                                         onClick={() => handleUploadClick(role)}
                                         className="flex items-center gap-1 text-xs text-indigo-400 hover:text-indigo-300"
                                         aria-label={`Fazer upload de arquivo de texto para ${role}`}
                                     >
                                         <UploadIcon className="w-4 h-4" />
                                         <span>Fazer Upload (.txt)</span>
                                     </button>
                                 )}
                            </div>
                            <textarea
                                value={currentData[role]}
                                onChange={(e) => currentHandler(role, e.target.value)}
                                className="w-full h-24 p-2 bg-gray-900 rounded-md border border-gray-600 focus:ring-indigo-500 focus:border-indigo-500"
                            />
                        </div>
                    ))}
                </div>
            </div>

            <div className="mt-4 pt-4 border-t border-gray-700">
                <div className="flex gap-2 mb-2">
                    <button onClick={handleImportClick} className="w-full flex items-center justify-center gap-2 px-4 py-2 font-bold text-white bg-gray-600 rounded-md hover:bg-gray-500">
                        <UploadIcon className="w-5 h-5"/> Importar
                    </button>
                    <button onClick={handleExport} className="w-full flex items-center justify-center gap-2 px-4 py-2 font-bold text-white bg-gray-600 rounded-md hover:bg-gray-500">
                        <DownloadIcon className="w-5 h-5"/> Exportar
                    </button>
                </div>
                 <button onClick={handleSave} className="w-full px-4 py-2 font-bold text-white bg-indigo-600 rounded-md hover:bg-indigo-700">
                    Salvar Alterações
                </button>
            </div>
        </div>
    );
};

const ChatMessage: React.FC<{ message: Message }> = ({ message }) => {
    const isUser = message.sender === 'user';
    
    return (
        <div className={`flex items-start gap-4 p-4 ${isUser ? '' : 'bg-white/5'}`}>
            <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${isUser ? 'bg-indigo-500' : 'bg-gray-600'}`}>
                {isUser ? <UserIcon className="w-5 h-5 text-white" /> : <BotIcon className="w-5 h-5 text-white" />}
            </div>
            <div className="flex-grow pt-1">
                {message.image && (
                     <img src={`data:image/jpeg;base64,${message.image}`} alt="Uploaded content" className="mb-2 rounded-lg max-w-xs" />
                )}
                 <div className={`prose prose-invert prose-p:text-white prose-p:text-base ${message.isError ? 'text-red-400' : 'text-gray-200'}`}>
                    <ReactMarkdown>{message.text + (message.isStreaming ? '▍' : '')}</ReactMarkdown>
                </div>
            </div>
        </div>
    );
};

interface ChatInputHandles {
    focus: () => void;
}

const ChatInput = forwardRef<ChatInputHandles, { onSendMessage: (text: string, image?: string) => void; isLoading: boolean; }>(({ onSendMessage, isLoading }, ref) => {
    const [text, setText] = useState('');
    const [image, setImage] = useState<string | undefined>(undefined);
    const textareaRef = useRef<HTMLTextAreaElement>(null);
    const fileInputRef = useRef<HTMLInputElement>(null);

    useImperativeHandle(ref, () => ({
        focus: () => {
            textareaRef.current?.focus();
        },
    }));

    useEffect(() => {
        const textarea = textareaRef.current;
        if (textarea) {
            textarea.style.height = 'auto';
            textarea.style.height = `${textarea.scrollHeight}px`;
        }
    }, [text]);

    const handleSendMessage = () => {
        if ((text.trim() || image) && !isLoading) {
            onSendMessage(text, image);
            setText('');
            setImage(undefined);
            if (fileInputRef.current) fileInputRef.current.value = "";
        }
    };
    
    const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (file) {
            const reader = new FileReader();
            reader.onloadend = () => {
                const base64String = (reader.result as string).split(',')[1];
                setImage(base64String);
            };
            reader.readAsDataURL(file);
        }
    };

    return (
        <div className="bg-gray-800 p-4 border-t border-gray-700">
             <div className="relative flex items-end gap-2 bg-gray-700 rounded-lg p-2">
                <button
                    onClick={() => fileInputRef.current?.click()}
                    className="p-2 text-gray-400 hover:text-white disabled:text-gray-600"
                    disabled={isLoading}
                    aria-label="Anexar imagem"
                >
                    <PaperclipIcon className="w-6 h-6" />
                </button>
                <input
                    type="file"
                    ref={fileInputRef}
                    className="hidden"
                    accept="image/*"
                    onChange={handleFileChange}
                />
                <textarea
                    ref={textareaRef}
                    value={text}
                    onChange={(e) => setText(e.target.value)}
                    onKeyDown={(e) => {
                        if (e.key === 'Enter' && !e.shiftKey) {
                            e.preventDefault();
                            handleSendMessage();
                        }
                    }}
                    placeholder={image ? "Imagem pronta para enviar. Adicione um texto (opcional)." : "Digite sua mensagem..."}
                    className="w-full bg-transparent text-white placeholder-gray-400 resize-none focus:outline-none max-h-48"
                    rows={1}
                    disabled={isLoading}
                />
                <button
                    onClick={handleSendMessage}
                    disabled={isLoading || (!text.trim() && !image)}
                    className="p-2 text-white bg-indigo-600 rounded-lg disabled:bg-indigo-400 disabled:cursor-not-allowed"
                    aria-label="Enviar mensagem"
                >
                    <SendIcon className="w-6 h-6" />
                </button>
            </div>
             {image && (
                <div className="mt-2 text-xs text-gray-400">
                    <img src={`data:image/jpeg;base64,${image}`} className="w-16 h-16 rounded inline-block mr-2" alt="Preview"/>
                    Imagem anexada. Clique em enviar.
                </div>
            )}
        </div>
    );
});

// --- MAIN APP COMPONENT ---
const App = () => {
    const [currentUser, setCurrentUser] = useState<User | null>(null);
    const [conversations, setConversations] = useState<Conversation[]>([]);
    const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
    const [isLoadingResponse, setIsLoadingResponse] = useState(false);
    const [isLoadingApp, setIsLoadingApp] = useState(true);
    const [isSidebarOpen, setIsSidebarOpen] = useState(window.innerWidth >= 768);
    const [isAdminPanelVisible, setIsAdminPanelVisible] = useState(false);
    const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' | 'info' } | null>(null);
    
    const chatInputRef = useRef<ChatInputHandles>(null);
    const chatEndRef = useRef<HTMLDivElement>(null);

    const showToast = (message: string, type: 'success' | 'error' | 'info') => setToast({ message, type });
    
    useEffect(() => {
        setIsLoadingApp(false); 
        const handleResize = () => {
            if (window.innerWidth < 768) {
                setIsSidebarOpen(false);
            }
        };
        window.addEventListener('resize', handleResize);
        return () => window.removeEventListener('resize', handleResize);
    }, []);

    const activeConversation = conversations.find(c => c.id === activeConversationId);

    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [activeConversation?.messages, isLoadingResponse]);
    
    const handleConversationSelect = (id: string) => {
        setActiveConversationId(id);
        if (window.innerWidth < 768) {
            setIsSidebarOpen(false);
        }
    };
    
    const handleLoginSuccess = async (user: User) => {
        setCurrentUser(user);
        try {
            const userConversations = await firebaseService.getDecryptedConversations(user);
            setConversations(userConversations);
            if (userConversations.length > 0) {
                setActiveConversationId(userConversations[0].id);
            } else {
                handleNewConversation();
            }
        } catch (error) {
            console.error(error);
            showToast("Não foi possível carregar suas conversas.", "error");
        }
    };
    
    const handleLogout = () => {
        firebaseService.logout();
        setCurrentUser(null);
        setConversations([]);
        setActiveConversationId(null);
        showToast("Logout realizado com sucesso!", "success");
    };

    const handleNewConversation = () => {
        if (!currentUser) return;
        const newConversation: Conversation = {
            id: `conv-${Date.now()}`,
            name: "Nova Conversa",
            messages: []
        };
        const updatedConversations = [newConversation, ...conversations];
        setConversations(updatedConversations);
        setActiveConversationId(newConversation.id);
        firebaseService.saveEncryptedConversations(currentUser, updatedConversations);
        setIsAdminPanelVisible(false); // Close admin panel on new chat
        if (window.innerWidth < 768) {
            setIsSidebarOpen(false);
        }
    };

    const handleDeleteConversation = (id: string) => {
        if (!currentUser) return;
        const updatedConversations = conversations.filter(c => c.id !== id);
        setConversations(updatedConversations);
        if (activeConversationId === id) {
            setActiveConversationId(updatedConversations.length > 0 ? updatedConversations[0].id : null);
        }
        firebaseService.saveEncryptedConversations(currentUser, updatedConversations);
        showToast("Conversa apagada.", "success");
    };

    const handleSubmit = async (text: string, image?: string) => {
        if (!activeConversation || !currentUser) return;
        
        const usage = firebaseService.checkUsageLimit(currentUser);
        if (!usage.allowed) {
            showToast(`Você atingiu seu limite de ${usage.limit} mensagens hoje.`, "error");
            return;
        }

        const userMessage: Message = { id: `msg-${Date.now()}`, sender: 'user', text, image };
        const updatedMessages = [...activeConversation.messages, userMessage];
        const botMessageId = `msg-${Date.now() + 1}`;
        
        const updatedConversations = conversations.map(c =>
            c.id === activeConversationId ? { ...c, messages: updatedMessages } : c
        );
        setConversations(updatedConversations);
        setIsLoadingResponse(true);
        
        firebaseService.recordUsage(currentUser);

        const history = updatedMessages.slice(0, -1);

        await firebaseService.sendMessageStream(
            history,
            text,
            image,
            currentUser.role,
            (chunk) => { // onChunk
                setConversations(prev => prev.map(c => {
                    if (c.id !== activeConversationId) return c;
                    const existingBotMessage = c.messages.find(m => m.id === botMessageId);
                    if (existingBotMessage) {
                        return { ...c, messages: c.messages.map(m => m.id === botMessageId ? { ...m, text: m.text + chunk } : m) };
                    } else {
                        const newBotMessage: Message = { id: botMessageId, sender: 'bot', text: chunk, isStreaming: true };
                        return { ...c, messages: [...c.messages, newBotMessage] };
                    }
                }));
            },
            (error) => { // onError
                const errorMessage: Message = { id: botMessageId, sender: 'bot', text: error, isError: true };
                setConversations(prev => prev.map(c => c.id === activeConversationId ? { ...c, messages: [...c.messages, errorMessage] } : c));
            }
        );
        
        setIsLoadingResponse(false);

        setConversations(currentConversations => {
            const finalConversations = currentConversations.map(c => {
                 if (c.id !== activeConversationId) return c;
                 const finalMessages = c.messages.map(m => m.id === botMessageId ? {...m, isStreaming: false} : m);
                 if (!finalMessages.some(m => m.id === botMessageId)) {
                    finalMessages.push({ id: botMessageId, sender: 'bot', text: '', isStreaming: false });
                 }
                 return {...c, messages: finalMessages};
            });
            firebaseService.saveEncryptedConversations(currentUser, finalConversations);
            return finalConversations;
        });

        setTimeout(() => chatInputRef.current?.focus(), 0);
    };

    if (isLoadingApp) return <div>Carregando...</div>;
    
    if (!currentUser) {
        return (
            <>
                <Login onLoginSuccess={handleLoginSuccess} showToast={showToast} />
                <Toast message={toast?.message} type={toast?.type} onClose={() => setToast(null)} />
            </>
        );
    }

    // Main App UI
    return (
      <>
        <div className="flex h-screen text-white bg-gray-900 overflow-hidden">
             {/* Overlay for mobile */}
             {isSidebarOpen && (
                 <div
                     onClick={() => setIsSidebarOpen(false)}
                     className="fixed inset-0 bg-black/60 z-30 md:hidden"
                     aria-hidden="true"
                 ></div>
             )}

             {/* Sidebar */}
             <div className={`fixed inset-y-0 left-0 z-40 w-80 bg-gray-800 flex flex-col transform transition-transform duration-300 ease-in-out md:relative md:translate-x-0 ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full md:w-0'} overflow-hidden`}>
                {isAdminPanelVisible && currentUser.role === 'ADMIN' ? (
                    <AdminPanel 
                        onClose={() => setIsAdminPanelVisible(false)} 
                        showToast={showToast} 
                    />
                ) : (
                    <>
                        <div className="p-4 flex justify-between items-center border-b border-gray-700">
                            <button onClick={handleNewConversation} className="flex items-center gap-2 p-2 rounded-md hover:bg-gray-700 w-full">
                                <PlusIcon className="w-5 h-5" />
                                <span>Nova Conversa</span>
                            </button>
                        </div>
                        <div className="flex-grow overflow-y-auto">
                            {conversations.map(conv => (
                                <div key={conv.id} onClick={() => handleConversationSelect(conv.id)}
                                    className={`p-3 m-2 rounded-md cursor-pointer truncate ${activeConversationId === conv.id ? 'bg-indigo-600' : 'hover:bg-gray-700'}`}>
                                    {conv.name || "Nova Conversa"}
                                </div>
                            ))}
                        </div>
                        <div className="p-4 border-t border-gray-700">
                            <div className="flex items-center justify-between gap-3 mb-2">
                                <div className="flex items-center gap-3 overflow-hidden">
                                    <UserIcon className="w-8 h-8 p-1 bg-gray-600 rounded-full flex-shrink-0" />
                                    <span className="truncate">{currentUser.email}</span>
                                </div>
                                {currentUser.role === 'ADMIN' && (
                                    <button 
                                        onClick={() => setIsAdminPanelVisible(true)} 
                                        className="p-2 rounded-md hover:bg-gray-700 flex-shrink-0"
                                        aria-label="Painel de Administrador"
                                    >
                                        <AdminIcon className="w-5 h-5" />
                                    </button>
                                )}
                            </div>
                            <a href={`mailto:suporte@protocoloelo.com.br?subject=Feedback Beta Protocolo ELO`} className="text-sm text-gray-400 hover:underline mb-2 block">Reportar um Bug</a>
                            <button onClick={handleLogout} className="w-full flex items-center justify-center p-2 rounded-md hover:bg-gray-700 text-red-400">
                                <LogoutIcon className="w-5 h-5 mr-2" /> Logout
                            </button>
                        </div>
                    </>
                )}
             </div>
             
             {/* Main Content */}
             <div className="flex-1 flex flex-col relative">
                {/* Mobile Header */}
                 <div className="md:hidden p-3 flex items-center justify-between border-b border-gray-700 bg-gray-900">
                     <button onClick={() => setIsSidebarOpen(true)} className="p-1" aria-label="Abrir menu">
                         <MenuIcon className="w-6 h-6" />
                     </button>
                     <h1 className="text-md font-semibold truncate px-2">
                         {activeConversation?.name || "Protocolo ELO"}
                     </h1>
                     <div className="w-6"></div> {/* Spacer */}
                 </div>
                
                 {/* Desktop Sidebar Toggle */}
                <button
                    onClick={() => setIsSidebarOpen(!isSidebarOpen)}
                    className="hidden md:block absolute top-1/2 -translate-y-1/2 -ml-4 bg-gray-800 hover:bg-indigo-600 text-white p-2 rounded-full z-10 transition-all duration-300 ease-in-out focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-900 focus:ring-indigo-500"
                    style={{ left: 0 }}
                    aria-label={isSidebarOpen ? "Recolher barra lateral" : "Expandir barra lateral"}
                    >
                    <ChevronDoubleLeftIcon className={`w-5 h-5 transition-transform duration-300 ${isSidebarOpen ? '' : 'rotate-180'}`} />
                </button>
                 
                {activeConversation ? (
                    <div className="flex-1 flex flex-col overflow-hidden">
                        <div className="flex-1 overflow-y-auto">
                            {activeConversation.messages.map(msg => <ChatMessage key={msg.id} message={msg} />)}
                            {isLoadingResponse && !activeConversation.messages.find(m => m.isStreaming) && (
                                <ChatMessage message={{id:'streaming', sender: 'bot', text: '', isStreaming: true}}/>
                            )}
                            <div ref={chatEndRef} />
                        </div>
                        <ChatInput ref={chatInputRef} onSendMessage={handleSubmit} isLoading={isLoadingResponse} />
                    </div>
                ) : (
                    <div className="flex-1 flex items-center justify-center text-gray-400 text-center p-4">
                        Selecione uma conversa ou crie uma nova para começar.
                    </div>
                )}
             </div>
        </div>
        <Toast message={toast?.message} type={toast?.type} onClose={() => setToast(null)} />
      </>
    );
};


// --- RENDER ---
const rootElement = document.getElementById('root');
if (!rootElement) throw new Error('Failed to find the root element');
const root = ReactDOM.createRoot(rootElement);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);