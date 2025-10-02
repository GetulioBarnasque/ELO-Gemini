
import React, { useState, useEffect, useRef, useImperativeHandle, forwardRef } from 'react';
import ReactDOM from 'react-dom/client';
import { GoogleGenAI } from "@google/genai";
import ReactMarkdown from 'react-markdown';

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
  id: string;
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
        <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 0 2l-.15.08a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.38a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1 0-2l.15-.08a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" /><circle cx="12" cy="12" r="3" />
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

const TrashIcon: React.FC<{ className?: string }> = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12 .562c.34-.059.68-.114 1.022-.165m0 0a48.11 48.11 0 013.478-.397m7.5 0v-.916c0-1.18-.91-2.134-2.09-2.134H8.09a2.09 2.09 0 00-2.09 2.134v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
    </svg>
);
  
const EditIcon: React.FC<{ className?: string }> = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L6.832 19.82a4.5 4.5 0 01-1.897 1.13l-2.685.8.8-2.685a4.5 4.5 0 011.13-1.897L16.863 4.487zm0 0L19.5 7.125" />
    </svg>
);

const MenuIcon: React.FC<{ className?: string }> = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
    </svg>
);

const UploadIcon: React.FC<{ className?: string }> = ({ className }) => (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
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
    private readonly USAGE_LIMIT = 25;

    constructor() {
        try {
            if (!process.env.API_KEY) {
                console.error("API_KEY not found. Chat functionality will be disabled.");
                return;
            }
            this.ai = new GoogleGenAI({ apiKey: process.env.API_KEY });
            this.initializeDefaultData();
        } catch (error) {
            console.error("Failed to initialize FirebaseService:", error);
        }
    }

    private async initializeDefaultData() {
        const storedUsers = localStorage.getItem('elo_users');
        if (!storedUsers) {
            // This is a complex setup for default users, let's create them on the fly
            // For simplicity, we'll just ensure they exist if needed.
        } else {
            this.users = JSON.parse(storedUsers);
        }
    }

    // --- Crypto Methods ---
    private strToArrBuf(str: string): Uint8Array { return new TextEncoder().encode(str); }
    private arrBufToStr(buf: ArrayBuffer): string { return new TextDecoder().decode(buf); }
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
        return `${this.bufToBase64(iv)}:${this.bufToBase64(encryptedData)}`;
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
        
        if (key === this.MASTER_KEY) {
            email = 'elo@protocoloelo.com';
            password = 'BetaUserPassword123!'; // Dummy password for KEK derivation
        } else if (key === this.ADMIN_KEY) {
            email = 'admin@protocoloelo.com';
            password = this.ADMIN_KEY;
        } else {
            return null;
        }

        let user = this.users.find(u => u.email === email);
        if (!user) { // First time login for this user
            user = await this.createDefaultUser(email, password);
        }

        const [saltB64, encryptedDekB64] = user.passwordHash.split(':');
        const salt = this.base64ToBuf(saltB64);
        const kek = await this.deriveKey(password, salt);
        
        this.sessionKey = kek; // Store KEK
        
        const dek = await window.crypto.subtle.unwrapKey(
            'raw', this.base64ToBuf(encryptedDekB64), kek,
            { name: 'AES-GCM', iv: new Uint8Array(12) }, // IV is not used for unwrap, but required
            { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );

        this.dataKey = dek; // Store DEK
        
        return user;
    }

    private async createDefaultUser(email: string, password: string): Promise<User> {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const kek = await this.deriveKey(password, salt);
        const dek = await window.crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
        );

        const wrappedDek = await window.crypto.subtle.wrapKey(
            'raw', dek, kek, { name: 'AES-GCM', iv: new Uint8Array(12) }
        );

        const defaultConversations: Conversation[] = [{ id: `conv-${Date.now()}`, name: "Nova Conversa", messages: [
            { id: 'welcome', sender: 'bot', text: "Bem-vindo ao Beta do Protocolo ELO! Seu limite de uso é de 25 mensagens por dia. Encontrou um problema? Use o link 'Reportar um Bug' na barra lateral. Agradecemos seu feedback!"}
        ] }];

        const encryptedConversations = await this.encryptData(JSON.stringify(defaultConversations), dek);
        
        const newUser: User = {
            id: `user-${Date.now()}`,
            email,
            passwordHash: `${this.bufToBase64(salt)}:${this.bufToBase64(wrappedDek)}`,
            role: email === 'admin@protocoloelo.com' ? 'ADMIN' : 'FREE',
            conversations: encryptedConversations,
        };

        this.users.push(newUser);
        this.saveUsers();
        return newUser;
    }

    logout() {
        this.sessionKey = null;
        this.dataKey = null;
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
    checkUsageLimit(user: User): { allowed: boolean; remaining: number } {
        if (user.role === 'ADMIN') return { allowed: true, remaining: Infinity };
        const today = new Date().toISOString().split('T')[0];
        const usageDataStr = localStorage.getItem(`elo_usage_${user.id}`);
        let usageData = usageDataStr ? JSON.parse(usageDataStr) : { date: today, count: 0 };
        
        if (usageData.date !== today) {
            usageData = { date: today, count: 0 };
        }
        
        return {
            allowed: usageData.count < this.USAGE_LIMIT,
            remaining: this.USAGE_LIMIT - usageData.count,
        };
    }

    recordUsage(user: User) {
        if (user.role === 'ADMIN') return;
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
    
    // RAG and System Prompts
    private getRoleSystemInstruction(role: Role): string {
        const instructions = JSON.parse(localStorage.getItem('elo_system_instructions') || '{}');
        return instructions[role] || "Você é um assistente prestativo.";
    }
    
    private getKnowledgeBase(role: Role): string {
        const bases = JSON.parse(localStorage.getItem('elo_knowledge_bases') || '{}');
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
    
    // --- Gemini API Call ---
// FIX: Updated to use modern `generateContentStream` API instead of deprecated chat methods.
async sendMessageStream(
    history: Message[],
    newMessage: string,
    image: string | undefined,
    role: Role,
    onChunk: (chunk: string) => void,
    onError: (error: string) => void
) {
    if (!this.ai) {
        onError("API não inicializada. Verifique a chave da API.");
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

const AdminPanel: React.FC<{ user: User; onLogout: () => void; showToast: (message: string, type: 'success' | 'error') => void; }> = ({ user, onLogout, showToast }) => {
    // This is a simplified version for the beta. Full logic can be restored later.
     return (
        <div className="bg-gray-800 text-white p-4 h-full flex flex-col">
            <h2 className="text-xl font-bold mb-4">Painel de Admin</h2>
            <p className="mb-4">Bem-vindo, {user.email}.</p>
            <p className="text-sm text-gray-400 mb-4">Funcionalidades completas do painel, como edição de prompts e RAG, estão disponíveis nesta conta e podem ser gerenciadas diretamente no código ou reativadas na UI quando necessário.</p>
            <button
                onClick={onLogout}
                className="w-full mt-auto flex items-center justify-center px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-md hover:bg-red-700"
            >
                <LogoutIcon className="w-5 h-5 mr-2" />
                Logout
            </button>
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

const ConfirmationModal: React.FC<{ isOpen: boolean; title: string; message: string; onConfirm: () => void; onCancel: () => void; }> = ({ isOpen, title, message, onConfirm, onCancel }) => {
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-gray-800 rounded-lg shadow-xl p-6 w-full max-w-sm">
                <h3 className="text-lg font-bold text-white mb-2">{title}</h3>
                <p className="text-gray-300 mb-4">{message}</p>
                <div className="flex justify-end gap-4">
                    <button onClick={onCancel} className="px-4 py-2 rounded bg-gray-600 hover:bg-gray-500 text-white">Cancelar</button>
                    <button onClick={onConfirm} className="px-4 py-2 rounded bg-red-600 hover:bg-red-500 text-white">Confirmar</button>
                </div>
            </div>
        </div>
    );
};


// --- MAIN APP COMPONENT ---
const App = () => {
    const [currentUser, setCurrentUser] = useState<User | null>(null);
    const [conversations, setConversations] = useState<Conversation[]>([]);
    const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
    const [isLoadingResponse, setIsLoadingResponse] = useState(false);
    const [isLoadingApp, setIsLoadingApp] = useState(true);
    const [isSidebarOpen, setIsSidebarOpen] = useState(true);
    const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' | 'info' } | null>(null);
    const [modal, setModal] = useState<{ type: 'deleteConversation'; conversationId: string } | null>(null);
    
    const chatInputRef = useRef<ChatInputHandles>(null);
    const chatEndRef = useRef<HTMLDivElement>(null);

    const showToast = (message: string, type: 'success' | 'error' | 'info') => setToast({ message, type });
    
    useEffect(() => {
        setIsLoadingApp(false); 
    }, []);

    const activeConversation = conversations.find(c => c.id === activeConversationId);

    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [activeConversation?.messages, isLoadingResponse]);

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
    };

    const handleDeleteConversation = (id: string) => {
        if (!currentUser) return;
        const updatedConversations = conversations.filter(c => c.id !== id);
        setConversations(updatedConversations);
        if (activeConversationId === id) {
            setActiveConversationId(updatedConversations.length > 0 ? updatedConversations[0].id : null);
        }
        firebaseService.saveEncryptedConversations(currentUser, updatedConversations);
        setModal(null);
        showToast("Conversa apagada.", "success");
    };

    const handleSubmit = async (text: string, image?: string) => {
        if (!activeConversation || !currentUser) return;
        
        const usage = firebaseService.checkUsageLimit(currentUser);
        if (!usage.allowed) {
            showToast(`Você atingiu seu limite de ${usage.remaining + firebaseService.USAGE_LIMIT} mensagens hoje.`, "error");
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

        // This needs to be done via a state update to get the latest conversations state
        setConversations(currentConversations => {
            const finalConversations = currentConversations.map(c => {
                 if (c.id !== activeConversationId) return c;
                 const finalMessages = c.messages.map(m => m.id === botMessageId ? {...m, isStreaming: false} : m);
                 // Ensure the bot message exists if chunks were empty
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
        <div className="flex h-screen text-white bg-gray-900">
             {/* Sidebar */}
             <div className={`transition-all duration-300 ${isSidebarOpen ? 'w-64' : 'w-0'} overflow-hidden bg-gray-800 flex flex-col`}>
                <div className="p-4 flex justify-between items-center border-b border-gray-700">
                    <button onClick={handleNewConversation} className="flex items-center gap-2 p-2 rounded-md hover:bg-gray-700 w-full">
                        <PlusIcon className="w-5 h-5" />
                        <span>Nova Conversa</span>
                    </button>
                </div>
                <div className="flex-grow overflow-y-auto">
                    {conversations.map(conv => (
                        <div key={conv.id} onClick={() => setActiveConversationId(conv.id)}
                            className={`p-3 m-2 rounded-md cursor-pointer truncate ${activeConversationId === conv.id ? 'bg-indigo-600' : 'hover:bg-gray-700'}`}>
                            {conv.name}
                        </div>
                    ))}
                </div>
                <div className="p-4 border-t border-gray-700">
                    <div className="flex items-center gap-3 mb-2">
                        <UserIcon className="w-8 h-8 p-1 bg-gray-600 rounded-full" />
                        <span>{currentUser.email}</span>
                    </div>
                    {currentUser.role === 'ADMIN' && (
                         <div className="mb-2">Admin Panel will be here.</div>
                    )}
                    <a href={`mailto:seu-email-de-feedback@example.com?subject=Feedback Beta Protocolo ELO`} className="text-sm text-gray-400 hover:underline mb-2 block">Reportar um Bug</a>
                    <button onClick={handleLogout} className="w-full flex items-center justify-center p-2 rounded-md hover:bg-gray-700 text-red-400">
                        <LogoutIcon className="w-5 h-5 mr-2" /> Logout
                    </button>
                </div>
             </div>
             
             {/* Main Content */}
             <div className="flex-1 flex flex-col relative">
                <button onClick={() => setIsSidebarOpen(!isSidebarOpen)} className="absolute top-1/2 -translate-y-1/2 bg-gray-800 hover:bg-indigo-600 text-white p-1 rounded-r-lg z-10" style={{left: isSidebarOpen ? '16rem' : '0rem', transition: 'left 0.3s ease-in-out'}}>
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
                    <div className="flex-1 flex items-center justify-center text-gray-400">
                        Selecione uma conversa ou crie uma nova para começar.
                    </div>
                )}
             </div>
        </div>
        <Toast message={toast?.message} type={toast?.type} onClose={() => setToast(null)} />
        {/* ConfirmationModal can be added here if needed */}
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
