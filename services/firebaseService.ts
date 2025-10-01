import { Chat, GoogleGenAI, GenerateContentResponse, Part } from "@google/genai";
import { Conversation, Message, PublicUser, Role, RoleSystemInstructions, User } from "../types";

// FIX: Added a helper function for UUID generation as it was used but not defined.
function randomUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        var r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// FIX: Added and exported 'convertFileToParts' to handle file to base64 conversion for image uploads.
export const convertFileToParts = (file: File): Promise<{ data: string; mimeType: string }> => {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => {
      const base64Data = (reader.result as string).split(',')[1];
      if (base64Data) {
        resolve({
          data: base64Data,
          mimeType: file.type,
        });
      } else {
        reject(new Error("Failed to read file as base64."));
      }
    };
    reader.onerror = (error) => reject(error);
    reader.readAsDataURL(file);
  });
};


// FIX: The entire service logic was not wrapped in a class, causing numerous parsing errors.
class FirebaseService {
    // FIX: The 'users' property was used throughout the class but not declared.
    private users: User[] = [];
    private conversations: Conversation[] = [];
    private systemInstructions: RoleSystemInstructions = {
        [Role.FREE]: 'Você é um assistente prestativo.',
        [Role.PRO]: 'Você é um assistente especialista em produtividade e negócios.',
        [Role.PREMIUM]: 'Você é um assistente de elite, capaz de análises profundas e insights criativos complexos.',
        [Role.ADMIN]: 'Você é um assistente de depuração para o administrador do sistema. Responda de forma concisa e técnica.'
    };
    private welcomeMessage: string = 'Bem-vindo ao Protocolo ELO! Como posso ajudá-lo hoje?';
    private knowledgeBases: RoleSystemInstructions = {
        [Role.FREE]: `O Protocolo ELO é uma aplicação de chat com IA. A versão FREE tem acesso a informações gerais.`,
        [Role.PRO]: `O framework do Protocolo ELO é descrito como "relacional e simbiótico". Usuários PRO podem perguntar sobre detalhes da arquitetura simulada.`,
        [Role.PREMIUM]: `Para usuários PREMIUM: A estratégia de monetização do Protocolo ELO envolve planos de assinatura escalonados (Free, Pro, Premium) que oferecem acesso a bases de conhecimento progressivamente mais valiosas.`,
        [Role.ADMIN]: `ADMIN NOTE: A base de usuários atual é simulada e armazenada no localStorage. A chave da API Gemini está exposta no frontend, o que é uma vulnerabilidade de segurança a ser tratada antes da produção.`
    };
    private ai: GoogleGenAI;
    private chats: Map<string, Chat> = new Map();

    constructor() {
        // IMPORTANT: In a real app, the API key must be handled securely on a backend.
        // For this frontend-only simulation, we'll assume it's available.
        if (!process.env.API_KEY) {
            console.error("API_KEY environment variable not set!");
            alert("A chave da API não foi configurada. A aplicação não pode funcionar.");
        }
        this.ai = new GoogleGenAI({ apiKey: process.env.API_KEY! });
        this.loadFromStorage();
    }

    private loadFromStorage() {
        try {
            const usersData = localStorage.getItem('elo_users');
            const convosData = localStorage.getItem('elo_conversations');
            const instructionsData = localStorage.getItem('elo_system_instructions');
            const welcomeMsgData = localStorage.getItem('elo_welcome_message');
            const knowledgeBasesData = localStorage.getItem('elo_knowledge_bases');
            
            this.users = usersData ? JSON.parse(usersData) : [];
            this.conversations = convosData ? JSON.parse(convosData) : [];
            this.systemInstructions = instructionsData ? JSON.parse(instructionsData) : this.systemInstructions;
            this.welcomeMessage = welcomeMsgData ? JSON.parse(welcomeMsgData) : this.welcomeMessage;
            this.knowledgeBases = knowledgeBasesData ? JSON.parse(knowledgeBasesData) : this.knowledgeBases;


            if (!this.users || this.users.length === 0) {
                this.createDefaultUsers();
            }

        } catch (error) {
            console.error("Failed to load data from storage:", error);
            this.users = [];
            this.conversations = [];
            this.createDefaultUsers();
        }
    }
    
    private createDefaultUsers() {
        this.users = [
            { id: 'admin-user', username: 'admin', email: 'admin@protocoloelo.com', passwordHash: 'Admin123!', isEmailVerified: true, emailVerificationToken: null, role: Role.ADMIN },
            { id: 'elo-user', username: 'elo', email: 'elo@protocoloelo.com', passwordHash: 'elo', isEmailVerified: true, emailVerificationToken: null, role: Role.FREE },
        ];
        this.saveUsers();
    }

    private saveUsers() {
        localStorage.setItem('elo_users', JSON.stringify(this.users));
    }

    private saveConversations() {
        localStorage.setItem('elo_conversations', JSON.stringify(this.conversations));
    }

    private saveSystemInstructions() {
        localStorage.setItem('elo_system_instructions', JSON.stringify(this.systemInstructions));
    }

    private saveWelcomeMessage() {
        localStorage.setItem('elo_welcome_message', JSON.stringify(this.welcomeMessage));
    }

    private saveKnowledgeBases() {
        localStorage.setItem('elo_knowledge_bases', JSON.stringify(this.knowledgeBases));
    }


    // --- User Management ---

    async registerUser(userData: Omit<User, 'id' | 'passwordHash' | 'isEmailVerified' | 'emailVerificationToken' | 'role'> & { password: string }): Promise<User> {
        if (this.users.some(u => u.email === userData.email)) {
            throw new Error('E-mail já cadastrado.');
        }
        if (this.users.some(u => u.username === userData.username)) {
            throw new Error('Nome de usuário já cadastrado.');
        }
        const emailVerificationToken = randomUUID();
        const newUser: User = {
            id: randomUUID(),
            username: userData.username,
            email: userData.email,
            passwordHash: userData.password, // In a real app, this MUST be hashed securely.
            isEmailVerified: false,
            emailVerificationToken,
            role: Role.FREE,
            recoveryEmail: userData.recoveryEmail,
            recoveryPhone: userData.recoveryPhone,
        };
        this.users.push(newUser);
        this.saveUsers();
        console.log(`--- SIMULAÇÃO DE E-MAIL DE CONFIRMAÇÃO ---
Token de confirmação para ${newUser.email}: ${emailVerificationToken}
--------------------------------------`);
        return newUser;
    }

    async login(email: string, password: string): Promise<PublicUser> {
        const user = this.users.find(u => u.email === email && u.passwordHash === password);
        if (!user) {
            throw new Error('Credenciais inválidas.');
        }
        if (!user.isEmailVerified) {
             throw new Error('EMAIL_NOT_VERIFIED');
        }
        localStorage.setItem('elo_currentUser', JSON.stringify(user.id));
        // FIX: Correctly create PublicUser by omitting all sensitive fields.
        const { passwordHash, isEmailVerified, emailVerificationToken, recoveryEmail, recoveryPhone, passwordResetToken, passwordResetExpires, ...publicUser } = user;
        return publicUser;
    }

    async logout(): Promise<void> {
        const userId = JSON.parse(localStorage.getItem('elo_currentUser') || 'null');
        if (userId) {
            localStorage.removeItem(`elo_lastActiveConvo_${userId}`);
        }
        localStorage.removeItem('elo_currentUser');
    }

    async getCurrentUser(): Promise<PublicUser | null> {
        const userId = JSON.parse(localStorage.getItem('elo_currentUser') || 'null');
        if (!userId) return null;
        const user = this.users.find(u => u.id === userId);
        if (!user) {
            localStorage.removeItem('elo_currentUser');
            return null;
        }
        // FIX: Correctly create PublicUser by omitting all sensitive fields.
        const { passwordHash, isEmailVerified, emailVerificationToken, recoveryEmail, recoveryPhone, passwordResetToken, passwordResetExpires, ...publicUser } = user;
        return publicUser;
    }
    
    // FIX: Added missing auth functions (confirmEmail, requestPasswordReset, resetPassword) to resolve errors in Login.tsx.
    async confirmEmail(token: string): Promise<boolean> {
        const user = this.users.find(u => u.emailVerificationToken === token);
        if (user) {
            user.isEmailVerified = true;
            user.emailVerificationToken = null;
            this.saveUsers();
            return true;
        }
        return false;
    }

    async requestPasswordReset(email: string): Promise<void> {
        const user = this.users.find(u => u.email === email);
        if (user) {
            const resetToken = randomUUID();
            user.passwordResetToken = resetToken;
            user.passwordResetExpires = Date.now() + 3600000; // 1 hour
            this.saveUsers();
            console.log(`--- SIMULAÇÃO DE E-MAIL DE RECUPERAÇÃO DE SENHA ---
Token de recuperação para ${user.email}: ${resetToken}
--------------------------------------------------`);
        }
        // Intentionally do nothing if email not found to prevent enumeration attacks
    }

    async resetPassword(token: string, newPassword: string): Promise<boolean> {
        const user = this.users.find(u => u.passwordResetToken === token);

        if (user && user.passwordResetExpires && user.passwordResetExpires > Date.now()) {
            user.passwordHash = newPassword; // In a real app, this MUST be hashed securely.
            user.passwordResetToken = null;
            user.passwordResetExpires = null;
            this.saveUsers();
            return true;
        }
        
        // If token is found but expired, invalidate it.
        if (user) {
            user.passwordResetToken = null;
            user.passwordResetExpires = null;
            this.saveUsers();
        }

        return false;
    }

    // --- Admin Functions ---
    async getAllUsers(): Promise<PublicUser[]> {
        return this.users.map(u => {
            // FIX: Correctly create PublicUser by omitting all sensitive fields.
            const { passwordHash, isEmailVerified, emailVerificationToken, recoveryEmail, recoveryPhone, passwordResetToken, passwordResetExpires, ...publicUser } = u;
            return publicUser;
        });
    }

    async updateUserRole(userId: string, newRole: User['role']): Promise<void> {
        const userToUpdate = this.users.find(u => u.id === userId);
        if (!userToUpdate) throw new Error("User not found.");

        // Safeguard: Prevent removing the last admin
        const adminCount = this.users.filter(u => u.role === Role.ADMIN).length;
        if (userToUpdate.role === Role.ADMIN && adminCount <= 1 && newRole !== Role.ADMIN) {
            throw new Error("Cannot remove the last administrator.");
        }
        
        userToUpdate.role = newRole;
        this.saveUsers();
    }
    
    async updateUserRoleByEmail(email: string, newRole: User['role']): Promise<PublicUser> {
        const userToUpdate = this.users.find(u => u.email === email);
        if (!userToUpdate) {
            throw new Error(`User with email "${email}" not found.`);
        }
         const adminCount = this.users.filter(u => u.role === Role.ADMIN).length;
        if (userToUpdate.role === Role.ADMIN && adminCount <= 1 && newRole !== Role.ADMIN) {
            throw new Error("Cannot remove the last administrator.");
        }

        userToUpdate.role = newRole;
        this.saveUsers();
        // FIX: Correctly create PublicUser by omitting all sensitive fields.
        const { passwordHash, isEmailVerified, emailVerificationToken, recoveryEmail, recoveryPhone, passwordResetToken, passwordResetExpires, ...publicUser } = userToUpdate;
        return publicUser;
    }

    async getSystemInstructions(): Promise<RoleSystemInstructions> {
        return this.systemInstructions;
    }

    async setSystemInstructions(instructions: RoleSystemInstructions): Promise<void> {
        this.systemInstructions = instructions;
        this.saveSystemInstructions();
    }

    async getWelcomeMessage(): Promise<string> {
        return this.welcomeMessage;
    }

    async setWelcomeMessage(message: string): Promise<void> {
        if(!message.trim()) throw new Error("Welcome message cannot be empty.");
        this.welcomeMessage = message;
        this.saveWelcomeMessage();
    }

    async getKnowledgeBases(): Promise<RoleSystemInstructions> {
        return this.knowledgeBases;
    }

    async updateKnowledgeBase(role: keyof RoleSystemInstructions, content: string): Promise<void> {
        this.knowledgeBases[role] = content;
        this.saveKnowledgeBases();
    }

    // --- Conversation Management ---

    async getConversations(userId: string): Promise<Conversation[]> {
        return this.conversations
            .filter(c => c.userId === userId)
            .sort((a, b) => b.createdAt - a.createdAt);
    }
    
    getLastActiveConversationId(userId: string): string | null {
        return localStorage.getItem(`elo_lastActiveConvo_${userId}`);
    }

    setLastActiveConversationId(userId: string, conversationId: string | null) {
        if(conversationId) {
            localStorage.setItem(`elo_lastActiveConvo_${userId}`, conversationId);
        } else {
             localStorage.removeItem(`elo_lastActiveConvo_${userId}`);
        }
    }

    async createConversation(userId: string): Promise<Conversation> {
        const now = new Date();
        const formattedDate = `${now.getDate().toString().padStart(2, '0')}/${(now.getMonth() + 1).toString().padStart(2, '0')}/${now.getFullYear().toString().slice(-2)}`;
        const formattedTime = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
        
        const welcomeMessage: Message = {
            role: Role.MODEL,
            parts: [{ text: this.welcomeMessage }]
        };

        const newConversation: Conversation = {
            id: randomUUID(),
            userId,
            title: `${formattedDate}-${formattedTime}`,
            messages: [welcomeMessage],
            createdAt: Date.now(),
        };
        this.conversations.unshift(newConversation);
        this.saveConversations();
        return newConversation;
    }
    
    async deleteConversation(conversationId: string): Promise<void> {
        const initialLength = this.conversations.length;
        this.conversations = this.conversations.filter(c => c.id !== conversationId);
        if(this.conversations.length < initialLength) {
             this.saveConversations();
        } else {
            // This case should ideally not happen if ID is found
            throw new Error("Conversation not found for deletion.");
        }
    }
    
    async renameConversation(conversationId: string, newTitle: string): Promise<Conversation> {
        const conversation = this.conversations.find(c => c.id === conversationId);
        if (!conversation) throw new Error("Conversation not found.");
        if (!newTitle.trim()) throw new Error("Title cannot be empty.");
        conversation.title = newTitle.trim();
        this.saveConversations();
        return conversation;
    }

    async addMessageToConversation(conversationId: string, message: Message): Promise<void> {
        this.conversations = this.conversations.map(c => {
            if (c.id === conversationId) {
                // Return a new object with the new message array to ensure immutability
                return { ...c, messages: [...c.messages, message] };
            }
            return c;
        });
        this.saveConversations();
    }

    async replaceLastMessageInConversation(conversationId: string, message: Message): Promise<void> {
        this.conversations = this.conversations.map(c => {
            if (c.id === conversationId) {
                const newMessages = c.messages.slice(0, -1);
                newMessages.push(message);
                return { ...c, messages: newMessages };
            }
            return c;
        });
        this.saveConversations();
    }

    // --- Gemini API Interaction ---
    private mapMessagesToGeminiHistory(messages: Message[], welcomeMessage: string) {
        // Exclude the last message, which is the current user's prompt.
        const history = messages.slice(0, -1);
        
        let filteredHistory = history;
        if (history.length > 0 && history[0].role === Role.MODEL && history[0].parts[0].text === welcomeMessage) {
            filteredHistory = history.slice(1);
        }

        return filteredHistory.map(msg => ({
            role: msg.role === Role.MODEL ? 'model' : 'user',
            parts: msg.parts.map(p => ({ text: p.text })),
        }));
    }

    async sendMessageStream(conversationId: string): Promise<AsyncGenerator<GenerateContentResponse>> {
        const conversation = this.conversations.find(c => c.id === conversationId);
        const user = this.users.find(u => u.id === conversation?.userId);
        
        if (!conversation || !user) {
            throw new Error('Conversa ou usuário não encontrado.');
        }
    
        const systemInstruction = this.systemInstructions[user.role as keyof RoleSystemInstructions];
        const lastMessage = conversation.messages[conversation.messages.length - 1];
        
        const userQuestion = lastMessage.parts.map(p => p.text).join(' ').trim();
        
        const geminiParts: Part[] = lastMessage.parts.map(p => ({ text: p.text }));
        if (lastMessage.image) {
            geminiParts.push({
                inlineData: {
                    data: lastMessage.image.data,
                    mimeType: lastMessage.image.mimeType
                }
            });
        }
    
        if (userQuestion) {
            const findRelevantContext = (question: string, knowledge: string): string | null => {
                const questionWords = new Set(question.toLowerCase().replace(/[.,?]/g, '').split(/\s+/).filter(w => w.length > 3));
                if (questionWords.size === 0) return null;
    
                const knowledgeChunks = knowledge.split(/\n\s*\n/);
                let bestChunk = '';
                let maxScore = 0;
    
                knowledgeChunks.forEach(chunk => {
                    const chunkWords = new Set(chunk.toLowerCase().replace(/[.,?]/g, '').split(/\s+/));
                    let score = 0;
                    questionWords.forEach(qWord => {
                        if (chunkWords.has(qWord)) {
                            score++;
                        }
                    });
                    if (score > maxScore) {
                        maxScore = score;
                        bestChunk = chunk;
                    }
                });
                
                const threshold = questionWords.size > 5 ? 2 : 1;
                if (maxScore >= threshold) {
                    return bestChunk.trim();
                }
                return null;
            };
    
            let combinedKnowledge = '';
            const userRole = user.role;
            const kbs = this.knowledgeBases;

            // Build knowledge base with hierarchy
            const freeKb = kbs[Role.FREE] || '';
            const proKb = kbs[Role.PRO] || '';
            const premiumKb = kbs[Role.PREMIUM] || '';
            const adminKb = kbs[Role.ADMIN] || '';

            if (userRole === Role.ADMIN) {
                combinedKnowledge = [adminKb, premiumKb, proKb, freeKb].filter(Boolean).join('\n\n');
            } else if (userRole === Role.PREMIUM) {
                combinedKnowledge = [premiumKb, proKb, freeKb].filter(Boolean).join('\n\n');
            } else if (userRole === Role.PRO) {
                combinedKnowledge = [proKb, freeKb].filter(Boolean).join('\n\n');
            } else { // FREE
                combinedKnowledge = freeKb;
            }

            const relevantContext = findRelevantContext(userQuestion, combinedKnowledge);
    
            if (relevantContext) {
                const augmentedPromptText = `Com base no seguinte contexto, responda à pergunta do usuário. Se a resposta não estiver no contexto, diga que você não tem essa informação.\n\n### CONTEXTO ###\n${relevantContext}\n\n### PERGUNTA DO USUÁRIO ###\n${userQuestion}`;
                console.log("--- RAG ATIVADO ---");
                console.log("Contexto Relevante:", relevantContext);
                console.log("-------------------");
                
                const textPartIndex = geminiParts.findIndex(p => 'text' in p);
                if (textPartIndex !== -1) {
                    geminiParts[textPartIndex].text = augmentedPromptText;
                } else {
                    geminiParts.unshift({ text: augmentedPromptText });
                }
            }
        }
        
        const history = this.mapMessagesToGeminiHistory(conversation.messages, this.welcomeMessage);
        
        const chat = this.ai.chats.create({
            model: 'gemini-2.5-flash',
            config: {
                systemInstruction,
            },
            history,
        });
        
        const result = await chat.sendMessageStream({ message: geminiParts });
        return result;
    }
}

export const firebaseService = new FirebaseService();