import React, { useState, useEffect, useCallback, useRef } from 'react';
import { firebaseService, convertFileToParts } from './services/firebaseService';
import { PublicUser, Conversation, Message, Role } from './types';
import Login from './components/Login';
import ChatMessage from './components/ChatMessage';
import ChatInput, { ChatInputHandles } from './components/ChatInput';
import PlusIcon from './components/icons/PlusIcon';
import LogoutIcon from './components/icons/LogoutIcon';
import AdminIcon from './components/icons/AdminIcon';
import EditIcon from './components/icons/EditIcon';
import TrashIcon from './components/icons/TrashIcon';
import EloIcon from './components/icons/EloIcon';
import ChevronDoubleLeftIcon from './components/icons/ChevronDoubleLeftIcon';
import AdminPanel from './components/AdminPanel';
import ConfirmationModal from './components/ConfirmationModal';

const App: React.FC = () => {
    // Authentication and User State
    const [currentUser, setCurrentUser] = useState<PublicUser | null>(null);
    const [isLoadingUser, setIsLoadingUser] = useState(true);

    // Chat and Conversation State
    const [conversations, setConversations] = useState<Conversation[]>([]);
    const [activeConversation, setActiveConversation] = useState<Conversation | null>(null);
    const [input, setInput] = useState('');
    const [image, setImage] = useState<File | null>(null);
    const [isLoadingResponse, setIsLoadingResponse] = useState(false);
    
    // UI State
    const [isSidebarOpen, setIsSidebarOpen] = useState(true);
    const [isAdminPanelOpen, setIsAdminPanelOpen] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [editingConversationId, setEditingConversationId] = useState<string | null>(null);
    const [editingTitle, setEditingTitle] = useState('');
    
    // Modal State
    const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
    const [conversationToDelete, setConversationToDelete] = useState<string | null>(null);

    // Refs
    const messagesEndRef = useRef<HTMLDivElement>(null);
    const editInputRef = useRef<HTMLInputElement>(null);
    const chatInputRef = useRef<ChatInputHandles>(null);

    // Show toast for error
    const showErrorToast = (message: string) => {
        setError(message);
        setTimeout(() => setError(null), 5000);
    };

    // --- Effects ---

    // Check for current user on mount
    useEffect(() => {
        const checkUser = async () => {
            try {
                const user = await firebaseService.getCurrentUser();
                setCurrentUser(user);
            } catch (err) {
                console.error("Error checking user session:", err);
                showErrorToast("Failed to check user session.");
            } finally {
                setIsLoadingUser(false);
            }
        };
        checkUser();
    }, []);

    const handleNewConversation = useCallback(async () => {
        if (!currentUser) return;
        try {
            const newConvo = await firebaseService.createConversation(currentUser.id);
            setConversations(prev => [newConvo, ...prev]);
            setActiveConversation(newConvo);
        } catch (err) {
            console.error("Error creating new conversation:", err);
            showErrorToast("Failed to create new conversation.");
        }
    }, [currentUser]);

    // Fetch conversations when user logs in
    const fetchConversations = useCallback(async (user: PublicUser) => {
        try {
            let convos = await firebaseService.getConversations(user.id);
            
            if (convos.length === 0) {
                // If no conversations exist, create one.
                const newConvo = await firebaseService.createConversation(user.id);
                convos = [newConvo];
            }
            
            setConversations(convos);

            const lastActiveId = firebaseService.getLastActiveConversationId(user.id);
            const lastActiveConvo = convos.find(c => c.id === lastActiveId);
            setActiveConversation(lastActiveConvo || convos[0]);

        } catch (err) {
            console.error("Error fetching conversations:", err);
            showErrorToast("Failed to load conversations.");
        }
    }, []);

    useEffect(() => {
        if (currentUser) {
            fetchConversations(currentUser);
        } else {
            // Clear state on logout
            setConversations([]);
            setActiveConversation(null);
        }
    }, [currentUser, fetchConversations]);

    // Scroll to bottom of messages
    useEffect(() => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [activeConversation?.messages]);

    // Focus on edit input when editing starts
    useEffect(() => {
        if (editingConversationId && editInputRef.current) {
            editInputRef.current.focus();
        }
    }, [editingConversationId]);
    
    // --- Handlers ---
    
    const handleLogin = (user: PublicUser) => {
        setCurrentUser(user);
    };

    const handleLogout = async () => {
        try {
            await firebaseService.logout();
            setCurrentUser(null);
        } catch (err) {
            console.error("Error logging out:", err);
            showErrorToast("Failed to log out.");
        }
    };
    
    const handleSelectConversation = (conversationId: string) => {
        if (!currentUser) return;
        const conversation = conversations.find(c => c.id === conversationId);
        if (conversation) {
            setActiveConversation(conversation);
            firebaseService.setLastActiveConversationId(currentUser.id, conversation.id);
        }
    };

    const handleRenameConversation = async (conversationId: string) => {
        if (!editingTitle.trim()) {
            showErrorToast("Title cannot be empty.");
            cancelEditing();
            return;
        }
        try {
            const updatedConvo = await firebaseService.renameConversation(conversationId, editingTitle);
            setConversations(convos => convos.map(c => c.id === conversationId ? updatedConvo : c));
            if (activeConversation?.id === conversationId) {
                setActiveConversation(updatedConvo);
            }
            setEditingConversationId(null);
        } catch (err: any) {
            showErrorToast(err.message || "Failed to rename conversation.");
        }
    };
    
    const startEditing = (conversation: Conversation) => {
        setEditingConversationId(conversation.id);
        setEditingTitle(conversation.title);
    };
    
    const cancelEditing = () => {
        setEditingConversationId(null);
        setEditingTitle('');
    };
    
    const confirmDelete = (conversationId: string) => {
        setConversationToDelete(conversationId);
        setIsDeleteModalOpen(true);
    };

    const handleDeleteConversation = async () => {
        if (!conversationToDelete || !currentUser) return;
        const convoIdToDelete = conversationToDelete;
        
        try {
            // First, determine the next active conversation
            const currentIndex = conversations.findIndex(c => c.id === convoIdToDelete);
            const nextActiveConvo = conversations[currentIndex - 1] || conversations[currentIndex + 1] || null;

            // Delete from service
            await firebaseService.deleteConversation(convoIdToDelete);

            // Update state
            const remainingConversations = conversations.filter(c => c.id !== convoIdToDelete);
            setConversations(remainingConversations);
            
            if (remainingConversations.length === 0) {
                handleNewConversation();
            } else {
                setActiveConversation(nextActiveConvo);
                firebaseService.setLastActiveConversationId(currentUser.id, nextActiveConvo ? nextActiveConvo.id : null);
            }

        } catch (err: any) {
            showErrorToast(err.message || "Failed to delete conversation.");
        } finally {
            setIsDeleteModalOpen(false);
            setConversationToDelete(null);
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if ((!input.trim() && !image) || !activeConversation || !currentUser) return;

        setIsLoadingResponse(true);
        setError(null);
        
        const userMessage: Message = {
            role: currentUser.role,
            parts: [{ text: input.trim() }],
        };
        
        if (image) {
            try {
                userMessage.image = await convertFileToParts(image);
            } catch (err) {
                 console.error("Error converting image:", err);
                 showErrorToast("Failed to process image file.");
                 setIsLoadingResponse(false);
                 return;
            }
        }

        const convoId = activeConversation.id;
        
        // Optimistically update UI
        const updatedConvoWithUserMessage = {
            ...activeConversation,
            messages: [...activeConversation.messages, userMessage],
        };
        
        const modelMessagePlaceholder: Message = {
            role: Role.MODEL,
            parts: [{ text: '...' }]
        };

        const updatedConvoWithPlaceholder = {
            ...updatedConvoWithUserMessage,
            messages: [...updatedConvoWithUserMessage.messages, modelMessagePlaceholder]
        };

        // Update both states simultaneously to prevent desync
        setActiveConversation(updatedConvoWithPlaceholder);
        setConversations(prev => prev.map(c => c.id === convoId ? updatedConvoWithPlaceholder : c));
        
        setInput('');
        setImage(null);

        try {
            await firebaseService.addMessageToConversation(convoId, userMessage);
            const stream = await firebaseService.sendMessageStream(convoId);

            let accumulatedText = '';
            
            for await (const chunk of stream) {
                const chunkText = chunk.text;
                if (chunkText) {
                    accumulatedText += chunkText;
                    
                    setActiveConversation(prevActive => {
                        if (!prevActive) return null;
                        const newMessages = [...prevActive.messages];
                        newMessages[newMessages.length - 1] = { role: Role.MODEL, parts: [{ text: accumulatedText }] };
                        
                        const updatedConvo = { ...prevActive, messages: newMessages };
                        
                        setConversations(prevConvos => prevConvos.map(c => c.id === convoId ? updatedConvo : c));
                        
                        return updatedConvo;
                    });
                }
            }
            
            const finalModelMessage: Message = {
                role: Role.MODEL,
                parts: [{ text: accumulatedText || "Desculpe, não consegui gerar uma resposta." }]
            };

            await firebaseService.replaceLastMessageInConversation(convoId, finalModelMessage);

        } catch (err: any) {
            console.error("Error sending message:", err);
            
            // Default error message
            let errorMessage = "Ocorreu um erro ao comunicar com a IA. Por favor, tente novamente.";

            // Try to parse a more specific message from the Gemini API error
            if (err && err.message) {
                if (/rate limit|resource has been exhausted|quota/i.test(err.message)) {
                    errorMessage = "Você atingiu o limite de requisições. Por favor, aguarde um momento e tente novamente.";
                } else if (/API key not valid/.test(err.message)) {
                    errorMessage = "A chave da API é inválida. Por favor, verifique a configuração.";
                } else if (/safety settings/i.test(err.message)) {
                    errorMessage = "A resposta foi bloqueada por questões de segurança. Tente reformular sua pergunta.";
                } else if (err.message.includes('500') || err.message.includes('server error')) {
                    errorMessage = "Ocorreu um erro no servidor da IA. Tente novamente mais tarde.";
                }
            }

            showErrorToast(errorMessage);
            
            // Update the UI to show the error in place of the response.
            setActiveConversation(prev => {
                if (!prev) return null;
                const newMessages = [...prev.messages];

                // Ensure we are replacing the correct placeholder message.
                if (newMessages.length > 0 && newMessages[newMessages.length - 1].role === Role.MODEL && newMessages[newMessages.length - 1].parts[0].text === '...') {
                    const errorText = `**[ERRO]** ${errorMessage}`;
                    newMessages[newMessages.length - 1] = { role: Role.MODEL, parts: [{ text: errorText }] };
                } else {
                    // Fallback if the placeholder isn't found, though this shouldn't happen.
                    const errorText = `**[ERRO]** Falha ao gerar resposta: ${errorMessage}`;
                    newMessages.push({ role: Role.MODEL, parts: [{ text: errorText }] });
                }

                const updatedConvo = { ...prev, messages: newMessages };
                setConversations(prevConvos => prevConvos.map(c => c.id === convoId ? updatedConvo : c));
                return updatedConvo;
            });
        } finally {
            setIsLoadingResponse(false);
            // Adia a chamada de foco para permitir que o componente renderize novamente com a entrada ativada
            setTimeout(() => {
                chatInputRef.current?.focus();
            }, 0);
        }
    };
    
    // --- Render Logic ---

    if (isLoadingUser) {
        return (
            <div className="flex items-center justify-center h-screen bg-gray-900 text-white">
                <p>Loading session...</p>
            </div>
        );
    }

    if (!currentUser) {
        return <Login onLogin={handleLogin} />;
    }

    return (
        <div className="flex h-screen bg-gray-900 text-gray-200 relative">
            {error && (
                <div className="fixed top-5 right-5 bg-red-800 text-white p-3 rounded-lg shadow-lg z-50">
                    {error}
                </div>
            )}
            
            <ConfirmationModal
                isOpen={isDeleteModalOpen}
                onClose={() => setIsDeleteModalOpen(false)}
                onConfirm={handleDeleteConversation}
                title="Apagar Conversa"
                message="Tem certeza que deseja apagar esta conversa? Esta ação não pode ser desfeita."
            />

            {isAdminPanelOpen && (
                <AdminPanel currentUser={currentUser} onClose={() => {
                    setIsAdminPanelOpen(false);
                    fetchConversations(currentUser); // Refresh data on close
                }} />
            )}

            {/* Sidebar */}
            <aside className={`bg-gray-800 flex flex-col transition-all duration-300 ${isSidebarOpen ? 'w-64' : 'w-0'} overflow-hidden`}>
                <div className="flex items-center justify-between p-4 border-b border-gray-700 flex-shrink-0">
                    <div className="flex items-center gap-2">
                        <EloIcon className="w-6 h-6 text-teal-400" />
                        <h1 className="text-xl font-bold text-white">ELO</h1>
                    </div>
                    <button onClick={handleNewConversation} className="flex items-center gap-2 p-2 rounded-md text-sm font-medium hover:bg-gray-700" title="Nova Conversa">
                        <span>Nova Conversa</span>
                        <PlusIcon className="w-4 h-4" />
                    </button>
                </div>
                
                <nav className="flex-grow overflow-y-auto p-2 space-y-1">
                    {conversations.map(convo => (
                        <div key={convo.id} className={`group flex items-center p-2 rounded-md cursor-pointer ${activeConversation?.id === convo.id ? 'bg-teal-600/30' : 'hover:bg-gray-700'}`}
                             onClick={() => handleSelectConversation(convo.id)}>
                             {editingConversationId === convo.id ? (
                                <input
                                    ref={editInputRef}
                                    type="text"
                                    value={editingTitle}
                                    onChange={(e) => setEditingTitle(e.target.value)}
                                    onBlur={() => handleRenameConversation(convo.id)}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter') handleRenameConversation(convo.id);
                                        if (e.key === 'Escape') cancelEditing();
                                    }}
                                    className="flex-grow bg-transparent text-sm font-medium outline-none"
                                />
                             ) : (
                                <span className="flex-grow text-sm font-medium truncate">{convo.title}</span>
                             )}
                            <div className="flex items-center opacity-0 group-hover:opacity-100 transition-opacity">
                                <button onClick={(e) => { e.stopPropagation(); startEditing(convo); }} className="p-1 text-gray-400 hover:text-white" title="Renomear Conversa">
                                    <EditIcon className="w-4 h-4" />
                                </button>
                                <button onClick={(e) => { e.stopPropagation(); confirmDelete(convo.id); }} className="p-1 text-gray-400 hover:text-red-500" title="Apagar Conversa">
                                    <TrashIcon className="w-4 h-4" />
                                </button>
                            </div>
                        </div>
                    ))}
                </nav>

                <div className="p-4 border-t border-gray-700 flex-shrink-0">
                    <div className="flex items-center gap-3 mb-4">
                        <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center text-sm font-bold">{currentUser.username.charAt(0).toUpperCase()}</div>
                        <div className="flex-grow">
                            <p className="font-semibold text-white">{currentUser.username}</p>
                             <p className="text-xs text-gray-400 capitalize">{currentUser.role}</p>
                        </div>
                    </div>
                    <div className="flex flex-col space-y-2">
                         {currentUser.role === Role.ADMIN && (
                            <button onClick={() => setIsAdminPanelOpen(true)} className="flex items-center gap-3 w-full text-left p-2 rounded-md text-sm hover:bg-gray-700">
                                <AdminIcon className="w-5 h-5 text-gray-400" />
                                Admin Panel
                            </button>
                        )}
                        <button onClick={handleLogout} className="flex items-center gap-3 w-full text-left p-2 rounded-md text-sm hover:bg-gray-700">
                            <LogoutIcon className="w-5 h-5 text-gray-400" />
                            Logout
                        </button>
                    </div>
                </div>
            </aside>

            {/* Sidebar Toggle Button */}
            <button
                onClick={() => setIsSidebarOpen(!isSidebarOpen)}
                className={`absolute top-1/2 -translate-y-1/2 z-10 p-2 bg-gray-800 rounded-r-lg transition-all duration-300 ${isSidebarOpen ? 'left-64' : 'left-0'}`}
                title={isSidebarOpen ? "Recolher Menu" : "Expandir Menu"}>
                <ChevronDoubleLeftIcon className={`w-5 h-5 transition-transform duration-300 ${isSidebarOpen ? '' : 'rotate-180'}`} />
            </button>

            {/* Main Content */}
            <main className="flex-1 flex flex-col relative">
                <div className="flex-1 overflow-y-auto">
                    {activeConversation ? (
                        activeConversation.messages.map((message, index) => (
                            <ChatMessage key={index} message={message} />
                        ))
                    ) : (
                        <div className="flex items-center justify-center h-full text-gray-500">
                            <p>Selecione uma conversa ou inicie uma nova.</p>
                        </div>
                    )}
                    <div ref={messagesEndRef} />
                </div>
                <ChatInput 
                    ref={chatInputRef}
                    input={input}
                    setInput={setInput}
                    onSubmit={handleSubmit}
                    isLoading={isLoadingResponse}
                    image={image}
                    setImage={setImage}
                />
            </main>
        </div>
    );
};

export default App;