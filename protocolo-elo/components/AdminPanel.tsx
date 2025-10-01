import React, { useState, useEffect, useCallback, useRef } from 'react';
import { firebaseService } from '../services/firebaseService';
import { PublicUser, Role, RoleSystemInstructions, User } from '../types';
import XCircleIcon from './icons/XCircleIcon';
import AdminIcon from './icons/AdminIcon';
import UploadIcon from './icons/UploadIcon';

interface AdminPanelProps {
  currentUser: PublicUser;
  onClose: () => void;
}

const AdminPanel: React.FC<AdminPanelProps> = ({ currentUser, onClose }) => {
  const [users, setUsers] = useState<PublicUser[]>([]);
  const [systemInstructions, setSystemInstructions] = useState<RoleSystemInstructions | null>(null);
  const [originalInstructions, setOriginalInstructions] = useState<RoleSystemInstructions | null>(null);
  const [welcomeMessage, setWelcomeMessage] = useState('');
  const [originalWelcomeMessage, setOriginalWelcomeMessage] = useState('');
  const [knowledgeBases, setKnowledgeBases] = useState<RoleSystemInstructions | null>(null);
  const [originalKnowledgeBases, setOriginalKnowledgeBases] = useState<RoleSystemInstructions | null>(null);
  const [activeKbTab, setActiveKbTab] = useState<keyof RoleSystemInstructions>(Role.FREE);

  
  const [searchEmail, setSearchEmail] = useState('');
  const [selectedRole, setSelectedRole] = useState<User['role']>(Role.FREE);
  
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);
  
  const showToast = (setter: React.Dispatch<React.SetStateAction<string | null>>, message: string) => {
    setter(message);
    setTimeout(() => setter(null), 3000);
  };

  const fetchData = useCallback(async () => {
    setIsLoading(true);
    try {
      const [allUsers, instructions, welcomeMsg, kbs] = await Promise.all([
        firebaseService.getAllUsers(),
        firebaseService.getSystemInstructions(),
        firebaseService.getWelcomeMessage(),
        firebaseService.getKnowledgeBases(),
      ]);
      setUsers(allUsers);
      setSystemInstructions(instructions);
      setOriginalInstructions(instructions);
      setWelcomeMessage(welcomeMsg);
      setOriginalWelcomeMessage(welcomeMsg);
      setKnowledgeBases(kbs);
      setOriginalKnowledgeBases(kbs);
    } catch (err: any) {
      showToast(setError, err.message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleRoleChangeByEmail = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchEmail) {
      showToast(setError, 'Please enter an email address.');
      return;
    }
    try {
      const updatedUser = await firebaseService.updateUserRoleByEmail(searchEmail, selectedRole);
      setUsers(prevUsers =>
        prevUsers.map(u => (u.id === updatedUser.id ? { ...u, role: selectedRole } : u))
      );
      showToast(setSuccess, `User ${searchEmail} role updated to ${selectedRole}.`);
      setSearchEmail('');
    } catch (err: any) {
      showToast(setError, err.message);
    }
  };
  
  const handleInstructionChange = (role: keyof RoleSystemInstructions, value: string) => {
      if (systemInstructions) {
          setSystemInstructions({ ...systemInstructions, [role]: value });
      }
  };

  const handleKbChange = (role: keyof RoleSystemInstructions, value: string) => {
    if (knowledgeBases) {
        setKnowledgeBases({ ...knowledgeBases, [role]: value });
    }
  };

  const handleSaveInstructions = async (role: keyof RoleSystemInstructions) => {
    if (!systemInstructions) return;
    try {
        await firebaseService.setSystemInstructions(systemInstructions);
        setOriginalInstructions(systemInstructions);
        showToast(setSuccess, `System instruction for ${role} updated.`);
    } catch (err: any) {
        showToast(setError, err.message);
    }
  };

  const handleSaveWelcomeMessage = async () => {
    try {
        await firebaseService.setWelcomeMessage(welcomeMessage);
        setOriginalWelcomeMessage(welcomeMessage);
        showToast(setSuccess, `Welcome message updated.`);
    } catch (err: any) {
        showToast(setError, err.message);
    }
  };

  const handleSaveKnowledgeBase = async (role: keyof RoleSystemInstructions) => {
    if (!knowledgeBases) return;
    try {
        await firebaseService.updateKnowledgeBase(role, knowledgeBases[role]);
        if(originalKnowledgeBases) {
             setOriginalKnowledgeBases({...originalKnowledgeBases, [role]: knowledgeBases[role]});
        }
        showToast(setSuccess, `Knowledge Base for ${role} updated successfully.`);
    } catch (err: any) {
        showToast(setError, err.message);
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    try {
      let combinedContent = '';
      for (const file of Array.from(files)) {
        const text = await file.text();
        // Add a separator with the filename for clarity
        combinedContent += `\n\n--- CONTEÚDO DE ${file.name} ---\n\n${text}`;
      }
      
      if (knowledgeBases) {
        setKnowledgeBases({
          ...knowledgeBases,
          [activeKbTab]: (knowledgeBases[activeKbTab] || '') + combinedContent,
        });
        showToast(setSuccess, `${files.length} arquivo(s) carregado(s). Revise e salve.`);
      }
    } catch (error) {
      console.error("Error reading file:", error);
      // FIX: The error object in a catch block is of type 'unknown'. Added a type guard to safely access the error message.
      if (error instanceof Error) {
        showToast(setError, `Error reading file: ${error.message}`);
      } else {
        showToast(setError, 'Falha ao ler o conteúdo do arquivo.');
      }
    }

    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };


  return (
    <div className="fixed inset-0 bg-black bg-opacity-75 flex items-center justify-center z-50">
      <div className="bg-gray-800 rounded-lg shadow-xl w-full max-w-4xl h-[90vh] max-h-[800px] flex flex-col p-6">
        <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileChange}
            className="hidden"
            accept=".txt,.md"
            multiple
        />
        <div className="flex justify-between items-center mb-4 border-b border-gray-700 pb-4">
          <div className="flex items-center gap-3">
             <AdminIcon className="w-8 h-8 text-teal-400"/>
             <h2 className="text-2xl font-bold text-teal-400">Admin Panel</h2>
          </div>
          <button onClick={onClose} className="p-2 rounded-full hover:bg-gray-700">
            <XCircleIcon className="w-6 h-6 text-gray-400" />
          </button>
        </div>

        {isLoading ? (
          <div className="flex-grow flex items-center justify-center">
            <p className="text-gray-400">Loading admin data...</p>
          </div>
        ) : (
          <div className="flex-grow overflow-y-auto pr-2 space-y-8">
             {error && <div className="p-3 mb-4 bg-red-900/50 border border-red-500 text-red-300 rounded-lg sticky top-0">{error}</div>}
             {success && <div className="p-3 mb-4 bg-green-900/50 border border-green-500 text-green-300 rounded-lg sticky top-0">{success}</div>}

            {/* Welcome Message Section */}
            <div>
                 <h3 className="text-xl font-semibold mb-4 text-gray-200">Welcome Message</h3>
                 <p className="text-sm text-gray-400 mb-2">This message appears at the start of every new conversation.</p>
                 <textarea
                    value={welcomeMessage}
                    onChange={(e) => setWelcomeMessage(e.target.value)}
                    rows={3}
                    className="w-full p-3 bg-gray-700 rounded-md text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-teal-500"
                />
                 <div className="text-right mt-2">
                    <button
                    onClick={handleSaveWelcomeMessage}
                    disabled={originalWelcomeMessage === welcomeMessage || !welcomeMessage.trim()}
                    className="px-4 py-2 text-sm font-bold text-white bg-teal-600 rounded-md hover:bg-teal-700 disabled:bg-gray-600 disabled:cursor-not-allowed"
                    >
                    Save Welcome Message
                    </button>
                </div>
            </div>

            {/* Knowledge Base Section */}
            <div>
                 <h3 className="text-xl font-semibold mb-2 text-gray-200">Knowledge Base (RAG) by Role</h3>
                 <p className="text-sm text-gray-400 mb-4">Este conteúdo será usado para fornecer respostas baseadas em contexto para cada perfil de usuário.</p>
                 <div className="border-b border-gray-600 flex space-x-4">
                     {knowledgeBases && Object.keys(knowledgeBases).map((role) => (
                         <button key={role} onClick={() => setActiveKbTab(role as keyof RoleSystemInstructions)}
                         className={`px-4 py-2 text-sm font-medium capitalize transition-colors ${activeKbTab === role ? 'border-b-2 border-teal-400 text-teal-400' : 'text-gray-400 hover:text-white'}`}>
                            {role}
                         </button>
                     ))}
                 </div>
                 <div className="mt-4">
                    {knowledgeBases && (
                         <>
                            <textarea
                                value={knowledgeBases[activeKbTab]}
                                onChange={(e) => handleKbChange(activeKbTab, e.target.value)}
                                rows={8}
                                className="w-full p-3 bg-gray-700 rounded-md text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-teal-500 font-mono text-sm"
                                placeholder={`Insira o conteúdo para o perfil ${activeKbTab}...`}
                            />
                             <div className="flex justify-end items-center gap-2 mt-2">
                                <button
                                    onClick={() => fileInputRef.current?.click()}
                                    className="flex items-center gap-2 px-4 py-2 text-sm font-bold text-white bg-gray-600 rounded-md hover:bg-gray-500 transition-colors"
                                    title="Carregar conteúdo de arquivos .txt ou .md"
                                >
                                    <UploadIcon className="w-4 h-4" />
                                    Upload Arquivo(s)
                                </button>
                                <button
                                onClick={() => handleSaveKnowledgeBase(activeKbTab)}
                                disabled={originalKnowledgeBases?.[activeKbTab] === knowledgeBases[activeKbTab]}
                                className="px-4 py-2 text-sm font-bold text-white bg-teal-600 rounded-md hover:bg-teal-700 disabled:bg-gray-600 disabled:cursor-not-allowed"
                                >
                                Save {activeKbTab.charAt(0).toUpperCase() + activeKbTab.slice(1)}
                                </button>
                            </div>
                        </>
                    )}
                 </div>
            </div>

            {/* System Instructions Section */}
            <div>
                 <h3 className="text-xl font-semibold mb-4 text-gray-200">System Instructions by Role</h3>
                 <div className="space-y-4">
                    {systemInstructions && Object.entries(systemInstructions).map(([role, instruction]) => (
                        <div key={role}>
                            <label className="block text-sm font-medium text-gray-300 mb-1 capitalize">{role}</label>
                            <textarea
                                value={instruction}
                                onChange={(e) => handleInstructionChange(role as keyof RoleSystemInstructions, e.target.value)}
                                rows={3}
                                className="w-full p-3 bg-gray-700 rounded-md text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-teal-500"
                            />
                             <div className="text-right mt-2">
                                <button
                                onClick={() => handleSaveInstructions(role as keyof RoleSystemInstructions)}
                                disabled={originalInstructions?.[role as keyof RoleSystemInstructions] === instruction}
                                className="px-4 py-2 text-sm font-bold text-white bg-teal-600 rounded-md hover:bg-teal-700 disabled:bg-gray-600 disabled:cursor-not-allowed"
                                >
                                Save {role.charAt(0).toUpperCase() + role.slice(1)}
                                </button>
                            </div>
                        </div>
                    ))}
                 </div>
            </div>

            {/* User Management Section */}
            <div>
              <h3 className="text-xl font-semibold mb-4 text-gray-200">User Management</h3>
              
              {/* Direct User Role Change */}
              <form onSubmit={handleRoleChangeByEmail} className="p-4 mb-4 bg-gray-900/50 rounded-lg flex items-end gap-4">
                  <div className="flex-grow">
                      <label htmlFor="userEmail" className="block text-sm font-medium text-gray-300 mb-1">User Email</label>
                      <input 
                        id="userEmail"
                        type="email"
                        value={searchEmail}
                        onChange={(e) => setSearchEmail(e.target.value)}
                        placeholder="user@example.com"
                        className="w-full p-2 bg-gray-700 rounded-md text-gray-200 focus:outline-none focus:ring-2 focus:ring-teal-500"
                      />
                  </div>
                  <div>
                      <label htmlFor="userRole" className="block text-sm font-medium text-gray-300 mb-1">New Role</label>
                      <select
                        id="userRole"
                        value={selectedRole}
                        onChange={(e) => setSelectedRole(e.target.value as User['role'])}
                        className="w-full p-2 bg-gray-700 rounded-md text-gray-200 focus:outline-none focus:ring-2 focus:ring-teal-500"
                      >
                         {Object.values(Role).filter(r => r !== Role.MODEL).map(role => (
                            <option key={role} value={role}>{role.charAt(0).toUpperCase() + role.slice(1)}</option>
                         ))}
                      </select>
                  </div>
                  <button type="submit" className="px-4 py-2 font-bold text-white bg-teal-600 rounded-md hover:bg-teal-700">
                    Change
                  </button>
              </form>

              <div className="bg-gray-900/50 rounded-lg overflow-hidden">
                <table className="w-full text-left text-sm">
                  <thead className="text-xs text-gray-400 uppercase border-b border-gray-700">
                    <tr>
                      <th scope="col" className="px-4 py-3">Username</th>
                      <th scope="col" className="px-4 py-3">Email</th>
                      <th scope="col" className="px-4 py-3">Role</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map(user => (
                      <tr key={user.id} className="border-b border-gray-700 hover:bg-gray-700/50 last:border-b-0">
                        <td className="px-4 py-3 font-medium text-white">{user.username}</td>
                        <td className="px-4 py-3 text-gray-300">{user.email}</td>
                        <td className="px-4 py-3">
                            <span className={`px-2 py-1 text-xs font-semibold rounded-full ${
                                user.role === Role.ADMIN ? 'bg-red-500 text-white' :
                                user.role === Role.PREMIUM ? 'bg-purple-500 text-white' :
                                user.role === Role.PRO ? 'bg-blue-500 text-white' :
                                'bg-gray-600 text-gray-200'
                            }`}>
                                {user.role.charAt(0).toUpperCase() + user.role.slice(1)}
                            </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default AdminPanel;