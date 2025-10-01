import React from 'react';
import { Message, Role } from '../types';
import UserIcon from './icons/UserIcon';
import BotIcon from './icons/BotIcon';

interface ChatMessageProps {
  message: Message;
}

const ChatMessage: React.FC<ChatMessageProps> = ({ message }) => {
  // FIX: Changed condition to check if the message role is not the model, as Role.USER does not exist.
  const isUser = message.role !== Role.MODEL;

  const textContent = message.parts.map(part => part.text).join('');
  const isError = textContent.startsWith('**[ERRO]**');

  return (
    <div className={`flex items-start gap-4 p-4 md:p-6 ${isUser ? '' : 'bg-gray-800/50'}`}>
      <div className="flex-shrink-0">
        {isUser ? (
          <div className="w-8 h-8 rounded-full bg-blue-600 flex items-center justify-center">
            <UserIcon className="w-5 h-5 text-white" />
          </div>
        ) : (
          <div className="w-8 h-8 rounded-full bg-teal-500 flex items-center justify-center">
            <BotIcon className="w-5 h-5 text-white" />
          </div>
        )}
      </div>
      <div className="flex-grow pt-0.5">
        <p className="font-bold text-gray-200">{isUser ? 'Você' : 'ELO'}</p>
        {isError ? (
          <div className="text-red-400 border border-red-500/50 bg-red-900/20 rounded-md p-3 mt-2">
            <p className="font-semibold">Falha na Resposta</p>
            <p className="text-sm">{textContent.replace('**[ERRO]**', '').trim()}</p>
          </div>
        ) : (
          <div className="prose prose-invert max-w-none text-gray-300 whitespace-pre-wrap">
            {textContent}
          </div>
        )}
        {message.image && (
          <div className="mt-2">
            <img 
              // FIX: Construct data URL from mimeType and base64 data.
              src={`data:${message.image.mimeType};base64,${message.image.data}`} 
              alt="User upload" 
              className="max-w-xs rounded-lg border border-gray-700" 
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default ChatMessage;
