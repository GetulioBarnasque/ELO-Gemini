import React, { useState, useRef, useLayoutEffect, forwardRef, useImperativeHandle } from 'react';
import SendIcon from './icons/SendIcon';
import PaperclipIcon from './icons/PaperclipIcon';

interface ChatInputProps {
  input: string;
  setInput: (value: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  isLoading: boolean;
  image: File | null;
  setImage: (file: File | null) => void;
}

export interface ChatInputHandles {
  focus: () => void;
}

const ChatInput = forwardRef<ChatInputHandles, ChatInputProps>(({ input, setInput, onSubmit, isLoading, image, setImage }, ref) => {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [imagePreview, setImagePreview] = useState<string | null>(null);

  useImperativeHandle(ref, () => ({
    focus: () => {
      textareaRef.current?.focus();
    },
  }));

  useLayoutEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`;
    }
  }, [input]);

  useLayoutEffect(() => {
    if (image) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setImagePreview(reader.result as string);
      };
      reader.readAsDataURL(image);
    } else {
      setImagePreview(null);
    }
  }, [image]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      onSubmit(e as any);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setImage(e.target.files[0]);
    }
  };

  const handleRemoveImage = () => {
    setImage(null);
    if(fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return (
    <div className="w-full max-w-3xl mx-auto p-4 bg-gray-900 border-t border-gray-800">
      {imagePreview && (
        <div className="mb-2 p-2 bg-gray-800 rounded-lg relative w-fit">
          <img src={imagePreview} alt="Preview" className="h-20 w-auto rounded" />
          <button 
            onClick={handleRemoveImage}
            className="absolute -top-2 -right-2 bg-red-600 text-white rounded-full h-6 w-6 flex items-center justify-center text-xs font-bold"
            title="Remover Imagem"
          >
            X
          </button>
        </div>
      )}
      <form onSubmit={onSubmit} className="relative flex items-center">
        <button
          type="button"
          onClick={() => fileInputRef.current?.click()}
          disabled={isLoading}
          className="absolute left-3 top-1/2 -translate-y-1/2 p-2 rounded-md text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
          title="Anexar Imagem"
        >
          <PaperclipIcon className="w-5 h-5" />
        </button>
        <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleFileChange}
            accept="image/*"
            className="hidden" 
        />
        <textarea
            ref={textareaRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Envie uma mensagem para o ELO..."
            rows={1}
            disabled={isLoading}
            className="w-full resize-none p-3 pl-12 pr-12 bg-gray-800 rounded-2xl text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-teal-500 max-h-40 disabled:cursor-not-allowed"
        />
        <button
          type="submit"
          disabled={isLoading || (!input.trim() && !image)}
          className="absolute right-3 top-1/2 -translate-y-1/2 p-2 rounded-full text-gray-400 bg-gray-700 hover:bg-teal-600 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          title="Enviar Mensagem"
        >
          <SendIcon className="w-5 h-5" />
        </button>
      </form>
    </div>
  );
});

export default ChatInput;